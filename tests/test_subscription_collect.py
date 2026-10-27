"""Snapshot `subscription` from fake homes: documented limit messages in transcripts, model mix by family
and the documented extra-usage settings. Only kinds, session keys and UTC dates are kept, never text."""
import json
import os
import time
from unittest import mock

from test_collect import collect
from test_plugin_footprint import observer_key
from test_privacy import PatchedHome, args
import privacy

WEEKLY = "You've hit your weekly limit · resets Mon 12:00am"


def stamp(offset=0):
    return collect.datetime.fromtimestamp(time.time() + offset, collect.timezone.utc).isoformat()


def synthetic(text, uuid="u1", api_error=True):
    return {"type": "assistant", "uuid": uuid, "timestamp": stamp(), "sessionId": "s", "isApiErrorMessage": api_error,
            "error": "rate_limit", "message": {"id": "m-" + uuid, "model": "<synthetic>", "role": "assistant",
                                                "content": [{"type": "text", "text": text}]}}


def plain_assistant(text):
    return {"type": "assistant", "uuid": "a1", "timestamp": stamp(), "sessionId": "s",
            "message": {"id": "m-a1", "model": "claude-opus-5-5", "content": [{"type": "text", "text": text}]}}


def tool_result(text):
    return {"type": "user", "uuid": "t1", "timestamp": stamp(), "sessionId": "s", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_1", "content": text}]}}


def assistant_usage(model, mid, usage):
    return {"type": "assistant", "uuid": "u-" + mid, "timestamp": stamp(), "sessionId": "s",
            "message": {"id": mid, "model": model, "usage": usage, "content": []}}


def api_request(model, rid, source="repl_main_thread"):
    return {"type": "api-request", "sessionId": "s", "id": rid, "timestamp": stamp(), "querySource": source,
            "params": {"model": model}}


class Base(PatchedHome):
    def put(self, key, name, records):
        self.write(f".claude/projects/{key}/{name}.jsonl", "\n".join(json.dumps(r) for r in records))

    def sub(self, **kw):
        return collect.build_snapshot(args(**kw))["subscription"]


class LimitEvents(Base):
    def test_quoted_limit_text_not_counted(self):
        self.put("-a", "s1", [plain_assistant(WEEKLY), tool_result(WEEKLY),
                              {"type": "user", "timestamp": stamp(), "message": {"content": WEEKLY}}])
        events = self.sub()["limit_events"]
        self.assertEqual(set(events) - {"basis"}, set())
        self.put("-a", "s2", [synthetic(WEEKLY)])
        weekly = self.sub()["limit_events"]["weekly"]
        self.assertEqual(weekly["count"], 1)
        self.assertEqual((weekly["sessions"], weekly["subagent_count"]), (1, 0))
        today = time.strftime("%Y-%m-%d", time.gmtime())
        self.assertEqual((weekly["first_date"], weekly["last_date"]), (today, today))

    def test_limit_events_spawned_excluded(self):
        self.put(observer_key(self), "o1", [synthetic(WEEKLY)])
        self.put(observer_key(self) + "/o1/subagents", "agent-1", [synthetic(WEEKLY)])
        self.assertNotIn("weekly", self.sub()["limit_events"])

    def test_subagent_events_count_under_the_parent_session(self):
        self.put("-a", "s1", [synthetic(WEEKLY)])
        self.put("-a/s1/subagents", "agent-1", [synthetic(WEEKLY, uuid="u2")])
        weekly = self.sub()["limit_events"]["weekly"]
        self.assertEqual((weekly["count"], weekly["sessions"], weekly["subagent_count"]), (2, 1, 1))

    def test_system_records_and_resumed_copies(self):
        wait = {"type": "system", "uuid": "w1", "timestamp": stamp(), "sessionId": "s",
                "content": "Usage limit reached · continuing automatically at 3:45pm · esc to cancel"}
        self.put("-a", "s1", [wait, synthetic(WEEKLY)])
        self.put("-a", "s1-resumed", [wait, synthetic(WEEKLY)])  # resumed copy repeats uuids and sessionId
        events = self.sub()["limit_events"]
        self.assertEqual((events["auto_continue_wait"]["count"], events["weekly"]["count"]), (1, 1))

    def test_warning_85_records_the_window_named(self):
        self.put("-a", "s1", [synthetic("You've used 85% of your session limit · resets 3:45pm", uuid="w1"),
                              synthetic("You’ve used 85% of your weekly limit · resets Mon", uuid="w2"),
                              synthetic("You've used 90% of your weekly limit", uuid="w3"),
                              synthetic("You've used 85% of your Opus limit", uuid="w4")])
        warning = self.sub()["limit_events"]["warning_85"]
        self.assertEqual(warning["count"], 4)
        self.assertEqual(warning["windows"], {"session": 1, "weekly": 2, "other": 1})
        self.put("-b", "s2", [synthetic(WEEKLY)])
        self.assertNotIn("windows", self.sub()["limit_events"]["weekly"])

    def test_records_outside_the_window_are_ignored(self):
        old = synthetic(WEEKLY)
        old["timestamp"] = stamp(-40 * 86400)
        self.put("-a", "s1", [old])
        self.assertNotIn("weekly", self.sub()["limit_events"])

    def test_message_text_is_never_stored(self):
        self.put("-a", "s1", [synthetic(WEEKLY + " CANARY-limit-text")])
        snap = collect.build_snapshot(args())
        self.assertEqual(snap["subscription"]["limit_events"]["weekly"]["count"], 1)
        self.assertNotIn("CANARY-limit-text", json.dumps(snap))


class ModelMix(Base):
    def test_model_mix_families(self):
        self.put("-a", "s1", [api_request("claude-opus-5-5", f"r{i}") for i in range(3)]
                 + [api_request("claude-sonnet-5-5", "r9"), api_request("claude-haiku-4-5", "x1", "agent:Explore")])
        mix = self.sub()["model_mix"]
        self.assertEqual(mix["main"]["opus"], {"requests": 3, "tokens": 0, "share": 0.75})
        self.assertEqual(mix["main"]["sonnet"], {"requests": 1, "tokens": 0, "share": 0.25})
        self.assertEqual(mix["main"]["fable"], {"requests": 0, "tokens": 0, "share": 0.0})
        self.assertEqual(mix["agent"]["haiku"], {"requests": 1, "tokens": 0, "share": 1.0})
        self.assertIn("api-request", mix["basis"])

    def test_model_mix_uses_full_counters_not_capped_rows(self):
        models = [f"claude-sonnet-x{i}" for i in range(collect.REQUEST_MODEL_LIMIT + 3)]
        self.put("-a", "s1", [api_request(m, f"r{i}") for i, m in enumerate(models)])
        snap = collect.build_snapshot(args())
        self.assertGreater(snap["transcripts"]["request_params"]["main"]["omitted_models"], 0)
        self.assertEqual(snap["subscription"]["model_mix"]["main"]["sonnet"]["requests"], len(models))

    def test_no_requests_gives_null_shares(self):
        self.assertEqual(self.sub()["model_mix"]["main"]["opus"], {"requests": 0, "tokens": 0, "share": None})

    def test_tokens_by_family(self):
        usage = {"input_tokens": 1, "cache_creation_input_tokens": 10, "cache_read_input_tokens": 100,
                 "output_tokens": 1000}
        self.put("-a", "s1", [
            assistant_usage("claude-opus-5-5", "m1", usage),
            assistant_usage("claude-opus-5-5", "m1", usage),  # streamed chunk of the same message
            assistant_usage("claude-sonnet-5-5", "m2", {"output_tokens": 7, "input_tokens": "x"}),
            {**assistant_usage("claude-haiku-4-5", "m3", usage), "isSidechain": True},  # not a main-file record
            {**assistant_usage("claude-opus-5-5", "m4", usage), "timestamp": stamp(-40 * 86400)},  # out of window
        ])
        self.put("-a/s1/subagents", "agent-1", [assistant_usage("claude-haiku-4-5", "m5", usage)])
        self.put(observer_key(self), "o1", [assistant_usage("claude-opus-5-5", "m6", usage)])  # plugin-spawned
        mix = self.sub()["model_mix"]
        self.assertEqual({f: v["tokens"] for f, v in mix["main"].items()},
                         {"opus": 1111, "sonnet": 7, "haiku": 0, "fable": 0, "other": 0})
        self.assertEqual({f: v["tokens"] for f, v in mix["agent"].items()},
                         {"opus": 0, "sonnet": 0, "haiku": 1111, "fable": 0, "other": 0})
        self.assertIn("message id", mix["basis"])


class ExtraUsage(Base):
    def test_extra_usage_settings(self):
        self.write(".claude/settings.json", {"autoContinueAtUsageLimit": False, "fastMode": True,
                                             "fastModePerSessionOptIn": "yes"})
        snap = collect.build_snapshot(args())
        rows = snap["subscription"]["extra_usage"]["settings"]
        self.assertEqual(rows, [{"path": "~/.claude/settings.json", "setting": "autoContinueAtUsageLimit", "value": False},
                                {"path": "~/.claude/settings.json", "setting": "fastMode", "value": True},
                                {"path": "~/.claude/settings.json", "setting": "fastModePerSessionOptIn",
                                 "value": "invalid"}])
        other = snap["global"]["settings"][0]["other"]
        self.assertIs(other["autoContinueAtUsageLimit"], False)
        self.assertIs(other["fastMode"], True)

    def test_messages_count_spend_and_credit_kinds(self):
        self.put("-a", "s1", [synthetic("You've hit your monthly spend limit · raise it", uuid="u1"),
                              synthetic("API Error: Usage credits required for 1M context", uuid="u2"),
                              synthetic(WEEKLY, uuid="u3")])
        self.assertEqual(self.sub()["extra_usage"]["messages"],
                         {"spend_limit": 1, "credits_required_1m": 1, "fable_consent_unanswered": 0})

    def test_not_observable_listed(self):
        self.assertEqual(self.sub()["extra_usage"]["not_observable"],
                         ["plan tier", "usage-credit balance and limit", "available limit resets"])


class Privacy(Base):
    def setUp(self):
        super().setUp()
        self.write(".claude/settings.json", {"fastMode": True})
        self.put("-a", "s1", [synthetic(WEEKLY), api_request("claude-opus-5-5", "r1"),
                              synthetic("You've used 85% of your session limit", uuid="w1"),
                              assistant_usage("claude-opus-5-5", "m1", {"output_tokens": 5})])

    def test_every_string_leaf_is_classified(self):
        sub = collect.build_snapshot(args())["subscription"]
        strings = [(p, v) for p, v in privacy.leaves({"subscription": sub}) if isinstance(v, str)]
        self.assertTrue(strings)
        for path, v in strings:
            self.assertTrue(privacy.is_kept(path), path)

    def test_metadata_only_keeps_kinds_dates_and_settings_rows(self):
        full, meta = collect.build_snapshot(args())["subscription"], collect.build_snapshot(
            args(metadata_only=True))["subscription"]
        self.assertEqual(meta, full)

    def test_hash_paths_hashes_the_settings_path_in_config_files(self):
        snap = collect.build_snapshot(args(hash_paths=True))
        (row,) = snap["subscription"]["extra_usage"]["settings"]
        self.assertRegex(row["path"], r"^h:[0-9a-f]{12}$")
        self.assertEqual(row["path"], snap["global"]["settings"][0]["path"])

    def test_schema_types_the_new_fields(self):
        import snapshot_contract as contract
        snap = collect.build_snapshot(args())
        contract.validate_snapshot(snap)
        for mutate in (lambda s: s["extra_usage"]["settings"][0].update(value="on"),
                       lambda s: s["limit_events"]["weekly"].update(count="1"),
                       lambda s: s["model_mix"]["main"]["opus"].update(requests=-1),
                       lambda s: s["model_mix"]["main"]["opus"].update(tokens=-1),
                       lambda s: s["model_mix"]["agent"]["haiku"].pop("tokens"),
                       lambda s: s["limit_events"]["warning_85"].pop("windows"),
                       lambda s: s["limit_events"]["warning_85"]["windows"].update(weekly="1")):
            bad = json.loads(json.dumps(snap))
            mutate(bad["subscription"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(bad)


def log_line(at, pct, resets_at, kind="seven_day"):
    return json.dumps({"version": 1, "at": at, "windows": {kind: {"used_percentage": pct, "resets_at": resets_at}}})


class RateLimitLog(Base):
    def make_log(self, name="rate-limits.jsonl"):
        # Two closed weekly windows (both reset long before now); entries a few hours before each reset.
        path = f"{self.home}/.claude/audits/{name}"
        self.write(f".claude/audits/{name}", "\n".join([
            log_line("2026-01-01T00:00:00Z", 40, 1767312000),
            log_line("2026-01-01T23:00:00Z", 60, 1767312000),
            log_line("2026-01-08T00:00:00Z", 30, 1767916800),
            log_line("2026-01-08T23:00:00Z", 90, 1767916800)]) + "\n")
        return path

    def test_log_absent_without_flag(self):
        sub = self.sub()
        self.assertEqual(sub["log"], {"status": "absent"})
        self.assertNotIn("windows", sub)
        self.assertNotIn("early_resets", sub)

    def test_log_absent_for_missing_file(self):
        sub = self.sub(rate_limit_log=f"{self.home}/.claude/audits/none.jsonl")
        self.assertEqual(sub["log"]["status"], "absent")
        self.assertNotIn("windows", sub)

    def test_log_collected(self):
        sub = self.sub(rate_limit_log=self.make_log())
        self.assertEqual(sub["log"]["status"], "collected")
        self.assertEqual((sub["log"]["entries"], sub["log"]["malformed"]), (4, 0))
        self.assertEqual((sub["log"]["first_at"], sub["log"]["last_at"]),
                         ("2026-01-01T00:00:00Z", "2026-01-08T23:00:00Z"))
        self.assertEqual(sub["windows"]["seven_day"]["closed"], 2)
        self.assertEqual(sub["windows"]["seven_day"]["counted"], 2)
        self.assertEqual(sub["early_resets"], [])
        self.assertIn("rate-limit log", sub["log_basis"])
        self.assertTrue(sub["log"]["path"].startswith("~/") or sub["log"]["path"].startswith("/"))

    def test_log_global_scope_without_transcripts(self):
        sub = self.sub(scope="global", rate_limit_log=self.make_log())
        self.assertEqual(sub["windows"]["seven_day"]["closed"], 2)

    def test_log_outside_allowed_is_invalid(self):
        path = f"{self.home}/elsewhere.jsonl"
        self.write("elsewhere.jsonl", log_line("2026-01-01T00:00:00Z", 40, 1767312000) + "\n")
        # the fake home lives in the system temp directory, which is allowed; narrow the rule to audits only
        with mock.patch.object(collect, "_out_allowed_dirs", lambda: {os.path.realpath(f"{self.home}/.claude/audits")}):
            sub = self.sub(rate_limit_log=path)
            ok = self.sub(rate_limit_log=self.make_log())
        self.assertEqual(ok["log"]["status"], "collected")
        self.assertEqual(sub["log"]["status"], "invalid")
        self.assertNotIn("windows", sub)

    def test_log_path_hashed(self):
        snap = collect.build_snapshot(args(hash_paths=True, rate_limit_log=self.make_log()))
        self.assertRegex(snap["subscription"]["log"]["path"], r"^h:[0-9a-f]{12}$")
        self.assertNotIn("rate-limits.jsonl", json.dumps(snap))
        base = collect.build_snapshot(args(hash_paths=True))["coverage"]["privacy"]["hashed_path_families"]
        counts = snap["coverage"]["privacy"]["hashed_path_families"]
        self.assertEqual(counts["config_files"], base["config_files"] + 1)
        self.assertEqual(counts["other_paths"], base["other_paths"])

    def test_invalid_log_path_hashed(self):
        self.write("elsewhere.jsonl", log_line("2026-01-01T00:00:00Z", 40, 1767312000) + "\n")
        with mock.patch.object(collect, "_out_allowed_dirs", lambda: {os.path.realpath(f"{self.home}/.claude/audits")}):
            plain = collect.build_snapshot(args(rate_limit_log=f"{self.home}/elsewhere.jsonl"))
            snap = collect.build_snapshot(args(hash_paths=True, rate_limit_log=f"{self.home}/elsewhere.jsonl"))
        self.assertEqual(plain["subscription"]["log"], {"status": "invalid", "path": "~/elsewhere.jsonl"})
        self.assertEqual(snap["subscription"]["log"]["status"], "invalid")
        self.assertRegex(snap["subscription"]["log"]["path"], r"^h:[0-9a-f]{12}$")
        self.assertNotIn("elsewhere.jsonl", json.dumps(snap))
        base = collect.build_snapshot(args(hash_paths=True))["coverage"]["privacy"]["hashed_path_families"]
        counts = snap["coverage"]["privacy"]["hashed_path_families"]
        self.assertEqual(counts["config_files"], base["config_files"] + 1)  # the config-file family, not a fallback

    def test_metadata_only_keeps_numbers(self):
        path = self.make_log()
        full = self.sub(rate_limit_log=path)
        meta = self.sub(rate_limit_log=path, metadata_only=True)
        self.assertEqual(meta, full)

    def test_every_string_leaf_is_classified(self):
        sub = self.sub(rate_limit_log=self.make_log())
        for path, v in privacy.leaves({"subscription": sub}):
            if isinstance(v, str):
                self.assertTrue(privacy.is_kept(path), path)

    def test_schema_types_log_fields(self):
        import snapshot_contract as contract
        snap = collect.build_snapshot(args(rate_limit_log=self.make_log()))
        contract.validate_snapshot(snap)
        bad = json.loads(json.dumps(snap))
        bad["subscription"]["windows"]["seven_day"]["closed"] = "2"
        with self.assertRaises(contract.SnapshotError):
            contract.validate_snapshot(bad)
        for mutate in (lambda w: w.update(counted="2"), lambda w: w.pop("counted")):
            bad = json.loads(json.dumps(snap))
            mutate(bad["subscription"]["windows"]["seven_day"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(bad)
        bad = json.loads(json.dumps(snap))
        bad["subscription"]["log"]["status"] = "weird"
        with self.assertRaises(contract.SnapshotError):
            contract.validate_snapshot(bad)
