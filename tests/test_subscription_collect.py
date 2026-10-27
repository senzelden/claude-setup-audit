"""Snapshot `subscription` from fake homes: documented limit messages in transcripts, model mix by family
and the documented extra-usage settings. Only kinds, session keys and UTC dates are kept, never text."""
import json
import time

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
        self.assertEqual(mix["main"]["opus"], {"requests": 3, "share": 0.75})
        self.assertEqual(mix["main"]["sonnet"], {"requests": 1, "share": 0.25})
        self.assertEqual(mix["main"]["fable"], {"requests": 0, "share": 0.0})
        self.assertEqual(mix["agent"]["haiku"], {"requests": 1, "share": 1.0})
        self.assertIn("api-request", mix["basis"])

    def test_model_mix_uses_full_counters_not_capped_rows(self):
        models = [f"claude-sonnet-x{i}" for i in range(collect.REQUEST_MODEL_LIMIT + 3)]
        self.put("-a", "s1", [api_request(m, f"r{i}") for i, m in enumerate(models)])
        snap = collect.build_snapshot(args())
        self.assertGreater(snap["transcripts"]["request_params"]["main"]["omitted_models"], 0)
        self.assertEqual(snap["subscription"]["model_mix"]["main"]["sonnet"]["requests"], len(models))

    def test_no_requests_gives_null_shares(self):
        self.assertEqual(self.sub()["model_mix"]["main"]["opus"], {"requests": 0, "share": None})


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
        self.put("-a", "s1", [synthetic(WEEKLY), api_request("claude-opus-5-5", "r1")])

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
                       lambda s: s["model_mix"]["main"]["opus"].update(requests=-1)):
            bad = json.loads(json.dumps(snap))
            mutate(bad["subscription"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(bad)
