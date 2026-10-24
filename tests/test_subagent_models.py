"""Subagent model mix and per-request parameters from fake transcripts; descriptions are never stored."""
import json
import os
from unittest import mock

from test_collect import FakeHome, collect
from test_privacy import PatchedHome, args
import privacy
import snapshot_contract as contract

NOW = 1789473600  # 2026-09-15 12:00 UTC
SECRET_DESCRIPTION = "UNIQUE-DESCRIPTION-TEXT sk-sentinel0123456789"


def stamp(offset=0):
    return collect.datetime.fromtimestamp(NOW + offset, collect.timezone.utc).isoformat()


def assistant(model, msg_id, tokens=(10, 0, 0, 5)):
    inp, write, read, out = tokens
    return {"type": "assistant", "isSidechain": True, "timestamp": stamp(),
            "message": {"id": msg_id, "model": model,
                        "usage": {"input_tokens": inp, "cache_creation_input_tokens": write,
                                  "cache_read_input_tokens": read, "output_tokens": out}}}


def api_request(source="repl_main_thread", model="claude-opus-5-5", effort="medium", thinking="adaptive",
                ttls=("1h", None), rid="r", session="s"):
    params = {"model": model, "betas": ["x"], "max_tokens": 1}
    if effort is not None:
        params["output_config"] = {"effort": effort}
    if thinking is not None:
        params["thinking"] = {"type": thinking}
    return {"type": "api-request", "sessionId": session, "id": rid, "timestamp": stamp(),
            "querySource": source, "shapeHash": "h", "params": params,
            "cacheControl": [{"path": ["a"], "value": dict({"type": "ephemeral"}, **({"ttl": t} if t else {}))}
                             for t in ttls]}


class SubagentModels(FakeHome):
    def transcript(self, rel, records):
        self.write(f".claude/projects/{rel}", "\n".join(map(json.dumps, records)))

    def agent(self, name, records, meta="default", proj="-a", session="sess"):
        self.transcript(f"{proj}/{session}/subagents/{name}.jsonl", records)
        if meta == "default":
            meta = {"agentType": "general-purpose", "description": SECRET_DESCRIPTION, "toolUseId": "toolu_x"}
        if meta is not None:
            self.write(f".claude/projects/{proj}/{session}/subagents/{name}.meta.json", meta)

    def scan(self, **kw):
        with mock.patch.object(collect.time, "time", return_value=NOW):
            return collect.collect_transcripts(1, **kw)

    def rows(self, **kw):
        return self.scan(**kw)["subagent_models"]["rows"]

    def test_passed_model_versus_absent_and_actual_model(self):
        self.agent("a1", [assistant("claude-opus-5-5", "m1", (1, 2, 3, 4))],
                   {"agentType": "general-purpose", "model": "opus"})
        self.agent("a2", [assistant("claude-sonnet-5-5", "m2", (1, 0, 0, 1))], {"agentType": "general-purpose"})
        rows = self.rows()
        self.assertEqual(rows, [
            {"agent_type": "general-purpose", "requested_model": "opus", "actual_model": "claude-opus-5-5",
             "spawns": 1, "tokens": 10},
            {"agent_type": "general-purpose", "requested_model": None, "actual_model": "claude-sonnet-5-5",
             "spawns": 1, "tokens": 2}])

    def test_actual_model_is_the_majority_and_tokens_dedupe_by_message_id(self):
        self.agent("a1", [assistant("claude-opus-5-5", "m1"), assistant("claude-opus-5-5", "m1"),  # chunk copy
                          assistant("claude-sonnet-5-5", "m2"), assistant("claude-sonnet-5-5", "m3")])
        (row,) = self.rows()
        self.assertEqual((row["actual_model"], row["tokens"]), ("claude-sonnet-5-5", 45))

    def test_rows_aggregate_spawns_by_key(self):
        for i in range(3):
            self.agent(f"a{i}", [assistant("claude-opus-5-5", f"m{i}")], {"agentType": "Explore"})
        (row,) = self.rows()
        self.assertEqual((row["agent_type"], row["spawns"], row["tokens"]), ("Explore", 3, 45))

    def test_missing_malformed_and_symlinked_meta_are_counted_and_tolerated(self):
        self.agent("none", [assistant("claude-opus-5-5", "m1")], None)
        self.agent("bad", [assistant("claude-opus-5-5", "m2")], "{not json")
        self.agent("list", [assistant("claude-opus-5-5", "m3")], "[1]")
        self.agent("huge", [assistant("claude-opus-5-5", "m4")], '{"agentType": "' + "x" * 70000 + '"}')
        outside = self.write("outside.json", {"agentType": "SYMLINK-TARGET"})
        self.agent("link", [assistant("claude-opus-5-5", "m5")], None)
        os.symlink(outside, os.path.join(self.claude, "projects/-a/sess/subagents/link.meta.json"))
        t = self.scan()["subagent_models"]
        self.assertEqual((t["meta_absent"], t["meta_unusable"]), (1, 4))
        self.assertEqual([(r["agent_type"], r["spawns"]) for r in t["rows"]], [(None, 5)])
        self.assertNotIn("SYMLINK-TARGET", json.dumps(t))

    def test_description_and_tool_use_id_are_never_stored(self):
        self.agent("a1", [assistant("claude-opus-5-5", "m1")],
                   {"agentType": "x", "description": SECRET_DESCRIPTION, "toolUseId": "toolu_SENTINEL",
                    "spawnDepth": 1, "requestShape": "background"})
        full = self.scan()
        full.pop("_harness")  # in-memory raw with tuple keys; consumed and dropped by build_snapshot
        text = json.dumps(full)
        self.assertNotIn("UNIQUE-DESCRIPTION-TEXT", text)
        self.assertNotIn("toolu_SENTINEL", text)

    def test_out_of_window_subagent_is_not_counted(self):
        old = assistant("claude-opus-5-5", "m1")
        old["timestamp"] = stamp(-3 * 86400)
        self.agent("old", [old])
        self.assertEqual(self.rows(), [])

    def test_row_cap_reports_omitted(self):
        for i in range(collect.SUBAGENT_ROW_LIMIT + 2):
            self.agent(f"a{i}", [assistant("claude-opus-5-5", f"m{i}")], {"agentType": f"agent{i:03d}"})
        t = self.scan()["subagent_models"]
        self.assertEqual((len(t["rows"]), t["omitted"]["rows"], t["omitted"]["spawns"]),
                         (collect.SUBAGENT_ROW_LIMIT, 2, 2))

    def test_request_params_by_source_class(self):
        self.transcript("-a/s.jsonl", [
            api_request("repl_main_thread", rid="1"), api_request("repl_main_thread", effort=None, rid="2"),
            api_request("sdk", model="claude-sonnet-5-5", rid="3", ttls=(None,)),
            api_request("agent:builtin:general-purpose", rid="4", thinking=None),
            api_request("agent:custom:plug:rev", rid="5"), api_request("something-else", rid="6")])
        p = self.scan()["request_params"]
        self.assertEqual({k: p[k]["requests"] for k in ("main", "sdk", "agent", "other")},
                         {"main": 2, "sdk": 1, "agent": 2, "other": 1})
        self.assertEqual(p["main"]["by_model"], [["claude-opus-5-5", 2]])
        self.assertEqual(p["main"]["by_thinking"], [["adaptive", 2]])
        self.assertEqual(p["agent"]["by_thinking"], [["adaptive", 1], [None, 1]])

    def test_effort_is_null_when_absent(self):
        self.transcript("-a/s.jsonl", [api_request(effort="medium", rid="1"), api_request(effort=None, rid="2"),
                                       api_request(effort=None, rid="3")])
        self.assertEqual(self.scan()["request_params"]["main"]["by_effort"], [[None, 2], ["medium", 1]])

    def test_ttl_classes_default_to_five_minutes(self):
        self.transcript("-a/s.jsonl", [api_request(ttls=("1h", None, "5m", "24h"))])
        self.assertEqual(self.scan()["request_params"]["main"]["cache_breakpoints"], {"1h": 1, "5m": 2, "other": 1})

    def test_requests_are_read_from_subagent_files_and_deduplicated(self):
        rec = api_request("agent:builtin:Explore", rid="dup", session="s9")
        self.transcript("-a/one.jsonl", [rec])
        self.transcript("-a/copy.jsonl", [rec])  # resumed copy, same session and id
        self.agent("a1", [api_request("agent:builtin:Explore", rid="other", session="s9")])
        self.assertEqual(self.scan()["request_params"]["agent"]["requests"], 2)

    def test_malformed_request_fields_are_tolerated(self):
        self.transcript("-a/s.jsonl", [
            {"type": "api-request", "timestamp": stamp(), "querySource": 7, "params": "junk", "cacheControl": 5},
            {"type": "api-request", "timestamp": stamp(), "querySource": "sdk", "params": {"model": ["x"],
             "output_config": [], "thinking": "adaptive"}, "cacheControl": ["a", {"value": 3}, {"value": {"ttl": 1}}]}])
        p = self.scan()["request_params"]
        self.assertEqual((p["other"]["requests"], p["sdk"]["requests"]), (1, 1))
        self.assertEqual(p["sdk"]["by_model"], [[None, 1]])

    def test_only_fixed_fields_are_stored(self):
        rec = api_request(rid="r1")
        rec["params"]["system"] = "SYSTEM-PROMPT-SENTINEL"
        rec["requestDigest"] = "DIGEST-SENTINEL"
        self.transcript("-a/s.jsonl", [rec, {"type": "api-request-blob", "timestamp": stamp(),
                                              "content": "BLOB-SENTINEL"}])
        full = self.scan()
        full.pop("_harness")
        text = json.dumps(full)
        for s in ("SYSTEM-PROMPT-SENTINEL", "DIGEST-SENTINEL", "BLOB-SENTINEL", '"shapeHash"'):
            self.assertNotIn(s, text)


class SubagentModelSnapshot(PatchedHome):
    def snapshot(self, **kw):
        return collect.build_snapshot(args(**kw))

    def seed(self):
        self.write(".claude/projects/-a/sess/subagents/a1.jsonl", json.dumps(assistant("claude-opus-5-5", "m1")))
        self.write(".claude/projects/-a/sess/subagents/a1.meta.json",
                   {"agentType": "acme:reviewer", "model": "opus", "description": SECRET_DESCRIPTION})
        self.write(".claude/projects/-a/s.jsonl", "\n".join(json.dumps(api_request(src, rid=src)) for src in (
            "repl_main_thread", "sdk", "agent:builtin:Explore", "other")))

    def test_configured_reports_env_key_names_only(self):
        self.write(".claude/settings.json", {"env": {"CLAUDE_CODE_SUBAGENT_MODEL": "SECRET-VALUE-XYZ"}})
        snap = self.snapshot()
        self.assertEqual(snap["transcripts"]["subagent_models"]["configured"],
                         {"model_env": True, "force_env": False})
        self.assertNotIn("SECRET-VALUE-XYZ", json.dumps(snap["transcripts"]))

    def test_force_env_detected_and_default_false(self):
        self.assertEqual(self.snapshot()["transcripts"]["subagent_models"]["configured"],
                         {"model_env": False, "force_env": False})
        self.write(".claude/settings.json", {"env": {"CLAUDE_CODE_SUBAGENT_MODEL_FORCE": "1"}})
        self.assertTrue(self.snapshot()["transcripts"]["subagent_models"]["configured"]["force_env"])

    def test_metadata_only_keeps_names_and_counts_but_not_descriptions(self):
        self.seed()
        snap = self.snapshot(metadata_only=True, days=36500)
        (row,) = snap["transcripts"]["subagent_models"]["rows"]
        self.assertEqual((row["agent_type"], row["requested_model"], row["actual_model"], row["spawns"]),
                         ("acme:reviewer", "opus", "claude-opus-5-5", 1))
        self.assertEqual(snap["transcripts"]["request_params"]["main"]["by_model"], [["claude-opus-5-5", 1]])
        text = json.dumps(snap)
        self.assertNotIn("UNIQUE-DESCRIPTION-TEXT", text)
        self.assertEqual(snap["coverage"]["privacy"]["replaced_fields"].get("unclassified", 0), 0)

    def test_every_kept_pattern_is_reached(self):
        self.seed()
        meta = self.snapshot(metadata_only=True, days=36500)
        paths = [p for p, v in privacy.leaves(meta) if isinstance(v, str) and not privacy.MARKER_RE.match(v)]
        self.assertEqual([pat for pat in privacy.SUBAGENT_KEEP
                          if "basis" not in pat[-1] and not any(privacy.path_matches(p, pat) for p in paths)], [])

    def test_snapshot_validates_against_schema(self):
        self.seed()
        contract.validate_snapshot(self.snapshot(days=36500))
