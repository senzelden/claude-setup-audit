"""Whole-branch review fixes for 0.12.0: malformed ids, drift server choice, spawned-session scope,
shared failure_loops ledger pass, permission-gate anchoring. Fake homes only."""
import builtins
import json
import os
from unittest import mock

from test_collect import FakeHome, collect  # also puts the plugin scripts directory on sys.path
import drift
import ledger
from test_failure_loops import Base, NOW, call, flat, nid, prompt, result, run, stamp
from test_plugin_footprint import observer_key


def malformed_records():
    """Records whose id fields have the wrong JSON type; a scan must skip them, not crash."""
    bad_call = {"type": "assistant", "timestamp": stamp(1), "message": {
        "id": ["m"], "usage": {"input_tokens": 5}, "content": [
            {"type": "tool_use", "id": ["t"], "name": "Bash", "input": {"command": "make x"}},
            {"type": "tool_use", "id": {"a": 1}, "name": "Edit", "input": {"file_path": "/r/a.py"}}]}}
    bad_result = {"type": "user", "timestamp": stamp(2), "message": {"content": [
        {"type": "tool_result", "tool_use_id": ["t"], "content": "x", "is_error": True},
        {"type": "tool_result", "tool_use_id": {"a": 1}, "content": "x"}]}}
    return [prompt(), bad_call, bad_result, dict(bad_call, message=dict(bad_call["message"], id={"k": 1}))]


class MalformedIds(Base):
    def test_main_scan_survives_list_and_dict_ids(self):
        t = self.one(malformed_records())
        self.assertEqual(t["turns_scanned"], 1)

    def test_harness_record_survives_list_message_id(self):
        raw = {"main_tokens": collect.defaultdict(int), "sub_tokens": collect.defaultdict(int)}
        seen = set()
        for record in malformed_records()[1::2]:
            collect.harness_record(raw, record, "p", ("k", "s"), True, seen)
        self.assertEqual(raw["main_tokens"][("k", "s")], 10)  # unhashable ids are never deduplicated

    def test_ledger_failure_loops_selector_survives(self):
        self.transcript("-a/s.jsonl", malformed_records())
        with mock.patch.object(collect.time, "time", return_value=NOW):
            c = collect.count_selector({"type": "failure_loops", "kind": "any"}, NOW - 3600, NOW, None)
        self.assertEqual((c["matches"], c["complete"]), (0, True))


class DriftServerChoice(FakeHome):
    def snap(self, servers, observed=100):
        rows = [{"server": n, "sessions_failed": f, "sessions_pending": 0, "sessions_present": p, "error_codes": []}
                for n, f, p in servers]
        return {"global": {}, "projects": {}, "transcripts": {"cache": {"hit_ratio": None},
                "mcp_failures": {"sessions_observed": observed, "servers": rows}}}

    def cross(self, snap):
        signals, fps = drift.derive(snap, "g")
        meta = {"scope": "all", "project": None, "window_days": 30}
        return signals, drift.compare(signals, fps, [], meta,
                                      {"claude_md_max_lines": 200, "cache_hit_min": 0.9, "growth_min": 0.25})

    def test_a_server_crossing_both_thresholds_is_not_masked_by_a_bigger_count(self):
        signals, crossings = self.cross(self.snap([("big", 10, 100), ("small", 5, 5)]))
        self.assertEqual(signals["mcp_failures"]["server"], "small")
        (c,) = crossings
        self.assertEqual((c["server"], c["share"]), ("small", 1.0))

    def test_summary_prints_the_denominator_the_share_uses(self):
        _, crossings = self.cross(self.snap([("small", 5, 6)], observed=100))
        line = drift.summary_line(crossings, "~/d.jsonl")
        self.assertIn("failed in 5 of 6 sessions", line)
        self.assertNotIn("of 100", line)


class SpawnedSessions(Base):
    def test_spawned_cwd_is_not_a_project_root(self):
        spawn = os.path.join(self.home, ".claude-mem", "observer-sessions", "abc123")
        real = os.path.join(self.home, "work", "app")
        os.makedirs(spawn)
        os.makedirs(real)
        self.write(".claude/projects/-a/s.jsonl", json.dumps({"type": "user", "cwd": real}))
        self.write(".claude/projects/-o/s.jsonl", json.dumps({"type": "user", "cwd": spawn}))
        self.write(".claude/usage-data/session-meta/m.json", {"project_path": spawn})
        self.assertEqual(collect.discover_projects(), [real])

    def spawned_records(self):
        c, tid = call("Bash", {"command": "uv run pytest -q"})
        r = result(tid, "KeyError: 'DATABASE_URL'")
        m = {"type": "assistant", "timestamp": stamp(3), "message": {"id": nid(), "content": [
            {"type": "tool_use", "id": "m1", "name": "mcp__srv__q", "input": {}}]}}
        return [prompt(), c, r, m]

    def test_spawned_sessions_do_not_feed_env_test_time_or_mcp_calls(self):
        self.transcript(observer_key(self) + "/o.jsonl", self.spawned_records())
        self.transcript("-a/s.jsonl", self.spawned_records())
        with mock.patch.object(collect.time, "time", return_value=NOW):
            t = collect.collect_transcripts(1)
        self.assertEqual(list(t["env_error_hits_by_project"].values()), [1])
        self.assertEqual(list(t["test_run_seconds_by_project"]), ["-a"])
        self.assertEqual(dict(t["mcp_calls_by_server"]), {"srv": 1})


class LoopLedgerPass(Base):
    def entry(self, n, kind):
        sel = {"type": "failure_loops", "kind": kind}
        return dict(id=f"L-20260901-{n}", applied_at=ledger.iso(NOW - 3000), run="r", finding_id="LRN-x", pattern="p",
                    mechanism="rule", state="active", supersedes=None, selector=sel,
                    scope=dict(scope="all", project=None, window_days=30),
                    baseline={"from": "2026-08-01T00:00:00Z", "to": "2026-09-01T00:00:00Z", "matches": 3,
                              "sessions_matched": 3, "sessions_scanned": 9, "complete": True},
                    edits=[dict(file="~/x.md", kind="markdown_block", sha256="a" * 64, backup=None)],
                    observations=[])

    def book(self, kinds=("any", "edit_test", "repeat_error")):
        path = os.path.join(self.claude, "audits", "ledger.json")
        ledger.dump(dict(version=1, entries=[self.entry(i + 1, k) for i, k in enumerate(kinds)]), path)
        return path

    def signals(self, path):
        with mock.patch.object(collect.time, "time", return_value=NOW):
            return collect.collect_ledger_signals(path, 30, None)["entries"]

    def reads(self, fn):
        real, seen = builtins.open, []

        def spy(file, *a, **k):
            if str(file).endswith(".jsonl"):
                seen.append(str(file))
            return real(file, *a, **k)
        with mock.patch.object(builtins, "open", spy):
            out = fn()
        return out, seen

    def plant(self):
        self.transcript("-a/new.jsonl", [prompt()] + flat(*[run("make build", True) for _ in range(3)]))
        return os.path.join(self.claude, "projects", "-a", "new.jsonl")

    def test_k_entries_read_each_transcript_once(self):
        path = self.plant()
        book = self.book()
        out, seen = self.reads(lambda: self.signals(book))
        self.assertEqual(seen.count(path), 1)
        self.assertEqual([out[f"L-20260901-{i}"]["matches"] for i in (1, 2, 3)], [1, 0, 1])

    def test_files_older_than_the_window_are_not_read(self):
        path = self.plant()
        old = NOW - 2 * 86400
        os.utime(path, (old, old))
        book = self.book(("any",))
        out, seen = self.reads(lambda: self.signals(book))
        self.assertEqual(seen, [])
        self.assertEqual(out["L-20260901-1"]["sessions_scanned"], 0)

    def test_file_cap_marks_counts_incomplete(self):
        self.plant()
        self.transcript("-b/new.jsonl", [prompt()] + flat(*[run("make build", True) for _ in range(3)]))
        book = self.book(("any",))
        with mock.patch.object(collect, "MAX_LOOP_FILES", 1):
            out = self.signals(book)
        self.assertFalse(out["L-20260901-1"]["complete"])
        self.assertEqual(out["L-20260901-1"]["sessions_scanned"], 1)


class GateAnchoring(FakeHome):
    def test_tool_errors_that_only_mention_a_block_or_approval_are_not_gates(self):
        for text in ("Request was blocked by proxy (403)", "MCP error: the request was blocked by policy engine",
                     "WebFetch failed: domain requires approval from admin", "network blocked"):
            with self.subTest(text=text):
                self.assertNotEqual(collect.tool_error_category(text), "permission_gate")
                self.assertFalse(collect.tool_error_denied(text))
