"""Per-tool and per-MCP-server tool-error clustering from fake transcripts; error text is never stored."""
import json
from unittest import mock
from test_collect import FakeHome, collect

NOW = 1789473600  # 2026-09-15 12:00 UTC


def stamp(offset=0):
    return collect.datetime.fromtimestamp(NOW + offset, collect.timezone.utc).isoformat()


def use(tid, name, session="s"):
    return {"type": "assistant", "sessionId": session, "timestamp": stamp(),
            "message": {"content": [{"type": "tool_use", "id": tid, "name": name, "input": {}}]}}


def result(tid, text, is_error=True, session="s", offset=0):
    item = {"type": "tool_result", "tool_use_id": tid, "content": text}
    if is_error is not None:
        item["is_error"] = is_error
    return {"type": "user", "sessionId": session, "timestamp": stamp(offset), "message": {"content": [item]}}


class ToolErrors(FakeHome):
    def transcript(self, rel, records):
        self.write(f".claude/projects/{rel}", "\n".join(map(json.dumps, records)))

    def scan_errors(self, full=False):  # not `run`: that would override unittest.TestCase.run
        with mock.patch.object(collect.time, "time", return_value=NOW):
            t = collect.collect_transcripts(1)
        return t if full else t["tool_errors"]

    def test_builtin_counts_rate_and_denials(self):
        self.transcript("-a/s.jsonl", [use(f"b{i}", "Bash") for i in range(6)] + [
            result("b0", "Exit code 1\nboom"), result("b1", "Exit code 2"),
            result("b2", "Permission to use Bash with command x has been denied."),
            result("b3", "ok", is_error=False)])
        t = self.scan_errors()
        self.assertEqual(t["by_tool"], [{"tool": "Bash", "calls": 6, "errors": 3, "denied": 1, "failure_rate": 0.333,
                                         "categories": {"nonzero_exit": 2, "permission_denied": 1}}])
        self.assertEqual((t["error_results_paired"], t["error_results_unmatched"], t["results_without_is_error"]),
                         (3, 0, 0))
        self.assertEqual(t["min_calls_for_rate"], 5)

    def test_mcp_servers_cluster_with_failing_tools(self):
        self.transcript("-a/s.jsonl", [use(f"c{i}", "mcp__github__create_issue") for i in range(3)]
                        + [use(f"r{i}", "mcp__github__read") for i in range(2)]
                        + [use("q0", "mcp__plugin_demo_db__query")]
                        + [result("c0", [{"type": "text", "text": "MCP error -32001: 401 Unauthorized"}]),
                           result("c1", "403 Forbidden"), result("q0", "connect ECONNREFUSED 127.0.0.1:5432")])
        t = self.scan_errors()
        self.assertEqual(t["by_mcp_server"], [
            {"server": "github", "top_error_tools": [["create_issue", 2]], "calls": 5, "errors": 2, "denied": 0,
             "failure_rate": 0.4, "categories": {"auth": 2}},
            {"server": "plugin_demo_db", "top_error_tools": [["query", 1]], "calls": 1, "errors": 1, "denied": 0,
             "failure_rate": None, "categories": {"connection": 1}}])
        self.assertEqual(t["by_tool"], [])

    def test_unmatched_and_unflagged_results(self):
        self.transcript("-a/s.jsonl", [use("a", "Read"), result("zzz", "File does not exist."),
                                       result("a", "fine", is_error=None)])
        t = self.scan_errors()
        self.assertEqual((t["error_results_paired"], t["error_results_unmatched"], t["results_without_is_error"]),
                         (0, 1, 1))
        self.assertEqual(t["by_tool"], [])

    def test_error_text_is_never_stored(self):
        self.transcript("-a/s.jsonl", [use("x", "Bash"),
                                       result("x", "Exit code 1 sk-sentinel0123456789 UNIQUE-ERROR-TEXT")])
        full = self.scan_errors(full=True)
        full.pop("_harness", None)  # in-memory raw with tuple keys; consumed and dropped by build_snapshot
        text = json.dumps(full, default=str)
        self.assertNotIn("sk-sentinel0123456789", text)
        self.assertNotIn("UNIQUE-ERROR-TEXT", text)

    def test_server_and_tool_segments_are_redacted_and_capped(self):
        secret = "sk-sentinel0123456789abcdef"
        long_tool = "t" * 200
        self.transcript("-a/s.jsonl", [use("m1", f"mcp__{secret}__{long_tool}"), result("m1", "Exit code 1")])
        t = self.scan_errors()
        text = json.dumps(t)
        self.assertNotIn(secret, text)
        (server,) = t["by_mcp_server"]
        self.assertLessEqual(len(server["server"]), collect.MCP_NAME_CAP)
        self.assertLessEqual(len(server["top_error_tools"][0][0]), 64)

    def test_malformed_records_are_skipped(self):
        good = [use("g", "Bash"), result("g", "Exit code 1")]
        bad = [
            {"type": "assistant", "timestamp": stamp(), "message": {"content": "not a list"}},
            {"type": "user", "timestamp": stamp(), "message": "string message"},
            {"type": "assistant", "timestamp": stamp(), "message": {"content": [
                "junk", 5, None, {"type": "tool_use", "name": 7, "id": "n"},
                {"type": "tool_use", "name": "Bash"},  # missing id: counted, cannot pair
                {"type": "tool_result", "is_error": True, "content": None},  # missing id: unmatched
                {"type": "tool_result", "tool_use_id": ["x"], "is_error": True}]}},
        ]
        self.transcript("-a/s.jsonl", bad + good)
        t = self.scan_errors()
        self.assertEqual([(r["tool"], r["calls"], r["errors"]) for r in t["by_tool"]], [("Bash", 2, 1)])
        self.assertEqual(t["error_results_unmatched"], 2)

    def test_dedup_window_and_subagents(self):
        failing = [use("d", "Edit", session="s1"),
                   result("d", "<tool_use_error>String to replace not found</tool_use_error>", session="s1")]
        self.transcript("-a/s1.jsonl", failing)
        self.transcript("-a/copy.jsonl", failing)  # resumed copy, same sessionId
        self.transcript("-a/old.jsonl", [use("o", "Edit", session="s2"),
                                         result("o", "Exit code 1", session="s2", offset=-2 * 86400)])
        self.transcript("-a/sess/subagents/agent-1.jsonl", [use("g", "Grep", session="s9"),
                                                            result("g", "Exit code 2", session="s9")])
        t = self.scan_errors()
        self.assertEqual([(r["tool"], r["calls"], r["errors"], r["categories"]) for r in t["by_tool"]],
                         [("Edit", 2, 1, {"file_state": 1}), ("Grep", 1, 1, {"nonzero_exit": 1})])

    def test_tool_cap(self):
        records = []
        for i in range(17):
            records += [use(f"t{i}", f"Tool{i:02d}"), result(f"t{i}", "Exit code 1")]
        self.transcript("-a/s.jsonl", records)
        t = self.scan_errors()
        self.assertEqual((len(t["by_tool"]), t["omitted"]["tools"], t["by_tool"][0]["tool"]), (15, 2, "Tool00"))

    def test_categories_are_ordered_first_match(self):
        cases = [
            ("Exit code 1\nbwrap: setting up uid map: Permission denied", "sandbox"),
            ("Exit code 2\nls: cannot access 'x': No such file or directory", "nonzero_exit"),
            ("Exit code 124\nCommand timed out after 2m", "timeout"),
            ("The user doesn't want to proceed with this tool use.", "user_rejected"),
            ("Permission to use Bash with command rm -rf x has been denied.", "permission_denied"),
            ("<tool_use_error>InputValidationError: Edit failed</tool_use_error>", "validation"),
            ("<tool_use_error>File has not been read yet. Read it first.</tool_use_error>", "file_state"),
            ("File does not exist. Note: your current working directory is /x.", "not_found"),
            ("File content (3.2MB) exceeds maximum allowed size (256KB).", "too_large"),
            ([{"type": "text", "text": "MCP error -32001: 401 Unauthorized"}], "auth"),
            ([{"type": "text", "text": "MCP error -32000: Connection closed"}], "connection"),
            ("Something unexpected", "other"),
            (None, "other")]
        for content, want in cases:
            self.assertEqual(collect.tool_error_category(content), want, content)
