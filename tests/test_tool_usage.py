"""Tool usage and MCP connection failures from fake transcripts (deferred_tools_delta, observed and
undocumented). Names and counts only: error text never appears, spawned sessions are excluded."""
import contextlib
import io
import json
import os
import time

from test_collect import FakeHome, collect
from test_plugin_footprint import observer_key
from test_privacy import PatchedHome, args
import drift
import privacy
import tool_usage

SECRET = "token=ZZ-canary-error-text"


def stamp():
    return collect.datetime.fromtimestamp(time.time(), collect.timezone.utc).isoformat()


def delta(added=(), failed=(), pending=(), surfaced=(), readded=()):
    return {"type": "attachment", "timestamp": stamp(), "sessionId": "s", "attachment": {
        "type": "deferred_tools_delta", "addedNames": list(added), "addedLines": [], "removedNames": [],
        "wireHiddenNames": [], "readdedNames": list(readded), "surfacedNames": list(surfaced),
        "pendingMcpServers": list(pending), "failedMcpServers": list(failed)}}


def failure(name, code="ENDPOINT_NOT_FOUND", error=SECRET):
    return {"name": name, "errorCode": code, "error": error}


def calls(*names):
    return {"type": "assistant", "timestamp": stamp(), "sessionId": "s", "message": {"content": [
        {"type": "tool_use", "id": f"t{i}", "name": n, "input": {}} for i, n in enumerate(names)]}}


class Base(PatchedHome):
    def put(self, key, name, records):
        self.write(f".claude/projects/{key}/{name}.jsonl", "\n".join(json.dumps(r) for r in records))

    def scan(self):
        return collect.collect_transcripts(days=30)


class Usage(Base):
    def test_used_sessions_are_counted_once_per_session_and_never_called_tools_are_listed(self):
        self.put("-a", "s1", [delta(added=["mcp__x__read", "mcp__x__write", "Cron"]),
                              calls("Bash", "Bash", "mcp__x__read"), calls("Bash")])
        self.put("-a", "s2", [delta(added=["mcp__x__write"]), calls("Bash")])
        tu = self.scan()["tool_usage"]
        self.assertEqual({r["tool"]: r["sessions"] for r in tu["used"]}, {"Bash": 2, "mcp__x__read": 1})
        self.assertEqual({r["tool"]: r["sessions_listed"] for r in tu["listed_never_called"]},
                         {"Cron": 1, "mcp__x__write": 2})
        self.assertEqual((tu["sessions"], tu["sessions_with_deferred_records"]), (2, 2))
        self.assertIn("Always-loaded built-in tools are not listed", tu["basis"])

    def test_sessions_without_records_count_but_say_nothing_about_listing(self):
        self.put("-a", "s1", [calls("Bash")])
        tu = self.scan()["tool_usage"]
        self.assertEqual((tu["sessions"], tu["sessions_with_deferred_records"], tu["listed_never_called"]),
                         (1, 0, []))

    def test_spawned_sessions_are_excluded_and_own_subagent_calls_count_as_use(self):
        self.put("-a", "s1", [delta(added=["T1", "T4", "T5"]), calls("Bash")])
        self.put(observer_key(self), "o1", [delta(added=["T2"], failed=[failure("srv")]), calls("Spawned", "T5")])
        self.put(observer_key(self) + "/o1/subagents", "agent-9", [calls("T1")])
        self.put("-a/s1/subagents", "agent-1", [delta(added=["T3"], failed=[failure("sub")]), calls("T4")])
        t = self.scan()
        tu = t["tool_usage"]
        # used[] stays main-thread; the subagent's T4 only clears it from never-called.
        self.assertEqual([r["tool"] for r in tu["used"]], ["Bash"])
        self.assertEqual(sorted(r["tool"] for r in tu["listed_never_called"]), ["T1", "T5"])
        self.assertEqual((tu["sessions"], tu["sessions_with_deferred_records"]), (1, 1))
        self.assertEqual(t["mcp_failures"]["servers"], [])
        self.assertIn("subagent", tu["basis"])

    def test_tool_search_observed_ignores_spawned_and_subagent_records(self):
        self.put("-a", "s1", [calls("Bash")])
        self.put(observer_key(self), "o1", [delta(added=["T"])])
        self.assertIs(self.scan()["tool_search_observed"], False)
        self.put("-a", "s2", [delta(added=["T"])])
        self.assertIs(self.scan()["tool_search_observed"], True)

    def test_tool_search_observed_is_null_with_only_spawned_sessions(self):
        self.put(observer_key(self), "o1", [delta(added=["T"])])
        self.assertIsNone(self.scan()["tool_search_observed"])

    def test_a_tool_called_in_another_session_is_not_never_called(self):
        self.put("-a", "s1", [delta(added=["T1"])])
        self.put("-a", "s2", [calls("T1")])
        self.assertEqual(self.scan()["tool_usage"]["listed_never_called"], [])

    def test_rows_are_capped_with_omitted_counts(self):
        names = [f"Tool{i:03d}" for i in range(tool_cap() + 5)]
        self.put("-a", "s1", [delta(added=names), calls(*names[:1])])
        tu = self.scan()["tool_usage"]
        self.assertEqual((len(tu["listed_never_called"]), tu["listed_never_called_omitted"],
                          tu["listed_never_called_total"]), (tool_cap(), 4, tool_cap() + 4))

    def test_used_rows_are_capped_with_omitted_count_and_stable_order(self):
        names = [f"Used{i:03d}" for i in range(tool_cap() + 3)]
        self.put("-a", "s1", [calls(*names)])
        self.put("-a", "s2", [calls(names[-1])])
        tu = self.scan()["tool_usage"]
        self.assertEqual((len(tu["used"]), tu["used_omitted"], tu["used"][0]), (tool_cap(), 3, {"tool": names[-1], "sessions": 2}))

    def test_old_records_outside_the_window_and_odd_shapes_are_ignored(self):
        old = delta(added=["Old"])
        old["timestamp"] = "2020-01-01T00:00:00+00:00"
        odd = {"type": "attachment", "timestamp": stamp(), "attachment": {
            "type": "deferred_tools_delta", "addedNames": "nope", "failedMcpServers": [1, {"name": 5}, "x"],
            "pendingMcpServers": {"a": 1}}}
        self.put("-a", "s1", [old, odd, calls("Bash")])
        t = self.scan()
        self.assertEqual(t["tool_usage"]["listed_never_called"], [])
        self.assertEqual(t["mcp_failures"]["servers"], [])


def tool_cap():
    return tool_usage.ROW_CAP


class Failures(Base):
    def test_per_server_session_counts_and_code_classes_without_error_text(self):
        self.put("-a", "s1", [delta(failed=[failure("plugin:data:definite")]),
                              delta(failed=[failure("plugin:data:definite")], pending=["slow"])])
        self.put("-a", "s2", [delta(failed=[failure("plugin:data:definite", "TIMEOUT"), failure("other-srv", "bad code!")])])
        self.put("-a", "s3", [delta(added=["T"])])
        f = self.scan()["mcp_failures"]
        self.assertEqual(f["sessions_observed"], 3)
        rows = {r["server"]: r for r in f["servers"]}
        d = rows["plugin:data:definite"]
        self.assertEqual((d["sessions_failed"], d["sessions_pending"]), (2, 0))
        self.assertEqual({c["code"]: c["sessions"] for c in d["error_codes"]}, {"ENDPOINT_NOT_FOUND": 1, "TIMEOUT": 1})
        self.assertEqual((rows["slow"]["sessions_failed"], rows["slow"]["sessions_pending"]), (0, 1))
        self.assertEqual(rows["other-srv"]["error_codes"], [{"code": "other", "sessions": 1}])
        self.assertNotIn(SECRET, json.dumps(f))
        self.assertNotIn("bad code!", json.dumps(f))

    def test_needs_auth_servers_are_counted_by_name(self):
        rec = delta()
        rec["attachment"]["needsAuthMcpServers"] = ["claude.ai Gmail", {"name": "docs"}, 7]
        self.put("-a", "s1", [rec])
        self.put("-a", "s2", [rec])
        rows = {r["server"]: r for r in self.scan()["mcp_failures"]["servers"]}
        self.assertEqual({k: v["sessions_needs_auth"] for k, v in rows.items()}, {"claude.ai Gmail": 2, "docs": 2})
        self.assertEqual(rows["docs"]["sessions_failed"], 0)

    def test_sessions_present_counts_sessions_where_the_server_appears_or_has_tools(self):
        self.put("-a", "s1", [delta(failed=[failure("plugin:data:definite")])])
        self.put("-a", "s2", [delta(added=["mcp__plugin_data_definite__q"])])
        self.put("-a", "s3", [delta(added=["mcp__other__q"]), calls("mcp__plugin_data_definite__q")])
        self.put("-a", "s4", [delta(added=["mcp__other__q"])])
        (row,) = self.scan()["mcp_failures"]["servers"]
        self.assertEqual((row["sessions_failed"], row["sessions_present"]), (1, 3))

    def test_names_that_are_not_identifier_like_are_dropped(self):
        self.put("-a", "s1", [delta(failed=[failure("/home/user/secret-server"), failure("x" * 500)],
                                    pending=["../etc"])])
        self.assertEqual(self.scan()["mcp_failures"]["servers"], [])

    def test_snapshot_joins_configured_names(self):
        self.write(".claude/settings.json", {})
        root = os.path.join(self.home, "repo")
        self.write("repo/.mcp.json", {"mcpServers": {"github": {"command": "x"}}})
        self.write(".claude.json", {"mcpServers": {"usersrv": {"command": "x"}}})  # user scope is not read
        self.put("-a", "s1", [delta(failed=[failure("github"), failure("usersrv"), failure("ghost")])])
        snap = collect.build_snapshot(args(roots=[root]))
        rows = {r["server"]: r for r in snap["transcripts"]["mcp_failures"]["servers"]}
        self.assertEqual((rows["github"]["configured"], rows["usersrv"]["configured"], rows["ghost"]["configured"]),
                         (True, False, False))

    def test_unused_covers_project_managed_and_plugin_servers(self):
        root = os.path.join(self.home, "repo")
        self.write("repo/.mcp.json", {"mcpServers": {"projsrv": {"command": "x"}}})
        self.write("managed/managed-mcp.json", {"mcpServers": {"orgsrv": {"command": "x"}}})
        plugin_root = os.path.join(self.claude, "plugins/cache/m/demo/1")
        self.write(".claude/plugins/installed_plugins.json", {"plugins": {
            "demo@m": [{"scope": "user", "installPath": plugin_root}]}})
        self.write(".claude/plugins/cache/m/demo/1/.claude-plugin/plugin.json",
                   {"name": "demo", "mcpServers": {"inl": {"command": "x"}}})
        self.put("-a", "s1", [calls("mcp__usedsrv__q", "mcp__projsrv__q")])
        snap = collect.build_snapshot(args(roots=[root]))
        unused = snap["transcripts"]["mcp_configured_but_unused"]
        self.assertEqual(unused, ["orgsrv", "plugin_demo_inl"])
        self.put("-a", "s1", [calls("mcp__orgsrv__q", "mcp__plugin_demo_inl__q", "mcp__projsrv__q")])
        snap = collect.build_snapshot(args(roots=[root]))
        self.assertEqual(snap["transcripts"]["mcp_configured_but_unused"], [])
        note = snap["transcripts"]["mcp_configured_but_unused_note"]
        self.assertIn("managed", note)
        self.assertIn("plugins", note)


class Privacy(Base):
    def setUp(self):
        super().setUp()
        self.put("-a", "s1", [delta(added=["mcp__x__never", "Cron"], failed=[failure("plugin:data:definite", "bad code!")]),
                              calls("Bash")])

    def keep(self, **kw):
        snap = collect.build_snapshot(args(**kw))
        return snap["transcripts"]

    def test_metadata_only_keeps_names_and_codes_but_not_error_text(self):
        t = self.keep(metadata_only=True)
        self.assertEqual([r["tool"] for r in t["tool_usage"]["used"]], ["Bash"])
        self.assertEqual([r["tool"] for r in t["tool_usage"]["listed_never_called"]], ["Cron", "mcp__x__never"])
        self.assertEqual(t["mcp_failures"]["servers"][0]["server"], "plugin:data:definite")
        self.assertEqual(t["mcp_failures"]["servers"][0]["error_codes"][0]["code"], "other")
        self.assertNotIn(SECRET, json.dumps(t))

    def test_every_string_leaf_of_the_new_fields_is_classified(self):
        t = collect.build_snapshot(args())["transcripts"]
        for key in ("tool_usage", "mcp_failures"):
            for path, v in privacy.leaves({"transcripts": {key: t[key]}}):
                if isinstance(v, str):
                    self.assertTrue(privacy.is_kept(path), path)

    def test_hash_paths_leaves_names_unchanged(self):
        before = collect.build_snapshot(args())["transcripts"]
        snap = {"transcripts": {k: before[k] for k in ("tool_usage", "mcp_failures")}}
        dump = json.dumps(snap)
        privacy.hash_paths(snap, privacy.PathHasher(b"k" * 16, self.home), [])
        self.assertEqual(json.dumps(snap), dump)


class DriftSignal(FakeHome):
    def snap(self, failed, observed, extra=()):
        servers = [{"server": "srv", "sessions_failed": failed, "sessions_pending": 0, "error_codes": []}, *extra]
        return {"global": {}, "projects": {}, "transcripts": {"cache": {"hit_ratio": None},
                "mcp_failures": {"sessions_observed": observed, "servers": servers}}}

    def cross(self, snap):
        signals, fps = drift.derive(snap, "g")
        return signals, drift.compare(signals, fps, [], {"scope": "all", "project": None, "window_days": 30},
                                      {"claude_md_max_lines": 200, "cache_hit_min": 0.9, "growth_min": 0.25})

    def test_server_failing_in_many_sessions_crosses(self):
        signals, crossings = self.cross(self.snap(4, 6))
        self.assertEqual(signals["mcp_failures"]["value"], 4)
        (c,) = crossings
        self.assertEqual((c["signal"], c["kind"], c["server"], c["share"]), ("mcp_failures", "high_failure_rate", "srv", 0.667))
        self.assertIn("MCP server srv failed in 4 of 6", drift.summary_line(crossings, "~/d.jsonl"))

    def test_few_sessions_or_low_share_do_not_cross(self):
        self.assertEqual(self.cross(self.snap(2, 2))[1], [])  # below 3 sessions
        self.assertEqual(self.cross(self.snap(3, 10))[1], [])  # below half

    def test_share_uses_sessions_where_the_server_appears(self):
        snap = self.snap(3, 20)
        snap["transcripts"]["mcp_failures"]["servers"][0]["sessions_present"] = 3
        signals, crossings = self.cross(snap)
        self.assertEqual((signals["mcp_failures"]["share"], signals["mcp_failures"]["sessions_present"]), (1.0, 3))
        self.assertEqual(len(crossings), 1)

    def test_no_records_is_null(self):
        self.assertIsNone(self.cross(self.snap(0, 5))[0]["mcp_failures"])
        self.assertIsNone(drift.derive({"global": {}, "projects": {}, "transcripts": {}}, "g")[0]["mcp_failures"])


class DriftCliFlags(FakeHome):
    def run_drift(self, *extra):
        out = io.StringIO()
        log = os.path.join(self.home, "drift.jsonl")
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = drift.main(["--claude-dir", self.claude, "--log", log, *extra])
        return code, out.getvalue()

    def setUp(self):
        super().setUp()
        for i in range(2):  # two failing sessions of five with records
            self.write(f".claude/projects/-a/s{i}.jsonl", json.dumps(delta(failed=[failure("srv")])))
        for i in range(2, 5):
            self.write(f".claude/projects/-a/s{i}.jsonl", json.dumps(delta(added=["mcp__srv__q"])))

    def test_default_thresholds_do_not_cross(self):
        self.assertEqual(self.run_drift(), (0, ""))

    def test_flags_reach_the_comparison(self):
        code, out = self.run_drift("--mcp-fail-min-sessions", "2", "--mcp-fail-min-share", "0.4")
        self.assertEqual(code, 0)
        self.assertIn("MCP server srv failed in 2 of 5 sessions", out)

    def test_session_flag_alone_still_gates(self):
        self.assertEqual(self.run_drift("--mcp-fail-min-sessions", "3", "--mcp-fail-min-share", "0.1"), (0, ""))
