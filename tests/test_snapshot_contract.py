"""Snapshot boundary regressions; fixture data only, no real configuration."""
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest import mock

from test_collect import FakeHome, SCRIPTS, collect
import snapshot_contract as contract


class SnapshotContract(FakeHome):
    def snapshot(self, scope='global', pilot=False):
        root = os.path.join(self.home, 'repo')
        self.write('repo/CLAUDE.md', 'Quote the exact error.')
        self.write('.claude/CLAUDE.md', 'Quote the exact error.')
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {
            'missing@fixture': [{'scope': 'user', 'installPath': '/outside'}]}})
        argv = ['collect.py', '--scope', scope]
        if scope == 'project':
            argv += ['--project', root]
        if scope == 'all':
            argv += ['--roots', root]
        if pilot:
            argv += ['--clarity-pilot']
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(sys, 'stdout', output), \
             mock.patch.object(collect, 'managed_directory', return_value=self.home), \
             mock.patch.object(collect.subprocess, 'run', side_effect=OSError('fixture CLI unavailable')):
            collect.main()
        return json.loads(output.getvalue())

    def test_producer_scopes_and_optional_pilot(self):
        for scope in ('global', 'project', 'all'):
            for pilot in (False, True):
                with self.subTest(scope=scope, pilot=pilot):
                    snapshot = self.snapshot(scope, pilot)
                    self.assertEqual(contract.validate_snapshot(snapshot), 'v1')
                    self.assertEqual('instruction_clarity' in snapshot, pilot)
                    sources = {s['source']: s for s in snapshot['coverage']['sources']}
                    for field in ('global.version', 'global.doctor'):
                        self.assertEqual(sources[field]['status'], 'not_checked')
                        self.assertEqual(sources[field]['reason'], 'cli_diagnostics_not_run_read_only')

    def test_rejects_missing_fields_types_versions_and_bad_coverage(self):
        baseline = self.snapshot()
        variants = []
        for key in ('snapshot_version', 'coverage', 'instructions'):
            altered = copy.deepcopy(baseline)
            del altered[key]
            variants.append(altered)
        for version in (True, '1', 2, None):
            variants.append(dict(baseline, snapshot_version=version))
        variants += [dict(baseline, projects=[]), dict(baseline, window_days=0),
                     dict(baseline, extra=float('nan')), dict(baseline, extra=float('inf'))]
        for key, value in [('requested_scope', 'all'), ('projects_collected', ['fake']),
                           ('sources', [{'source': 'x', 'scope': 'user', 'status': 'complete'}]),
                           ('sources', [{'source': 'x', 'scope': 'user', 'status': 'partial', 'omitted': -1}])]:
            variants.append(dict(baseline, coverage={**baseline['coverage'], key: value}))
        for altered in variants:
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)

    def test_ledger_signals_are_optional_and_checked(self):
        snap = self.snapshot()
        snap["ledger_signals"] = {"status": "collected", "entries": {"L-20260901-1": {
            "from": "2026-09-01T00:00:00Z", "to": "2026-09-28T00:00:00Z", "matches": 1,
            "sessions_matched": 1, "sessions_scanned": 5, "complete": True, "selector_sha": "a" * 64}}}
        contract.validate_snapshot(snap)
        snap["ledger_signals"]["status"] = "other"
        with self.assertRaises(contract.SnapshotError):
            contract.validate_snapshot(snap)

    def test_drift_signals_are_optional_and_checked(self):
        snap = self.snapshot()
        snap["drift_signals"] = {"status": "collected", "path": "~/d.jsonl", "entries": 1, "malformed": 0,
                                 "first_at": "2026-09-01T00:00:00Z", "last_at": "2026-09-01T00:00:00Z",
                                 "signals": {"cache_hit_ratio": {"last_value": 0.93, "crossings": 0,
                                                                 "first_crossing_at": None,
                                                                 "last_crossing_at": None, "scopes": ["all"]}}}
        contract.validate_snapshot(snap)
        contract.validate_snapshot({**snap, "drift_signals": {"status": "invalid", "path": "~/d.jsonl"}})
        for mutate in (lambda d: d.update(status="bogus"), lambda d: d.update(entries=-1),
                       lambda d: d["signals"]["cache_hit_ratio"].update(crossings=-1),
                       lambda d: d["signals"]["cache_hit_ratio"].pop("scopes"),
                       lambda d: d["signals"]["cache_hit_ratio"].pop("last_value")):
            altered = copy.deepcopy(snap)
            mutate(altered["drift_signals"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)

    def test_number_type_is_finite_int_or_float_but_not_bool(self):
        schema = {"type": "number"}
        root = {"$defs": {}}
        for ok in (0, 3, 0.93, -1.5):
            contract._check(ok, schema, root)
        for bad in (True, False, "1", None, float("nan"), float("inf"), [1]):
            with self.assertRaises(contract.SnapshotError, msg=repr(bad)):
                contract._check(bad, schema, root)

    def test_drift_last_value_is_number_or_null(self):
        snap = self.snapshot()
        sig = {"last_value": 0.93, "crossings": 0, "first_crossing_at": None, "last_crossing_at": None,
               "scopes": ["all"]}
        snap["drift_signals"] = {"status": "collected", "path": "~/d.jsonl", "entries": 1, "malformed": 0,
                                 "first_at": None, "last_at": None, "signals": {"cache_hit_ratio": sig}}
        for ok in (0.93, 7, None):
            accepted = copy.deepcopy(snap)
            accepted["drift_signals"]["signals"]["cache_hit_ratio"]["last_value"] = ok
            contract.validate_snapshot(accepted)
        for bad in (True, "0.9", [1]):
            altered = copy.deepcopy(snap)
            altered["drift_signals"]["signals"]["cache_hit_ratio"]["last_value"] = bad
            with self.assertRaises(contract.SnapshotError, msg=repr(bad)):
                contract.validate_snapshot(altered)

    def test_skill_listing_series_shape_is_checked(self):
        snap = self.snapshot()
        snap["harness_overhead"] = {
            "window_days": 30, "sessions_scanned": 2, "complete": True, "incomplete_reasons": [],
            "injected_context": {"sessions_with_injection": 0, "sources": []},
            "skill_listing_series": {
                "sessions": 2, "first": {"date": "2026-09-01", "skill_count": 3, "chars": 900},
                "last": {"date": "2026-09-02", "skill_count": 4, "chars": 1200},
                "max": {"skill_count": 4, "chars": 1200}, "sdk_sessions_excluded": 0,
                "per_plugin_skills": [{"plugin": "a@m", "skills": 2}]},
            "subagent_spend": {"subagent_files_scanned": 0, "sessions_with_subagents": 0,
                               "subagent_tokens_per_session_median": None,
                               "main_tokens_per_session_median": 100,
                               "main_tokens_median_in_subagent_sessions": None,
                               "entrypoints": {"cli": 2, "sdk-py": 0, "sdk-cli": 0, "other": 0}},
            "model_spawning_hooks": []}
        contract.validate_snapshot(snap)
        for mutate in (lambda h: h["skill_listing_series"].update(sessions="2"),
                       lambda h: h["skill_listing_series"].update(sdk_sessions_excluded=-1),
                       lambda h: h["skill_listing_series"].pop("last"),
                       lambda h: h["skill_listing_series"]["first"].update(chars=True),
                       lambda h: h["skill_listing_series"]["per_plugin_skills"][0].update(skills="1")):
            altered = copy.deepcopy(snap)
            mutate(altered["harness_overhead"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)

    def test_harness_overhead_is_checked(self):
        snap = self.snapshot()
        snap["harness_overhead"] = {
            "window_days": 30, "sessions_scanned": 2, "complete": True, "incomplete_reasons": [],
            "injected_context": {"sessions_with_injection": 1, "sources": [{
                "plugin": "a@m", "attribution": "matched", "hook_event": "SessionStart", "sessions": 1,
                "records": 1, "chars_per_session_median": 40, "chars_per_session_p90": 40,
                "est_tokens_per_session_median": 10}]},
            "skill_listing_series": None,
            "subagent_spend": {"subagent_files_scanned": 0, "sessions_with_subagents": 0,
                               "subagent_tokens_per_session_median": None,
                               "main_tokens_per_session_median": 100,
                               "main_tokens_median_in_subagent_sessions": None,
                               "entrypoints": {"cli": 2, "sdk-py": 0, "sdk-cli": 0, "other": 0}},
            "model_spawning_hooks": [{"plugin": "a@m", "hook_event": "Stop", "file": "hooks/r.sh",
                                      "line": 1, "pattern": "claude_print"}]}
        contract.validate_snapshot(snap)
        for reason in ("plugin_registry_unreadable", "hook_file_unreadable", "manifest_unreadable",
                       "transcripts_not_read"):
            accepted = copy.deepcopy(snap)
            accepted["harness_overhead"].update(complete=False, incomplete_reasons=[reason])
            contract.validate_snapshot(accepted)
        for mutate in (lambda h: h.update(incomplete_reasons=["bogus"]),
                       lambda h: h["subagent_spend"]["entrypoints"].update(cli=-1),
                       lambda h: h["subagent_spend"].update(main_tokens_median_in_subagent_sessions="1"),
                       lambda h: h["subagent_spend"].pop("main_tokens_median_in_subagent_sessions")):
            altered = copy.deepcopy(snap)
            mutate(altered["harness_overhead"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)

    def test_cli_ledger_flag_writes_validated_signals(self):
        import ledger
        sel = {"type": "keywords", "source": "corrections", "any": ["tests"]}
        entry = dict(id="L-20260901-1", applied_at="2026-09-01T00:00:00Z", run="r", finding_id="LRN-x",
                     pattern="p", mechanism="rule", state="active", supersedes=None, selector=sel,
                     scope=dict(scope="all", project=None, window_days=30),
                     baseline={"from": "2026-08-01T00:00:00Z", "to": "2026-09-01T00:00:00Z", "matches": 3,
                               "sessions_matched": 3, "sessions_scanned": 9, "complete": True},
                     edits=[dict(file="~/x.md", kind="markdown_block", sha256="a" * 64, backup=None)],
                     observations=[])
        path = os.path.join(self.claude, "audits", "ledger.json")
        ledger.dump(dict(version=1, entries=[entry]), path)
        out = os.path.join(self.home, "snap.json")
        argv = ["collect.py", "--scope", "global", "--ledger", path, "--out", out]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(sys, "stdout", io.StringIO()), \
                mock.patch.object(collect, "managed_directory", return_value=self.home), \
                mock.patch.object(collect.subprocess, "run", side_effect=OSError("fixture CLI unavailable")):
            collect.main()
        with open(out) as f:
            snapshot = json.load(f)
        self.assertEqual(contract.validate_snapshot(snapshot), "v1")
        signals = snapshot["ledger_signals"]
        self.assertEqual(signals["status"], "collected")
        self.assertEqual(signals["entries"]["L-20260901-1"]["selector_sha"], ledger.selector_hash(sel))

    def test_additive_fields_and_legacy_policy(self):
        snapshot = self.snapshot()
        snapshot['future_optional'] = {'value': 1}
        self.assertEqual(contract.validate_snapshot(snapshot), 'v1')
        del snapshot['snapshot_version']
        with self.assertRaises(contract.SnapshotError):
            contract.validate_snapshot(snapshot)
        self.assertEqual(contract.validate_snapshot(snapshot, allow_legacy=True), 'legacy')

    def test_invalid_producer_preserves_existing_output(self):
        output = self.write('.claude/audits/snapshot.json', 'existing')
        with mock.patch.object(sys, 'argv', ['collect.py', '--scope', 'global', '--out', output]), \
             mock.patch.object(collect, 'managed_directory', return_value=self.home), \
             mock.patch.object(collect.subprocess, 'run', side_effect=OSError('unavailable')), \
             mock.patch.object(collect, 'snapshot_coverage', return_value={}):
            with self.assertRaises(contract.SnapshotError):
                collect.main()
        self.assertEqual(Path(output).read_text(), 'existing')

    def test_query_rejects_future_and_malformed_without_echoing_values(self):
        script = os.path.join(SCRIPTS, 'query_snapshot.py')
        for content in ('{"snapshot_version":999,"secret":"PRIVATE"}', 'PRIVATE invalid JSON'):
            path = self.write('input.json', content)
            result = subprocess.run([sys.executable, '-B', script, path], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertNotIn('PRIVATE', result.stderr)
        path = self.write('input.json', {'section': 'legacy'})
        result = subprocess.run([sys.executable, '-B', script, path, 'section'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('Legacy unversioned', result.stderr)
        self.assertIn('<untrusted_snapshot_data>', result.stdout)

    def test_dynamic_keys_are_not_in_errors(self):
        snapshot = self.snapshot()
        snapshot['readiness'] = {'PRIVATE': []}
        with self.assertRaises(contract.SnapshotError) as caught:
            contract.validate_snapshot(snapshot)
        self.assertNotIn('PRIVATE', str(caught.exception))

    def test_config_conflicts_are_optional_and_checked(self):
        snap = self.snapshot()
        self.assertEqual(snap["config_conflicts"]["stacks"], 1)
        snap["config_conflicts"] = {
            "stacks": 1, "hook_duplicates_omitted": 0, "permission_overlaps_omitted": 0,
            "hook_duplicates": [{"stack": "global", "event": "PreToolUse", "matcher": "Bash", "type": "command",
                                 "fingerprint": "0123456789abcdef", "effect": "deduplicated",
                                 "sources": [{"layer": "user", "path": "~/.claude/settings.json", "plugin": None}]}],
            "permission_overlaps": [{"stack": "global",
                                     "allow": {"layer": "user", "path": "~/.claude/settings.json", "rule": "Bash(x)"},
                                     "by": {"list": "deny", "layer": "managed", "path": "/etc/m.json", "rule": "Bash"},
                                     "match": "tool"}]}
        contract.validate_snapshot(snap)
        contract.validate_snapshot({k: v for k, v in snap.items() if k != "config_conflicts"})
        for mutate in (lambda c: c["hook_duplicates"][0].update(effect="bogus"),
                       lambda c: c["hook_duplicates"][0].pop("fingerprint"),
                       lambda c: c["hook_duplicates"][0]["sources"][0].update(layer="bogus"),
                       lambda c: c["permission_overlaps"][0].update(match="bogus"),
                       lambda c: c["permission_overlaps"][0]["by"].update(list="allow"),
                       lambda c: c.update(permission_overlaps_omitted=-1),
                       lambda c: c.update(stacks=0)):
            altered = copy.deepcopy(snap)
            mutate(altered["config_conflicts"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)

    def test_mcp_exposure_and_tool_errors_are_checked(self):
        snap = self.snapshot()
        snap["extensions"]["mcp_servers"] = [{
            "source": "/h/.claude.json", "scope": "user", "status": "collected", "transport_class": "remote",
            "config_notes": [], "endpoint_locality": "named_host", "plaintext_transport": False,
            "oauth_scopes": None, "tool_prefix": "gh", "file_git_status": "tracked",
            "project_trust_accepted": None,
            "policy_observations": [{"source": "~/.claude/settings.json", "kind": "permission_allow", "value": 2}]}]
        snap["extensions"]["mcp_project_state"] = [{"project": "/h/p", "source": "/h/.claude.json",
                                                    "trust_accepted": None}]
        snap["extensions"]["mcp_name_collisions"] = [{"name": "gh", "project": "/h/p", "scopes": ["local", "user"],
                                                      "endpoint_origins_differ": True}]
        snap["transcripts"]["tool_errors"] = {
            "error_results_paired": 1, "error_results_unmatched": 0, "results_without_is_error": 0,
            "by_tool": [{"tool": "Bash", "calls": 6, "errors": 1, "denied": 0, "failure_rate": 0.167,
                         "categories": {"nonzero_exit": 1}}],
            "by_mcp_server": [{"server": "gh", "calls": 1, "errors": 0, "denied": 0, "failure_rate": None,
                               "categories": {}, "top_error_tools": []}],
            "omitted": {"tools": 0, "mcp_servers": 0}, "min_calls_for_rate": 5}
        contract.validate_snapshot(snap)
        server = lambda s: s["extensions"]["mcp_servers"][0]  # noqa: E731
        errors = lambda s: s["transcripts"]["tool_errors"]  # noqa: E731
        for mutate in (lambda s: server(s).update(transport_class="bogus"),
                       lambda s: server(s).update(endpoint_locality="moon"),
                       lambda s: server(s).update(config_notes=["nope"]),
                       lambda s: server(s).update(file_git_status="maybe"),
                       lambda s: server(s).update(plaintext_transport="no"),
                       lambda s: server(s).update(oauth_scopes="read"),
                       lambda s: server(s).update(policy_observations_omitted=-1),
                       lambda s: server(s)["policy_observations"][0].pop("kind"),
                       lambda s: server(s)["policy_observations"][0].update(kind="bogus"),
                       lambda s: server(s)["policy_observations"][0].update(value="2"),
                       lambda s: s["extensions"]["mcp_project_state"][0].update(trust_accepted="yes"),
                       lambda s: s["extensions"]["mcp_name_collisions"][0].update(scopes=["plugin"]),
                       lambda s: errors(s)["by_tool"][0].update(failure_rate="x"),
                       lambda s: errors(s)["by_tool"][0].update(failure_rate=True),
                       lambda s: errors(s)["by_tool"][0].update(failure_rate=float("nan")),
                       lambda s: errors(s)["by_tool"][0].update(calls=-1),
                       lambda s: errors(s)["by_mcp_server"][0]["categories"].update(auth=-1),
                       lambda s: errors(s).pop("omitted")):
            altered = copy.deepcopy(snap)
            mutate(altered)
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)
