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
