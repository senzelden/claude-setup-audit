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
