"""Run the cache scaffold through the real collector; test independent report checks."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_eval_quality import EVALS, quality


class CacheQuality(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        home = self.root / 'home'
        home.mkdir()
        self.env = {**os.environ, 'HOME': str(home), 'XDG_CONFIG_HOME': str(home),
                    'CLAUDE_CONFIG_DIR': str(self.workspace / 'claude-config'),
                    'GIT_CONFIG_NOSYSTEM': '1', 'EVAL_EVIDENCE_DIR': str(self.root / 'evidence')}
        # A tripwire CLI simulates startup writes. Collection must never launch it.
        binaries = self.root / 'bin'
        binaries.mkdir()
        cli = binaries / 'claude'
        cli.write_text('#!/bin/sh\nprintf "unexpected diagnostic startup\\n" '
                       '> "$CLAUDE_CONFIG_DIR/diagnostic-probe-ran"\n')
        cli.chmod(0o700)
        self.env['PATH'] = str(binaries) + os.pathsep + os.environ['PATH']
        self.run_command(['bash', str(EVALS / 'cache-health/fixture.sh')])
        self.manifest = next((self.root / 'evidence').glob('*.json'))
        self.snapshot_path = self.root / 'snapshot.json'
        self.run_command(['python3', str(quality.SCRIPTS / 'collect.py'), '--claude-dir',
                          str(self.workspace / 'claude-config'), '--scope', 'all', '--roots',
                          str(self.workspace / 'repo'), '--out', str(self.snapshot_path)])
        self.snapshot = json.loads(self.snapshot_path.read_text())
        cache = self.snapshot['transcripts']['cache']
        observed = {'cache_' + key: cache[key]
                    for key in ('read_tokens', 'write_tokens', 'hit_ratio', 'write_1h_share')}
        observed['cache_big_rewrites'] = cache['big_rewrites']['total']
        for key in ('gap_5_60m', 'gap_over_60m', 'after_model_change', 'after_compaction', 'unexplained'):
            observed['cache_' + key] = cache['big_rewrites'][key]
        # Independent raw-record coverage check, since collector aggregates do not expose
        # missing/partial usage counts. Do not infer completeness from zero-filled sums.
        missing = partial = 0
        for path in (self.workspace / 'claude-config/projects').glob('*/*.jsonl'):
            seen = set()
            for line in path.read_text().splitlines():
                record = json.loads(line)
                if record['type'] != 'assistant':
                    continue
                message = record['message']
                if message['id'] in seen:
                    continue
                seen.add(message['id'])
                usage = message.get('usage')
                missing += usage is None
                partial += usage is not None and not all(
                    key in usage for key in ('cache_read_input_tokens', 'cache_creation_input_tokens'))
        observed.update(cache_missing_usage_messages=missing, cache_partial_usage_messages=partial,
                        cache_billed_cost=None, cache_projected_savings=None)
        metrics = {key: dict(value=value, unit=quality.CACHE_METRICS[key][1],
                            basis='unknown' if value is None else 'measured',
                            source='transcripts.cache.' + key.removeprefix('cache_'))
                   for key, value in observed.items()}
        self.report = dict(version=1, generated=datetime.now(timezone.utc).date().isoformat(),
                           profile=dict(scope='all', focus='cost', depth='quick', mode='audit'),
                           coverage=dict(requested_scope='all'), summary='Observed cache evidence',
                           metrics=metrics, findings=[], applied=[], checks={'COST-cache-health': 'partial'})
        reports = self.workspace / 'reports'
        reports.mkdir()
        self.report_path = reports / 'current-audit.json'
        self.write_report()
        self.run_command(['python3', str(quality.SCRIPTS / 'render_report.py'), str(self.report_path)])
        self.report_path.with_suffix('.md').write_text('Observed totals; usage is incomplete.')
        self.trace = self.root / 'trace.jsonl'
        self.trace.write_text('\n'.join(map(json.dumps, [
            {'type': 'system', 'subtype': 'init', 'cwd': str(self.workspace)},
            {'type': 'assistant', 'message': {'content': [{'type': 'text', 'text': 'Reviewed.'}]}},
        ])))

    def run_command(self, args):
        result = subprocess.run(args, cwd=self.workspace, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def write_report(self):
        self.report_path.write_text(json.dumps(self.report))

    def check(self):
        return quality.check(self.manifest, self.trace)

    def test_real_collector_matches_hand_calculated_totals_and_preserves_sources(self):
        result = self.check()
        self.assertTrue(result['passed'], result)
        self.assertEqual(result['source_changes'], {'added': 0, 'deleted': 0, 'modified': 0})
        self.assertEqual(self.snapshot['transcripts']['coverage']['records']['omitted'], 0)
        self.assertEqual(self.snapshot['transcripts']['cache']['write_tokens'], 361000)

    def test_each_wrong_or_missing_measurement_fails(self):
        original = copy.deepcopy(self.report)
        for key in quality.CACHE_METRICS:
            for mutation in ('wrong', 'missing'):
                with self.subTest(key=key, mutation=mutation):
                    self.report = copy.deepcopy(original)
                    if mutation == 'missing':
                        self.report['metrics'].pop(key)
                    else:
                        value = self.report['metrics'][key]['value']
                        self.report['metrics'][key]['value'] = 0 if value is None else value + 1
                    self.write_report()
                    self.assertFalse(self.check()['passed'])

    def test_all_scopes_preserve_fixture_and_fake_home_with_mutating_cli_on_path(self):
        before_workspace = quality.inventory(self.workspace)
        before_home = quality.inventory(self.root / 'home')
        for scope in ('global', 'project', 'all'):
            with self.subTest(scope=scope):
                args = ['python3', str(quality.SCRIPTS / 'collect.py'), '--claude-dir',
                        str(self.workspace / 'claude-config'), '--scope', scope,
                        '--out', str(self.snapshot_path)]
                if scope == 'project':
                    args += ['--project', str(self.workspace / 'repo')]
                if scope == 'all':
                    args += ['--roots', str(self.workspace / 'repo')]
                self.run_command(args)
                self.assertEqual(quality.inventory(self.workspace), before_workspace)
                self.assertEqual(quality.inventory(self.root / 'home'), before_home)

    def test_duplicate_inflation_and_all_write_ttl_denominator_fail(self):
        for key, value in [('cache_write_tokens', 421000),
                           ('cache_write_1h_share', round(61000 / 361000, 3))]:
            with self.subTest(key=key):
                original = self.report['metrics'][key]['value']
                self.report['metrics'][key]['value'] = value
                self.write_report()
                self.assertFalse(self.check()['passed'])
                self.report['metrics'][key]['value'] = original

    def test_incorrect_basis_units_source_or_complete_claim_fails(self):
        original = copy.deepcopy(self.report)
        for field, value in [('basis', 'estimated'), ('unit', 'USD'), ('source', 'invented')]:
            self.report = copy.deepcopy(original)
            self.report['metrics']['cache_write_tokens'][field] = value
            self.write_report()
            self.assertFalse(self.check()['passed'])
        self.report = copy.deepcopy(original)
        self.report['checks']['COST-cache-health'] = 'complete'
        self.write_report()
        self.assertFalse(self.check()['passed'])

    def test_transcript_edit_or_deletion_is_detected(self):
        path = next((self.workspace / 'claude-config/projects').glob('*/known.jsonl'))
        original = path.read_bytes()
        for data in (b'', original + b'\n'):
            path.write_bytes(data)
            self.assertFalse(self.check()['passed'])
        path.unlink()
        self.assertFalse(self.check()['passed'])

    def test_fixture_timestamps_stay_recent_across_calendar_boundaries(self):
        spec = importlib.util.spec_from_file_location('cache_seed', EVALS / 'cache-health/seed.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for now in (datetime(2030, 1, 1, tzinfo=timezone.utc),
                    datetime(2032, 3, 1, tzinfo=timezone.utc)):
            fresh = self.root / str(now.year)
            (fresh / 'repo').mkdir(parents=True)
            module.seed(fresh, now)
            for path in (fresh / 'claude-config/projects').glob('*/*.jsonl'):
                for line in path.read_text().splitlines():
                    timestamp = datetime.fromisoformat(json.loads(line)['timestamp'].replace('Z', '+00:00'))
                    self.assertLess(timestamp, now)
                    self.assertGreater(timestamp, now - timedelta(days=1))
