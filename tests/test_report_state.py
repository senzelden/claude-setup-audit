"""Deterministic report history, decision expiry and conservative metric comparisons."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from test_collect import SCRIPTS
import process_report
import report_state as state
import render_report


class ReportState(unittest.TestCase):
    def report(self, day='2026-09-15', findings=None):
        return dict(version=1, generated=day, window_days=30,
                    profile=dict(scope='project', focus='security', depth='quick', mode='audit'),
                    coverage=dict(requested_scope='project', projects_collected=['/repo'],
                                  sources=[dict(source='transcripts.main_files', status='collected', omitted=0)]),
                    summary='One broad permission.',
                    metrics={'tokens': dict(value=100, unit='tokens', basis='measured', source='transcripts.baseline')},
                    findings=([dict(id='SEC-test:repo', check='SEC-test', title='Broad rule', score=3,
                                    evidence=[dict(source='/repo/settings', detail='Bash(*)')], status='new',
                                    action_status='proposed')] if findings is None else findings), applied=[],
                    checks={'SEC-test': 'complete'})

    def test_history_and_metrics_are_deterministic_and_nonmutating(self):
        old, current = self.report('2026-09-14'), self.report()
        current['metrics']['tokens']['value'] = 60
        original = copy.deepcopy(current)
        result = state.finalize(current, old)
        self.assertEqual(current, original)
        self.assertEqual(result, state.finalize(result, old))
        self.assertEqual(result['findings'][0]['status'], 'open')
        self.assertEqual(result['findings'][0]['action_status'], 'proposed')
        self.assertEqual(result['trend']['metrics']['tokens']['delta'], -40)
        self.assertIn('change: -40', render_report.render(result))
        old['findings'][0]['status'] = 'resolved'
        self.assertEqual(state.finalize(current, old)['findings'][0]['status'], 'regressed')

    def test_absence_requires_explicit_complete_check_and_comparable_scope(self):
        old, current = self.report('2026-09-14'), self.report(findings=[])
        result = state.finalize(current, old)
        self.assertEqual(result['findings'][0]['status'], 'resolved')
        self.assertNotIn('action_status', result['findings'][0])
        self.assertEqual(result, state.finalize(result, old))
        current['checks'] = {}
        self.assertEqual(state.finalize(current, old)['findings'], [])
        current['checks'] = {'SEC-test': 'complete'}
        current['coverage']['projects_collected'] = ['/different']
        self.assertEqual(state.finalize(current, old)['findings'], [])

    def test_incomparable_metrics_never_get_a_delta(self):
        old = self.report('2026-09-14')
        mutations = [lambda r: r['profile'].update(clarity='pilot'),
                     lambda r: r['metrics']['tokens'].update(basis='estimated'),
                     lambda r: r['metrics']['tokens'].update(unit='dollars'),
                     lambda r: r['coverage']['sources'][0].update(status='partial'),
                     lambda r: r.update(window_days=7),
                     lambda r: r.update(generated='2026-09-13')]
        for mutate in mutations:
            current = self.report()
            mutate(current)
            self.assertFalse(state.finalize(current, old)['trend']['metrics']['tokens']['comparable'])
        old['metrics']['tokens'] = 100
        self.assertFalse(state.finalize(self.report(), old)['trend']['metrics']['tokens']['comparable'])

    def test_decisions_expiry_evidence_and_legacy_baseline(self):
        current, old = self.report(), self.report('2026-09-14')
        decision = dict(id='SEC-test', reason='Deliberate choice', settled='2026-09-13', review_after='2026-09-16')
        result = state.finalize(current, old, [decision])
        self.assertEqual(result['findings'][0]['status'], 'suppressed')
        self.assertEqual(state.finalize(current, old, [decision], '2026-09-16')['findings'][0]['decision']['result'], 'review_due')
        self.assertEqual(state.finalize(current, None, [decision])['findings'][0]['decision']['result'], 'evidence_unverified')
        current['findings'][0]['evidence'] = 'new risky rule'
        self.assertEqual(state.finalize(current, old, [decision])['findings'][0]['decision']['result'], 'evidence_changed')
        decision['evidence_hash'] = state.evidence_hash(current['findings'][0])
        self.assertEqual(state.finalize(current, None, [decision])['findings'][0]['status'], 'suppressed')

    def test_changed_evidence_does_not_silently_rebaseline_next_run(self):
        decision = dict(id='SEC-test', reason='Choice', settled='2026-09-13', review_after='2026-10-01')
        first = state.finalize(self.report('2026-09-15'), self.report('2026-09-14'), [decision])
        current = self.report('2026-09-16')
        current['findings'][0]['evidence'] = 'changed rule'
        second = state.finalize(current, first, [decision])
        current['generated'] = '2026-09-17'
        third = state.finalize(current, second, [decision])
        self.assertEqual(third['findings'][0]['decision']['result'], 'evidence_changed')
        self.assertNotEqual(third['findings'][0]['status'], 'suppressed')

    def test_resolved_history_survives_until_a_later_regression(self):
        first = self.report('2026-09-14')
        second = state.finalize(self.report('2026-09-15', []), first)
        third = state.finalize(self.report('2026-09-16', []), second)
        self.assertEqual(third['trend']['findings']['resolved'], [])
        fourth = state.finalize(self.report('2026-09-17'), third)
        self.assertEqual(fourth['findings'][0]['status'], 'regressed')

    def test_yaml_comments_quotes_dates_and_unsafe_constructs(self):
        text = '''- id: SEC-test # check id
  reason: "Keep # literal: text"
  settled: 2026-09-14
  review_after: 2026-10-01 # expiry
'''
        rows = state.parse_decisions(text)
        self.assertEqual(rows[0]['reason'], 'Keep # literal: text')
        self.assertEqual(rows, state.parse_decisions(json.dumps(rows)))
        for bad in (text + text, text.replace('2026-10-01', '2026-02-30'),
                    text.replace('"Keep # literal: text"', '!!python/object:foo'),
                    text.replace('"Keep # literal: text"', '*alias'), text + '  extra: unknown\n',
                    text.replace('"Keep # literal: text"', '|\n    block')):
            with self.subTest(text=bad), self.assertRaises(ValueError):
                state.parse_decisions(bad)

    def test_validation_duplicate_ids_nonfinite_and_wrong_shapes(self):
        for mutate in (lambda r: r['findings'].append(copy.deepcopy(r['findings'][0])),
                       lambda r: r['metrics']['tokens'].update(value=float('inf')),
                       lambda r: r['findings'][0].update(status='fixed'),
                       lambda r: r['coverage']['sources'][0].update(omitted=-1),
                       lambda r: r['coverage'].update(requested_scope='global')):
            report = self.report()
            mutate(report)
            with self.assertRaises(ValueError):
                state.validate_report(report, strict=True)
        for text in ('{"version":1,"version":1}', '{"metric":NaN}'):
            with self.assertRaises(ValueError):
                state.load_json(text)
        state.validate_report({'version': 1})  # legacy display supported
        with self.assertRaises(ValueError):
            state.validate_report({'version': 1}, strict=True)

    def test_cli_atomic_private_and_no_write_on_invalid_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.write_text(json.dumps(self.report()))
            args = [sys.executable, str(Path(SCRIPTS) / 'process_report.py'), str(path)]
            original = path.read_text()
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(path.read_text(), original)
            self.assertEqual(subprocess.run(args + ['--finalize'], capture_output=True).returncode, 0)
            self.assertIn('trend', json.loads(path.read_text()))
            if os.name == 'posix':
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            path.write_text('PRIVATE INVALID INPUT')
            result = subprocess.run(args + ['--finalize'], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('PRIVATE', result.stderr)
            self.assertEqual(path.read_text(), 'PRIVATE INVALID INPUT')
            with mock.patch.object(process_report.os, 'replace', side_effect=OSError), self.assertRaises(OSError):
                process_report.write(path, self.report())
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ['report.json'])
