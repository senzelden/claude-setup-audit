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

    def test_overflowing_delta_is_unavailable_not_invalid_report(self):
        old, current = self.report('2026-09-14'), self.report()
        old['metrics']['tokens']['value'] = -1e308
        current['metrics']['tokens']['value'] = 1e308
        result = state.finalize(current, old)
        self.assertFalse(result['trend']['metrics']['tokens']['comparable'])
        state.validate_report(result, strict=True)

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

    def test_ledger_trend_rows_are_validated(self):
        result = state.finalize(self.report())
        result['trend']['ledger'] = [dict(entry='L-20260901-1', verdict='dropped', reason='rate_at_or_below_half',
                                          proposal=None, next_mechanism=None, matches=1, sessions_matched=1,
                                          sessions_scanned=20, value=None)]
        state.validate_report(result, strict=True)
        result['trend']['ledger'][0]['verdict'] = 'great'
        with self.assertRaises(state.ReportError):
            state.validate_report(result, strict=True)

    def test_applied_ledger_entry_must_be_text(self):
        report = self.report()
        report['applied'] = [dict(id='SEC-test:repo', status='applied', ledger_entry='L-20260901-1')]
        state.validate_report(report, strict=True)
        report['applied'][0]['ledger_entry'] = 5
        with self.assertRaises(state.ReportError):
            state.validate_report(report, strict=True)

    def test_processor_writes_trend_ledger_and_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            import ledger
            from test_ledger import entry, current
            report = Path(tmp, '2026-10-05-audit.json')
            report.write_text(json.dumps(self.report('2026-10-05')))
            book = Path(tmp, 'ledger.json')
            ledger.dump(dict(version=1, entries=[entry()]), str(book))
            snap = Path(tmp, 'snap.json')
            snap.write_text(json.dumps(dict(window_days=30, collection_scope=dict(requested='all', project=None),
                                            ledger_signals=dict(status='collected',
                                                                entries={'L-20260901-1': current(2, 20)}))))
            script = os.path.join(SCRIPTS, 'process_report.py')
            run = subprocess.run([sys.executable, script, str(report), '--ledger', str(book), '--snapshot', str(snap),
                                  '--finalize'], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(report.read_text())['trend']['ledger'][0]['verdict'], 'dropped')
            self.assertEqual(len(ledger.load(str(book))['entries'][0]['observations']), 1)
            # without --finalize nothing is written
            before = book.read_text()
            other = Path(tmp, '2026-10-06-audit.json')  # a different run id would add an observation
            other.write_text(json.dumps(self.report('2026-10-06')))
            subprocess.run([sys.executable, script, str(other), '--ledger', str(book), '--snapshot', str(snap)],
                           check=True, capture_output=True)
            self.assertEqual(book.read_text(), before)

    def test_processor_ledger_errors_name_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, 'r.json')
            report.write_text(json.dumps(self.report()))
            bad = Path(tmp, 'ledger.json')
            bad.write_text('{"version": 1, "entries": [], "x": "sk-SECRET"}')
            snap = Path(tmp, 's.json')
            snap.write_text('{}')
            script = os.path.join(SCRIPTS, 'process_report.py')
            run = subprocess.run([sys.executable, script, str(report),
                                  '--ledger', str(bad), '--snapshot', str(snap), '--finalize'],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('The ledger', run.stderr)
            self.assertNotIn('SECRET', run.stderr)
            run = subprocess.run([sys.executable, script, str(report), '--ledger', str(bad)],
                                 capture_output=True, text=True)
            self.assertIn('snapshot', run.stderr)

    def test_processor_malformed_snapshot_gives_unknown_rows_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            import ledger
            from test_ledger import entry
            report = Path(tmp, 'r.json')
            report.write_text(json.dumps(self.report()))
            book = Path(tmp, 'ledger.json')
            ledger.dump(dict(version=1, entries=[entry()]), str(book))
            script = os.path.join(SCRIPTS, 'process_report.py')
            for text in ('[]', '{"ledger_signals": 5}', '"x"'):
                snap = Path(tmp, 's.json')
                snap.write_text(text)
                run = subprocess.run([sys.executable, script, str(report), '--ledger', str(book),
                                      '--snapshot', str(snap), '--finalize'], capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(report.read_text())['trend']['ledger'][0]['verdict'], 'unknown')
            self.assertEqual(ledger.load(str(book))['entries'][0]['observations'], [])


class PreviousAndInputErrors(unittest.TestCase):
    """The processor must read its own earlier output and say which input failed."""
    report = ReportState.report

    def run_cli(self, tmp, current=None, previous=None, decisions=None, previous_text=None,
                decisions_text=None, current_text=None):
        tmp = Path(tmp)
        (tmp / 'current.json').write_text(current_text if current_text is not None
                                          else json.dumps(current or self.report('2026-09-20')))
        args = [sys.executable, str(Path(SCRIPTS) / 'process_report.py'), str(tmp / 'current.json')]
        if previous is not None or previous_text is not None:
            (tmp / 'previous.json').write_text(previous_text if previous_text is not None
                                               else json.dumps(previous))
            args += ['--previous', str(tmp / 'previous.json')]
        if decisions_text is not None:
            (tmp / 'decisions.yaml').write_text(decisions_text)
            args += ['--decisions', str(tmp / 'decisions.yaml')]
        return subprocess.run(args + ['--finalize'], capture_output=True, text=True), tmp / 'current.json'

    def real_world_previous(self):
        previous = self.report('2026-09-10', findings=[
            dict(id='F-fixed', check='C-fixed', title='Old', score=1, evidence=['x'], status='fixed'),
            dict(id='F-nochange', check='C-nc', title='Old', score=1, evidence=['x'], status='no_change_needed'),
            dict(id='F-partial', check='C-partial', title='Old', score=1, evidence=['x'], status='partial'),
            dict(id='F-idonly')])
        previous['metrics']['friction'] = {'buggy_code': 7, 'wrong_approach': 2}
        previous['parked'] = [dict(id='P-1', note='later')]
        return previous

    def test_each_failing_input_is_named_without_private_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, _ = self.run_cli(tmp, current_text='{"PRIVATE": ')
            self.assertEqual(result.returncode, 1)
            self.assertIn('current report', result.stderr)
            self.assertIn('line 1', result.stderr)
            self.assertNotIn('PRIVATE', result.stderr)
            result, _ = self.run_cli(tmp, previous_text='{\n"PRIVATE": ')
            self.assertIn('previous report', result.stderr)
            self.assertIn('line 2', result.stderr)
            self.assertNotIn('PRIVATE', result.stderr)
            result, _ = self.run_cli(tmp, previous=dict(self.report('2026-09-10'), version=2, PRIVATE='x'))
            self.assertIn('previous report', result.stderr)
            self.assertNotIn('PRIVATE', result.stderr)
            bad_current = self.report()
            bad_current['generated'] = 'PRIVATE-DATE'
            result, _ = self.run_cli(tmp, current=bad_current)
            self.assertIn('current report', result.stderr)
            self.assertNotIn('PRIVATE', result.stderr)
            result, _ = self.run_cli(tmp, decisions_text='- id: PRIVATE\n  reason: "x"\n  bogus line\n')
            self.assertIn('decisions file', result.stderr)
            self.assertIn('line 3', result.stderr)
            self.assertNotIn('PRIVATE', result.stderr)

    def test_block_scalar_decisions_get_line_and_quote_hint(self):
        text = ('- id: SEC-x\n  reason: >\n    folded PRIVATE text\n  settled: "2026-09-14"\n'
                '  review_after: "2027-03-01"\n')
        with tempfile.TemporaryDirectory() as tmp:
            result, path = self.run_cli(tmp, decisions_text=text)
            before = path.read_text()
        self.assertEqual(result.returncode, 1)
        self.assertIn('decisions file', result.stderr)
        self.assertIn('line 2', result.stderr)
        self.assertIn('block scalar', result.stderr)
        self.assertIn('quote', result.stderr)
        self.assertNotIn('PRIVATE', result.stderr)
        self.assertNotIn('trend', before)  # not finalized
        with self.assertRaises(ValueError):  # the parser still rejects block scalars
            state.parse_decisions(text)

    def test_previous_with_unknown_statuses_and_nested_metrics_is_read_leniently(self):
        current = self.report('2026-09-20', findings=[
            dict(id='F-fixed', check='C-fixed', title='Back', score=2, evidence=['y'], status='new')])
        previous = self.real_world_previous()
        with tempfile.TemporaryDirectory() as tmp:
            result, path = self.run_cli(tmp, current=current, previous=previous)
            self.assertEqual(result.returncode, 0, result.stderr)
            out = json.loads(path.read_text())
        trend = out['trend']
        self.assertTrue(trend['comparable'])
        self.assertEqual(trend['findings']['open'], ['F-fixed'])  # known to the previous run, not resolved
        self.assertEqual(trend['findings']['resolved'], [])
        self.assertEqual(sorted(trend['findings']['not_rechecked']), ['F-idonly', 'F-nochange', 'F-partial'])
        self.assertFalse(any(f['status'] == 'resolved' for f in out['findings']))
        self.assertTrue(trend['metrics']['tokens']['comparable'])

    def test_unknown_status_is_never_claimed_resolved_even_with_complete_check(self):
        current = self.report('2026-09-20', findings=[])
        current['checks'] = {'C-fixed': 'complete', 'C-nc': 'complete', 'C-partial': 'complete'}
        out = state.finalize(current, self.real_world_previous())
        self.assertEqual(out['trend']['findings']['resolved'], [])
        self.assertFalse(any(f['status'] == 'resolved' for f in out['findings']))

    def test_unusable_previous_metrics_are_skipped_without_delta(self):
        current = self.report('2026-09-20')
        current['metrics']['friction'] = dict(value=3, unit='count', basis='measured', source='transcripts.friction')
        previous = self.real_world_previous()
        previous['metrics']['broken'] = dict(value='seven', unit='n', basis='measured', source='x')
        previous['metrics']['odd'] = 'text'
        out = state.finalize(current, previous)
        friction = out['trend']['metrics']['friction']
        self.assertFalse(friction['comparable'])
        self.assertNotIn('delta', friction)
        self.assertTrue(out['trend']['metrics']['tokens']['comparable'])

    def test_trend_records_ignored_ids_and_names_only(self):
        previous = self.real_world_previous()
        previous['findings'][0]['status'] = 'PRIVATE-STATUS'
        previous['metrics']['friction'] = {'buggy_code': 'PRIVATE-VALUE'}
        out = state.finalize(self.report('2026-09-20'), previous)
        ignored = out['trend']['ignored']
        self.assertEqual(ignored['finding_statuses'], ['F-fixed', 'F-nochange', 'F-partial'])
        self.assertEqual(ignored['metrics'], ['friction'])
        self.assertNotIn('PRIVATE', json.dumps(ignored))
        state.validate_report(out, strict=True)  # the output shape stays valid
        clean = state.finalize(self.report('2026-09-20'), self.report('2026-09-10'))
        self.assertEqual(clean['trend']['ignored'], dict(finding_statuses=[], metrics=[], fields=[]))

    def test_current_report_stays_strict(self):
        for mutate in (lambda r: r['findings'][0].update(status='fixed'),
                       lambda r: r['metrics'].update(friction={'buggy_code': 7})):
            current = self.report('2026-09-20')
            mutate(current)
            with self.assertRaises(ValueError):
                state.finalize(current, self.report('2026-09-10'))
            with tempfile.TemporaryDirectory() as tmp:
                result, _ = self.run_cli(tmp, current=current, previous=self.report('2026-09-10'))
                self.assertEqual(result.returncode, 1)
                self.assertIn('current report', result.stderr)

    def test_previous_still_needs_version_1(self):
        for bad in ({'version': 2}, {}, [], {'version': True}):
            with self.assertRaises(ValueError):
                state.finalize(self.report('2026-09-20'), bad)

    def test_previous_findings_without_usable_ids_are_dropped_and_counted(self):
        previous = self.report('2026-09-10', findings=[
            {'status': 'fixed'}, {'id': 3}, {'id': ''}, 'PRIVATE', {'id': 'A'}, {'id': 'A'}])
        out = state.finalize(self.report('2026-09-20'), previous)
        self.assertEqual(out['trend']['ignored']['fields'],
                         ['findings[0]', 'findings[1]', 'findings[2]', 'findings[3]', 'findings[5]'])
        self.assertEqual(out['trend']['findings']['not_rechecked'], ['A'])

    def test_every_unusable_previous_field_is_ignored_and_never_leaks(self):
        previous = self.report('2026-09-10', findings=[
            dict(id='F1', check='C', title='Old', score=1, evidence=5, status='resolved',
                 severity='PRIVATE', action_status='PRIVATE', why=7),
            dict(id='F2', check='C2', title='Old', score='PRIVATE', evidence=['x'], status='open')])
        previous['applied'] = [dict(id='Y', status='PRIVATE'), 'PRIVATE']
        previous['checks'] = {'C': 'PRIVATE', 'C2': 'complete'}
        previous['trend'] = {'old': 'PRIVATE'}
        previous['coverage']['sources'].append(dict(source='s', status='PRIVATE'))
        previous['profile']['depth'] = 'PRIVATE'
        current = self.report('2026-09-20', findings=[])
        current['checks'] = {'C': 'complete', 'C2': 'complete'}
        out = state.finalize(current, previous)
        trend = out['trend']
        self.assertTrue(trend['comparable'])
        self.assertEqual(trend['findings']['resolved'], ['F2'])  # only from intact data
        self.assertEqual(trend['findings']['not_rechecked'], ['F1'])
        self.assertEqual(sorted(trend['ignored']['fields']), sorted([
            'findings[F1].evidence', 'findings[F1].severity', 'findings[F1].action_status',
            'findings[F1].why', 'findings[F2].score', 'applied[0].status', 'applied[1]',
            'checks.C', 'trend', 'coverage.sources[1]', 'profile.depth']))
        self.assertNotIn('PRIVATE', json.dumps(trend))
        state.validate_report(out, strict=True)

    def test_malformed_or_missing_previous_generated_and_bad_metrics_container(self):
        for mutate in (lambda r: r.update(generated='PRIVATE'), lambda r: r.pop('generated'),
                       lambda r: r.update(generated=5)):
            previous = self.report('2026-09-10')
            mutate(previous)
            out = state.finalize(self.report('2026-09-20'), previous)
            self.assertFalse(out['trend']['comparable'])
            self.assertEqual(out['trend']['ignored']['fields'], ['generated'])
            self.assertNotIn('PRIVATE', json.dumps(out['trend']))
        previous = self.report('2026-09-10')
        previous['metrics'] = 'PRIVATE'
        out = state.finalize(self.report('2026-09-20'), previous)
        self.assertEqual(out['trend']['ignored']['fields'], ['metrics'])
        self.assertFalse(out['trend']['metrics']['tokens']['comparable'])

    def test_bad_as_of_and_output_failures_are_labelled(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'current.json'
            path.write_text(json.dumps(self.report('2026-09-20')))
            for bad in ('2026-13-45', 'PRIVATE'):
                result = subprocess.run([sys.executable, str(Path(SCRIPTS) / 'process_report.py'), str(path),
                                         '--as-of', bad], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn('--as-of', result.stderr)
                self.assertNotIn('PRIVATE', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
        message = process_report.failure_message(OSError('PRIVATE'), 'output')
        self.assertIn('current report', message)
        self.assertIn('cannot be written', message)
        self.assertNotIn('PRIVATE', message)
        self.assertNotIn('Input:', process_report.failure_message(ValueError('PRIVATE'), None))

    def test_dropped_previous_coverage_source_makes_metrics_not_comparable(self):
        for bad in (dict(source='transcripts.main_files.x', status='truncated'), 'PRIVATE'):
            previous = self.report('2026-09-10')
            previous['coverage']['sources'].append(bad)
            out = state.finalize(self.report('2026-09-20'), previous)
            self.assertTrue(out['trend']['comparable'])
            self.assertFalse(out['trend']['metrics']['tokens']['comparable'])
            self.assertNotIn('delta', out['trend']['metrics']['tokens'])
        previous = self.report('2026-09-10')
        previous['coverage']['sources'] = 'PRIVATE'
        out = state.finalize(self.report('2026-09-20'), previous)
        self.assertFalse(out['trend']['metrics']['tokens']['comparable'])
        # Control: an intact previous still yields a delta.
        out = state.finalize(self.report('2026-09-20'), self.report('2026-09-10'))
        self.assertTrue(out['trend']['metrics']['tokens']['comparable'])

    def test_same_file_error_is_labelled_current_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'r.json'
            path.write_text(json.dumps(self.report()))
            result = subprocess.run([sys.executable, str(Path(SCRIPTS) / 'process_report.py'), str(path),
                                     '--previous', str(path), '--finalize'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('current report', result.stderr)
        self.assertNotIn('Report processing', result.stderr)
