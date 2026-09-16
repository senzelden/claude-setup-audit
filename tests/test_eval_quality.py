"""Free checks for paid-eval evidence handling, using only temporary fake homes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

EVALS = Path(__file__).resolve().parents[1] / 'plugins/setup-audit/evals'
spec = importlib.util.spec_from_file_location('check_quality', EVALS / 'helpers/check_quality.py')
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)


class EvalQuality(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        self.evidence = self.root / 'evidence'
        (self.workspace / 'app').mkdir()
        (self.workspace / 'claude-config').mkdir()
        (self.workspace / 'app/source.py').write_text('original\n')
        self.manifest = quality.capture(self.workspace, self.evidence, 'readiness-envrc-pointers')
        self.reports = self.workspace / 'reports'
        self.reports.mkdir()
        self.report = {
            'version': 1, 'generated': '2026-09-16',
            'profile': {'scope': 'project', 'focus': 'readiness', 'mode': 'audit', 'depth': 'quick'},
            'coverage': {'requested_scope': 'project'}, 'summary': 'Fixture',
            'findings': [], 'metrics': {}, 'applied': [],
        }
        self.report_path = self.reports / '2026-09-16-audit.json'
        self.report_path.write_text(json.dumps(self.report))
        self.report_path.with_suffix('.md').write_text('Read-only audit')
        self.report_path.with_suffix('.html').write_text('<html><body>Audit</body></html>')
        self.trace = self.root / 'trace.jsonl'
        self.events = [
            {'type': 'system', 'subtype': 'init', 'cwd': str(self.workspace)},
            {'type': 'assistant', 'message': {'content': [
                {'type': 'tool_use', 'id': 'collect', 'name': 'Bash',
                 'input': {'command': 'python3 /plugin/scripts/collect.py --out /tmp/snap.json'}}]}},
            {'type': 'user', 'message': {'content': [
                {'type': 'tool_result', 'tool_use_id': 'collect',
                 'content': 'wrote /tmp/snap.json (200 est. tokens)'}]}},
            {'type': 'assistant', 'message': {'content': [{'type': 'text', 'text': 'Audit complete.'}]}},
        ]
        self.write_trace()

    def write_trace(self):
        self.trace.write_text('\n'.join(json.dumps(event) for event in self.events) + '\n')

    def check(self):
        return quality.check(self.manifest, self.trace)

    def test_clean_report_and_collector_evidence(self):
        result = self.check()
        self.assertTrue(result['passed'], result)
        self.assertTrue(result['collector_ran'])
        self.assertEqual(result['source_changes'], {'added': 0, 'deleted': 0, 'modified': 0})
        cli = subprocess.run(['python3', str(EVALS / 'helpers/check_quality.py'), 'check',
                              '--manifest', str(self.manifest), '--trace', str(self.trace)],
                             capture_output=True, text=True)
        self.assertEqual(cli.returncode, 0, cli.stderr)

    def test_modified_deleted_and_added_sources_are_detected(self):
        for operation in ['modified', 'deleted', 'added']:
            with self.subTest(operation=operation):
                path = self.workspace / 'app/source.py'
                path.write_text('original\n')
                extra = self.workspace / 'app/new.env'
                extra.unlink(missing_ok=True)
                if operation == 'modified':
                    path.write_text('changed via Bash or Write')
                elif operation == 'deleted':
                    path.unlink()
                else:
                    extra.write_text('new')
                result = self.check()
                self.assertFalse(result['passed'])
                self.assertEqual(result['source_changes'][operation], 1)

    def test_raw_reads_are_allowed_but_assistant_text_and_tool_inputs_are_not(self):
        self.events.append({'type': 'user', 'message': {'content': [
            {'type': 'tool_result', 'tool_use_id': 'read', 'content': quality.MARKER}]}})
        self.write_trace()
        self.assertTrue(self.check()['passed'])
        for block in [{'type': 'text', 'text': quality.MARKER},
                      {'type': 'tool_use', 'name': 'Write', 'input': {'content': quality.MARKER}},
                      {'type': 'thinking', 'thinking': quality.MARKER}]:
            with self.subTest(kind=block['type']):
                self.events.append({'type': 'assistant', 'message': {'content': [block]}})
                self.write_trace()
                result = self.check()
                self.assertTrue(result['output_leak'])
                self.assertFalse(result['passed'])
                self.assertNotIn(quality.MARKER, json.dumps(result))
                self.events.pop()

    def test_result_text_is_checked(self):
        self.events.append({'type': 'result', 'result': quality.MARKER})
        self.write_trace()
        self.assertTrue(self.check()['output_leak'])

    def test_every_report_file_is_checked_for_leaks(self):
        for suffix in ['.md', '.html', '.txt']:
            with self.subTest(suffix=suffix):
                extra = self.reports / ('extra' + suffix)
                extra.write_text(quality.MARKER.replace('F', '&#70;'))
                self.assertTrue(self.check()['artifact_leak'])
                self.assertFalse(self.check()['passed'])
                extra.unlink()

    def test_report_json_escapes_do_not_hide_marker(self):
        report = copy.deepcopy(self.report)
        report['summary'] = quality.MARKER
        self.report_path.write_text(json.dumps(report).replace('FAKE', '\\u0046AKE'))
        self.assertFalse(self.check()['passed'])

    def test_missing_invalid_or_wrong_profile_reports_fail_closed(self):
        for change in ['missing', 'invalid', 'profile', 'applied', 'companion']:
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                if change == 'profile':
                    report['profile']['mode'] = 'apply'
                if change == 'applied':
                    report['applied'] = [{'id': 'not-a-finding'}]
                self.report_path.write_text(json.dumps(report))
                if change == 'missing':
                    self.report_path.unlink()
                elif change == 'invalid':
                    self.report_path.write_text('{}')
                elif change == 'companion':
                    self.report_path.with_suffix('.md').unlink()
                self.assertFalse(self.check()['complete'])
                self.report_path.with_suffix('.md').write_text('Report')

    def test_missing_malformed_and_empty_traces_are_incomplete(self):
        for content in [None, '', '{}', '{broken']:
            with self.subTest(content=content):
                if content is None:
                    self.trace.unlink(missing_ok=True)
                else:
                    self.trace.write_text(content)
                self.assertFalse(self.check()['complete'])
                self.assertFalse(self.check()['passed'])

    def test_collector_claims_and_failed_calls_are_not_success(self):
        for change in ['claim', 'error', 'other-tool']:
            with self.subTest(change=change):
                events = copy.deepcopy(self.events)
                if change == 'claim':
                    events.pop(2)
                    events[-1]['message']['content'][0]['text'] = 'wrote /tmp/snap (200 est. tokens)'
                elif change == 'error':
                    events[2]['message']['content'][0]['is_error'] = True
                else:
                    events[1]['message']['content'][0]['input']['command'] = 'python3 something.py'
                self.trace.write_text('\n'.join(map(json.dumps, events)))
                result = self.check()
                self.assertTrue(result['passed'])
                self.assertFalse(result['collector_ran'])

    def test_trace_from_another_workspace_is_not_accepted(self):
        self.events[0]['cwd'] = str(self.root / 'another-run')
        self.write_trace()
        self.assertFalse(self.check()['complete'])

    def test_sealed_retention_layout_keeps_original_trace_identity(self):
        original = self.root / 'home/cwd'
        retained = self.root / 'sealed/home/cwd'
        retained.parent.mkdir(parents=True)
        self.workspace.rename(retained)
        manifest = json.loads(self.manifest.read_text())
        manifest['workspace'] = str(original)
        self.manifest.write_text(json.dumps(manifest))
        self.events[0]['cwd'] = str(original)
        (self.root / 'out').mkdir()
        self.trace = self.root / 'out/trace.jsonl'
        self.write_trace()
        self.assertFalse(self.check()['complete'])
        self.assertTrue(quality.check(self.manifest, self.trace, sealed=True)['passed'])
        other = self.root / 'other-trace.jsonl'
        shutil.copyfile(self.trace, other)
        self.assertFalse(quality.check(self.manifest, other, sealed=True)['complete'])

    def test_symlinks_are_not_followed_for_source_or_report_evidence(self):
        source = self.workspace / 'app/source.py'
        source.unlink()
        source.symlink_to(self.root / 'missing')
        self.assertFalse(self.check()['passed'])
        source.unlink()
        source.write_text('original\n')
        self.report_path.unlink()
        self.report_path.symlink_to(self.root / 'missing')
        self.assertFalse(self.check()['complete'])

    def test_report_directory_symlink_and_missing_workspace_are_incomplete(self):
        moved = self.root / 'moved-reports'
        self.reports.rename(moved)
        self.reports.symlink_to(moved, target_is_directory=True)
        self.assertFalse(self.check()['complete'])
        self.workspace.rename(self.root / 'moved-workspace')
        self.assertFalse(self.check()['complete'])

    def test_capture_rejects_mutable_in_workspace_manifest(self):
        with self.assertRaises(ValueError):
            quality.capture(self.workspace, self.workspace / 'baseline', 'readiness-envrc-pointers')

    def test_oversized_report_fails_without_echoing_contents(self):
        self.report_path.write_bytes(b'x' * (quality.LIMIT + 1))
        result = self.check()
        self.assertFalse(result['complete'])
        self.assertEqual(result['errors'], ['report_evidence_invalid_or_unavailable'])

    def test_real_scaffolds_capture_external_manifests_in_fake_homes(self):
        for case in quality.CASES:
            with self.subTest(case=case):
                work = self.root / case
                work.mkdir()
                home = self.root / (case + '-home')
                home.mkdir()
                env = {**os.environ, 'HOME': str(home), 'XDG_CONFIG_HOME': str(home),
                       'GIT_CONFIG_NOSYSTEM': '1', 'EVAL_EVIDENCE_DIR': str(self.evidence)}
                result = subprocess.run(['bash', str(EVALS / case / 'fixture.sh')],
                                        cwd=work, env=env, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                manifests = [json.loads(p.read_text()) for p in self.evidence.glob(case + '-*.json')]
                manifest = next(m for m in manifests if m['workspace'] == str(work.resolve()))
                self.assertEqual(manifest['entries'], quality.inventory(work))
                self.assertTrue((work / quality.CASES[case]['project'] / '.git').is_dir())

    def test_scaffold_default_manifest_location_without_operator_environment(self):
        # The CLI gives scaffolds a filtered environment without operator EVAL_* variables.
        case = 'readiness-envrc-pointers'
        suite = self.root / 'suite'
        (suite / case).mkdir(parents=True)
        shutil.copyfile(EVALS / case / 'fixture.sh', suite / case / 'fixture.sh')
        (suite / 'helpers').symlink_to(EVALS / 'helpers', target_is_directory=True)
        work = self.root / 'fresh-workspace'
        work.mkdir()
        home = self.root / 'fake-home'
        home.mkdir()
        env = {'PATH': os.environ['PATH'], 'HOME': str(home), 'GIT_CONFIG_NOSYSTEM': '1'}
        result = subprocess.run(['bash', str(suite / case / 'fixture.sh')], cwd=work,
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifests = list((suite / 'results/manifests').glob('*.json'))
        self.assertEqual(len(manifests), 1)
        self.assertEqual(json.loads(manifests[0].read_text())['workspace'], str(work.resolve()))
