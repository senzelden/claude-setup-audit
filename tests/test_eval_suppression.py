"""Exercise the real report processor and independent suppression oracle without models."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_eval_quality import EVALS, quality


class SuppressionQuality(unittest.TestCase):
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
        self.run_command(['bash', str(EVALS / 'decision-suppression/fixture.sh')])
        self.manifest = next((self.root / 'evidence').glob('*.json'))
        self.inputs = self.workspace / 'inputs'
        reports = self.workspace / 'reports'
        reports.mkdir()
        self.report_path = reports / 'current-audit.json'
        self.report_path.write_bytes((self.inputs / 'current.json').read_bytes())
        self.trace = self.root / 'trace.jsonl'
        self.trace.write_text('\n'.join(map(json.dumps, [
            {'type': 'system', 'subtype': 'init', 'cwd': str(self.workspace)},
            {'type': 'assistant', 'message': {'content': [{'type': 'text', 'text': 'Reviewed.'}]}},
        ])))
        self.run_command(['python3', str(quality.SCRIPTS / 'process_report.py'),
                          str(self.report_path), '--previous', str(self.inputs / 'previous.json'),
                          '--decisions', str(self.inputs / 'decisions.json'), '--finalize'])
        self.report = json.loads(self.report_path.read_text())
        self.run_command(['python3', str(quality.SCRIPTS / 'render_report.py'), str(self.report_path)])
        self.report_path.with_suffix('.md').write_text('Synthetic decision review.')

    def run_command(self, args):
        result = subprocess.run(args, cwd=self.workspace, env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def check(self):
        return quality.check(self.manifest, self.trace)

    def write_report(self):
        self.report_path.write_text(json.dumps(self.report))

    def test_real_finalization_preserves_inputs_and_matches_independent_oracle(self):
        result = self.check()
        self.assertTrue(result['passed'], result)
        self.assertFalse(result['collector_ran'])  # This is report-finalization evidence only.
        self.assertEqual([f['status'] for f in self.report['findings']],
                         ['suppressed', 'suppressed', 'open', 'open', 'new'])
        self.assertEqual(result['source_changes'], {'added': 0, 'deleted': 0, 'modified': 0})

    def test_suppressed_is_retained_not_resolved_or_applied(self):
        original = copy.deepcopy(self.report)
        for change in ['omitted', 'resolved', 'applied', 'reason']:
            with self.subTest(change=change):
                self.report = copy.deepcopy(original)
                finding = self.report['findings'][0]
                if change == 'omitted':
                    self.report['findings'].pop(0)
                elif change == 'resolved':
                    finding['status'] = 'resolved'
                elif change == 'applied':
                    finding['action_status'] = 'applied'
                else:
                    finding['decision']['reason'] = 'Invented reason'
                self.write_report()
                self.assertFalse(self.check()['passed'])

    def test_negative_controls_cannot_be_suppressed_or_omitted(self):
        original = copy.deepcopy(self.report)
        for index in (2, 3, 4):
            for change in ('suppressed', 'omitted', 'reason'):
                with self.subTest(index=index, change=change):
                    self.report = copy.deepcopy(original)
                    if change == 'omitted':
                        self.report['findings'].pop(index)
                    elif change == 'suppressed':
                        self.report['findings'][index]['status'] = 'suppressed'
                    else:
                        self.report['findings'][index]['decision']['result'] = 'suppressed'
                    self.write_report()
                    self.assertFalse(self.check()['passed'])

    def test_model_cannot_rewrite_evidence_dates_or_decisions_to_pass(self):
        original = copy.deepcopy(self.report)
        for change in ('evidence', 'date', 'decision', 'source'):
            with self.subTest(change=change):
                self.report = copy.deepcopy(original)
                if change == 'evidence':
                    self.report['findings'][2]['evidence'] = 'old evidence'
                elif change == 'date':
                    self.report['generated'] = '2000-01-01'
                elif change == 'decision':
                    self.report['findings'][3]['decision']['review_after'] = '2099-01-01'
                else:
                    (self.inputs / 'decisions.json').write_text('[]')
                self.write_report()
                self.assertFalse(self.check()['passed'])

    def test_raw_unfinalized_input_is_not_a_passing_report(self):
        self.report_path.write_bytes((self.inputs / 'current.json').read_bytes())
        self.assertFalse(self.check()['passed'])
