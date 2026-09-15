"""Report rendering regressions; all file writes use temporary directories."""
import copy
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / 'plugins/setup-audit/skills/setup-audit/scripts'
sys.path.insert(0, str(SCRIPTS))
import render_report


class Elements(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.elements = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ReportTests(unittest.TestCase):
    def report(self):
        return {'version': 1, 'generated': '2026-09-15',
                'profile': {'scope': 'project'},
                'coverage': {'sources': [{'source': 'transcripts', 'status': 'partial',
                                          'scanned': 10, 'omitted': 2}]},
                'metrics': {'tokens': {'value': 42, 'basis': 'measured'},
                            'overhead': {'value': 12, 'basis': 'estimated'}},
                'findings': [{'id': 'low', 'title': 'Low item', 'score': 1},
                             {'id': 'high', 'title': 'High item', 'score': 3,
                              'evidence': [{'source': 'settings.json', 'detail': 'rule'}],
                              'fix': {'before': 'old\ntext', 'after': 'new'},
                              'status': 'open', 'action_status': 'failed'}],
                'applied': [{'id': 'high', 'status': 'failed', 'verification': 'check failed'}]}

    def test_content_ranking_and_determinism(self):
        report = self.report()
        original = copy.deepcopy(report)
        output = render_report.render(report)
        self.assertEqual(output, render_report.render(report))
        self.assertEqual(report, original)
        self.assertLess(output.index('1. High item'), output.index('2. Low item'))
        for text in ('partial', 'Omitted', 'measured', 'estimated', 'settings.json',
                     'old\ntext', 'Action status', 'failed', 'check failed'):
            self.assertIn(text, output)

    def test_all_untrusted_fields_are_inert(self):
        attack = '</style><script>alert(1)</script><img src="https://bad" onerror="x"> & \' "'
        report = self.report()
        report.update(summary=attack, caveats=[attack], profile={attack: attack})
        report['findings'][0].update(title=attack, evidence=attack,
                                     docs=['javascript:alert(1)', attack], fix={'after': attack})
        report['applied'] = [{attack: attack}]
        output = render_report.render(report)
        self.assertNotIn(attack, output)
        self.assertIn('&lt;script&gt;', output)
        for tag, attrs in Elements(output).elements:
            self.assertNotIn(tag, ('script', 'img', 'iframe', 'link', 'object'))
            self.assertFalse(any(k.startswith('on') or k == 'src' for k in attrs))
            if 'href' in attrs:
                self.assertTrue(attrs['href'].startswith('#'))

    def test_legacy_empty_and_separate_sections(self):
        output = render_report.render({'version': 1})
        self.assertIn('Not reported. Requested scope', output)
        self.assertIn('No findings reported', output)
        report = self.report()
        report['findings'] += [dict(id='park', title='Park item', type='parked', score=99),
                               dict(id='done', title='Done item', status='resolved', score=99),
                               dict(id='hidden', title='Hidden item', status='suppressed', score=99)]
        output = render_report.render(report)
        self.assertIn('1. High item', output)
        self.assertNotIn('3. ', output)
        for title in ('Park item', 'Done item', 'Hidden item'):
            self.assertEqual(output.count(title), 1)

    def test_readable_summary_actions_and_metric_explanation(self):
        report = self.report()
        report['example'] = True
        report['summary'] = 'One permission needs your attention.'
        report['findings'][1].update(why='This can affect files outside the repo.',
                                    action_status='proposed',
                                    fix={'summary': 'Remove the broad permission.', 'before': 'old', 'after': 'new'})
        report['metrics']['tokens'].update(label='Typical starting context', unit='tokens',
                                          explanation='Context already in use before work begins.')
        output = render_report.render(report)
        self.assertLess(output.index('At a glance'), output.index('1. High item'))
        for text in ('Example report · fictional data', 'Awaiting your approval',
                     'This can affect files outside the repo.', 'Remove the broad permission.',
                     'Typical starting context', 'Context already in use before work begins.'):
            self.assertIn(text, output)
        details = [attrs for tag, attrs in Elements(output).elements if tag == 'details']
        self.assertTrue(details)
        self.assertTrue(all('open' not in attrs for attrs in details))
        self.assertNotIn('Lower-value changes to consider later', output)
        self.assertNotIn('Accepted exceptions', output)

    def test_invalid_contract(self):
        for report in ([], {'version': True}, {'version': 2}, {'version': 1, 'findings': [{}], 'applied': [1]},
                       {'version': 1, 'findings': ['bad']},
                       *({'version': 1, 'findings': [{'score': score}]} for score in ('3', True, float('nan'), float('inf')))):
            with self.subTest(report=report), self.assertRaises(ValueError):
                render_report.render(report)

    def test_cli_sibling_private_output_and_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'audit.json'
            source.write_text(json.dumps(self.report()))
            result = subprocess.run([sys.executable, str(SCRIPTS / 'render_report.py'), str(source)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            target = source.with_suffix('.html')
            self.assertEqual(result.stdout.strip(), str(target))
            if os.name == 'posix':
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            report = self.report()
            report['findings'][1]['action_status'] = 'applied'
            source.write_text(json.dumps(report))
            render_report.write_report(source)
            self.assertIn('applied', target.read_text())
            self.assertEqual(json.loads(source.read_text()), report)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ['audit.html', 'audit.json'])

    def test_failed_write_preserves_existing_output_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'audit.json'
            source.write_text('{"version":1}')
            target = source.with_suffix('.html')
            target.write_text('previous')
            with mock.patch.object(render_report.os, 'replace', side_effect=OSError), self.assertRaises(OSError):
                render_report.write_report(source)
            self.assertEqual(target.read_text(), 'previous')
            self.assertEqual(len(list(Path(tmp).iterdir())), 2)

    @unittest.skipUnless(os.name == 'posix', 'POSIX symlink behavior')
    def test_existing_output_symlink_does_not_modify_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'audit.json'
            source.write_text('{"version":1}')
            victim = Path(tmp) / 'untouched'
            victim.write_text('original')
            target = source.with_suffix('.html')
            target.symlink_to(victim)
            render_report.write_report(source)
            self.assertFalse(target.is_symlink())
            self.assertEqual(victim.read_text(), 'original')

    def test_invalid_json_error_does_not_echo_input_or_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'audit.json'
            source.write_text('PRIVATE INVALID CONTENT')
            target = source.with_suffix('.html')
            target.write_text('previous')
            result = subprocess.run([sys.executable, str(SCRIPTS / 'render_report.py'), str(source)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('PRIVATE', result.stdout + result.stderr)
            self.assertEqual(target.read_text(), 'previous')


if __name__ == '__main__':
    unittest.main()
