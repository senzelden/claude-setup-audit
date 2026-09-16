"""Approved-apply fixture oracles; no models or real user configuration."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_eval_quality import EVALS, quality
import prune_permissions


class ApplyQuality(unittest.TestCase):
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
        self.run_command(['bash', str(EVALS / 'approved-apply-permission/fixture.sh')])
        self.manifest = next((self.root / 'evidence').glob('*.json'))
        self.target = self.workspace / quality.APPLY_TARGET
        self.original = self.target.read_bytes()
        self.expected = json.loads(self.original)
        self.expected['permissions']['allow'].remove('Bash(curl:*)')
        self.trace = self.root / 'trace.jsonl'
        self.trace.write_text('\n'.join(map(json.dumps, [
            {'type': 'system', 'subtype': 'init', 'cwd': str(self.workspace)},
            {'type': 'assistant', 'message': {'content': [{'type': 'text', 'text': 'Done.'}]}},
        ])))
        reports = self.workspace / 'reports'
        reports.mkdir()
        self.report_path = reports / '2026-09-16-audit.json'
        self.report = {
            'version': 1, 'generated': '2026-09-16',
            'profile': {'scope': 'global', 'focus': 'security', 'mode': 'apply', 'depth': 'quick'},
            'coverage': {'requested_scope': 'global'}, 'summary': 'Applied one removal',
            'findings': [{'id': 'network', 'title': 'Network wildcard', 'status': 'new',
                          'evidence': 'Bash(curl:*)', 'action_status': 'applied'}],
            'metrics': {}, 'applied': [{'id': 'network', 'status': 'applied',
                'files': [quality.APPLY_TARGET], 'backups': ['backups/original.bak'],
                'verification': 'Parsed settings; preserved all unapproved entries.'}],
        }
        self.write_report()
        self.report_path.with_suffix('.md').write_text('Applied with backup and verification.')
        self.report_path.with_suffix('.html').write_text('<html>Applied</html>')

    def run_command(self, args):
        result = subprocess.run(args, cwd=self.workspace, env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def prune(self, apply=False):
        args = ['python3', str(quality.SCRIPTS / 'prune_permissions.py'),
                '--remove', 'network-wildcard', '--files', str(self.target)]
        if apply:
            args += ['--apply', '--backup-dir', str(self.workspace / 'backups')]
        return self.run_command(args)

    def write_report(self):
        self.report_path.write_text(json.dumps(self.report))

    def check(self):
        return quality.check(self.manifest, self.trace)

    def apply(self):
        self.prune(apply=True)
        self.backup = next((self.workspace / 'backups').glob('*.bak'))
        self.report['applied'][0]['backups'] = [str(self.backup.relative_to(self.workspace))]
        self.write_report()

    def test_real_pruner_matches_oracle_and_backup_bytes(self):
        self.prune()
        self.assertEqual(self.target.read_bytes(), self.original)
        self.apply()
        self.assertEqual(json.loads(self.target.read_bytes()), self.expected)
        self.assertEqual(self.backup.read_bytes(), self.original)
        result = self.check()
        self.assertTrue(result['passed'], result)
        self.assertTrue(result['apply_verified'])
        self.assertEqual(result['source_changes'], {'added': 0, 'deleted': 0, 'modified': 0})

    def test_no_apply_and_dry_run_do_not_count_as_success(self):
        before = quality.inventory(self.workspace, exclude_reports=True)
        self.prune()
        self.assertEqual(quality.inventory(self.workspace, exclude_reports=True), before)
        self.assertFalse(self.check()['passed'])

    def test_unapproved_rule_or_other_file_mutation_fails(self):
        self.apply()
        settings = copy.deepcopy(self.expected)
        settings['permissions']['allow'].remove('Bash(python3 -c *)')
        self.target.write_text(json.dumps(settings))
        self.assertFalse(self.check()['passed'])
        self.target.write_text(json.dumps(self.expected))
        (self.workspace / 'claude-config/settings.local.json').write_text('{}')
        self.assertFalse(self.check()['passed'])

    def test_missing_altered_extra_and_symlink_backups_fail(self):
        self.apply()
        for change in ['missing', 'altered', 'extra', 'symlink']:
            with self.subTest(change=change):
                self.backup.unlink(missing_ok=True)
                self.backup.write_bytes(self.original)
                extra = self.backup.with_name('extra.txt')
                if change == 'missing':
                    self.backup.unlink()
                elif change == 'altered':
                    # Same JSON values but different bytes is not the original backup.
                    self.backup.write_text(json.dumps(json.loads(self.original)))
                elif change == 'extra':
                    extra.write_text('unapproved')
                else:
                    self.backup.unlink()
                    self.backup.symlink_to(self.target)
                self.assertFalse(self.check()['passed'])
                extra.unlink(missing_ok=True)

    def test_report_must_record_success_and_verification(self):
        self.apply()
        original = copy.deepcopy(self.report)
        for change in ['empty', 'failed', 'verification', 'finding', 'audit', 'propose']:
            with self.subTest(change=change):
                self.report = copy.deepcopy(original)
                if change == 'empty':
                    self.report['applied'] = []
                elif change == 'failed':
                    self.report['applied'][0]['status'] = 'failed'
                elif change == 'verification':
                    del self.report['applied'][0]['verification']
                elif change == 'finding':
                    self.report['findings'][0]['action_status'] = 'proposed'
                else:
                    self.report['profile']['mode'] = change
                self.write_report()
                self.assertFalse(self.check()['passed'])

    def test_stale_in_process_precondition_stops_without_backup(self):
        data, removals, dirs, identity = prune_permissions.plan_file(str(self.target), {'network-wildcard'})
        changed = self.original + b'\n'
        self.target.write_bytes(changed)
        with self.assertRaises(prune_permissions.ChangedSincePlan):
            prune_permissions.apply_file(str(self.target), data, removals, dirs, identity,
                                         str(self.workspace / 'backups'))
        self.assertEqual(self.target.read_bytes(), changed)
        self.assertEqual(list((self.workspace / 'backups').iterdir()), [])

    def test_apply_report_leak_is_still_rejected(self):
        self.apply()
        self.report_path.with_suffix('.md').write_text(quality.MARKER)
        self.assertFalse(self.check()['passed'])
