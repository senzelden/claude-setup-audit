"""Managed collection uses fake homes and never executes discovered commands."""
import json
import os
from unittest import mock
from test_collect import FakeHome, collect


class ManagedSettings(FakeHome):
    def scan(self):
        with mock.patch.object(collect, 'managed_directory', return_value=self.home):
            return collect.collect_managed_settings()

    def test_absence_does_not_prove_no_policy(self):
        result = self.scan()
        self.assertEqual(result['effective_policy'], 'unknown')
        self.assertEqual(result['sources'][0]['status'], 'absent')
        self.assertEqual(result['sources'][-1]['status'], 'not_checked')

    def test_summaries_order_redaction_and_no_execution(self):
        self.write('managed-settings.json', {'permissions': {'allow': ['Bash(*)']},
                   'env': {'SECRET': 'opaque-private-value'}, 'policyHelper': 'touch NEVER'})
        self.write('managed-settings.d/20.json', {'model': 'second'})
        self.write('managed-settings.d/10.json', {'model': 'first'})
        self.write('managed-settings.d/.hidden.json', {'model': 'hidden'})
        with mock.patch.object(collect.subprocess, 'run', side_effect=AssertionError('execution')):
            result = self.scan()
        self.assertEqual([s['model'] for s in result['settings']], [None, 'first', 'second'])
        self.assertIn('wildcard-all', result['settings'][0]['permissions']['risky'])
        self.assertNotIn('opaque-private-value', json.dumps(result))
        self.assertNotIn('touch NEVER', json.dumps(result))

    def test_invalid_and_oversized_files(self):
        for content in ('{', '[]', '{"hooks": 1}', '{"permissions":{"allow":[1]}}'):
            self.write('managed-settings.json', content)
            self.assertEqual(self.scan()['sources'][0]['reason'], 'invalid_settings')
        self.write('managed-settings.json', ' ' * 20)
        with mock.patch.object(collect, 'MANAGED_MAX_BYTES', 10):
            self.assertEqual(self.scan()['sources'][0]['reason'], 'byte_limit')

    def test_unreadable_is_not_absent(self):
        with mock.patch.object(collect.os, 'open', side_effect=PermissionError):
            self.assertEqual(self.scan()['sources'][0]['reason'], 'read_failed')

    def test_file_cap_and_nonregular(self):
        os.mkfifo(os.path.join(self.home, 'managed-settings.json'))
        self.write('managed-settings.d/1.json', {})
        self.write('managed-settings.d/2.json', {})
        with mock.patch.object(collect, 'MANAGED_MAX_FILES', 1):
            result = self.scan()
        self.assertEqual(result['sources'][0]['reason'], 'not_regular_file')
        directory = next(s for s in result['sources'] if s['source'].endswith('.d'))
        self.assertEqual((directory['status'], directory['omitted']), ('partial', 1))

    def test_dangling_link_and_unsupported_platform(self):
        os.symlink('missing', os.path.join(self.home, 'managed-settings.json'))
        self.assertEqual(self.scan()['sources'][0]['status'], 'unavailable')
        with mock.patch.object(collect, 'managed_directory', return_value=None):
            self.assertEqual(collect.collect_managed_settings()['sources'][0]['status'], 'not_checked')

    def test_shared_coverage_preserves_counts_and_scope(self):
        for scope in ('global', 'project', 'all'):
            counts = {'eligible': 3, 'scanned': 2, 'omitted': 1, 'unknown_date': 1}
            snap = {'collection_scope': {'requested': scope}, 'managed_settings': self.scan(),
                    'usage': {'coverage': {'session_meta': counts}}, 'transcripts': {'coverage': {}}}
            coverage = collect.snapshot_coverage(snap, [self.home])
            source = next(s for s in coverage['sources'] if s['source'] == 'usage.session_meta')
            self.assertEqual(source['scope'], scope)
            self.assertEqual(source['status'], 'partial')
            self.assertEqual(source['omitted'], 1)
            self.assertEqual(counts['scanned'], 2)
