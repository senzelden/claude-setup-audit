"""Drift mode: snapshot builder, log, signals, comparison, CLI and collector summary. Fake homes only."""
import argparse
import contextlib
import io
import json
import os
import stat
import unittest
from pathlib import Path
from unittest import mock
from test_collect import FakeHome, collect
import drift
import drift_log


def parsed(*argv):
    ap = argparse.ArgumentParser()
    collect.add_collection_args(ap)
    ap.add_argument('--ledger')
    ap.add_argument('--drift-log')
    a = ap.parse_args(list(argv))
    collect.apply_collection_args(ap, a)
    return a


class BuildSnapshot(FakeHome):
    def test_build_snapshot_matches_main_output(self):
        self.write('.claude/CLAUDE.md', 'one\ntwo\n')
        self.write('.claude/settings.json', {'permissions': {'allow': ['Bash(sudo ls)']}})
        out = os.path.join(self.home, 'snap.json')
        with mock.patch('sys.argv', ['collect.py', '--claude-dir', self.claude, '--out', out]), \
                mock.patch.object(collect, '_write_snapshot', lambda p, t: Path(p).write_text(t)), \
                contextlib.redirect_stdout(io.StringIO()):
            collect.main()
        written = json.loads(Path(out).read_text())
        built = collect.build_snapshot(parsed('--claude-dir', self.claude))
        for snap in (built, written):
            snap.pop('generated')
        self.assertEqual(json.dumps(built, indent=1), json.dumps(written, indent=1))


class DriftLog(FakeHome):
    def setUp(self):
        super().setUp()
        self.allowed = {os.path.realpath(self.home)}
        self.log = os.path.join(self.home, 'drift.jsonl')

    def entry(self, **over):
        e = {'version': 1, 'at': '2026-09-29T10:00:00Z', 'scope': 'all', 'project': None, 'window_days': 30,
             'signals': {}, 'crossings': []}
        e.update(over)
        return e

    def test_append_creates_private_file_and_reads_back(self):
        drift_log.append(self.log, self.entry(), self.allowed, os.path.join(self.claude, 'audits'))
        drift_log.append(self.log, self.entry(at='2026-09-30T10:00:00Z'), self.allowed, os.path.join(self.claude, 'audits'))
        self.assertEqual(stat.S_IMODE(os.stat(self.log).st_mode), 0o600)
        entries, malformed = drift_log.read(self.log)
        self.assertEqual(([e['at'] for e in entries], malformed), (['2026-09-29T10:00:00Z', '2026-09-30T10:00:00Z'], 0))

    def test_audits_dir_is_created_private(self):
        audits = os.path.join(self.claude, 'audits')
        drift_log.append(os.path.join(audits, 'drift.jsonl'), self.entry(), {os.path.realpath(audits)}, audits)
        self.assertEqual(stat.S_IMODE(os.stat(audits).st_mode), 0o700)

    def test_outside_allowed_and_symlink_are_refused(self):
        with self.assertRaises(drift_log.DriftLogError):
            drift_log.check_path('/etc/drift.jsonl', self.allowed)
        target = self.write('elsewhere.jsonl', '')
        os.symlink(target, self.log)
        with self.assertRaises(drift_log.DriftLogError):
            drift_log.append(self.log, self.entry(), self.allowed, os.path.join(self.claude, 'audits'))
        self.assertEqual(Path(target).read_text(), '')

    def test_missing_parent_outside_audits_is_refused(self):
        with self.assertRaises(drift_log.DriftLogError):
            drift_log.append(os.path.join(self.home, 'nope', 'drift.jsonl'), self.entry(), self.allowed,
                             os.path.join(self.claude, 'audits'))

    def test_partial_last_line_is_malformed_and_append_still_works(self):
        Path(self.log).write_text(json.dumps(self.entry()) + '\n' + '{"version": 1, "at": "2026')
        self.assertEqual(len(drift_log.read(self.log)[0]), 1)
        self.assertEqual(drift_log.read(self.log)[1], 1)
        drift_log.append(self.log, self.entry(at='2026-10-01T00:00:00Z'), self.allowed, os.path.join(self.claude, 'audits'))
        entries, malformed = drift_log.read(self.log)
        self.assertEqual(([e['at'] for e in entries], malformed),
                         (['2026-09-29T10:00:00Z', '2026-10-01T00:00:00Z'], 1))

    def test_wrong_version_non_object_and_bad_json_are_malformed(self):
        Path(self.log).write_text('\n'.join([json.dumps(self.entry(version=2)), '[1]', '{bad', '']) + '\n')
        self.assertEqual(drift_log.read(self.log), ([], 3))

    def test_missing_log_is_empty(self):
        self.assertEqual(drift_log.read(self.log), ([], 0))
