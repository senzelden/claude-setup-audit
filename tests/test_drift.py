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
