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
        old_umask = os.umask(0o277)
        self.addCleanup(os.umask, old_umask)
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

    def test_log_path_that_is_a_directory_raises_drift_log_error(self):
        os.mkdir(self.log)
        with self.assertRaises(drift_log.DriftLogError) as cm:
            drift_log.append(self.log, self.entry(), self.allowed, os.path.join(self.claude, 'audits'))
        self.assertNotIn(self.home, str(cm.exception))
        self.assertEqual(os.listdir(self.log), [])

    def test_short_write_raises_drift_log_error(self):
        with mock.patch('drift_log.os.write', return_value=1):
            with self.assertRaises(drift_log.DriftLogError):
                drift_log.append(self.log, self.entry(), self.allowed, os.path.join(self.claude, 'audits'))

    def test_pathological_nesting_is_malformed(self):
        Path(self.log).write_text('[' * 100000 + '\n')
        self.assertEqual(drift_log.read(self.log), ([], 1))


def snapshot(**over):
    snap = {
        'global': {'claude_md': {'lines': 50, 'est_tokens': 900},
                   'settings': [{'path': '~/.claude/settings.json',
                                 'permissions': {'risky': {'sudo': ['Bash(sudo ls)']}}}]},
        'projects': {'~/code/app': {'claude_md_lines': 120, 'claude_md_tokens': 2000},
                     '~/code/app/.worktrees/x': {'claude_md_lines': 999, 'is_worktree_copy': True}},
        'transcripts': {'cache': {'hit_ratio': 0.95}},
        'coverage': {'sources': [{'source': 'transcripts.main_files', 'status': 'collected'}]},
        'harness_overhead': {'complete': True,
                             'skill_listing_series': {'last': {'chars': 10000}},
                             'injected_context': {'sources': [{'plugin': 'p@m', 'hook_event': 'SessionStart',
                                                               'est_tokens_per_session_median': 800}]}},
    }
    snap.update(over)
    return snap


META = {'scope': 'all', 'project': None, 'window_days': 30}
LIMITS = {'claude_md_max_lines': 200, 'cache_hit_min': 0.9, 'growth_min': 0.25}


class Signals(unittest.TestCase):
    def test_derive_all_signals(self):
        signals, fps = drift.derive(snapshot(), '~/.claude/CLAUDE.md')
        self.assertEqual(signals['claude_md'], {'~/.claude/CLAUDE.md': {'lines': 50, 'est_tokens': 900},
                                                '~/code/app/CLAUDE.md': {'lines': 120, 'est_tokens': 2000}})
        self.assertEqual(signals['cache_hit_ratio'], {'value': 0.95, 'complete': True})
        fp = drift.fingerprint('~/.claude/settings.json', 'sudo', 'Bash(sudo ls)')
        self.assertEqual(signals['broad_permissions'], {'count': 1, 'fingerprints': [fp]})
        self.assertEqual(fps, {fp: '~/.claude/settings.json'})
        self.assertEqual(signals['skill_listing_chars'], {'value': 10000, 'complete': True})
        self.assertEqual(signals['injected_tokens'], {'value': 800, 'plugin': 'p@m', 'hook_event': 'SessionStart',
                                                      'complete': True})

    def test_missing_sources_are_null(self):
        signals, _ = drift.derive({'global': {}, 'projects': {}, 'transcripts': {'cache': {'hit_ratio': None}}},
                                  '~/.claude/CLAUDE.md')
        self.assertEqual([signals[k] for k in ('claude_md', 'cache_hit_ratio', 'skill_listing_chars', 'injected_tokens')],
                         [None, None, None, None])
        self.assertEqual(signals['broad_permissions'], {'count': 0, 'fingerprints': []})

    def test_partial_transcripts_mark_cache_incomplete(self):
        snap = snapshot(coverage={'sources': [{'source': 'transcripts.main_files', 'status': 'partial'}]})
        self.assertFalse(drift.derive(snap, 'g')[0]['cache_hit_ratio']['complete'])


class Compare(unittest.TestCase):
    def run_compare(self, snap, entries=(), meta=META):
        signals, fps = drift.derive(snap, '~/.claude/CLAUDE.md')
        return drift.compare(signals, fps, list(entries), meta, LIMITS)

    def entry(self, snap, **meta):
        return dict({'version': 1, 'at': '2026-09-28T00:00:00Z', **META, **meta},
                    signals=drift.derive(snap, '~/.claude/CLAUDE.md')[0], crossings=[])

    def test_first_run_is_a_baseline(self):
        self.assertEqual(self.run_compare(snapshot()), [])

    def test_above_max_and_below_min(self):
        snap = snapshot(transcripts={'cache': {'hit_ratio': 0.61}})
        snap['global']['claude_md']['lines'] = 250
        self.assertEqual(self.run_compare(snap), [
            {'signal': 'claude_md', 'kind': 'above_max', 'path': '~/.claude/CLAUDE.md', 'value': 250, 'threshold': 200},
            {'signal': 'cache_hit_ratio', 'kind': 'below_min', 'value': 0.61, 'threshold': 0.9}])

    def test_new_broad_permission_against_previous(self):
        before = self.entry(snapshot())
        now = snapshot()
        now['global']['settings'][0]['permissions']['risky']['sudo'].append('Bash(sudo rm)')
        crossings = self.run_compare(now, [before])
        self.assertEqual(crossings, [{'signal': 'broad_permissions', 'kind': 'new',
                                      'fingerprints': [drift.fingerprint('~/.claude/settings.json', 'sudo', 'Bash(sudo rm)')],
                                      'paths': ['~/.claude/settings.json']}])

    def test_growth_and_threshold_edges(self):
        before = self.entry(snapshot())
        now = snapshot()
        now['harness_overhead']['skill_listing_series']['last']['chars'] = 12500  # exactly +25%
        now['harness_overhead']['injected_context']['sources'][0]['est_tokens_per_session_median'] = 999  # +24.9%
        self.assertEqual(self.run_compare(now, [before]), [
            {'signal': 'skill_listing_chars', 'kind': 'growth', 'value': 12500, 'previous': 10000,
             'fraction': 0.25, 'threshold': 0.25}])

    def test_injected_growth_needs_same_plugin_and_event(self):
        before = self.entry(snapshot())
        now = snapshot()
        now['harness_overhead']['injected_context']['sources'][0].update(plugin='other@m',
                                                                         est_tokens_per_session_median=5000)
        self.assertEqual(self.run_compare(now, [before]), [])

    def test_other_scope_is_not_comparable(self):
        before = self.entry(snapshot(), scope='project', project='/x')
        now = snapshot()
        now['harness_overhead']['skill_listing_series']['last']['chars'] = 50000
        now['global']['settings'][0]['permissions']['risky']['sudo'].append('Bash(sudo rm)')
        self.assertEqual(self.run_compare(now, [before]), [])

    def test_comparable_skips_null_and_growth_from_zero(self):
        zero = snapshot()
        zero['harness_overhead']['skill_listing_series']['last']['chars'] = 0
        null = snapshot(harness_overhead={'complete': True, 'skill_listing_series': None,
                                          'injected_context': {'sources': []}})
        entries = [self.entry(zero), self.entry(null)]
        self.assertIsNone(drift.comparable(entries[1:], META, 'skill_listing_chars'))
        self.assertEqual(drift.comparable(entries, META, 'skill_listing_chars'), {'value': 0, 'complete': True})
        self.assertEqual(self.run_compare(snapshot(), entries), [])


class CorruptLog(unittest.TestCase):
    run_compare = Compare.run_compare
    entry = Compare.entry

    def corrupt(self, **signals):
        return {'version': 1, 'at': 'x', **META, 'signals': signals, 'crossings': []}

    def test_corrupt_previous_shapes_never_crash(self):
        now = snapshot()
        now['global']['settings'] = []
        now['harness_overhead']['skill_listing_series']['last']['chars'] = 99999
        bad = self.corrupt(broad_permissions={'count': 5, 'fingerprints': 3},
                           skill_listing_chars={'value': 'x', 'complete': True},
                           injected_tokens={'value': True, 'plugin': 'p@m', 'hook_event': 'SessionStart'})
        self.assertEqual(self.run_compare(now, [bad]), [])
        for junk in (5, 'x', [1], True):
            entry = self.corrupt(broad_permissions=junk, skill_listing_chars=junk, injected_tokens=junk)
            self.assertEqual(self.run_compare(now, [entry]), [])
        self.assertEqual(self.run_compare(now, [{'signals': 7, **META}]), [])

    def test_non_list_fingerprints_are_not_comparable(self):
        now = snapshot()  # one risky rule
        bad = self.corrupt(broad_permissions={'count': 1, 'fingerprints': 3})
        self.assertEqual(self.run_compare(now, [bad]), [])
        good = self.entry(snapshot())
        self.assertEqual(self.run_compare(now, [good, bad]), [])
        now['global']['settings'][0]['permissions']['risky']['sudo'].append('Bash(sudo rm)')
        self.assertEqual([c['kind'] for c in self.run_compare(now, [good, bad])], ['new'])

    def test_corrupt_latest_falls_back_to_earlier_dict(self):
        good = self.entry(snapshot())
        bad = self.corrupt(skill_listing_chars=5)
        now = snapshot()
        now['harness_overhead']['skill_listing_series']['last']['chars'] = 20000
        self.assertEqual([c['signal'] for c in self.run_compare(now, [good, bad])], ['skill_listing_chars'])

    def test_injected_growth_fires(self):
        before = self.entry(snapshot())
        now = snapshot()
        now['harness_overhead']['injected_context']['sources'][0]['est_tokens_per_session_median'] = 1000
        self.assertEqual(self.run_compare(now, [before]), [
            {'signal': 'injected_tokens', 'kind': 'growth', 'value': 1000, 'previous': 800,
             'fraction': 0.25, 'threshold': 0.25}])

    def test_incomplete_does_not_suppress_cache_crossing(self):
        snap = snapshot(transcripts={'cache': {'hit_ratio': 0.5}},
                        coverage={'sources': [{'source': 'transcripts.main_files', 'status': 'partial'}]})
        crossings = self.run_compare(snap)
        self.assertEqual([(c['signal'], c['kind']) for c in crossings], [('cache_hit_ratio', 'below_min')])


class DriftCli(FakeHome):
    def run_drift(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        log = os.path.join(self.home, 'drift.jsonl')
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = drift.main(['--claude-dir', self.claude, '--scope', 'global', '--log', log, *extra])
        return code, out.getvalue(), err.getvalue(), log

    def test_silent_without_crossings_and_one_line_with(self):
        self.write('.claude/CLAUDE.md', 'short\n')
        code, out, _, log = self.run_drift()
        self.assertEqual((code, out), (0, ''))
        self.write('.claude/CLAUDE.md', 'x\n' * 250)
        code, out, _, _ = self.run_drift()
        self.assertEqual(code, 0)
        self.assertEqual(out.count('\n'), 1)
        self.assertTrue(out.startswith('setup-audit drift: 1 crossed ('))
        self.assertLessEqual(len(out.strip()), 300)
        entries, malformed = drift_log.read(log)
        self.assertEqual((len(entries), malformed), (2, 0))
        self.assertEqual(entries[1]['crossings'][0]['kind'], 'above_max')

    def test_new_permission_on_second_run(self):
        self.write('.claude/settings.json', {'permissions': {'allow': ['Bash(sudo ls)']}})
        self.assertEqual(self.run_drift()[1], '')
        self.write('.claude/settings.json', {'permissions': {'allow': ['Bash(sudo ls)', 'Bash(sudo cat *)']}})
        out = self.run_drift()[1]
        self.assertIn('new broad permission in ~/.claude/settings.json', out)

    def test_refused_log_exits_1_without_writing(self):
        with mock.patch.object(collect, 'build_snapshot') as build:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = drift.main(['--claude-dir', self.claude, '--log', '/etc/drift.jsonl'])
        self.assertEqual((code, out.getvalue()), (1, ''))
        self.assertIn('setup-audit drift:', err.getvalue())
        build.assert_not_called()
        self.assertFalse(os.path.exists('/etc/drift.jsonl'))

    def test_collection_failure_exits_1_without_writing(self):
        with mock.patch.object(collect, 'build_snapshot', side_effect=RuntimeError('SECRET-DETAIL')):
            code, out, err, log = self.run_drift()
        self.assertEqual((code, out), (1, ''))
        self.assertNotIn('SECRET-DETAIL', err)
        self.assertFalse(os.path.exists(log))

    def test_usage_errors_exit_2(self):
        for argv in (['--growth-min', '0'], ['--cache-hit-min', '1.5'], ['--claude-md-max-lines', '0']):
            with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stderr(io.StringIO()):
                drift.main(['--claude-dir', self.claude, *argv])
            self.assertEqual(ctx.exception.code, 2)

    def test_log_holds_no_rule_or_claude_md_text(self):
        canary = 'DRIFT-CANARY-9c1e'
        self.write('.claude/settings.json', {'permissions': {'allow': [f'Bash(sudo {canary})']}})
        self.write('.claude/CLAUDE.md', f'{canary}\n' * 3)
        _, out, err, log = self.run_drift()
        self.assertNotIn(canary, Path(log).read_text())
        self.assertNotIn(canary, out + err)
        entries, _ = drift_log.read(log)
        self.assertGreaterEqual(entries[0]['signals']['broad_permissions']['count'], 1)

    def test_default_log_lives_in_audits(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drift.main(['--claude-dir', self.claude, '--scope', 'global']), 0)
        path = os.path.join(self.claude, 'audits', 'drift.jsonl')
        self.assertEqual(len(drift_log.read(path)[0]), 1)

    def test_summary_line_keeps_log_suffix_when_truncated(self):
        crossings = [{'signal': 'claude_md', 'kind': 'above_max', 'path': f'/p/{i}/CLAUDE.md' + 'x' * 30,
                      'value': 999, 'threshold': 200} for i in range(20)]
        log = '~/.claude/audits/' + 'd' * 60 + '/drift.jsonl'
        line = drift.summary_line(crossings, log)
        self.assertLessEqual(len(line), 300)
        self.assertNotIn('\n', line)
        self.assertTrue(line.endswith('; log ' + log))

    def test_newline_in_displayed_path_stays_one_line(self):
        crossings = [{'signal': 'claude_md', 'kind': 'above_max', 'path': '/p/a\nb\rc/CLAUDE.md',
                      'value': 999, 'threshold': 200}]
        line = drift.summary_line(crossings, '/tmp/x\ny.jsonl')
        self.assertFalse(set(line) & {'\n', '\r'})

    def test_default_log_follows_claude_config_dir(self):
        import importlib
        cfg = os.path.join(self.home, 'cfg')
        os.makedirs(cfg)
        saved = (collect.HOME, collect.CLAUDE)
        try:
            with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': cfg}):
                importlib.reload(collect)
            collect.HOME = self.home
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(drift.main(['--scope', 'global']), 0)
        finally:
            importlib.reload(collect)
            collect.HOME, collect.CLAUDE = saved
        self.assertEqual(len(drift_log.read(os.path.join(cfg, 'audits', 'drift.jsonl'))[0]), 1)


class Summary(unittest.TestCase):
    def test_summarize_counts_dates_scopes(self):
        e1 = {'version': 1, 'at': '2026-09-01T00:00:00Z', 'scope': 'all',
              'signals': {'cache_hit_ratio': {'value': 0.95}, 'claude_md': {'a': {'lines': 10}, 'b': {'lines': 30}},
                          'broad_permissions': {'count': 2, 'fingerprints': ['x', 'y']}},
              'crossings': []}
        e2 = {'version': 1, 'at': '2026-09-05T00:00:00Z', 'scope': 'global',
              'signals': {'cache_hit_ratio': None, 'claude_md': {'a': {'lines': 250}},
                          'broad_permissions': {'count': 3, 'fingerprints': []}},
              'crossings': [{'signal': 'claude_md', 'kind': 'above_max'}]}
        s = drift_log.summarize([e1, e2], 1, '~/.claude/audits/drift.jsonl')
        self.assertEqual({k: s[k] for k in ('status', 'entries', 'malformed', 'first_at', 'last_at')},
                         {'status': 'collected', 'entries': 2, 'malformed': 1,
                          'first_at': '2026-09-01T00:00:00Z', 'last_at': '2026-09-05T00:00:00Z'})
        self.assertEqual(s['signals']['claude_md'], {'last_value': 250, 'crossings': 1,
                                                     'first_crossing_at': '2026-09-05T00:00:00Z',
                                                     'last_crossing_at': '2026-09-05T00:00:00Z',
                                                     'scopes': ['all', 'global']})
        self.assertEqual(s['signals']['cache_hit_ratio']['last_value'], 0.95)
        self.assertEqual(s['signals']['broad_permissions']['last_value'], 3)
        self.assertNotIn('injected_tokens', s['signals'])

    def test_wrong_value_types_never_crash(self):
        bad = {'version': 1, 'at': 5, 'scope': ['x'],
               'signals': {'cache_hit_ratio': {'value': 'high'}, 'claude_md': {'a': {'lines': True}, 'b': 7},
                           'broad_permissions': {'count': [1]}, 'skill_listing_chars': 'oops'},
               'crossings': 'nope'}
        s = drift_log.summarize([bad], 0, 'p')
        self.assertIsNone(s['first_at'])
        for name in ('cache_hit_ratio', 'claude_md', 'broad_permissions'):
            self.assertIsNone(s['signals'][name]['last_value'])
            self.assertEqual(s['signals'][name]['scopes'], [])
        self.assertNotIn('skill_listing_chars', s['signals'])


class CollectorDriftLog(FakeHome):
    def test_snapshot_carries_drift_signals(self):
        log = os.path.join(self.home, 'drift.jsonl')
        with contextlib.redirect_stdout(io.StringIO()):
            drift.main(['--claude-dir', self.claude, '--scope', 'global', '--log', log])
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--scope', 'global', '--drift-log', log))
        self.assertEqual((snap['drift_signals']['status'], snap['drift_signals']['entries']), ('collected', 1))

    def test_unreadable_log_is_invalid(self):
        directory = os.path.join(self.home, 'adir')
        os.makedirs(directory)
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--scope', 'global', '--drift-log', directory))
        self.assertEqual(snap['drift_signals']['status'], 'invalid')

    def test_without_flag_no_section(self):
        self.assertNotIn('drift_signals', collect.build_snapshot(parsed('--claude-dir', self.claude, '--scope', 'global')))

    def test_path_outside_allowed_dirs_is_invalid(self):
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--scope', 'global',
                                             '--drift-log', '/etc/drift.jsonl'))
        self.assertEqual(snap['drift_signals'], {'status': 'invalid', 'path': '/etc/drift.jsonl'})

    def test_symlinked_log_is_invalid(self):
        real = os.path.join(self.home, 'real.jsonl')
        Path(real).write_text('')
        link = os.path.join(self.home, 'link.jsonl')
        os.symlink(real, link)
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--scope', 'global', '--drift-log', link))
        self.assertEqual(snap['drift_signals']['status'], 'invalid')
