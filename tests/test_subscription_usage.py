"""Rate-limit log analysis. Temp dirs only."""
import json
import os
import random
import sys
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins', 'setup-audit',
                                                'skills', 'setup-audit', 'scripts')))
import subscription_usage as su  # noqa: E402

T0 = 1_800_000_000
H = 3600
D = 24 * H


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def entry(t, kind='seven_day', pct=10, resets=None):
    return {'version': 1, 'at': iso(t), 'windows': {kind: {'used_percentage': pct, 'resets_at': resets}}}


def weekly(last_before_reset, pct, resets):
    return entry(resets - last_before_reset, 'seven_day', pct, resets)


class Headroom(unittest.TestCase):
    def test_closed_window_headroom(self):
        entries = [weekly(2 * H, p, T0 + i * 7 * D) for i, p in enumerate((30, 45, 80))]
        r = su.analyze_windows(entries, T0 + 30 * D)['seven_day']
        self.assertEqual(r['closed'], 3)
        self.assertEqual(r['unused_at_close_pct']['median'], 55)
        self.assertEqual(r['stale_excluded'], 0)
        self.assertEqual(r['median_lead_hours'], 2)

    def test_stale_window_excluded(self):
        entries = [weekly(30 * H, 50, T0),
                   entry(T0 - 90 * 60, 'five_hour', 40, T0)]
        r = su.analyze_windows(entries, T0 + D)
        self.assertEqual(r['seven_day']['stale_excluded'], 1)
        self.assertIsNone(r['seven_day']['unused_at_close_pct'])
        self.assertEqual(r['five_hour']['stale_excluded'], 1)
        self.assertIsNone(r['five_hour']['peak_used_pct'])

    def test_current_window(self):
        entries = [weekly(2 * H, 30, T0), weekly(D, 20, T0 + 7 * D)]
        r = su.analyze_windows(entries, T0 + 2 * D)['seven_day']
        self.assertEqual(r['closed'], 1)
        self.assertEqual(r['windows'], 2)
        self.assertEqual(r['current'], {'used_percentage': 20, 'resets_at': T0 + 7 * D})

    def test_closed_by_now_not_last_entry(self):
        r = su.analyze_windows([weekly(2 * H, 30, T0)], T0 + 5 * D)['seven_day']
        self.assertEqual(r['closed'], 1)
        self.assertIsNone(r['current'])

    def test_reached_counts(self):
        entries = [weekly(H, 86, T0), weekly(H, 100, T0 + 7 * D), weekly(H, 50, T0 + 14 * D)]
        r = su.analyze_windows(entries, T0 + 30 * D)['seven_day']
        self.assertEqual((r['reached_85'], r['reached_100']), (2, 1))

    def test_peak_is_max_in_window(self):
        entries = [entry(T0 - 3 * H, pct=70, resets=T0), entry(T0 - H, pct=60, resets=T0)]
        r = su.analyze_windows(entries, T0 + H)['seven_day']
        self.assertEqual(r['peak_used_pct']['max'], 70)
        self.assertEqual(r['unused_at_close_pct']['median'], 30)

    def test_unused_is_100_minus_peak_not_last_value(self):
        # A lower value logged after the peak (another session's stale reading) never raises unused.
        entries = [entry(T0 - 5 * H, pct=80, resets=T0), entry(T0 - H, pct=20, resets=T0)]
        r = su.analyze_windows(entries, T0 + H)['seven_day']
        self.assertEqual(r['unused_at_close_pct'], {'min': 20, 'median': 20, 'max': 20})

    def test_counted_is_closed_minus_stale(self):
        entries = [weekly(2 * H, 30, T0), weekly(30 * H, 40, T0 + 7 * D), weekly(H, 50, T0 + 14 * D),
                   weekly(H, 10, T0 + 30 * D)]  # the last window is still open
        r = su.analyze_windows(entries, T0 + 20 * D)['seven_day']
        self.assertEqual((r['windows'], r['closed'], r['stale_excluded'], r['counted']), (4, 3, 1, 2))

    def test_lead_exactly_at_the_staleness_bound_counts(self):
        for kind, hours in (('seven_day', 24), ('five_hour', 1)):
            with self.subTest(kind=kind):
                r = su.analyze_windows([entry(T0 - hours * H, kind, 40, T0)], T0 + H)[kind]
                self.assertEqual((r['counted'], r['stale_excluded']), (1, 0))
                r = su.analyze_windows([entry(T0 - hours * H - 1, kind, 40, T0)], T0 + H)[kind]
                self.assertEqual((r['counted'], r['stale_excluded']), (0, 1))


class Early(unittest.TestCase):
    def test_early_reset_detected(self):
        entries = [entry(T0, pct=60, resets=T0 + 3 * D), entry(T0 + H, pct=2, resets=T0 + 7 * D)]
        ev = su.early_resets(entries)
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]['previous_pct'], ev[0]['new_pct'], ev[0]['window']), (60, 2, 'seven_day'))
        self.assertEqual(ev[0]['at'], iso(T0 + H)[:10])

    def test_normal_rollover_not_early(self):
        entries = [entry(T0, pct=60, resets=T0 + 3 * D), entry(T0 + 4 * D, pct=2, resets=T0 + 10 * D)]
        self.assertEqual(su.early_resets(entries), [])

    def test_small_drop_not_early(self):
        for a, b in ((12, 5), (8, 0)):
            entries = [entry(T0, pct=a, resets=T0 + 3 * D), entry(T0 + H, pct=b, resets=T0 + 7 * D)]
            self.assertEqual(su.early_resets(entries), [], (a, b))

    def test_threshold_boundaries(self):
        for a, b, expected in ((10, 0, 1), (20, 10, 1), (9.9, 0, 0), (20, 10.1, 0)):
            with self.subTest(previous=a, new=b):
                entries = [entry(T0, pct=a, resets=T0 + 3 * D), entry(T0 + H, pct=b, resets=T0 + 7 * D)]
                self.assertEqual(len(su.early_resets(entries)), expected)

    def test_clock_skew_margin(self):
        for before, expected in ((60, 0), (61, 1)):
            with self.subTest(seconds_before_reset=before):
                prev_reset = T0 + 3 * D
                entries = [entry(T0, pct=60, resets=prev_reset),
                           entry(prev_reset - before, pct=2, resets=T0 + 7 * D)]
                self.assertEqual(len(su.early_resets(entries)), expected)

    def test_flip_flop_is_one_event(self):
        old, new = T0 + 3 * D, T0 + 7 * D
        entries = [entry(T0, pct=60, resets=old), entry(T0 + H, pct=2, resets=new),
                   entry(T0 + 2 * H, pct=60, resets=old), entry(T0 + 3 * H, pct=3, resets=new)]
        ev = su.early_resets(entries)
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]['new_pct'], ev[0]['at']), (2, iso(T0 + H)[:10]))

    def test_interleaved_duplicates_no_early_reset(self):
        base = [entry(T0 + i * H, pct=10 + i * 5, resets=T0 + 3 * D) for i in range(6)]
        base += [entry(T0 + 7 * H, pct=3, resets=T0 + 3 * D)]  # same window: no new resets_at
        noisy = base + base
        random.Random(1).shuffle(noisy)
        self.assertEqual(su.early_resets(noisy), su.early_resets(base))
        self.assertEqual(su.early_resets(noisy), [])
        self.assertEqual(su.analyze_windows(noisy, T0 + 9 * D), su.analyze_windows(base, T0 + 9 * D))

    def test_interleaved_sessions_with_event(self):
        base = [entry(T0, pct=60, resets=T0 + 3 * D), entry(T0 + H, pct=2, resets=T0 + 7 * D)]
        noisy = base + base[::-1]
        self.assertEqual(len(su.early_resets(noisy)), 1)


class Reading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'rate-limits.jsonl')

    def write(self, path, lines):
        with open(path, 'w') as f:
            for ln in lines:
                f.write((ln if isinstance(ln, str) else json.dumps(ln)) + '\n')

    def test_bad_window_values_skipped(self):
        good = entry(T0, 'seven_day', 10, T0 + D)
        ms = {'version': 1, 'at': iso(T0), 'windows': {
            'seven_day': {'used_percentage': 5, 'resets_at': 1738425600000},
            'five_hour': {'used_percentage': 5, 'resets_at': T0 + H}}}
        self.write(self.path, [good, ms, '{"version": 1, "at": "%s", "windows": {"seven_day": {"used_percentage": NaN, "resets_at": %d}}}' % (iso(T0), T0 + D), '{"version": 1, "at": "x"',
                               {'version': 1, 'at': iso(T0), 'windows': {'five_hour': {
                                   'used_percentage': True, 'resets_at': T0 + H}}}])
        entries, malformed = su.read_log(self.path)
        self.assertEqual(len(entries), 2)
        self.assertEqual(set(entries[1]['windows']), {'five_hour'})
        self.assertEqual(malformed, 4)

    def test_rotated_file_read_first(self):
        self.write(self.path + '.1', [entry(T0, pct=1, resets=T0 + D)])
        self.write(self.path, [entry(T0 + H, pct=2, resets=T0 + D)])
        entries, malformed = su.read_log(self.path)
        self.assertEqual([e['windows']['seven_day']['used_percentage'] for e in entries], [1, 2])
        self.assertEqual(malformed, 0)

    def test_missing_files_empty(self):
        self.assertEqual(su.read_log(self.path), ([], 0))

    def test_sorted_by_time_across_files(self):
        self.write(self.path + '.1', [entry(T0 + 2 * H, pct=3, resets=T0 + D)])
        self.write(self.path, [entry(T0, pct=1, resets=T0 + D)])
        entries, _ = su.read_log(self.path)
        self.assertEqual([e['windows']['seven_day']['used_percentage'] for e in entries], [1, 3])


# Example strings from errors.md ("Usage limits") and interactive-mode.md, fetched 2026-10-26.
DOCUMENTED = [
    ("You've hit your session limit · resets 3:45pm", 'session'),
    ("You've hit your weekly limit · resets Mon 12:00am", 'weekly'),
    ("You've hit your Opus limit · resets 3:45pm", 'opus'),
    ("You've hit your Sonnet limit · resets 3:45pm", 'sonnet'),
    ("You've used 85% of your session limit · resets 3:45pm", 'warning_85'),
    ('Usage limit reached · continuing automatically at 3:45pm · esc to cancel', 'auto_continue_wait'),
    ("You've hit your monthly spend limit · raise it at https://claude.ai/settings/usage", 'spend_limit'),
    ("You've hit your individual spend limit · ask your admin for a higher limit", 'spend_limit'),
    ("You've hit your org's monthly spend limit · visit https://claude.ai/admin-settings/usage", 'spend_limit'),
    ("You've hit your channel's monthly spend limit", 'spend_limit'),
    ("You've hit your team's shared budget · ask your admin to raise it", 'spend_limit'),
    ("You've hit your individual usage limit", 'spend_limit'),
    ('API Error: Usage credits required for 1M context · run /usage-credits to turn them on', 'credits_required_1m'),
    ('Fable limit reached · continuing on Fable 5.1 uses usage credits, and the prompt to confirm went '
     'unanswered — nothing was sent · answer it where this session is running, or /model to change',
     'fable_consent_unanswered'),
    ('Fable 5.1 now uses usage credits · the prompt to confirm went unanswered — nothing was sent',
     'fable_consent_unanswered'),
]


class Classifier(unittest.TestCase):
    def test_classify_documented_texts(self):
        for text, kind in DOCUMENTED:
            with self.subTest(text=text):
                self.assertEqual(su.classify_limit_text(text), kind)
                self.assertEqual(su.classify_limit_text('  \n' + text.replace("'", '’')), kind)
        self.assertEqual({k for _, k in DOCUMENTED}, set(su.LIMIT_KINDS))

    def test_unanchored_or_other_text_is_not_a_limit(self):
        for text in ("x You've hit your weekly limit", "Quoted: You've hit your Opus limit",
                     'API Error: 500 Internal server error', 'Fable 5.1 is experiencing high load', '', None, 5):
            with self.subTest(text=text):
                self.assertIsNone(su.classify_limit_text(text))

    def test_is_limit_record(self):
        self.assertTrue(su.is_limit_record({'type': 'assistant', 'message': {'model': '<synthetic>'}}))
        self.assertTrue(su.is_limit_record({'type': 'assistant', 'isApiErrorMessage': True, 'message': {}}))
        self.assertTrue(su.is_limit_record({'type': 'system'}))
        self.assertFalse(su.is_limit_record({'type': 'assistant', 'message': {'model': 'claude-opus-5-5'}}))
        self.assertFalse(su.is_limit_record({'type': 'assistant', 'isApiErrorMessage': 'yes', 'message': 5}))
        self.assertFalse(su.is_limit_record({'type': 'user', 'isApiErrorMessage': True}))

    def test_model_family(self):
        self.assertEqual([su.model_family(m) for m in ('claude-opus-5-5', 'Claude-Sonnet-5-5', 'claude-haiku-4-5',
                                                        'claude-fable-5-1', 'gpt-x', None, 7)],
                         ['opus', 'sonnet', 'haiku', 'fable', 'other', 'other', 'other'])


if __name__ == '__main__':
    unittest.main()
