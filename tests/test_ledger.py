"""Ledger format, strict validation, ids and verdict rules. Pure functions; fake paths only."""
import copy
import datetime
import json
import os
import stat
import tempfile
import unittest

from test_collect import SCRIPTS  # noqa: F401
import ledger

SCOPE = dict(scope="all", project=None, window_days=30)
KW = dict(type="keywords", source="corrections", any=["run the tests"])


def counts(matched, scanned, matches=None, start="2026-09-01T00:00:00Z", end="2026-09-28T00:00:00Z"):
    return {"from": start, "to": end, "matches": matched if matches is None else matches,
            "sessions_matched": matched, "sessions_scanned": scanned, "complete": True}


def entry(**changes):
    item = dict(id="L-20260901-1", applied_at="2026-09-01T00:00:00Z", run="2026-09-01-audit",
                finding_id="LRN-corrections:tests", pattern="Reports done without running tests",
                mechanism="rule", state="active", supersedes=None, selector=dict(KW),
                scope=dict(SCOPE), baseline=counts(6, 30, start="2026-08-02T00:00:00Z",
                                                   end="2026-09-01T00:00:00Z"),
                edits=[dict(file="~/.claude/CLAUDE.md", kind="markdown_block", sha256="a" * 64,
                            backup="~/.claude/backups/x/CLAUDE.md.bak")],
                observations=[])
    item.update(changes)
    return item


def current(matched, scanned, matches=None, end="2026-09-28T00:00:00Z", sel=KW):
    c = counts(matched, scanned, matches, start="2026-09-01T00:00:00Z", end=end)
    c["selector_sha"] = ledger.selector_hash(sel)
    return c


class Format(unittest.TestCase):
    def test_round_trip_and_private_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "audits", "ledger.json")
            book = dict(version=1, entries=[entry()])
            ledger.dump(book, path)
            self.assertEqual(ledger.load(path), book)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)

    def test_absent_file_is_empty_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            self.assertEqual(ledger.load(path), ledger.empty())
            target = os.path.join(tmp, "real.json")
            ledger.dump(ledger.empty(), target)
            os.symlink(target, path)
            with self.assertRaises(ledger.LedgerError):
                ledger.load(path)
            with self.assertRaises(ledger.LedgerError):
                ledger.dump(ledger.empty(), path)

    def test_strict_validation_rejects_bad_shapes_without_quoting_values(self):
        secretish = "sk-live-VALUE-SHOULD-NOT-APPEAR"
        bad = [
            dict(version=2, entries=[]),
            dict(version=1, entries=[], extra=1),
            dict(version=1, entries=[dict(entry(), extra=secretish)]),
            dict(version=1, entries=[entry(mechanism=secretish)]),
            dict(version=1, entries=[entry(state="retired")]),
            dict(version=1, entries=[entry(), entry()]),  # duplicate id
            dict(version=1, entries=[entry(selector=dict(KW, any=["x"] * 6))]),
            dict(version=1, entries=[entry(selector=dict(KW, any=["x" * 41]))]),
            dict(version=1, entries=[entry(selector=dict(type="regex", pattern=secretish))]),
            dict(version=1, entries=[entry(pattern="p" * 201)]),
            dict(version=1, entries=[entry(edits=[])]),
            dict(version=1, entries=[entry(baseline=dict(counts(5, 3)))]),  # matched > scanned
        ]
        for book in bad:
            with self.subTest(book=json.dumps(book)[:80]):
                with self.assertRaises(ledger.LedgerError) as caught:
                    ledger.loads(json.dumps(book))
                self.assertNotIn(secretish, str(caught.exception))
                self.assertEqual(caught.exception.input, "ledger")

    def test_duplicate_json_keys_fail_with_line(self):
        with self.assertRaises(ledger.LedgerError) as caught:
            ledger.loads('{"version": 1,\n "version": 1, "entries": []}')
        self.assertEqual(caught.exception.input, "ledger")

    def test_next_id_counts_per_day(self):
        book = dict(version=1, entries=[entry(id="L-20260928-1"), entry(id="L-20260928-7"),
                                        entry(id="L-20260927-9")])
        self.assertEqual(ledger.next_id(book, datetime.date(2026, 9, 28)), "L-20260928-8")
        self.assertEqual(ledger.next_id(ledger.empty(), datetime.date(2026, 9, 28)), "L-20260928-1")


class Verdicts(unittest.TestCase):
    def check(self, cur, expected, previous=None, **changes):
        self.assertEqual(ledger.verdict(entry(**changes), cur, dict(SCOPE), previous), expected)

    def test_incomparable_and_incomplete(self):
        self.check(None, ("unknown", "incomparable"))
        other = current(1, 20, sel=dict(KW, any=["other"]))
        self.check(other, ("unknown", "incomparable"))
        self.assertEqual(ledger.verdict(entry(), current(1, 20), dict(SCOPE, window_days=7), None),
                         ("unknown", "incomparable"))
        partial = dict(current(1, 20), complete=False)
        self.check(partial, ("unknown", "incomplete"))

    def test_no_and_weak_baseline_and_few_sessions(self):
        self.check(current(1, 20), ("unknown", "no_baseline"), baseline=counts(0, 0))
        self.check(current(1, 20), ("too_early", "weak_baseline"), baseline=counts(2, 30))
        self.check(current(0, 4), ("too_early", "few_sessions"))

    def test_dropped_boundary_and_not_dropped(self):
        # baseline rate 6/30 = 0.2; half = 0.1
        self.check(current(2, 20), ("dropped", "rate_at_or_below_half"))
        self.check(current(3, 20), ("not_dropped", "rate_above_half"))

    def test_quiet_needs_two_zero_observations_and_thirty_days(self):
        prev = dict(counts(0, 10), run="r1", verdict="dropped", reason="rate_at_or_below_half")
        self.check(current(0, 10, end="2026-10-01T00:00:00Z"), ("quiet", "quiet"), previous=prev)
        # 29 days after the fix: not yet quiet, zero rate still counts as dropped
        self.check(current(0, 10, end="2026-09-30T00:00:00Z"), ("dropped", "rate_at_or_below_half"),
                   previous=prev)
        # previous observation was not comparable
        unknown_prev = dict(prev, verdict="unknown", reason="incomplete")
        self.check(current(0, 10, end="2026-10-01T00:00:00Z"), ("dropped", "rate_at_or_below_half"),
                   previous=unknown_prev)

    def test_metric_verdicts(self):
        sel = dict(type="metric", name="corrections_count_30d", basis="measured", unit="prompts",
                   source="corrections.count")
        base = {"from": "2026-08-02T00:00:00Z", "to": "2026-09-01T00:00:00Z", "value": 10, "complete": True}
        e = entry(selector=sel, baseline=base)
        late = {"from": "2026-09-02T00:00:00Z", "to": "2026-10-02T00:00:00Z", "value": 5,
                "complete": True, "selector_sha": ledger.selector_hash(sel)}
        self.assertEqual(ledger.verdict(e, late, dict(SCOPE), None), ("dropped", "rate_at_or_below_half"))
        self.assertEqual(ledger.verdict(e, dict(late, value=6), dict(SCOPE), None),
                         ("not_dropped", "rate_above_half"))
        overlap = dict(late, **{"from": "2026-08-31T00:00:00Z"})
        self.assertEqual(ledger.verdict(e, overlap, dict(SCOPE), None), ("too_early", "window_overlaps_fix"))


class Proposals(unittest.TestCase):
    def test_escalate_after_two_not_dropped(self):
        prev = dict(counts(5, 20), run="r1", verdict="not_dropped", reason="rate_above_half")
        self.assertEqual(ledger.proposal(entry(), "not_dropped", prev), "escalate")
        self.assertIsNone(ledger.proposal(entry(), "not_dropped", None))
        self.assertEqual(ledger.next_rung(entry()), "hook")
        self.assertIsNone(ledger.proposal(entry(mechanism="skill"), "not_dropped", prev))
        self.assertIsNone(ledger.proposal(entry(mechanism="setting"), "not_dropped", prev))

    def test_retire_only_quiet_memory_or_rule(self):
        self.assertEqual(ledger.proposal(entry(mechanism="memory"), "quiet", None), "retire")
        self.assertEqual(ledger.proposal(entry(), "quiet", None), "retire")
        self.assertIsNone(ledger.proposal(entry(mechanism="hook"), "quiet", None))


if __name__ == "__main__":
    unittest.main()
