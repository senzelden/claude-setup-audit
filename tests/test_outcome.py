"""Measured outcome after apply: report-only ledger entries for SEC/COST fixes whose metric is
computed from the snapshot by outcome_metrics.py. Fake homes and fake snapshots only."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest import mock

from test_collect import SCRIPTS
import ledger
import outcome_metrics
import render_report
import report_state

APPLIED = "2026-09-01T12:00:00Z"
RISKY = dict(type="metric", name="risky_allow_rule_count", **{
    k: outcome_metrics.CATALOG["risky_allow_rule_count"][k] for k in ("basis", "unit", "source")})
CONTEXT = dict(type="metric", name="context_baseline_tokens_median", **{
    k: outcome_metrics.CATALOG["context_baseline_tokens_median"][k] for k in ("basis", "unit", "source")})
CACHE = dict(type="metric", name="cache_write_share", **{
    k: outcome_metrics.CATALOG["cache_write_share"][k] for k in ("basis", "unit", "source")})
ALLOW = dict(type="metric", name="allow_rule_count", **{
    k: outcome_metrics.CATALOG["allow_rule_count"][k] for k in ("basis", "unit", "source")})
SCOPE = dict(scope="all", project=None, window_days=30)


def snapshot(at="2026-09-01T10:00:00Z", risky=None, allow=12, median=20000, read=900, write=100,
             transcripts="collected", window_days=30, mode="full"):
    """A fake collector snapshot carrying only the fields the outcome metrics read."""
    risky = {"sudo": ["Bash(sudo *)"], "docker": ["Bash(docker *)", "Bash(sudo *)"]} if risky is None else risky
    return {
        "generated": "2026-09-01 12:00", "generated_utc": at, "window_days": window_days,
        "collection_scope": dict(requested="all", project=None, projects_collected=1),
        "global": {"settings": [{"path": "~/.claude/settings.json",
                                 "permissions": {"allow_count": allow, "risky": risky}}]},
        "projects": {"~/repo": {"settings": [{"path": "~/repo/.claude/settings.local.json",
                                             "permissions": {"allow_count": 3, "risky": {}}}]}},
        "transcripts": {"sessions_measured": 9,
                        "context_baseline_tokens": {"median": median, "p90": None, "max": None},
                        "cache": {"read_tokens": read, "write_tokens": write}},
        "coverage": {"sources": [{"source": "transcripts.main_files", "status": transcripts, "omitted": 0},
                                 {"source": "usage.stats", "status": "partial"}],
                     "privacy": {"mode": mode}},
    }


def report(finding="SEC-risky-allow:global", check="SEC-risky-allow", status="applied", generated=None,
           backups=("~/.claude/backups/setup-audit-20260901/settings.json",)):
    return dict(version=1, generated=generated or "2026-09-01T11:00:00Z", window_days=30, metrics={},
                findings=[dict(id=finding, check=check)],
                applied=[dict(id=finding, status=status, backups=list(backups))] if status else [])


def path_hashes(*paths):
    import hashlib
    return sorted(hashlib.sha256(p.encode("utf-8")).hexdigest() for p in paths)


# The settings files snapshot() counts, as a point metric's baseline records them.
BASIS = path_hashes("~/.claude/settings.json", "~/repo/.claude/settings.local.json")


def outcome_entry(selector=RISKY, baseline=None, **changes):
    item = dict(id="L-20260901-1", applied_at=APPLIED, run="2026-09-01-audit",
                finding_id="SEC-risky-allow:global", pattern="Broad allow rules removed",
                mechanism="setting", state="active", supersedes=None, selector=dict(selector),
                scope=dict(SCOPE),
                baseline=baseline or {"from": "2026-09-01T10:00:00Z", "to": "2026-09-01T10:00:00Z",
                                      "value": 2, "complete": True, "settings_basis": list(BASIS)},
                edits=[], observations=[], outcome_only=True)
    item.update(changes)
    return item


def lrn_entry(**changes):
    item = dict(id="L-20260901-2", applied_at="2026-09-01T00:00:00Z", run="2026-09-01-audit",
                finding_id="LRN-corrections:tests", pattern="Reports done without running tests",
                mechanism="rule", state="active", supersedes=None,
                selector=dict(type="keywords", source="corrections", any=["run the tests"]),
                scope=dict(SCOPE),
                baseline={"from": "2026-08-02T00:00:00Z", "to": "2026-09-01T00:00:00Z", "matches": 6,
                          "sessions_matched": 6, "sessions_scanned": 30, "complete": True},
                edits=[dict(file="~/.claude/CLAUDE.md", kind="markdown_block", sha256="a" * 64,
                            backup="~/.claude/backups/x/CLAUDE.md.bak")],
                observations=[])
    item.update(changes)
    return item


class Metrics(unittest.TestCase):
    """Values come from snapshot fields only, by a fixed rule per catalog metric."""

    def test_point_in_time_metrics_use_collection_time_as_window(self):
        snap = snapshot()
        risky = outcome_metrics.compute(RISKY, snap)
        # three flagged entries, two distinct (file, rule) pairs
        self.assertEqual(risky, {"from": "2026-09-01T10:00:00Z", "to": "2026-09-01T10:00:00Z",
                                 "value": 2, "complete": True, "settings_basis": BASIS})
        self.assertEqual(outcome_metrics.compute(ALLOW, snap)["value"], 15)

    def test_windowed_metrics_span_the_snapshot_window(self):
        snap = snapshot()
        ctx = outcome_metrics.compute(CONTEXT, snap)
        self.assertEqual(ctx, {"from": "2026-08-02T10:00:00Z", "to": "2026-09-01T10:00:00Z",
                               "value": 20000, "complete": True})
        self.assertEqual(outcome_metrics.compute(CACHE, snap)["value"], 0.1)
        self.assertIsNone(outcome_metrics.compute(CACHE, snapshot(read=0, write=0))["value"])

    def test_completeness_follows_coverage_and_caps(self):
        self.assertFalse(outcome_metrics.compute(CONTEXT, snapshot(transcripts="partial"))["complete"])
        capped = {"sudo": ["Bash(sudo %d)" % i for i in range(outcome_metrics.RISKY_CAP)]}
        self.assertFalse(outcome_metrics.compute(RISKY, snapshot(risky=capped))["complete"])
        self.assertFalse(outcome_metrics.compute(RISKY, snapshot(mode="metadata-only"))["complete"])

    def test_missing_settings_data_is_incomplete_not_zero(self):
        no_list = snapshot()
        del no_list["global"]["settings"]
        bad_list = dict(snapshot(), **{"global": {"settings": "x"}})
        no_perms = snapshot()
        no_perms["global"]["settings"].append({"path": "~/.claude/settings.local.json"})
        no_risky = snapshot()
        no_risky["global"]["settings"][0]["permissions"] = {"allow_count": 12}
        unread = snapshot()
        unread["coverage"]["sources"].append({"source": "/home/u/.claude/settings.json", "scope": "user",
                                              "status": "unavailable", "reason": "invalid_settings"})
        unread_project = snapshot()
        unread_project["coverage"]["sources"].append({"source": "/home/u/repo/.claude/settings.local.json",
                                                      "scope": "session_settings_candidate",
                                                      "status": "unavailable", "reason": "read_failed"})
        cases = {"no settings list": (no_list, (RISKY, ALLOW)), "settings not a list": (bad_list, (RISKY, ALLOW)),
                 "item without permissions": (no_perms, (RISKY, ALLOW)), "permissions without risky": (no_risky, (RISKY,)),
                 "user settings unread": (unread, (RISKY, ALLOW)),
                 "project settings unread": (unread_project, (RISKY, ALLOW))}
        for name, (snap, selectors) in cases.items():
            for sel in selectors:
                with self.subTest(name, metric=sel["name"]):
                    self.assertFalse(outcome_metrics.compute(sel, snap)["complete"])
        # a symlinked settings file the inventory did not follow was still read by the collector
        linked = snapshot()
        linked["coverage"]["sources"].append({"source": "/home/u/.claude/settings.json", "scope": "user",
                                              "status": "not_checked", "reason": "symlink_not_followed"})
        self.assertTrue(outcome_metrics.compute(RISKY, linked)["complete"])

    def test_unread_settings_make_a_drop_unknown(self):
        unread = snapshot(at="2026-10-05T00:00:00Z", risky={})
        unread["coverage"]["sources"].append({"source": "/home/u/.claude/settings.json", "scope": "user",
                                              "status": "unavailable", "reason": "invalid_settings"})
        rows, _ = ledger.evaluate(dict(version=1, entries=[outcome_entry()]), unread,
                                  report(generated="2026-10-05T00:00:00Z"), "r")
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("unknown", "incomplete"))

    def test_unknown_selector_or_missing_collection_time_is_none(self):
        self.assertIsNone(outcome_metrics.compute(dict(RISKY, unit="files"), snapshot()))
        self.assertIsNone(outcome_metrics.compute(dict(RISKY, name="tokens"), snapshot()))
        no_time = snapshot()
        del no_time["generated_utc"]
        self.assertIsNone(outcome_metrics.compute(RISKY, no_time))
        for bad in ([], None, "x", {}, dict(snapshot(), generated_utc="junk"), dict(snapshot(), window_days=0)):
            self.assertIsNone(outcome_metrics.compute(RISKY, bad))


class FakeHomeCase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        home = tmp.name
        os.makedirs(os.path.join(home, ".claude"))
        import collect
        for patcher in (mock.patch.dict(os.environ, {"HOME": home}), mock.patch.object(collect, "HOME", home),
                        mock.patch.object(collect, "CLAUDE", os.path.join(home, ".claude"))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.now = ledger.epoch(APPLIED)

    def spec(self, **changes):
        s = dict(id="L-20260901-1", finding_id="SEC-risky-allow:global", pattern="Broad allow rules removed",
                 mechanism="setting", selector=dict(RISKY), edits=[], outcome_only=True)
        s.update(changes)
        return s


class Record(FakeHomeCase):
    def test_record_outcome_entry_takes_baseline_from_snapshot(self):
        book = ledger.record(ledger.empty(), self.spec(), snapshot(), report(), "2026-09-01-audit", self.now)
        item = book["entries"][0]
        self.assertTrue(item["outcome_only"])
        self.assertEqual((item["mechanism"], item["edits"], item["applied_at"]), ("setting", [], APPLIED))
        self.assertEqual(item["baseline"], {"from": "2026-09-01T10:00:00Z", "to": "2026-09-01T10:00:00Z",
                                            "value": 2, "complete": True, "settings_basis": BASIS})
        self.assertNotIn("~/repo", json.dumps(item))   # the basis holds path hashes, not paths
        # the model-written report metric with the same name is never the source of the value
        rep = report()
        rep["metrics"] = {"risky_allow_rule_count": dict(value=99, **{k: RISKY[k] for k in ("basis", "unit", "source")})}
        again = ledger.record(ledger.empty(), self.spec(), snapshot(), rep, "r", self.now)
        self.assertEqual(again["entries"][0]["baseline"]["value"], 2)

    def test_record_refuses_ineligible_outcome_entries(self):
        no_time = snapshot()
        del no_time["generated_utc"]
        cases = {
            "lrn finding": (self.spec(finding_id="LRN-corrections:tests"),
                            snapshot(), report("LRN-corrections:tests", "LRN-corrections")),
            "hyg finding": (self.spec(finding_id="HYG-one-off-rules:global"),
                            snapshot(), report("HYG-one-off-rules:global", "HYG-one-off-rules")),
            "check has no metric": (self.spec(finding_id="SEC-sandbox:global"), snapshot(),
                                    report("SEC-sandbox:global", "SEC-sandbox")),
            "metric not for check": (self.spec(selector=dict(CONTEXT)), snapshot(), report()),
            "not catalog": (self.spec(selector=dict(RISKY, name="risky_rules")), snapshot(), report()),
            "wrong labels": (self.spec(selector=dict(RISKY, unit="files")), snapshot(), report()),
            "not applied": (self.spec(), snapshot(), report(status="partial")),
            "no applied item": (self.spec(), snapshot(), report(status=None)),
            "applied without backup": (self.spec(), snapshot(), report(backups=())),
            "unmapped cost check": (self.spec(finding_id="COST-model-default:global", selector=dict(CONTEXT)),
                                    snapshot(), report("COST-model-default:global", "COST-model-default")),
            "cost check, wrong metric": (self.spec(finding_id="COST-cache-health:global", selector=dict(CONTEXT)),
                                         snapshot(), report("COST-cache-health:global", "COST-cache-health")),
            "has edits": (self.spec(edits=[dict(file="~/x", kind="markdown_block", backup=None)]),
                          snapshot(), report()),
            "other mechanism": (self.spec(mechanism="rule"), snapshot(), report()),
            "supersedes": (self.spec(supersedes="L-20260801-1"), snapshot(), report()),
            "outcome_only false": (self.spec(outcome_only=False), snapshot(), report()),
            "no baseline value": (self.spec(), snapshot(risky={}), report()),
            "no collection time": (self.spec(), no_time, report()),
            "collected after apply": (self.spec(), snapshot(at="2026-09-01T13:00:00Z"), report()),
        }
        for name, (spec, snap, rep) in cases.items():
            with self.subTest(name):
                with self.assertRaises(ledger.LedgerError):
                    ledger.record(ledger.empty(), spec, snap, rep, "r", self.now)

    def test_lrn_entries_cannot_supersede_outcome_entries(self):
        book = dict(version=1, entries=[outcome_entry()])
        spec = dict(id="L-20260901-2", finding_id="LRN-corrections:tests", pattern="p", mechanism="rule",
                    selector=dict(type="metric", name="m", basis="measured", unit="u", source="corrections.count"),
                    edits=[dict(file="~/x.md", kind="markdown_block", backup=None)], supersedes="L-20260901-1")
        with self.assertRaises(ledger.LedgerError):
            ledger.record(book, spec, snapshot(), report("LRN-corrections:tests", "LRN-corrections"), "r",
                          self.now)


class CostEndToEnd(FakeHomeCase):
    """COST-claude-md-size measured by the context baseline: record, two snapshots, render."""

    def test_record_verdicts_and_render(self):
        finding = "COST-claude-md-size:~/repo"
        rep = report(finding, "COST-claude-md-size",
                     backups=("~/.claude/backups/setup-audit-20260901/repo/CLAUDE.md",))
        spec = self.spec(finding_id=finding, pattern="CLAUDE.md split into nested files",
                         selector=dict(CONTEXT))
        book = ledger.record(ledger.empty(), spec, snapshot(median=24000), rep, "2026-09-01-audit", self.now)
        item = book["entries"][0]
        self.assertEqual(item["baseline"], {"from": "2026-08-02T10:00:00Z", "to": "2026-09-01T10:00:00Z",
                                            "value": 24000, "complete": True})
        later = report(finding, "COST-claude-md-size", generated="2026-10-05T00:00:00Z")
        rows, book = ledger.evaluate(book, snapshot(at="2026-09-15T00:00:00Z", median=11000), later, "mid")
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("too_early", "window_overlaps_fix"))
        rows, book = ledger.evaluate(book, snapshot(at="2026-10-05T00:00:00Z", median=11000), later,
                                     "2026-10-05-audit")
        self.assertEqual((rows[0]["verdict"], rows[0]["proposal"], rows[0]["outcome_only"]),
                         ("dropped", None, True))
        rows2, _ = ledger.evaluate(book, snapshot(at="2026-10-05T00:00:00Z", median=13000), later, "again")
        self.assertEqual(rows2[0]["verdict"], "not_dropped")
        html = render_report.render(dict(later, trend=dict(comparable=False, reason="x", metrics={},
                                                           findings={}, ledger=rows)))
        section = html.split('id="outcomes"', 1)[1].split("</section>", 1)[0]
        for text in (finding, "Applied 2026-09-01", "Context baseline tokens median",
                     "24,000 tokens, 2026-08-02 to 2026-09-01", "11,000 tokens, 2026-09-05 to 2026-10-05",
                     "dropped to half or less", "not proof that the fix caused the change"):
            self.assertIn(text, section)

    def test_every_mapped_check_names_catalog_metrics_of_its_family(self):
        for check, names in outcome_metrics.CHECKS.items():
            self.assertTrue(check.startswith(outcome_metrics.FAMILIES), check)
            self.assertTrue(names and all(n in outcome_metrics.CATALOG for n in names), check)
        self.assertEqual(outcome_metrics.CHECKS["COST-cache-health"], ("cache_write_share",))


class Verdicts(unittest.TestCase):
    """Two fake snapshots: the baseline one (inside the entry) and the next audit's."""

    def evaluate(self, entry, snap, run="2026-10-05-audit"):
        return ledger.evaluate(dict(version=1, entries=[entry]), snap, report(generated="2026-10-05T00:00:00Z"), run)

    def test_point_in_time_dropped_and_not_dropped(self):
        rows, book = self.evaluate(outcome_entry(), snapshot(at="2026-10-05T00:00:00Z", risky={}))
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("dropped", "rate_at_or_below_half"))
        self.assertEqual(rows[0]["current"], {"value": 0, "from": "2026-10-05T00:00:00Z",
                                              "to": "2026-10-05T00:00:00Z"})
        self.assertEqual(len(book["entries"][0]["observations"]), 1)
        rows, _ = self.evaluate(outcome_entry(), snapshot(at="2026-10-05T00:00:00Z",
                                                          risky={"sudo": ["Bash(sudo *)", "Bash(sudo x)"]}))
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("not_dropped", "rate_above_half"))

    def test_point_in_time_snapshot_collected_before_apply_is_too_early(self):
        rows, _ = self.evaluate(outcome_entry(), snapshot(at="2026-09-01T11:59:00Z", risky={}))
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("too_early", "collected_before_fix"))

    def test_windowed_metric_needs_a_window_after_the_fix(self):
        base = {"from": "2026-08-02T10:00:00Z", "to": "2026-09-01T10:00:00Z", "value": 20000, "complete": True}
        e = outcome_entry(CONTEXT, base, finding_id="COST-baseline:global")
        rows, _ = self.evaluate(e, snapshot(at="2026-09-20T00:00:00Z", median=5000))
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("too_early", "window_overlaps_fix"))
        rows, _ = self.evaluate(e, snapshot(at="2026-10-05T00:00:00Z", median=9000))
        self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("dropped", "rate_at_or_below_half"))
        rows, _ = self.evaluate(e, snapshot(at="2026-10-05T00:00:00Z", median=15000))
        self.assertEqual(rows[0]["verdict"], "not_dropped")

    def test_incomparable_metric_is_unknown_without_observation(self):
        later = snapshot(at="2026-10-05T00:00:00Z", risky={})
        no_time = copy.deepcopy(later)
        del no_time["generated_utc"]
        no_value = snapshot(at="2026-10-05T00:00:00Z", median=None)
        base = {"from": "2026-08-02T10:00:00Z", "to": "2026-09-01T10:00:00Z", "value": 20000, "complete": True}
        for name, entry, snap, reason in (
                ("no collection time", outcome_entry(), no_time, "incomparable"),
                ("other window", outcome_entry(), dict(later, window_days=7), "incomparable"),
                ("value missing", outcome_entry(CONTEXT, base, finding_id="COST-baseline:global"), no_value,
                 "incomparable"),
                ("incomplete", outcome_entry(), snapshot(at="2026-10-05T00:00:00Z", mode="metadata-only"),
                 "incomplete")):
            with self.subTest(name):
                rows, book = self.evaluate(entry, snap)
                self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("unknown", reason))
                self.assertEqual(book["entries"][0]["observations"], [])

    def test_rows_carry_finding_dates_and_both_windows(self):
        rows, _ = self.evaluate(outcome_entry(), snapshot(at="2026-10-05T00:00:00Z", risky={}))
        row = rows[0]
        self.assertEqual((row["finding_id"], row["applied_at"], row["outcome_only"]),
                         ("SEC-risky-allow:global", APPLIED, True))
        self.assertEqual(row["metric"], {k: RISKY[k] for k in ("name", "basis", "unit", "source")})
        self.assertEqual(row["baseline"], {"value": 2, "from": "2026-09-01T10:00:00Z",
                                           "to": "2026-09-01T10:00:00Z"})
        report_state.validate_report(dict(report(), trend=dict(comparable=False, reason="x", metrics={},
                                                                findings={}, ledger=rows)), strict=False)


class SettingsBasis(unittest.TestCase):
    """Point metrics compare only when the current snapshot still counts every baseline file."""

    def evaluate(self, entry, snap):
        return ledger.evaluate(dict(version=1, entries=[entry]), snap, report(generated="2026-10-05T00:00:00Z"),
                               "2026-10-05-audit")

    def later(self, **kw):
        return snapshot(at="2026-10-05T00:00:00Z", risky={}, allow=1, **kw)

    def assert_unknown(self, entry, snap, reason):
        for sel in (RISKY, ALLOW):
            e = dict(entry, selector=dict(sel))
            rows, book = self.evaluate(e, snap)
            self.assertEqual((rows[0]["verdict"], rows[0]["reason"]), ("unknown", reason), sel["name"])
            self.assertEqual(book["entries"][0]["observations"], [])

    def test_window_metrics_carry_no_basis(self):
        self.assertNotIn("settings_basis", outcome_metrics.compute(CONTEXT, snapshot()))

    def test_comparable_when_every_baseline_file_is_still_counted(self):
        rows, book = self.evaluate(outcome_entry(), self.later())
        self.assertEqual(rows[0]["verdict"], "dropped")
        self.assertNotIn("settings_basis", book["entries"][0]["observations"][0])
        more = self.later()
        more["projects"]["~/other"] = {"settings": [{"path": "~/other/.claude/settings.json",
                                                     "permissions": {"allow_count": 0, "risky": {}}}]}
        self.assertEqual(self.evaluate(outcome_entry(), more)[0][0]["verdict"], "dropped")  # superset is fine

    def test_project_dropping_out_of_the_snapshot_is_unknown(self):
        gone = self.later()
        gone["projects"] = {}
        self.assert_unknown(outcome_entry(), gone, "settings_files_changed")

    def test_unreadable_project_file_without_coverage_row_is_unknown(self):
        # collect.load_json drops an unreadable settings.local.json found through --roots; no coverage
        # row names it, so only the missing path shows the file was not counted
        unread = self.later()
        unread["projects"]["~/repo"]["settings"] = []
        self.assert_unknown(outcome_entry(), unread, "settings_files_changed")

    def test_entries_recorded_without_a_basis_are_unknown(self):
        legacy = {"from": "2026-09-01T10:00:00Z", "to": "2026-09-01T10:00:00Z", "value": 2, "complete": True}
        self.assert_unknown(outcome_entry(baseline=legacy), self.later(), "no_settings_basis")
        ledger.validate(dict(version=1, entries=[outcome_entry(baseline=legacy)]))   # still loads

    def test_hashed_path_snapshot_degrades_to_unknown(self):
        hashed = self.later()
        hashed["global"]["settings"][0]["path"] = "h:0123456789ab"
        hashed["projects"] = {"h:ba9876543210": {"settings": [{"path": "h:ba9876543210",
                                                              "permissions": {"allow_count": 0, "risky": {}}}]}}
        self.assert_unknown(outcome_entry(), hashed, "settings_files_changed")
        broken = self.later()
        broken["global"]["settings"][0]["path"] = 7   # malformed: incomplete, never a crash
        rows, _ = self.evaluate(outcome_entry(), broken)
        self.assertEqual(rows[0]["verdict"], "unknown")

    def test_malformed_basis_is_refused_on_load(self):
        for bad in ("x", ["zz"], [BASIS[1], BASIS[0]], [BASIS[0], BASIS[0]]):
            with self.subTest(bad=bad):
                base = dict(outcome_entry()["baseline"], settings_basis=bad)
                with self.assertRaises(ledger.LedgerError):
                    ledger.validate(dict(version=1, entries=[outcome_entry(baseline=base)]))


class ReportOnly(unittest.TestCase):
    """Outcome entries are never escalated, retired or removed, and nothing offers either."""

    def test_proposal_is_never_made_for_outcome_entries(self):
        prev = dict(value=2, run="r1", verdict="not_dropped", reason="rate_above_half")
        quiet_prev = dict(prev, verdict="quiet")
        # mechanism forced onto a ladder rung to prove the outcome marker itself blocks proposals
        for mechanism in ("memory", "rule", "hook", "setting"):
            e = outcome_entry(mechanism=mechanism)
            self.assertIsNone(ledger.proposal(e, "not_dropped", prev), mechanism)
            self.assertIsNone(ledger.proposal(e, "quiet", quiet_prev), mechanism)

    def test_two_not_dropped_runs_never_escalate(self):
        book = dict(version=1, entries=[outcome_entry()])
        still = snapshot(at="2026-10-05T00:00:00Z", risky={"sudo": ["Bash(sudo *)", "Bash(sudo y)"]})
        rep = report(generated="2026-10-05T00:00:00Z")
        _, book = ledger.evaluate(book, still, rep, "run-a")
        rows, _ = ledger.evaluate(book, still, rep, "run-b")
        self.assertEqual(rows[0]["verdict"], "not_dropped")
        self.assertIsNone(rows[0]["proposal"])
        self.assertIsNone(rows[0]["next_mechanism"])

    def test_removal_refuses_outcome_entries_and_all_skips_them(self):
        book = dict(version=1, entries=[outcome_entry(), lrn_entry()])
        with self.assertRaises(ledger.LedgerError):
            ledger.plan_removal(book, ["L-20260901-1"])
        self.assertEqual(ledger.removable_ids(book), ["L-20260901-2"])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            ledger.dump(book, path)
            out = subprocess.run([sys.executable, "-B", os.path.join(SCRIPTS, "ledger.py"), "remove",
                                  "--ledger", path, "--entry", "L-20260901-1"],
                                 capture_output=True, text=True, timeout=60,
                                 env={**os.environ, "HOME": tmp})
            self.assertEqual(out.returncode, 1)
            self.assertIn("report-only", out.stderr)

    def test_validation_rejects_outcome_entries_that_could_act(self):
        bad = [outcome_entry(mechanism="rule"), outcome_entry(edits=lrn_entry()["edits"]),
               outcome_entry(outcome_only=False), outcome_entry(outcome_only=1),
               outcome_entry(selector=dict(RISKY, name="custom")), outcome_entry(supersedes="L-20260801-1"),
               outcome_entry(finding_id="LRN-corrections:tests")]
        for item in bad:
            with self.subTest(item=json.dumps(item)[:60]):
                with self.assertRaises(ledger.LedgerError):
                    ledger.validate(dict(version=1, entries=[item]))
        # an LRN entry may not supersede an outcome entry
        with self.assertRaises(ledger.LedgerError):
            ledger.validate(dict(version=1, entries=[outcome_entry(state="superseded"),
                                                     lrn_entry(supersedes="L-20260901-1")]))

    def test_report_rejects_actionable_outcome_rows(self):
        rows, _ = ledger.evaluate(dict(version=1, entries=[outcome_entry()]),
                                  snapshot(at="2026-10-05T00:00:00Z", risky={}), report(), "r")
        base = dict(report(), trend=dict(comparable=False, reason="x", metrics={}, findings={}))
        for change in (dict(proposal="retire"), dict(proposal="escalate", next_mechanism="hook"),
                       dict(metric=dict(rows[0]["metric"], name="custom")),
                       dict(metric=dict(rows[0]["metric"], unit="files")),
                       dict(outcome_only="yes"), dict(baseline=dict(rows[0]["baseline"], value="2")),
                       dict(current=dict(rows[0]["current"], to="junk"))):
            with self.subTest(change=change):
                with self.assertRaises(report_state.ReportError):
                    report_state.validate_report(dict(base, trend=dict(base["trend"], ledger=[dict(rows[0], **change)])))


class LegacyLedger(unittest.TestCase):
    """A ledger written by 0.14.x has no outcome fields and must still load, evaluate and save."""

    LEGACY = {"version": 1, "entries": [{
        "id": "L-20260915-1", "applied_at": "2026-09-15T08:00:00Z", "run": "2026-09-15-audit",
        "finding_id": "LRN-corrections:tests", "pattern": "Reports done without running tests",
        "mechanism": "rule", "state": "active", "supersedes": None,
        "selector": {"type": "metric", "name": "corrections_count_30d", "basis": "measured",
                     "unit": "prompts", "source": "corrections.count"},
        "scope": {"scope": "all", "project": None, "window_days": 30},
        "baseline": {"from": "2026-08-16T08:00:00Z", "to": "2026-09-15T08:00:00Z", "value": 10, "complete": True},
        "edits": [{"file": "~/.claude/CLAUDE.md", "kind": "markdown_block", "sha256": "b" * 64, "backup": None}],
        "observations": [{"from": "2026-09-16T00:00:00Z", "to": "2026-10-16T00:00:00Z", "value": 7,
                          "complete": True, "run": "2026-10-16-audit", "verdict": "not_dropped",
                          "reason": "rate_above_half"}]}]}

    def test_legacy_ledger_loads_evaluates_and_round_trips_unchanged(self):
        text = json.dumps(self.LEGACY, indent=2)
        book = ledger.loads(text)
        self.assertNotIn("outcome_only", book["entries"][0])
        self.assertEqual(ledger.removable_ids(book), ["L-20260915-1"])
        rep = dict(report("LRN-corrections:tests", "LRN-corrections", generated="2026-11-20T00:00:00Z"),
                   coverage={"sources": [{"source": "corrections", "status": "collected"}]},
                   metrics={"corrections_count_30d": {"value": 4, "basis": "measured", "unit": "prompts",
                                                      "source": "corrections.count"}})
        rows, new = ledger.evaluate(book, snapshot(at="2026-11-20T00:00:00Z"), rep, "2026-11-20-audit")
        self.assertEqual(rows[0]["verdict"], "dropped")  # legacy metric selectors still read the report
        self.assertFalse(rows[0]["outcome_only"])
        self.assertNotIn("outcome_only", new["entries"][0])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ledger.json")
            ledger.dump(book, path)
            self.assertEqual(ledger.load(path), self.LEGACY)


class Rendering(unittest.TestCase):
    def finalized(self):
        rows, _ = ledger.evaluate(dict(version=1, entries=[outcome_entry(), lrn_entry()]),
                                  snapshot(at="2026-10-05T00:00:00Z", risky={}),
                                  report(generated="2026-10-05T00:00:00Z"), "r")
        return dict(report(generated="2026-10-05T00:00:00Z"),
                    trend=dict(comparable=False, reason="No previous report supplied.", metrics={},
                               findings={}, ledger=rows))

    def test_outcome_section_lists_dates_values_windows_verdict_and_caveat(self):
        html = render_report.render(self.finalized())
        section = html.split('id="outcomes"', 1)[1].split("</section>", 1)[0]
        for text in ("Outcome of applied fixes", "SEC-risky-allow:global", "2026-09-01",
                     "Risky allow rule count", "2 rules", "at 2026-09-01 10:00 UTC",
                     "0 rules", "at 2026-10-05 00:00 UTC", "dropped",
                     "A verdict is a comparison of counts, not proof that the fix caused the change."):
            self.assertIn(text, section)
        self.assertNotIn("propose", section.lower())
        # the learning-fix lines keep LRN rows only
        trend = html.split('id="trend"', 1)[1].split("</section>", 1)[0]
        self.assertNotIn("Learning fix L-20260901-1", trend)
        self.assertIn("Learning fix L-20260901-2", trend)

    def test_windowed_rows_show_date_ranges_and_missing_current(self):
        rep = self.finalized()
        row = dict(rep["trend"]["ledger"][0], metric={k: CONTEXT[k] for k in ("name", "basis", "unit", "source")},
                   baseline={"value": 20000, "from": "2026-08-02T10:00:00Z", "to": "2026-09-01T10:00:00Z"},
                   current=None, verdict="unknown", reason="incomparable", finding_id="COST-baseline:global")
        rep["trend"]["ledger"] = [row]
        section = render_report.render(rep).split('id="outcomes"', 1)[1].split("</section>", 1)[0]
        for text in ("20,000 tokens", "2026-08-02 to 2026-09-01", "Not measured this run", "not comparable"):
            self.assertIn(text, section)

    def test_no_section_without_metric_rows(self):
        rep = self.finalized()
        rep["trend"]["ledger"] = rep["trend"]["ledger"][1:]
        self.assertNotIn('id="outcomes"', render_report.render(rep))


class ProcessReportCLI(unittest.TestCase):
    def test_finalize_writes_outcome_row_and_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            book_path = os.path.join(tmp, "ledger.json")
            ledger.dump(dict(version=1, entries=[outcome_entry()]), book_path)
            snap_path = os.path.join(tmp, "snap.json")
            with open(snap_path, "w") as f:
                json.dump(snapshot(at="2026-10-05T00:00:00Z", risky={}), f)
            rep = dict(report(generated="2026-10-05T00:00:00Z"), profile=dict(scope="all"), summary="s",
                       coverage=dict(sources=[]))
            rep["findings"][0].update(title="t", evidence="e", status="new")
            rep_path = os.path.join(tmp, "2026-10-05-audit.json")
            with open(rep_path, "w") as f:
                json.dump(rep, f)
            out = subprocess.run([sys.executable, "-B", os.path.join(SCRIPTS, "process_report.py"), rep_path,
                                  "--finalize", "--ledger", book_path, "--snapshot", snap_path],
                                 capture_output=True, text=True, timeout=60, env={**os.environ, "HOME": tmp})
            self.assertEqual(out.returncode, 0, out.stderr)
            with open(rep_path) as f:
                row = json.load(f)["trend"]["ledger"][0]
            self.assertEqual((row["verdict"], row["current"]["value"], row["outcome_only"]), ("dropped", 0, True))
            self.assertEqual(ledger.load(book_path)["entries"][0]["observations"][0]["value"], 0)


class CollectionTime(unittest.TestCase):
    def test_snapshot_records_collection_time_in_utc(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = os.path.join(tmp, "cfg")
            os.makedirs(cfg)
            out = os.path.join(tmp, "snap.json")
            before = time.time()
            result = subprocess.run([sys.executable, "-B", os.path.join(SCRIPTS, "collect.py"), "--claude-dir", cfg,
                                     "--scope", "global", "--days", "1", "--out", out],
                                    capture_output=True, text=True, timeout=180,
                                    env={**os.environ, "HOME": tmp, "CLAUDE_CONFIG_DIR": cfg, "TZ": "Asia/Tokyo"})
            self.assertEqual(result.returncode, 0, result.stderr[-500:])
            with open(out) as f:
                stamp = json.load(f)["generated_utc"]
            self.assertRegex(stamp, r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
            at = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            self.assertLessEqual(abs(at - before), 120)


class Docs(unittest.TestCase):
    def test_reference_lists_every_catalog_metric_and_check(self):
        path = os.path.join(SCRIPTS, "..", "references", "ledger.md")
        with open(path, encoding="utf-8") as f:
            ref = f.read()
        for name, row in outcome_metrics.CATALOG.items():
            for text in (name, row["unit"], row["source"]):
                self.assertIn("`%s`" % text, ref)
        for check in outcome_metrics.CHECKS:
            self.assertIn("`%s`" % check, ref)
        self.assertIn("outcome_only", ref)


if __name__ == "__main__":
    unittest.main()
