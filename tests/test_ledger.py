"""Ledger format, strict validation, ids and verdict rules. Pure functions; fake paths only."""
import contextlib
import copy
import datetime
import io
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_collect import SCRIPTS
import ledger

SCOPE = dict(scope="all", project=None, window_days=30)
KW = dict(type="keywords", source="corrections", any=["run the tests"])
SCRIPT = os.path.join(SCRIPTS, "ledger.py")


def slurp(path, mode="r"):
    with open(path, mode) as stream:
        return stream.read()


def jload(path):
    with open(path) as stream:
        return json.load(stream)


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

    def test_unparseable_input_is_a_constant_ledger_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = os.path.join(tmp, "binary.json")
            with open(binary, "wb") as stream:
                stream.write(b"\xff\xfeSECRETBYTES")
            folder = os.path.join(tmp, "dir.json")
            os.mkdir(folder)
            cases = [lambda: ledger.loads("[" * 100000),
                     lambda: ledger.loads('{"version": ' + "9" * 5000 + "}"),
                     lambda: ledger.load(binary),
                     lambda: ledger.load(folder)]
            for run in cases:
                with self.assertRaises(ledger.LedgerError) as caught:
                    run()
                self.assertEqual(caught.exception.input, "ledger")
                self.assertNotIn("SECRETBYTES", str(caught.exception))
                self.assertNotIn("xff", str(caught.exception))

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

ZERO = dict(matches=0, sessions_matched=0, sessions_scanned=0, complete=True)


class LedgerFiles(unittest.TestCase):
    """Fake home for record/remove tests: HOME, collect.HOME and collect.CLAUDE all point at it,
    so `~` in recorded paths never expands to the real home."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        self.claude = os.path.join(self.home, ".claude")
        os.makedirs(self.claude)
        env = mock.patch.dict(os.environ, {"HOME": self.home})
        env.start()
        self.addCleanup(env.stop)
        import collect
        for name, value in (("HOME", self.home), ("CLAUDE", self.claude)):
            patcher = mock.patch.object(collect, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.md = self.put("proj/CLAUDE.md", "# Rules\n<!-- setup-audit:begin L-20260928-1 -->\n"
                                            "Run the tests before saying done.\n"
                                            "<!-- setup-audit:end L-20260928-1 -->\n")
        self.settings = self.put(".claude/settings.json", json.dumps(
            {"permissions": {"deny": ["Bash(rm -rf *)"]}, "hooks": {}}))
        self.snapshot = dict(window_days=30, collection_scope=dict(requested="all", project=None, projects_collected=1))
        self.report = dict(version=1, generated="2026-09-28T10:00:00Z", findings=[dict(id="LRN-corrections:tests")],
                           metrics={}, applied=[])

    def put(self, rel, text):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def spec(self, **changes):
        s = dict(id="L-20260928-1", finding_id="LRN-corrections:tests", pattern="Reports done without tests",
                 mechanism="rule", selector=dict(KW),
                 edits=[dict(file=self.md, kind="markdown_block", backup=None)])
        s.update(changes)
        return s

    def record(self, book=None, spec=None, snapshot=None, report=None):
        with mock.patch("collect.count_selector", return_value=dict(ZERO)):
            return ledger.record(book or ledger.empty(), spec or self.spec(), snapshot or self.snapshot,
                                 report or self.report, "r", 1_790_000_000)


class Record(LedgerFiles):
    def test_record_markdown_block_fingerprint_and_baseline(self):
        with mock.patch("collect.count_selector", return_value=dict(matches=4, sessions_matched=3,
                                                                     sessions_scanned=12, complete=True)):
            book = ledger.record(ledger.empty(), self.spec(), self.snapshot, self.report, "2026-09-28-audit", 1_790_000_000)
        e = book["entries"][0]
        self.assertEqual(e["edits"][0]["sha256"], hashlib.sha256(b"Run the tests before saying done.\n").hexdigest())
        self.assertTrue(e["edits"][0]["file"].startswith("~"))
        self.assertEqual(e["baseline"]["sessions_matched"], 3)
        self.assertEqual(e["scope"], dict(scope="all", project=None, window_days=30))
        self.assertEqual((e["state"], e["observations"], e["run"]), ("active", [], "2026-09-28-audit"))

    def test_markers_missing_or_duplicated_are_refused(self):
        for text in ("# no markers\n",
                     "<!-- setup-audit:begin L-20260928-1 -->\nx\n<!-- setup-audit:end L-20260928-1 -->\n" * 2,
                     "<!-- setup-audit:end L-20260928-1 -->\nx\n<!-- setup-audit:begin L-20260928-1 -->\n"):
            with open(self.md, "w") as f:
                f.write(text)
            with self.subTest(text=text[:30]), self.assertRaises(ledger.LedgerError) as caught:
                ledger.record(ledger.empty(), self.spec(), self.snapshot, self.report, "r", 1_790_000_000)
            self.assertEqual(caught.exception.input, "edited file")

    def test_json_edits_store_parent_pointer_and_value_hash_only(self):
        spec = self.spec(mechanism="setting", edits=[dict(file=self.settings, kind="json_array_append",
                                                         pointer="/permissions/deny/0", backup=None)])
        book = self.record(spec=spec)
        edit = book["entries"][0]["edits"][0]
        self.assertEqual(edit["pointer"], "/permissions/deny")
        self.assertEqual(edit["sha256"], ledger.fingerprint("Bash(rm -rf *)"))
        self.assertNotIn("rm -rf", json.dumps(book))

    def test_unknown_finding_duplicate_id_and_bad_supersedes_refused(self):
        with self.assertRaises(ledger.LedgerError):
            self.record(spec=self.spec(finding_id="LRN-other"))
        book = self.record()
        with self.assertRaises(ledger.LedgerError):
            self.record(book)
        with self.assertRaises(ledger.LedgerError):
            self.record(book, self.spec(id="L-20260928-2", supersedes="L-20260101-1"))

    def test_supersedes_marks_old_entry(self):
        book = self.record()
        hook = self.put(".claude/hooks/check-tests.sh", "#!/bin/sh\n# setup-audit: L-20260928-2\nexit 0\n")
        book = self.record(book, self.spec(id="L-20260928-2", mechanism="hook", supersedes="L-20260928-1",
                                           edits=[dict(file=hook, kind="hook_script", backup=None)]))
        self.assertEqual([e["state"] for e in book["entries"]], ["superseded", "active"])

    def test_pattern_and_keywords_are_redacted(self):
        secret = "ghp_" + "a" * 36
        book = self.record(spec=self.spec(pattern="leaks " + secret, selector=dict(KW, any=[secret])))
        self.assertNotIn(secret, json.dumps(book))

    def test_metric_baseline_from_report(self):
        sel = dict(type="metric", name="corrections_count_30d", basis="measured", unit="prompts", source="corrections.count")
        report = dict(self.report, window_days=30, metrics={"corrections_count_30d": dict(
            value=12, basis="measured", unit="prompts", source="corrections.count")},
            coverage=dict(sources=[dict(source="corrections", status="collected", omitted=0)]))
        book = ledger.record(ledger.empty(), self.spec(selector=sel), self.snapshot, report, "r", 1_790_000_000)
        self.assertEqual(book["entries"][0]["baseline"]["value"], 12)
        self.assertTrue(book["entries"][0]["baseline"]["complete"])

    def test_wrong_typed_fields_raise_ledger_error_naming_the_input(self):
        sel = dict(type="metric", name="m", basis="measured", unit="prompts", source="corrections.count")
        cases = [
            ("report", dict(self.report, findings="x"), self.snapshot, self.spec()),
            ("report", dict(self.report, findings=["x", 3]), self.snapshot, self.spec()),
            ("report", dict(self.report, metrics=[1]), self.snapshot, self.spec(selector=sel)),
            ("report", dict(self.report, metrics={"m": dict(value=1, basis="measured", unit="prompts",
                                                            source="corrections.count")},
                            coverage="x"), self.snapshot, self.spec(selector=sel)),
            ("report", dict(self.report, metrics={"m": dict(value=1, basis="measured", unit="prompts",
                                                            source="corrections.count")},
                            coverage=dict(sources=[3])), self.snapshot, self.spec(selector=sel)),
            ("report", dict(self.report, metrics={"m": dict(value=1, basis="measured", unit="prompts",
                                                            source="corrections.count")},
                            coverage=dict(sources=[dict(source="corrections")])), self.snapshot,
             self.spec(selector=sel)),
            ("snapshot", self.report, dict(self.snapshot, collection_scope="x"), self.spec()),
            ("spec", self.report, self.snapshot, self.spec(mechanism="setting", edits=[dict(
                file=self.settings, kind="json_array_append", pointer="/permissions/deny/\u00b2", backup=None)])),
            ("spec", self.report, self.snapshot, self.spec(mechanism="setting", edits=[dict(
                file=self.settings, kind="json_array_append", pointer="/permissions/deny/x", backup=None)])),
            ("edited file", self.report, self.snapshot, self.spec(mechanism="setting", edits=[dict(
                file=self.settings, kind="json_array_append", pointer="/permissions/deny/5", backup=None)])),
            ("snapshot", self.report, dict(self.snapshot, collection_scope=[]), self.spec()),
            ("snapshot", self.report, dict(self.snapshot, collection_scope=dict(requested="project", project=None)),
             self.spec()),
            ("spec", self.report, self.snapshot, self.spec(edits=["x"])),
            ("spec", self.report, self.snapshot, self.spec(edits="x")),
            ("spec", self.report, self.snapshot, self.spec(supersedes=["L-1"])),
            ("spec", self.report, self.snapshot, self.spec(finding_id=["x"])),
            ("spec", self.report, self.snapshot, self.spec(selector="x")),
            ("spec", self.report, self.snapshot, self.spec(pattern=5)),
        ]
        for label, report, snapshot, spec in cases:
            with self.subTest(label=label, spec=str(spec)[:40]), mock.patch(
                    "collect.count_selector", return_value=dict(ZERO)):
                with self.assertRaises(ledger.LedgerError) as caught:
                    ledger.record(ledger.empty(), spec, snapshot, report, "r", 1_790_000_000)
                self.assertEqual(caught.exception.input, label)

    def test_hook_marker_must_appear_exactly_once_near_the_top(self):
        m = "# setup-audit: L-20260928-2\n"
        for text in ("#!/bin/sh\n" + m + m + "exit 0\n", "#!/bin/sh\n" * 6 + m, "#!/bin/sh\nexit 0\n"):
            hook = self.put(".claude/hooks/h.sh", text)
            spec = self.spec(id="L-20260928-2", mechanism="hook", edits=[dict(file=hook, kind="hook_script", backup=None)])
            with self.subTest(text=text[:40]), self.assertRaises(ledger.LedgerError) as caught:
                self.record(spec=spec)
            self.assertEqual(caught.exception.input, "edited file")

    def cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True,
                              env=dict(os.environ, HOME=self.home))

    def test_cli_next_id_and_record_write_private_ledger(self):
        path = os.path.join(self.home, "audits", "ledger.json")
        out = self.cli("next-id", "--ledger", path).stdout.strip()
        self.assertRegex(out, r"^L-\d{8}-1$")
        files = {}
        for name, data in (("snap.json", self.snapshot), ("report.json", self.report),
                           ("spec.json", self.spec(id=out, edits=[dict(file=self.settings, kind="json_set",
                                                                       pointer="/permissions/deny", backup=None)]))):
            files[name] = self.put(name, json.dumps(data))
        run = self.cli("record", "--ledger", path, "--snapshot", files["snap.json"],
                       "--report", files["report.json"], "--spec", files["spec.json"], "--claude-dir", self.claude)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(ledger.load(path)["entries"][0]["id"], out)

    def test_cli_errors_name_input_and_leave_ledger_unchanged(self):
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(ledger.empty(), path)
        before = slurp(path)
        bad = self.put("spec.json", '{"id": "sk-SECRET-VALUE"}')
        snap = self.put("snap.json", json.dumps(self.snapshot))
        rep = self.put("report.json", json.dumps(self.report))
        run = self.cli("record", "--ledger", path, "--snapshot", snap, "--report", rep, "--spec", bad,
                       "--claude-dir", self.claude)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("entry spec", run.stderr)
        self.assertNotIn("SECRET", run.stderr)
        self.assertEqual(slurp(path), before)

    def test_cli_non_object_json_inputs_fail_with_constant_message(self):
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(ledger.empty(), path)
        before = slurp(path)
        good = {"snap": self.snapshot, "rep": self.report, "spec": self.spec()}
        labels = {"snap": "snapshot", "rep": "current report", "spec": "entry spec"}
        for which in good:
            for bad in ('["SECRET-VALUE"]', '"SECRET-VALUE"', "3", "null"):
                paths = {k: self.put(k + ".json", json.dumps(v)) for k, v in good.items()}
                paths[which] = self.put(which + ".json", bad)
                with self.subTest(which=which, bad=bad):
                    run = self.cli("record", "--ledger", path, "--snapshot", paths["snap"], "--report", paths["rep"],
                                   "--spec", paths["spec"], "--claude-dir", self.claude)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertIn("Ledger update failed. The " + labels[which], run.stderr)
                    self.assertNotIn("SECRET", run.stderr)
                    self.assertNotIn("Traceback", run.stderr)
                    self.assertEqual(slurp(path), before)


class Remove(LedgerFiles):
    def recorded(self, *specs):
        book = ledger.empty()
        zero = dict(matches=0, sessions_matched=0, sessions_scanned=0, complete=True)
        with mock.patch("collect.count_selector", return_value=zero):
            for spec in specs:
                book = ledger.record(book, spec, self.snapshot, self.report, "r", 1_790_000_000)
        return book

    def backups(self):
        return os.path.join(self.home, "backups")

    def remove(self, book, ids=("L-20260928-1",)):
        return ledger.apply_removal(book, ledger.plan_removal(book, list(ids)), self.backups(), self.home)

    def test_markdown_round_trip_and_dry_run_writes_nothing(self):
        before = "# Rules\n"
        book = self.recorded(self.spec())
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual([r["status"] for r in rows], ["removable"])
        self.assertEqual(rows[0]["edit"], 0)
        self.assertIn("setup-audit:begin", slurp(self.md))  # plan changed nothing
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(slurp(self.md), before)
        self.assertEqual(rows[0]["status"], "removed")
        self.assertTrue(os.path.exists(rows[0]["backup"]))
        self.assertEqual(book["entries"][0]["state"], "removed")
        self.assertNotIn("_identity", rows[0])
        json.dumps(rows)

    def test_crlf_block_is_modified_not_removed(self):
        book = self.recorded(self.spec())
        with open(self.md, "rb") as f:
            data = f.read()
        with open(self.md, "wb") as f:
            f.write(data.replace(b"\n", b"\r\n"))
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("modified", "hash_mismatch"))
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(slurp(self.md, "rb"), data.replace(b"\n", b"\r\n"))
        self.assertEqual(book["entries"][0]["state"], "active")

    def test_missing_file_is_absent_and_entry_closes(self):
        book = self.recorded(self.spec())
        os.unlink(self.md)
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual(rows[0]["status"], "absent")
        book, _ = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(book["entries"][0]["state"], "removed")

    def test_other_entry_block_survives(self):
        with open(self.md, "a") as f:
            f.write("<!-- setup-audit:begin L-20260928-2 -->\nKeep me.\n<!-- setup-audit:end L-20260928-2 -->\n")
        book = self.recorded(self.spec(), self.spec(id="L-20260928-2"))
        book, _ = self.remove(book)
        self.assertEqual(slurp(self.md), "# Rules\n<!-- setup-audit:begin L-20260928-2 -->\nKeep me.\n"
                                               "<!-- setup-audit:end L-20260928-2 -->\n")
        self.assertEqual([e["state"] for e in book["entries"]], ["removed", "active"])

    def hook_book(self):
        hook = self.put(".claude/hooks/check.sh", "#!/bin/sh\n# setup-audit: L-20260928-1\nexit 0\n")
        group = {"matcher": "Bash", "hooks": [{"type": "command", "command": hook, "timeout": 5}]}
        with open(self.settings, "w") as f:
            json.dump({"permissions": {"deny": ["Bash(rm -rf *)"]}, "hooks": {"PreToolUse": [group]}}, f)
        return hook, self.recorded(self.spec(mechanism="hook", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/hooks/PreToolUse/0", backup=None),
            dict(file=hook, kind="hook_script", backup=None)]))

    def test_hook_and_registration_round_trip(self):
        hook, book = self.hook_book()
        book, rows = self.remove(book)
        self.assertEqual([r["status"] for r in rows], ["removed", "removed"])
        self.assertFalse(os.path.exists(hook))
        self.assertEqual(jload(self.settings), {"permissions": {"deny": ["Bash(rm -rf *)"]},
                                                          "hooks": {"PreToolUse": []}})

    def test_hook_script_blocked_when_registration_removal_blocked(self):
        hook, book = self.hook_book()
        os.rename(self.settings, self.settings + ".real")
        os.symlink(self.settings + ".real", self.settings)
        book, rows = self.remove(book)
        self.assertEqual([r["status"] for r in rows], ["blocked", "blocked"])
        self.assertTrue(os.path.exists(hook))
        self.assertEqual(book["entries"][0]["state"], "active")

    def test_hook_without_recorded_registration_is_blocked(self):
        hook = self.put(".claude/hooks/check.sh", "#!/bin/sh\n# setup-audit: L-20260928-1\nexit 0\n")
        book = self.recorded(self.spec(mechanism="hook", edits=[dict(file=hook, kind="hook_script", backup=None)]))
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("blocked", "registration_unrecorded"))

    def test_json_set_restores_from_backup_or_blocks(self):
        backup = self.put("backups/settings.json.bak", json.dumps({"model": "sonnet"}))
        with open(self.settings, "w") as f:
            json.dump({"model": "opus", "env": {}}, f)
        book = self.recorded(self.spec(mechanism="setting", edits=[
            dict(file=self.settings, kind="json_set", pointer="/model", backup=backup)]))
        os.rename(backup, backup + ".gone")
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("blocked", "backup_missing"))
        os.rename(backup + ".gone", backup)
        book, rows = self.remove(book)
        self.assertEqual(rows[0]["status"], "removed")
        self.assertEqual(jload(self.settings), {"model": "sonnet", "env": {}})

    def test_json_set_without_backup_deletes_key(self):
        with open(self.settings, "w") as f:
            json.dump({"model": "opus"}, f)
        book = self.recorded(self.spec(mechanism="setting", edits=[
            dict(file=self.settings, kind="json_set", pointer="/model", backup=None)]))
        book, rows = self.remove(book)
        self.assertEqual(rows[0]["status"], "removed")
        self.assertEqual(jload(self.settings), {})

    def test_two_appends_to_the_same_array_in_one_entry_are_both_removed(self):
        with open(self.settings, "w") as f:
            json.dump({"permissions": {"deny": ["Bash(rm -rf *)", "Read(.env)", "Bash(sudo *)"]}}, f)
        book = self.recorded(self.spec(mechanism="setting", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/permissions/deny/1", backup=None),
            dict(file=self.settings, kind="json_array_append", pointer="/permissions/deny/2", backup=None)]))
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual([r["edit"] for r in rows], [0, 1])
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual([r["status"] for r in rows], ["removed", "removed"])
        self.assertEqual(jload(self.settings), {"permissions": {"deny": ["Bash(rm -rf *)"]}})
        self.assertEqual(len(os.listdir(self.backups())), 1)  # one backup per file
        self.assertEqual(rows[0]["backup"], rows[1]["backup"])

    def test_symlinked_file_is_blocked(self):
        book = self.recorded(self.spec())
        real = self.md + ".real"
        os.rename(self.md, real)
        os.symlink(real, self.md)
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("blocked", "symlink"))

    def test_file_changed_between_plan_and_apply_is_blocked(self):
        book = self.recorded(self.spec())
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        with open(self.md, "a") as f:
            f.write("user line\n")
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("blocked", "changed_since_plan"))
        self.assertIn("setup-audit:begin", slurp(self.md))

    def test_failed_backup_blocks_the_edit_and_other_files_continue(self):
        book = self.recorded(self.spec(), self.spec(id="L-20260928-2", mechanism="setting", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/permissions/deny/0", backup=None)]))
        before = slurp(self.md)
        real = ledger.safe_write.backup_from_fd

        def flaky(fd, path, backup_dir, home):
            if path == self.md:
                raise OSError("disk full")
            return real(fd, path, backup_dir, home)

        rows = ledger.plan_removal(book, ["L-20260928-1", "L-20260928-2"])
        with mock.patch.object(ledger.safe_write, "backup_from_fd", side_effect=flaky):
            book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("blocked", "backup_failed"))
        self.assertEqual(slurp(self.md), before)
        self.assertEqual(rows[1]["status"], "removed")
        self.assertEqual([e["state"] for e in book["entries"]], ["active", "removed"])

    def test_failed_write_blocks_the_edit_and_leaves_file(self):
        book = self.recorded(self.spec())
        before = slurp(self.md)
        with mock.patch.object(ledger.safe_write, "atomic_write", side_effect=OSError("read-only")):
            book, rows = self.remove(book)
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("blocked", "write_failed"))
        self.assertEqual(slurp(self.md), before)
        self.assertEqual(book["entries"][0]["state"], "active")

    def test_apply_rejects_rows_without_plan_identity(self):
        book = self.recorded(self.spec())
        rows = [dict(r) for r in ledger.plan_removal(book, ["L-20260928-1"])]
        for r in rows:
            r.pop("_identity")
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(rows[0]["reason"], "changed_since_plan")
        self.assertIn("setup-audit:begin", slurp(self.md))

    def test_unknown_entry_id_is_a_ledger_error(self):
        with self.assertRaises(ledger.LedgerError):
            ledger.plan_removal(self.recorded(self.spec()), ["L-20260101-9"])

    def cli(self, *args):
        return subprocess.run([sys.executable, SCRIPT, *args], capture_output=True, text=True,
                              env=dict(os.environ, HOME=self.home))

    def test_cli_dry_run_then_apply(self):
        book = self.recorded(self.spec())
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(book, path)
        dry = self.cli("remove", "--ledger", path, "--all")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(json.loads(dry.stdout)[0]["status"], "removable")
        self.assertNotIn("_identity", dry.stdout)
        self.assertEqual(ledger.load(path), book)
        applied = self.cli("remove", "--ledger", path, "--all", "--apply", "--backup-dir", self.backups())
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertNotIn("_identity", applied.stdout)
        self.assertEqual(ledger.load(path)["entries"][0]["state"], "removed")
        self.assertNotIn("Run the tests", applied.stdout)

    def test_cli_blocked_exits_two_and_still_records_progress(self):
        book = self.recorded(self.spec(), self.spec(id="L-20260928-2", mechanism="setting", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/permissions/deny/0", backup=None)]))
        real = self.md + ".real"
        os.rename(self.md, real)
        os.symlink(real, self.md)
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(book, path)
        run = self.cli("remove", "--ledger", path, "--all", "--apply", "--backup-dir", self.backups())
        self.assertEqual(run.returncode, 2, run.stderr)
        self.assertEqual([e["state"] for e in ledger.load(path)["entries"]], ["active", "removed"])

    def test_cli_errors_are_constant_and_apply_needs_backup_dir(self):
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(self.recorded(self.spec()), path)
        run = self.cli("remove", "--ledger", path, "--entry", "L-20260101-9")
        self.assertEqual(run.returncode, 1)
        self.assertIn("Ledger update failed", run.stderr)
        self.assertNotIn("Traceback", run.stderr)
        run = self.cli("remove", "--ledger", path, "--all", "--apply")
        self.assertEqual(run.returncode, 1)
        self.assertIn("Ledger update failed", run.stderr)
        self.assertIn("--backup-dir", run.stderr)
        self.assertIn("setup-audit:begin", slurp(self.md))

    def test_hook_script_survives_when_registration_was_edited(self):
        hook, book = self.hook_book()
        registration = jload(self.settings)
        registration["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 9  # user edited the group
        with open(self.settings, "w") as f:
            json.dump(registration, f)
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual([(r["kind"], r["status"], r["reason"]) for r in rows],
                         [("json_array_append", "absent", "value_missing"),
                          ("hook_script", "blocked", "registration_remains")])
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertTrue(os.path.exists(hook))
        self.assertEqual(jload(self.settings), registration)
        self.assertEqual(book["entries"][0]["state"], "active")

    def test_hook_registration_appearing_after_plan_blocks_the_unlink(self):
        hook, book = self.hook_book()
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual([r["status"] for r in rows], ["removable", "removable"])
        registered = jload(self.settings)
        registered["hooks"]["Other"] = [{"hooks": [{"type": "command", "command": hook}]}]
        with open(self.settings, "w") as f:
            json.dump(registered, f)
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertTrue(os.path.exists(hook))
        self.assertEqual(rows[1]["status"], "blocked")

    def test_duplicate_appended_values_are_ambiguous_and_untouched(self):
        with open(self.settings, "w") as f:
            json.dump({"permissions": {"deny": ["Read(.env)", "Read(.env)"]}}, f)
        book = self.recorded(self.spec(mechanism="setting", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/permissions/deny/0", backup=None)]))
        before = slurp(self.settings)
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("modified", "ambiguous_duplicate"))
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(slurp(self.settings), before)
        self.assertEqual(book["entries"][0]["state"], "active")

    def test_non_ascii_settings_survive_a_json_rewrite_as_utf8(self):
        with open(self.settings, "w", encoding="utf-8") as f:
            json.dump({"note": "caf\u00e9 \u2603", "permissions": {"deny": ["Read(.env)"]}}, f, ensure_ascii=False)
        book = self.recorded(self.spec(mechanism="setting", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/permissions/deny/0", backup=None)]))
        book, rows = self.remove(book)
        self.assertEqual(rows[0]["status"], "removed")
        raw = slurp(self.settings, "rb")
        self.assertIn("caf\u00e9 \u2603".encode("utf-8"), raw)
        self.assertNotIn(b"\\u00e9", raw)

    def test_cli_failure_after_files_changed_says_so(self):
        book = self.recorded(self.spec())
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(book, path)
        err = io.StringIO()
        with mock.patch.object(ledger, "dump", side_effect=OSError("disk full")), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()), \
                self.assertRaises(SystemExit) as caught:
            ledger.main(["remove", "--ledger", path, "--all", "--apply", "--backup-dir", self.backups()])
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("after files were changed", err.getvalue())
        self.assertNotIn("Nothing was changed", err.getvalue())
        self.assertNotIn("setup-audit:begin", slurp(self.md))  # the edit did happen
        self.assertEqual(ledger.load(path), book)


if __name__ == "__main__":
    unittest.main()
