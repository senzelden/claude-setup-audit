# Per-item Learning Ledger Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record each applied learning fix in a strict ledger, count its specific friction pattern
deterministically on later runs, emit verdicts/proposals, and remove tool-written edits safely.

**Architecture:** A new `ledger.py` owns the format, verdict rules and the `next-id`/`record`/`remove`
CLI. `collect.py` counts selectors over raw local sources (`history.jsonl`, facets) and writes
`ledger_signals` into the snapshot. `process_report.py` turns signals into `trend.ledger` rows
and appends one observation per run. File-safety helpers move from `prune_permissions.py` into
`safe_write.py` so both the pruner and the removal helper share them.

**Tech Stack:** Python 3.11+ standard library only; `unittest`; CI adds `jsonschema` (schema
check) and `coverage` (floor 88).

**Spec:** `docs/superpowers/specs/2026-09-28-learning-ledger-design.md`

## Global Constraints

- Standard library only in `scripts/` and `tests/` (CI-only `tests/check_snapshot_schema.py` may use `jsonschema`).
- Tests use temporary fake homes (`tests/test_collect.py` `FakeHome`); never read or write the real `~/.claude`.
- Ledger holds counts, hashes, paths, ids, a ≤200-char redacted `pattern` and ≤5 redacted keywords (≤40 chars each). Never prompt text, friction text or configuration values.
- Error messages are constant text naming the input (`ledger`, `snapshot`, `current report`, `entry spec`, `edited file`, `backup`) and a line when known; never quote input values.
- Ledger writes are atomic, refuse symlinks, and leave mode 0600. Invalid input leaves every file unchanged.
- Every path is explicit; no script searches for a ledger.
- Verdict constants: `MIN_SESSIONS = 5`, `MIN_BASELINE = 3`, `QUIET_DAYS = 30`, drop threshold rate ≤ 0.5 × baseline rate.
- Snapshot stays `snapshot_version` 1; `ledger_signals` is an additive optional field.
- Existing tests (`python3 -m unittest discover -s tests -v`) must keep passing unchanged.
- Commits: stage explicit paths; message ends with the single trailer `Assisted-by: Claude:claude-opus-5-5`. No push, tag or version bump.
- Gate before completion: `python3 -m unittest discover -s tests -v`; `python3 tests/check_snapshot_schema.py -v` (needs `jsonschema`; if not installed locally, say so rather than skipping silently); `git diff --check`; `python3 -m coverage run -m unittest discover -s tests && python3 -m coverage combine && python3 -m coverage report --fail-under=88` when `coverage` is available.

Spec deviation ruled during planning: the entry `state` enum is `active | removed | superseded`.
The spec's `retired` had no writer (retirement is carried out with `remove`, which sets
`removed`). Task 7 updates the spec text.

## Review Focus

1. Rerunning `process_report.py --finalize` for the same report (documented after applying fixes) must replace that run's observation, not append a duplicate — otherwise two identical observations fake "two in a row" and trigger escalation/quiet. (Task 6 test `test_rerun_replaces_same_run_observation`.)
2. An editor converting a Markdown file to CRLF or trimming trailing spaces: markers must still be found (compare `line.strip()`), but the changed block must report `modified` and never be removed. (Task 5 test `test_crlf_block_is_modified_not_removed`.)
3. The edited file deleted by the user: `remove` reports `absent` and closes the entry without crashing. (Task 5 test `test_missing_file_is_absent_and_entry_closes`.)
4. An entry whose `applied_at` lies in the future (clock skew or hand edit): counting yields zero sessions → `too_early`, not an exception. (Task 3 test `test_future_applied_at_counts_nothing`.)
5. Two entries with markers in the same CLAUDE.md: removing one leaves the other's block and markers byte-identical. (Task 5 test `test_other_entry_block_survives`.)

---

### Task 1: Extract `safe_write.py` from the permission pruner

**Files:**
- Create: `plugins/setup-audit/skills/setup-audit/scripts/safe_write.py`
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/prune_permissions.py` (lines ~31-135 and `apply_file` ~157-201)
- Test: `tests/test_safe_write.py`

**Interfaces:**
- Produces: `safe_write.SymlinkRefused`, `safe_write.ChangedSincePlan`, `safe_write.open_no_symlink(path, allow_symlinks=False) -> (fd, stat)`, `safe_write.identity_of(stat) -> tuple`, `safe_write.atomic_write(target: str, text: str, prefix: str = ".prune_permissions.") -> None`, `safe_write.backup_from_fd(fd: int, path: str, backup_dir: str, home: str) -> str` (backup path; file mode 0600; name prefix is `path` relative to `home` with separators replaced by `__`).
- `prune_permissions` keeps exporting `SymlinkRefused`, `ChangedSincePlan`, `open_no_symlink`, `identity_of`, `atomic_write` (imported names) so existing tests that patch `prune_permissions.atomic_write` and `prune_permissions.shutil.copyfileobj` keep working.

- [ ] **Step 1: Write the failing test**

```python
"""Shared file-safety helpers: symlink refusal, atomic writes, private unique backups."""
import os
import stat
import tempfile
import unittest

from test_collect import SCRIPTS  # noqa: F401  (puts scripts/ on sys.path)
import safe_write


class SafeWrite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        self.path = os.path.join(self.home, "proj", "CLAUDE.md")
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("original\n")

    def test_backup_is_private_unique_and_complete(self):
        backups = os.path.join(self.home, "backups")
        made = []
        for _ in range(2):
            fd, _st = safe_write.open_no_symlink(self.path)
            try:
                made.append(safe_write.backup_from_fd(fd, self.path, backups, self.home))
            finally:
                os.close(fd)
        self.assertNotEqual(made[0], made[1])
        for backup in made:
            self.assertTrue(os.path.basename(backup).startswith("proj__CLAUDE.md."))
            self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
            with open(backup) as f:
                self.assertEqual(f.read(), "original\n")

    def test_symlink_is_refused(self):
        link = os.path.join(self.home, "link.md")
        os.symlink(self.path, link)
        with self.assertRaises(safe_write.SymlinkRefused):
            safe_write.open_no_symlink(link)

    def test_atomic_write_uses_prefix_and_replaces(self):
        safe_write.atomic_write(self.path, "new\n", prefix=".ledger.")
        with open(self.path) as f:
            self.assertEqual(f.read(), "new\n")
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.path))), ["CLAUDE.md"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_safe_write -v` (from repo root; if module path fails use `cd tests && python3 -m unittest test_safe_write -v`)
Expected: FAIL with `ModuleNotFoundError: No module named 'safe_write'`

- [ ] **Step 3: Create `safe_write.py`**

Move `SymlinkRefused`, `ChangedSincePlan`, `open_no_symlink`, `identity_of` and `atomic_write` **verbatim** (including their docstrings and comments) from `prune_permissions.py`, changing only `atomic_write`'s signature to `atomic_write(target, text, prefix=".prune_permissions.")` and its `mkstemp(prefix=".prune_permissions.", ...)` call to `mkstemp(prefix=prefix, ...)`. Add the module header and the new backup helper:

```python
#!/usr/bin/env python3
"""Symlink-refusing reads, identity checks, atomic writes and private backups (stdlib only).

Shared by prune_permissions.py and ledger.py; behaviour moved unchanged from prune_permissions.py.
"""
import errno
import os
import shutil
import tempfile
import time

# ... SymlinkRefused, ChangedSincePlan, open_no_symlink, identity_of, atomic_write moved here ...


def backup_from_fd(fd, path, backup_dir, home):
    """Copy the open file into backup_dir under an exclusive, private (0600), unique name.

    mkstemp uses exclusive creation and mode 0600: repeated backups cannot overwrite recovery
    data or follow a pre-existing backup symlink, even in the same second. A partial backup is
    removed and the error re-raised, so a failed backup always blocks the edit.
    """
    os.makedirs(backup_dir, exist_ok=True)
    prefix = path.replace(home, "").strip(os.sep).replace(os.sep, "__")
    backup_fd, backup = tempfile.mkstemp(prefix=prefix + f".{int(time.time())}.",
                                         suffix=".bak", dir=backup_dir)
    try:
        with os.fdopen(backup_fd, "wb") as dst, os.fdopen(fd, "rb", closefd=False) as src:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
    except BaseException:
        try:
            os.unlink(backup)
        except OSError:
            pass
        raise
    return backup
```

- [ ] **Step 4: Make `prune_permissions.py` import the helpers**

Delete the moved definitions from `prune_permissions.py` and add after `import collect`:

```python
from safe_write import (  # noqa: E402  (re-exported: tests and callers use these names here)
    ChangedSincePlan, SymlinkRefused, atomic_write, backup_from_fd, identity_of, open_no_symlink)
```

Keep `import shutil` with the comment `# noqa: F401  tests patch prune_permissions.shutil.copyfileobj`. Replace the inline backup block in `apply_file` (from `os.makedirs(backup_dir, exist_ok=True)` through the `except BaseException` cleanup) with:

```python
        backup = backup_from_fd(fd, path, backup_dir, collect.HOME)
```

keeping the surrounding `try: ... finally: os.close(fd)`, and the identity check before it. `apply_file` must still call `atomic_write(target, text)` by its bare name so `mock.patch.object(prune_permissions, 'atomic_write', ...)` still intercepts it.

- [ ] **Step 5: Run the new and the existing tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS, including `ReadOnlyDiagnostics`, `AtomicWrite`, and every `prune_permissions` backup test in `tests/test_collect.py` and `tests/test_eval_apply.py`, unchanged.

- [ ] **Step 6: Red proof**

Temporarily change `backup_from_fd`'s `mkstemp` to write with `os.open(..., 0o644)` semantics (e.g. add `os.chmod(backup, 0o644)` after the copy); run `python3 -m unittest discover -s tests -k backup -v`; expect `test_backup_is_private_unique_and_complete` (and pruner backup-permission tests) to FAIL. Revert.

- [ ] **Step 7: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/safe_write.py plugins/setup-audit/skills/setup-audit/scripts/prune_permissions.py tests/test_safe_write.py
git commit -m "Extract file-safety helpers from the permission pruner

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 2: Ledger format, validation, ids and verdicts (`ledger.py` core)

**Files:**
- Create: `plugins/setup-audit/skills/setup-audit/scripts/ledger.py`
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/report_state.py` (add `LEDGER_VERDICTS` constant next to `HISTORY`)
- Test: `tests/test_ledger.py`

**Interfaces:**
- Consumes: `report_state.ReportError(message, input=None, line=None)`, `report_state.load_json(text)`, `report_state.timestamp(value) -> datetime`, `report_state.finite(value)`, `collect.redact(text)`.
- Produces:
  - `ledger.LedgerError(report_state.ReportError)` — default `input='ledger'`.
  - `ledger.empty() -> dict` → `{"version": 1, "entries": []}`.
  - `ledger.loads(text: str) -> dict` (strict; raises `LedgerError`).
  - `ledger.load(path: str) -> dict` (absent file → `empty()`; symlink → `LedgerError('ledger must not be a symlink')`).
  - `ledger.dump(book: dict, path: str) -> None` (validates, refuses symlink, `safe_write.atomic_write(path, text, prefix=".ledger.")`, then `os.chmod(path, 0o600)`; creates parent dir).
  - `ledger.validate(book) -> dict`, `ledger.validate_selector(sel)`, `ledger.validate_counts(counts, metric: bool)`.
  - `ledger.selector_hash(sel) -> str` (sha256 hex of canonical JSON).
  - `ledger.fingerprint(value) -> str` (sha256 hex of `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`).
  - `ledger.iso(epoch: float) -> str` (`YYYY-MM-DDTHH:MM:SSZ`), `ledger.epoch(text: str) -> float`.
  - `ledger.next_id(book, day: datetime.date) -> str` → `L-YYYYMMDD-N`.
  - `ledger.verdict(entry, current, scope, previous) -> (verdict, reason)`.
  - `ledger.proposal(entry, verdict, previous) -> "escalate" | "retire" | None`, `ledger.next_rung(entry) -> str | None`.
  - Constants: `MECHANISMS`, `LADDER`, `STATES`, `SOURCES`, `KINDS`, `MIN_SESSIONS`, `MIN_BASELINE`, `QUIET_DAYS`, `ID_RE`.
  - `report_state.LEDGER_VERDICTS = ('unknown', 'too_early', 'quiet', 'dropped', 'not_dropped')`.

Entry shape (all fields required, no extras):

```
id, applied_at, run, finding_id, pattern, mechanism, state, supersedes, selector, scope,
baseline, edits, observations
```

- counts (non-metric): `from, to, matches, sessions_matched, sessions_scanned, complete`
- counts (metric): `from, to, value, complete`
- current counts passed to `verdict` additionally carry `selector_sha`.
- observation: counts + `run, verdict, reason`.
- edit: `file, kind, sha256, backup` (+ `pointer` for `json_*` kinds); `backup` is a string or `null` (file did not exist before the edit).
- scope: `scope` (`global|project|all`), `project` (string or null), `window_days` (positive int).

- [ ] **Step 1: Write the failing tests**

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tests && python3 -m unittest test_ledger -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'ledger'`

- [ ] **Step 3: Add the verdict constant to `report_state.py`**

After `BASIS = {...}`:

```python
LEDGER_VERDICTS = ('unknown', 'too_early', 'quiet', 'dropped', 'not_dropped')
```

- [ ] **Step 4: Write `ledger.py` core**

```python
#!/usr/bin/env python3
"""Per-item learning ledger: strict format, verdicts, and the next-id/record/remove CLI.

The ledger is the plugin's own file. It holds counts, hashes, paths and ids, never prompt text
or configuration values. Every path is explicit; nothing is searched for. Stdlib only.
"""
import copy
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_state  # noqa: E402
import safe_write  # noqa: E402

VERSION = 1
MECHANISMS = ('memory', 'rule', 'hook', 'skill', 'setting')
LADDER = ('memory', 'rule', 'hook', 'skill')
STATES = ('active', 'removed', 'superseded')
SOURCES = ('corrections', 'friction_details')
KINDS = ('markdown_block', 'hook_script', 'json_array_append', 'json_set')
SCOPES = ('global', 'project', 'all')
ID_RE = re.compile(r'L-\d{8}-\d{1,4}\Z')
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
MIN_SESSIONS, MIN_BASELINE, QUIET_DAYS = 5, 3, 30
ENTRY_FIELDS = {'id', 'applied_at', 'run', 'finding_id', 'pattern', 'mechanism', 'state',
                'supersedes', 'selector', 'scope', 'baseline', 'edits', 'observations'}
COUNT_FIELDS = {'from', 'to', 'matches', 'sessions_matched', 'sessions_scanned', 'complete'}
METRIC_FIELDS = {'from', 'to', 'value', 'complete'}
OBSERVATION_EXTRA = {'run', 'verdict', 'reason'}


class LedgerError(report_state.ReportError):
    """Constant-text validation failure; `input` names the file role, never its content."""

    def __init__(self, message, input='ledger', line=None):
        super().__init__(message, input=input, line=line)


def require(condition, message, input='ledger'):
    if not condition:
        raise LedgerError(message, input=input)


def empty():
    return {'version': VERSION, 'entries': []}


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def epoch(text):
    try:
        return report_state.timestamp(text).timestamp()
    except (report_state.ReportError, ValueError, TypeError, AttributeError):
        raise LedgerError('invalid timestamp') from None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def selector_hash(selector):
    return fingerprint(selector)


def _text(value, limit):
    return isinstance(value, str) and 0 < len(value.strip()) and len(value) <= limit


def _count(value):
    return type(value) is int and value >= 0


def validate_selector(selector):
    require(isinstance(selector, dict), 'invalid selector')
    kind = selector.get('type')
    if kind == 'keywords':
        require(set(selector) == {'type', 'source', 'any'}, 'invalid selector fields')
        require(selector['source'] in SOURCES, 'invalid selector source')
        words = selector['any']
        require(isinstance(words, list) and 1 <= len(words) <= 5, 'selector needs 1 to 5 keywords')
        require(all(_text(w, 40) for w in words), 'keywords must be 1 to 40 characters')
    elif kind == 'friction_category':
        require(set(selector) == {'type', 'name'} and _text(selector['name'], 60), 'invalid selector fields')
    elif kind == 'metric':
        require(set(selector) == {'type', 'name', 'basis', 'unit', 'source'}, 'invalid selector fields')
        require(all(_text(selector[k], 120) for k in ('name', 'basis', 'unit', 'source')), 'invalid selector fields')
    else:
        raise LedgerError('invalid selector type')


def validate_counts(counts, metric, extra=frozenset()):
    require(isinstance(counts, dict), 'invalid counts')
    require(set(counts) == (METRIC_FIELDS if metric else COUNT_FIELDS) | set(extra), 'invalid count fields')
    epoch(counts['from'])
    epoch(counts['to'])
    require(type(counts['complete']) is bool, 'invalid completeness flag')
    if metric:
        require(counts['value'] is None or report_state.finite(counts['value']), 'invalid metric value')
    else:
        require(all(_count(counts[k]) for k in ('matches', 'sessions_matched', 'sessions_scanned')),
                'counts must be non-negative integers')
        require(counts['sessions_matched'] <= counts['sessions_scanned'], 'matched sessions exceed scanned')
        require(counts['sessions_matched'] <= counts['matches'], 'matched sessions exceed matches')


def validate_edit(edit):
    require(isinstance(edit, dict) and edit.get('kind') in KINDS, 'invalid edit kind')
    fields = {'file', 'kind', 'sha256', 'backup'} | ({'pointer'} if edit['kind'].startswith('json_') else set())
    require(set(edit) == fields, 'invalid edit fields')
    require(_text(edit['file'], 4096), 'invalid edit file')
    require(edit['backup'] is None or _text(edit['backup'], 4096), 'invalid edit backup')
    require(isinstance(edit['sha256'], str) and SHA_RE.match(edit['sha256']), 'invalid edit fingerprint')
    if 'pointer' in edit:
        require(isinstance(edit['pointer'], str) and edit['pointer'].startswith('/'), 'invalid JSON pointer')


def validate_scope(scope):
    require(isinstance(scope, dict) and set(scope) == {'scope', 'project', 'window_days'}, 'invalid scope')
    require(scope['scope'] in SCOPES, 'invalid scope')
    require(scope['project'] is None or _text(scope['project'], 4096), 'invalid scope project')
    require(type(scope['window_days']) is int and scope['window_days'] > 0, 'invalid window')


def validate_entry(item):
    require(isinstance(item, dict) and set(item) == ENTRY_FIELDS, 'invalid entry fields')
    require(isinstance(item['id'], str) and ID_RE.match(item['id']), 'invalid entry id')
    epoch(item['applied_at'])
    require(_text(item['run'], 120), 'invalid run')
    require(_text(item['finding_id'], 200), 'invalid finding id')
    require(_text(item['pattern'], 200), 'invalid pattern')
    require(item['mechanism'] in MECHANISMS, 'invalid mechanism')
    require(item['state'] in STATES, 'invalid state')
    require(item['supersedes'] is None or (isinstance(item['supersedes'], str) and ID_RE.match(item['supersedes'])),
            'invalid supersedes')
    validate_selector(item['selector'])
    validate_scope(item['scope'])
    metric = item['selector']['type'] == 'metric'
    validate_counts(item['baseline'], metric)
    require(isinstance(item['edits'], list) and item['edits'], 'entry needs edits')
    for edit in item['edits']:
        validate_edit(edit)
    require(isinstance(item['observations'], list), 'invalid observations')
    for obs in item['observations']:
        validate_counts(obs, metric, OBSERVATION_EXTRA)
        require(_text(obs['run'], 120) and obs['verdict'] in report_state.LEDGER_VERDICTS
                and _text(obs['reason'], 60), 'invalid observation')


def validate(book):
    require(isinstance(book, dict) and set(book) == {'version', 'entries'}, 'invalid ledger fields')
    require(book['version'] == VERSION, 'unsupported ledger version')
    require(isinstance(book['entries'], list), 'invalid ledger entries')
    seen = set()
    for item in book['entries']:
        validate_entry(item)
        require(item['id'] not in seen, 'duplicate entry id')
        seen.add(item['id'])
    return book


def loads(text, input='ledger'):
    try:
        return validate(report_state.load_json(text))
    except LedgerError as exc:
        exc.input = input
        raise
    except report_state.ReportError as exc:
        raise LedgerError(exc.message, input=input, line=exc.line) from None


def load(path):
    require(not os.path.islink(path), 'ledger must not be a symlink')
    if not os.path.exists(path):
        return empty()
    with open(path, encoding='utf-8') as stream:
        text = stream.read(8 * 1024 * 1024 + 1)
    require(len(text) <= 8 * 1024 * 1024, 'ledger too large')
    return loads(text)


def dump(book, path):
    validate(book)
    require(not os.path.islink(path), 'ledger must not be a symlink')
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    text = json.dumps(book, indent=2, ensure_ascii=True, allow_nan=False) + '\n'
    safe_write.atomic_write(path, text, prefix='.ledger.')
    os.chmod(path, 0o600)


def next_id(book, day):
    stem = 'L-%s-' % day.strftime('%Y%m%d')
    used = [int(e['id'][len(stem):]) for e in book['entries'] if e['id'].startswith(stem)]
    return stem + str(max(used, default=0) + 1)


def _rate(counts):
    return counts['sessions_matched'] / counts['sessions_scanned']


def verdict(entry, current, scope, previous):
    """Classify one entry for this run. `current` carries `selector_sha`; `previous` is the latest
    observation from another run (or None). Returns (verdict, reason code)."""
    if (current is None or scope != entry['scope']
            or current.get('selector_sha') != selector_hash(entry['selector'])):
        return 'unknown', 'incomparable'
    base = entry['baseline']
    if not (base['complete'] and current['complete']):
        return 'unknown', 'incomplete'
    if entry['selector']['type'] == 'metric':
        if epoch(current['from']) < epoch(entry['applied_at']):
            return 'too_early', 'window_overlaps_fix'
        if base['value'] is None or current['value'] is None:
            return 'unknown', 'incomparable'
        if current['value'] <= 0.5 * base['value']:
            return 'dropped', 'rate_at_or_below_half'
        return 'not_dropped', 'rate_above_half'
    if base['sessions_scanned'] == 0:
        return 'unknown', 'no_baseline'
    if base['sessions_matched'] < MIN_BASELINE:
        return 'too_early', 'weak_baseline'
    if current['sessions_scanned'] < MIN_SESSIONS:
        return 'too_early', 'few_sessions'
    days = (epoch(current['to']) - epoch(entry['applied_at'])) / 86400
    if (current['matches'] == 0 and previous is not None and previous.get('matches') == 0
            and previous['verdict'] not in ('unknown', 'too_early') and days >= QUIET_DAYS):
        return 'quiet', 'quiet'
    if _rate(current) <= 0.5 * _rate(base):
        return 'dropped', 'rate_at_or_below_half'
    return 'not_dropped', 'rate_above_half'


def next_rung(entry):
    if entry['mechanism'] not in LADDER[:-1]:
        return None
    return LADDER[LADDER.index(entry['mechanism']) + 1]


def proposal(entry, verdict_now, previous):
    if verdict_now == 'quiet' and entry['mechanism'] in ('memory', 'rule'):
        return 'retire'
    if (verdict_now == 'not_dropped' and previous is not None and previous['verdict'] == 'not_dropped'
            and next_rung(entry) is not None):
        return 'escalate'
    return None
```

Note: `copy` is imported for Task 6 (`evaluate`); if a linter flags it before then, add it in Task 6 instead.

- [ ] **Step 5: Run tests**

Run: `cd tests && python3 -m unittest test_ledger -v`
Expected: PASS (all `Format`, `Verdicts`, `Proposals` tests).

- [ ] **Step 6: Red proof**

Change `if _rate(current) <= 0.5 * _rate(base)` to `<` and rerun; `test_dropped_boundary_and_not_dropped` must FAIL. Change `days >= QUIET_DAYS` to `days >= 0`; `test_quiet_needs_two_zero_observations_and_thirty_days` must FAIL. Revert both.

- [ ] **Step 7: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/ledger.py plugins/setup-audit/skills/setup-audit/scripts/report_state.py tests/test_ledger.py
git commit -m "Add learning ledger format, validation and verdict rules

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 3: Selector counting and `ledger_signals` in the collector

**Files:**
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/collect.py` (new functions after `collect_corrections` ~line 1262; `main()` argparse ~1268 and `snap` dict ~1302)
- Modify: `plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json` (top-level `properties`)
- Modify: `plugins/setup-audit/skills/setup-audit/references/snapshot-format.md`
- Test: `tests/test_collect.py` (new class `LedgerCounting(FakeHome)`)

**Interfaces:**
- Consumes: `ledger.load`, `ledger.LedgerError`, `ledger.iso`, `ledger.epoch`, `ledger.selector_hash` (Task 2); existing `collect.CORRECTION_RE`, `collect._dated`, `collect.load_json`, `collect.CLAUDE`.
- Produces:
  - `collect.count_selector(selector: dict, since: float, until: float, project_filter=None) -> {"matches", "sessions_matched", "sessions_scanned", "complete"}` (epoch-second inclusive bounds; raises `ValueError` for `metric` selectors).
  - `collect.collect_ledger_signals(path: str, days: int, project_filter) -> {"status": "collected"|"invalid", "entries": {id: counts + from, to, selector_sha}}`.
  - CLI flag `collect.py --ledger PATH`; snapshot key `ledger_signals` only when the flag is given.

Counting rules (from the spec):
- `keywords`/`corrections`: `history.jsonl` rows with numeric `timestamp` (ms) inside bounds and in `project_filter`; `sessions_scanned` = distinct `sessionId` of all such rows; a match is a row whose stripped `display` matches `CORRECTION_RE` and contains any keyword (case-insensitive substring); `matches` = matching rows. Missing file, a malformed line, a non-numeric timestamp, or a row without `sessionId` → `complete: False` (rows without a session id still count, each as its own session).
- `friction_details` / `friction_category`: facets joined to session-meta by unique `session_id` (ambiguous duplicate → unattributable); start time via `_dated`; in bounds and in scope. Unattributable or undated facets, or no facets at all → `complete: False`. `friction_details` match = any keyword in `friction_detail`; `friction_category` matches = positive int `friction_counts[name]`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_collect.py`)

```python
class LedgerCounting(FakeHome):
    NOW = 1_790_000_000  # fixed epoch seconds

    def history(self, rows):
        self.write(".claude/history.jsonl", "".join(json.dumps(r) + "\n" for r in rows))

    def row(self, text, offset, sid="s1", project="/a"):
        return {"display": text, "timestamp": (self.NOW + offset) * 1000, "project": project, "sessionId": sid}

    def test_corrections_keywords_count_sessions_after_cutoff_only(self):
        sel = {"type": "keywords", "source": "corrections", "any": ["Run The Tests"]}
        self.history([
            self.row("no, run the tests first", -10, "s1"),
            self.row("no, run the tests again", -9, "s1"),
            self.row("wrong, you forgot to run the tests", -8, "s2"),
            self.row("please run the tests", -7, "s3"),        # not a correction
            self.row("no, run the tests", -500, "s4"),          # before `since`
            self.row("no, run the tests", -5, "s5", "/b"),      # out of scope
        ])
        c = collect.count_selector(sel, self.NOW - 100, self.NOW, {"/a"})
        self.assertEqual(c, {"matches": 3, "sessions_matched": 2, "sessions_scanned": 3, "complete": True})

    def test_missing_session_id_or_bad_line_marks_incomplete(self):
        sel = {"type": "keywords", "source": "corrections", "any": ["tests"]}
        self.write(".claude/history.jsonl", json.dumps({"display": "no tests", "timestamp": self.NOW * 1000,
                                                        "project": "/a"}) + "\n{broken\n")
        c = collect.count_selector(sel, self.NOW - 100, self.NOW, None)
        self.assertFalse(c["complete"])
        self.assertEqual((c["matches"], c["sessions_scanned"]), (1, 1))

    def test_absent_history_is_incomplete(self):
        sel = {"type": "keywords", "source": "corrections", "any": ["tests"]}
        c = collect.count_selector(sel, 0, self.NOW, None)
        self.assertEqual(c, {"matches": 0, "sessions_matched": 0, "sessions_scanned": 0, "complete": False})

    def facet(self, sid, offset, project="/a", **fields):
        start = datetime.fromtimestamp(self.NOW + offset, timezone.utc).isoformat()
        self.write(f".claude/usage-data/session-meta/{sid}.json",
                   {"session_id": sid, "start_time": start, "project_path": project})
        self.write(f".claude/usage-data/facets/{sid}.json", dict(session_id=sid, **fields))

    def test_friction_category_and_details(self):
        self.facet("a", -10, friction_counts={"buggy_code": 2}, friction_detail="Forgot to RUN tests")
        self.facet("b", -9, friction_counts={"wrong_approach": 1}, friction_detail="other")
        self.facet("c", -900, friction_counts={"buggy_code": 5})  # before since
        cat = collect.count_selector({"type": "friction_category", "name": "buggy_code"},
                                     self.NOW - 100, self.NOW, None)
        self.assertEqual(cat, {"matches": 2, "sessions_matched": 1, "sessions_scanned": 2, "complete": True})
        det = collect.count_selector({"type": "keywords", "source": "friction_details", "any": ["run tests"]},
                                     self.NOW - 100, self.NOW, None)
        self.assertEqual(det, {"matches": 1, "sessions_matched": 1, "sessions_scanned": 2, "complete": True})

    def test_orphan_facet_marks_incomplete(self):
        self.facet("a", -10, friction_counts={"buggy_code": 1})
        self.write(".claude/usage-data/facets/orphan.json", {"session_id": "nope", "friction_counts": {"buggy_code": 1}})
        c = collect.count_selector({"type": "friction_category", "name": "buggy_code"}, self.NOW - 100, self.NOW, None)
        self.assertFalse(c["complete"])
        self.assertEqual(c["matches"], 1)

    def ledger_file(self, applied_at, state="active"):
        import ledger
        sel = {"type": "keywords", "source": "corrections", "any": ["tests"]}
        entry = dict(id="L-20260901-1", applied_at=applied_at, run="r", finding_id="LRN-x", pattern="p",
                     mechanism="rule", state=state, supersedes=None, selector=sel,
                     scope=dict(scope="all", project=None, window_days=30),
                     baseline={"from": "2026-08-01T00:00:00Z", "to": "2026-09-01T00:00:00Z", "matches": 3,
                               "sessions_matched": 3, "sessions_scanned": 9, "complete": True},
                     edits=[dict(file="~/x.md", kind="markdown_block", sha256="a" * 64, backup=None)],
                     observations=[])
        path = os.path.join(self.claude, "audits", "ledger.json")
        ledger.dump(dict(version=1, entries=[entry]), path)
        return path, ledger.selector_hash(sel)

    def test_signals_count_only_after_applied_at(self):
        import ledger
        self.history([self.row("no tests", -50, "s1"), self.row("no tests", -5, "s2")])
        path, sha = self.ledger_file(ledger.iso(self.NOW - 20))
        with mock.patch.object(collect.time, "time", return_value=self.NOW):
            out = collect.collect_ledger_signals(path, 30, None)
        self.assertEqual(out["status"], "collected")
        sig = out["entries"]["L-20260901-1"]
        self.assertEqual((sig["matches"], sig["sessions_scanned"]), (1, 1))
        self.assertEqual(sig["from"], ledger.iso(self.NOW - 20))
        self.assertEqual(sig["selector_sha"], sha)

    def test_future_applied_at_counts_nothing(self):
        import ledger
        self.history([self.row("no tests", -5, "s1")])
        path, _ = self.ledger_file(ledger.iso(self.NOW + 3600))
        with mock.patch.object(collect.time, "time", return_value=self.NOW):
            sig = collect.collect_ledger_signals(path, 30, None)["entries"]["L-20260901-1"]
        self.assertEqual((sig["matches"], sig["sessions_scanned"]), (0, 0))

    def test_inactive_entries_skipped_and_invalid_ledger_reported(self):
        import ledger
        path, _ = self.ledger_file(ledger.iso(self.NOW - 20), state="removed")
        self.assertEqual(collect.collect_ledger_signals(path, 30, None)["entries"], {})
        with open(path, "w") as f:
            f.write('{"version": 1}')
        self.assertEqual(collect.collect_ledger_signals(path, 30, None), {"status": "invalid", "entries": {}})
```

Add `from datetime import datetime, timezone` to the test module imports if not already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tests && python3 -m unittest test_collect.LedgerCounting -v`
Expected: FAIL with `AttributeError: module 'collect' has no attribute 'count_selector'`

- [ ] **Step 3: Implement counting in `collect.py`** (after `collect_corrections`)

```python
def _history_rows(since, until, project_filter, counts):
    """Yield (session_id or None, prompt) for in-bounds, in-scope history rows."""
    path = os.path.join(CLAUDE, "history.jsonl")
    if not os.path.exists(path):
        counts["complete"] = False
        return
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                d = json.loads(line)
            except ValueError:
                counts["complete"] = False
                continue
            ts = d.get("timestamp") if isinstance(d, dict) else None
            if type(ts) not in (int, float):
                counts["complete"] = False
                continue
            if not since <= ts / 1000 <= until:
                continue
            if project_filter is not None and os.path.expanduser(d.get("project") or "") not in project_filter:
                continue
            sid = d.get("sessionId")
            if not isinstance(sid, str) or not sid:
                counts["complete"] = False
                sid = None
            text = d.get("display")
            yield sid, (text if isinstance(text, str) else "").strip()


def _facet_rows(since, until, project_filter, counts):
    """Yield (session_id, facet) for facets joined to in-bounds, in-scope session metadata."""
    index = {}
    for f in sorted(glob.glob(os.path.join(CLAUDE, "usage-data", "session-meta", "*.json"))):
        m = load_json(f)
        sid = m.get("session_id") if isinstance(m, dict) else None
        if isinstance(sid, str) and sid:
            index[sid] = m if sid not in index else None
    facets = sorted(glob.glob(os.path.join(CLAUDE, "usage-data", "facets", "*.json")))
    if not facets:
        counts["complete"] = False
    for f in facets:
        d = load_json(f)
        sid = d.get("session_id") if isinstance(d, dict) else None
        m = index.get(sid) if isinstance(sid, str) else None
        stamp = _dated(m.get("start_time")) if m else None
        if stamp is None:
            counts["complete"] = False
            continue
        if not since <= stamp <= until:
            continue
        if project_filter is not None and os.path.expanduser(m.get("project_path") or "") not in project_filter:
            continue
        yield sid, d


def _positive(value):
    return value if type(value) is int and value > 0 else 0


def count_selector(selector, since, until, project_filter=None):
    """Count one ledger selector between epoch-second bounds (inclusive). Counts only, never text."""
    counts = dict(matches=0, sessions_matched=0, sessions_scanned=0, complete=True)
    kind = selector["type"]
    words = [w.lower() for w in selector.get("any", [])]
    if kind == "keywords" and selector["source"] == "corrections":
        rows = ((sid, int(bool(CORRECTION_RE.search(text)) and any(w in text.lower() for w in words)))
                for sid, text in _history_rows(since, until, project_filter, counts))
    elif kind == "keywords":
        rows = ((sid, int(any(w in str(d.get("friction_detail") or "").lower() for w in words)))
                for sid, d in _facet_rows(since, until, project_filter, counts))
    elif kind == "friction_category":
        rows = ((sid, _positive((d.get("friction_counts") or {}).get(selector["name"])))
                for sid, d in _facet_rows(since, until, project_filter, counts))
    else:
        raise ValueError("metric selectors are not counted from raw sources")
    scanned, matched = set(), set()
    for sid, n in rows:
        key = sid if sid is not None else object()
        scanned.add(key)
        if n:
            counts["matches"] += n
            matched.add(key)
    counts["sessions_scanned"], counts["sessions_matched"] = len(scanned), len(matched)
    return counts


def collect_ledger_signals(path, days, project_filter):
    """Post-fix counts for each active, non-metric ledger entry. Read-only."""
    import ledger  # lazy: ledger's CLI imports collect
    try:
        book = ledger.load(path)
    except (ledger.LedgerError, OSError, UnicodeDecodeError):
        return {"status": "invalid", "entries": {}}
    now = time.time()
    entries = {}
    for entry in book["entries"]:
        if entry["state"] != "active" or entry["selector"]["type"] == "metric":
            continue
        since = max(now - days * 86400, ledger.epoch(entry["applied_at"]))
        counts = count_selector(entry["selector"], since, now, project_filter)
        counts.update({"from": ledger.iso(since), "to": ledger.iso(now),
                       "selector_sha": ledger.selector_hash(entry["selector"])})
        entries[entry["id"]] = counts
    return {"status": "collected", "entries": entries}
```

When `since > now` (future `applied_at`), every row falls outside the bounds, so counts are zero.

- [ ] **Step 4: Wire the CLI flag**

In `main()` add:

```python
    ap.add_argument("--ledger", help="learning ledger to count active entries against (read-only)")
```

After the `snap = {...}` dict literal:

```python
    if a.ledger:
        snap["ledger_signals"] = collect_ledger_signals(
            os.path.abspath(os.path.expanduser(a.ledger)), a.days, project_filter)
```

- [ ] **Step 5: Add the schema property** (top-level `properties` in `snapshot.schema.json`, next to `instruction_clarity`)

```json
    "ledger_signals": {
      "type": "object",
      "required": ["status", "entries"],
      "properties": {
        "status": {"enum": ["collected", "invalid"]},
        "entries": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "required": ["from", "to", "matches", "sessions_matched", "sessions_scanned", "complete", "selector_sha"],
            "properties": {
              "from": {"type": "string"},
              "to": {"type": "string"},
              "matches": {"type": "integer", "minimum": 0},
              "sessions_matched": {"type": "integer", "minimum": 0},
              "sessions_scanned": {"type": "integer", "minimum": 0},
              "complete": {"type": "boolean"},
              "selector_sha": {"type": "string"}
            }
          }
        }
      }
    },
```

Add a test to `tests/test_snapshot_contract.py` that a snapshot with a valid `ledger_signals` passes `validate_snapshot` and one with `"status": "other"` fails (follow that file's existing fixture helper `self.snapshot()`):

```python
    def test_ledger_signals_are_optional_and_checked(self):
        snap = self.snapshot()
        snap["ledger_signals"] = {"status": "collected", "entries": {"L-20260901-1": {
            "from": "2026-09-01T00:00:00Z", "to": "2026-09-28T00:00:00Z", "matches": 1,
            "sessions_matched": 1, "sessions_scanned": 5, "complete": True, "selector_sha": "a" * 64}}}
        contract.validate_snapshot(snap)
        snap["ledger_signals"]["status"] = "other"
        with self.assertRaises(ValueError):
            contract.validate_snapshot(snap)
```

(Check the exception type `validate_snapshot` raises in that file and use it.)

- [ ] **Step 6: Document** in `references/snapshot-format.md` under the optional fields: "`ledger_signals` (only with `--ledger`): `status` `collected`/`invalid`, and per active non-metric entry post-fix `matches`, `sessions_matched`, `sessions_scanned`, `complete`, `from`, `to`, `selector_sha`. Counts only; additive within snapshot v1."

- [ ] **Step 7: Run tests**

Run: `python3 -m unittest discover -s tests -v` and, if `jsonschema` is installed, `python3 tests/check_snapshot_schema.py -v`
Expected: PASS.

- [ ] **Step 8: Red proof**

Replace `since = max(now - days * 86400, ...)` with `since = now - days * 86400`; `test_signals_count_only_after_applied_at` must FAIL. Remove `counts["complete"] = False` in the orphan-facet branch; `test_orphan_facet_marks_incomplete` must FAIL. Revert.

- [ ] **Step 9: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json plugins/setup-audit/skills/setup-audit/references/snapshot-format.md tests/test_collect.py tests/test_snapshot_contract.py
git commit -m "Count learning-ledger selectors in the collector

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 4: `ledger.py next-id` and `record`

**Files:**
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/ledger.py`
- Test: `tests/test_ledger.py` (new class `Record`)

**Interfaces:**
- Consumes: Task 2 core; `collect.count_selector`, `collect.redact`, `collect.CLAUDE`, `collect.HOME`; `report_state.validate_report`, `report_state.metric_coverage`, `report_state.timestamp`.
- Produces:
  - `ledger.begin_marker(entry_id) -> str` = `"<!-- setup-audit:begin %s -->"`; `ledger.end_marker(entry_id)`; `ledger.hook_marker(entry_id) = "# setup-audit: %s"`.
  - `ledger.find_block(text: str, entry_id: str) -> (begin_index, end_index) | None` over `text.splitlines(keepends=True)`; raises `LedgerError('markers are ambiguous', input='edited file')` for duplicate or out-of-order markers.
  - `ledger.block_hash(text, entry_id) -> str` (sha256 of `''.join(lines[b+1:e]).encode()`).
  - `ledger.pointer_parts(pointer) -> list[str]`, `ledger.resolve(doc, parts)` (raises `LedgerError('JSON pointer not found', input='edited file')`).
  - `ledger.snapshot_scope(snapshot) -> (scope_dict, project_filter)`.
  - `ledger.record(book, spec, snapshot, report, run, now: float) -> dict` (returns the new ledger; pure apart from reading edited files and counting sources).
  - CLI: `ledger.py next-id --ledger L`; `ledger.py record --ledger L --snapshot S --report R --spec SPEC [--claude-dir D]`.

Spec (model-written JSON file) fields: `id`, `finding_id`, `pattern`, `mechanism`, `selector`, `edits` (list of `{file, kind, backup, pointer?}`), optional `supersedes`. For `json_array_append`, `pointer` names the appended **element** (e.g. `/permissions/deny/3`); the ledger stores the parent array pointer and the element fingerprint. For `json_set`, `pointer` names the value.

- [ ] **Step 1: Write the failing tests**

```python
import subprocess
import sys

SCRIPT = os.path.join(SCRIPTS, "ledger.py")


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
        with mock.patch("collect.count_selector", return_value=dict(matches=0, sessions_matched=0,
                                                                     sessions_scanned=0, complete=True)):
            book = ledger.record(ledger.empty(), spec, self.snapshot, self.report, "r", 1_790_000_000)
        edit = book["entries"][0]["edits"][0]
        self.assertEqual(edit["pointer"], "/permissions/deny")
        self.assertEqual(edit["sha256"], ledger.fingerprint("Bash(rm -rf *)"))
        self.assertNotIn("rm -rf", json.dumps(book))

    def test_unknown_finding_duplicate_id_and_bad_supersedes_refused(self):
        with mock.patch("collect.count_selector", return_value=dict(matches=0, sessions_matched=0,
                                                                     sessions_scanned=0, complete=True)):
            with self.assertRaises(ledger.LedgerError):
                ledger.record(ledger.empty(), self.spec(finding_id="LRN-other"), self.snapshot, self.report, "r", 1_790_000_000)
            book = ledger.record(ledger.empty(), self.spec(), self.snapshot, self.report, "r", 1_790_000_000)
            with self.assertRaises(ledger.LedgerError):
                ledger.record(book, self.spec(), self.snapshot, self.report, "r", 1_790_000_000)
            with self.assertRaises(ledger.LedgerError):
                ledger.record(book, self.spec(id="L-20260928-2", supersedes="L-20260101-1"),
                              self.snapshot, self.report, "r", 1_790_000_000)

    def test_supersedes_marks_old_entry(self):
        with mock.patch("collect.count_selector", return_value=dict(matches=0, sessions_matched=0,
                                                                     sessions_scanned=0, complete=True)):
            book = ledger.record(ledger.empty(), self.spec(), self.snapshot, self.report, "r", 1_790_000_000)
            hook = self.put(".claude/hooks/check-tests.sh", "#!/bin/sh\n# setup-audit: L-20260928-2\nexit 0\n")
            book = ledger.record(book, self.spec(id="L-20260928-2", mechanism="hook", supersedes="L-20260928-1",
                                                 edits=[dict(file=hook, kind="hook_script", backup=None)]),
                                 self.snapshot, self.report, "r", 1_790_000_000)
        self.assertEqual([e["state"] for e in book["entries"]], ["superseded", "active"])

    def test_pattern_and_keywords_are_redacted(self):
        secret = "ghp_" + "a" * 36
        with mock.patch("collect.count_selector", return_value=dict(matches=0, sessions_matched=0,
                                                                     sessions_scanned=0, complete=True)):
            book = ledger.record(ledger.empty(), self.spec(pattern="leaks " + secret,
                                                           selector=dict(KW, any=[secret])),
                                 self.snapshot, self.report, "r", 1_790_000_000)
        self.assertNotIn(secret, json.dumps(book))

    def test_metric_baseline_from_report(self):
        sel = dict(type="metric", name="corrections_count_30d", basis="measured", unit="prompts", source="corrections.count")
        report = dict(self.report, window_days=30, metrics={"corrections_count_30d": dict(
            value=12, basis="measured", unit="prompts", source="corrections.count")},
            coverage=dict(sources=[dict(source="corrections", status="collected", omitted=0)]))
        book = ledger.record(ledger.empty(), self.spec(selector=sel), self.snapshot, report, "r", 1_790_000_000)
        self.assertEqual(book["entries"][0]["baseline"]["value"], 12)
        self.assertTrue(book["entries"][0]["baseline"]["complete"])

    def test_cli_next_id_and_record_write_private_ledger(self):
        path = os.path.join(self.home, "audits", "ledger.json")
        out = subprocess.run([sys.executable, SCRIPT, "next-id", "--ledger", path],
                             capture_output=True, text=True, check=True).stdout.strip()
        self.assertRegex(out, r"^L-\d{8}-1$")
        files = {}
        for name, data in (("snap.json", self.snapshot), ("report.json", self.report),
                           ("spec.json", self.spec(id=out, edits=[dict(file=self.settings, kind="json_set",
                                                                       pointer="/permissions/deny", backup=None)]))):
            files[name] = self.put(name, json.dumps(data))
        env = dict(os.environ, HOME=self.home)
        run = subprocess.run([sys.executable, SCRIPT, "record", "--ledger", path, "--snapshot", files["snap.json"],
                              "--report", files["report.json"], "--spec", files["spec.json"],
                              "--claude-dir", self.claude], capture_output=True, text=True, env=env)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(ledger.load(path)["entries"][0]["id"], out)

    def test_cli_errors_name_input_and_leave_ledger_unchanged(self):
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(ledger.empty(), path)
        before = open(path).read()
        bad = self.put("spec.json", '{"id": "sk-SECRET-VALUE"}')
        snap = self.put("snap.json", json.dumps(self.snapshot))
        rep = self.put("report.json", json.dumps(self.report))
        run = subprocess.run([sys.executable, SCRIPT, "record", "--ledger", path, "--snapshot", snap,
                              "--report", rep, "--spec", bad, "--claude-dir", self.claude],
                             capture_output=True, text=True, env=dict(os.environ, HOME=self.home))
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("entry spec", run.stderr)
        self.assertNotIn("SECRET", run.stderr)
        self.assertEqual(open(path).read(), before)
```

Add `import hashlib` and `from unittest import mock` to the test module, and `from test_collect import SCRIPTS`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tests && python3 -m unittest test_ledger.Record -v`
Expected: FAIL with `AttributeError: module 'ledger' has no attribute 'record'`

- [ ] **Step 3: Implement record helpers in `ledger.py`**

```python
import argparse
import time
from pathlib import Path

SPEC_FIELDS = {'id', 'finding_id', 'pattern', 'mechanism', 'selector', 'edits'}
LABELS = {'ledger': 'ledger', 'snapshot': 'snapshot', 'report': 'current report',
          'spec': 'entry spec', 'edited file': 'edited file', 'backup': 'backup'}


def begin_marker(entry_id):
    return '<!-- setup-audit:begin %s -->' % entry_id


def end_marker(entry_id):
    return '<!-- setup-audit:end %s -->' % entry_id


def hook_marker(entry_id):
    return '# setup-audit: %s' % entry_id


def find_block(text, entry_id):
    lines = text.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.strip() == begin_marker(entry_id)]
    ends = [i for i, line in enumerate(lines) if line.strip() == end_marker(entry_id)]
    if not begins and not ends:
        return None
    require(len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0], 'markers are ambiguous',
            input='edited file')
    return begins[0], ends[0]


def block_hash(text, entry_id):
    span = find_block(text, entry_id)
    require(span is not None, 'markers not found', input='edited file')
    lines = text.splitlines(keepends=True)
    return hashlib.sha256(''.join(lines[span[0] + 1:span[1]]).encode()).hexdigest()


def pointer_parts(pointer):
    require(isinstance(pointer, str) and pointer.startswith('/'), 'invalid JSON pointer', input='spec')
    return [p.replace('~1', '/').replace('~0', '~') for p in pointer[1:].split('/')]


def pointer_text(parts):
    return '/' + '/'.join(p.replace('~', '~0').replace('/', '~1') for p in parts)


def resolve(doc, parts):
    node = doc
    for part in parts:
        if isinstance(node, list):
            require(part.isdigit() and int(part) < len(node), 'JSON pointer not found', input='edited file')
            node = node[int(part)]
        else:
            require(isinstance(node, dict) and part in node, 'JSON pointer not found', input='edited file')
            node = node[part]
    return node


def read_text(path, input='edited file'):
    require(not os.path.islink(path), 'symlinks are refused', input=input)
    try:
        with open(path, 'rb') as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
    except OSError:
        raise LedgerError('cannot be read', input=input) from None
    require(len(data) <= 8 * 1024 * 1024, 'file too large', input=input)
    return data


def read_json(path, input='edited file'):
    try:
        return report_state.load_json(read_text(path, input).decode('utf-8'))
    except (report_state.ReportError, UnicodeDecodeError) as exc:
        raise LedgerError('invalid JSON', input=input, line=getattr(exc, 'line', None)) from None


def tilde(path, home):
    return '~' + path[len(home):] if path == home or path.startswith(home + os.sep) else path


def fingerprint_edit(entry_id, edit, home):
    require(isinstance(edit, dict) and edit.get('kind') in KINDS, 'invalid edit kind', input='spec')
    json_kind = edit['kind'].startswith('json_')
    require(set(edit) == {'file', 'kind', 'backup'} | ({'pointer'} if json_kind else set()),
            'invalid edit fields', input='spec')
    require(_text(edit['file'], 4096), 'invalid edit file', input='spec')
    require(edit['backup'] is None or _text(edit['backup'], 4096), 'invalid edit backup', input='spec')
    path = os.path.abspath(os.path.expanduser(edit['file']))
    if edit['backup'] is not None:
        require(os.path.exists(os.path.expanduser(edit['backup'])), 'backup not found', input='backup')
    out = dict(file=tilde(path, home), kind=edit['kind'],
               backup=None if edit['backup'] is None else tilde(os.path.abspath(os.path.expanduser(edit['backup'])), home))
    if edit['kind'] == 'markdown_block':
        out['sha256'] = block_hash(read_text(path).decode('utf-8', 'replace'), entry_id)
    elif edit['kind'] == 'hook_script':
        data = read_text(path)
        head = data.decode('utf-8', 'replace').splitlines()[:5]
        require(any(line.strip() == hook_marker(entry_id) for line in head), 'hook marker not found',
                input='edited file')
        out['sha256'] = hashlib.sha256(data).hexdigest()
    else:
        parts = pointer_parts(edit['pointer'])
        value = resolve(read_json(path), parts)
        if edit['kind'] == 'json_array_append':
            require(parts and parts[-1].isdigit(), 'pointer must name the appended element', input='spec')
            require(isinstance(resolve(read_json(path), parts[:-1]), list), 'pointer parent must be an array',
                    input='edited file')
            parts = parts[:-1]
        out['pointer'] = pointer_text(parts)
        out['sha256'] = fingerprint(value)
    return out


def snapshot_scope(snapshot):
    try:
        cs = snapshot['collection_scope']
        scope = dict(scope=cs['requested'], project=cs.get('project'), window_days=snapshot['window_days'])
        validate_scope(scope)
    except (KeyError, TypeError, LedgerError):
        raise LedgerError('snapshot scope is missing', input='snapshot') from None
    if scope['scope'] == 'all':
        return scope, None
    if scope['scope'] == 'global':
        return scope, set()
    return scope, {os.path.abspath(os.path.expanduser(scope['project']))}


def metric_baseline(selector, report, start, end):
    metric = (report.get('metrics') or {}).get(selector['name'])
    labels = all(isinstance(metric, dict) and metric.get(k) == selector[k] for k in ('basis', 'unit', 'source'))
    value = metric.get('value') if labels else None
    return {'from': iso(start), 'to': iso(end),
            'value': value if report_state.finite(value) else None,
            'complete': bool(labels and report_state.metric_coverage(report, metric))}


def record(book, spec, snapshot, report, run, now):
    import collect  # lazy: collect imports ledger lazily too
    book = copy.deepcopy(validate(book))
    require(isinstance(spec, dict) and SPEC_FIELDS <= set(spec) <= SPEC_FIELDS | {'supersedes'},
            'invalid spec fields', input='spec')
    require(isinstance(spec['id'], str) and ID_RE.match(spec['id']), 'invalid entry id', input='spec')
    ids = {e['id']: e for e in book['entries']}
    require(spec['id'] not in ids, 'entry id already used', input='spec')
    findings = {f.get('id') for f in report.get('findings', []) if isinstance(f, dict)}
    require(spec['finding_id'] in findings, 'finding not in current report', input='spec')
    supersedes = spec.get('supersedes')
    if supersedes is not None:
        require(supersedes in ids and ids[supersedes]['state'] == 'active', 'superseded entry not active',
                input='spec')
    require(_text(spec['pattern'], 200), 'invalid pattern', input='spec')
    try:
        validate_selector(spec['selector'])
    except LedgerError as exc:
        exc.input = 'spec'
        raise
    require(spec['mechanism'] in MECHANISMS, 'invalid mechanism', input='spec')
    require(isinstance(spec['edits'], list) and spec['edits'], 'entry needs edits', input='spec')
    selector = copy.deepcopy(spec['selector'])
    if selector['type'] == 'keywords':
        selector['any'] = [collect.redact(w) for w in selector['any']]
    scope, project_filter = snapshot_scope(snapshot)
    start = now - scope['window_days'] * 86400
    if selector['type'] == 'metric':
        baseline = metric_baseline(selector, report, start, now)
    else:
        baseline = collect.count_selector(selector, start, now, project_filter)
        baseline.update({'from': iso(start), 'to': iso(now)})
    entry = dict(id=spec['id'], applied_at=iso(now), run=run, finding_id=spec['finding_id'],
                 pattern=collect.redact(spec['pattern'])[:200], mechanism=spec['mechanism'], state='active',
                 supersedes=supersedes, selector=selector, scope=scope, baseline=baseline,
                 edits=[fingerprint_edit(spec['id'], e, collect.HOME) for e in spec['edits']], observations=[])
    if supersedes is not None:
        ids[supersedes]['state'] = 'superseded'
    book['entries'].append(entry)
    return validate(book)
```

- [ ] **Step 4: Implement the CLI** (bottom of `ledger.py`; `remove` subcommand is added in Task 5)

```python
def fail(parser, exc):
    what = LABELS.get(getattr(exc, 'input', None), 'input')
    where = ' (line %d)' % exc.line if getattr(exc, 'line', None) else ''
    detail = exc.message if isinstance(exc, report_state.ReportError) else 'cannot be read or written'
    parser.exit(1, 'Ledger update failed. The %s%s: %s. Nothing was changed.\n' % (what, where, detail))


def read_input(path, input):
    try:
        return report_state.load_json(read_text(path, input).decode('utf-8'))
    except report_state.ReportError as exc:
        raise LedgerError(exc.message, input=input, line=exc.line) from None
    except UnicodeDecodeError:
        raise LedgerError('invalid text encoding', input=input) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('next-id', help='print the next free entry id for today')
    p.add_argument('--ledger', required=True)
    p = sub.add_parser('record', help='append an entry for an applied, verified learning fix')
    for flag in ('--ledger', '--snapshot', '--report', '--spec'):
        p.add_argument(flag, required=True)
    p.add_argument('--claude-dir', help='Claude Code config directory (default: $CLAUDE_CONFIG_DIR, else ~/.claude)')
    args = parser.parse_args(argv)
    try:
        book = load(args.ledger)
        if args.command == 'next-id':
            print(next_id(book, datetime.now(timezone.utc).date()))
            return
        import collect
        if args.claude_dir:
            collect.CLAUDE = os.path.abspath(os.path.expanduser(args.claude_dir))
        snapshot = read_input(args.snapshot, 'snapshot')
        report = read_input(args.report, 'report')
        spec = read_input(args.spec, 'spec')
        book = record(book, spec, snapshot, report, Path(args.report).stem, time.time())
        dump(book, args.ledger)
        entry = book['entries'][-1]
        print(json.dumps({'recorded': entry['id'], 'baseline': entry['baseline']}, indent=2))
    except report_state.ReportError as exc:
        fail(parser, exc)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        fail(parser, LedgerError('cannot be processed', input=getattr(exc, 'input', None) or 'ledger'))


if __name__ == '__main__':
    main()
```

- [ ] **Step 5: Run tests**

Run: `cd tests && python3 -m unittest test_ledger -v`
Expected: PASS.

- [ ] **Step 6: Red proof**

Make `find_block` accept duplicates (`begins[-1]`, drop the `len(...) == 1` checks); `test_markers_missing_or_duplicated_are_refused` must FAIL. Remove the `collect.redact` call on keywords; `test_pattern_and_keywords_are_redacted` must FAIL. Revert.

- [ ] **Step 7: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/ledger.py tests/test_ledger.py
git commit -m "Record applied learning fixes with fingerprints and baselines

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 5: `ledger.py remove`

**Files:**
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/ledger.py`
- Test: `tests/test_ledger.py` (new class `Remove`)

**Interfaces:**
- Consumes: Task 4 helpers (`find_block`, `block_hash`, `pointer_parts`, `resolve`, `read_text`, `read_json`, `fingerprint`), `safe_write.open_no_symlink`, `safe_write.identity_of`, `safe_write.backup_from_fd`, `safe_write.atomic_write`, `safe_write.SymlinkRefused`.
- Produces:
  - `ledger.plan_removal(book, entry_ids: list[str]) -> list[dict]` with rows `{entry, file, kind, status, reason}`; `status` ∈ `removable | modified | absent | blocked`.
  - `ledger.apply_removal(book, rows, backup_dir: str, home: str) -> (book, rows)` — rows gain `backup` (new backup path) and `status` becomes `removed` or `blocked` (`changed_since_plan`, `symlink`, `verify_failed`).
  - CLI: `ledger.py remove --ledger L (--entry ID | --all) [--apply --backup-dir D]`; exit 0, or 2 when any row is `blocked`. Output JSON rows; never values.

Rules:
- `--all` selects entries whose `state` is not `removed`.
- Order per entry: `json_*` edits, then `markdown_block`, then `hook_script`.
- `hook_script` whose entry has no `json_array_append` edit → `blocked` / `registration_unrecorded`.
- `json_set` with a non-null `backup` that is missing/unreadable → `blocked` / `backup_missing`; previous value from the backup via the same pointer; pointer absent in backup (or `backup` null) → delete the key.
- `json_array_append`: remove the first element of the parent array whose fingerprint matches; none → `absent`.
- Markdown: delete lines `begin..end` inclusive; hash mismatch → `modified`; markers missing → `absent`; ambiguous → `modified` / `markers_ambiguous`.
- Apply groups rows by file: one backup per file (via `backup_from_fd` on a fresh `open_no_symlink` descriptor whose identity matches the plan), one atomic write (JSON via `json.dumps(doc, indent=2) + "\n"` and `json.loads` check), then re-read and re-plan the rows to verify each is now `absent`; otherwise `verify_failed`.
- Entry becomes `removed` when every one of its rows ends `removed` or `absent`; otherwise it stays as it was.
- Dry run writes nothing (neither user files nor the ledger).

- [ ] **Step 1: Write the failing tests**

```python
class Remove(LedgerFiles):
    def recorded(self, *specs):
        book = ledger.empty()
        with mock.patch("collect.count_selector", return_value=dict(matches=0, sessions_matched=0,
                                                                     sessions_scanned=0, complete=True)):
            for spec in specs:
                book = ledger.record(book, spec, self.snapshot, self.report, "r", 1_790_000_000)
        return book

    def backups(self):
        return os.path.join(self.home, "backups")

    def test_markdown_round_trip_and_dry_run_writes_nothing(self):
        before = "# Rules\n"
        book = self.recorded(self.spec())
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual([r["status"] for r in rows], ["removable"])
        self.assertIn("setup-audit:begin", open(self.md).read())  # plan changed nothing
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(open(self.md).read(), before)
        self.assertEqual(rows[0]["status"], "removed")
        self.assertTrue(os.path.exists(rows[0]["backup"]))
        self.assertEqual(book["entries"][0]["state"], "removed")

    def test_crlf_block_is_modified_not_removed(self):
        book = self.recorded(self.spec())
        with open(self.md, "rb") as f:
            data = f.read()
        with open(self.md, "wb") as f:
            f.write(data.replace(b"\n", b"\r\n"))
        rows = ledger.plan_removal(book, ["L-20260928-1"])
        self.assertEqual((rows[0]["status"], rows[0]["reason"]), ("modified", "hash_mismatch"))
        book, rows = ledger.apply_removal(book, rows, self.backups(), self.home)
        self.assertEqual(open(self.md, "rb").read(), data.replace(b"\n", b"\r\n"))
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
        book, _ = ledger.apply_removal(book, ledger.plan_removal(book, ["L-20260928-1"]), self.backups(), self.home)
        self.assertEqual(open(self.md).read(), "# Rules\n<!-- setup-audit:begin L-20260928-2 -->\nKeep me.\n"
                                               "<!-- setup-audit:end L-20260928-2 -->\n")
        self.assertEqual([e["state"] for e in book["entries"]], ["removed", "active"])

    def test_hook_and_registration_round_trip(self):
        hook = self.put(".claude/hooks/check.sh", "#!/bin/sh\n# setup-audit: L-20260928-1\nexit 0\n")
        group = {"matcher": "Bash", "hooks": [{"type": "command", "command": hook, "timeout": 5}]}
        with open(self.settings, "w") as f:
            json.dump({"permissions": {"deny": ["Bash(rm -rf *)"]}, "hooks": {"PreToolUse": [group]}}, f)
        book = self.recorded(self.spec(mechanism="hook", edits=[
            dict(file=self.settings, kind="json_array_append", pointer="/hooks/PreToolUse/0", backup=None),
            dict(file=hook, kind="hook_script", backup=None)]))
        book, rows = ledger.apply_removal(book, ledger.plan_removal(book, ["L-20260928-1"]), self.backups(), self.home)
        self.assertEqual([r["status"] for r in rows], ["removed", "removed"])
        self.assertFalse(os.path.exists(hook))
        self.assertEqual(json.load(open(self.settings)), {"permissions": {"deny": ["Bash(rm -rf *)"]},
                                                          "hooks": {"PreToolUse": []}})

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
        book, rows = ledger.apply_removal(book, ledger.plan_removal(book, ["L-20260928-1"]), self.backups(), self.home)
        self.assertEqual(json.load(open(self.settings)), {"model": "sonnet", "env": {}})

    def test_json_set_without_backup_deletes_key(self):
        with open(self.settings, "w") as f:
            json.dump({"model": "opus"}, f)
        book = self.recorded(self.spec(mechanism="setting", edits=[
            dict(file=self.settings, kind="json_set", pointer="/model", backup=None)]))
        ledger.apply_removal(book, ledger.plan_removal(book, ["L-20260928-1"]), self.backups(), self.home)
        self.assertEqual(json.load(open(self.settings)), {})

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
        self.assertIn("setup-audit:begin", open(self.md).read())

    def test_cli_dry_run_then_apply(self):
        book = self.recorded(self.spec())
        path = os.path.join(self.home, "audits", "ledger.json")
        ledger.dump(book, path)
        env = dict(os.environ, HOME=self.home)
        dry = subprocess.run([sys.executable, SCRIPT, "remove", "--ledger", path, "--all"],
                             capture_output=True, text=True, env=env)
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertEqual(json.loads(dry.stdout)[0]["status"], "removable")
        self.assertEqual(ledger.load(path), book)
        applied = subprocess.run([sys.executable, SCRIPT, "remove", "--ledger", path, "--all", "--apply",
                                  "--backup-dir", self.backups()], capture_output=True, text=True, env=env)
        self.assertEqual(applied.returncode, 0, applied.stderr)
        self.assertEqual(ledger.load(path)["entries"][0]["state"], "removed")
        self.assertNotIn("Run the tests", applied.stdout)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tests && python3 -m unittest test_ledger.Remove -v`
Expected: FAIL with `AttributeError: module 'ledger' has no attribute 'plan_removal'`

- [ ] **Step 3: Implement planning**

```python
ORDER = {'json_array_append': 0, 'json_set': 0, 'markdown_block': 1, 'hook_script': 2}
_MISSING = object()


def _row(entry, edit, status, reason='', identity=None):
    # _identity is internal (file identity at plan time); callers strip it before printing.
    return dict(entry=entry['id'], file=edit['file'], kind=edit['kind'], status=status, reason=reason,
                _identity=identity)


def _previous_value(edit):
    """Value at the pointer before the edit, or _MISSING. Raises LedgerError when unreadable."""
    if edit['backup'] is None:
        return _MISSING
    backup = os.path.expanduser(edit['backup'])
    require(os.path.isfile(backup), 'backup not found', input='backup')
    try:
        return resolve(read_json(backup, 'backup'), pointer_parts(edit['pointer']))
    except LedgerError as exc:
        if exc.message == 'JSON pointer not found':
            return _MISSING
        raise


def plan_edit(entry, edit):
    path = os.path.expanduser(edit['file'])
    if os.path.islink(path):
        return _row(entry, edit, 'blocked', 'symlink')
    if not os.path.exists(path):
        return _row(entry, edit, 'absent', 'file_missing')
    identity = safe_write.identity_of(os.stat(path))
    kind = edit['kind']

    def row(status, reason=''):
        return row(status, reason, identity)
    try:
        if kind == 'hook_script':
            if not any(e['kind'] == 'json_array_append' for e in entry['edits']):
                return row('blocked', 'registration_unrecorded')
            same = hashlib.sha256(read_text(path)).hexdigest() == edit['sha256']
            return row('removable' if same else 'modified', '' if same else 'hash_mismatch')
        if kind == 'markdown_block':
            text = read_text(path).decode('utf-8', 'replace')
            try:
                span = find_block(text, entry['id'])
            except LedgerError:
                return row('modified', 'markers_ambiguous')
            if span is None:
                return row('absent', 'markers_missing')
            same = block_hash(text, entry['id']) == edit['sha256']
            return row('removable' if same else 'modified', '' if same else 'hash_mismatch')
        doc = read_json(path)
        try:
            node = resolve(doc, pointer_parts(edit['pointer']))
        except LedgerError:
            return row('absent', 'pointer_missing')
        if kind == 'json_array_append':
            if not isinstance(node, list):
                return row('modified', 'not_an_array')
            found = any(fingerprint(x) == edit['sha256'] for x in node)
            return row('removable' if found else 'absent', '' if found else 'value_missing')
        if fingerprint(node) != edit['sha256']:
            return row('modified', 'hash_mismatch')
        try:
            _previous_value(edit)
        except LedgerError:
            return row('blocked', 'backup_missing')
        return row('removable')
    except LedgerError:
        return row('blocked', 'unreadable')


def plan_removal(book, entry_ids):
    index = {e['id']: e for e in book['entries']}
    rows = []
    for entry_id in entry_ids:
        require(entry_id in index, 'entry not found')
        entry = index[entry_id]
        for edit in sorted(entry['edits'], key=lambda e: ORDER[e['kind']]):
            rows.append(plan_edit(entry, edit))
    return rows
```

- [ ] **Step 4: Implement applying**

```python
def _strip_block(text, entry_id):
    begin, end = find_block(text, entry_id)
    lines = text.splitlines(keepends=True)
    return ''.join(lines[:begin] + lines[end + 1:])


def _remove_json(doc, edit):
    parts = pointer_parts(edit['pointer'])
    if edit['kind'] == 'json_array_append':
        array = resolve(doc, parts)
        for i, item in enumerate(array):
            if fingerprint(item) == edit['sha256']:
                del array[i]
                return
        return
    parent = resolve(doc, parts[:-1])
    key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
    previous = _previous_value(edit)
    if previous is _MISSING:
        del parent[key]
    else:
        parent[key] = previous


def _edit_for(book, row):
    entry = next(e for e in book['entries'] if e['id'] == row['entry'])
    edit = next(e for e in entry['edits'] if e['file'] == row['file'] and e['kind'] == row['kind'])
    return entry, edit


def apply_removal(book, rows, backup_dir, home):
    book = copy.deepcopy(book)
    rows = [dict(r) for r in rows]
    by_file = {}
    for row in rows:
        if row['status'] == 'removable':
            by_file.setdefault(row['file'], []).append(row)
    for file, group in by_file.items():
        path = os.path.expanduser(file)
        planned = [plan_edit(*_edit_for(book, r)) for r in group]
        if any(p['status'] != 'removable' for p in planned):
            for r in group:
                r.update(status='blocked', reason='changed_since_plan')
            continue
        try:
            fd, st = safe_write.open_no_symlink(path)
        except safe_write.SymlinkRefused:
            for r in group:
                r.update(status='blocked', reason='symlink')
            continue
        if any(safe_write.identity_of(st) != r['_identity'] for r in group):
            os.close(fd)
            for r in group:
                r.update(status='blocked', reason='changed_since_plan')
            continue
        try:
            before = os.read(fd, 8 * 1024 * 1024 + 1)
            os.lseek(fd, 0, os.SEEK_SET)
            backup = safe_write.backup_from_fd(fd, path, backup_dir, home)
        finally:
            os.close(fd)
        kinds = {r['kind'] for r in group}
        if kinds == {'hook_script'}:
            os.unlink(path)
        elif kinds == {'markdown_block'}:
            text = before.decode('utf-8')
            for r in group:
                text = _strip_block(text, r['entry'])
            safe_write.atomic_write(path, text, prefix='.ledger.')
        else:
            doc = report_state.load_json(before.decode('utf-8'))
            for r in group:
                _remove_json(doc, _edit_for(book, r)[1])
            text = json.dumps(doc, indent=2) + '\n'
            json.loads(text)
            safe_write.atomic_write(path, text, prefix='.ledger.')
        for r in group:
            after = plan_edit(*_edit_for(book, r))
            # A restored json_set value no longer matches the recorded fingerprint: that is success.
            done = after['status'] == 'absent' or (r['kind'] == 'json_set' and after['reason'] == 'hash_mismatch')
            r.update(backup=backup, status='removed' if done else 'blocked',
                     reason='' if done else 'verify_failed')
    for entry in book['entries']:
        mine = [r for r in rows if r['entry'] == entry['id']]
        if mine and all(r['status'] in ('removed', 'absent') for r in mine):
            entry['state'] = 'removed'
    return validate(book), rows
```

The `planned` re-check re-hashes each edit; the `_identity` comparison (device, inode, size, mtime captured at plan time) additionally blocks a file changed anywhere since planning, e.g. a line appended outside the block.

A file holding both JSON and Markdown edits cannot happen (one file has one format), so `kinds` is either JSON kinds, `{'markdown_block'}` or `{'hook_script'}`.

- [ ] **Step 5: Add the CLI subcommand** (in `main`)

```python
    p = sub.add_parser('remove', help='remove recorded edits (dry run unless --apply)')
    p.add_argument('--ledger', required=True)
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument('--entry', action='append')
    which.add_argument('--all', action='store_true')
    p.add_argument('--apply', action='store_true')
    p.add_argument('--backup-dir')
```

and in the `try` block before the `next-id`/`record` handling:

```python
        if args.command == 'remove':
            if args.apply and not args.backup_dir:
                parser.error('--apply requires --backup-dir')
            ids = args.entry or [e['id'] for e in book['entries'] if e['state'] != 'removed']
            rows = plan_removal(book, ids)
            if args.apply:
                book, rows = apply_removal(book, rows, os.path.abspath(os.path.expanduser(args.backup_dir)),
                                           os.path.expanduser('~'))
                dump(book, args.ledger)
            for row in rows:
                row.pop('_identity', None)
            print(json.dumps(rows, indent=2))
            if any(r['status'] == 'blocked' for r in rows):
                sys.exit(2)
            return
```

- [ ] **Step 6: Run tests**

Run: `cd tests && python3 -m unittest test_ledger -v`
Expected: PASS.

- [ ] **Step 7: Red proof**

Make `plan_edit` return `removable` regardless of `hash_mismatch`; `test_crlf_block_is_modified_not_removed` must FAIL. Remove the `_identity` comparison; `test_file_changed_between_plan_and_apply_is_blocked` must FAIL. Revert.

- [ ] **Step 8: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/ledger.py tests/test_ledger.py
git commit -m "Add dry-run-first removal of ledger-recorded edits

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 6: Verdicts in the report processor and renderer

**Files:**
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/ledger.py` (add `evaluate`)
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/report_state.py` (`_validate_report`: `trend.ledger`, `applied[].ledger_entry`)
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/process_report.py` (`--ledger`, `--snapshot`, labels)
- Modify: `plugins/setup-audit/skills/setup-audit/scripts/render_report.py` (trend section ~line 184)
- Test: `tests/test_ledger.py` (class `Evaluate`), `tests/test_report_state.py`, `tests/test_render_report.py`

**Interfaces:**
- Consumes: Task 2 `verdict`, `proposal`, `next_rung`, `validate_counts`, `selector_hash`, `iso`; Task 4 `snapshot_scope`, `metric_baseline`.
- Produces:
  - `ledger.evaluate(book, snapshot, report, run) -> (rows: list[dict], book: dict)`; row keys: `entry, verdict, reason, proposal, next_mechanism, matches, sessions_matched, sessions_scanned, value` (unused counts `None`).
  - `report['trend']['ledger']` (list of rows) validated by `report_state`.
  - `process_report.py --ledger L --snapshot S` (both required together).

- [ ] **Step 1: Write the failing tests** (`tests/test_ledger.py`)

```python
class Evaluate(unittest.TestCase):
    def snapshot(self, sig=None, status="collected"):
        return dict(window_days=30, collection_scope=dict(requested="all", project=None),
                    ledger_signals=dict(status=status, entries={} if sig is None else {"L-20260901-1": sig}))

    def report(self):
        return dict(version=1, generated="2026-10-05T00:00:00Z", window_days=30, metrics={}, findings=[], applied=[])

    def test_rows_and_observation(self):
        book = dict(version=1, entries=[entry()])
        rows, new = ledger.evaluate(book, self.snapshot(current(2, 20)), self.report(), "2026-10-05-audit")
        self.assertEqual(rows[0]["verdict"], "dropped")
        self.assertEqual(rows[0]["sessions_scanned"], 20)
        obs = new["entries"][0]["observations"]
        self.assertEqual((len(obs), obs[0]["run"], obs[0]["verdict"]), (1, "2026-10-05-audit", "dropped"))
        self.assertNotIn("selector_sha", obs[0])
        self.assertEqual(book["entries"][0]["observations"], [])  # input not mutated

    def test_rerun_replaces_same_run_observation(self):
        book = dict(version=1, entries=[entry()])
        _, once = ledger.evaluate(book, self.snapshot(current(5, 20)), self.report(), "run-a")
        rows, twice = ledger.evaluate(once, self.snapshot(current(5, 20)), self.report(), "run-a")
        self.assertEqual(len(twice["entries"][0]["observations"]), 1)
        self.assertIsNone(rows[0]["proposal"])  # one not_dropped run, not two

    def test_escalation_after_two_runs(self):
        book = dict(version=1, entries=[entry()])
        _, book = ledger.evaluate(book, self.snapshot(current(5, 20)), self.report(), "run-a")
        rows, _ = ledger.evaluate(book, self.snapshot(current(5, 20)), self.report(), "run-b")
        self.assertEqual((rows[0]["proposal"], rows[0]["next_mechanism"]), ("escalate", "hook"))

    def test_missing_or_invalid_signals_are_unknown_without_observation(self):
        book = dict(version=1, entries=[entry()])
        for snap in (self.snapshot(), self.snapshot(status="invalid"),
                     self.snapshot(dict(current(2, 20), sessions_matched=99))):
            rows, new = ledger.evaluate(book, snap, self.report(), "r")
            self.assertEqual(rows[0]["verdict"], "unknown")
            self.assertEqual(new["entries"][0]["observations"], [])

    def test_inactive_entries_are_skipped(self):
        book = dict(version=1, entries=[entry(state="removed")])
        rows, _ = ledger.evaluate(book, self.snapshot(current(2, 20)), self.report(), "r")
        self.assertEqual(rows, [])
```

In `tests/test_report_state.py` add:

```python
    def test_ledger_trend_rows_are_validated(self):
        result = state.finalize(self.report())
        result['trend']['ledger'] = [dict(entry='L-20260901-1', verdict='dropped', reason='rate_at_or_below_half',
                                          proposal=None, next_mechanism=None, matches=1, sessions_matched=1,
                                          sessions_scanned=20, value=None)]
        state.validate_report(result, strict=True)
        result['trend']['ledger'][0]['verdict'] = 'great'
        with self.assertRaises(state.ReportError):
            state.validate_report(result, strict=True)

    def test_processor_writes_trend_ledger_and_observation(self):
        with tempfile.TemporaryDirectory() as tmp:
            import ledger
            from test_ledger import entry, current
            report = Path(tmp, '2026-10-05-audit.json')
            report.write_text(json.dumps(self.report('2026-10-05')))
            book = Path(tmp, 'ledger.json')
            ledger.dump(dict(version=1, entries=[entry()]), str(book))
            snap = Path(tmp, 'snap.json')
            snap.write_text(json.dumps(dict(window_days=30, collection_scope=dict(requested='all', project=None),
                                            ledger_signals=dict(status='collected',
                                                                entries={'L-20260901-1': current(2, 20)}))))
            script = os.path.join(SCRIPTS, 'process_report.py')
            run = subprocess.run([sys.executable, script, str(report), '--ledger', str(book), '--snapshot', str(snap),
                                  '--finalize'], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(report.read_text())['trend']['ledger'][0]['verdict'], 'dropped')
            self.assertEqual(len(ledger.load(str(book))['entries'][0]['observations']), 1)
            # without --finalize nothing is written
            before = book.read_text()
            subprocess.run([sys.executable, script, str(report), '--ledger', str(book), '--snapshot', str(snap)],
                           check=True, capture_output=True)
            self.assertEqual(book.read_text(), before)

    def test_processor_ledger_errors_name_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp, 'r.json')
            report.write_text(json.dumps(self.report()))
            bad = Path(tmp, 'ledger.json')
            bad.write_text('{"version": 1, "entries": [], "x": "sk-SECRET"}')
            snap = Path(tmp, 's.json')
            snap.write_text('{}')
            run = subprocess.run([sys.executable, os.path.join(SCRIPTS, 'process_report.py'), str(report),
                                  '--ledger', str(bad), '--snapshot', str(snap), '--finalize'],
                                 capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn('The ledger', run.stderr)
            self.assertNotIn('SECRET', run.stderr)
            run = subprocess.run([sys.executable, os.path.join(SCRIPTS, 'process_report.py'), str(report),
                                  '--ledger', str(bad)], capture_output=True, text=True)
            self.assertIn('snapshot', run.stderr)
```

In `tests/test_render_report.py` add:

```python
    def test_ledger_rows_render_verdicts_and_proposals(self):
        import report_state
        from test_report_state import ReportState
        report = report_state.finalize(ReportState().report())
        report['trend']['ledger'] = [
            dict(entry='L-20260901-1', verdict='dropped', reason='rate_at_or_below_half', proposal=None,
                 next_mechanism=None, matches=1, sessions_matched=1, sessions_scanned=20, value=None),
            dict(entry='L-20260901-2', verdict='not_dropped', reason='rate_above_half', proposal='escalate',
                 next_mechanism='hook', matches=9, sessions_matched=6, sessions_scanned=20, value=None)]
        html = render_report.render(report)
        self.assertIn('L-20260901-1: the targeted pattern dropped', html)
        self.assertIn('1 of 20 later sessions matched', html)
        self.assertIn('propose moving it to a hook', html)
```

(Import `render_report` the way that file already does.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd tests && python3 -m unittest test_ledger.Evaluate test_report_state test_render_report -v`
Expected: FAIL (`evaluate` missing; `trend.ledger` not validated; renderer lacks ledger text).

- [ ] **Step 3: Implement `evaluate` in `ledger.py`**

```python
ROW_COUNTS = ('matches', 'sessions_matched', 'sessions_scanned', 'value')


def _current_counts(entry, signals, report):
    if entry['selector']['type'] == 'metric':
        try:
            end = report_state.timestamp(report['generated']).timestamp()
            start = end - report['window_days'] * 86400
        except (KeyError, TypeError, ValueError, report_state.ReportError):
            return None
        counts = metric_baseline(entry['selector'], report, start, end)
    else:
        counts = copy.deepcopy(signals.get(entry['id']))
        if counts is None:
            return None
        sha = counts.pop('selector_sha', None) if isinstance(counts, dict) else None
        try:
            validate_counts(counts, False)
        except LedgerError:
            return None
        counts['selector_sha'] = sha
        return counts
    counts['selector_sha'] = selector_hash(entry['selector'])
    return counts
    return counts


def evaluate(book, snapshot, report, run):
    """Verdict rows for this run and a ledger copy holding this run's observation per entry.

    Rerunning for the same run replaces that run's observation, so reprocessing is idempotent.
    Entries without usable current counts get an `unknown` row and no observation.
    """
    book = copy.deepcopy(validate(book))
    signals = snapshot.get('ledger_signals') if isinstance(snapshot, dict) else None
    entries = (signals or {}).get('entries') if isinstance(signals, dict) and signals.get('status') == 'collected' else {}
    entries = entries if isinstance(entries, dict) else {}
    try:
        scope, _ = snapshot_scope(snapshot)
    except LedgerError:
        scope = None
    rows = []
    for entry in book['entries']:
        if entry['state'] != 'active':
            continue
        current = _current_counts(entry, entries, report)
        earlier = [o for o in entry['observations'] if o['run'] != run]
        previous = earlier[-1] if earlier else None
        verdict_now, reason = verdict(entry, current, scope, previous)
        offer = proposal(entry, verdict_now, previous)
        row = dict(entry=entry['id'], verdict=verdict_now, reason=reason, proposal=offer,
                   next_mechanism=next_rung(entry) if offer == 'escalate' else None)
        row.update({k: (current or {}).get(k) for k in ROW_COUNTS})
        rows.append(row)
        if current is not None:
            observation = {k: v for k, v in current.items() if k != 'selector_sha'}
            observation.update(run=run, verdict=verdict_now, reason=reason)
            entry['observations'] = earlier + [observation]
    return rows, validate(book)
```

Make sure `copy` is imported at the top of `ledger.py`. If `validate_counts` fails on the metric observation (e.g. `value` not finite), it is already `None`, which is allowed.

- [ ] **Step 4: Validate the new report fields** in `report_state._validate_report`

In the `applied` item branch (after the `files`/`backups` loop):

```python
                if 'ledger_entry' in item:
                    require(isinstance(item['ledger_entry'], str), 'invalid ledger entry reference')
```

In the `trend` block (after the `ignored` check):

```python
        if 'ledger' in trend:
            rows = trend['ledger']
            require(isinstance(rows, list), 'invalid trend ledger')
            for row in rows:
                require(isinstance(row, dict) and isinstance(row.get('entry'), str)
                        and row.get('verdict') in LEDGER_VERDICTS and isinstance(row.get('reason'), str)
                        and row.get('proposal') in (None, 'escalate', 'retire')
                        and (row.get('next_mechanism') is None or isinstance(row['next_mechanism'], str)),
                        'invalid trend ledger')
                require(all(row.get(k) is None or (type(row[k]) is int and row[k] >= 0)
                            for k in ('matches', 'sessions_matched', 'sessions_scanned'))
                        and (row.get('value') is None or finite(row['value'])), 'invalid trend ledger')
```

`finalize` builds a fresh `trend` each run, so `trend.ledger` from an earlier processing pass is dropped and rebuilt by the processor; keep it that way.

- [ ] **Step 5: Wire `process_report.py`**

Add `import ledger` after `import report_state`. Extend `LABELS` with `'ledger': 'ledger', 'snapshot': 'snapshot'`. Add arguments:

```python
    parser.add_argument('--ledger', help='learning ledger; with --finalize, this run\'s observations are recorded')
    parser.add_argument('--snapshot', help='collector snapshot with ledger_signals; required with --ledger')
```

After `result = report_state.finalize(...)`:

```python
        book = None
        if args.ledger:
            if not args.snapshot:
                raise report_state.ReportError('--ledger requires --snapshot', input='snapshot')
            stage = 'ledger'
            book = ledger.load(args.ledger)
            stage = 'snapshot'
            snapshot = report_state.load_json(read(args.snapshot))
            stage = None
            rows, book = ledger.evaluate(book, snapshot, result, Path(args.report).stem)
            result['trend']['ledger'] = rows
            report_state.validate_report(result, strict=True)
```

In the `if args.finalize:` branch, before `write(args.report, result)` and after the same-file check:

```python
            if book is not None:
                stage = 'ledger'
                ledger.dump(book, args.ledger)
```

`LedgerError` is a `ReportError`, so `failure_message` already names its `input` and line. For `stage = 'ledger'` or `'snapshot'`, non-ReportError exceptions fall back to the constant text. Update the module docstring: "With `--ledger`/`--snapshot` and `--finalize`, one observation per active ledger entry is written to the ledger (atomically, 0600)."

- [ ] **Step 6: Render ledger rows** in `render_report.py`, inside the trend section after the metrics loop:

```python
        verdict_text = {'dropped': 'the targeted pattern dropped', 'not_dropped': 'the targeted pattern did not drop',
                        'quiet': 'the targeted pattern has been quiet', 'too_early': 'too early to judge',
                        'unknown': 'not comparable this run'}
        for row in trend.get('ledger', []):
            text = f"Learning fix {row['entry']}: {verdict_text.get(row['verdict'], row['verdict'])} ({row['reason']})"
            if row.get('sessions_scanned') is not None:
                text += f"; {row['sessions_matched']} of {row['sessions_scanned']} later sessions matched"
            if row.get('proposal') == 'escalate':
                text += f"; propose moving it to a {row['next_mechanism']}"
            elif row.get('proposal') == 'retire':
                text += '; propose retiring it'
            parts.append(paragraph(text + '.'))
```

- [ ] **Step 7: Run all tests**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

- [ ] **Step 8: Red proof**

In `evaluate`, change `earlier = [o for o in entry['observations'] if o['run'] != run]` to `earlier = list(entry['observations'])`; `test_rerun_replaces_same_run_observation` must FAIL. Move `ledger.dump` outside `if args.finalize`; `test_processor_writes_trend_ledger_and_observation` must FAIL. Revert.

- [ ] **Step 9: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/ledger.py plugins/setup-audit/skills/setup-audit/scripts/report_state.py plugins/setup-audit/skills/setup-audit/scripts/process_report.py plugins/setup-audit/skills/setup-audit/scripts/render_report.py tests/test_ledger.py tests/test_report_state.py tests/test_render_report.py
git commit -m "Report per-entry ledger verdicts and record observations

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 7: Skill workflow, references and user docs

**Files:**
- Create: `plugins/setup-audit/skills/setup-audit/references/ledger.md`
- Modify: `plugins/setup-audit/skills/setup-audit/SKILL.md` (Step 1 collector call; Step 3 "Compare with the previous run"; Step 4 processor call; Step 5 new item 9; new section "Removing tool-written edits")
- Modify: `plugins/setup-audit/skills/setup-audit/references/checklist.md` (`LRN-effectiveness`)
- Modify: `plugins/setup-audit/skills/setup-audit/references/report-state.md`, `references/report-format.md`, `references/coverage.md`
- Modify: `README.md` (Uninstall), `docs/roadmap.md`, `CHANGELOG.md` (`[Unreleased]`)
- Modify: `docs/superpowers/specs/2026-09-28-learning-ledger-design.md` (state enum: drop `retired`)
- Test: `tests/test_ledger.py` (class `Docs`)

**Interfaces:**
- Consumes: CLI surfaces from Tasks 3–6 exactly: `collect.py --ledger`, `process_report.py --ledger --snapshot`, `ledger.py next-id|record|remove`.

- [ ] **Step 1: Write the failing doc-consistency test**

```python
class Docs(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..")
    SKILL = os.path.join(ROOT, "plugins", "setup-audit", "skills", "setup-audit")

    def read(self, *parts):
        with open(os.path.join(*parts), encoding="utf-8") as f:
            return f.read()

    def test_skill_documents_every_ledger_command(self):
        skill = self.read(self.SKILL, "SKILL.md")
        for text in ("ledger.py next-id", "ledger.py record", "ledger.py remove", "--ledger", "--snapshot",
                     "references/ledger.md"):
            self.assertIn(text, skill)

    def test_reference_matches_constants(self):
        ref = self.read(self.SKILL, "references", "ledger.md")
        for value in (str(ledger.MIN_SESSIONS), str(ledger.MIN_BASELINE), str(ledger.QUIET_DAYS),
                      *ledger.STATES, *ledger.KINDS, *ledger.SOURCES, "fetched 2026-09-28"):
            self.assertIn(value, ref)
        self.assertNotIn("retired", ref)

    def test_readme_uninstall_mentions_removal_dry_run(self):
        readme = self.read(self.ROOT, "README.md")
        section = readme.split("## Uninstall", 1)[1].split("\n## ", 1)[0]
        self.assertIn("ledger", section)
        self.assertIn("dry run", section)
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd tests && python3 -m unittest test_ledger.Docs -v`
Expected: FAIL (`references/ledger.md` missing; SKILL.md lacks commands).

- [ ] **Step 3: Write `references/ledger.md`** covering, in this order:
  1. Purpose (one paragraph) and default path `<report_dir>/ledger.json`, explicit paths only, mode 0600.
  2. Entry fields table (from Task 2 Interfaces), states `active`, `removed`, `superseded`, mechanisms and ladder `memory < rule < hook < skill` (`setting` has no next rung).
  3. Selectors table (`keywords` with sources `corrections`/`friction_details`, `friction_category`, `metric`), limits (1–5 keywords, 1–40 chars, literals, case-insensitive), what makes counts incomplete (missing history, malformed lines, rows without session id, unattributable or undated facets, no facets).
  4. Verdict table with the exact constants: fewer than 5 post-fix sessions, baseline below 3 matched sessions, quiet after 30 days and two zero observations, drop at rate ≤ half; metric selectors need a report window starting after the fix.
  5. Proposals: escalate after two consecutive `not_dropped`; retire only quiet `memory`/`rule`; hooks never proposed for retirement in v1 (reason).
  6. Markers and edit kinds `markdown_block`, `hook_script`, `json_array_append`, `json_set` with exact marker strings; the documentation fact: "Block-level HTML comments in CLAUDE.md files are stripped before injection into context (https://code.claude.com/docs/en/memory.md, fetched 2026-09-28). The page does not say this for `.claude/rules/` or memory files; markers there may cost a few tokens."
  7. Removal statuses (`removable`, `modified`, `absent`, `blocked` with reasons `symlink`, `registration_unrecorded`, `backup_missing`, `unreadable`, `changed_since_plan`, `verify_failed`), dry run default, exit code 2 on blocked.
  8. Privacy: counts, hashes, paths, ids, redacted pattern/keywords only.

- [ ] **Step 4: Update SKILL.md**
  - Step 1 collector command: append `--ledger "<report_dir>/ledger.json"` when that file exists, with one sentence: "The collector only counts; it never writes the ledger."
  - Step 3 "Compare with the previous run": add "For each `trend.ledger` row with a `proposal`, write a finding `LRN-effectiveness:<entry>`: `escalate` proposes `next_mechanism`, `retire` proposes `ledger.py remove --entry <id>`. `unknown`/`too_early` rows are reported, never acted on. See `references/ledger.md`."
  - Step 4 processor command: add `--ledger "<report_dir>/ledger.json" --snapshot <snapshot>` when a ledger exists or any LRN item may be applied.
  - Step 5 new item 9 "Ledger": before an approved LRN edit run `python3 ${CLAUDE_SKILL_DIR}/scripts/ledger.py next-id --ledger <ledger>`; write markers exactly as in `references/ledger.md`; after verifying the edit write an entry spec to `$TMPDIR` and run `ledger.py record --ledger <ledger> --snapshot <snapshot> --report <current.json> --spec <spec>`; add `ledger_entry` to the matching `applied` item. Escalations set `supersedes`. Do not record non-LRN fixes.
  - New section "Removing tool-written edits": run `ledger.py remove --ledger <ledger> --all` (dry run), show every row, apply only after approval with `--apply --backup-dir ~/.claude/backups/setup-audit-<timestamp>/`; list `modified` rows for manual review; never edit them.

- [ ] **Step 5: Update the other references and docs**
  - `checklist.md` `LRN-effectiveness`: replace the body with: "(`trend.ledger` from the ledger; report-level `applied` + `metrics` only for fixes applied before the ledger existed). Act on processor proposals: escalate after two consecutive `not_dropped` verdicts, retire quiet memory/rule entries. A verdict is not causal proof."
  - `report-state.md`: new subsection "Learning ledger" — the two flags, that the ledger is written only with `--finalize`, idempotent per run, and that failures name `ledger`/`snapshot`.
  - `report-format.md`: `applied[].ledger_entry` (optional) and `trend.ledger` rows.
  - `coverage.md`: ledger counting limits (what makes `complete: false`), and that orphan facets make facet selectors incomplete.
  - `README.md` Uninstall: before the commands add "If the audit recorded learning fixes, ask Claude to run the setup-audit removal dry run first (`ledger.py remove --all`); it lists every edit the plugin made and removes only unchanged ones after you approve. Edits you changed since are listed for manual review."
  - `docs/roadmap.md`: move "Per-item learning ledger" into a new "Unreleased" section as done, noting v1 limits (no backfill, no regex, no tool-error source, hooks not retired).
  - `CHANGELOG.md` `[Unreleased]`: "Added: per-item learning ledger (`ledger.py`), post-fix selector counts in the collector (`--ledger`), `trend.ledger` verdicts and escalation/retirement proposals, dry-run-first removal of recorded edits. Changed: file-safety helpers moved to `safe_write.py`."
  - Spec: change "`state`: `active` | `retired` | `removed` | `superseded`" to "`active` | `removed` | `superseded` (retirement is carried out with `remove`)".

- [ ] **Step 6: Run the full gate**

Run:
```bash
python3 -m unittest discover -s tests -v
python3 tests/check_snapshot_schema.py -v
git diff --check
python3 -m coverage run -m unittest discover -s tests && python3 -m coverage combine && python3 -m coverage report --fail-under=88
```
Expected: all PASS; coverage ≥ 88. If `jsonschema` or `coverage` is not installed locally, report that explicitly.

- [ ] **Step 7: Red proof**

Delete the "fetched 2026-09-28" phrase from `references/ledger.md`; `test_reference_matches_constants` must FAIL. Restore.

- [ ] **Step 8: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/references/ledger.md plugins/setup-audit/skills/setup-audit/SKILL.md plugins/setup-audit/skills/setup-audit/references/checklist.md plugins/setup-audit/skills/setup-audit/references/report-state.md plugins/setup-audit/skills/setup-audit/references/report-format.md plugins/setup-audit/skills/setup-audit/references/coverage.md README.md docs/roadmap.md CHANGELOG.md docs/superpowers/specs/2026-09-28-learning-ledger-design.md tests/test_ledger.py
git commit -m "Document the learning ledger workflow, removal and limits

Assisted-by: Claude:claude-opus-5-5"
```
