# Drift Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A model-free `drift.py` command that collects, derives five drift signals, compares them with thresholds and the previous comparable run, appends one line to a guarded JSONL log and prints only when something crossed; plus a read-only `collect.py --drift-log` summary for the full audit.

**Architecture:** `collect.main()` is split into shared argument helpers and `build_snapshot(args)`, which returns the sanitized, validated snapshot dict. A new `drift_log.py` owns the log path guard, append, reader and summary; a new `drift.py` holds pure `derive`/`compare` functions and the CLI. The collector's `--drift-log` uses `drift_log.read`/`summarize`.

**Tech Stack:** Python 3.11+ standard library; `unittest`; the bundled snapshot schema evaluator.

**Spec:** `docs/superpowers/specs/2026-09-29-drift-mode-design.md`

## Global Constraints

- Stdlib only. Tests use temporary fake homes (`FakeHome` in `tests/test_collect.py`); never read or write the real `~/.claude`, never run the collector or `drift.py` against the real home.
- The log holds counts, sizes, ratios, paths, dates and 16-hex fingerprints only; never rule text, prompt text or configuration values.
- Log path must resolve inside a system temp directory (incl. `$TMPDIR`) or `CLAUDE/audits`; symlinks refused; new file mode 0600; append-only, one `write` per line, then `fsync`.
- Output: nothing on stdout without crossings; one line of at most 300 characters with crossings; exit 0 on success, 2 on usage errors (argparse), 1 on runtime errors with no log line written.
- Thresholds (defaults): `--claude-md-max-lines 200`, `--cache-hit-min 0.90`, `--growth-min 0.25`.
- Comparable entry = most recent earlier entry with equal `scope`, `project`, `window_days` and a non-null value for the signal.
- Snapshot stays version 1; `drift_signals` is optional and additive. Schema evaluator types: object, array, string, null, integer, boolean (no `number`; leave float fields untyped).
- Commits: explicit paths; message ends with exactly one trailer `Assisted-by: Claude:claude-opus-5-5`. Never stage `AGENTS.md`, `CODEX-SETUP.md`, `.superpowers/`.
- Run focused tests as `python3 -m unittest discover -s tests -p test_drift.py -v` (`tests/` is not a package).
- Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`, `git diff --check`, coverage ≥ 88 (`uvx --from coverage==7.16.2 coverage run -m unittest discover -s tests` then `coverage report`; clean up with `coverage erase`, never a glob `rm`).
- Bash sandbox is broken in this environment; run commands with the sandbox disabled.

Paths: `S = plugins/setup-audit/skills/setup-audit`.

## Review Focus

1. A log whose last line was cut mid-write (no trailing newline) → counted malformed and skipped; the next append still produces a valid line after it. (Task 2 `test_partial_last_line_is_malformed_and_append_still_works`.)
2. A first-ever run with an existing broad permission → baseline, no `new` crossing. (Task 3 `test_first_run_is_a_baseline`.)
3. A project-scope run followed by an all-scope run → never compared. (Task 3 `test_other_scope_is_not_comparable`.)
4. A refused log path → exit 1, nothing written, collection not even started. (Task 4 `test_refused_log_exits_1_without_writing`.)
5. A permission rule containing a secret-looking or unique string → absent from the log. (Task 4 `test_log_holds_no_rule_or_claude_md_text`.)

---

### Task 1: Extract `build_snapshot` and shared collection arguments

**Files:**
- Modify: `S/scripts/collect.py` (`main`)
- Test: `tests/test_drift.py` (new)

**Interfaces:**
- Produces:
  - `collect.add_collection_args(ap: argparse.ArgumentParser) -> None` — adds `--roots`, `--days`, `--claude-dir`, `--scope`, `--project` (same help texts and defaults as today).
  - `collect.apply_collection_args(ap, a) -> None` — the existing validation (`--days` positive, scope/project/roots rules via `ap.error`) and sets the module global `CLAUDE` from `--claude-dir`.
  - `collect.build_snapshot(a) -> dict` — everything from `audits = sorted(glob...)` through `validate_snapshot`, returning `json.loads(text)` (the sanitized, validated dict). Reads `getattr(a, 'ledger', None)`, `getattr(a, 'clarity_pilot', False)`, `getattr(a, 'drift_log', None)` (the last is used from Task 5).
  - `main()` keeps `--out`, `--clarity-pilot`, `--ledger`, then writes `json.dumps(snap, indent=1, allow_nan=False)` exactly as before.

- [ ] **Step 1: Write the failing test** (`tests/test_drift.py`)

```python
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
```

`import drift` / `import drift_log` will fail until Tasks 2-3; for this task's RED/GREEN, temporarily create both modules as empty files with only a docstring (commit them as such; later tasks fill them).

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: FAIL/ERROR `AttributeError: module 'collect' has no attribute 'add_collection_args'`.

- [ ] **Step 3: Implement the split in `collect.py`**

```python
def add_collection_args(ap):
    """Arguments shared by collect.py and drift.py."""
    ap.add_argument("--roots", nargs="*", default=[],
                    help="extra directories to scan in addition to projects discovered from Claude Code's own records")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--claude-dir", help="Claude Code config directory (default: $CLAUDE_CONFIG_DIR, else ~/.claude)")
    ap.add_argument("--scope", choices=["global", "project", "all"], default="all",
                    help="global: settings/hooks/memory/global usage stats only, no per-project file scanning; "
                         "project: only --project's files and usage/history entries; all: every discovered "
                         "project plus --roots (default)")
    ap.add_argument("--project", help="project root to audit; required with --scope project")


def apply_collection_args(ap, a):
    """Validate the shared arguments (argparse usage errors) and point CLAUDE at --claude-dir."""
    global CLAUDE
    if a.days < 1:
        ap.error('--days must be positive')
    if a.claude_dir:
        CLAUDE = os.path.abspath(os.path.expanduser(a.claude_dir))
    if a.scope == "project" and not a.project:
        ap.error("--scope project requires --project")
    if a.project and a.scope != "project":
        ap.error("--project is only used with --scope project (use --roots to add a directory under --scope all)")
    if a.roots and a.scope != "all":
        ap.error("--roots is only used with --scope all")


def build_snapshot(a):
    """Collect, sanitize and validate a snapshot for parsed arguments; return the JSON-native dict."""
    audits = sorted(glob.glob(os.path.join(CLAUDE, "audits", "*.md")))
    # ... move the existing body of main() here unchanged, from `contexts = []` through the
    # mcp_configured_but_unused_note assignment, reading a.ledger / a.clarity_pilot via getattr ...
    text = json.dumps(sanitize(snap), indent=1, default=lambda o: redact(str(o)), allow_nan=False)
    snap = json.loads(text)
    validate_snapshot(snap)
    return snap


def main():
    ap = argparse.ArgumentParser()
    add_collection_args(ap)
    ap.add_argument("--out")
    ap.add_argument("--clarity-pilot", action="store_true", help="opt-in instruction clarity review candidates")
    ap.add_argument("--ledger", help="learning ledger to count active entries against (read-only)")
    a = ap.parse_args()
    apply_collection_args(ap, a)
    text = json.dumps(build_snapshot(a), indent=1, allow_nan=False)
    if a.out:
        _write_snapshot(a.out, text)
        print(f"wrote {a.out} ({len(text)//4} est. tokens)")
    else:
        print(text)
```

Replace `if a.ledger:` with `if getattr(a, "ledger", None):` and `if a.clarity_pilot:` with `if getattr(a, "clarity_pilot", False):` inside `build_snapshot`. The body is moved, not rewritten.

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`, then the full suite once.
Expected: PASS; all existing collector tests unchanged.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/scripts/drift.py plugins/setup-audit/skills/setup-audit/scripts/drift_log.py tests/test_drift.py
git commit -m "Extract build_snapshot and shared collection arguments

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 2: Guarded drift log append and tolerant reader

**Files:**
- Modify: `S/scripts/drift_log.py`
- Test: `tests/test_drift.py`

**Interfaces:**
- Produces:
  - `drift_log.VERSION = 1`; `drift_log.SIGNALS = ('claude_md', 'cache_hit_ratio', 'broad_permissions', 'skill_listing_chars', 'injected_tokens')`.
  - `class DriftLogError(ValueError)` — messages never contain data values.
  - `check_path(path: str, allowed_dirs: set[str]) -> str` — absolute path; raises if the parent directory's realpath is not inside an allowed dir or the path is a symlink.
  - `append(path: str, entry: dict, allowed_dirs: set[str], audits_dir: str) -> None`.
  - `read(path: str) -> tuple[list[dict], int]` — `(entries, malformed)`; missing file → `([], 0)`; other `OSError` → `DriftLogError`.

- [ ] **Step 1: Write the failing tests** (append)

```python
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
```

Note on the partial-line test: the append after a partial line must still yield a parseable new line. Because the partial line has no `\n`, `append` must first check whether the file is non-empty and does not end with `\n`, and if so write a leading `\n` before the entry (in the same single `write`). This keeps the cut line isolated as one malformed line.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: ERROR `AttributeError: module 'drift_log' has no attribute ...`.

- [ ] **Step 3: Implement `drift_log.py`**

```python
"""Drift log: a guarded, append-only JSON Lines file with a tolerant reader. Stdlib only.

Entries hold counts, sizes, ratios, paths, dates and fingerprints, never rule or prompt text.
"""
import json
import os

VERSION = 1
SIGNALS = ('claude_md', 'cache_hit_ratio', 'broad_permissions', 'skill_listing_chars', 'injected_tokens')


class DriftLogError(ValueError):
    pass


def check_path(path, allowed_dirs):
    """Absolute log path, or DriftLogError when it is outside allowed_dirs or a symlink."""
    path = os.path.abspath(os.path.expanduser(path))
    real_dir = os.path.realpath(os.path.dirname(path))
    if not any(real_dir == d or real_dir.startswith(d + os.sep) for d in allowed_dirs):
        raise DriftLogError('drift log must be under a system temp directory or the audits directory')
    if os.path.islink(path):
        raise DriftLogError('drift log refuses to write through a symlink')
    return path


def append(path, entry, allowed_dirs, audits_dir):
    """Append one entry as a single line; create the file 0600 (and the audits dir 0700)."""
    path = check_path(path, allowed_dirs)
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        if os.path.abspath(directory) != os.path.abspath(audits_dir):
            raise DriftLogError('drift log directory does not exist')
        os.makedirs(directory, mode=0o700)
    line = json.dumps(entry, separators=(',', ':'), allow_nan=False) + '\n'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b'\n':
            line = '\n' + line  # isolate an interrupted earlier line
        os.write(fd, line.encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def read(path):
    """(entries, malformed); a missing log is empty. Partial, non-object or other-version lines are malformed."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return [], 0
    except OSError:
        raise DriftLogError('drift log cannot be read') from None
    entries, malformed = [], 0
    for raw in data.splitlines(keepends=True):
        if not raw.strip():
            continue
        if not raw.endswith(b'\n'):
            malformed += 1
            continue
        try:
            obj = json.loads(raw)
        except ValueError:
            malformed += 1
            continue
        if isinstance(obj, dict) and obj.get('version') == VERSION and isinstance(obj.get('signals'), dict):
            entries.append(obj)
        else:
            malformed += 1
    return entries, malformed
```

`os.makedirs(mode=0o700)` is subject to umask; follow it with `os.chmod(directory, 0o700)`.

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: PASS. Red-proof: remove the leading-`\n` isolation and confirm `test_partial_last_line_is_malformed_and_append_still_works` fails; restore.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/drift_log.py tests/test_drift.py
git commit -m "Add a guarded append-only drift log

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 3: Derive signals and compare (pure functions)

**Files:**
- Modify: `S/scripts/drift.py`
- Test: `tests/test_drift.py`

**Interfaces:**
- Consumes: `drift_log.SIGNALS`.
- Produces:
  - `drift.fingerprint(path: str|None, flag: str, rule: str) -> str` — first 16 hex chars of SHA-256 of `f"{path}\0{flag}\0{rule}"`.
  - `drift.derive(snap: dict, global_claude_md: str) -> tuple[dict, dict]` — `(signals, fingerprint_paths)`; signals keyed by `SIGNALS`.
  - `drift.comparable(entries: list[dict], meta: dict, name: str) -> dict|None`.
  - `drift.compare(signals, fingerprint_paths, entries, meta, thresholds) -> list[dict]` — `meta` has `scope`, `project`, `window_days`; `thresholds` has `claude_md_max_lines`, `cache_hit_min`, `growth_min`.

- [ ] **Step 1: Write the failing tests** (append)

```python
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
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: ERROR `AttributeError: module 'drift' has no attribute 'derive'`.

- [ ] **Step 3: Implement** (in `drift.py`)

```python
#!/usr/bin/env python3
"""Opt-in, model-free drift check: collect, derive five signals, compare, append one log line.

Silent unless a threshold is crossed. Never installs a hook or schedule; see references/drift.md.
"""
import hashlib
import drift_log

SIGNALS = drift_log.SIGNALS
META_KEYS = ('scope', 'project', 'window_days')


def fingerprint(path, flag, rule):
    return hashlib.sha256(f'{path}\0{flag}\0{rule}'.encode()).hexdigest()[:16]


def derive(snap, global_claude_md):
    """(signals, fingerprint -> settings path) from a collected snapshot. Rule text is not kept."""
    glob_ = snap.get('global') or {}
    projects = snap.get('projects') or {}
    claude_md = {}
    g = glob_.get('claude_md')
    if isinstance(g, dict):
        claude_md[global_claude_md] = {'lines': g.get('lines'), 'est_tokens': g.get('est_tokens')}
    for path, entry in sorted(projects.items()):
        if 'claude_md_lines' in entry and not entry.get('is_worktree_copy'):
            claude_md[path.rstrip('/') + '/CLAUDE.md'] = {'lines': entry['claude_md_lines'],
                                                         'est_tokens': entry.get('claude_md_tokens')}
    fps = {}
    for s in list(glob_.get('settings') or []) + [s for p in projects.values() for s in p.get('settings') or []]:
        for flag, rules in sorted(((s.get('permissions') or {}).get('risky') or {}).items()):
            for rule in rules:
                fps[fingerprint(s.get('path'), flag, rule)] = s.get('path')
    ratio = ((snap.get('transcripts') or {}).get('cache') or {}).get('hit_ratio')
    transcripts_complete = all(c.get('status') == 'collected' for c in (snap.get('coverage') or {}).get('sources', [])
                               if str(c.get('source', '')).startswith('transcripts.'))
    h = snap.get('harness_overhead') or {}
    series = h.get('skill_listing_series')
    sources = (h.get('injected_context') or {}).get('sources') or []
    top = sources[0] if sources else None
    signals = {
        'claude_md': claude_md or None,
        'cache_hit_ratio': None if ratio is None else {'value': ratio, 'complete': transcripts_complete},
        'broad_permissions': {'count': len(fps), 'fingerprints': sorted(fps)},
        'skill_listing_chars': None if not series else {'value': series['last']['chars'],
                                                        'complete': bool(h.get('complete'))},
        'injected_tokens': None if not top else {'value': top['est_tokens_per_session_median'],
                                                 'plugin': top['plugin'], 'hook_event': top['hook_event'],
                                                 'complete': bool(h.get('complete'))},
    }
    return signals, fps


def comparable(entries, meta, name):
    """The signal from the most recent entry with the same scope, project and window, if not null."""
    for e in reversed(entries):
        if all(e.get(k) == meta[k] for k in META_KEYS) and (e.get('signals') or {}).get(name) is not None:
            return e['signals'][name]
    return None


def compare(signals, fingerprint_paths, entries, meta, thresholds):
    crossings = []
    for path, v in sorted((signals['claude_md'] or {}).items()):
        if type(v.get('lines')) is int and v['lines'] > thresholds['claude_md_max_lines']:
            crossings.append({'signal': 'claude_md', 'kind': 'above_max', 'path': path, 'value': v['lines'],
                              'threshold': thresholds['claude_md_max_lines']})
    cache = signals['cache_hit_ratio']
    if cache and cache['value'] < thresholds['cache_hit_min']:
        crossings.append({'signal': 'cache_hit_ratio', 'kind': 'below_min', 'value': cache['value'],
                          'threshold': thresholds['cache_hit_min']})
    previous = comparable(entries, meta, 'broad_permissions')
    if previous is not None:
        new = sorted(set(signals['broad_permissions']['fingerprints']) - set(previous.get('fingerprints') or []))
        if new:
            crossings.append({'signal': 'broad_permissions', 'kind': 'new', 'fingerprints': new,
                              'paths': sorted({fingerprint_paths[f] for f in new if fingerprint_paths.get(f)})})
    for name in ('skill_listing_chars', 'injected_tokens'):
        current, previous = signals[name], comparable(entries, meta, name)
        if not current or not previous:
            continue
        if name == 'injected_tokens' and (current['plugin'], current['hook_event']) != (
                previous.get('plugin'), previous.get('hook_event')):
            continue
        before = previous.get('value')
        if type(before) not in (int, float) or before <= 0:
            continue
        fraction = (current['value'] - before) / before
        if fraction >= thresholds['growth_min']:
            crossings.append({'signal': name, 'kind': 'growth', 'value': current['value'], 'previous': before,
                              'fraction': round(fraction, 3), 'threshold': thresholds['growth_min']})
    return crossings
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: PASS. Red-proof: change `>=` to `>` in the growth test and confirm `test_growth_and_threshold_edges` fails; restore.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/drift.py tests/test_drift.py
git commit -m "Derive drift signals and compare with thresholds

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 4: The `drift.py` command

**Files:**
- Modify: `S/scripts/drift.py`
- Test: `tests/test_drift.py`

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: `drift.summary_line(crossings: list[dict], log_display: str) -> str`; `drift.main(argv: list[str]|None = None) -> int` (returns the exit code; `if __name__ == '__main__': sys.exit(main())`).

- [ ] **Step 1: Write the failing tests** (append)

```python
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
        _, _, _, log = self.run_drift()
        self.assertNotIn(canary, Path(log).read_text())

    def test_default_log_lives_in_audits(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(drift.main(['--claude-dir', self.claude, '--scope', 'global']), 0)
        path = os.path.join(self.claude, 'audits', 'drift.jsonl')
        self.assertEqual(len(drift_log.read(path)[0]), 1)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: ERROR `AttributeError: module 'drift' has no attribute 'main'`.

- [ ] **Step 3: Implement** (append to `drift.py`; add `import argparse, os, sys`, `from datetime import datetime, timezone`, `import collect`)

```python
def summary_line(crossings, log_display):
    parts = []
    for c in crossings:
        if c['kind'] == 'above_max':
            parts.append(f"{c['path']} {c['value']} lines > {c['threshold']}")
        elif c['kind'] == 'below_min':
            parts.append(f"cache_hit_ratio {c['value']} < {c['threshold']}")
        elif c['kind'] == 'new':
            parts.append('new broad permission in ' + ', '.join(c['paths'] or ['an unknown settings file']))
        else:
            parts.append(f"{c['signal']} +{round(c['fraction'] * 100)}% ({c['value']})")
    line = f"setup-audit drift: {len(crossings)} crossed ({'; '.join(parts)}); log {log_display}"
    return line if len(line) <= 300 else line[:297] + '...'


def _fraction(text, low, high, name):
    value = float(text)
    if not low < value <= high:
        raise argparse.ArgumentTypeError(f'{name} must be in ({low}, {high}]')
    return value


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    collect.add_collection_args(ap)
    ap.add_argument('--log', help='drift log (default: <claude dir>/audits/drift.jsonl)')
    ap.add_argument('--claude-md-max-lines', type=int, default=200)
    ap.add_argument('--cache-hit-min', type=lambda t: _fraction(t, 0, 1, '--cache-hit-min'), default=0.9)
    ap.add_argument('--growth-min', type=lambda t: _fraction(t, 0, 100, '--growth-min'), default=0.25)
    a = ap.parse_args(argv)
    if a.claude_md_max_lines < 1:
        ap.error('--claude-md-max-lines must be positive')
    collect.apply_collection_args(ap, a)
    audits = os.path.join(collect.CLAUDE, 'audits')
    allowed = collect._out_allowed_dirs()
    try:
        path = drift_log.check_path(a.log or os.path.join(audits, 'drift.jsonl'), allowed)
        entries, _ = drift_log.read(path)
    except drift_log.DriftLogError as e:
        print(f'setup-audit drift: {e}', file=sys.stderr)
        return 1
    try:
        snap = collect.build_snapshot(a)
    except Exception as e:  # never echo data from the failure
        print(f'setup-audit drift: collection failed ({type(e).__name__})', file=sys.stderr)
        return 1
    display = lambda p: p.replace(collect.HOME, '~', 1) if p.startswith(collect.HOME) else p  # noqa: E731
    meta = {'scope': a.scope,
            'project': os.path.abspath(os.path.expanduser(a.project)) if a.project else None,
            'window_days': a.days}
    signals, fps = derive(snap, display(os.path.join(collect.CLAUDE, 'CLAUDE.md')))
    crossings = compare(signals, fps, entries, meta, {'claude_md_max_lines': a.claude_md_max_lines,
                                                      'cache_hit_min': a.cache_hit_min, 'growth_min': a.growth_min})
    entry = {'version': drift_log.VERSION, 'at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
             **meta, 'signals': signals, 'crossings': crossings}
    try:
        drift_log.append(path, entry, allowed, audits)
    except (drift_log.DriftLogError, OSError) as e:
        msg = str(e) if isinstance(e, drift_log.DriftLogError) else 'drift log cannot be written'
        print(f'setup-audit drift: {msg}', file=sys.stderr)
        return 1
    if crossings:
        print(summary_line(crossings, display(path)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
```

`collect.build_snapshot` may call `sys.exit` via `ap.error` only during argument handling, which happens before this point; a `SystemExit` from collection is not expected. Make the file executable (`chmod +x`), like `collect.py`.

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`, then the full suite once.
Expected: PASS. Red-proof: print the summary line unconditionally and confirm `test_silent_without_crossings_and_one_line_with` fails; restore.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/drift.py tests/test_drift.py
git commit -m "Add the drift.py command

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 5: Collector `--drift-log` summary and schema

**Files:**
- Modify: `S/scripts/drift_log.py`, `S/scripts/collect.py` (`main`, `build_snapshot`), `S/references/snapshot.schema.json`
- Test: `tests/test_drift.py`, `tests/test_snapshot_contract.py`

**Interfaces:**
- Consumes: `drift_log.read`, `SIGNALS`; `build_snapshot` reads `getattr(a, 'drift_log', None)`.
- Produces: `drift_log.summarize(entries, malformed, display_path) -> dict`; snapshot key `drift_signals`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_drift.py`)

```python
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
```

In `tests/test_snapshot_contract.py`, following the existing `ledger_signals`/`harness_overhead` rejection tests: a valid `drift_signals` passes; `status: "bogus"` is rejected; `entries: -1` is rejected.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_drift.py -v`
Expected: ERROR (`summarize` missing; `drift_signals` absent).

- [ ] **Step 3: Implement**

`drift_log.py`:

```python
def _last_value(name, signal):
    if name == 'claude_md':
        return max((v.get('lines') for v in signal.values() if isinstance(v, dict) and type(v.get('lines')) is int),
                   default=None)
    if name == 'broad_permissions':
        return signal.get('count')
    return signal.get('value')


def summarize(entries, malformed, display_path):
    """Per-signal last value, crossing count and dates, for the collector's drift_signals."""
    signals = {}
    for name in SIGNALS:
        seen = [e for e in entries if isinstance(e['signals'].get(name), dict)]
        dates = [e.get('at') for e in entries for c in e.get('crossings') or []
                 if isinstance(c, dict) and c.get('signal') == name]
        if not seen and not dates:
            continue
        dated = sorted(d for d in dates if isinstance(d, str))
        signals[name] = {'last_value': _last_value(name, seen[-1]['signals'][name]) if seen else None,
                         'crossings': len(dates),
                         'first_crossing_at': dated[0] if dated else None,
                         'last_crossing_at': dated[-1] if dated else None,
                         'scopes': sorted({e.get('scope') for e in seen if isinstance(e.get('scope'), str)})}
    ats = sorted(e['at'] for e in entries if isinstance(e.get('at'), str))
    return {'status': 'collected', 'path': display_path, 'entries': len(entries), 'malformed': malformed,
            'first_at': ats[0] if ats else None, 'last_at': ats[-1] if ats else None, 'signals': signals}
```

`collect.py`: add `import drift_log`; in `main()` add `ap.add_argument("--drift-log", help="drift log to summarize (read-only)")`; in `build_snapshot`, next to the ledger block:

```python
    if getattr(a, "drift_log", None):
        path = os.path.abspath(os.path.expanduser(a.drift_log))
        display = path.replace(HOME, "~")
        try:
            entries, malformed = drift_log.read(path)
            snap["drift_signals"] = drift_log.summarize(entries, malformed, display)
        except drift_log.DriftLogError:
            snap["drift_signals"] = {"status": "invalid", "path": display}
```

`drift_log.read` on a directory raises `IsADirectoryError` (an `OSError`) → `DriftLogError` → `invalid`.

Schema (`properties`, after `harness_overhead`):

```json
    "drift_signals": {
      "type": "object",
      "required": ["status", "path"],
      "properties": {
        "status": {"enum": ["collected", "invalid"]},
        "path": {"type": "string"},
        "entries": {"type": "integer", "minimum": 0},
        "malformed": {"type": "integer", "minimum": 0},
        "first_at": {"type": ["string", "null"]},
        "last_at": {"type": ["string", "null"]},
        "signals": {"type": "object", "additionalProperties": {
          "type": "object",
          "required": ["last_value", "crossings", "first_crossing_at", "last_crossing_at", "scopes"],
          "properties": {
            "crossings": {"type": "integer", "minimum": 0},
            "first_crossing_at": {"type": ["string", "null"]},
            "last_crossing_at": {"type": ["string", "null"]},
            "scopes": {"type": "array", "items": {"type": "string"}}
          }}}
      }
    }
```

(`last_value` is untyped: it can be a float.)

- [ ] **Step 4: Run tests and the schema check**

Run: `python3 -m unittest discover -s tests && python3 tests/check_snapshot_schema.py`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/drift_log.py plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json tests/test_drift.py tests/test_snapshot_contract.py
git commit -m "Summarize the drift log into the snapshot

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 6: Documentation

**Files:**
- Create: `S/references/drift.md`
- Modify: `S/references/checklist.md`, `S/references/snapshot-format.md`, `S/references/coverage.md` (short `drift_signals` note), `S/SKILL.md`, `README.md`, `CHANGELOG.md` (`[Unreleased]`), `docs/roadmap.md`

- [ ] **Step 1: Fetch documentation.** `https://code.claude.com/docs/en/memory.md` (the CLAUDE.md size target; today the checklist says ~200 lines) and `https://code.claude.com/docs/en/hooks.md` (whether command hooks can run asynchronously — e.g. an `async` field — and which events; how SessionStart stdout is used). Record facts with "fetched 2026-09-29". If the memory target is no longer 200 lines, stop and report it (the default threshold would need a ruling).

- [ ] **Step 2: `references/drift.md`**, terse like `references/ledger.md`: purpose; how to run (`python3 <plugin>/skills/setup-audit/scripts/drift.py`, flags); signals table with thresholds and their sources (memory docs fetched date; checklist `COST-cache-health` line); comparable-entry rule and baseline; crossing kinds; log format (the spec's example entry), path rule, 0600, append-only, malformed handling, no rotation; privacy (no rule or prompt text; fingerprints); exit codes (0, 1, 2); cost (about 7 s at scope `all` on the author's machine on 2026-09-29, near-instant at `global` without transcript signals); wiring examples the user adds themselves: a crontab line, and — only if Step 1 confirms asynchronous command hooks — a user-settings hook entry using it. State plainly that the plugin never installs them. Find the plugin script path users should use the same way README already refers to plugin scripts (check README for the installed-plugin path convention; if none, show `${CLAUDE_PLUGIN_ROOT}` only where the docs say hooks expand it, else an explicit path placeholder the user fills in).

- [ ] **Step 3: `checklist.md`.** Add a short "Drift log" paragraph near the COST checks: when the snapshot has `drift_signals`, cite each signal's crossings with dates as measured evidence under `COST-claude-md-size`, `COST-cache-health`, `SEC-risky-allow`, `COST-harness-overhead` / `COST-startup-hooks`; a crossing alone is never a proposal; the current snapshot value outranks a logged one; `status: invalid` means the log could not be read.

- [ ] **Step 4: `snapshot-format.md` / `coverage.md`.** `drift_signals`: optional, only with `--drift-log`; counts, dates, scopes, last values; additive within v1.

- [ ] **Step 5: `SKILL.md`.** Where the collector invocation is described, mention `--drift-log <report_dir>/drift.jsonl` when that file exists, and that the audit never writes it.

- [ ] **Step 6: `README.md`.** A short "Drift mode (optional)" section: what it does, one example command, link to `references/drift.md`, never installs anything.

- [ ] **Step 7: `CHANGELOG.md` `[Unreleased]` and `docs/roadmap.md`.** Added: drift mode and `--drift-log`. Changed: collector internals split (`build_snapshot`), no behavior change. Roadmap: mark the item implemented (unreleased).

- [ ] **Step 8: Gate.** Full suite, schema check, `git diff --check`, coverage ≥ 88.

- [ ] **Step 9: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/references/drift.md plugins/setup-audit/skills/setup-audit/references/checklist.md plugins/setup-audit/skills/setup-audit/references/snapshot-format.md plugins/setup-audit/skills/setup-audit/references/coverage.md plugins/setup-audit/skills/setup-audit/SKILL.md README.md CHANGELOG.md docs/roadmap.md
git commit -m "Document drift mode

Assisted-by: Claude:claude-opus-5-5"
```
