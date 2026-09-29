# Opt-in script-only drift mode — design

Date: 2026-09-29. Status: approved in conversation; awaiting written-spec review.
Roadmap item: "Opt-in script-only drift mode" in `docs/roadmap.md`.

## Goal

Between full audits, nothing notices when a setup drifts: CLAUDE.md grows past its target, the
cache hit ratio falls, a broad permission rule appears, the skill listing or hook-injected context
grows. A drift run is a deterministic, model-free command the user runs themselves or wires into
their own cron job or hook. It collects, derives a few signals, compares them with thresholds and
with the previous comparable run, appends one line to a drift log and stays silent unless something
crossed. The plugin never installs a hook or schedule. The full `/setup-audit` reads the log
read-only and cites crossings as dated evidence; any change still needs the user's approval.

Success: a fixture run shows each crossing kind; the first run records a baseline without "new" or
growth crossings; runs with a different scope, project or window are never compared; nothing is
printed without a crossing; the log never contains rule text, prompt text or configuration values;
the collector's `--drift-log` summary validates against the snapshot schema.

## Decisions (user, 2026-09-29)

1. Signals: CLAUDE.md size, cache hit ratio, new broad permission rules, skill-listing size and
   median injected tokens per session.
2. Output: always append one log line; print one short line only when a threshold is crossed; exit
   0 on success regardless of crossings, non-zero only on errors.
3. Audit link: collector flag `--drift-log PATH` summarizes the log into the snapshot, read-only.
4. Default scope `all` (about 7 s on the author's machine; fits cron or an asynchronous hook, not a
   blocking SessionStart hook), overridable with `--scope`.

## Approach

A new `scripts/drift.py` reuses the collector in-process. The snapshot-building part of
`collect.main()` moves into `collect.build_snapshot(args) -> dict` (sanitized and validated, the
exact object `main()` serializes today); `main()` keeps argument parsing and writing. This avoids a
second collection code path and a temporary snapshot file.

## Components

| Unit | Responsibility | Writes |
|---|---|---|
| `scripts/collect.py` | `build_snapshot(args)` extracted from `main()`; new `--drift-log PATH` flag producing `drift_signals` | snapshot only |
| `scripts/drift.py` (new) | CLI; derive signals from a snapshot (pure function); compare with thresholds and the previous comparable entry (pure function); append the log line; print on crossings | the drift log only |
| `scripts/drift_log.py` (new) | Log path guard, safe append, tolerant reader, summary for the collector (pure where possible) | the drift log (append) |
| `references/drift.md` (new) | Signals, thresholds and their sources, log format, privacy, wiring examples | — |
| `references/snapshot.schema.json`, `snapshot-format.md` | optional typed `drift_signals` | — |
| `references/checklist.md`, `SKILL.md`, `README.md` | how the audit cites drift; how users run it | — |

## Signals

Derived from the snapshot `build_snapshot` returns. Each signal is `null` when its source is absent.

| Signal | Value | Crosses when | Default threshold (flag) |
|---|---|---|---|
| `claude_md` | `{path: {"lines": int, "est_tokens": int}}` for the global CLAUDE.md and each collected project's CLAUDE.md files (paths as the snapshot prints them) | any file's lines exceed the maximum | 200 lines (`--claude-md-max-lines`), the memory docs' target already used by `COST-claude-md-size`; re-fetch and date it |
| `cache_hit_ratio` | `transcripts.cache.hit_ratio` | the ratio is below the minimum | 0.90 (`--cache-hit-min`), the "healthy above ~90%" line of `COST-cache-health` |
| `broad_permissions` | `{"count": int, "fingerprints": [str]}`: one fingerprint per (settings file path, risky flag name, redacted rule), the first 16 hex characters of its SHA-256 | a fingerprint absent from the previous comparable entry appears | — (`new` kind) |
| `skill_listing_chars` | `harness_overhead.skill_listing_series.last.chars` | it grew by at least the fraction over the previous comparable entry | 0.25 (`--growth-min`) |
| `injected_tokens` | `est_tokens_per_session_median` of the first `harness_overhead.injected_context.sources` row, plus that row's `plugin` and `hook_event` | same growth rule, and only when plugin and hook_event match the previous entry's | 0.25 (`--growth-min`) |

Rules:

- **Comparable entry**: the most recent earlier log entry with the same `scope`, `project` and
  `window_days`, whose signal is not `null`. Without one, `new` and growth crossings are not
  evaluated for that signal (baseline).
- **Null never crosses.** `complete` notes are recorded per signal from the snapshot (coverage
  status of `transcripts.*` for the cache ratio, `harness_overhead.complete` for the harness
  signals) but do not suppress crossings; the audit weighs them.
- **Broad permissions** are the snapshot's `permissions.risky` flags from every collected
  settings file. The rule text is used only to compute the fingerprint and is never written.
- Growth compares against the previous comparable value only when that value is greater than 0.

## Log

Default path `~/.claude/audits/drift.jsonl` (under `$CLAUDE_CONFIG_DIR` when set, like the
collector). One JSON object per line:

```json
{"version": 1, "at": "2026-09-29T10:00:00Z", "scope": "all", "project": null, "window_days": 30,
 "signals": {"claude_md": {"~/.claude/CLAUDE.md": {"lines": 48, "est_tokens": 900}},
             "cache_hit_ratio": {"value": 0.93, "complete": false},
             "broad_permissions": {"count": 1, "fingerprints": ["3f1c0a9b7e2d4c55"]},
             "skill_listing_chars": {"value": 29782, "complete": false},
             "injected_tokens": {"value": 885, "plugin": "superpowers@claude-plugins-official",
                                 "hook_event": "SessionStart", "complete": false}},
 "crossings": [{"signal": "cache_hit_ratio", "kind": "below_min", "value": 0.61, "threshold": 0.9}]}
```

Crossing kinds: `above_max` (claude_md, with `path`), `below_min`, `new` (broad_permissions, with
the new fingerprints and their settings file paths), `growth` (with `previous` and `fraction`).

Safety:

- The log directory must resolve inside `CLAUDE/audits` or a system temp directory (the collector's
  `--out` rule); the directory is created with mode 0700 if missing only when it is `CLAUDE/audits`.
- A symlink at the log path is refused. A new file is created with mode 0600 (`O_CREAT|O_APPEND|
  O_NOFOLLOW` where available). Each entry is one `write` of a line ending in `\n`, then `fsync`.
- Reading: malformed, non-object or wrong-version lines are skipped and counted; a missing log is
  empty. A final line without `\n` (interrupted write) counts as malformed.
- No rotation in v1; an entry is about 1 KB.

## CLI behavior

`drift.py [--scope all|global|project] [--project P] [--roots ...] [--days 30] [--claude-dir D]
[--log PATH] [--claude-md-max-lines N] [--cache-hit-min R] [--growth-min F]`

Scope, project, roots, days and claude-dir mean exactly what they mean for `collect.py` and are
validated the same way.

- No crossing: print nothing, exit 0.
- Crossings: print one line to stdout, at most 300 characters:
  `setup-audit drift: <n> crossed (<signal detail>; ...); log <path>`. Exit 0.
- Error (invalid arguments, log path refused, unwritable log, collection failure): message to
  stderr, exit 1, and no log line is written.

## Audit link

`collect.py --drift-log PATH` (read-only; missing file = empty) adds optional `drift_signals`:

```json
{"status": "collected", "path": "~/.claude/audits/drift.jsonl", "entries": 42, "malformed": 0,
 "first_at": "2026-09-01T06:00:00Z", "last_at": "2026-09-29T06:00:00Z",
 "signals": {"cache_hit_ratio": {"last_value": 0.93, "crossings": 3,
                                 "first_crossing_at": "...", "last_crossing_at": "..."}}}
```

Per-signal `last_value` is scalar (`claude_md`: maximum lines across files; `broad_permissions`:
count; `injected_tokens`: value). `status` is `collected` or `invalid` (path refused or unreadable).
Entries from every scope are summarized; each signal summary also carries `scopes` (sorted list).

Checklist: drift crossings are dated, measured evidence cited under the existing check they point
to (`COST-claude-md-size`, `COST-cache-health`, `SEC-risky-allow`, `COST-harness-overhead`,
`COST-startup-hooks`); a crossing alone is never a proposal, and a current snapshot value outranks
a logged one.

## Documentation

`references/drift.md`: signals and thresholds with sources (memory docs page re-fetched with date;
checklist lines), log format and privacy, exit codes, cost (about 7 s at scope `all` measured
2026-09-29 on the author's machine; near-instant at scope `global`, which has no transcript
signals), and wiring examples: a crontab line, and a user-settings hook entry. Re-fetch the hooks
docs for whether command hooks can run asynchronously and which events suit it; show only what the
docs support. The plugin never installs either. README: a short "Drift mode" section linking to it.
CHANGELOG `[Unreleased]`, roadmap.

## Testing

Fake homes only.

- `build_snapshot` equals what `main()` wrote before the refactor for the same fake home (compare
  the serialized JSON of both paths on one fixture, excluding `generated`).
- Derivation: each signal from a hand-built snapshot dict; null sources give null.
- Comparison: each crossing kind; baseline run (no `new`/`growth`); scope/project/window mismatch is
  not comparable; growth from 0 not evaluated; injected-token growth not evaluated when the plugin or
  event changed; comparable entry skips entries whose signal is null.
- Log: symlink refused; path outside allowed dirs refused (exit 1, nothing written); new file mode
  0600; append preserves earlier lines; malformed and partial lines counted and skipped.
- CLI: silent without crossings (empty stdout, exit 0); one line with crossings; exit 1 on refused
  log; privacy canary in a permission rule and in CLAUDE.md text never appears in the log.
- Collector: `--drift-log` summary counts, dates, scopes; invalid path → `invalid`; schema accepts
  and rejects.

Gate: `python3 -m unittest discover -s tests -v`, `python3 tests/check_snapshot_schema.py`,
`git diff --check`, coverage ≥ 88.

## Out of scope

- Installing hooks, cron entries or any background process.
- Rotation or pruning of the log.
- Model analysis in the drift run; notifications beyond one stdout line.
- Signals beyond the five above.
