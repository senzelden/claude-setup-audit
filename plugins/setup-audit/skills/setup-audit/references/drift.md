# Drift mode

An optional, model-free command that notices setup drift between full audits. It collects a
snapshot, derives five signals, compares them with thresholds and earlier comparable runs,
appends one line to a drift log, and prints one line only when something crossed. You run it or wire
it into your own cron job or hook. The plugin never installs a hook, schedule or background process.
The full audit reads the log read-only and cites crossings as dated evidence (see `checklist.md`).

## Run

```bash
python3 <plugin dir>/skills/setup-audit/scripts/drift.py [--scope all|global|project] [--project P] \
  [--roots ...] [--days 30] [--claude-dir D] [--log PATH] [--claude-md-max-lines 200] \
  [--cache-hit-min 0.9] [--growth-min 0.25]
```

`--scope`, `--project`, `--roots`, `--days` and `--claude-dir` mean what they mean for `collect.py`
and are validated the same way. Defaults: scope `all`, 30 days. `<plugin dir>` is where the plugin
is installed on your machine; fill it in yourself.

## Signals

| Signal | Value | Crosses when | Default threshold and source |
|---|---|---|---|
| `claude_md` | lines and estimated tokens per CLAUDE.md (global and each project; worktree copies skipped) | a file's lines exceed the maximum (`above_max`) | 200 lines: "target under 200 lines per CLAUDE.md file", memory docs, fetched 2026-09-29 (`COST-claude-md-size`) |
| `cache_hit_ratio` | `transcripts.cache.hit_ratio` | below the minimum (`below_min`) | 0.90: "above ~90% is healthy" (`COST-cache-health`) |
| `broad_permissions` | count and fingerprints of `permissions.risky` rules | a fingerprint is absent from the previous comparable entry (`new`) | none |
| `skill_listing_chars` | last `harness_overhead.skill_listing_series` size | grew by at least the fraction over its growth anchor (`growth`) | 0.25 (`--growth-min`), a recommendation, not a documented limit |
| `injected_tokens` | median estimated tokens per session of the top injected-context source | same growth rule; the anchor only reaches back over runs whose plugin, hook event and `attribution` match the current ones (entries logged without `attribution` end the walk) | 0.25 (`--growth-min`) |

A signal is `null` when its source is absent, and a null signal never crosses. The `complete` flag
recorded per signal comes from the snapshot's coverage; it does not suppress a crossing, and the
audit weighs it.

**Comparable entry:** the most recent earlier log entry with the same `scope`, `project` and
`window_days` whose signal is not `null`. Without one, this run is the baseline for that signal: no
`new` or `growth` crossing is evaluated. `above_max` and `below_min` need no previous entry.

Comparability keys on `scope`, `project` and `window_days` only. Changing `--roots` or `--claude-dir`
while writing to the same log can raise `new` crossings for rules that already existed. `project` is
logged in `~` form like the other paths.

**Growth anchor:** growth is measured against the value at the last `growth` crossing of that
signal, or, before any crossing, the earliest comparable run; only a value above 0 can be the anchor.
Slow creep therefore crosses once its total reaches the threshold, and the crossing resets the
anchor, so the next alert needs another full step. A drop below the anchor does not move it.
(User decision 2026-09-29; the first design compared run to run, which never caught gradual
creep.) `skill_listing_chars` is taken
from the most recent non-SDK session, so at scope `all` it can move with whichever project was used
last.

**Crossing kinds:** `above_max` (with `path`), `below_min`, `new` (with the new fingerprints and
their settings file paths), `growth` (with `previous`, the anchor value, `since`, the anchor run's `at`, and `fraction`).

**Fingerprint limits.** A fingerprint is the first 16 hex characters of the SHA-256 of settings file
path, flag name and redacted rule. The collector keeps at most 6 risky rules per flag, each
truncated to 160 characters, so a rule beyond the cap is invisible and removing an earlier rule can
surface a hidden one as `new`. Redacted rules collapse to the same text, so their fingerprints can
merge. Settings from worktree copies count, so a worktree appearing can raise `new`.

## Log

Default path `~/.claude/audits/drift.jsonl` (`<CLAUDE config dir>/audits/drift.jsonl`, following
`$CLAUDE_CONFIG_DIR` or `--claude-dir`). It does not move when you change the audit's `report_dir`.
One JSON object per line, appended only; there is no rotation in v1 (an entry is about 0.5-1 KB; a measured minimal one is ~480 B):

```json
{"version": 1, "at": "2026-09-29T10:00:00Z", "scope": "all", "project": null, "window_days": 30,
 "signals": {"claude_md": {"~/.claude/CLAUDE.md": {"lines": 48, "est_tokens": 900}},
             "cache_hit_ratio": {"value": 0.93, "complete": false},
             "broad_permissions": {"count": 1, "fingerprints": ["3f1c0a9b7e2d4c55"]},
             "skill_listing_chars": {"value": 29782, "complete": false},
             "injected_tokens": {"value": 885, "plugin": "superpowers@claude-plugins-official",
                                 "hook_event": "SessionStart", "attribution": "matched", "complete": false}},
 "crossings": [{"signal": "cache_hit_ratio", "kind": "below_min", "value": 0.61, "threshold": 0.9}]}
```

- **Path rule:** the log's directory must resolve inside `<CLAUDE config dir>/audits` or a system
  temp directory. The audits directory is created with mode 0700 if missing; any other missing
  directory is an error. A symlink at the log path is refused. A new file is created with mode 0600.
- **Corrupt entries:** a malformed, non-object, wrong-version or half-written line is skipped and
  counted. A corrupt or hand-edited entry is skipped for comparison, and comparison falls back to
  an earlier valid entry or to the baseline. It never crashes a run. A missing log is empty.

## Privacy

The log holds counts, sizes, ratios, paths, dates and fingerprints. It never holds rule text,
prompt text or configuration values.

## Output and exit codes

- No crossing: prints nothing, exit 0 (the log line is still appended).
- Crossings: one stdout line, at most 300 characters, `setup-audit drift: <n> crossed (<detail>;
  ...); log <path>`. Long detail is shortened with `...`; the `; log <path>` suffix is kept unless the log path itself is longer than about 270 characters, where the hard 300-character cap applies. Exit 0.
- Invalid arguments: usage error, exit 2.
- Errors: one message to stderr without data values, exit 1, and no log line is written. This covers
  a refused, unreadable or unwritable log, and a collection failure, which prints
  `setup-audit drift: collection failed (<ExceptionType>)`.

## Cost

Measured on the author's machine on 2026-09-29: about 7 seconds at scope `all`, near-instant at
scope `global`. Scope `global` has no transcript signals, so `cache_hit_ratio` is `null`. Seven
seconds fits cron (the recommended default cadence), or an asynchronous hook on an event off the startup path. Claude's first
response waits for `SessionStart` hooks to finish (hooks docs, fetched 2026-09-29).

## Wiring (yours to add)

The plugin installs none of this. Replace `<plugin dir>` with the installed plugin's path.

Crontab, weekdays at 08:00, appending to the default log and mailing any output through cron:

```
0 8 * * 1-5 python3 <plugin dir>/skills/setup-audit/scripts/drift.py
```

Hook entry in `~/.claude/settings.json` (project settings can hold hooks too). The hooks docs
(fetched 2026-09-29) say `"async": true` on a command hook runs it in the background without
blocking and without enforcing `timeout`; that in non-interactive mode (`-p`) async hooks still
running at teardown are killed; and that `SessionEnd` hooks share a 1.5-second budget by default,
too short for a 7-second run. The example uses `Stop`, which fires after every response. Each response then costs a ~7 s
collection at scope `all` and appends one line of about 0.5 KB, and parallel sessions can run it
concurrently. The log is read whole on each run; a measured 200k-line (~96 MB) log took ~1 s to
read. Cron is the better fit for a steady cadence.

```json
{"hooks": {"Stop": [{"hooks": [
  {"type": "command", "command": "python3 <plugin dir>/skills/setup-audit/scripts/drift.py", "async": true}
]}]}}
```

An async hook's results reach Claude only as `additionalContext` or `systemMessage` fields of a JSON
response, and are not shown to you. `drift.py` prints plain text, so from a hook its crossings land
only in the log; the next audit reads them through `--drift-log`.
For a visible one-line alert, use cron with mail, or run `drift.py` by hand.
