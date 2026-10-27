# Rate-limit log

An optional, model-free status-line command that records your subscription rate-limit windows
(5-hour, 7-day and, behind a Claude apps gateway, spend limit) so a later audit can see how much of
your plan you actually used. You wire it in yourself; the plugin installs no hook, schedule,
setting or background process. The full audit reads the log read-only.

## Run

```bash
python3 <plugin dir>/skills/setup-audit/scripts/rate_limit_log.py [--log PATH] [-- COMMAND ...]
```

`<plugin dir>` is where the plugin is installed on your machine; fill it in yourself.

## Wiring

In your own `settings.json`:

```json
"statusLine": {"type": "command", "command": "python3 <plugin dir>/skills/setup-audit/scripts/rate_limit_log.py"}
```

It prints one short line such as `5h 23% · 7d 41% (resets Mon 00:00)` (local time), or nothing when
no rate-limit data is present. To keep an existing status line, wrap it:

```json
"statusLine": {"type": "command", "command": "python3 <plugin dir>/skills/setup-audit/scripts/rate_limit_log.py -- <your command>"}
```

The wrapped command receives the same stdin bytes (no shell, 3 second timeout) and its stdout is
printed instead. If it fails, times out or is not found, the logger's own line is printed.

## Log

Default `<CLAUDE config dir>/audits/rate-limits.jsonl` (`$CLAUDE_CONFIG_DIR`, else `~/.claude`).
One line per change:
`{"version":1,"at":"<UTC ISO>","windows":{"five_hour":{"used_percentage":23.5,"resets_at":1738425600},...}}`.
A line is appended only when a window appeared or disappeared (never when no window is present, which is normal at every session start), a `resets_at` changed, or the
whole-number part of a `used_percentage` changed; "last logged" is read from the last 4 KB. Concurrent
sessions may write a duplicate; readers tolerate it. `spend_limit` may also carry `period`
(`daily`, `weekly` or `monthly`).

Path rule, the same guard as the drift log: the directory must be the audits directory or under a
system temp directory (`--log` elsewhere is refused), a symlink is never written through, the file
is created 0600 and the audits directory 0700. At 2 MB the log is renamed to `rate-limits.jsonl.1`
(replacing an older one) before the next append.

The logger never breaks the status line: any logging problem is swallowed, nothing goes to stderr,
and it exits 0. Invalid arguments exit 2.

## When it runs

From the statusline docs (fetched 2026-10-26): the command runs at session start, after each
assistant message, after `/compact`, on mode changes and when a window reaches `resets_at`, with
updates debounced at 300 ms. `rate_limits` appears only for Pro and Max subscribers (or a gateway
spend limit) and only after the first API response; each window may be absent, and Claude Code
drops a window once its `resets_at` has passed. It only sees the plan while Claude Code runs on
this machine, so usage elsewhere (claude.ai, other devices) is not in the log.

## Privacy

Numbers and timestamps only: no USD amounts, session ids, model names, paths or text.
