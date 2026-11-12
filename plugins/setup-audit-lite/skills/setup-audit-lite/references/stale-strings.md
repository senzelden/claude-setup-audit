# Stale strings

Strings that mark advice as written for an older Claude Code. Use them to vet community pages
(`sources.md`) and to spot outdated keys in the user's own settings (`HYG-settings-shape`,
`HYG-scope-ignored`). Every version below is the changelog entry that made the change, checked
against the raw changelog page on 2026-11-12 (newest entry 2.1.322).

How to count: a string counts as a hit when it appears in a page as advice to use it, not when the
page says it is deprecated or removed. Rows whose status is `old style, still valid` or
`current again` are never hits; they are listed so they aren't flagged by mistake.

| string | status | since | replacement |
|---|---|---|---|
| `includeCoAuthoredBy` | deprecated | 2.0.62 | the `attribution` setting |
| `ignorePatterns` | removed from the global config file | 2.0.8 | `Read` deny rules in settings (migrated to deny permissions in 2.0.35) |
| `allowedTools` | removed from the global config file | 2.0.8 | `permissions.allow` in settings |
| `todoFeatureEnabled` | removed from the global config file | 2.0.8 | none |
| `/allowed-tools` | renamed | 1.0.7 | `/permissions` |
| `TaskOutput` | removed (deprecated in 2.1.83) | 2.1.277 | `Read` on the background task's output file |
| `taskOutputMaxChars` | removed, no effect | 2.1.277 | none |
| `TASK_MAX_OUTPUT_LENGTH` | removed, no effect | 2.1.277 | none |
| `Write(` | warned at startup, never matched by file checks | 2.1.210 | `Edit(path)` rules |
| `ProgramData\ClaudeCode` | removed (deprecated in 2.1.2) | 2.1.75 | `C:\Program Files\ClaudeCode\managed-settings.json` |
| `/output-style` | current again | 2.1.269 | none; deprecated in 2.1.73, re-added as `/output-style [name]` in 2.1.269 |
| `Bash(x:*)` | old style, still valid | — | `Bash(x *)`; the permissions page calls the `:*` suffix equivalent, at the end of a pattern only |

Notes:

- `allowedTools` is stale only as a global-config key; `--allowedTools` is a current CLI flag, so
  count it only in a config-file context.
- `MultiEdit`: the permissions page calls it "legacy" and says to write `Edit(...)` rules instead,
  but no changelog entry names it, so it is not a table row. Mention it as "legacy per the
  permissions page" when a source uses it in a permission rule; don't count it as a stale hit.
- Dropped for lack of a changelog or docs match on 2026-11-12: `permissionExplainerEnabled` (no
  match anywhere) and `teammateDefaultModel` (the changelog for 2.1.234 removes the "Default teammate
  model" setting from `/config` but doesn't print a key name).
- Watch: fast mode on Opus 4.8 is deprecated (changelog 2.1.316) and is removed on November 30, 2026.
  After that date, advice to use fast mode on Opus 4.8 is stale.
