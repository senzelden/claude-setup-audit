# Plugin runtime side effects: survey evidence (2026-10-25)

Read-only survey: every plugin in anthropics/claude-plugins-official (315 entries), a random 57 of
2,283 community entries, ~35 popular third-party repos. Hook files and scripts read directly at
default-branch HEAD (not marketplace-pinned shas). Clones were kept in a session scratchpad, not in the repo.
Docs: code.claude.com hooks.md and plugins-reference.md fetched raw 2026-10-25.

## Doc facts (raw docs, 2026-10-25)
- Hook `timeout` is seconds; omitted = 600 s for command hooks (30 s UserPromptSubmit) (hooks.md:414).
- Hook output (additionalContext, systemMessage, stdout) capped at 10,000 chars; above that Claude
  Code saves it to a file and sends a path + 2,000-char preview (hooks.md:1050-1053).
- `onFailure` default `continue`, 2.1.295+ (hooks.md:447,904). No surveyed plugin sets it.
- A timed-out PreToolUse / UserPromptSubmit hook discards its output and the action proceeds
  (hooks.md:879,1482).
- Plugin-root settings.json honours only `agent` and `subagentStatusLine` (plugins-reference.md:216,629).
- `${CLAUDE_PLUGIN_DATA}` = `~/.claude/plugins/data/<id>/`, id = plugin@marketplace with chars
  other than [A-Za-z0-9_-] replaced by `-` (plugins-reference.md:559).
- `pluginConfigs` in user settings is written by Claude Code for plugins with userConfig (not a
  plugin side effect) (plugins-reference.md:491).

## Robust fingerprints (use these; anything else is out of scope per user ruling)
| Plugin | Behaviour | Fingerprint |
|---|---|---|
| TokenEconomizer (microsoft/TokenEconomizer) | auto bare-name `permissions.deny` in `<repo>/.claude/settings.local.json`; adds file to `.git/info/exclude` when it creates it | ledger `$TOKENECONOMIZER_HOME` (default `~/.tokeneconomizer`) `/**/untool_applied.json`: `{"by_path": {"<realpath of settings file>": ["Tool", ...]}, "kept": {...}}` (older shape `{"tools": [...], "path": "..."}`). denylist.py:170-200 |
| quartermaster (Eigenwise/eigenwise-toolshed) | opt-in auto `permissions.allow` appends in `.claude/settings.local.json` after N approvals | top-level key `"quartermaster": {"autoApprovePermissions": true}` in that settings file (lib/permission-allowlist.js:12,68-83). Individual rules not attributable |
| claude-mem (thedotmack/claude-mem) | spawns observer Claude sessions | session cwd/project under `~/.claude-mem/observer-sessions/<id>` (src/shared/paths.ts:26,70) |
| remember (Digital-Process-Tools/claude-remember) | nested `claude -p` Haiku summarizer | env `REMEMBER_NESTED_SUMMARIZER` set for the child (verify in its scripts; if it isn't observable in transcripts, drop it) |
| autoharness (tigerless-labs/autoharness) | detached `claude -p --resume --fork-session`, `claude -p --agent ... --dangerously-skip-permissions` (hook/spawn.py:92,108); writes skills to `.claude/skills/` and `.claude/skills/.archive/`; state `.claude/autoharness/` | state dir; spawned sessions: check what transcripts show (entrypoint `sdk-cli`?) before claiming attribution |
| ralph-loop (official) | Stop hook blocks to loop | `.claude/ralph-loop.local.md` |
| hookify (official) | rule files | `.claude/hookify.*.local.md` |
| auto-memory (severity1) | Stop blocks until CLAUDE.md/AGENTS.md updated | `.claude/auto-memory/config.json` |
| claude-hud | writes statusLine on /claude-hud:setup | `~/.claude/plugins/claude-hud/` |

## Generic classes (common; detect without a per-plugin table)
- Context injection per hook 1-11k chars, often conditional; measure from transcript attachments
  `hook_additional_context` (content[]) and `hook_success` (hookName e.g. `SessionStart:startup`,
  hookEvent, stdout). Over-10k outputs are spilled (model sees 2k preview).
- Hook-supplied permission decisions: PermissionRequest hooks (night-market conserve auto-approves
  and auto-denies); PreToolUse hooks returning `permissionDecision: "allow"` (railway, clay) or
  denying built-in tools (youdotcom denies WebFetch/WebSearch inline in plugin.json; context-mode;
  cc-safety-net); `updatedInput` rewriting Bash (token-saver, context-mode). Invisible in rule lists.
- Timeouts > 600 s are almost certainly milliseconds by mistake (agentforce-adlc 5000/10000,
  gortex 3000/5000, mpp-inspector 5000) = effectively no timeout.
- Fail-open is the default everywhere and often deliberate (claude-mem moved from exit 2 to exit 0
  after dropped prompts). Defect only for security/policy guards (already SEC-hooks' scope).
- Spawned child sessions pollute usage/learning analysis.
