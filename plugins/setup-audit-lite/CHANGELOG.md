# Changelog

## [0.1.0] - 2026-11-13

First release of the Markdown-only edition of Setup Audit: one skill and its references, with
Read, Grep, Glob and LS pre-approved and no scripts, hooks or MCP servers.

### What it does

- Compares your configuration with the current official docs and with vetted community practice,
  side by side, with doc dates and "current docs", "quote not confirmed" and "may have changed"
  labels. A bundled, dated snapshot is the fallback when fetching fails.
- Ranks findings by severity times focus weight (security, cost, learning, readiness), with a
  clutter check that prefers removing or merging over adding.
- Applies the findings you pick, logs each change in `~/.claude/setup-audit-lite/applied.md`, and
  checks in after 7 days to measure or roll back.

### What it reads

- Settings files: never with Read. Only lines matching a whole-line Grep allowlist (known
  non-secret scalar settings, block openers, permission rules, hook fields) and count-only probes.
- CLAUDE.md, CLAUDE.local.md, AGENTS.md and rules; skills, agents and commands by frontmatter;
  memory only when a repeated mistake is named.
- The MCP inventory from a pasted `claude mcp list`, using server names, transport and status.
- The Claude Code version from a pasted `claude --version`.

### What it never reads

- `.claude.json`, `.mcp.json`, `.credentials.json`, `.env*` and `.envrc` files, other credential
  files, plugin manifests, the backups directory and session logs. Existence checks by Glob only.

### What it changes

- Instruction files (CLAUDE.md, rules, skills, agents, commands, memory) are edited after approval,
  with one backup per log entry under `~/.claude/setup-audit-lite/backups/`, never next to the
  file or in the project. Full restore is a command the user runs; lite never opens a backup.
- Settings changes are handed over as paste-ready edits with a backup command.
- Community-only practices are never applied.
- Credentials, loosening security, adding hooks, MCP servers or plugins, and managed settings are
  never applied.

### Validation and limits

- Guarded by `tests/test_lite_bundle.py` (directory rules: Markdown and JSON only, no Bash grants,
  credential names never paired with URLs in one file, file size limits) and strict
  `claude plugin validate` at plugin and marketplace level. The snapshot freshness test fails 120
  days after 2026-11-12; refresh the snapshot and allowlist each release.
- No model-based evaluation has been run for this release. No eval cases yet.
- Best-effort residuals, documented in `reading-rules.md`: inline secrets in rules, hook commands
  and URLs are filtered by known shapes only. Not covered: a password passed as a separate argument
  or a bare token with no known prefix, a path- or host-shaped secret inside an args list, a token
  in a webhook host name, a token on a Makefile `define` line that starts with a common target name,
  and an env or header entry named like an allowlisted setting (its value is shown).
- Settings the allowlist does not know are counted, not shown, until the allowlist is refreshed.
- Parked minor items: CRLF or BOM frontmatter in a non-skill Markdown file skips the allowed-tools
  check in the guard test; two red-proof samples are missing for the guard's secret-name patterns.
