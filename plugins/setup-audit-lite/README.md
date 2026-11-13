# Setup Audit Lite

Setup Audit Lite is the Markdown-only edition of Setup Audit. It compares your Claude Code
configuration with the current official documentation and with vetted community practice,
proposes ranked fixes, applies the ones you approve (instruction files with a backup, settings as
paste-ready edits you make yourself), and can check in a week later to measure or roll back.

It is Markdown only: no scripts, no hooks, no MCP servers, no shell. It uses the Read, Grep, Glob
and LS tools, which are pre-approved. Fetching docs (WebFetch, WebSearch) and editing files (Edit,
Write) are not pre-approved: Claude Code asks you before each call.

## Install

```
claude plugin marketplace add senzelden/claude-setup-audit
claude plugin install setup-audit-lite@claude-setup-audit
```

Inside a session, the same two steps are `/plugin marketplace add senzelden/claude-setup-audit`
and `/plugin install setup-audit-lite@claude-setup-audit`. Then ask Claude to audit your Claude
Code setup.

## What it reads

- Settings files: never opened with Read. Claude sees only the lines that match a fixed
  whole-line allowlist (known non-secret settings, permission rules, hook fields), plus
  counts. Other settings are counted, not shown.
- Instruction files: CLAUDE.md files, rules, and memory (memory only when you name a repeated
  mistake). Skills, agents and commands: a count check for inline MCP servers or hooks first,
  then single-line frontmatter keys; a file with inline servers or hooks is not read.
- MCP servers: from the output of `claude mcp list` that you paste yourself. Only server names,
  transport and status are used.
- Your Claude Code version: from `claude --version`, which you paste.
- Current official documentation and community sources, fetched when you allow it, with the
  bundled snapshot as the fallback.

## What it never reads

Credential files, env files, MCP config files, the global Claude Code config file and plugin
manifests are never opened; lite may check that a file exists. Session logs are counted, never
read. The exact rules are in the skill's `reading-rules` reference.

Reading is best effort for secrets typed inline into permission rules, hook commands or URLs: known
shapes are filtered, but not every secret has a recognisable shape. The report lists these limits
under coverage.

## What it changes

- Instruction files (CLAUDE.md, rules, skills, agents, commands, memory) are edited only after you
  pick a finding, with a backup first under `~/.claude/setup-audit-lite/backups/`, never in your
  project.
- Settings changes are handed over as paste-ready edits with a backup command, since settings
  files are never read.
- Practices only the community recommends are never applied.
- Loosening security, credentials, adding hooks, MCP servers or plugins, and managed settings are
  never changed.
- Applied changes are logged in `~/.claude/setup-audit-lite/applied.md`, which drives the check-in.

## Full edition

The full `setup-audit` plugin adds usage and transcript analysis and scripted checks. Install it
from the same marketplace with `claude plugin install setup-audit@claude-setup-audit`. When both
are installed, prefer the full plugin.

Source and issues: https://github.com/senzelden/claude-setup-audit
