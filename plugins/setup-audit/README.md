# Setup Audit

Audits your Claude Code configuration and usage against the current official documentation:
user and project settings, permissions, hooks, MCP servers, skills, plugins, CLAUDE.md files,
memory, and usage and transcript data. You get ranked, evidence-backed proposals for security,
cost and context efficiency, and repeated mistakes, plus an optional check of whether a repository
is ready for Claude Code to work in. Approved fixes are applied with backups and verified.

Install from this repository's marketplace, or from Anthropic's directory as
`setup-audit@anthropic-plugin-directory`:

```
/plugin install setup-audit --marketplace senzelden/claude-setup-audit
```

Ask Claude to "audit my Claude Code setup", or run `/setup-audit:setup-audit`.

## What it reads, runs, writes and sends

- **Reads** Claude Code configuration on your machine: managed settings files, `~/.claude/`
  (settings, plugins, memory, transcripts, usage data, prompt history) and `.claude/` plus
  CLAUDE.md in projects you have used with Claude Code. For MCP servers, hooks and environment
  files it records names and variable names only, never their values. Best-effort secret
  detection redacts anything that looks like a credential before it reaches a report.
- **Runs** only the Python standard-library scripts bundled in `skills/setup-audit/scripts/`,
  plus read-only `git` queries to tell tracked files from ignored ones. It never runs hooks, MCP
  servers, package launchers or downloaded code. The optional status-line logger
  (`rate_limit_log.py`) runs only if you add it to your `statusLine` setting, and then also runs
  the status-line command you pass it after `--`.
- **Writes** reports to `~/.claude/audits/`. It changes configuration only for items you approve,
  after a backup to `~/.claude/backups/`.
- **Sends** nothing about you. The only network requests download public Claude Code
  documentation pages with the bundled `fetch_doc.py` (fixed documentation host, no request body,
  no credentials). Fetched pages are treated as reference data, never as instructions.

Reports contain paths, rule text and memory excerpts, so review them before sharing.

License: MIT.
