# Setup Audit Lite

Setup Audit Lite is the config-only edition of Setup Audit. It compares your Claude Code
configuration with the current official documentation and with vetted community practice,
proposes ranked fixes, applies the ones you approve with backups, and can check in later to
roll back or measure the effect.

It is Markdown only: no scripts, no hooks, no MCP servers. It uses only the Read, Grep, Glob
and LS tools.

## Install

```
/plugin marketplace add senzelden/claude-setup-audit
/plugin install setup-audit-lite@claude-setup-audit
```

Then ask Claude to audit your Claude Code setup.

## What it reads

Settings files (by key, never whole), CLAUDE.md files, skills, agents, commands and plugin
manifests, in your user directory and in the current project.

## What it never reads

Credential files, env files and MCP config are never opened. The MCP inventory comes from
output you paste yourself. The exact rules are in the skill's reading-rules reference.

## Full edition

The full `setup-audit` plugin adds usage and transcript analysis and scripted checks. Install it
from the same marketplace with `/plugin install setup-audit@claude-setup-audit`. When both are
installed, prefer the full plugin.

Source and issues: https://github.com/senzelden/claude-setup-audit
