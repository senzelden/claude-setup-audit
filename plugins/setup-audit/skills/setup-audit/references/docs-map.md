# Docs map — which page to fetch for which audit area

Base: `https://code.claude.com/docs/en/<page>.md` (index: `https://code.claude.com/docs/llms.txt`).
For **exact setting keys, rule syntax and defaults**, don't rely on WebFetch summaries. A small
model writes those summaries, it has misnamed keys before (`effort` vs `effortLevel`), and large
pages get truncated. Download the raw markdown instead and grep it:

```bash
curl -sL https://code.claude.com/docs/en/settings-reference.md -o <scratchpad>/docs/settings-reference.md
grep -n -i 'autoCompact\|effortLevel\|sandbox' <scratchpad>/docs/settings-reference.md
```

WebFetch is fine for overview pages (What's new, costs, best practices). If a URL 404s,
re-read llms.txt, because pages get renamed. Any setting you propose must appear verbatim in
`settings-reference`, which is the source of truth for key names.

| Area | Pages | Extract |
|------|-------|---------|
| Settings keys & precedence | settings, settings-reference | exact key names, precedence order, new/deprecated keys, `cleanupPeriodDays`, `env` |
| Permissions | permissions, permission-modes | rule syntax (`Bash(cmd *)` and the equivalent trailing `:*` form), deny/ask semantics, how compound commands are matched, defaultMode options |
| Sandboxing | sandboxing, sandbox-environments | sandbox settings keys, network allowlist, when sandbox replaces permission prompts |
| Security | security, security-guidance, data-usage | recommended protections, prompt-injection guidance, what is sent where |
| Hooks | hooks, hooks-guide | event names, input JSON schema, exit-code semantics (block vs warn), matcher syntax, timeouts |
| Cost | costs, prompt-caching, context-window, model-config, fast-mode | cost levers: model aliases, effort levels, auto-compact, subagent model choice, what invalidates cache, MCP tool-search |
| Memory | memory | CLAUDE.md load order, imports, size guidance, auto-memory behaviour |
| Skills / subagents / plugins | skills, sub-agents, plugins, discover-plugins | frontmatter fields (model, allowed-tools), per-agent model to save cost |
| MCP | mcp | tool search / deferred tools, per-server scoping, token cost of servers |
| Monitoring | monitoring-usage | OTel / usage tracking options |
| What's new | whats-new/index + weekly pages since last audit; changelog for anything newer | new features, changed defaults, deprecations relevant to this setup. The weekly index often lags by a few weeks, so cover the gap with `changelog.md` entries newer than the latest weekly page, compared against `global.version` |
| Debugging config | debug-your-config, troubleshooting | commands for verifying effective settings |
