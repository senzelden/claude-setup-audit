# Cache effect of applied changes

Every proposal and every op states its effect on the prompt cache. This is information only: apply
never holds, refuses or delays a change because of it, and the user decides. Table source: Claude
Code docs, raw pages fetched 2026-10-25: `prompt-caching.md` (PC), `settings.md` "When edits take
effect" (ST), `permissions.md` (PM). The table lives in `scripts/cache_effects.py` (`ROWS`);
`cache_effects.py table` prints it. Anything not covered is `unknown`; do not guess.

Effects:

- `keeps`: the cached prefix is untouched.
- `invalidates_next_request`: the next request re-reads the whole conversation uncached.
- `invalidates_without_tool_search`: a bare-name or tool-name-glob deny (adding or removing).
  With tool search active (default on supported models) the tool definitions do not change and the
  cache survives; with tool search off or unavailable the next request invalidates it. Labelled
  "keeps the cache (tool search observed)" when `transcripts.tool_search_observed` is true,
  a hedged "may invalidate: no tool-search records seen in the window; tool search is on by
  default on supported models" when false, and both possibilities ("not known from this run") when
  the snapshot is missing, lacks the field or has it null (no main-thread session in the window). "Observed" is evidence from transcripts (undocumented record shape),
  not proof of a live session's state.
- `applies_next_session`: the edit does not reach the running session. Row field `applies_at`
  says when: `restart` (keys read once at session start: `model`, `effortLevel`, `modelSettings`;
  MCP config until restart) or `clear` (the project context layer: CLAUDE.md and auto memory load
  at session start and after `/clear` or `/compact`). The running cache is
  not touched. Editing a file does not change what the current session sees.
- `unknown`: the docs do not say.

| Family | Effect | Source | Basis |
| - | - | - | - |
| `permission.allow_or_ask_rule` | `keeps` | prompt-caching "Denying an entire tool" | all allow and ask rules do not change which tools Claude sees; Claude Code checks them when Claude attempts a call |
| `permission.deny_scoped_rule` | `keeps` | prompt-caching "Denying an entire tool"; permissions | a scoped deny such as Bash(rm *) leaves the tool available and is checked at call time |
| `permission.mcp_parenthesized_rule` | `unknown` | permissions "Match by input parameter" | Claude Code skips any mcp__ rule with parentheses when it loads a settings file, so the rule has no effect and no cache effect; only --disallowedTools takes one |
| `permission.deny_bare_tool_rule` | `invalidates_without_tool_search` | prompt-caching "Denying an entire tool"; permissions | a bare tool name, the Bash(*) form or a tool-name glob like "*" or "mcp__*" removes the tool; with tool search active the definitions do not change and the prefix survives, otherwise the next request invalidates the cache, and so does removing the rule later |
| `permission.mode_default` | `keeps` | prompt-caching "Changing permission mode" | permission mode does not change the system prompt or tool definitions (exception: plan mode with the opusplan model setting is a model switch) |
| `permission.additional_directories` | `unknown` | settings "When edits take effect" | permission edits reload mid-session, but the prompt-caching page does not say whether directory entries touch the cached prefix |
| `settings.model` | `applies_next_session` | settings "When edits take effect" | model is read once at session start; /model switches mid-session and invalidates the cache because each model has its own cache (prompt-caching "Switching models") |
| `settings.effort` | `applies_next_session` | settings "When edits take effect" | effortLevel and modelSettings are read once at session start; /effort changes mid-session (prompt-caching "Changing effort level": keeps on Opus 5.5, Sonnet 5.5, Haiku 5.5, Fable 5.1 with an API key or subscription, invalidates on most other models) |
| `settings.output_style` | `keeps` | prompt-caching "Changing output style" | a mid-session style switch is delivered as a conversation message |
| `settings.sandbox` | `unknown` | settings "When edits take effect" | settings reload mid-session, but the prompt-caching page says nothing about sandbox keys |
| `settings.hooks` | `unknown` | settings "When edits take effect" | hooks in settings files reload mid-session; the prompt-caching sentence that hooks never invalidate covers plugin hooks, not settings-file hooks |
| `settings.env` | `unknown` | settings "When edits take effect" | the page lists no env behaviour; some variables are read once at start, which the docs do not enumerate |
| `settings.prompt_cache_ttl` | `unknown` | prompt-caching "Cache lifetime" | the page names promptCacheTtl and subagentPromptCacheTtl but does not say when an edit applies to a running session |
| `settings.enabled_plugins` | `unknown` | prompt-caching "Enabling or disabling a plugin" | depends on the plugin: its skills, commands, agents, hooks, monitors and themes keep the cache; plugin MCP servers follow the MCP rules; an LSP tool is added by code intelligence plugins |
| `mcp.config` | `applies_next_session` | prompt-caching "Connecting or removing an MCP server" | editing MCP config does not by itself change the cache; the new config takes effect only after a restart (disabling a server in /mcp mid-session is a different action) |
| `memory.claude_md` | `applies_next_session` | prompt-caching "Editing CLAUDE.md mid-session" | project-root and user-level CLAUDE.md are read once at start; editing keeps the cache but does not apply until /clear, /compact or restart |
| `memory.auto_memory` | `applies_next_session` | prompt-caching "How the cache is organized" | the project context layer (CLAUDE.md, auto memory, unscoped rules) changes when the session starts or after /clear or /compact |
| `file.other` | `unknown` | prompt-caching | no sentence covers this file or key |

Key mapping (`classify_setting`; `cache_effects.py table` prints the rows, and `cache_effects.py
effect setting <key>` classifies one key): `sandbox`, `sandbox.*` -> `settings.sandbox`; `model` ->
`settings.model`; `effortLevel`, `modelSettings` -> `settings.effort`; `outputStyle` ->
`settings.output_style`; `permissions.defaultMode`, `defaultMode` -> `permission.mode_default`;
`permissions.additionalDirectories` -> `permission.additional_directories`; `hooks`, `hooks.*` ->
`settings.hooks`; `env`, `env.*` -> `settings.env`; `promptCacheTtl`, `subagentPromptCacheTtl` ->
`settings.prompt_cache_ttl`; `enabledPlugins`, `enabledPlugins.*` -> `settings.enabled_plugins`;
`mcpServers`, `enabledMcpjsonServers`, `disabledMcpjsonServers`, `enableAllProjectMcpServers` ->
`mcp.config`; anything else -> `file.other` (`unknown`).
Files (`classify_file`): `CLAUDE.md`, `CLAUDE.local.md` -> `memory.claude_md`; `MEMORY.md` and
memory-directory files -> `memory.auto_memory`; `.mcp.json`, `.claude.json` -> `mcp.config`.
Permission rules (`classify_rule`): allow and ask keep; a deny that is a bare tool name, `Tool(*)`
or a tool-name glob (`*`, `mcp__*`) is the bare-tool family (the docs state `Tool(*)` equals the bare
name for Bash and PowerShell only, so other tools are classified conservatively, and the row says
so); other deny rules are scoped and keep; any `mcp__` rule with parentheses is skipped by Claude
Code when it loads settings, so it is `permission.mcp_parenthesized_rule` (`unknown`, no effect).
Nested `CLAUDE.md` and `paths:` rules load on demand (PC "Editing CLAUDE.md mid-session"); the table
does not model that and calls them root-level, so state the caveat when proposing one.

Where it shows:

- `apply_ops.py` (plan and apply) puts `cache_effect` on every op row; `prune_permissions.py` on
  every rule removal (`remove_rules[].cache_effect`) and on stale-directory removals
  (`remove_dirs_cache_effect`). Both accept `--snapshot` for tool-search state.
- Each proposal in the report states its cache effect in the finding text, from the table: for
  example "SEC-sandbox: sandbox keys, cache effect unknown (settings reload mid-session; PC silent)".

Estimate of one full re-read (`cache_effects.py estimate --snapshot S [--model M] [--ttl 1h]`,
also `cache_estimate` in helper output when an effect may invalidate): the conversation's cached
context (`transcripts.cache.context_tokens.median`, measured over deduplicated main-thread
responses; the TTL is the snapshot's majority cache-write TTL from `cache.write_1h_share`, else 5m,
and the model the top entry of `transcripts.request_params.main.by_model`, else the default 0.1x
read multiplier) at the cache-write multiplier instead of the read multiplier. Multipliers are the ones in
`checklist.md` (writes 1.25x on the 5-minute TTL, 2x on the 1-hour TTL; reads 0.1x, 0.05x on Opus
5.5 and Sonnet 5.5, 0.025x on Fable 5.1; docs fetched 2026-10-24). Output is in base-input-token
equivalents, labelled an estimate, with no prices. The median is over all responses, so it
overstates a short session and understates a long one; say so.
