# Audit checklist

Use it as a prompt for where to look, not as a form to fill in. Skip checks that don't apply,
and don't report a check that passed unless it has been resolved since the last run. Check IDs
(`SEC-…`, `COST-…`, `LRN-…`, `HYG-…`) prefix the finding `id` in audit.json. Field names refer to
the collector snapshot.

In a metadata-only snapshot (`coverage.privacy.mode`), mark these checks as follows and add a
caveat. **Partial:** SEC-risky-allow (flags and counts, no rule text; this covers every check keyed on
`permissions.risky` flags, including SEC-secret-literal and SEC-secret-env), SEC-sandbox (keys and
booleans only), SEC-hooks (type, matcher, origin, header keys, on_failure, background; no command or prompt),
COST-model-default (`model_settings` values masked), LRN-friction (categories, no details),
LRN-corrections (counts, no themes), LRN-duplicate-memory (file names only), HYG-missing-hook-script
(count only), and the rule-shape checks SEC-wildcard-placement, SEC-ineffective-deny and
HYG-shadowed-allow (rule text masked; flags, layers, paths and match kinds remain), and
HYG-plugin-footprint (plugin-written rule names masked; plugin names, counts, flags and enums remain).
**Not checked:**
SEC-docs-only-constraint, LRN-contradiction, LRN-enforce and the clarity pilot. **Unaffected:**
readiness, cost metrics and harness overhead.

## Security (`SEC-`)

- **SEC-risky-allow** (`permissions.risky` per settings file). Weigh by blast radius:
  - `wildcard-all`, `sudo`, `rm-recursive`
  - `network-wildcard` (`curl:*` enables exfiltration and download-and-run)
  - `interpreter-wildcard` (`python -c *` means arbitrary code)
  - `git-destructive` / `gh-api` (irreversible or outward-facing)
  - `docker` (root-equivalent on most hosts)

  Fix: remove or narrow the rule, and add `deny`/`ask` rules for the dangerous forms. When the
  same broad rule appears in many projects, propose one user-level rule instead.

  Model permissions and hooks as one evaluation, not two independent lists (verified against the
  permissions and hooks docs): deny and ask rules apply regardless of what a PreToolUse hook
  returns — an "allow" from a hook never overrides a matching deny or ask rule. A blocking hook
  (exit code 2) does take precedence over allow rules, stopping the call before they're evaluated.
  So an allow rule that looks risky in isolation may already be constrained by a blocking hook
  (check `hook_handlers` for a command hook on the same matcher before proposing a redundant deny
  rule), and a hook that looks protective doesn't substitute for a missing deny rule.
- **SEC-wildcard-placement** (`permissions.rule_shape_issues.allow`, static; permissions docs "Wildcard
  patterns", fetched 2026-09-30): allow rules whose `*` reaches further than the rule reads.
  - `wildcard-before-subcommand`: a `*` after only the program name, followed by a later word
    (`Bash(git * main)`, `Bash(git -C * status *)`). The `*` also matches options inserted there:
    `git -c core.fsmonitor=<script> diff main` makes git run a program. Claude Code (v2.1.246+) warns
    at startup when the later word is the subcommand; the collector can't tell a subcommand from an
    argument, so confirm before proposing. Fix: the exact value, or one rule per subcommand with the
    `*` after it (`Bash(git status *)`).
  - `wildcard-program`: `*` in the program position (`Bash(* --version)`) matches any program.
  - `star-joined-to-program`: no space before the trailing `*` (`Bash(ls*)` also matches `lsof`).
    Fix: `Bash(ls *)`.
  - `colon-star-literal`, `mcp-rule-with-parentheses`: the rule does nothing as written (hygiene).
  Weigh together with SEC-risky-allow: a flagged git, interpreter or network rule is worse.
- **SEC-ineffective-deny** (`permissions.rule_shape_issues.deny` / `.ask`, static): deny or ask rules
  Claude Code doesn't apply as written, so the block or prompt the user expects never happens.
  - `colon-star-literal`: `:*` only works at the end; in `Bash(git:* push)` the colon is literal
    and the rule matches no git command. Fix: `Bash(git push *)`.
  - `ignored-primary-field`: `Tool(param:value)` on a primary content field (`command`, `file_path`,
    `path`, `notebook_path`, `url`). The docs say these can't be matched this way; for
    `Bash(command:rm *)` they say Claude Code ignores the rule and warns at startup. Fix:
    `Bash(rm *)`, `Read(./path)`, `WebFetch(domain:host)`.
  - `mcp-rule-with-parentheses`: settings files skip `mcp__` rules with parentheses; parameter
    matching on MCP tools needs `--disallowedTools`.
  Other wildcard shapes in deny/ask match more rather than less (Claude Code refuses or prompts for
  the extra commands, errors docs), so they aren't flagged. Severity is high when the rule guards
  secrets or destructive commands.
- **SEC-deny-baseline**: there are no `deny` rules anywhere. Propose a small user-level baseline,
  verified against the permissions docs: reads of `.env` files, `~/.ssh`, `~/.aws`, credential
  files and `/proc/*/environ`, and force-push. Anchor paths with `//` or `~/` so they apply in
  every project; a single leading `/` anchors at the settings file's location.
- **SEC-secret-literal** (`secret-literal-in-rule`): a real token was baked into an allow rule
  when a command was approved. Confirm on the file (never copy the value), then rotate, delete the
  rule, and move the secret into env or a secrets manager.
- **SEC-secret-env** (`secret-via-env-file`): the rule pulls a key out of `.env` onto the command
  line, so it lands in transcripts. Lower severity. Fix: wrap the call in a script that reads env.
- **SEC-settings-in-git** (`projects[].git`): a `settings.local.json` that is `tracked`, or
  `untracked` rather than `ignored`, can leak approvals when pushed. `not-a-git-repo` isn't a finding.
- **SEC-auto-mode**: if `auto_mode_configured` is set, or sessions run unattended, raise the weight
  of risky allows and of a missing sandbox, because fewer actions reach a human.
- **SEC-sandbox** (`settings[].sandbox`): no sandbox configured despite autonomous or long
  sessions, or one that's configured but leaves a gap. Check platform prerequisites first
  (`/sandbox` lists missing dependencies). Filesystem and network isolation only protect together;
  a filesystem-only sandbox with unrestricted network access can still exfiltrate what it can read,
  and vice versa. Check specifically:
  - `sandbox.enabled` (or the platform equivalent) — missing entirely is the base finding
  - `sandbox.failIfUnavailable`: unset or `false` means Claude Code warns and *runs unsandboxed*
    when the sandbox can't start (e.g. bubblewrap missing on Linux) — worth flagging wherever
    `SEC-auto-mode` also fires, since that's exactly when silent unsandboxed fallback matters most
  - `sandbox.allowNestedUserNamespaces: true` (Linux/WSL2, 2.1.305+) turns off a security
    boundary: the docs say code from a sandboxed command can end up running outside the sandbox,
    so none of its restrictions can be relied on, and in auto-allow mode such a command runs
    without a prompt. High severity when it is `true` in user or managed settings (`--settings`
    JSON counts too, but isn't collected); a project `true` is ignored, so report that as
    ineffective rather than as exposure. `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1` ignores every
    `true`. For rootless Podman or Buildah the docs point to `excludedCommands` instead (settings
    reference, fetched 2026-10-24).
  - filesystem write/read exceptions and the network allowlist: broad entries undermine the
    boundary the sandbox exists for; note when a permission `allow` rule grants something the
    sandbox would otherwise have blocked, since that rule is now the only remaining control
  - Fix: change `sandbox.*` keys only via `apply_ops.py` (SKILL.md Step 5 item 7); keys it refuses
    stay blocked unless the user authorizes a manual edit.
- **SEC-hooks** (`hook_handlers`, `allow_managed_hooks_only`): hooks run with the user's
  permissions, but the boundary differs by handler `type` (verified against the hooks docs) —
  weigh each differently rather than reporting all hooks generically:
  - `command`: local execution boundary. Flag ones that fetch remote code, write outside the
    project, or match every tool with a slow command.
  - Guards fail open by default: when a `command` or `http` hook can't start, times out or exits
    with an unexpected code, the action goes ahead on most events. For a `PreToolUse` or
    `PermissionRequest` hook that exists to block something, propose `"onFailure": "block"`
    unless `on_failure` already says `block` (hooks docs "Block the action when a hook fails",
    fetched 2026-10-24; Claude Code 2.1.295+). Don't propose it for loggers or formatters: a
    broken one would then block every matching call. It has no effect on background hooks
    (`background`, i.e. `async`/`asyncRewake`) or on `Stop`, `SubagentStop`, `TaskCompleted` and
    `TeammateIdle`; a `block` set there is `on_failure_no_effect` (HYG-hook-config).
  - `http`: a network egress point — every matching event's JSON is POSTed to that URL. Flag an
    unfamiliar host, a matcher wide enough to send most tool calls, and whether `header_keys` /
    `allowed_env_vars` on the handler (names only, never values) suggest a secret is being
    interpolated into the request.
  - `prompt` / `agent`: another LLM trust boundary. The hook's own `prompt` text is untrusted-in
    reverse — it's instructions the *hook* sends to a model, so treat a hook prompt built from
    unsanitized tool input the same way `SEC-risky-allow` treats an unsafe command: something that
    can be steered by whatever text it's fed.
  - `mcp_tool`: only as trustworthy as the target server; cross-reference `SEC-mcp`.

  If managed settings don't set `allowManagedHooksOnly`, any project can add its own hooks of any
  type, including `http` — mention this once per audit rather than per hook when it's unset.
- **SEC-mods** (`extensions.plugins[].components[].mod`, `settings[].mods`; mods overview "What a
  mod can reach", mods-admin "Review what a mod can do", fetched 2026-10-25): a mod is a plugin
  whose `hooks/hooks.json` has `modules`. Its module runs unsandboxed with the user's permissions,
  so weigh `mod.calls` and `mod.events` (names from a heuristic text scan, never executed):
  - calls: `fs.read` / `fs.write` (files), `process.run` / `process.spawn` (commands),
    `http.fetch` (network egress), `env.get` / `env.set` (environment, possible secrets),
    `settings.read`, `mcp.call`, `model.complete` (spends tokens), `prompt.submit` and
    `session.send` (acts as the user). A `process.*` or `http.fetch` call next to `fs.read` or
    `env.get` is the exfiltration shape; a read-only status panel is not.
  - events: `tool.call` (can inspect or change tool use), `tool.check` (can approve a call, past
    `ask` rules unless managed settings or a Team/Enterprise login apply), `prompt.submit`,
    `session.append` (sees the conversation) and `settings.read` (can rewrite merged settings:
    the collected files are then not the effective settings, see coverage).
  - Guard options (mods-admin "Set options on the built-in guard", fetched 2026-10-25) are read
    only at `pluginConfigs["cc-plugin-sec-default@builtin"].options` and only from managed settings;
    `settings[].mods` records them as `true`/`false`/null (unset or non-boolean) for managed files only.
    - `allow_managed_mods_only` true stops user-installed mods from loading. When it is not true,
      mention that once per audit, and only when a mod is installed or managed settings exist.
    - `allow_mods_override_deny_rules` true in managed settings is a finding: a user's mod that
      approves tool calls can approve a call a `deny` rule refuses, so deny rules no longer bind mods.
    - `prepend_names_guard` false (a managed `prependPlugins` list without `sec-default@builtin` or
      `cc-plugin-sec-default@builtin`): the guard does not load, so neither option applies.
    - `guard_options_ignored` true (HYG note, not protection): a user, project or local file carries the
      guard entry, which neither sets nor loosens an option. Its value is deliberately not recorded.
    - `prepend_plugins` / `append_plugins` change plugin load order; report presence only.
  - The scan is heuristic: names can include extras from comments or strings, member calls such as
    `child.on(...)` are skipped but indirect or dynamic use is missed, and a mod with `reason`
    (`outside_plugin_root`, `not_regular_file`, `absent`, `unsupported_extension`,
    `unreadable`, `invalid_modules`) was not read, and `mod.truncated` means a cap cut the scan. For the authoritative list tell the user to run
    `claude plugin validate <dir>` themselves; collection never runs it.
- **SEC-mcp**: unknown servers, servers with write access to external systems, and unpinned
  `@latest` packages. See `SEC-mcp-exposure` for per-server exposure fields.
- **SEC-mcp-exposure** (`extensions.mcp_servers[]` exposure fields, `policy_observations`,
  `settings[].mcp_policy`; static, never connected, no values stored). Weigh, citing field and
  source:
  - `headers_literal_keys` / `env_literal_keys` on a `project` server whose `file_git_status` is
    `tracked`: a committed credential is likely. Confirm on the file (never copy the value), then
    propose moving the value out of `.mcp.json`: reference an environment variable (`${VAR}` in
    `headers`/`env`) or use `headersHelper`, and rotate the credential if it was committed. This
    is MCP-specific; `SEC-secret-literal` covers tokens in allow rules, not this.
  - `url_has_userinfo` or `url_has_query` on a remote server: a credential may sit in the URL.
    Prefer headers with `${VAR}` references. Credential variables such as `ANTHROPIC_API_KEY` in a
    remote `url`/`headers` read as empty (mcp.md), so `url_variable_references` naming one means a
    broken server, not a leak.
  - `plaintext_transport`: tokens and tool traffic in cleartext to a non-loopback host.
    Recommendation-level; the docs do not rate it.
  - A `project` server with a `policy_observations` kind `approval_enable_all` or
    `approval_enabled`: any server a teammate adds to `.mcp.json` loads. In `claude -p`, SDK and
    cloud sessions, project servers load without asking (mcp.md). Propose
    `disabledMcpjsonServers` for unwanted ones. Committed approvals are ignored in an untrusted
    folder, so cite `project_trust_accepted`.
  - `credential_mechanisms` containing `headersHelper_configured` on a `project` server: a
    repo-supplied shell command that runs once the folder is trusted ("arbitrary shell command",
    mcp.md).
  - `permission_allow` (or `permission_allow_any_server`) observations on a server that writes to
    external systems: calls run without a prompt. `mcp__*` in allow is skipped by Claude Code;
    rule validity is reported by the permission-rule checks, not here.
  - Allowlist posture, once per audit and only in an organization context: `allowedMcpServers`
    without `allowManagedMcpServersOnly` merges user allowlists, and a `serverName` entry "is not
    a security control" (managed-mcp.md). `serverUrl`/`serverCommand` entries are not evaluated
    here, so never claim a server is unrestricted without checking them.
  - `oauth_scopes: null` on a sensitive remote service: suggest pinning `oauth.scopes`, the
    documented way to restrict a server.
  Cross-check reliability through `tool_prefix` = `transcripts.tool_errors.by_mcp_server[].server`.
- **SEC-install**: a failed auto-update (`global.last_update`), or a version far behind the changelog.
  Version/doctor probes are not run during collection. Assess version lag only with an
  already-supplied version observation; unavailable diagnostics are not installation failures.
- **SEC-docs-only-constraint**: sensitive-data rules stated only in CLAUDE.md or auto-mode text and
  not enforced by `deny` rules.

## Cost & context (`COST-`)

- **COST-baseline** (`transcripts.context_baseline_tokens`, measured): real tokens loaded before
  the first answer. Compare the median across projects
  (`context_baseline_by_project_median`, ≥3 sessions each). A project well above the user's median
  points at its CLAUDE.md, rules, MCP servers or plugins. Report tokens × sessions per month.
- **Drift log** (`drift_signals`, measured, only when the snapshot has it): cite each signal's
  crossings with their dates as evidence under `COST-claude-md-size`, `COST-cache-health`,
  `SEC-risky-allow`, and `COST-harness-overhead` / `COST-startup-hooks`. A crossing alone is never a
  proposal. The current snapshot value outranks a logged one. `status: invalid` means the log could
  not be read. See `drift.md`.
- **COST-model-default** (`global.settings[].model`, `model_settings`, `usage.stats_lifetime_by_model`;
  `transcripts.request_params` `by_model` / `by_effort` are observed, undocumented evidence of what
  requests actually carried, null effort meaning none was sent):
  a top-tier 1M-context model as the default for mostly mechanical work. Options: `opusplan`, a
  cheaper default with per-task switching, or `CLAUDE_CODE_SUBAGENT_MODEL` for subagents. Quote
  exact values from `model-config`.
- **COST-long-sessions** (`usage.heaviest_sessions`, `daily_token_totals_recent`): marathon sessions
  near the context ceiling re-send huge contexts on every turn. Suggest `autoCompactWindow` (a
  number), `/clear` plus handoffs between phases, or background runs. Since 2.1.288 `/autocompact`
  saves the window per model (changelog 2.1.288; `modelSettings.<model>.autoCompactWindow` wins over
  the top-level key for that model, settings reference fetched 2026-10-24), so check
  `model_settings` before proposing a global number: a per-model value may already override it.
- **COST-claude-md-size** (`claude_md_lines`, `claude_md_tokens`, estimated): over the docs' target
  (~200 lines). Fix by moving area-specific guidance into nested CLAUDE.md or path-scoped
  `.claude/rules/`, and procedures into skills. `@imports` still load at launch, so they don't save
  context. Apply only with the split protocol in SKILL.md.
- **COST-memory-index** (`memory.by_project[].index_lines`): only the first 200 lines / 25KB of
  MEMORY.md load, so a larger index silently drops entries.
- **COST-mcp-unused** (`transcripts.mcp_configured_but_unused`, bounded observation): these
  legacy user/project names have no observed calls in the scanned records. Check transcript
  coverage and `extensions` provenance/activation before drawing conclusions. Empty global-scope
  transcript scans provide no usage evidence. Propose removal only with additional evidence that
  the server is unnecessary; lack of calls alone is not enough. Preserve deliberate standby tools.
- **COST-skill-listing** (`skill_listing`, excerpt-size observation): verify runtime activation,
  `skillListingBudgetFraction` and `skillListingMaxDescChars` against current settings and docs
  before claiming listing overflow. Collected excerpts do not establish the effective budget or
  description folding. Recommend trimming only when actual listing pressure is established.
- **COST-startup-hooks** (`harness_overhead.injected_context`, measured; fallback
  `global.plugin_session_start_hooks`, `basis: using_skill_file_size_guess`, or `not_measured`
  with no estimate): context injected by hooks per session. Use the measured source rows when any
  session in the window has them, and say which basis you used. The fallback is a guess shaped
  after the superpowers plugin (the size of its `skills/using-*/SKILL.md`); for any other plugin
  it is absent, not zero.
  Each source row also carries `chars_max` and `over_cap` (characters of the injected text; the
  cap is applied per JSON field, hooks docs "Hook output"): hook output (`additionalContext`,
  `systemMessage`, plain stdout) is capped at 10,000 characters, and a larger one is written to a
  file for Claude with a 2,000-character preview (hooks docs "Hook output", fetched 2026-10-25;
  `injected_context.output_cap_chars`). A non-zero `over_cap` means the plugin's own text is being
  cut; a transcript may keep only the preview, so zero is not proof. `hook_stdout` lists printed
  hook output per plugin, event and `kind`: `plain` rows are whole-stdout sizes (the cap applies to
  the whole text); `json` rows are the same injections the source rows already count, sized by the
  largest capped field of the object. Do not add `hook_stdout` counts to the source rows' counts;
  use `plain` rows for hooks that print without injecting. Evidence: plugin (or `ambiguous`/`unattributed`), event, sessions and median
  estimated tokens per session (chars/4). SessionStart re-fires on `startup`, `resume`, `clear`,
  `compact` and `fork` (https://code.claude.com/docs/en/hooks.md, fetched 2026-09-29), and its
  `additionalContext` is added to context before the first prompt.
- **COST-harness-overhead** (`harness_overhead`, measured and static): judge together
  - skill listing growth (`skill_listing_series` first -> last, and `last.chars` against the
    documented listing budget: 1% of the model's context window, raised by
    `skillListingBudgetFraction` or `SLASH_COMMAND_TOOL_CHAR_BUDGET`, each entry capped at 1,536
    characters by default, configurable with `skillListingMaxDescChars`; https://code.claude.com/docs/en/skills.md, fetched
    2026-09-29), with `per_plugin_skills` naming the largest contributors;
  - `model_spawning_hooks`: an enabled plugin hook that runs `claude -p`, the Agent SDK or the
    Anthropic API spends tokens outside the session; cite file, line and pattern id;
  - `subagent_spend`: subagent median tokens per session against
    `main_tokens_median_in_subagent_sessions` (main tokens of the same sessions), not the
    all-session `main_tokens_per_session_median`, which mixes in small SDK runs;
  - the listing series covers non-SDK sessions only (`sdk_sessions_excluded` counts the rest).
  `entrypoints` are shares only: never call SDK sessions "reflection" or attribute them to a plugin
  or hook. Treat `complete: false` and its `incomplete_reasons` as limits on every claim. Record
  metrics `skills.listing_count` (unit `skills`), `skills.listing_chars` (unit `chars`) and
  `hooks.injected_tokens_per_session_median` (unit `tokens`, basis `estimated`), all with
  `source: harness_overhead.<field>`, so the next audit gets deltas.
  `hooks.injected_tokens_per_session_median` is the `est_tokens_per_session_median` of the first
  `injected_context.sources` row (rows are sorted by sessions descending, so the most frequent
  source); name that row's plugin and attribution in the evidence. Under global scope
  (`transcripts_not_read`) only `model_spawning_hooks` is observed; record no transcript metrics.
- **COST-subagents** (`usage.subagent_session_share`, Agent tool counts, `transcripts.subagent_models`
  and `request_params.agent`; the transcript fields are measured but read undocumented shapes): many
  small agents re-reading context, or a top-tier model on mechanical agents. `tokens` is volume
  (input + cache creation + cache read + output), not spend, and cache reads usually dominate it while
  billing at a fraction of base input (0.1x; see `COST-cache-health`). Judge cost on
  `tokens - cache_read_tokens` (input + cache writes + output) and never present either number as a
  share of spend. Name how many subagent tokens ran on a top-tier model (`rows[].actual_model`) and
  why, from `requested_model` (the sibling meta file's `model` value):
  - A model name (e.g. `opus`): Claude passed it for that call. The per-invocation parameter outranks
    everything except a mod's `agent.spawn` hook. Fix: CLAUDE.md guidance on when to pass `model`, or
    `CLAUDE_CODE_SUBAGENT_MODEL_FORCE=1` together with `CLAUDE_CODE_SUBAGENT_MODEL` set to the wanted
    model (FORCE alone runs subagents on the main model), which makes Claude unable to pass one.
  - `inherit`, usually `agent_type: fork`: a fork, which runs on the main model. It is not a per-call
    choice of Claude's, and `_FORCE` does not change it.
  - Null with a cheaper `actual_model`: the definition's `model:` frontmatter or
    `CLAUDE_CODE_SUBAGENT_MODEL` applied; the snapshot cannot say which.
  - Null with the main model's `actual_model`: no frontmatter `model:` (or one set to `inherit`) and no variable; built-in
    Explore and Plan ignore the variable, and forks inherit the main model. Fix for custom or plugin
    agents: frontmatter `model:`; for Explore and Plan: `_FORCE=1` (with the variable set).
  - `configured.model_env` true with top-tier rows is the case to explain: since 2.1.251 the variable is
    only a default, below the per-call parameter and frontmatter; without `configured.force_env` it
    changes neither.
  Source: sub-agents "Choose a model" and "Run every subagent on one model", fetched 2026-10-25.
  `request_params.agent` shows the effort and thinking mix of those requests; cite it, don't threshold it.
- **COST-tool-errors** (`avg_tool_errors_per_session`, `tool_error_categories`): every failed call
  is a paid retry. Recurring categories point at missing commands in CLAUDE.md or a missing script.
  Prefer `transcripts.tool_errors` (see `COST-tool-error-clusters`) when present.
- **COST-tool-error-clusters** (`transcripts.tool_errors`, measured; categories heuristic): cite
  `by_tool` and `by_mcp_server` counts, never error text (none is stored). Separate `denied`
  (permission prompts refused or rules denying) from failures; `failure_rate` already excludes
  them and is `null` under `min_calls_for_rate` calls.
  - An MCP server with `failure_rate` >= 0.2 over >= 20 calls and mostly `auth`/`connection`:
    fix authentication or configuration (`claude mcp get <name>` shows an `Issue:` line), or
    propose removal together with its `SEC-mcp-exposure` fields. The thresholds are a
    recommendation.
  - Bash `sandbox`: sandbox prerequisites (`SEC-sandbox`), not the commands.
  - `nonzero_exit` clusters: missing run or test commands (`RDY-test-loop`, CLAUDE.md).
  - `file_state` recurring: an edit-before-read habit; an `LRN-` pattern if it spans 3+ sessions.
  - `validation`: malformed tool calls; check for a tool or server whose schema confuses the model.
  `error_results_unmatched` and `results_without_is_error` bound the evidence; say so when large.
- **COST-cache-health** (`transcripts.cache`, measured; `transcripts.request_params[*].cache_breakpoints`
  adds observed, undocumented TTL counts per source class, `5m` including breakpoints with no `ttl`): Claude Code places cache points itself, so
  there's no `cache_control` to set. What the user controls is the cache lifetime (TTL) and the
  habits that break the cache.
  - `hit_ratio` (reads / (reads + writes)) above ~90% is healthy; say so and move on.
  - `write_1h_share`: Claude Code uses the 1-hour TTL for the main conversation only within a
    subscription's included usage. Usage credits, API keys, subagents and cloud providers get 5
    minutes. Writes cost 1.25× base input on the 5-minute TTL and 2× on the 1-hour TTL, while
    reads cost 0.1×.
  - `big_rewrites` by cause:
    - `gap_5_60m` large on credits or an API key: propose `promptCacheTtl: "1h"` (and
      `subagentPromptCacheTtl` if subagents idle that long). The 2× writes only pay off for
      pauses in the 5–60 minute range.
    - `gap_over_60m`: no TTL helps; suggest `/clear` plus a handoff instead of resuming huge contexts.
    - `after_model_change`: `/model` or fast-mode switches mid-session re-read everything; switch
      at task boundaries.
    - `after_compaction`: compaction rewrites the conversation cache by design. Weigh it against
      `autoCompactWindow`: a smaller window means cheaper turns but more rewrites, so compare with
      the previous audit's metrics.
    - `unexplained` large: suspect MCP servers connecting or disconnecting while tool search is off,
      or effort changes on older models (see the prompt-caching docs' invalidation list).

  - Idle compaction (`idleCompaction`, Claude Code 2.1.290+; settings reference fetched 2026-10-24):
    on by default in an interactive session on the 1-hour TTL once context reaches 200,000 tokens
    (`CLAUDE_CODE_IDLE_COMPACT_MIN_TOKENS`, floor 100,000) and about 54 minutes idle: it compacts
    shortly before the cache expires, so the return trip sends a summary instead of rewriting the
    whole conversation. It is a lever for `gap_5_60m`/`gap_over_60m` rewrites of big contexts when the
    user is on the 1-hour TTL; if a settings file sets `idleCompaction: false` (or
    `DISABLE_AUTO_COMPACT`/`autoCompactEnabled` is off) ask why before leaving it off. It needs
    feature-flag fetching and doesn't apply on the 5-minute TTL.

  Quote exact setting names and values from `settings-reference` / `prompt-caching`.

  Cache effect of every proposal (`references/cache-effects.md`, docs fetched 2026-10-25): state
  it in each proposal, from the table. Inform only; never hold or reorder a change for it.
  Mid-session edits to allow, ask and scoped deny rules keep the cache; a bare-name or
  tool-name-glob deny keeps it when tool search is active and invalidates it otherwise
  (`transcripts.tool_search_observed` labels this, hedged when none was seen); `model`,
  `effortLevel`, `modelSettings` and MCP config reach the running session only at the next session
  start (restart); CLAUDE.md and auto-memory edits apply after `/clear`, `/compact` or restart, and
  keep the cache meanwhile; sandbox, hooks and env edits are `unknown`. Where a
  change may invalidate, add the re-read estimate (`cache_effects.py estimate`): about the median
  cached context (`transcripts.cache.context_tokens`) at the write multiplier instead of the read
  multiplier, labelled an estimate.

## Learning from repeated mistakes (`LRN-`)

Only patterns count: the same signal across 3+ sessions or 2+ projects. Pick the lightest
mechanism that will hold (memory < CLAUDE.md / path-scoped rule < hook < skill), and record the
metric that motivated it, so the next run can check whether it moved.

- **LRN-friction** (`usage.facet_friction`, `facet_friction_details`; needs `/insights`). Map each category:
  - `buggy_code` → test-first rule plus a PostToolUse hook running a fast, file-relevant test subset
  - `environment_issue` → preflight script or hook (ports, venvs), plus a "how to run" section
  - `tooling_failure` / `external_service_error` → checkpointing and progress files for long runs
  - `wrong_approach` / `misunderstood_request` → upfront question batch or plan mode for large tasks
- **LRN-corrections** (`corrections.samples`, `by_project`): cluster correction prompts by theme and
  quote 1–2 short samples. A theme across projects belongs in `~/.claude/CLAUDE.md` or `~/.claude/rules/`.
- **LRN-interruptions** (`usage.most_friction_sessions`): user interruptions mark where Claude went off
  track. Look at the task types involved.
- **LRN-duplicate-memory** (`memory.similar_across_projects` is a filename hint only; also read
  `entries[].description`): conventions re-learned per repo. Promote them to user scope and delete
  the duplicates, but keep memories that carry project-specific incidents or detail.
- **LRN-contradiction**: two active instruction surfaces that disagree (global vs project CLAUDE.md,
  CLAUDE.md vs a rule, prose vs `package.json`/CI). Executable manifests outrank prose. Propose one
  canonical statement. If conventions really differ per repo (e.g. commit trailers), make the
  global rule defer, or give enforcement hooks a per-repo opt-out. An `AGENTS.md` in the inventory
  is an observation, not proof it is loaded (`contexts[].agents_md_present`,
  `agents_md_setting_observed`): with a CLAUDE.md family file in scope, Claude Code reads it only when
  `instructionFiles` allows or the CLAUDE.md imports it. Do not call an AGENTS.md/CLAUDE.md conflict
  active without saying this.
- **LRN-enforce**: a rule that exists in CLAUDE.md but keeps being violated (it recurs in corrections
  or friction) should become a hook.
- **LRN-effectiveness** (`trend.ledger` from the ledger; report-level `applied` + `metrics` only
  for fixes applied before the ledger existed). Act on processor proposals: escalate after two
  consecutive `not_dropped` verdicts, retire quiet memory/rule entries. A verdict is not causal
  proof.
- **LRN-failure-loops** (`transcripts.failure_loops`, measured counts; thresholds in `thresholds`). A turn
  (real user prompt to the next, main thread) that repeats one failing Bash command (`repeat_error`) or
  edits one file and fails the tests again (`edit_test`) 3 or more times. Evidence is counts only: `turns_with_loop`
  of `turns_scanned`, `by_kind`, `max_repeats`, `command_heads` (first token, e.g. `pytest`, `npm`; `other` when not an
  identifier), `by_project`; command text and file paths are not stored, so ask the user which commands, or read the
  repo's test setup, before proposing. Weigh by `tokens_in_loop_turns` against `tokens_scanned` (volume incl.
  cache reads, not spend); propose only when loops recur in 3+ sessions or 2+ projects (`sessions_with_loop`,
  `by_project`), and skip a single outlier. Lightest durable fix that fits the cause:
  - the loop's command fails for an environmental reason (missing variable, service, wrong interpreter): an
    environment fact in the repo's CLAUDE.md ("run tests with ...; needs X"), or `RDY-env-*`;
  - `edit_test` on a slow or broad suite: `RDY-test-loop` (a fast subset target, a file-relevant test script);
  - the same mistake each time: a PreToolUse or PostToolUse hook that runs the right command, per `LRN-enforce`.
  Never propose a runtime intervention (interrupting or redirecting a turn): the audit sees the pattern after the
  fact only. The sibling idea is TokenEconomizer's turn-duration redirect (microsoft/TokenEconomizer, as summarized in
  the 0.12.0 plan, not re-fetched); this check uses repetition counts, not durations. Plugin-spawned sessions are excluded. Record the metric (ledger
  selector `{"type": "failure_loops", "kind": ...}`) so the next run can show whether loops dropped.

## Hygiene (`HYG-`)

- **HYG-settings-shape** (`settings[].shape_issues`, key paths only): a value of the wrong type,
  e.g. `permissions` that isn't an object or a `deny` list holding a non-string. The collector
  drops it and reads the rest. Claude Code either skips the entry (Settings Warning) or the whole
  file (Settings Error) and offers to continue without it; `-p` runs skip it silently (settings
  docs "Fix a broken settings file", fetched 2026-10-24). Which one happened isn't observable here,
  so ask the user to check `/status` or `claude doctor`. High severity when the key is
  `permissions` or `hooks`, since the skipped part can be a deny rule or guard hook; managed files
  keep enforcing the rest (`coverage` reason `invalid_entries`).
- **HYG-scope-ignored** (`settings[].scope_ignored_keys`, `settings[].ignored_env_keys`, static,
  names only): a setting or `env` variable in a file where Claude Code ignores it, so it does
  nothing there. Say so as an ineffective setting, not a security finding, and propose moving it to
  the file that works (or removing it). Which file works comes from the key's documented scope
  (settings reference, key table "Scope" column and each key's **Scope** line, fetched 2026-10-24):
  - `user_or_managed` is honoured in user and managed settings only, so a project or local file
    ignores it (`axScreenReader`, `autoMode`, `modelPicker`, `skipAutoPermissionPrompt`,
    `forceLoginGatewayUrl`, `processWrapper`, `prependPlugins`, `appendPlugins`, `sshConfigs`,
    `sandbox.network.strictAllowlist`, ...). `user` (`worktree.location`) is user-only.
  - `managed` is honoured in managed settings only (the page: "Claude Code ignores the key in user,
    project, and local settings"), so even a user file ignores it. Either an admin deploys it or
    the line is dead.
  - `global_config` keys (`claudeInChromeDefaultEnabled`, `autoConnectIde`, ...) live in
    `~/.claude.json`; every settings file ignores them.
  - `user_local_managed` (`syncClaudeAiSkills`, `syncClaudeAiPlugins`, `useAutoModeDuringPlan`,
    `skipDangerousModePermissionPrompt`) is ignored in the shared project `.claude/settings.json`
    only, so the personal `settings.local.json` is the right place.
  - `ignored_env_keys[].reason`: `project_local` = dropped from project and local settings (the
    "Variables Claude Code ignores in `env`" list: storage directories, `XDG_*`, `CLAUDE_AX_*`,
    process wrapper and sync variables, the telemetry exporter group from Claude Code 2.1.282, the
    dialog timer and `CLAUDE_CODE_DISABLE_ATTACHMENTS` from 2.1.290); `every_file` = ignored from every
    settings file, user included (hosting-environment identity variables, `CLAUDE_CODE_RESTRICTED`, ...);
    `telemetry_unless_off` = the exporter selectors and `OTEL_LOG_USER_PROMPTS`/`_TOOL_CONTENT`/`_TOOL_DETAILS`:
    ignored in project and local settings unless the value turns telemetry off (`none`, `0`). Values
    aren't collected, so say "ignored unless it turns telemetry off", never that it was definitely
    dropped; `ignored_if_1` = `CLAUDE_CODE_ENABLE_CFC` or `OTEL_LOG_MANAGED_SETTINGS` set to `1` is ignored there (env-vars page,
    fetched 2026-10-24), other values apply. Claude Code logs the dropped ones in `claude --debug`
    and lists them in `/status` or `claude doctor`; a `-p` run shows no notice.
  - Managed files are never flagged. A key missing from the table isn't judged. Unmeasured: whether
    `--settings` or the launch environment also sets the value.
  - SEC note: a repository file (project or local) that sets telemetry exporters or
    `OTEL_LOG_RAW_API_BODIES` is an attempt to export session content from whoever opens it. Claude
    Code drops these (exporters from 2.1.282, the raw-body and beta-tracing variables from 2.1.251), so the
    setting is harmless on current versions; still tell the user who added it, and check which
    version ran if it is older.
- **HYG-missing-hook-script** (`missing_hook_scripts`): a hook points at a file that doesn't exist.
  High severity for PreToolUse, because it can block every call.
- **HYG-dead-refs** (`claude_md_dead_refs`): CLAUDE.md names paths that don't exist. Before reporting,
  check whether the path is generated or gitignored (e.g. `data/`, `eval/results/`), since that isn't
  a dead reference.
- **HYG-one-off-rules** (`one_off_rules`, allow count > ~50): old exact-command approvals that hide
  the risky rules. Prune them with `prune_permissions.py --remove one-off`.
- **HYG-stale-dirs** (`missing_additional_dirs`): directories that no longer exist, or paths from
  another machine or user.
- **HYG-worktrees** (`is_worktree_copy`): many stale worktree copies of CLAUDE.md.
- **HYG-hook-duplicates** (`config_conflicts.hook_duplicates`, static): the same handler (event,
  matcher, whole handler object; `fingerprint` joins to `hook_handlers[].fingerprint` for the
  redacted command) in several places of one stack. Per the hooks docs (fetched 2026-09-30), the
  same handler in more than one settings file runs once (`effect: deduplicated`: clutter, low); a
  plugin's copy stays separate (`separate_copies`: it runs twice, double cost and side effects,
  medium, higher on `PreToolUse`/`SessionStart`); `same_file`: the docs don't say, report as
  clutter. Fix: drop the settings copy when a plugin provides the hook. Under
  `allow_managed_hooks_only` or `disableAllHooks`, check which copies actually run first.
- **HYG-shadowed-allow** (`config_conflicts.permission_overlaps`, static): an allow rule that a
  deny or ask rule in the same stack always matches first. Rules are evaluated deny, then ask, then
  allow, across every scope (permissions docs), so the allow never takes effect: with `by.list: deny`
  the call is blocked; with `ask` it still prompts (the usual cause of "I said don't ask again and it
  still asks"). `match`: `exact`, `tool` (a bare or tool-glob rule) or `prefix` (a Bash trailing
  wildcard). Only provable coverage is reported; path globs and mid-rule wildcards aren't compared,
  and equal text isn't taken as coverage for a non-Bash `!` specifier (gitignore negation denies
  nothing), a single-`/` path across different settings files (each anchors at its own directory),
  or a tool whose deny/ask lists in that file hold a `!` rule. A Bash deny shaped like an input
  parameter (`Bash(timeout:*)`) is compared by raw text only. Absence isn't proof. Fix: remove the
  dead allow, or narrow the deny/ask if the allow was intended; never propose loosening a managed
  rule.
- **HYG-hook-config** (`hook_handlers[].issues` / `unknown_fields`, the same fields on
  `extensions.plugins[].components[].handlers[]`, static; hooks docs fetched 2026-10-24): hook
  configuration that doesn't do what it reads.
  - Never fires: `unknown_event` (not a documented event; check case, e.g. `pretooluse`),
    `if_never_runs` (`if` on a non-tool event), `mcp_server_only_matcher` (`mcp__server` without
    `__.*` is compared exactly and matches no tool).
  - Fires more than intended: `matcher_ignored` (a matcher on an event without matcher support is
    silently ignored, so the hook runs on every occurrence), `narrow_event_regex_path` (a
    `StopFailure` matcher with a comma, space or hyphen is a regex, not a list; only `|` separates).
  - Unclear: `invalid_regex` (doesn't compile; checked with Python `re`, JS-only constructs skipped;
    what Claude Code does with it is undocumented, so say "invalid", not "ignored"),
    `timeout_suspect_ms` (`timeout` above 600: the field is seconds and 600 is already the
    default for command, http and mcp_tool hooks, so a value such as 5000 or 10000 was almost
    certainly written in milliseconds and sets no useful limit; hooks docs "Hook handler fields",
    fetched 2026-10-25; a hung hook can then hold the event for well over an hour, so propose the intended number
    of seconds; not reported for `async: true` command hooks, whose timeout Claude Code does not
    enforce, or for `SessionEnd`, whose hooks share a 1.5-second budget), `matcher_not_string`, `unknown_type`, `unknown_fields` (not in the documented fields for that
    handler type; name the field, don't claim it's ignored), `invalid_on_failure` (`onFailure` on a
    `command`/`http` hook that is neither `"continue"` nor `"block"`), `on_failure_no_effect`
    (`"block"` on a background hook or an event where it does nothing; the hook still fails open).
  A guard that never fires (a `PreToolUse` or security hook) is high severity; the rest is hygiene.
- **HYG-plugin-footprint** (`settings[].plugin_written_rules`, `settings[].plugin_markers`,
  `global.plugin_state` / `projects[].plugin_state`, hook handlers' `decides_permissions` /
  `rewrites_input`, `transcripts.plugin_spawned`; generic signals plus a table of file and key
  fingerprints dated 2026-10-25, plugin sources surveyed that day): what plugins do outside
  their own files, attributed so the user can see and undo it. Report only what the snapshot
  shows, name the plugin, and never call a plugin's behaviour a defect by itself.
  - **Rules a plugin wrote.** `plugin_written_rules` (`plugin`, `list`, `rules`, `rule_count`,
    `ledger_only`) means TokenEconomizer's own ledger (`~/.tokeneconomizer/**/untool_applied.json`)
    lists this settings file and the listed bare-name `deny` rules are in it; `ledger_only` counts
    listed rules the file no longer holds. These are not the user's hand-written policy: say so in
    SEC findings that cite the deny list, do not propose removing them (the plugin writes them
    again; `prune_permissions.py` only removes allow rules and never touches deny rules), and note they can make a
    tool unavailable that the user expects (a denied bare tool name). Only the default directory is
    read, not `$TOKENECONOMIZER_HOME`.
  - **Auto-approve markers.** `plugin_markers: ["quartermaster.autoApprovePermissions"]` means
    that plugin's opt-in feature appends `allow` rules to this file after repeated approvals.
    Individual rules are not attributable, so an allow list in a marked file is partly
    machine-written: weigh `SEC-risky-allow` there with that in mind and expect pruned rules to
    return. `prune_permissions.py` flags such files (`plugin_note`) but still lists the rules.
  - **State files.** `plugin_state` booleans (`ralph-loop`, `hookify`, `auto-memory`,
    `autoharness`, `claude-hud`) say a plugin's state file or directory exists; contents are
    never read. They explain behaviour (a Stop hook that keeps a session going, hook rules living
    in `.claude/hookify.*.local.md`), they are not findings.
  - **Hooks that decide or rewrite.** A plugin handler on `PermissionRequest` decides permissions
    by definition (`decision_basis: permission_request_event`). A `PreToolUse` handler whose
    command line or plugin-local script text contains `permissionDecision` `"allow"`/`"deny"`
    sets `decides_permissions`, and `updatedInput` sets `rewrites_input` (`decision_basis:
    static_scan`, `decision_file` names the script). The scan is a heuristic text match over at
    most 64 KiB per script inside the plugin root, never executed, sourced scripts not followed.
    It matches `permissionDecision` allow/deny, the deprecated top-level `"decision"`
    `approve`/`block`, and exit code 2 (which blocks a `PreToolUse` call; hooks docs "Exit code 2
    behavior per event"), so a script that merely exits 2 on an internal error can be flagged.
    Scripts are found by absolute plugin-root path or, after `cd "$CLAUDE_PLUGIN_ROOT" &&`, by
    relative path. `scan_gap` (`script_unresolved`, `script_truncated`, `no_local_script` for a
    command such as `npx -y pkg hook` that names no plugin-local script) means part of the logic
    was not read. A missing flag is never evidence that a hook does not decide or rewrite. These decisions do not appear in any rule list. Per the
    hooks docs, a hook's `allow` does not override deny or ask rules, and `updatedInput` replaces
    the whole tool input and is what permission rules are then checked against (hooks docs
    "PreToolUse decision control", fetched 2026-10-25). Fail-open behaviour is not a finding here:
    it stays with SEC-hooks and only for hooks that exist to guard.
  - **Spawned sessions.** `transcripts.plugin_spawned` counts sessions whose working directory is
    one a known plugin runs Claude in (claude-mem observer sessions under
    `~/.claude-mem/observer-sessions`). Their tokens are in every cost total, so name them when
    they are a large `tokens_spawned / tokens_total` share, and propose the plugin's own setting if
    it has one. They are excluded from tool-error counts, corrections, friction and the context
    baseline, so do not treat their absence there as clean. Plugins that spawn sessions without a
    trace in the files the collector reads (remember's nested summarizer, autoharness forks) are
    not attributed.
- **HYG-mcp-config** (`config_notes`, `extensions.mcp_name_collisions`): `url_without_type`
  (Claude Code skips the server; add `"type": "http"`), `sdk_type_skipped`, `reserved_name`
  (skipped at load), `sse_deprecated` (switch to `http`), and the same name in several scopes with
  `endpoint_origins_differ: true` (OAuth sign-ins are stored per endpoint, so sign-in state differs
  between projects). `empty_url_placeholder` is a documented placeholder, not a finding.

## Agent readiness (`RDY-`, opt-in via `focus=readiness`)

These are repo properties that decide whether Claude can set up, run, verify and understand a
project cheaply (`readiness[<repo>]`). Two rules keep this section from preaching:

- **Evidence first.** Report a gap when there's agent-side evidence (friction, `env_error_hits`, slow
  `test_run_seconds`, corrections), or when the fix is cheap and high-leverage. Everything else
  goes under Parked.
- **Match the repo.** Recommend tools from the repo's own stack and the user's existing conventions
  (lockfiles and configs show them): never Zod to a Python repo, never Husky to a uv/ruff
  project. Use `repo.commits` / `repo.first_commit` to calibrate: strictness advice is "turn it
  on now" for young repos and Parked, with a cost estimate, for mature ones.

- **RDY-first-run** (`setup_entrypoints`, `toolchain_pins`, `lockfiles`): no single setup command or
  no version pins, combined with `environment_issue` friction or repeated install failures. Fix: a
  `make setup` / `just setup` / `dev` script, plus pins in the repo's existing style.
- **RDY-env-undeclared** (`env.undeclared`): the code reads variables that no mechanism declares.
  Any mechanism counts: `.env.example`, a pointer-only `.envrc` (direnv + pass/1Password/sops),
  mise `[env]`, devcontainer, compose, pydantic settings. Propose a declaration in the mechanism the
  repo already uses; suggest `.env.example` only when there is none. Lead with `kind: required`
  (crashes when missing), then `read`. Mention `optional` (has a fallback) and `test-only` only as
  counts (`undeclared_counts`).
- **RDY-env-failfast** (`env.validation` empty, several required reads): suggest validation in the
  stack's idiom (pydantic-settings, zod/t3-env, envalid). Parked for small scripts.
- **RDY-envrc-literal-secret** (`envrc.literal_secret_names`, counted under security): a `.envrc`
  holds values rather than pointers. Worse if `envrc.git` is `tracked`. Report names only.
- **RDY-env-invisible-to-claude** (`envrc` present and `claude_env_hook` false, especially with
  `env_error_hits` > 0): direnv loads at an interactive prompt, which Claude's Bash tool never
  shows, so variables that work in the user's terminal are missing for Claude. Offer these
  options, stating the trade-off:
  1. *Non-secret* variables: a `SessionStart` + `CwdChanged` hook that writes `export` lines to
     `CLAUDE_ENV_FILE` (see the hooks docs), filtered to an allowlist of non-secret names.
  2. *Secrets*: `direnv exec . <cmd>` inside the specific Makefile or script targets that need them,
     so values exist only for that process and never sit in Claude's shell env or on disk.
     **Recommended default.**
  3. Export everything through the hook: zero friction, but every key is visible to every command
     Claude runs and can end up in transcripts.

  With the sandbox on, also check `sandbox.credentials` (`envVars` deny/mask; see "Protect
  credentials" / "Mask credentials" in the sandboxing docs) before proposing option 3.
- **RDY-env-secret-backend** (pointers resolve empty inside Claude's shell, e.g. the gpg or
  1Password agent is unreachable from the sandbox): check only with the user's OK. Probe variable
  names, never values, and tell the user rather than working around the sandbox.
- **RDY-format-guardrails** (`precommit`, `formatter_config`): a formatter is configured but not
  enforced. Evidence: edit rounds that only change formatting. Propose both a git pre-commit
  hook (humans) and a Claude PostToolUse format-on-edit hook (agent), in the repo's existing tool.
- **RDY-type-strictness** (`type_strictness`): strict mode off. Weigh by repo age, as above.
- **RDY-test-loop** (`test_run_seconds` median/p90, measured from transcripts; includes any
  permission-prompt wait): slow verification loops multiply cost. Suggest a fast subset target,
  or a file-relevant test hook. `ci.caching` matters only when CI is used.
- **RDY-test-data** (`tests.testcontainers`, `tests.seed_or_fixtures`): integration tests that need
  external services with no seeds or containers, together with flaky-failure evidence.
- **RDY-adr** (`adr`): no decision records while corrections show Claude re-deciding settled
  questions. Propose `docs/adr/` in the repo's existing style, and link it from CLAUDE.md.
- **RDY-boundaries** (`boundaries`): report only with evidence of cross-boundary edits or circular
  imports.
- **COST-app-caching** (`app_caching`, static signals; readiness track because it's app code):
  Anthropic SDK call sites with no `cache_control` (`uncached_files`), and possible cache breakers
  (`timestamp`, `random-id`, `unsorted-json`) in files that call the API. Before proposing:
  - Confirm the breaker feeds the prompt prefix (system prompt, tools, early messages) rather than
    being a log timestamp.
  - Caching only pays when the shared prefix clears the model's minimum and repeats within the
    TTL. Minimums on the Claude API: 512 tokens on Opus 5.5, Sonnet 5.5, Haiku 5.5, Opus 5 and
    Fable 5.1; 1,024 on Sonnet 5 and Opus 4.8; 4,096 on Haiku 4.5. Cache writes cost 1.25x base
    input (5-minute TTL) or 2x (1-hour); reads cost 0.1x, 0.05x on Opus 5.5 and Sonnet 5.5, and 0.025x on Fable 5.1.
    Two requests break even on the 5-minute TTL, three on the 1-hour TTL (prompt caching docs,
    fetched 2026-10-24; other providers can differ).
  - Proposal shape: top-level `cache_control={"type": "ephemeral"}` on the create call (automatic
    placement), move volatile content after the last breakpoint, verify with
    `usage.cache_read_input_tokens` > 0 on repeat requests.

  For a measured analysis of spend, point the user to `/claude-api cost-optimize` in that repo
  instead of estimating savings here.
- Out of scope unless the user asks: structured logging and feature flags (product architecture,
  with no agent-side signal).

## New features (`type: adopt`)

From What's new and the changelog: list only features that address observed evidence in this
snapshot, each with a one-line cost/benefit sentence. Park anything interesting but
not worth the effort now.
