# Collection coverage, version 1

The snapshot envelope is versioned separately; see [snapshot-format.md](snapshot-format.md).
The additive snapshot `coverage` object is directly usable as report coverage. Existing
`collection_scope`, usage and transcript counters retain their meanings. Each source has
`source`, `scope` and `status`; optional counts retain the originating family's semantics.

- `collected`: the named representation was read, not proof of effective configuration.
- `absent`: the checked local path was not found; says nothing about other policy sources.
- `partial`: a byte/file bound or family omission limits evidence.
- `unavailable`: access, decoding, shape or filesystem failure prevented collection.
- `not_checked`: the collector cannot establish this source's state.

Unknown counts are omitted. Managed settings expose selected fields through the existing
redacted settings summarizer, never raw JSON or environment values. A file is capped at 1 MiB;
at most 100 eligible drop-ins are inspected. Files are kept separate, in order; no effective
merge or enforcement claim is computed. Malformed selected-field shapes yield unavailable
coverage rather than stopping collection. These checks are not a full settings validator.

## Documentation baseline

Verified 2026-09-15 against official documentation:

- Managed settings (docs page `managed-settings`): system directories are
  `/etc/claude-code` on Linux/WSL and `/Library/Application Support/ClaudeCode` on macOS.
  Read `managed-settings.json`, then non-hidden `*.json` entries in `managed-settings.d/`
  alphabetically. Windows files/registry are not implemented here. Server, MDM/registry,
  helper and embedding-host policy remain unchecked. Helpers must never be executed by this
  audit. Managed-source selection and opt-in composition prevent treating local files as
  effective policy; this collector does not reproduce those rules.
- Settings precedence (docs page `settings`): managed policy generally
  outranks other scopes, with security-sensitive exceptions. `/status` reports loaded sources;
  file presence alone cannot establish that a source applied to the audited session.

Managed files are inspected for every requested scope because their reach includes projects.
Requested scope still controls existing project and usage collection. Other effective-coverage
work beyond the instruction/worktree and MCP/plugin inventories below (including runtime
overrides) stays explicitly unchecked. A negative usage observation is bounded by that family's recorded omissions and
window; zero omissions is not a guarantee of complete historical or configuration coverage.

## Harness overhead

`harness_overhead` is coverage source `harness_overhead` (`collected` or `partial`). Its fields
come from undocumented transcript attachment records (`hook_additional_context`, `hook_success`,
`skill_listing`), observed 2026-09-29; they may change without notice, and absence means not
observed, not zero. A hook injection with missing or null content is not counted; a non-string
entrypoint counts as `other`. Estimated tokens are round(median chars / 4). Attribution is an exact
command-string match against enabled plugins resolved through the registry `installPath` (all
settings layers); no match is `unattributed`, several are `ambiguous`. An injection is paired with
its `hook_success` by `toolUseID` first. SessionStart injections carry the event name as
`toolUseID` (observed 2026-09-29), so when pairing fails the candidates are the commands of
`hook_success` records in the same file with the same `hookEvent` and non-empty `stdout`; user and
project hooks drop out, one plugin left is `matched`, several are `ambiguous`, none is
`unattributed`. `skill_listing_series` covers main sessions whose entrypoint does not start with
`sdk-` (no or unknown entrypoint counts as non-SDK); `sdk_sessions_excluded` counts the rest, and
only-SDK listings give `null` with `not_observed`. `per_plugin_skills` lists enabled plugins only,
once each. `subagent_spend.entrypoints` keys are `cli`, `sdk-py`, `sdk-cli` and `other`;
`main_tokens_median_in_subagent_sessions` is the main-token median over the sessions that have
subagent tokens, the like-for-like comparison for the subagent median. Global scope
(`--scope global`) reads no transcripts, so this section then holds only static signals (hook
index and scan). The static scan follows script references one level deep and only references
rooted at `${CLAUDE_PLUGIN_ROOT}`; wrapper scripts, relative references after `cd`, and unquoted
roots containing spaces are not followed. `complete: false` lists `incomplete_reasons`:

- `main_file_cap`, `subagent_file_cap`: the transcript file cap was hit, so later files are unread.
- `malformed_records`: some transcript lines could not be parsed.
- `plugin_registry_unreadable`: at least one plugin is enabled and `installed_plugins.json` is
  missing or unparseable, its `plugins` is not an object, or an enabled plugin has no registry rows.
- `plugin_root_unreadable`: an enabled plugin's registry `installPath` was missing, relative, not a
  string, outside plugin storage or not a directory, so its hooks are unscanned.
- `hook_file_unreadable`: an existing `hooks/hooks.json` or a hooks file named by the manifest
  (`hooks` as a path or a list of paths and inline objects, resolved against the plugin root) is a
  symlink, escapes the plugin root, is missing (manifest paths), unreadable, not a JSON object, or
  larger than 1 MiB.
- `manifest_unreadable`: a plugin's `.claude-plugin/plugin.json` exists but is unreadable, not
  valid JSON, not an object or larger than 1 MiB, so manifest-declared hooks were not indexed (the
  default `hooks/hooks.json` is still indexed). A missing manifest is normal and adds no reason.
- `script_unresolved`: a hook script path was a symlink, outside the plugin root, missing or
  unreadable, so it was not scanned.
- `script_truncated`: a hook script exceeded the scan size limit; only its start was scanned.
- `transcripts_not_read`: `--scope global` only, the sole caller path that passes
  `transcripts_read=False` (`collect.build_snapshot` filters transcripts by the audited project
  roots, and only global scope has none); no transcript signal was collected. `--scope project`
  and `--scope all` always read transcripts, even when no session matches: an empty window
  yields `not_observed` instead.
- `not_observed`: no non-SDK `skill_listing` record was seen (`skill_listing_series` is null),
  either because none exist or because every one came from an SDK session (those are counted in
  `sdk_sessions_excluded` only when a series exists); reported but does not make the section
  incomplete.

Nothing stored is transcript content, hook command text or script text: only counts, sizes, dates,
plugin names, relative script paths and pattern ids.

## Configuration checks

`config_conflicts` is coverage source `config_conflicts` (`collected`, or `partial` when the caps
omitted entries; `basis: static`). It reads settings text only.

- Scope-ignored settings (`settings[].scope_ignored_keys`, `ignored_env_keys`, `basis: static`): the
  table is the settings reference's Scope column and its "Variables Claude Code ignores in `env`"
  list (plus env-vars `CLAUDE_CODE_ENABLE_CFC`; the `env` names looked up are that fixed list, never
  the file's other names), fetched 2026-10-24; it must be refreshed when the docs change and judges
  only the file's own location. Not seen: `--settings` files, the launch environment,
  `~/.claude.json` (not opened), env values and other env names (so the telemetry group and
  `CLAUDE_CODE_ENABLE_CFC` are conditional), and a managed file never being flagged even where the
  key would be ignored. Metadata-only keeps the key names, scope classes, env names and reasons
  (fixed vocabulary). `settings[].env_documented_set` lists the documented `SUBAGENT_ENV` names
  present in `env`. `settings[].sandbox` omits `credentials`; `sandbox_credentials_configured`
  records only whether it is set. Not read either: `.envrc`, mise `[env]`, devcontainer env and
  compose `environment` (existence only: `env.envrc_not_read`, `env.env_files_not_read`).
- Stacks: `global` is managed + user + home-local settings; each collected project directory is
  managed + user `settings.json` + its own project files. Plugin enablement comes from the
  highest-precedence file in the stack (managed > local > project > user).
- Not seen: `--settings`, CLI flags, server/MDM policy and skill/agent frontmatter hooks. Nested
  project directories are separate stacks.
- Overlaps cover only exact, tool and single-trailing-wildcard Bash cases, so a missing overlap is
  not proof of none. Extension handler caps (100 per component) can hide a duplicate.
- Documentation baseline: the docs pages `permissions`, `errors` and `hooks` (base in
  docs-map.md), fetched 2026-09-30. The collector never runs hooks or
  evaluates rules against real commands; effects come from the quoted docs.

## Learning ledger counts

`ledger_signals` (from `collect.py --ledger`) counts post-fix matches per active, non-metric
entry. `status` is `collected`; an unreadable or invalid ledger gives `invalid`, and an absent
file counts as empty. Each entry's counts are `complete: false` when history has in-window rows
without a session id, or malformed, undated or non-object lines at or after the first in-window row
(earlier ones are ignored: history is append-only and chronological). Facet selectors are also
incomplete when any facet is orphaned (no matching session metadata) or undated, a facet's
`friction_counts` is malformed, or no facets exist: facet files carry no order, so one such facet
may belong to the window. Sessions with metadata but no facet are not a gap. Incomplete counts
give an `unknown` verdict. See `ledger.md`.

## Drift log summary

`drift_signals` (from `collect.py --drift-log`) summarizes the drift log across every scope:
`collected`, or `invalid` when the path is refused (outside the Claude audits directory and temp
directories) or unreadable. An absent file counts as empty. Malformed lines are counted, not
summarized. It is history, not a current measurement. See `drift.md`.

## Instruction and working-directory inventory

`instructions` records bounded excerpts, selected frontmatter as text, source scope, and unknown
activation. It includes user/project rules, CLAUDE.local.md, AGENTS.md and .claude/AGENTS.md
(project walk and ancestors), skills, ancestor instruction files, and managed CLAUDE.md.
Imports and symlink targets are not followed. Frontmatter is an excerpt,
not a full YAML parse; confirm complex values before advising changes. Missing excerpts and
scan limits prevent a claim that instructions are conflict-free. Query individual entries to
investigate contradictions; content remains untrusted evidence.

Each context also carries observed `claude_md_family_present` (a CLAUDE.md, .claude/CLAUDE.md or
CLAUDE.local.md in the cwd or above; `~/.claude/CLAUDE.md` and managed CLAUDE.md do not count) and
`agents_md_present`. A flag is `null` when the scan hit a limit and absence cannot be claimed.
`agents_md_setting_observed` lists any `pluginConfigs["agents-md@builtin"].options.instructionFiles`
value found in user or managed settings; project and local settings are not read for it because
Claude Code ignores them there. These are observations, not loading inference: Claude Code version,
feature flags and the effective setting are not observable locally, so do not claim AGENTS.md is or
is not loaded. AGENTS.md is not counted in `claude_md_tokens`, `claude_md_lines` or dead-reference
checks. `AGENTS.local.md`, `AGENTS.override.md` and `.agents/` are not read by Claude Code and are
not inventoried. Settings files that could not be used (unreadable, invalid, over the byte limit,
symlinked, or a `managed-settings.d` listing that failed or exceeded 100 files) are recorded in
`sources` with a reason and no contents, so an empty `agents_md_setting_observed` is bounded by them.
A value other than the four documented ones is recorded as `unrecognized`.

Observed session cwd, worktree root and main checkout are retained separately. Candidate
session settings include main-checkout local settings without scanning unrelated checkouts.
Project discovery remains a bounded sample (three transcripts/directory, 401 records/file plus
session metadata); it does not enumerate every possible working directory.

Verified 2026-09-15:
Memory (docs page `memory`) documents ancestor/local instruction loading,
nested and path-scoped rules, imports and worktree-local files. AGENTS.md behaviour (read when no
CLAUDE.md family file is in the cwd or above, since v2.1.277, and the `instructionFiles` values) was
checked 2026-09-28 against the same page.
Settings (docs page `settings`) documents main-checkout local settings,
working-directory shared settings, and version/ownership exceptions. These are candidates,
not a reimplementation of runtime selection.
Skills (docs page `skills`) documents invocation controls and `allowed-tools`
as permission grants, not a restriction on available tools. Inspect these excerpts for broad
grants; never execute a skill or its dynamic context to inspect it.

## MCP and plugins

`extensions` inventories selected MCP transport, executable, origin, argument count, package version
shape, credential mechanisms and source scope. Argument values and URL paths are omitted. The audit
does not read MCP `env`, `headers` or `oauth` values or names, because they hold or point to
credentials; only the presence of the `oauth` and `headersHelper` mechanisms is recorded. Neither
MCP servers nor authentication helpers are run. It does not open `~/.claude.json`, where user and
local MCP servers live, so only project (`.mcp.json`), plugin and managed servers appear; the user can review the
rest with `claude mcp list` (`coverage.limitations` says so). Remote connectors and runtime
overrides remain unverified. "Not observed in these transcripts" is not "unused" or grounds alone
for removal.

MCP exposure fields (`transport_class`, `endpoint_locality`, `plaintext_transport`, URL flags,
`tool_prefix`, `file_git_status`) come from configuration text only. Locality needs no DNS, and
nothing is connected, authenticated or executed. URL path, query, userinfo, argument, env, header,
`clientId` and `headersHelper` values are never copied. Allow and deny policy and permission rules
from settings files are per-source observations (`policy_observations`), not effective state;
`serverUrl`/`serverCommand` entries are counted, not evaluated. Approval lists, enable/disable
toggles and trust-dialog state live in `~/.claude.json`, so they are not observed. `tool_prefix`
uses the documented plugin normalization for every server. Documentation checked 2026-09-29:
`mcp.md`, `managed-mcp.md`, `settings-reference.md`, `permissions.md`.

Tool errors (`transcripts.tool_errors`): pairing of results to calls is within a file, and only
`is_error: true` counts. Categories are heuristic text patterns observed 2026-09-29; the error
text is not stored. Calls and paired errors are deduplicated by project directory, session id
(file fallback) and tool id; `results_without_is_error` and `error_results_unmatched` count each
occurrence, so resumed copies of a session can inflate them. Caps: 15 built-in tools (only those with errors), 15 MCP servers (with calls) and
3 failing tools per server; `failure_rate` (excluding permission denials and user rejections)
is null below 5 calls. The session-meta `tool_error_categories` remain separate and coarse.

Tool search (`transcripts.tool_search_observed`; observed, undocumented, Claude Code 2.1.310,
2026-10-25): true when any main-thread transcript record in the window is an attachment of type
`deferred_tools_delta` (the record Claude Code writes when deferred tool definitions are listed or
change). Claude Code documents tool search (mcp, "Scale with MCP tool search") but not this record.
False means none was seen in the scanned window, not that tool search is off: an older Claude
Code or a scan cap give the same value. Null means no main-thread session fell in the window, so
nothing was scanned. Only the record type is read, never its names.
Cache effects use it only to label bare-name deny changes ("tool search observed"); nothing gates
on it.

Subagent models and request parameters (`transcripts.subagent_models`, `transcripts.request_params`;
observed, undocumented, Claude Code 2.1.310, 2026-10-25): Claude Code documents neither shape.
`<agent>.meta.json` beside each subagent transcript supplies `agentType` and `model`; only those two
keys are read (never `description` or `toolUseId`), at most 64 KiB, regular files only. Absent files
are counted in `meta_absent`; malformed, oversized, non-object, symlinked or non-regular (FIFO,
opened nonblocking) ones in `meta_unusable`. The meta `model` is usually the model Claude passed for
that call, but is `inherit` for forks (which run on the main model, even under
`CLAUDE_CODE_SUBAGENT_MODEL_FORCE`; sub-agents, fetched 2026-10-25); its absence means the
definition, `CLAUDE_CODE_SUBAGENT_MODEL` or the main model applied (order documented in sub-agents
"Choose a model", fetched 2026-10-25), so the row cannot say which; `actual_model` is what the
transcript shows. A subagent counts when it has an in-window record; its tokens are the in-window
assistant usage, deduplicated by message id, and rows are capped at 30 by tokens (`omitted` counts
the rest). `tokens` is volume including `cache_read_tokens` (billed at a fraction of base input),
not spend. `api-request` records (`querySource`, `params.model`, `params.output_config.effort`,
`params.thinking.type`, `cacheControl[].value.ttl`) are counted per source class, deduplicated by
project (the transcript directory's project, also for subagent files), sessionId and request id; a
breakpoint without `ttl` counts as 5m (default per prompt-caching, fetched 2026-10-25). `configured`
is an exact name match to collected project, plugin and managed server names; user and local servers
(in `~/.claude.json`) are not read, so they are never `configured`. A shape change in a later Claude
Code release shows up as zero rows or `meta_unusable`, not as an error.

Limit messages (`subscription.limit_events`, 0.13.0): the message texts are documented (errors, "Usage
limits", and interactive-mode, "Wait for a usage limit to reset"; fetched 2026-10-26); the record wrapper is
observed, undocumented and unverified for limit messages. Observed on this machine (Claude Code 2.1.310): API-side
failures are assistant records with `isApiErrorMessage: true`, `message.model: "<synthetic>"` and the text in
`message.content[0].text`; no limit message exists in the retained transcripts, so the shape of a real limit
record is unconfirmed. A record counts only when it is such an assistant record or a `system` record and a text
(top-level `content` or `message.content`, a string or text blocks) *starts with* a documented prefix (after
leading whitespace and an optional `API Error: `; straight or curly apostrophes). Ordinary assistant text, user
text and tool results never count, because conversations about this feature quote the strings. Limit messages in
another wrapper are missed: an under-count, never an over-count. Records are deduplicated by project, sessionId
and record `uuid` (resumed copies), in window, in the user's own main and subagent files (plugin-spawned excluded).
Only the kind, session, UTC date and, for `warning_85`, the window it names (`session`, `weekly`, `other`) are
kept. `model_mix` requests reuse the observed `api-request` counters above; its tokens come from assistant
message `usage` and `message.model` (observed, undocumented), deduplicated by message id.
`extra_usage.settings` reads the documented keys `autoContinueAtUsageLimit`, `fastMode` and
`fastModePerSessionOptIn` (settings-reference, fetched 2026-10-26; all Boolean) from collected settings files;
plan tier, usage-credit balance and limit, and available limit resets are not observable locally (limit resets
are undocumented; costs, fetched 2026-10-26).

Failure loops (`transcripts.failure_loops`): turns are delimited by user records that are not tool results, meta,
compact summaries, sidechain or system-injected text (`<system-reminder>`, `<local-command...>`, `<task-notification>`,
interruption notices); observed, undocumented record shapes, so a change in a later Claude Code release shows up as
fewer turns, not an error. A failure is an `is_error` result that is not a permission answer: `user_rejected`,
`permission_denied` and `permission_gate` (the permission system replying instead of the command running, observed
2026-10-25, matched only at the start of the error text so a tool error that merely mentions a block or
approval (an MCP "request was blocked by proxy") is `other`: auto-mode classifier without a verdict, "requires approval", compound-command and variable checks,
"Blocked:" sleeps, built-in safety denials, `allowed_domains` notes) are neutral, and `transcripts.tool_errors` counts
`permission_gate` as `denied` too. Commands are compared by a hash of the whole normalized command (a leading
`cd ... &&` or `VAR=value` prefix and trailing `2>&1`, `/dev/null` redirects and pipes into tail/head/tee/grep/less/wc/cat
dropped; arguments otherwise stay, so a varied selector is a different command, and long commands never merge); the hash
never leaves the collector. `edit_test` pairs a successful Edit/Write/MultiEdit with the next test-like Bash command (the
runner list `TEST_CMD_RE`, also used for test timing; widened 2026-10-25 with `python -m unittest`, `tox`, `nox`,
`cargo nextest`, `deno test`, `dotnet test`, `just test`, `make check`). A passing run resets only the files edited since
the previous test run; a denied, interrupted (`[Request interrupted`, `toolUseResult.interrupted`) or background-launched
(`run_in_background`) run is neutral. NotebookEdit and edits made through Bash (`sed -i`, heredocs) are not tracked, and an
edit whose own result is an error does not count. `command_heads` come from a fixed allowlist (test runners and common
tools); any other first token, including project or script names, is `other`. Thresholds are 3 (`REPEAT_ERROR_MIN`,
`EDIT_TEST_MIN` in `failure_loops.py`), a recommendation calibrated on fake transcripts and an aggregate smoke over real
transcripts, not a documented limit. Tokens are main-thread assistant usage within the turn (subagent work inside it is
not attributed). The snapshot block comes from the bounded transcript scan (`max_files`, most recent first); the ledger
`failure_loops` selectors share one pass over the main transcripts modified since the earliest selector start (at most
`MAX_LOOP_FILES` newest files; hitting the cap marks the counts incomplete), so their counts are not comparable. Background shell
results, commands run through subagents and tests run by hooks are invisible here.

Plugin runtime footprint (`plugin_written_rules`, `plugin_markers`, `plugin_state`, hook `decides_permissions`
/ `rewrites_input`, `transcripts.plugin_spawned`; fingerprint table dated 2026-10-25, from a survey of plugin sources,
`docs/research/2026-10-25-plugin-side-effects.md`): only fingerprints that are a named file, key or directory are
used, never string shapes in settings (a `statusLine` command, the form of a deny rule). The TokenEconomizer
ledger (`~/.tokeneconomizer/**/untool_applied.json`, observed shape `{"by_path": {settings path: [rules]}}`
or the older `{"tools", "path"}`; undocumented, written by that plugin) is read to depth 4, 50 files,
256 KiB each, symlinks and non-regular files refused, regular files opened nonblocking; paths are matched
to collected settings files by realpath, only rule names present in the file's deny list are reported, and
the rest is a count. `$TOKENECONOMIZER_HOME` is not honoured (environment values are not collected);
a relocated ledger is invisible. The quartermaster marker is the key `quartermaster.autoApprovePermissions`
set to true; the rules it appends are not attributable. State files are presence checks (never read).
Permission-deciding hooks: a plugin handler on `PermissionRequest` decides by definition; for `PreToolUse`
the command line and the plugin-local scripts it names (inside the plugin root as `harness._inside`
decides, no symlinks, regular files, 64 KiB each) get a text match for `permissionDecision` `allow`/`deny`
and `updatedInput`, comment lines skipped, nothing executed or sourced. It misses logic built at run time,
sourced files, commands that name no plugin-local script (`scan_gap: no_local_script`) and scripts
beyond the bound (`scan_gap` says so); it can match prose in a string, and a script that exits 2 on an
internal error is flagged like a guard. It matches `permissionDecision` allow/deny, the deprecated
top-level `decision` approve/block and exit code 2 (hooks docs "Exit code 2 behavior per event"), and
resolves relative script paths only after `cd "$CLAUDE_PLUGIN_ROOT" &&`. A missing flag is not evidence
that a hook does not decide. Hooks
docs fetched 2026-10-25. Injection size: the cap applies to characters; `hook_additional_context.content`
is observed (2026-10-25) as a list of strings, whose lengths are summed (drift entries logged before this
carry no `unit` and end the `injected_tokens` growth anchor walk); `hook_stdout` rows are `plain` (whole stdout)
or `json` (largest of `additionalContext`, `systemMessage`, `initialUserMessage`, top level or in
`hookSpecificOutput`), because the cap measures JSON per field and plain stdout whole; a transcript may hold only the
2,000-character preview of a spilled output, so `over_cap` can undercount, and none has been seen locally.
Spawned sessions: the only attributed fingerprint is a working directory under
`~/.claude-mem/observer-sessions` (claude-mem), matched on the dash-encoded transcript directory name for
transcripts and on the project path for history, session-meta and facets; spawned working directories are also
not discovered as project roots, and spawned sessions feed no MCP call counts, env-error hits or test run times; the encoding cannot tell
`observer-sessions/x` from `observer-sessions-x`, and a relocated claude-mem data directory is not seen.
Not attributed because the files the collector reads do not show them: remember's
`REMEMBER_NESTED_SUMMARIZER` (an environment variable of the child process) and autoharness's detached
`claude -p --resume --fork-session` runs (same working directory as the user's session; transcripts of
`claude -p` runs carry the same `sdk-*` entrypoint as any other script). Entrypoint counts in
`harness_overhead.subagent_spend.entrypoints` remain the generic signal.

Plugin candidates come from `installed_plugins.json` records, not newest cache directories.
User/managed installs and matching project/local installs are inspected. Enablement settings
are reported as per-source observations, with active state unknown. Only paths within plugin
storage and components within their install are read. Default/custom skills, agents, commands,
hooks and MCP definitions are inspected; other manifest keys are inventoried, not implemented.
Mods: when a plugin's `hooks/hooks.json` has `modules`, the first module path (inside the plugin
root, no symlinks, regular file, `.js/.mjs/.cjs/.jsx/.ts/.mts/.cts/.tsx`) is text-scanned, never
imported or run, for `on('<event>'` and `$.<ns>.<method>` names: a heuristic (comments and strings
can add names; indirect or dynamic use is missed), capped at 512 KB and 50 names per list
(`mod.truncated`). Only identifier-shaped names are kept, never source text; metadata-only keeps
them as API vocabulary. A mod that registers `settings.read` can rewrite merged settings, so the
collected files are not the effective settings (reported as an extensions limitation). The
authoritative list is `claude plugin validate <dir>`, which collection never runs. Mods docs
fetched 2026-10-25. `settings[].mods` records, as booleans, the guard options
`allowManagedModsOnly` and `allowModsToOverrideDenyRules` (read only from
`pluginConfigs["cc-plugin-sec-default@builtin"].options` in managed settings; a non-managed entry
is only flagged as ignored), whether a managed `prependPlugins` names the guard, and the presence
of `prependPlugins`/`appendPlugins`.
Limits: 1 MiB/JSON; 100 MCP entries total; 50 installs; 100 paths per component kind;
100 directories/files per component path; 32 KiB/Markdown. Omissions are coverage limitations.

Verified 2026-09-15 against MCP (docs page `mcp`) (project `.mcp.json`; user and
local definitions live in `.claude.json`, which the audit does not open) and
plugin reference (docs page `plugins-reference`) (inline/custom component
locations). Installed-registry list records and field types were separately observed locally
on that date; no private values were used as fixtures. Unknown registry shapes are unsupported.
Skill listing totals now use observed excerpts without claiming a fixed cap, budget, or runtime
activation. Frontmatter folding and enablement can change the actual listing size.

## Privacy

`coverage.privacy` is always present: `mode` (`full` or `metadata-only`), `free_text`
(`collected` or `replaced`), `marker` (`[metadata-only: N chars]`), `replaced_fields` and
`redactions`. `replaced_fields` counts occurrences (one per masked string, not per field name)
grouped by family, and is empty in full mode. `redactions` counts `[REDACTED]` (`pattern_or_key`)
and `[REDACTED:context]` (`contextual`) tokens in the serialized snapshot.

In metadata-only mode the collector adds the source `free_text_fields` with status `not_checked`
and reason `metadata_only_mode`, plus a limitation saying that findings needing free text are not
assessable. Free text (prompts, corrections, friction details, memory and skill descriptions,
instruction excerpts, hook commands and targets, permission rule text (including `rule_shape_issues`
and `config_conflicts.permission_overlaps` rules), sandbox and other
structural values) is replaced by `[metadata-only: N chars]`, where N is the collected length (after
redaction and truncation). Masking has two passes: known free-text locations, then a fail-closed pass
that masks any other string the collector emitted at an unexpected place (for example a string where a
list or flag belongs in a malformed config), counted under the `unclassified` family of
`replaced_fields`. Paths, names, counts, flags and enums stay, and `claude_md_dead_refs` (path-like
tokens taken from CLAUDE.md text) are kept, so a metadata-only snapshot is still not free of
sensitive information; review it before sharing.

`--hash-paths` (with or without `--metadata-only`) additionally replaces path-like kept strings with
`h:<12 hex>` tags (HMAC-SHA256 truncated; families listed in `snapshot-format.md`) after every
collection join, and records `hashed_paths`, `hashed_path_families` and `hash_salt` (`per_run`, or
`file` for `--hash-salt-file`; the salt itself is never written) in `coverage.privacy`, plus a
limitation. The salt file must already exist, hold at least 16 bytes after trimming whitespace, and is
never created by the collector. This hides usernames, project names and file names that live in paths;
it does not hide names the collector keeps by design (plugin, skill, agent and MCP server names) and
does not mask full-mode free text beyond replacing known home and project directories inside it (what
follows a tag stays, e.g. `h:<12 hex>/run.sh` in a hook command; the count is `free_text_scrubbed`).
Equal strings get equal tags, so a relative file name is the same tag in every repo. Path-like kept
strings that no family names are hashed too and counted as `other_paths`; hook script names under
`projects/*/hooks` are names and stay.
What degrades: the report cannot name a project or file (cite the tag), and tags cannot be opened,
compared with another audit's tags (unless the same salt file is reused) or fed to
`prune_permissions.py --snapshot` or a project-scoped ledger entry.

The contextual detector runs in both modes. A high-entropy value next to a key-like name
(`AWS_SECRET_ACCESS_KEY=...`, `--api-token ...`, `sessionKey: ...`) or a `--password` value becomes
`[REDACTED:context]`, keeping the label. It ignores hashes, UUIDs, paths, references, word-like
identifiers and values with spaces, so it can miss short or low-entropy secrets and secrets with
unfamiliar labels. Redaction remains best-effort.

Tool usage and MCP failures (`transcripts.tool_usage`, `transcripts.mcp_failures`; observed, undocumented,
Claude Code 2.1.278 to 2.1.310, 2026-10-25): Claude Code documents neither shape. `deferred_tools_delta` attachments
carry name lists (`addedNames`, `readdedNames`, `surfacedNames`, `removedNames`), `pendingMcpServers` (names)
and `failedMcpServers` (`name`, `errorCode`, `error`); only names and `errorCode` are read, never `error`.
Always-loaded built-in tools are not listed anywhere, so only deferred tools (MCP, plugin and some built-ins)
can be "listed but never called". Counts are per transcript file in the window, so resumed copies of a
session can count twice; sessions without these records (older versions, no tool search) contribute to
`sessions` but not to listing or failure evidence. Observed (not documented): `addedLines` carries one line per added tool, so a deferred tool costs about one
listing line until used. Calls in the user's own subagent files count as use for "never called" (plugin-spawned
sessions do not); `used[].sessions` stays main-thread. `needsAuthMcpServers` is read as names (strings, or objects
with `name`) into `sessions_needs_auth`; in the author's data the key is present in most records but was never
non-empty, so its shape is unconfirmed. `sessions_present` counts sessions where a server appears in any of the
three lists or has `mcp__<server>__*` tools listed or used (names normalized with `_`). `tool_search_observed`
uses the same per-file pass and exclusions: any main-thread, non-spawned delta record in the window.
A shape change shows up as zero `sessions_with_deferred_records`, not as an error.
