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

- [Managed settings](https://code.claude.com/docs/en/managed-settings): system directories are
  `/etc/claude-code` on Linux/WSL and `/Library/Application Support/ClaudeCode` on macOS.
  Read `managed-settings.json`, then non-hidden `*.json` entries in `managed-settings.d/`
  alphabetically. Windows files/registry are not implemented here. Server, MDM/registry,
  helper and embedding-host policy remain unchecked. Helpers must never be executed by this
  audit. Managed-source selection and opt-in composition prevent treating local files as
  effective policy; this collector does not reproduce those rules.
- [Settings precedence](https://code.claude.com/docs/en/settings): managed policy generally
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

- Stacks: `global` is managed + user + home-local settings; each collected project directory is
  managed + user `settings.json` + its own project files. Plugin enablement comes from the
  highest-precedence file in the stack (managed > local > project > user).
- Not seen: `--settings`, CLI flags, server/MDM policy and skill/agent frontmatter hooks. Nested
  project directories are separate stacks.
- Overlaps cover only exact, tool and single-trailing-wildcard Bash cases, so a missing overlap is
  not proof of none. Extension handler caps (100 per component) can hide a duplicate.
- Documentation baseline: the permissions, errors and hooks pages at
  `https://code.claude.com/docs/en/`, fetched 2026-09-30. The collector never runs hooks or
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
[Memory](https://code.claude.com/docs/en/memory) documents ancestor/local instruction loading,
nested and path-scoped rules, imports and worktree-local files. AGENTS.md behaviour (read when no
CLAUDE.md family file is in the cwd or above, since v2.1.277, and the `instructionFiles` values) was
checked 2026-09-28 against the same page.
[Settings](https://code.claude.com/docs/en/settings) documents main-checkout local settings,
working-directory shared settings, and version/ownership exceptions. These are candidates,
not a reimplementation of runtime selection.
[Skills](https://code.claude.com/docs/en/skills) documents invocation controls and `allowed-tools`
as permission grants, not a restriction on available tools. Inspect these excerpts for broad
grants; never execute a skill or its dynamic context to inspect it.

## MCP and plugins

`extensions` inventories selected MCP transport, executable, origin, argument count, package
version shape, credential mechanisms and source scope. Argument values and URL paths are
omitted; environment/header keys and variable names are retained without their values.
Neither MCP servers nor authentication helpers are run. Same names across scopes are separate
observations, not a computed effective merge. Remote connectors and runtime overrides remain
unverified. "Not observed in these transcripts" is not "unused" or grounds alone for removal.

Plugin candidates come from `installed_plugins.json` records, not newest cache directories.
User/managed installs and matching project/local installs are inspected. Enablement settings
are reported as per-source observations, with active state unknown. Only paths within plugin
storage and components within their install are read. Default/custom skills, agents, commands,
hooks and MCP definitions are inspected; other manifest keys are inventoried, not implemented.
Limits: 1 MiB/JSON; 100 MCP entries total; 50 installs; 100 paths per component kind;
100 directories/files per component path; 32 KiB/Markdown. Omissions are coverage limitations.

Verified 2026-09-15 against [MCP](https://code.claude.com/docs/en/mcp) (user and per-project
local definitions in `.claude.json`, project `.mcp.json`) and
[plugin reference](https://code.claude.com/docs/en/plugins-reference) (inline/custom component
locations). Installed-registry list records and field types were separately observed locally
on that date; no private values were used as fixtures. Unknown registry shapes are unsupported.
Skill listing totals now use observed excerpts without claiming a fixed cap, budget, or runtime
activation. Frontmatter folding and enablement can change the actual listing size.
