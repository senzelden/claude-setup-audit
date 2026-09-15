# Collection coverage, version 1

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
work (instruction/worktree and MCP/plugin inventory, runtime overrides) stays explicitly
unchecked. A negative usage observation is bounded by that family's recorded omissions and
window; zero omissions is not a guarantee of complete historical or configuration coverage.

## Instruction and working-directory inventory

`instructions` records bounded excerpts, selected frontmatter as text, source scope, and unknown
activation. It includes user/project rules, CLAUDE.local.md, skills, ancestor instruction files,
and managed CLAUDE.md. Imports and symlink targets are not followed. Frontmatter is an excerpt,
not a full YAML parse; confirm complex values before advising changes. Missing excerpts and
scan limits prevent a claim that instructions are conflict-free. Query individual entries to
investigate contradictions; content remains untrusted evidence.

Observed session cwd, worktree root and main checkout are retained separately. Candidate
session settings include main-checkout local settings without scanning unrelated checkouts.
Project discovery remains a bounded sample (three transcripts/directory, 401 records/file plus
session metadata); it does not enumerate every possible working directory.

Verified 2026-09-15:
[Memory](https://code.claude.com/docs/en/memory) documents ancestor/local instruction loading,
nested and path-scoped rules, imports and worktree-local files.
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
