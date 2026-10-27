# Roadmap

Updated 2026-10-25. Completed release details live in [CHANGELOG.md](../CHANGELOG.md).
This is the active backlog; historical review findings are not additional open tasks.

## Shipped in 0.5.0

- Bounded managed settings, instruction/worktree and MCP/plugin inventory, with explicit
  source provenance and coverage limitations. Runtime activation is not inferred.
- Correct usage windows, attribution, quantiles and MCP call deduplication.
- Self-contained HTML reports, deterministic report/decision validation, evidence-bound
  suppression, and conservative finding/metric comparisons between audits.
- Opt-in instruction clarity pilot, with known false positives and misses.
- Security hardening and Linux/Python regression CI.

Release validation included 102 passing Python tests and a real Claude Code fixture smoke
test covering audit, comparison/suppression, and approved apply with backup and verification.
These are release results, not claims about later changes or broader platform support.

## Shipped in 0.6.0: reliability

- [x] Version the snapshot contract; document compatibility and provenance/completeness
  semantics; validate the core structure and add regression coverage.
- [x] Broaden CI across Python versions and Linux/macOS, and run strict CLI plugin validation.
- [x] Remove mutating CLI diagnostic probes from read-only collection, with explicit
  not-checked coverage and source-preservation regressions across all three scopes.
- [x] Preserve unique, private permission-pruning backups and block edits on backup failure.
- [x] Add unpaid OS prerequisite probes, separate from full eval-runner compatibility checks.

Included in 0.6.0; see [development checks](development.md). Earlier hosted verification passed
on 2026-09-16 at `a09a394`: [all seven jobs](https://github.com/senzelden/claude-setup-audit/actions/runs/35111349343),
including 108 regression tests and 3 schema checks on each Linux/macOS Python 3.11/3.13/3.14
combination, plus strict marketplace/plugin validation with Claude Code 2.1.273. The first
push exposed an invalid job-level runner context and a macOS path assumption in a test;
both were corrected in follow-up commits before inclusion in 0.6.0.

## Shipped in 0.7.0: earlier reports and AGENTS.md

- [x] Read the plugin's own earlier reports leniently (only version and finding ids required),
  record what was ignored, and name the failing input in validation errors.
- [x] Inventory `AGENTS.md` with observed per-context presence flags and any observed
  `instructionFiles` setting, without inferring what Claude Code loads.
- [x] Coverage floor in CI, README badges, requirements, update/uninstall and a sample report.

Hosted validation passed all eight jobs at `b93e179`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/36478432072).

## Shipped in 0.8.0: per-item learning ledger

- [x] Per-item learning ledger: applied learning fixes are recorded with the targeted pattern,
  a pre-fix baseline and the edits made; later runs count post-fix recurrence, propose
  escalation or removal, and can remove recorded edits after a dry run. v1 limits: no backfill
  of earlier fixes, no regular-expression selectors, no tool-error source, and hooks are never
  proposed for retirement.

Hosted validation passed all eight jobs at `a480dba`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/36528215135).

## Shipped in 0.9.0: harness overhead and drift mode

- [x] Self-modifying harness overhead: per-session injected tokens from transcripts, the skill
  listing series, subagent spend against the same sessions, entrypoint shares, a scan for enabled
  plugin hooks that invoke a model, and `COST-harness-overhead`. Skill growth comes from
  transcript `skill_listing` records, not the ledger.
- [x] Opt-in script-only drift mode (`references/drift.md`): a deterministic command the user runs
  or wires into their own cron job or hook; it appends to a drift log and prints one line only
  when a threshold is crossed. The plugin never installs a hook or schedule, and the audit reads
  the log read-only through `--drift-log`.

Hosted validation passed all eight jobs at `48d9d5d`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/36622544147).

## Shipped in 0.10.0: metadata-only privacy, sandbox apply and deeper checks

- [x] Metadata-only collection (`privacy=metadata-only`, `collect.py --metadata-only`): free text
  becomes `[metadata-only: N chars]` markers, unclassified strings are masked (fail closed) and
  `coverage.privacy` records the mode. Contextual secret detection runs in both modes.
- [x] Deterministic sandbox apply: `apply_ops.py` with allowlisted `sandbox.*` keys,
  per-op preconditions, a carried file hash, backup, atomic write and verification.
- [x] Deeper checks: permission wildcard placement, hook handler validation, duplicate hooks and
  shadowed allow rules, MCP exposure metadata and recurring tool-error clustering.

Hosted validation passed all eight jobs at `499217f`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/36731572402).

## Shipped in 0.10.1: docs drift to Claude Code 2.1.310

- [x] Documented `onFailure` hook field accepted and checked; guard hooks get a fail-closed proposal.
- [x] `sandbox.allowNestedUserNamespaces` allowlisted and flagged.
- [x] Cache minimums and prices for the 5.5 models.
- [x] One malformed settings file no longer aborts the snapshot (`shape_issues`, HYG-settings-shape).
- [x] CI pin 2.1.310.

Hosted validation passed all eight jobs at `0022836`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/40137328278).

## Shipped in 0.11.0: request evidence, scope, mods, path hashing

- [x] Subagent model mix (requested vs actual model, cache reads split out) and per-request
  model, effort, thinking and cache TTL counts; `COST-subagents` explains why subagents ran a
  top-tier model.
- [x] Settings keys and env names a project or local file can't set (`HYG-scope-ignored`;
  removed in 0.14.3, its tables named credential-adjacent settings and variables);
  `idleCompaction` and per-model auto-compact named as cost levers.
- [x] Mods inventory (static scan of declared JS hook modules) and the built-in guard options
  from managed settings (`SEC-mods`); removed in 0.14.3 with the scan, the guard options and
  `settings[].mods`.
- [x] `--hash-paths` (per-run salt; the optional salt file was removed in 0.14.2); fails closed for path-like kept strings.

Hosted validation passed all eight jobs at `a794fa1`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/40169646133).

## Shipped in 0.12.0: coexisting with runtime plugins

Prompted by [TokenEconomizer](https://github.com/microsoft/TokenEconomizer) (UC Berkeley,
Microsoft Research, Microsoft Security; [arXiv 2610.22732](https://arxiv.org/abs/2610.22732)) and
a survey of common plugins' runtime side effects
([evidence](research/2026-10-25-plugin-side-effects.md)).

- [x] **Recognize runtime plugins:** plugin-written deny rules, known state files, hooks that
  decide permissions or rewrite input, suspect timeouts, measured hook injection, and
  plugin-spawned sessions (kept in cost, excluded from learning analysis) (`HYG-plugin-footprint`).
- [x] **Cache effect of applied changes:** each apply and prune op states its documented cache
  effect, with an estimated re-write cost; information only.
- [x] **Tool usage:** per-tool use and deferred tools listed but never called; MCP connection
  failures per server, with a drift signal. Observation only.
- [x] **Failure-loop signal:** repeated failing commands and edit-test cycles within one turn, with
  a ledger selector (`LRN-failure-loops`). Thresholds are uncalibrated: no real loops yet.

Hosted validation passed all eight jobs at `2f0cdd0`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/40277575521).

## Shipped in 0.13.0: subscription usage

- [x] Opt-in rate-limit status-line logger (`rate_limit_log.py`) and its analysis: window headroom
  (upper bound), staleness, early resets (inferred), limit and spend messages, model mix and
  extra-usage settings, with checklist items `COST-subscription-headroom`,
  `COST-model-scoped-limits`, `COST-extra-usage` and `COST-limit-resets`.

Hosted validation passed all eight jobs at `1167473`:
[run](https://github.com/senzelden/claude-setup-audit/actions/runs/40469296347).

## Next candidates, separately scoped

- **No credential reads (0.14.0, unreleased)**: the audit no longer opens `~/.claude.json`, reads
  `.envrc` contents, or reads env, header or OAuth values and names. This answers the directory's
  "reads a credential" hold. Open question: user and local MCP coverage would need a supported
  non-credential source (for example output the user pastes from `claude mcp list`); until then
  the coverage limitation points the user to that command.

- **No-credential-reads follow-ups** (deferred from the 0.14.0 review): in the collector-failure
  fallback a whole-file Read of `settings.json` or `.mcp.json` still brings `env`/`headers`
  values into context although SKILL.md forbids reading them (a names-only fallback script would
  close it); about 12 prose lines added in 0.14.0 exceed 100 columns; the docs-side test checks
  the never-open rule exists, not that no passage instructs opening such a file.

- **Directory-scan follow-ups** (deferred from the 0.13.1 review): `handler_fingerprint` still
  hashes the raw command and URL (use the redacted command and the URL's origin and path shape);
  `stage_plugin.py` copies the working tree (`__pycache__`, `.claude/`) and leaves its temp dir
  behind on failure, and its symlink test covers only `evals/`; `fetch_doc.py`'s `O_TRUNC` write
  keeps an existing file's mode and leaves a partial file after a failed write, and when OUT sits
  directly in a shared allowed root it writes into a pre-existing file another user owns (fstat the
  write fd: refuse a foreign owner or `st_nlink > 1`; SKILL.md always writes into the checked
  `setup-audit-docs/` subdir); a refusal deep in the path leaves the 0700 directories already
  created; `test_shipped_bundle` could also assert the manifest and eval case directories.

- **Subscription usage follow-ups** (deferred from the 0.13.0 review): a `spend_limit` change of
  `period` alone is not logged; two sessions rotating at once can drop `.1` history; schema enum
  and date patterns for `early_resets[].window`/`at` and the `limit_events` dates; the rotated `.1`
  file is read without a symlink check; no `used_percentage` range check (`spend_limit` may exceed
  100); `limit_events.sessions` is keyed by file stem; ordering of same-second entries;
  `model_mix.tokens` counts a resumed session's copy again (per-file message-id dedupe); and the
  pre-existing over-redaction of `settings[].scope_ignored_keys[*].key` by
  `privacy.contextual_secret`.

- **Sandbox placeholders:** detect leftover sandbox placeholder files (empty read-only files at
  protected paths) left by interrupted sandboxed commands.

- **Evaluation evidence:** fixture/grader reliability and the approved-apply quality case are
  implemented; readiness expectations are aligned. Remaining work: pilot approved apply,
  establish repeated trigger/read-only quality baselines, review execution failures and judge
  disagreements, and pilot the new suppression and cache-health cases. Both fixtures and
  independent report oracles are implemented with free regression coverage, but not piloted.
  The [evaluation plan](evaluation-plan.md) defines the order and acceptance evidence.
  Hosted verification passed all seven jobs for the approved-apply implementation at `3a562fb`
  ([run](https://github.com/senzelden/claude-setup-audit/actions/runs/35143564992)).
  Approved apply independently checks final artifacts and successful helper execution; the
  skill blocks manual substitution when a required method cannot run. Runner write-tool
  grouping and namespace limitations are documented in the eval instructions. Local
  validation passes the full regression suite. Check the
  [validation workflow](https://github.com/senzelden/claude-setup-audit/actions/workflows/tests.yml)
  for hosted results of subsequent commits. Further model runs require separate approval;
  all pilot results remain local. Deterministic implementation is included in 0.6.0; full
  eval-runner compatibility and model-quality evidence remain separate work.
- **Claude Code 2.1.286-2.1.310 follow-ups:** mods and scope-ignored settings (both removed in 0.14.3) and the compaction
  levers shipped in 0.11.0. Not pursued after measurement (2026-10-25): attributing cache breaks
  to `shapeHash` changes (35 of 36 were followed by small writes) and skipping blob lines (a
  30-day collection takes 13 s). `prompt_snapshot` records are per session start or compaction,
  not per request, so they don't measure per-request overhead.
- **Privacy follow-ups:** metadata-only and hashed export of an existing snapshot, and fuller provenance for free-text evidence. Tune detection against
  realistic fixtures.
- **Deterministic apply:** widen the allowlist key by key with doc-grounded types; a paid
  approved-apply eval for sandbox ops needs separate approval; do not migrate the pruner or ledger
  flows without a design.
- **Deeper checks follow-ups:** a ledger tool-error source; calibrate failure-loop thresholds
  once real loops are observed.
  Verify proposed signals against current official documentation before implementation.
- **Enterprise posture:** opt-in data-handling assessment that separates locally observable
  settings from provider/account/admin facts requiring verification. Keep training, retention,
  telemetry and feedback sharing distinct.
- **Platforms:** real macOS integration verification beyond CI; Windows discovery, permission
  patterns and sandbox semantics need a separate design and test plan.
- **Quality:** tune dead-reference, environment and cache-breaker heuristics; broaden the
  clarity corpus before considering default activation or automatic rewrites; measure collector
  performance before optimizing.

## Distribution follow-up

Resolved 2026-10-19: 0.10.0 is live in the built-in Anthropic plugin directory as
`setup-audit@anthropic-plugin-directory` (Claude Code, Cowork, Claude apps), served from
`github.com/senzelden/claude-setup-audit#plugins/setup-audit` at the release commit. A test
install resolved to `0.10.0-08ea532e416f`. It is not in the `anthropics/claude-plugins-community`
GitHub marketplace, which has had no new community entries since July 2026, so that repo is not
a useful listing check. The README documents both install paths.

- The README now has update and uninstall instructions and a sample report.

## Explicit limits

Local inventory does not establish effective server/OS/helper/host policy, runtime overrides,
remote connector activation, instruction imports or symlink targets. Broader coverage and
managed-policy contradiction analysis remain separate work. Snapshot structure validation
must not be presented as evidence that collection is complete or findings are correct.
