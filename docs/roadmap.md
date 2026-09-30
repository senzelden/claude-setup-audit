# Roadmap

Updated 2026-09-29. Completed release details live in [CHANGELOG.md](../CHANGELOG.md).
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

## Next candidates, separately scoped

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
- **Privacy:** metadata-only collection/export, contextual secret detection and fuller
  provenance for free-text evidence. Tune detection against realistic fixtures.
- **Deterministic apply:** sandbox slice shipped (`apply_ops.py`, allowlisted `sandbox.*` keys).
  Next: widen the allowlist key by key with doc-grounded types; a paid approved-apply eval for
  sandbox ops needs separate approval; do not migrate the pruner or ledger flows without a design.
- **Deeper checks:** hook matcher validation, duplicate hooks/layer conflicts and permission
  wildcard placement, MCP exposure metadata and recurring tool-error clustering are implemented
  (unreleased).
  Follow-up: a ledger tool-error source and a drift signal for MCP failure rate.
  Follow-up: build_snapshot aborts when one settings file is malformed (e.g. permissions/hooks not
  an object, `ask: 5`, `deny: [null]`, `allow: [{}]` raise TypeError in analyze_permissions,
  summarize_settings, redact, harness.hook_index, hook_handler_entry); needs per-file coverage
  records like invalid_settings.
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

The 2026-09-16 handoff records community review approval but no entry in Anthropic's community
mirror. Recheck the live listing before adding community install instructions. Direct marketplace
installation remains documented in the README. This is external follow-up, not a release blocker.

- The README now has update and uninstall instructions and a sample report.

## Explicit limits

Local inventory does not establish effective server/OS/helper/host policy, runtime overrides,
remote connector activation, instruction imports or symlink targets. Broader coverage and
managed-policy contradiction analysis remain separate work. Snapshot structure validation
must not be presented as evidence that collection is complete or findings are correct.
