# Roadmap

Updated 2026-09-16. Completed release details live in [CHANGELOG.md](../CHANGELOG.md).
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

## Current priority: reliability

- [x] Version the snapshot contract; document compatibility and provenance/completeness
  semantics; validate the core structure and add regression coverage.
- [x] Broaden CI across Python versions and Linux/macOS, and run strict CLI plugin validation.
- [x] Remove mutating CLI diagnostic probes from read-only collection, with explicit
  not-checked coverage and source-preservation regressions across all three scopes.

Implemented after 0.5.0; see [development checks](development.md). Hosted verification passed
on 2026-09-16 at `a09a394`: [all seven jobs](https://github.com/senzelden/claude-setup-audit/actions/runs/35111349343),
including 108 regression tests and 3 schema checks on each Linux/macOS Python 3.11/3.13/3.14
combination, plus strict marketplace/plugin validation with Claude Code 2.1.273. The first
push exposed an invalid job-level runner context and a macOS path assumption in a test;
both were corrected in follow-up commits. These changes have been pushed but not released.

## Next candidates, separately scoped

- **Evaluation evidence:** fixture/grader reliability and the approved-apply quality case are
  implemented; readiness expectations are aligned. Remaining work: pilot approved apply,
  establish repeated trigger/read-only quality baselines, review execution failures and judge
  disagreements, and pilot the new suppression and cache-health cases. Both fixtures and
  independent report oracles are implemented with free regression coverage, but not piloted.
  The [evaluation plan](evaluation-plan.md) defines the order and acceptance evidence.
  Hosted verification passed all seven jobs for the approved-apply implementation at `3a562fb`
  ([run](https://github.com/senzelden/claude-setup-audit/actions/runs/35143564992)).
  Local validation now passes 150 regression tests. Check the
  [validation workflow](https://github.com/senzelden/claude-setup-audit/actions/workflows/tests.yml)
  for hosted results of subsequent commits. Model pilots remain pending and require separate approval;
  all pilot results remain local. No version bump or release is planned for this slice.
- **Privacy:** metadata-only collection/export, contextual secret detection and fuller
  provenance for free-text evidence. Tune detection against realistic fixtures.
- **Deterministic apply:** structured approved operations with preconditions, backup, minimal
  mutation and verification. Start with sandbox settings; do not redesign all apply paths at once.
- **Deeper checks:** hook content and matcher validation, duplicate hooks/layer conflicts,
  permission wildcard placement, MCP exposure metadata and recurring tool-error clustering.
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

## Explicit limits

Local inventory does not establish effective server/OS/helper/host policy, runtime overrides,
remote connector activation, instruction imports or symlink targets. Broader coverage and
managed-policy contradiction analysis remain separate work. Snapshot structure validation
must not be presented as evidence that collection is complete or findings are correct.
