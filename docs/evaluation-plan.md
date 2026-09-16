# Next evaluation improvements

Scoped 2026-09-16; the first implementation chunk is complete. Pilot results are kept local. This plan follows the snapshot
contract and hosted CI work. It does not expand collector checks or redesign apply behavior.

Implemented: aligned readiness expectations, four independent judge obligations and calibration
examples, explicit quick/read-only fixture profiles, external scaffold manifests, and a free
post-run checker for retained workspaces/traces and report artifacts. Nineteen new regression
tests cover the checker, runner compatibility and both real scaffolds; all 127 local tests pass. See the
[eval instructions](../plugins/setup-audit/evals/README.md) for commands and coverage limits.
Paid batches require explicit approval. Keep pilot summaries, observed-answer examples, raw
traces and reports in ignored local results; do not commit or publish them.

The approved-apply quality case is now implemented, with an external expected-settings and
original-byte backup oracle plus free tests using the real permission pruner. It has not been
piloted. Its negative controls cover unapproved mutations, bad backups, missing apply records
and the helper's in-process stale-file guard. Separate CLI dry-run/apply invocations re-plan;
they do not provide a persistent stale precondition. See the
[case coverage and limitations](../plugins/setup-audit/evals/README.md#approved-apply-case-implemented-not-piloted).
The decision-suppression case now has a relative-date scaffold, an independent external report
oracle, and five free regression tests using the real processor and renderer. It isolates
finalization of supplied findings, not their discovery. Cache health now also has a relative-time
scaffold, hand-calculated metric expectations, missing/partial usage controls, and six free tests
using the real collector. All three new case pilots and repeated baseline runs remain pending.
The full local suite now passes 150 tests, including diagnostic side-effect regressions.

An unstubbed collector test exposed a read-only integration gap: CLI 2.1.273 diagnostic probes
created config bookkeeping, backup and telemetry files in the fake config tree. The checker
correctly rejects these additions. A subsequent collector fix removed both diagnostic probes
and reports version/doctor as not checked. A mutating CLI tripwire now guards all three scopes,
and a normal-PATH fake-home smoke check preserved source and home inventories. No checker
exemptions were added. This closes the observed diagnostic-startup gap, not the separate
eval-runner seccomp failure or model quality gaps.
The trace checker also bounds reads before decoding and rejects empty or malformed assistant
content. Local verification now passes 137 regression tests, including seven approved-apply
tests and three additional trace checks. This is deterministic coverage, not model evidence.

## Evidence and gaps

The suite has six trigger cases, four read-only quality cases (including unpiloted suppression
and cache-health cases) and one unpiloted approved-apply quality case. Historical results in
[CHANGELOG.md](../CHANGELOG.md) include one trigger pass (6/6), single-run quality comparisons,
and three clean security redaction reruns after a fix. They are not a repeated baseline for
the current commit. The readiness case has documented misses and judge disagreements when
the collector could not run. That environment failure must remain visible separately from
the quality of fallback advice.

The initial case inspection found the following gaps, addressed by the first implementation
chunk above (retained here as rationale):

- Readiness's expected outcome rejects `.env.example` more broadly than its judge rubric,
  which allows it as a secondary alternative. Align both around preserving pointer-based
  declarations and offering a concrete way to make variables available to Claude.
- `no-edits` detects Edit calls; it cannot establish that Bash or Write left files unchanged.
  The security case's extra Write check covers settings paths only; readiness lacks it.
- Secret checks inspect the final reply, leaving generated reports unchecked. Raw fixture
  reads can legitimately contain the fake token; distinguish tool results from model-authored
  messages, tool inputs and artifacts when checking leaks.
- Under two-arm evaluation, `with-only` graders are informational. An aggregate score of 1.0
  therefore does not prove that the collector ran successfully.

## Commit-sized implementation order

1. **Make the existing cases trustworthy, without model calls.** Fix the readiness outcome
   and split its rubric into independently reviewable obligations: recognize `.envrc`, identify
   undeclared `DATABASE_URL`, preserve secret pointers, and offer concrete shell integration.
   Add author-reviewed positive, negative and borderline answer examples; these calibrate
   expectations but do not count as independent accuracy evidence. Give quality cases explicit
   quick/read-only profiles and fixture-local report paths. Keep natural trigger prompts.
   Add fixture manifests and post-run checks for source-file hashes, additions/deletions,
   report validity and fake-token leakage. Check the actual scaffold workspace, not paths or
   success claims supplied by the model. First verify the runner's retained-workspace/artifact
   interface; use a separate local result checker if graders cannot inspect final file state.
   Test that checker with synthetic passing and deliberately failing artifacts in fake homes.

2. **Establish a repeated baseline, after paid-run approval.** First pilot readiness once
   with the plugin. Inspect collector execution and judge disagreement before expanding.
   Then run the six triggers three times each without ablation (18 agent runs), and the two
   existing quality cases three times per arm (12 agent runs, plus judge calls). Report
   per-case/per-grader counts and individual failures, not just suite means. Three repetitions
   are a small regression sample, not a population reliability estimate. Keep collector-success
   and degraded runs in separate groups; do not silently rerun failures out of the denominator.
   Treat a degraded run as fallback evidence, not successful collector integration. Accept the
   baseline only with all expected trigger outcomes, zero unauthorized mutations or output
   leaks, and each readiness obligation met in all three with-plugin runs. Explain any judge
   disagreements against the saved answer before changing the rubric.

3. **Add quality cases in separate commits, with free fixture checks first.**

   | Case | Fixture and required evidence | Negative control |
   |---|---|---|
   | Approved apply | One explicitly approved removal using the existing permission-pruning path; exact final settings, original-byte backup, preserved unrelated rules and reported verification | Audit/propose or an unapproved second item leaves settings unchanged; a stale precondition must stop mutation |
   | Decision suppression | Fixture-local prior report and decisions with matching IDs/fingerprints; unchanged evidence before review date is suppressed but retained with its reason | Changed, expired or unverified evidence stays visible; suppression must not be labeled resolved |
   | Cache health | Synthetic transcripts with known read/write totals, TTL split, duplicate records, idle gaps, model switch and compaction; report measured values and bounded interpretation | Missing/partial usage does not become zero cost or invented savings; cache rewrites alone do not prove a cause |

   Reuse the behaviors covered by `tests/test_collect.py` and `tests/test_report_state.py` as
   fixture oracles, with timestamps generated relative to the run or an explicit fixed analysis
   date. Do not let fixtures expire out of the collection window. Apply approval must name the
   exact fixture operation in the prompt; grant only tools needed for that operation. A model's
   statement that it made a backup is not a passing backup check. Pilot each new case once,
   then request approval for repetitions. No general apply engine is part of this scope.

## Run approval and evidence record

No paid evaluation is authorized by this plan. Before each paid batch, present the exact
command, commit, cases, agent and judge models, arms, repetitions, tool grants and proposed
spend ceiling. Use `--no-publish`, explicit `--runs`, and concurrency 1. CLI 2.1.273 checks
`--max-cost-usd` before launching each run, so an in-flight run can exceed the threshold;
describe it as a launch threshold rather than a guaranteed total bill cap. Ask for approval
with that limitation stated. Do not run `plugin eval init` as a supposedly free setup step.

Record CLI version, OS, date, exact command, plugin commit, fixture/grader changes, execution
errors, collector status, per-grader results, judge disagreement and elapsed time. Label the
CLI cost figure as a list-price estimate, not a measured invoice. Keep raw traces, reports and reviewed pilot summaries
in ignored local results; do not commit or publish them. Paid evals remain outside
ordinary CI. A failed execution or missing artifact must be reported as incomplete evidence.

## Validation sources

Checked 2026-09-16 against installed `claude --version` / `claude plugin eval --help`
(2.1.273) and the official [plugin eval documentation](https://code.claude.com/docs/en/plugin-evals).
The docs describe repeated runs, baseline arms, informational with-only graders, paid judges,
artifact grading and cost reporting. Recheck supported grader/artifact fields when implementing;
this scope deliberately does not invent an unverified post-run hook API.
