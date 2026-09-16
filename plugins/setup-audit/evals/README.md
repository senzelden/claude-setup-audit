# Eval suite

Run with `claude plugin eval` (Claude Code v2.1.269+) from the repository root. Every run spends
real model usage, so start small.

The next improvements are scoped in [the evaluation plan](../../../docs/evaluation-plan.md):
fixture and grader reliability first, repeated baseline runs second, then apply, suppression
and cache-health cases. Ask for approval before paid runs; the plan itself authorizes none.

| Tag | Cases | What it measures | Cost |
|---|---|---|---|
| `trigger` | 3 should-trigger, 3 near-miss should-not-trigger | whether the skill fires on natural phrasing, and stays out of adjacent requests | cheap: turn cap of 3–4 |
| `quality` | `audit-flags-risky-permissions`, `readiness-envrc-pointers` | a full read-only audit against a fixture config: findings, secret handling, no edits | expensive: full audits |

## Trigger accuracy

```bash
claude plugin eval plugins/setup-audit --tag trigger --ablation none \
  --model claude-sonnet-5 --no-publish --max-cost-usd 3
```

`--ablation none`, because without the plugin loaded the skill can't fire, so a no-plugin
baseline tells you nothing here.

## Output quality

Quality cases build fake configuration with a setup script (`--scaffold`) and capture an
external manifest before the model starts. They request quick, read-only audits with reports
under the fixture's `./reports`. Bash runs the bundled scripts and Write creates the reports.
After obtaining approval, start with one case and one arm:

```bash
mkdir -p plugins/setup-audit/evals/results
quality_run_dir=$(mktemp -d "$PWD/plugins/setup-audit/evals/results/quality-XXXXXX")
claude plugin eval plugins/setup-audit --case readiness-envrc-pointers \
  --scaffold --keep-temp --trust-plugin --ablation none --runs 1 --concurrency 1 \
  --allow-tools "Bash(python3 *)" Write \
  --model claude-sonnet-5 --judge-model claude-haiku-4-5 \
  --no-publish --max-cost-usd 5 --output-dir "$quality_run_dir"
```

The $5 setting is a launch threshold: an in-flight run can exceed it. The command's cost is
an estimated list-price cost, not an invoice. Repetitions and baseline arms require their own
approval. A three-repeat trigger batch has 18 agent runs; the two current quality cases with
three repetitions and both arms have 12 agent runs, plus judge calls.

Run the free post-run checker for **each** retained run, even if its model score is perfect:

```bash
# CLI 2.1.273 seals retained home/tmp trees. Allow read/traverse for inspection only.
chmod 500 /tmp/claude-eval-<run-id>/sealed
python3 plugins/setup-audit/evals/helpers/check_quality.py check --sealed \
  --manifest "plugins/setup-audit/evals/results/manifests/<case>-<unique-id>.json" \
  --trace /tmp/claude-eval-<run-id>/out/trace.jsonl
```

The scaffold stores manifests in `evals/results/manifests/`, outside the model workspace.
CLI 2.1.273 does not forward operator `EVAL_*` variables to scaffold scripts, although it
forwards them to model children. Direct fixture tests can override `EVAL_EVIDENCE_DIR`.

Use `tracePath` from that run in `aggregate-result.json` and the external manifest whose
`workspace` matches the trace's system-init `cwd`. The `--sealed` option reads the
CLI's relocated `sealed/home/cwd` tree while verifying the original workspace identity.
Do not run Git, scripts or environment files from the retained tree; inspect it as data only.
For a workspace that has not been relocated, omit `--sealed`. Do not take paths from the model's answer.
`--keep-temp` is required; missing or mismatched traces/workspaces are incomplete evidence,
not a pass. Capture refuses a manifest inside the model workspace. Keep the external manifest
unchanged after capture. This is a regression check, not a boundary against hostile plugin code.

The checker hashes every scaffold workspace entry outside `reports/` (including additions,
deletions, symlink changes and Git metadata), validates `*-audit.json` with the strict report
contract and expected profile, and requires nonempty Markdown and HTML companions. It checks
all report files, assistant content/tool inputs and final result text for the security fixture's
fake-token marker; fixture reads in user tool results are allowed. The CLI's newly created empty
`.claude/.cc-writes` directory and its otherwise-empty new parent are counted separately as
`runtime_empty_directories`; files beneath either directory and symlinks are never exempt. This is a sentinel leak test,
not a general secret detector or an HTML correctness/security validator. It observes final file
state; transient edits later reverted require trace review. Only the fixture workspace is checked,
not every path on the host. Unsupported trace shapes and bounded-input failures are incomplete.

`passed` covers file preservation, reports and leak checks. `collector_ran` is separate and
requires a successful tool result linked to a collector command. A clean degraded audit is not
collector integration evidence. Under two-arm evaluation the built-in `with-only` graders are
informational, so also inspect collector status independently of the aggregate score. Fixture
or safety check failures must not be hidden by a high model score.

Readiness has four independent judge obligations. The author calibration examples in
`readiness-envrc-pointers/rubric-examples.json` cover positive, negative and borderline replies;
they are not an independent accuracy estimate. Review judge disagreements against these examples
and the answer before changing a rubric. The free checker tests run with the normal Python suite:

```bash
python3 -m unittest discover -s tests -p test_eval_quality.py -v
```

Runner flags, file grading limitations and estimated-cost semantics were checked on 2026-09-16
against CLI 2.1.273 and the official [eval reference](https://code.claude.com/docs/en/plugin-evals).

`results/` is gitignored. Keep pilot summaries and observed-answer examples there too; do not
commit or publish pilot results.

## Free instruction-clarity development check

The optional clarity pilot has a separate author-reviewed corpus, not a paid model evaluation:

```bash
python3 plugins/setup-audit/skills/setup-audit/scripts/evaluate_clarity.py \
  plugins/setup-audit/evals/clarity-corpus.json
```

See `skills/setup-audit/references/instruction-clarity.md` for the labels, known false positives,
misses and limits. These development results are not an independent accuracy estimate.
