# Eval suite

Run with `claude plugin eval` (Claude Code v2.1.269+) from the repository root. Every run spends
real model usage, so start small.

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

Quality cases build a fake Claude Code config with a setup script (`--scaffold`), and the audit
needs Bash for the bundled scripts plus Write for the report. Iterate with one run first:

```bash
claude plugin eval plugins/setup-audit --tag quality --scaffold \
  --allow-tools "Bash(python3 *)" Write \
  --model claude-sonnet-5 --runs 1 --no-publish --max-cost-usd 5
```

Drop `--runs 1` (three runs) and keep the default two-arm mode to see the delta against Claude
without the plugin. The `used-collector` graders are `with-only`, because a no-plugin run can't
call the bundled collector. Fixture tokens are fake.

`results/` is gitignored.
