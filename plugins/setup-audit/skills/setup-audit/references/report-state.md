# Report validation and two-run comparison

Run before rendering a new report:

```bash
python3 ${CLAUDE_SKILL_DIR}/scripts/process_report.py current-audit.json \
  --previous previous-audit.json --decisions decisions.yaml --finalize
python3 ${CLAUDE_SKILL_DIR}/scripts/render_report.py current-audit.json
```

Omit `--previous` or `--decisions` when absent. Without `--finalize`, the processor only
validates. Paths are explicit; it does not search other directories, edit configuration, or
write the previous report. It atomically replaces current JSON with private permissions.
Invalid inputs leave it unchanged. Errors omit private input values. After applying fixes,
revalidate with the same comparison inputs and regenerate HTML; align Markdown with JSON.

## Validation

New reports require version 1, an ISO timestamp, profile scope, coverage object, summary,
findings, labeled metrics, and applied array. IDs must be unique; finding titles, evidence and
history status are required. Dates, status enums, numeric values and coverage counts are checked.
Duplicate JSON keys and non-finite numbers fail. Metric values are finite numbers or null;
labels include unit, basis and source. Previous/legacy reports allow missing presentation fields
and bare numeric metrics, but missing metadata prevents comparisons. The renderer keeps legacy
support while sharing the structural validator. Unknown extra fields remain allowed.

## History and measurements

The processor compares explicitly supplied reports using dates, requested scope/focus, collected
projects and window_days. Store `window_days` from the snapshot. Stable finding IDs identify
new/open/regressed findings. A previous resolved finding that reappears is regressed.

A missing finding is resolved only with matching comparison metadata and a current
`checks: {"CHECK-id": "complete"}` entry for its check. Use `partial` or `not_checked` otherwise;
missing entries never prove resolution. Set complete only when relevant evidence was actually
reviewed, including policy/scan limitations. Derived resolved entries are marked so rerunning
is idempotent. History never implies an action was applied. Earlier unresolved items that could
not be reassessed appear in `trend.findings.not_rechecked`.

Metric deltas require matching numeric basis, unit and source, comparable report metadata, and
collected source coverage without omissions in both runs. The first dot-separated segment of
metric `source` selects coverage source families (for example `transcripts.context_baseline_tokens`
uses `transcripts.*`). Unsupported source labels, legacy metrics and partial scans yield no delta.
Deltas are current minus previous, without a causal or improvement claim. HTML shows available
comparisons and their limitations.

## Decisions

Accepted formats: a JSON array or a YAML list of flat scalar maps using `id`, `reason`, `settled`,
`review_after`, and optional `evidence_hash`. Quote strings with JSON double quotes or YAML single
quotes. Comments and empty files work. Nested YAML, aliases, tags and block scalars are rejected;
convert them explicitly instead of silently ignoring entries. Dates use YYYY-MM-DD.

Exact finding ID wins over check ID. A decision suppresses only after its settled date, before
its review date, and with unchanged evidence. Expiry is inclusive on review_after. The default
comparison date is the current report date; `--as-of YYYY-MM-DD` overrides it for reproducibility.
An evidence_hash binds the decision to the finalized finding's canonical evidence fingerprint.
Without it, an older comparable report at or after settlement can establish the baseline.
Otherwise the finding remains visible with `evidence_unverified`. Changed evidence remains visible.
The processor does not decide whether a textual change is materially equivalent.
