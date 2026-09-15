# Audit report format (version 1)

Write one JSON object using the existing version 1 envelope. The presentation fields below
are additive; older reports render with explicit missing-data labels. This is a minimal report
contract, not a snapshot schema or a validator for decisions, trends, or evidence correctness.

```json
{
  "version": 1,
  "generated": "2026-09-15T12:00:00Z",
  "claude_code_version": "observed version or unknown",
  "profile": {"focus": "security", "depth": "quick", "scope": "project", "mode": "audit"},
  "summary": "Short summary already used in Markdown.",
  "coverage": {
    "requested_scope": "project",
    "projects_collected": ["/example/repo"],
    "sources": [{"source": "transcripts", "status": "partial", "scanned": 10, "omitted": 2}],
    "limitations": ["Managed policy contents not collected."]
  },
  "metrics": {
    "context_baseline_median": {"value": 1234, "unit": "tokens", "basis": "measured", "source": "transcripts.context_baseline_tokens"}
  },
  "findings": [{
    "id": "SEC-example:repo", "check": "SEC-example", "area": "security",
    "type": "fix", "severity": "high", "score": 3,
    "title": "Example finding", "why": "Concrete consequence.",
    "evidence": [{"source": "/example/repo/.claude/settings.json", "detail": "Redacted rule shape", "basis": "observed"}],
    "fix": {"kind": "manual", "target": "/example/repo/.claude/settings.json", "steps": ["Specific proposed change."]},
    "docs": ["https://code.claude.com/docs/en/permissions"],
    "effort": "5 minutes", "reversible": true,
    "status": "new", "action_status": "proposed"
  }],
  "applied": [],
  "new_features": [],
  "caveats": ["Interactive /doctor output unavailable."]
}
```

## Write for the person reading the report

Lead with a short summary that says what needs attention and what to do first. Finding titles
must describe the actual problem. Use `why` for the consequence and `fix.summary` for a short,
plain-language next step; keep exact edits in `before`/`after`. Do not use placeholders such as
"Concrete consequence" in a real report. Evidence should explain the observation and cite its source.

Metrics may add `label` (a readable name) and `explanation` (what the number means, including
relevant limitations). Coverage may add `summary` explaining what was reviewed in one sentence.
The renderer shows these existing report fields directly; it does not invent interpretations.
It puts technical metadata and exact changes in expandable details, and omits empty optional
sections. Set `example: true` only for fictional demonstrations.

A complete fictional example is in `examples/readable-audit.json` in the plugin directory.

- Copy the snapshot `coverage` object, including managed sources and limitations (see
  `coverage.md`); add separately sourced runtime evidence if available. Use source statuses `collected`,
  `partial`, `absent`, `unavailable`, or `not_checked`. Keep unknown counts absent, never invent zeros.
  Include collector failure and bounded-scan omissions. Requested scope is not proof of coverage.
- Keep existing metric keys for comparison. New reports wrap each metric in `value`, `unit`,
  `basis` (`measured`, `estimated`, or `unknown`), and `source`. Older bare metrics remain
  readable but unclassified. Compare metric values, not the wrapper, when reading old reports.
- `findings` and `applied` are arrays of objects; scores are finite numbers. Ranking is descending
  score with input order breaking ties. Use that order for Markdown proposal numbers too.
  Parked, resolved and suppressed findings have separate sections and no proposal numbers.
- `status` records audit history (`new`, `open`, `regressed`, `resolved`, `suppressed`).
  `action_status` independently records `proposed`, `approved`, `applied`, `partial`, `failed`,
  `skipped`, or `declined`. Never infer application from the history status.
- For suppressed findings include the decision reason and `review_after`. For each attempted
  action, append an object to `applied` with `id`, `status`, `files`, `backups`, `verification`,
  and `revert`. Update the finding's `action_status` and regenerate HTML after changes.
- Text is plain text, including evidence, diffs, commands and URLs. The renderer does not execute
  commands, interpret Markdown, activate URLs, fetch resources, or add model-written narrative.
  Use redacted evidence only; escaping HTML does not redact secrets.

Run `python3 ${CLAUDE_SKILL_DIR}/scripts/render_report.py "<report_dir>/<stem>.json"`.
It writes `<stem>.html` beside the JSON, atomically with private (0600) permissions on POSIX.
Existing HTML is replaced for updates; choose an unused stem for each new audit across all three
formats. It leaves JSON/Markdown untouched. On failure, fix the input or report the missing HTML;
do not claim it was generated. No browser launch, upload, trend computation, or configuration edit.
