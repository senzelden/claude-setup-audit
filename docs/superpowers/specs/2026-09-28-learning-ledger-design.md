# Per-item learning ledger — design

Date: 2026-09-28. Status: approved in conversation; awaiting written-spec review.
Roadmap item: "Per-item learning ledger" in `docs/roadmap.md`.

## Goal

Today `LRN-effectiveness` compares whole-report metrics (`friction`, `corrections_count_30d`) and
the model judges whether an applied fix helped. Earlier `applied[]` entries record only
`id`/`result`/`files`/`backup`, so no specific pattern can be rechecked.

The ledger makes each applied learning fix checkable: it records run, targeted friction pattern,
evidence, mechanism and the edits made. Later runs count that pattern deterministically, give a
verdict, and the model proposes escalation (not dropped) or retirement (quiet) as ordinary
findings that need approval. Tool-written edits are marked or fingerprinted so later audits and a
removal helper can tell them from the user's own text.

Success: a fixture run shows each verdict branch; a record → remove round trip restores Markdown,
hook and JSON files exactly (modulo the pruner's JSON formatting); user-edited blocks are never
removed; no raw prompt text reaches the ledger.

## Decisions (user, 2026-09-28)

1. Storage: a separate strict, versioned ledger file, passed explicitly.
2. Signal: typed selectors (metric, friction category, literal keywords over a named source).
   No regex.
3. Markers: hybrid. Inline markers where the format has comments; ledger fingerprints for JSON.
4. Scope: ledger, verdicts **and** a removal helper in v1. No backfill of older reports.

Documentation fact (https://code.claude.com/docs/en/memory.md, fetched 2026-09-28): block-level
HTML comments in CLAUDE.md files are stripped before injection into context; comments inside code
blocks are preserved; the Read tool still shows them. The page does not say this for
`.claude/rules/` or memory files, so markers there may cost a few tokens. Record this in
`references/ledger.md` with the fetch date.

## Components

| Unit | Responsibility | Writes |
|---|---|---|
| `scripts/ledger.py` (new) | Ledger schema, strict load/validate, verdict rules (pure functions), CLI `record` and `remove` | Ledger; user files only via `remove --apply` |
| `scripts/safe_write.py` (new, extracted) | `open_no_symlink`, `identity_of`, `atomic_write`, exclusive private backup, moved out of `prune_permissions.py` unchanged in behavior | — |
| `collect.py` | Selector counting (`count_selector`), plus `--ledger L` emitting `ledger_signals` for active entries | Snapshot only |
| `process_report.py` | `--ledger L --snapshot S`: verdicts into `trend.ledger`; with `--finalize`, append one observation per entry to the ledger | Report; ledger observations |

`prune_permissions.py` imports the extracted helpers; its existing tests must pass unchanged.

Default ledger path: `<report_dir>/ledger.json`. Every script takes it only as an explicit path
and never searches for it. Writes are atomic with mode 0600. Validation failures leave the ledger
unchanged and name the input (`ledger`, `snapshot`, `entry spec`) and line when known, with
constant messages that never quote values.

### Flow over one audit

1. Step 1 collect: `collect.py ... --ledger L` → `ledger_signals[entry_id]` with counts for each
   active entry, restricted to sessions after that entry's `applied_at`.
2. Step 4 process: `process_report.py current.json --previous ... --ledger L --snapshot S
   --finalize` → `trend.ledger[]` (entry id, verdict, counts, reason code); appends observations.
   The model writes `LRN-effectiveness:<entry-id>` findings for escalation/retirement proposals.
3. Step 5 apply: after each approved LRN fix is written and verified,
   `ledger.py record --ledger L --snapshot S --report current.json --spec entry.json` validates the
   spec, verifies each declared edit exists in the file, computes fingerprints, counts the
   baseline over the snapshot's window and scope, and appends the entry. The report's
   `applied[]` item gains `ledger_entry: <id>`.
4. Retirement or escalation that the user approves: `ledger.py remove --entry ID` (for retirement)
   or a new `record` whose spec names `supersedes: ID` (escalation; the old entry becomes
   `superseded`).

## Ledger format (version 1)

```json
{
  "version": 1,
  "entries": [{
    "id": "L-20260928-1",
    "applied_at": "2026-09-28T14:02:11Z",
    "run": "2026-09-28-audit",
    "finding_id": "LRN-corrections:run-tests",
    "pattern": "Claude reports done without running the test suite",
    "mechanism": "rule",
    "state": "active",
    "supersedes": null,
    "selector": {"type": "keywords", "source": "corrections", "any": ["run the tests", "tests fail"]},
    "scope": {"scope": "all", "project": null, "window_days": 30},
    "baseline": {"from": "...", "to": "...", "matches": 7, "sessions_matched": 5,
                 "sessions_scanned": 40, "complete": true},
    "edits": [{"file": "~/.claude/CLAUDE.md", "kind": "markdown_block",
               "sha256": "...", "backup": "~/.claude/backups/setup-audit-.../..."}],
    "observations": [{"run": "...", "from": "...", "to": "...", "matches": 1,
                      "sessions_matched": 1, "sessions_scanned": 22, "complete": true,
                      "verdict": "dropped", "reason": "rate_at_or_below_half"}]
  }]
}
```

- `mechanism`: `memory` | `rule` | `hook` | `skill` | `setting`.
- `state`: `active` | `removed` | `superseded` (retirement is carried out with `remove`). Only `active` entries are counted.
- `pattern`: at most 200 characters, passed through `collect.redact()`; model-written summary,
  never a quoted prompt.
- Strict validation, like decisions: unknown top-level or entry fields fail. The ledger is the
  tool's own file; there is no lenient mode.

### Selectors

| `type` | Fields | Counted from | Post-fix restriction |
|---|---|---|---|
| `keywords` | `source`: `corrections` \| `friction_details`; `any`: 1–5 literals, 1–40 chars each | `corrections`: `history.jsonl` prompts matching `CORRECTION_RE`; `friction_details`: facet `friction_detail` | Yes, by entry timestamp / facet session start |
| `friction_category` | `name` (facet friction key) | facet `friction_counts` | Yes, by facet session start |
| `metric` | `name`, `basis`, `unit`, `source` | report `metrics` via the existing comparison rules | No — see verdicts |

Keywords match as case-insensitive literal substrings; no regex. Keywords pass through `redact()`
at record time. Sessions come from `sessionId` (history) and `session_id` (facets); entries
without a session id count as matches but make `complete: false`. Counting reuses the collector's
existing scope filters and coverage accounting, so a scope or coverage gap yields
`complete: false`. Tool-error text is out of v1 until a complete source is verified.

## Verdicts (pure function in `ledger.py`)

`rate = sessions_matched / sessions_scanned`, counting only sessions that start after
`applied_at` (baseline: the audit window up to `applied_at`). In order:

| Verdict | Condition | Reason code |
|---|---|---|
| `unknown` | selector/scope differ from the entry, either side `complete: false`, or `sessions_scanned` is 0 at baseline | `incomparable`, `incomplete`, `no_baseline` |
| `too_early` | fewer than 5 post-fix sessions, or baseline `sessions_matched` < 3 | `few_sessions`, `weak_baseline` |
| `quiet` | 0 matches in this and the previous comparable observation, and ≥ 30 days since `applied_at` | `quiet` |
| `dropped` | rate ≤ 0.5 × baseline rate | `rate_at_or_below_half` |
| `not_dropped` | otherwise | `rate_above_half` |

`metric` selectors: a verdict only when the current report window starts at or after
`applied_at` and the existing metric comparison rules give a delta; otherwise `too_early`
(`window_overlaps_fix`) or `unknown`. `dropped`/`not_dropped` compare values instead of rates.

Proposals (model writes findings; processor only emits verdicts):
- `not_dropped` in two consecutive observations → propose the next rung
  (memory < rule < hook < skill). `setting` and `skill` get no automatic next rung.
- `quiet` on `memory` or `rule` → propose retirement (it costs context).
- `hook` is never proposed for retirement in v1: the pattern may be quiet because the hook blocks
  it, and hooks cost no context.
- All proposals follow the normal approval flow; nothing is applied automatically.

## Markers and edit records

| Edited file | Marker written | `kind` | Recorded |
|---|---|---|---|
| Markdown (CLAUDE.md, rules, memory) | `<!-- setup-audit:begin L-… -->` and `<!-- setup-audit:end L-… -->`, each alone on its own line, around the inserted block | `markdown_block` | path, sha256 of the text between markers, backup |
| Hook script written by the tool | header line `# setup-audit: L-…` (file is tool-owned) | `hook_script` | path, sha256 of file, backup |
| JSON settings | none | `json_array_append` \| `json_set` | path, JSON Pointer, sha256 of canonical value (`sort_keys`, compact), backup |

`record` refuses an edit whose marker/pointer is not found or appears more than once. The
entry id is generated before the edit so the model writes it into the markers (SKILL.md Step 5
gets `ledger.py next-id`). No file content or JSON value is stored in the ledger.

## Removal helper

`ledger.py remove --ledger L (--entry ID | --all) [--apply --backup-dir D]`; dry run by default.
Per edit, status:

- `removable`: marker block / file / value present and its hash matches.
- `modified`: present but hash differs (the user edited it). Never touched.
- `absent`: already gone. The entry can still be closed.
- `blocked`: `json_set` whose backup is missing or unreadable (the previous value is restored from
  the backup), symlink refused, or file changed between plan and apply.

`--apply` removes only `removable` edits: unique private backup via `safe_write`, identity
re-check, minimal edit (Markdown: delete marker lines and block; hook file: delete the file and
the registration only when that registration is itself a recorded `json_array_append` edit of the
same entry; JSON: remove the matching array element or restore the previous value, then
`json.dumps(indent=2)` as the pruner does, and `json.loads` check), re-read to verify, then set
state `removed` (all edits removed or absent) or leave `active` and report partial. Output lists
every edit with status and backup path, never values. Exit code non-zero if any edit is `blocked`.

README Uninstall: run `ledger.py remove --all` as a dry run before uninstalling; `modified` items
are listed for manual review.

## Report and docs

- `trend.ledger[]`: `{entry, verdict, reason, matches, sessions_matched, sessions_scanned}` —
  validated by `report_state`; rendered in the HTML trend section as a table.
- `applied[].ledger_entry` optional string.
- Snapshot: additive `ledger_signals` object (v1-compatible per `snapshot-format.md`); update
  `snapshot.schema.json` only if it would otherwise reject it.
- New `references/ledger.md`: format, selectors, verdict table, markers, removal, doc fact with
  fetch date. Update SKILL.md (Steps 1, 4, 5), checklist `LRN-effectiveness`, `report-state.md`,
  `report-format.md`, `coverage.md`, README uninstall, `docs/roadmap.md`, CHANGELOG
  `[Unreleased]`.

## Testing

Standard-library `unittest`, temporary fake homes only; never the real `~/.claude`.

- Selector counting: fixture `history.jsonl` and facets; post-fix cut-off; missing session ids →
  incomplete; scope filter; keywords never copied into output beyond the entry's own list.
- Verdicts: one test per row and reason code, plus the metric overlap rule and the two-in-a-row
  escalation input.
- Ledger validation: unknown fields, bad enums, too many/long keywords, duplicate ids, duplicate
  JSON keys; error names the input and never quotes values.
- `record`: marker missing/duplicated refused; fingerprints computed; baseline counted.
- `remove`: round trip for each `kind`; `modified` untouched; `blocked` on missing backup;
  symlink refused; partial apply leaves state `active`; dry run writes nothing.
- `safe_write` extraction: existing `prune_permissions` tests unchanged and passing.
- Processor: `trend.ledger` shape, observations appended only with `--finalize`, ledger untouched
  on validation failure.
- Red proof for each rule: break it and confirm the test fails.
- Gate: `python3 -m unittest discover -s tests -v`, `tests/check_snapshot_schema.py`,
  `git diff --check`, coverage floor 88.

## Out of scope (v1)

Backfilling older reports; regex selectors; tool-error text source; hook-trigger counting;
automatic application of any proposal; removal of edits not recorded in the ledger.
