# Learning ledger

The ledger records, per applied learning fix (`LRN-` findings), which friction pattern the fix
targeted, how often that pattern occurred before the fix, and which files the tool edited. Later
runs count the same pattern after the fix, so a rule that did not help can be escalated and a
rule that nothing triggers any more can be removed. A verdict is a comparison of counts, not
proof that the fix caused the change.

The default path is `<report_dir>/ledger.json`. Every path is passed explicitly (`--ledger`);
nothing is searched for. The file is written atomically with mode 0600 and must not be a symlink.
An absent ledger file counts as empty. The collector never writes it: only `ledger.py record`,
`ledger.py remove --apply` and `process_report.py --finalize` do.

## Entries

| Field | Meaning |
|---|---|
| `id` | `L-YYYYMMDD-N`; get the next free one with `ledger.py next-id` |
| `applied_at`, `run` | when it was recorded, and the report stem of that run (at most 120 characters) |
| `finding_id`, `pattern` | the `LRN-` finding and a redacted pattern description (at most 200 characters) |
| `mechanism` | `memory`, `rule`, `hook`, `skill` or `setting` |
| `state` | `active`, `removed` or `superseded` |
| `supersedes` | id of the entry this one escalates; that entry becomes `superseded` |
| `selector` | what is counted (see below) |
| `scope` | requested scope, project and window days of the snapshot used for the baseline |
| `baseline` | counts for the window before the fix |
| `edits` | every file change the tool made, with a fingerprint |
| `observations` | one per run that produced a usable verdict |

Only `active` entries are counted and evaluated. Mechanisms form the ladder
`memory < rule < hook < skill`. `setting` has no next rung, so it is never escalated.
Escalating writes a new entry with `supersedes` set to the old one.

## Entry spec

`ledger.py record --spec <file>` reads one JSON object with exactly these fields, plus optional
`supersedes`. `record` computes everything else (hashes, baseline, scope, timestamps); a
`sha256` is never supplied.

```json
{
  "id": "L-20260928-1",
  "finding_id": "LRN-repeat-tests:myapp",
  "pattern": "Claude skips the test run before finishing",
  "mechanism": "hook",
  "selector": {"type": "keywords", "source": "corrections", "any": ["run the tests"]},
  "supersedes": "L-20260915-2",
  "edits": [
    {"file": "~/.claude/hooks/check-tests.sh", "kind": "hook_script", "backup": null},
    {"file": "~/.claude/settings.json", "kind": "json_array_append",
     "pointer": "/hooks/Stop/0/hooks/1", "backup": "~/.claude/backups/setup-audit-20260928/settings.json"}
  ]
}
```

- `id`: the value printed by `ledger.py next-id`.
- `finding_id`: must exist in the `--report` file (the current audit JSON).
- `pattern`: at most 200 characters; a short summary, never a quoted prompt.
- `mechanism`: `memory`, `rule`, `hook`, `skill` or `setting`.
- `supersedes`: optional; must name an `active` entry, which becomes `superseded`.
- `selector`, one of:
  - `{"type": "keywords", "source": "corrections" | "friction_details", "any": [...]}`
  - `{"type": "friction_category", "name": "..."}`
  - `{"type": "metric", "name": "...", "basis": "...", "unit": "...", "source": "..."}`
- Each edit is exactly `{file, kind, backup}`, plus `pointer` for the two `json_*` kinds. For
  `json_array_append` the pointer names the appended element (for example `/permissions/deny/3`);
  for `json_set` it names the value that was set. `backup` is the path of the pre-edit copy and
  must exist on disk, or is `null` when the file did not exist before the edit. A `json_set`
  with a `null` backup is refused unless deleting the value leaves only empty objects in the
  file; otherwise a backup is required so removal can restore the previous value.
- Markdown blocks and hook scripts need their markers first; see "Markers and edit kinds". Add no
  blank-line padding outside the Markdown markers: removal deletes only the marked lines.
- A hook script's registration is recorded as a `json_array_append` edit in the same entry, even
  when the hooks array was new. Without it the script can never be removed.
- `record` runs the removal plan on every new edit and refuses the entry unless each one is
  `removable` (for example, an appended value that already existed in the array is refused as an
  ambiguous duplicate).
- The report file stem becomes the entry's `run` and must be at most 120 characters.

## Selectors

| Selector | Counts |
|---|---|
| `keywords`, source `corrections` | sessions whose correction prompts (`history.jsonl`) match a correction pattern and contain a keyword |
| `keywords`, source `friction_details` | sessions whose `/insights` facet `friction_detail` contains a keyword |
| `friction_category` | the facet `friction_counts` for one category name |
| `metric` | one labeled report metric (name, basis, unit, source) compared between reports |

Keywords: 1 to 5 per selector, each 1 to 40 characters, literal strings (no regular expressions),
matched case-insensitively. A keyword that the collector's redaction would change (it looks like a
secret) is refused, because a redacted keyword would never match again. The pattern text is
redacted before it is stored.

A `global`-scope snapshot collects no per-project sessions, so `record` accepts only `metric`
selectors with it. A relative `project` in the snapshot scope is made absolute against the
current directory, both when recording and when comparing.

Counts are marked `complete: false`, and the verdict becomes `unknown`, when:

- history is missing, a row in the window has no session id, or a line at or after the first row
  inside the window is malformed, undated or not an object. `history.jsonl` is append-only and
  chronological, so bad lines before the window cannot hide an in-window prompt and are ignored;
- for facet selectors (`friction_details`, `friction_category`): any facet is orphaned (no
  matching session metadata) or undated, a facet's `friction_counts` is malformed, or no facets
  exist. Facet files are not ordered by time, so a single orphaned or undated facet may belong to
  the window and makes the counts incomplete. Sessions that have session metadata but no facet
  are not a gap; they are simply not scanned by facet selectors.

A metric selector is complete only when the report's metric coverage is complete.

## Verdicts

The collector counts sessions since the fix (`collect.py --ledger`); `process_report.py` compares
them with the baseline and writes one `trend.ledger` row per active entry.

| Verdict | Reason | Rule |
|---|---|---|
| `too_early` | `few_sessions` | fewer than 5 post-fix sessions scanned |
| `too_early` | `weak_baseline` | baseline matched fewer than 3 sessions |
| `too_early` | `window_overlaps_fix` | metric report window starts before the fix |
| `dropped` | `rate_at_or_below_half` | post-fix session match rate is at most half the baseline rate (metrics: value at most half) |
| `not_dropped` | `rate_above_half` | rate is above half the baseline rate |
| `quiet` | `quiet` | 30 days or more since the fix, zero matches now and in the previous usable observation |
| `unknown` | `incomparable`, `incomplete`, `no_baseline` | counts missing, from another scope or selector, incomplete, or no baseline sessions |

The thresholds are 5 post-fix sessions, 3 baseline matched sessions and 30 quiet days. Metric
selectors need a report window that starts after the fix. Observations are persisted only when
the verdict is not `unknown`; `unknown` rows still appear in the report.

## Proposals

- `escalate`: two consecutive `not_dropped` verdicts and a next rung on the ladder; the row
  carries `next_mechanism`.
- `retire`: a `quiet` verdict on a `memory` or `rule` entry. Carry it out with
  `ledger.py remove --entry <id>`.
- Hooks are never proposed for retirement in v1: a hook that works keeps the pattern quiet, so
  quiet is not evidence the hook is unnecessary.

`unknown` and `too_early` rows are reported and never acted on.

## Markers and edit kinds

Every edit is recorded with a kind, so removal can find and verify exactly what the tool wrote.

| Kind | What was written | Marker or identity |
|---|---|---|
| `markdown_block` | a block in a CLAUDE.md, rule or memory file | own lines `<!-- setup-audit:begin <id> -->` and `<!-- setup-audit:end <id> -->` around the block; the block hash is recorded |
| `hook_script` | a hook script file | its own line `# setup-audit: <id>` within the first five lines; whole-file hash |
| `json_array_append` | one element appended to a JSON array (for example a hook registration) | JSON pointer to the element; hash of its value |
| `json_set` | one JSON value set | JSON pointer; hash of the new value; `backup` holds the previous file so the old value can be restored |

Block-level HTML comments in CLAUDE.md files are stripped before injection into context
(https://code.claude.com/docs/en/memory.md, fetched 2026-09-28). The page does not say this for
`.claude/rules/` or memory files; markers there may cost a few tokens.

`record` refuses a symlinked edited file: removal refuses symlinks, so such an edit could never be
removed. It also refuses ambiguous or missing markers, a missing or unreadable backup, a hook
script without a recorded registration, a duplicate appended value, and an entry id that already
exists.

## Removal

`ledger.py remove --ledger <ledger> (--entry <id> ... | --all)` is a dry run. `--all` covers every
entry not already `removed`, including `superseded` ones, so the plan may list them. It prints one row
per edit (`entry`, `edit` index, `file`, `kind`, `status`, `reason`) and never values.

| Status | Reasons | Meaning |
|---|---|---|
| `removable` | | the edit is present and unchanged |
| `modified` | `hash_mismatch`, `markers_ambiguous`, `not_an_array`, `ambiguous_duplicate` | the user changed it since, or two identical array elements exist; never edited, listed for manual review |
| `absent` | `file_missing`, `markers_missing`, `pointer_missing`, `value_missing` | already gone; the entry can still be closed |
| `blocked` | `symlink`, `unreadable`, `registration_unrecorded`, `registration_remains`, `backup_missing`, `changed_since_plan`, `mixed_edits`, `backup_failed`, `write_failed`, `verify_failed` | not removed; see below |

Blocked reasons:

- `symlink`, `unreadable`: the file cannot be opened safely.
- `registration_unrecorded`: a hook script whose registration is not itself a recorded
  `json_array_append` edit of the same entry.
- `registration_remains`: a hook script is kept while any settings file named by the entry, or any
  `settings*.json` in the script's `.claude` directory, still contains the script's file name, or
  while that directory cannot be listed.
- `backup_missing`: a `json_set` whose backup cannot supply the previous value.
- `changed_since_plan`: the file changed between plan and apply.
- `mixed_edits`: more than one edit kind targets one file (only the two JSON kinds may share a file).
- `backup_failed`, `write_failed`, `verify_failed`: backup, rewrite or the re-read check failed.

`--apply` requires `--backup-dir` (exit 1 without it). It removes only `removable` edits: a unique
private backup first, an identity re-check, the minimal edit, then a re-read to verify. A verified
entry becomes `removed`; otherwise it stays `active`. JSON rewrites keep non-ASCII characters but
reformat the whole file with 2-space indentation.

Exit codes: 0 done, 1 error (nothing changed, or a distinct message when a failure happens after
files changed: backups are in the backup directory and the ledger was not updated), 2 when any row
is `blocked`.

## Privacy

The ledger holds counts, hashes, paths, ids, the redacted pattern and the keywords. It never holds
prompt text, friction text or configuration values.
