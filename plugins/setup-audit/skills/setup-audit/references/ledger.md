# Learning ledger

The ledger records, per applied learning fix (`LRN-` findings), which friction pattern the fix
targeted, how often that pattern occurred before the fix, and which files the tool edited. Later
runs count the same pattern after the fix, so a rule that did not help can be escalated and a
rule that nothing triggers any more can be removed. A verdict is a comparison of counts, not
proof that the fix caused the change.

It also records report-only outcome entries for applied SEC and COST fixes (see "Outcome
entries"): a metric before and after the fix, shown in the report and never acted on.

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
| `outcome_only` | only on outcome entries, and then always `true`; absent on learning entries (and in every ledger written before 0.15.0, which still loads unchanged) |

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
  - `{"type": "failure_loops", "kind": "any" | "repeat_error" | "edit_test"}`
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
- `outcome_only`: optional, only `true`; see "Outcome entries" for the rules it brings.

## Selectors

| Selector | Counts |
|---|---|
| `keywords`, source `corrections` | sessions whose correction prompts (`history.jsonl`) match a correction pattern and contain a keyword |
| `keywords`, source `friction_details` | sessions whose `/insights` facet `friction_detail` contains a keyword |
| `friction_category` | the facet `friction_counts` for one category name |
| `failure_loops` | turns with a failing-cycle loop (`transcripts.failure_loops`); matched sessions are main sessions with at least one such turn, scanned sessions those with any turn in the window |
| `metric` | a catalog metric (see "Outcome metrics") computed from the snapshot, or any other labeled report metric (name, basis, unit, source) compared between reports |

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

A metric selector is complete only when the report's metric coverage is complete. A catalog
metric is complete as its row in "Outcome metrics" says.

## Verdicts

The collector counts sessions since the fix (`collect.py --ledger`); `process_report.py` compares
them with the baseline and writes one `trend.ledger` row per active entry.

| Verdict | Reason | Rule |
|---|---|---|
| `too_early` | `few_sessions` | fewer than 5 post-fix sessions scanned |
| `too_early` | `weak_baseline` | baseline matched fewer than 3 sessions |
| `too_early` | `window_overlaps_fix` | metric report window starts before the fix |
| `too_early` | `collected_before_fix` | point-in-time catalog metric: the snapshot was collected before `applied_at` |
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

`unknown` and `too_early` rows are reported and never acted on. Outcome entries get no proposal
whatever their verdict.

## Outcome entries

After SKILL.md's apply flow applies an approved SEC or COST fix with a backed-up change
(`apply_ops.py`, `prune_permissions.py`, or Claude's own edit after the backup step) and the
finding's check has a metric below, record a report-only entry with the usual `ledger.py record`
command and this spec:

```json
{
  "id": "L-20261111-1",
  "finding_id": "SEC-risky-allow:global",
  "pattern": "Broad allow rules removed from user settings",
  "mechanism": "setting",
  "selector": {"type": "metric", "name": "risky_allow_rule_count", "basis": "measured",
               "unit": "rules", "source": "settings.permissions.risky"},
  "edits": [],
  "outcome_only": true
}
```

`record` refuses the spec unless all of these hold:

- `outcome_only` is `true`, `mechanism` is `setting`, `edits` is empty and there is no
  `supersedes`. The changed files and backups are in the report's `applied` item; an outcome
  entry records no edits, so nothing can remove it.
- The finding is in the `--report` file, its id starts with `SEC-` or `COST-`, its `check` (or
  the id before `:`) is listed below, and the selector is one of that check's metrics with the
  catalog's exact labels.
- The report's `applied` array holds an item for that finding with `status` `applied` and a
  non-empty `backups` list. That is how `record` sees a recorded, backed-up change; the entry's own
  `edits` stay empty so it can never be removed.
- The `--snapshot` (the Step 1 snapshot, collected before the fix) has `generated_utc`, the metric
  has a value above 0 in it, and it was collected no later than the record time.

The baseline is the metric computed from that snapshot; the model never supplies a value.

**Marker choice.** Outcome entries carry `outcome_only: true` rather than a new `mechanism`:
`mechanism` keeps saying what kind of change was made (`setting`), and the flag is the single
thing every report-only rule checks. Older ledgers have no such field and load unchanged.

**Report-only.** An outcome entry is never escalated or removed, never proposed for retirement, and nothing offers either:

- `proposal` is always null on its `trend.ledger` row, and `process_report.py` refuses a row with
  `outcome_only: true` that carries a proposal or a metric outside the catalog;
- `ledger.py remove --entry <id>` refuses it (exit 1), and `remove --all` skips it;
- no entry may supersede it, and it supersedes nothing.

## Outcome metrics

Each value is computed by `scripts/outcome_metrics.py` from snapshot fields the collector already
writes, by the fixed rule below, so the next audit produces a comparable value. Labels must match
exactly. The window is the snapshot's: `window` metrics cover `window_days` ending at
`generated_utc`; `point` metrics are the state at `generated_utc` (`from` equals `to`).

| Name | Unit | Source | Basis | Kind | Rule | Complete when |
|---|---|---|---|---|---|---|
| `context_baseline_tokens_median` | `tokens` | `transcripts.context_baseline_tokens.median` | `measured` | window | the median of first main-thread request tokens per session | every `transcripts.*` coverage source is `collected` with nothing omitted |
| `cache_write_share` | `ratio` | `transcripts.cache.write_tokens` | `measured` | window | `write_tokens / (read_tokens + write_tokens)`, 3 decimals; null without tokens | as above |
| `allow_rule_count` | `rules` | `settings.permissions.allow_count` | `measured` | point | sum of `allow_count` over user and project settings files, once per path | every file has an integer `allow_count` |
| `risky_allow_rule_count` | `rules` | `settings.permissions.risky` | `measured` | point | distinct (settings path, rule) pairs over every risky flag of those files | no flag list holds the collector's cap of 6 rules, and the snapshot is not metadata-only (masked rule text can merge) |

Permission prompts per session are not collected (transcripts record denials, not prompts), so no
prompt metric exists.

A check is listed only where its fix plausibly moves the metric:

| Finding check | Metrics | Why |
|---|---|---|
| `SEC-risky-allow` | `risky_allow_rule_count`, `allow_rule_count` | the prune removes the flagged allow rules |
| `SEC-secret-literal` | `risky_allow_rule_count`, `allow_rule_count` | the prune removes the rule carrying the literal (flag `secret-literal-in-rule`) |
| `SEC-secret-env` | `risky_allow_rule_count`, `allow_rule_count` | the prune removes the rule reading the env file (flag `secret-via-env-file`) |
| `COST-baseline` | `context_baseline_tokens_median` | the finding is this metric; its fix cuts what loads before the first answer |
| `COST-claude-md-size` | `context_baseline_tokens_median` | CLAUDE.md loads at launch, so moving text to nested files, rules or skills shrinks the first request |
| `COST-mcp-unused` | `context_baseline_tokens_median` | a removed server no longer lists its tools or instructions in the first request |
| `COST-skill-listing` | `context_baseline_tokens_median` | the skill listing is part of the first request |
| `COST-startup-hooks` | `context_baseline_tokens_median` | SessionStart `additionalContext` is added before the first prompt |
| `COST-harness-overhead` | `context_baseline_tokens_median` | its fixes trim skill listing growth and injected context, both in the first request |
| `COST-cache-health` | `cache_write_share` | TTL and habit fixes target cache rewrites, which are the write share |

Not listed, because no catalog metric measures what their fix changes: `SEC-sandbox` (prompts are
not collected), `COST-model-default`, `COST-long-sessions`, `COST-subagents`, `COST-memory-index`,
the tool-error and subscription checks. For SEC prunes prefer `risky_allow_rule_count`: the prune
removes those rules, while a total allow count rarely halves. Any metric-selector entry using a
catalog metric's exact labels is computed from the snapshot too.

The verdict rules are those of metric selectors: value at most half the baseline is `dropped`;
`window` metrics are `too_early` until the snapshot window starts after `applied_at`, `point`
metrics until a snapshot is collected after it; scope or window change, a missing value or
collection time make the row `unknown`. The report shows each metric row under "Outcome of applied
fixes" with the finding id, applied date, baseline and current value with their windows, the
verdict and the caveat that a verdict is a comparison of counts, not proof that the fix caused the
change. In scope `all`, a project discovered since the baseline adds its settings to the counts.

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
entry not already `removed`, including `superseded` ones, so the plan may list them, but never an
outcome entry (`--entry` with one exits 1). It prints one row
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
