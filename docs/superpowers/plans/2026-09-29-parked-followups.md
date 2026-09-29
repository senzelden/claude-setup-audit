# Parked follow-ups (harness overhead + drift) — implementation plan

Spec: none; the items are parked findings from the harness-overhead and drift-mode reviews
(`docs/superpowers/specs/2026-09-29-harness-overhead-design.md`,
`docs/superpowers/specs/2026-09-29-drift-mode-design.md`). Snapshot schema stays v1 (additive).

S = `plugins/setup-audit/skills/setup-audit`.

## Global Constraints

- Test-first: each behaviour change gets a test that fails without it (red proof in the report).
- Snapshot schema v1, additive only. Keep `tests/check_snapshot_schema.py` passing.
- Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`,
  `git diff --check`, coverage >= 88 (`uvx --from coverage==7.16.2 coverage run -m unittest
  discover -s tests`; `coverage report`; `coverage erase`). Never glob `rm`.
- Tests use temporary fake homes; never touch the real `~/.claude`.
- CHANGELOG `[Unreleased]` entry for user-visible changes. Commit trailer:
  `Assisted-by: Claude:<model-id>` only (no Co-Authored-By). Stage explicit paths.

## Task 1: Parked follow-ups batch

One commit per sub-item (a–g) is fine; small commits preferred.

a. `S/scripts/harness.py` `hook_index` (~line 86): `declared = (_json(manifest_path)[0] or {}).get('hooks')`
   drops the reason from `_json`. When the manifest exists but is unreadable/unparseable/not an
   object, add reason `manifest_unreadable` (a missing manifest is normal: no reason). Add the
   value to the reasons enum in `S/snapshot.schema.json` (~line 444), document it in
   `S/references/coverage.md` next to the other harness reasons, and test it (fake plugin storage
   with a broken `plugin.json`; the default `hooks/hooks.json` must still be indexed).
b. `S/references/coverage.md` (~line 79) and harness spec
   (`docs/superpowers/specs/2026-09-29-harness-overhead-design.md` ~lines 166-167): the
   `not_observed` wording must also cover the case where only SDK sessions were seen (the
   skill-listing series counts non-SDK sessions only). Check harness.py for the exact condition
   and describe it precisely.
c. `tests/test_harness.py` (~line 450): an end-to-end canary asserts a list `== ['extensions']`.
   Replace the pin with assertions of absence of the relevant key/reason in `harness_overhead` and
   transcripts only (read the test to see what it guards and keep that guarantee).
d. `S/references/coverage.md` (~line 78) says `transcripts_not_read` means "global scope". Find
   every caller path that passes `transcripts_read=False` to `harness.assemble` (and the
   docstring in harness.py ~line 222) and document every case accurately in both places.
e. `S/scripts/snapshot_contract.py` (~line 48): add `number` to the evaluator's `types` map
   (finite int or float, not bool). Keep the KEYWORDS/types list in `tests/check_snapshot_schema.py`
   in step. Then in `S/snapshot.schema.json` type drift `last_value` as `["number","null"]`
   (~line 425) and give `skill_listing_series` a `properties` block (~line 466) matching what
   harness.py emits. Schema accept + reject tests (bool, NaN/inf, string rejected for number).
f. `S/scripts/drift.py` `summary_line` (~lines 133-152): long log paths (> ~263 chars) lose the
   `; log <path>` suffix. Instead shorten the path itself (leading `...` + tail) so the line stays
   <= 300 chars with the suffix. Test with a 300-char path: suffix present, ends with the path's
   tail, line <= 300.
g. `docs/roadmap.md` (~line 86) cites "167 regression tests" (stale). Drop the number or replace
   it with the current count from the gate run.
