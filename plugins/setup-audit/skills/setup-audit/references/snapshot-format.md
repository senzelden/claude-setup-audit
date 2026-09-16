# Snapshot contract, version 1

`collect.py` emits `snapshot_version: 1`. This version is independent of the plugin release
and the nested coverage/report versions. The machine-readable contract is
[`snapshot.schema.json`](snapshot.schema.json), using JSON Schema Draft 2020-12.

The contract stabilizes the envelope: required sections, their container types, scope/window,
source provenance and coverage statuses/counts. Family-specific analytical payloads remain
extensible objects, not exhaustively typed records. Validation establishes structure, not
factual correctness, redaction completeness or effective policy. The collector validates the
serialized, sanitized snapshot before printing or writing it; invalid output is not published.

## Compatibility

- Add optional fields without changing existing meanings within v1. Readers ignore unknown
  fields. New required fields, removed/renamed fields, changed types/units/semantics or new
  status values require a new snapshot version and reader support.
- `query_snapshot.py` validates v1 before querying. Unsupported explicit versions fail closed.
- Pre-versioned snapshots remain queryable with a stderr warning: they have no validated
  contract. Do not silently label them v1 or infer complete coverage; recollect when needed.
- `snapshot_contract.py SNAPSHOT` is a strict, read-only validator: legacy snapshots fail.
  Runtime validation uses a small stdlib evaluator restricted to the bundled schema keywords,
  not a general JSON Schema implementation. CI also checks the schema with `jsonschema`.
- JSON values must be finite. The window is a positive integer number of days. The legacy
  `generated` field is local wall time (`YYYY-MM-DD HH:MM`), not a UTC timestamp; window filtering
  retains the existing family-specific semantics documented in `coverage.md`.

## Provenance and completeness

`collection_scope` records the requested scope, optional project selector and root count.
`coverage.projects_collected` lists those roots; its count and requested scope must agree.
It is not a list of every nested directory represented in the `projects` mapping.

`coverage.sources` and inventory source records carry `source`, `scope`, and `status`.
Paths and family labels identify evidence origins, not executable instructions. A plugin
record with a rejected/missing install path can omit `source`; its registry coverage explains
the provenance. Individual legacy/free-text fields do not yet all have their own source tags.

Statuses: `collected`, `absent`, `partial`, `unavailable`, `not_checked`. Unknown counters are
omitted, never synthesized as zero. Counts retain their originating family's meaning; do not
assume `eligible = scanned + omitted` because omitted evidence can have been inspected.
Inventory `truncated` can be a boolean; coverage families can use a count. See
[`coverage.md`](coverage.md) for bounds, interpretation and runtime limitations.

## Documentation baseline

Schema dialect and object/required/additional-property semantics checked 2026-09-16 against
the [JSON Schema 2020-12 specification](https://json-schema.org/draft/2020-12) and
[object reference](https://json-schema.org/understanding-json-schema/reference/object).
This is the plugin's own data contract, not a Claude Code configuration schema.
