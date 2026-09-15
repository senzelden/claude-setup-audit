# Collection coverage, version 1

The additive snapshot `coverage` object is directly usable as report coverage. Existing
`collection_scope`, usage and transcript counters retain their meanings. Each source has
`source`, `scope` and `status`; optional counts retain the originating family's semantics.

- `collected`: the named representation was read, not proof of effective configuration.
- `absent`: the checked local path was not found; says nothing about other policy sources.
- `partial`: a byte/file bound or family omission limits evidence.
- `unavailable`: access, decoding, shape or filesystem failure prevented collection.
- `not_checked`: the collector cannot establish this source's state.

Unknown counts are omitted. Managed settings expose selected fields through the existing
redacted settings summarizer, never raw JSON or environment values. A file is capped at 1 MiB;
at most 100 eligible drop-ins are inspected. Files are kept separate, in order; no effective
merge or enforcement claim is computed. Malformed selected-field shapes yield unavailable
coverage rather than stopping collection. These checks are not a full settings validator.

## Documentation baseline

Verified 2026-09-15 against official documentation:

- [Managed settings](https://code.claude.com/docs/en/managed-settings): system directories are
  `/etc/claude-code` on Linux/WSL and `/Library/Application Support/ClaudeCode` on macOS.
  Read `managed-settings.json`, then non-hidden `*.json` entries in `managed-settings.d/`
  alphabetically. Windows files/registry are not implemented here. Server, MDM/registry,
  helper and embedding-host policy remain unchecked. Helpers must never be executed by this
  audit. Managed-source selection and opt-in composition prevent treating local files as
  effective policy; this collector does not reproduce those rules.
- [Settings precedence](https://code.claude.com/docs/en/settings): managed policy generally
  outranks other scopes, with security-sensitive exceptions. `/status` reports loaded sources;
  file presence alone cannot establish that a source applied to the audited session.

Managed files are inspected for every requested scope because their reach includes projects.
Requested scope still controls existing project and usage collection. Other effective-coverage
work (instruction/worktree and MCP/plugin inventory, runtime overrides) stays explicitly
unchecked. A negative usage observation is bounded by that family's recorded omissions and
window; zero omissions is not a guarantee of complete historical or configuration coverage.
