# Snapshot contract, version 1

`collect.py` emits `snapshot_version: 1`. This version is independent of the plugin release
and the nested coverage/report versions. The machine-readable contract is
[`snapshot.schema.json`](snapshot.schema.json), using JSON Schema Draft 2020-12.

The contract stabilizes the envelope: required sections, their container types, scope/window,
source provenance and coverage statuses/counts. Family-specific analytical payloads remain
extensible objects, not exhaustively typed records. The settings summary definition is applied to
`global.settings` and `managed_settings.settings`; project settings and `instructions.settings_candidates`
stay untyped objects, so their summary fields (`scope_ignored_keys` among them) are not schema-checked. Validation establishes structure, not
factual correctness, redaction completeness or effective policy. The collector validates the
serialized, sanitized snapshot before printing or writing it; invalid output is not published.

## Compatibility

- Add optional fields without changing existing meanings within v1. Readers ignore unknown
  fields. New required fields, removed/renamed fields, changed types/units/semantics or new
  status values require a new snapshot version and reader support.
- `coverage.privacy`: optional in the schema, emitted by current collectors (`mode`, `free_text`,
  `marker`, `replaced_fields`, `redactions`). In metadata-only snapshots `[metadata-only: N chars]` markers replace free
  text, type-preserving (a list stays a list of markers), each matching `\[metadata-only: \d+ chars\]`.
  Hook handler entries carry `server`, `tool` (mcp_tool) and `target_origin` (http) so masked
  targets stay identifiable. Contextual detection replaces a labelled literal secret with
  `[REDACTED:context]` in every mode. Additive within snapshot v1.
- `coverage.privacy` also carries `hashed_paths: true`, `hashed_path_families` (family -> count of
  hashed values and keys) and `hash_salt` (`per_run` or `file`) when collected with `--hash-paths`
  (works with or without `--metadata-only`); the keys are absent otherwise. The salt is never stored.
  Path-like kept strings become `h:<12 hex>`, the first 48 bits of HMAC-SHA256(salt, normalized value);
  `~/x` and `<home>/x` hash equal, so the same string gets the same tag everywhere in one snapshot (a
  relative value such as `src/app.py` hashes equal in every repo that has it) and
  joins (`projects` and `readiness` keys, `coverage.projects_collected`, session and correction
  project fields, a root's transcript key and `memory.by_project`) keep working. Whole values are
  hashed: no basename, extension or depth survives, and the tags of a project root and of files under
  it are unrelated. Any other occurrence of the home directory, the config directory, a collected
  project root or their dash-encoded forms (mapped to the root's own tag) inside a remaining string
  (full-mode free text such as hook commands) is replaced by the same tags, at a path boundary only
  (`/h/u/code/app2` is not treated as inside `/h/u/code/app`); what follows a tag is kept, so a hook
  command reads `bash h:<12 hex>/run.sh`. Hook script names under `projects/*/hooks` are names, not
  paths, and stay. Fixed vocabulary (event names, model ids, setting keys,
  scopes, enums) and plugin, skill, agent and MCP server names are never hashed, except that a model id
  containing `/` (a Bedrock ARN, which can carry an account id, or a gateway name) is hashed by the
  fail-closed sweep, so its tier is lost under `--hash-paths`. Families
  (`privacy.PATH_FAMILIES` holds the patterns):

  | Family | Hashed |
  |---|---|
  | `project_roots` | project root directories: projects/readiness keys, session and correction project paths, coverage.projects_collected, collection_scope.project, session and worktree roots |
  | `transcript_keys` | transcript directory keys (dash-encoded project paths): memory and per-project transcript maps |
  | `config_files` | settings, instruction, managed and MCP config file paths, previous audit file names, the drift log path and the /insights report path |
  | `plugin_paths` | plugin install roots, plugin component files and declared mod modules (`mod.module`) |
  | `referenced_files` | file and directory names taken from repos and configs: CLAUDE.md dead references, missing hook scripts, additional directories, memory file names, rules and skill `paths:` frontmatter (hashed whole), SDK call-site file names, files that read undeclared env variables (`readiness.*.env.undeclared[*].files`), MCP executables |
  | `other_paths` | fail-closed counter: path-like kept strings and dict keys (whitespace-free, not a URL or `name/N` basis string) that no family above names, hashed after the families so a new field is hashed, not leaked |
  | `free_text_scrubbed` | counter: strings and dict keys in which a known home, config or project directory was replaced by its tag (full-mode free text such as hook commands) |

  `memory.similar_across_projects` pairs carry `a_project`, `a_file`, `b_project`, `b_file` and
  `shared_count` (additive; `a` and `b` stay `<project key>/<file>`). Hashed, `a_project`/`b_project`
  take the tag of that project's root (as in `memory.by_project`), `a_file`/`b_file` the tag of the
  whole file name, `a`/`b` one tag of the whole string, and `shared` (name-derived words) is emptied
  while `shared_count` keeps how many there were.

  Consumers: tags join within one snapshot. Across audits they match only with the same
  `--hash-salt-file` (the compare-between-audits check needs equal `projects_collected`, so a
  per-run salt turns comparison off with "Collected projects differ"). `prune_permissions.py
  --snapshot` and project-scoped `ledger.py` refuse a hashed snapshot (they open or match real paths);
  `query_snapshot.py` prints a `hashed paths` line first. Additive within snapshot v1.
- `ledger_signals` (only with `--ledger`): `status` `collected`/`invalid`, and per active non-metric entry
  post-fix `matches`, `sessions_matched`, `sessions_scanned`, `complete`, `from`, `to`, `selector_sha`.
  Counts only; additive within snapshot v1.
- `drift_signals` (only with `--drift-log`): `status` `collected`/`invalid`, `path`, entry and
  malformed counts, first and last dates, and per signal `last_value`, crossing count, first and
  last crossing dates and `scopes`. Counts, dates and scalars only; additive within snapshot v1.
- `harness_overhead`: optional; counts, sizes, dates, plugin names, relative script paths and
  pattern ids. Additive within snapshot v1. `global.plugin_session_start_hooks` entries gained
  `basis` (`file_size_estimate`).
- `extensions.plugins[].components[].mod` (hooks components of a plugin with `hooks.json`
  `modules`): optional; `module` (declared relative path), `exists`, `bytes`, `events[]`, `calls[]`
  (identifier-shaped names from a heuristic scan), `truncated`, and `reason` when unread.
  `settings[].mods`: `prepend_plugins`, `append_plugins`, `guard_options_ignored` booleans;
  `allow_managed_mods_only`, `allow_mods_override_deny_rules` and `prepend_names_guard`
  true/false/null (null: unset, non-boolean or not a managed file). Guard options are read only from
  `pluginConfigs["cc-plugin-sec-default@builtin"].options` in managed settings; no plugin ids are kept.
  Additive within snapshot v1.
- `extensions.mcp_servers[]` exposure fields, `extensions.mcp_project_state`,
  `extensions.mcp_name_collisions` and `transcripts.tool_errors`: optional; names, counts,
  booleans, enums and OAuth scope tokens only; additive within snapshot v1.
- `transcripts.subagent_models` and `transcripts.request_params`: optional; observed, undocumented
  transcript shapes (Claude Code 2.1.310, 2026-10-25). `subagent_models.rows[]`: `agent_type`,
  `requested_model` (the meta `model`: usually the model Claude passed for the call, `inherit` for
  forks; null when none), `actual_model` (majority
  model of the file's assistant messages), `spawns`, `tokens` (volume, includes cache reads), `cache_read_tokens`; plus `files`, `meta_absent`,
  `meta_unusable`, `omitted` (rows, spawns, tokens, cache_read_tokens beyond the 30-row cap) and `configured`
  (`model_env`, `force_env`: whether `CLAUDE_CODE_SUBAGENT_MODEL` / `_FORCE` are env keys of any
  collected settings; names only). `request_params.{main,sdk,agent,other}`: `requests`, `by_model`,
  `by_effort`, `by_thinking` (`[value, count]` pairs, value null when absent) and `cache_breakpoints`
  (`1h`, `5m`, `other`). Names, counts and booleans only; agent descriptions, tool-use ids, prompts,
  blobs and hashes are never stored. Additive within snapshot v1.
- `transcripts.tool_search_observed` (boolean, or null when no main-thread session fell in the window) and `transcripts.cache.context_tokens`
  (`median`, `p90`, `responses`): optional, additive within snapshot v1. `tool_search_observed` is
  true when any main-thread record in the window is a `deferred_tools_delta` attachment (observed,
  undocumented; `coverage.md`). `context_tokens` is input + cache-creation + cache-read tokens per
  deduplicated main-thread response (measured), the basis for the cache re-read estimate in
  `references/cache-effects.md`.
- `config_conflicts` (always emitted by current collectors, optional in the schema):
  - `stacks`;
  - `hook_duplicates` (stack, event, normalized matcher, type, 16-hex `fingerprint`, `effect`,
    sources with layer/path/plugin);
  - `permission_overlaps` (stack, allow and covering rule with layer/path, redacted rule text,
    covering list, `match`);
  - `*_omitted` counts.

  Settings summaries also carry:
  - `shape_issues` when present: sorted key paths whose value had the wrong type and was dropped
    (`permissions`, `permissions.allow`, `hooks`, `env`, ...); a managed file with any is `partial`
    with reason `invalid_entries`;
  - `permissions.rule_shape_issues`;
  - `scope_ignored_keys` (non-managed files, when non-empty): `{key, scope}` for each setting the file's
    layer (user, project or local, from the file location) cannot set, matched at the nested path;
    `scope` is `user_or_managed`, `managed`, `global_config`, `user_local_managed` or `user`. Table:
    settings reference, fetched 2026-10-24. Static, names only; `null` values and keys absent from
    the table are not reported;
  - `ignored_env_keys` (same files, when non-empty): `{name, reason}` for each `env` name Claude Code
    ignores there; `reason` is `project_local`, `every_file`, `telemetry_unless_off` or `ignored_if_1`
    (env values are never collected, so the last two are conditional). Managed files get neither field;
  - handler `fingerprint`, and `on_failure` (`command`/`http`, a documented value only), `background`
    (a command hook with `async` or `asyncRewake`),
    `issues`/`unknown_fields`/`plugin_relative` when present.

  Additive within snapshot v1.
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

`global.version` and `global.doctor` retain their string type but report `unavailable:`;
their coverage sources are `not_checked` with reason `cli_diagnostics_not_run_read_only`.
The collector no longer launches CLI diagnostic commands because startup was observed to
write configuration, backups and telemetry in a fake home (CLI 2.1.273, 2026-09-16).
The official [CLI reference](https://code.claude.com/docs/en/cli-reference), checked on
2026-09-16, describes `claude doctor` as read-only diagnostics; that description does not
negate the observed startup writes. Existing local update metadata is still read as evidence,
but is not proof of the currently running version. No version is inferred from install paths.

Schema dialect and object/required/additional-property semantics checked 2026-09-16 against
the [JSON Schema 2020-12 specification](https://json-schema.org/draft/2020-12) and
[object reference](https://json-schema.org/understanding-json-schema/reference/object).
This is the plugin's own data contract, not a Claude Code configuration schema.
