# Privacy: metadata-only mode and contextual secret detection — design

Date: 2026-09-29. Status: scope decided by the user; spec approved 2026-09-30 as a controller
ruling during the unattended run (pre-flighted against the plan on main 60f4ff6).
Roadmap item: "**Privacy:** metadata-only collection/export, contextual secret detection and fuller
provenance for free-text evidence. Tune detection against realistic fixtures." (`docs/roadmap.md`).
Inventory base: working tree at `7135b8e` (branch `fix/parked-followups`). Plans 2A, 2B and 3 land
before this one; their new fields are swept in the last task (see "Sweep").

## Goal

Two privacy improvements to the collector:

1. **`collect.py --metadata-only`** (opt-in). The snapshot keeps structure, identifiers, paths,
   counts, sizes, flags and enums. It replaces free text with length markers: prompts, corrections,
   friction details, memory and skill descriptions, instruction excerpts, hook commands and targets,
   permission rule text, and the string values of structurally copied objects such as `sandbox`. The
   mode is recorded in `coverage`. The auditing model knows the mode and does not invent the missing
   text.
2. **Contextual secret detection** runs in both modes, on top of `redact()`/`sanitize()`. It catches
   high-entropy values next to key-like names that the current `SECRET_RE` misses, for example
   `AWS_SECRET_ACCESS_KEY=…`, `STRIPE_SECRET_KEY=sk_live_…`, `--api-token <v>`, `--password <v>` and
   `-e NAME=<v>`. It is tuned on a fixed fixture table of true positives and must-not-flag negatives.

Success:

- A fake home with a unique canary in every free-text source produces a full-mode snapshot that
  contains every canary and a metadata-only snapshot that contains none of them. Both snapshots
  validate against schema v1.
- In metadata-only mode, every string leaf is either a marker or sits at a path in the
  classification registry (`privacy.KEPT_STRING_FIELDS`). A new unclassified string field fails a
  test.
- Every fixture true positive is redacted by the new detector and missed by `SECRET_RE` alone. Every
  must-not-flag negative comes back from `redact()` unchanged.
- `coverage.privacy.mode` is `full` or `metadata-only`. SKILL.md, report-format.md and checklist.md
  tell the model what it may and may not conclude in metadata-only mode. The renderer shows the mode.

## Decisions (user, 2026-09-29)

1. Metadata-only is an opt-in collector flag that drops free text. It records the mode in coverage.
2. Named fields: session `first_prompt`, `facet_friction_details`, correction `samples`, descriptions
   (memory and skill/command), hook `target` and `hook_commands`, risky rule text, the `deny` list and
   `sandbox` values. Also covered: any other free text found by a full inventory.
3. Contextual secret detection applies in both modes and is tuned on fixtures.
4. Snapshot schema stays v1 and additive.

Correction to the brief: `collect.py:553` is the **memory** entry description. Skill and command
descriptions are `frontmatter.description`/`when_to_use` in `instructions.entries[]` and
`extensions.plugins[].components[]`. Both are covered.

## Approach

A new stdlib module `scripts/privacy.py` owns both features, so `collect.py` (1,600 lines) grows only
by wiring.

- **Detection:** `privacy.contextual_redact(text)` is called at the end of `collect.redact()`. Every
  field-level redaction and the final `sanitize()` pass therefore get it. `sanitize()` also runs
  `privacy.contextual_secret(key, value)` on JSON key/value pairs, which is the structural shape
  `SECRET_KEY_NAMES` misses for compound names. `RISKY_RULES`' `secret-literal-in-rule` also fires on
  a contextual hit.
- **Masking:** `privacy.mask_snapshot(snap)` is one post-pass in `build_snapshot`. It runs after
  every derived join that reads text (`claude_env_hook` reads `hook_commands`, `skill_listing` sums
  description lengths) and before `sanitize()` and validation. It walks the known free-text
  locations (table below), replaces each string with a marker in place, and returns per-family
  counts. It is one choke point, and a registry test keeps it complete.

## Components

| Unit | Responsibility | Writes |
|---|---|---|
| `scripts/privacy.py` (new) | Detector (`shannon`, `label_segments`, `contextual_secret`, `contextual_redact`, `CONTEXT_TOKEN`), markers (`marker`, `MARKER_RE`), masking (`mask_settings`, `mask_handler`, `mask_frontmatter`, `mask_snapshot`), classification registry `KEPT_STRING_FIELDS` | nothing |
| `scripts/collect.py` | `redact()`/`sanitize()` call the detector; `secret-literal-in-rule` includes contextual hits; `hook_handler_entry` gains `server`/`tool` (mcp_tool) and `target_origin` (http) in both modes; `--metadata-only` flag; `coverage.privacy`; clarity conflict | snapshot only |
| `scripts/query_snapshot.py` | One fixed banner line before the data when the mode is metadata-only | stdout |
| `scripts/report_state.py`, `render_report.py` | Validate optional `profile.privacy`; show a badge and a footer variant | HTML report |
| `references/snapshot.schema.json` | Optional typed `coverage.privacy` | — |
| `SKILL.md`, `references/report-format.md`, `checklist.md`, `coverage.md`, `snapshot-format.md`, README, CHANGELOG, `docs/roadmap.md` | Mode option, model guidance, contract | — |

`drift.py` does not get the flag (Ruling 13). `build_snapshot` reads
`getattr(a, 'metadata_only', False)`, so drift is unaffected.

## Metadata-only output

**Marker:** a masked string becomes `[metadata-only: N chars]`, where N is the length of the collected
value, which is already redacted and truncated. Lists keep their length, so a count stays a count.
Dict keys, numbers, booleans and `null` are never changed. `privacy.MARKER_RE` =
`\[metadata-only: \d+ chars\]\Z`. Masking skips a value that already matches `MARKER_RE`. Several
lists share dict objects before serialization: `heaviest_sessions`/`most_friction_sessions` and the
combined `settings` list. Without the skip, a second visit would mask the marker.

**`coverage.privacy`** (always emitted by the new collector; optional in the schema):

```json
{"mode": "metadata-only", "free_text": "replaced", "marker": "[metadata-only: N chars]",
 "replaced_fields": {"first_prompt": 8, "hook_commands": 5, "permission_risky": 3},
 "redactions": {"pattern_or_key": 2, "contextual": 1}}
```

Full mode has `"mode": "full"`, `"free_text": "collected"` and `"replaced_fields": {}`. `redactions`
counts occurrences of `[REDACTED]` and `[REDACTED:context]` in the final serialized snapshot. These
are occurrences, not unique secrets. Metadata-only mode also adds a coverage source
`{"source": "free_text_fields", "status": "not_checked", "reason": "metadata_only_mode"}` and this
limitation: "Metadata-only mode: free text (prompts, corrections, friction details, memory and skill
descriptions, instruction excerpts, hook commands and targets, permission rule text, sandbox and other
structural values) was replaced by length markers at collection; findings that need that text are not
assessable from this snapshot." Reports that copy coverage therefore carry the mode without extra
work.

## Field inventory (every string the snapshot emits)

Classes: **id** = identifier or name (setting keys, env var names, plugin, MCP, tool and model
names, file names, flag names). **enum** = a closed value set. **path** = a filesystem path or glob
(home-relative where the collector already does so). **const** = collector-authored text such as
notes and limitations. **free** = free text taken from user content. In metadata-only mode, **free**
is masked and every other class is kept.

"Settings summary" (`summarize_settings`) appears at `global.settings[]`,
`managed_settings.settings[]`, `projects.*.settings[]` and `instructions.settings_candidates[]`.

| Location | Field | Class | Metadata-only |
|---|---|---|---|
| settings summary | `path`, `scope` | path, enum | keep |
| settings summary | `keys[]`, `env_keys[]`, `enabled_plugins` (keys) | id | keep |
| settings summary | `model` | id | keep |
| settings summary | `model_settings` | unknown-shape copy | mask string leaves (R4) |
| settings summary | `hooks.{event}[]` (matchers) | id (tool-name pattern) | keep (R19) |
| settings summary | `hook_commands[]` | free | mask |
| settings summary | `hook_handlers[].event`, `.type`, `.matcher` | enum, id | keep |
| settings summary | `hook_handlers[].target` (command, URL, prompt, `server:tool`) | free | mask, every type (R12) |
| settings summary | `hook_handlers[].server`, `.tool`, `.target_origin` (new, both modes) | id | keep |
| settings summary | `hook_handlers[].header_keys[]`, `.allowed_env_vars[]` | id | keep |
| settings summary | `missing_hook_scripts[]` (redacted command) | free | mask |
| settings summary | `sandbox` | unknown-shape copy | mask string leaves (R4) |
| settings summary | `permissions.deny[]` | free (rule text) | mask |
| settings summary | `permissions.risky.{flag}[]` | free (rule text); flag keys are enum | mask values, keep keys |
| settings summary | `permissions.default_mode` | enum | keep |
| settings summary | `permissions.additional_dirs[]`, `.missing_additional_dirs[]` | path | keep |
| settings summary | `other.statusLine` | unknown-shape copy (holds a command) | mask string leaves |
| settings summary | `other.outputStyle`, `other.autoUpdates` | id/enum | keep |
| `global` | `skills[]`, `agents[]`, `commands[]`, `mcp_user[]`, `installed_plugins[]` | id | keep |
| `global` | `version`, `doctor` | const | keep |
| `global` | `last_update` (copied `.last-update-result.json`) | unknown-shape copy | mask string leaves |
| `global` | `plugin_session_start_hooks[]` (plugin, version, matchers, basis) | id, enum | keep |
| `managed_settings` | `sources[]`, `effective_policy` | path, enum, const | keep |
| `projects.{path}` | `claude_md_dead_refs[]` | path (from CLAUDE.md text) | keep (R3) |
| `projects.{path}` | `mcp_servers[]`, `skills[]`, `agents[]`, `commands[]`, `hooks[]`, `git.*` | id, enum | keep |
| `readiness.{path}` | all fields (pins, lockfiles, make targets, env names, relative files, model ids, dates) | id, path, enum | keep |
| `memory.by_project.*.entries[]` | `file` | id | keep |
| `memory.by_project.*.entries[]` | `description` | free | mask |
| `memory.similar_across_projects[]` | `a`, `b`, `shared[]` | path, id (from file names) | keep |
| `usage` | `*_note`, `latest_insights_report` | const, path | keep |
| `usage` | `top_tools`, `tool_error_categories`, `facet_friction`, `sessions_per_project`, `daily_token_totals_recent[].date` | id, enum, path | keep |
| `usage.heaviest_sessions[]`, `.most_friction_sessions[]` | `project`, `start` | path, date | keep |
| same | `first_prompt` | free | mask |
| `usage` | `facet_friction_details[]` | free | mask |
| `corrections` | `by_project`, `samples[].project` | path | keep |
| `corrections` | `samples[].text` | free | mask |
| `transcripts` | notes, `context_baseline_by_project_median`, `mcp_calls_by_server`, `mcp_configured_but_unused` | const, id | keep |
| `previous_audits[]`, `generated`, `collection_scope.*` | — | path, date, enum | keep |
| `instructions.entries[]`, `extensions.plugins[].components[]` | `source`, `scope`, `status`, `kind`, `relation`, `active_state`, `reason`, `frontmatter_status`, `estimate_basis` | path, enum | keep |
| same | `excerpt` (up to 32 KiB of file text) | free | mask |
| same | `frontmatter.{name, model, context, agent, disable-model-invocation, user-invocable, paths}` | id, enum, path | keep (R5) |
| same | `frontmatter.{description, when_to_use, allowed-tools, disallowed-tools, hooks}` and any other key | free | mask (R5) |
| `extensions.plugins[].components[].handlers[]` | hook handler shape | as settings `hook_handlers` | as above |
| `instructions` | `sources[]`, `contexts[]`, `agents_md_setting_observed[]`, `limitations[]` | path, enum, const | keep |
| `extensions.mcp_servers[]` | `name`, `transport`, `executable`, `package_version_evidence`, `endpoint_origin`, `endpoint_detail`, `*_keys[]`, `*_variable_references[]`, `credential_mechanisms[]`, provenance | id, enum, path, const | keep |
| `extensions.plugins[]` | `name`, `scope`, `project`, `version`, `source`, `status`, `reason`, `manifest_keys[]`, `enablement_observations[].source` | id, path, enum | keep |
| `skill_listing`, `harness_overhead`, `ledger_signals`, `drift_signals`, `coverage` | all | id, enum, path, date, const | keep |
| `instruction_clarity.candidates[].excerpt` | free | — | never produced: the flag combination is refused (R6) |

Inventory notes:

- `inventory.py` and `extensions.py` already drop MCP argument values, URL paths and env/header
  values, and keep only names. `harness.py` keeps no command text. The drift log holds none. Ledger
  signals are counts and hashes.
- In metadata-only mode, `skill_listing.observed_description_chars` still reports the
  description lengths. It is computed before the pass, so it gives a size without text.

## Contextual secret detector

`contextual_redact(text)` scans with one regex and decides each candidate in Python:

```
(?<![\w.-])(?:(?P<flag>--?[A-Za-z][\w.-]{0,63})(?:\s+|=)|(?P<label>[A-Za-z][\w.-]{0,63})["']?\s*[:=]\s*)
["']?(?P<value>[A-Za-z0-9+/_.~=-]{6,512})(?![A-Za-z0-9+/_.~=:-])
```

`contextual_redact` is a search loop: when a candidate is not a hit, the scan resumes at that
candidate's value start, so a label inside a flag value (`-e NAME=…`, `--header=X-Api-Key:…`) is
examined next (amended 2026-09-30: `=` is in the value charset, so a plain `re.sub` lets the `-e`
value swallow the inner label and T10 fails). A hit replaces only the value with
`[REDACTED:context]`. The label, separator and quote are kept (R9).

**Label segmentation:** split camelCase (`sessionKey` becomes `session`, `key`), then split on
`[_.\-]`, lowercase, strip leading dashes.

- **Password class:** the **last** non-numeric segment is in {`password`, `passwd`, `pwd`,
  `passphrase`, `pass`} or ends in `password`/`passwd` (e.g. `PGPASSWORD`). (Amended 2026-09-30: with
  "any segment", `--passWithNoTests --coverage` was redacted in the default full mode.)
- **Secret class:** any segment in {`key`, `secret`, `token`, `auth`, `credential`, `credentials`,
  `creds`, `signature`, `sig`, `cookie`, `session`, `pat`, `apikey`}, or a segment ending in `key`,
  `secret` or `token`.
- **Qualifier (never a secret label):** any segment in {`id`, `ids`, `name`, `names`, `file`,
  `path`, `dir`, `url`, `uri`, `env`, `var`, `type`, `kind`, `format`, `count`, `len`, `length`,
  `size`, `max`, `min`, `limit`, `ttl`, `sha`, `hash`, `digest`, `commit`, `rev`, `checksum`,
  `fingerprint`, `etag`, `hint`, `header`, `field`, `prefix`, `mode`, `source`, `ref`, `version`,
  `expiry`, `expires`}.

**Value rules.** Exclusions apply to both classes: a value starting with `-` (the next flag;
amended 2026-09-30, so `psql --password --host db` is not redacted), a reference (first char `_`, matching
`_looks_like_reference`, since `$<{(` cannot occur in the value charset), a path (starts with `/`,
`~` or `.`, or ends with `\.[a-z]{1,5}`), or SCREAMING_SNAKE (`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$`).

- **Password class:** length ≥ 6 and not excluded. No entropy test.
- **Secret class:** 16 ≤ length ≤ 512, not excluded, and:
  - not a UUID (8-4-4-4-12 hex);
  - not word-like: split on `[-_.]`, every non-empty segment is all-lowercase letters or all digits,
    and at least two segments are alphabetic with length ≥ 3;
  - character classes: contains a digit, or both upper and lower case;
  - Shannon entropy over characters ≥ **3.5 bits/char**.

Constants: `CONTEXT_MIN_LEN = 16`, `CONTEXT_MAX_LEN = 512`, `PASSWORD_MIN_LEN = 6`,
`ENTROPY_MIN = 3.5`. Every negative in the fixture table is excluded by a structural rule (no label,
qualifier, UUID, path, SCREAMING_SNAKE, word-like, short) except N18/N19, which exercise the entropy
guard on purpose. A shift of the threshold within 3.2–4.0 therefore cannot turn a structural
negative into a hit.

**Tuning set** (tests use exactly these strings; entropies marked ≈ are recorded by Task 1 from the
implementation):

True positives. Each is missed by `SECRET_RE` alone and redacted by `redact()`, keeping its label:

| # | Input | Why `SECRET_RE` misses it | H (bits/char) |
|---|---|---|---|
| T1 | `export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | `secret` not followed by `[:=]` | ≈4.6 |
| T2 | `STRIPE_SECRET_KEY=sk_prod_4eC39HqLyjWDarjtT1zdp7dc` | `sk_` is not `sk-` | ≈4.5 |
| T3 | `SECRET_KEY = "Zx9fK2mQ7vL1pR8tW3yB6nD4"` | compound label | 4.585 |
| T4 | `curl --api-token 9fK2mQ7vL1pR8tW3yB6nD4hJ https://api.example.com` | space separator | 4.585 |
| T5 | `mysql --password hunter22x -h db` | space separator (password class) | n/a |
| T6 | `GITHUB_PAT=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF` | no `ghp_` prefix | ≈4.9 |
| T7 | `sessionKey: 7Hq2LmX9pRt4VzK8wN3b` | camelCase label | 4.322 |
| T8 | `curl -H "X-Auth: 3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c" https://x.example` | `auth` label | 3.906 |
| T9 | `https://b.s3.amazonaws.com/f?X-Amz-Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024` | `signature` label | ≈3.8 |
| T10 | `docker run -e AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY app` | flag value is a label | ≈4.6 |
| T11 | JSON `{"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}` via `sanitize()` | normalized key not in `SECRET_KEY_NAMES` | ≈4.6 |

Must-not-flag. `redact(x) == x` (`SECRET_RE` leaves them too):

| # | Input | Guard |
|---|---|---|
| N1 | `git checkout 3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c` | no label |
| N2 | `commit_sha=3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c` | no secret word |
| N3 | `session_id=550e8400-e29b-41d4-a716-446655440000` | qualifier, UUID |
| N4 | `claude --resume 550e8400-e29b-41d4-a716-446655440000` | no secret word |
| N5 | `key_file=/home/user/.ssh/id_ed25519` | qualifier, path |
| N6 | `ssh_key: ~/.ssh/id_ed25519` | path |
| N7 | `api_key_env=ANTHROPIC_API_KEY_BACKUP` | qualifier, SCREAMING_SNAKE |
| N8 | `SIGNING_KEY=PROD_SIGNING_KEY_2026` | SCREAMING_SNAKE |
| N9 | `max_tokens=4096` | no secret word |
| N10 | `image=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==` | base64 image data: no secret label |
| N11 | `cacheKey: release-2026-09-29-build` | word-like |
| N12 | `sort_keys=True` | no secret word, short |
| N13 | `hotkey: ctrl+shift+k` | short |
| N14 | `session=2026-09-29T10:00:00Z` | value followed by `:` |
| N15 | `--token-file ./secrets/ci.token` | qualifier, path |
| N16 | `fingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8` | no secret word |
| N17 | `signature_hash=9b74c9897bac770ffc029102a200c5de` | qualifier |
| N18 | `session_key=aaaaaaaa11111111` | entropy 1.0 |
| N19 | `auth_token_2=abababababababab12` | entropy ≈1.5 |
| N20 | `KEYBINDINGS=vim` | short |
| N21 | `/home/u/code/token-service/src/auth_middleware.py` | no separator |
| N22 | `OPENAI_API_KEY=$(pass show openai)` | reference |
| N23 | `password_file=/run/secrets/db` | qualifier, path |
| N24 | `--session-id 7c9e6679-7425-40de-944b-e07fc1f90ae7` | qualifier, UUID |
| N25 | `[metadata-only: 143 chars]` | marker |
| N26 | `npx jest --passWithNoTests --coverage` | password word not the last segment; value starts with `-` (added 2026-09-30) |
| N27 | `psql --password --host db` | value starts with `-` (added 2026-09-30) |

Accepted over-redaction, asserted so that the behaviour is deliberate: A1
`cache_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` is redacted (a
high-entropy value under a `key` label). A2 `password: required` was already redacted by `SECRET_RE`
and stays unchanged.

Measured 2026-09-30 with the implementation (bits/char): T1/T10/T11 4.663, T2 4.601, T6 5.338,
T9 3.824, A1 3.786, N18 1.000, N19 1.503; the closest true positives to the threshold are T9 and
T8 (3.906).

Known limit: a hit's value is not re-examined for further labels; non-hits are, via the search
loop. A password under a compound flag whose last segment is not a password word (`--pass-db x`)
is missed; `SECRET_RE` still catches `password=`. Unlabelled opaque
tokens remain out of reach. Redaction stays best-effort, as SKILL.md already says.

## Model and report guidance

`SKILL.md`:

- Step 0 gains the option `privacy` (`full` · `metadata-only`, default `full`). "Don't read my
  prompts", "metadata only" and "privacy mode" map to `metadata-only`.
- Step 1 adds `--metadata-only`. It is refused together with `clarity=pilot`; tell the user and run
  with clarity off.
- A new paragraph after the untrusted-data paragraph:
  - Read `coverage.privacy.mode` first.
  - `[metadata-only: N chars]` means the text was deliberately not collected. Never guess,
    paraphrase or reconstruct it, and do not open transcripts, history, memory or instruction files
    to recover it unless the user asks for that specific item.
  - Findings cite the file, field, flag and count, never quoted text.
  - In `propose` mode, fixes describe the change's shape ("remove the 1 rule flagged
    `network-wildcard` in ~/.claude/settings.json"). The exact before/after is read from the file
    only after approval, in Step 5.
  - Checks that need text are marked `partial` or `not_checked` in `checks`, with a caveat.
  - Record `profile.privacy`.

Affected checks. `checklist.md` gets one line near the top that lists them:

- **Partial:** SEC-risky-allow (flags and counts, no rule text), SEC-sandbox (keys and booleans
  only), SEC-hooks (type, matcher, origin, header keys; no command or prompt), COST-model-default
  (`model_settings` values masked), LRN-friction (categories, no details), LRN-corrections (counts,
  no themes), LRN-duplicate-memory (file names only), HYG-missing-hook-script (count only).
- **Not checked:** SEC-docs-only-constraint, LRN-contradiction, LRN-enforce and the clarity pilot.
- **Unaffected:** readiness, cost metrics and harness overhead.

`report-format.md`:

- `profile.privacy` is optional, `full` or `metadata-only`.
- A metadata-only report quotes no collected text.

`report_state.py` validates `profile.privacy` when present. `render_report.py` adds a header badge
("Metadata-only collection · prompt, rule and instruction text were not collected") and a footer
variant. `query_snapshot.py` prints one fixed line before the data block when the mode is
metadata-only: `privacy mode: metadata-only (free text replaced by [metadata-only: N chars]
markers; do not reconstruct it)`.

## Schema

`snapshot_contract.py` supports only `$schema $id $defs $ref title description type const enum
minimum required properties additionalProperties items`, with type lists. There is no
`oneOf`/`anyOf`, so a string-or-object union cannot be expressed, and the v1 compatibility rule
forbids changing a field's type anyway (R1). The only schema change is an optional
`coverage.privacy`:

```json
"privacy": {"type": "object", "required": ["mode", "free_text", "replaced_fields", "redactions"],
  "properties": {
    "mode": {"enum": ["full", "metadata-only"]},
    "free_text": {"enum": ["collected", "replaced"]},
    "marker": {"type": "string"},
    "replaced_fields": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
    "redactions": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}}}
```

The settings summaries are untyped objects in the schema, so the new handler fields need no schema
change. `snapshot-format.md` documents the fields, the marker grammar and `[REDACTED:context]`.

## Rulings

Format: `Ruling: what — why — cost if wrong`.

1. **Ruling:** Masked strings become in-place marker strings `[metadata-only: N chars]`, not `oneOf`
   string|object and not a separate sibling shape — v1 compatibility forbids changing a field's
   type; the evaluator has no `oneOf`/`anyOf`; existing consumers do string operations on these
   fields (`claude_env_hook` join, drift fingerprints, `prune_permissions`) — machine consumers
   must regex-parse the marker (`privacy.MARKER_RE`). A structured replacement would need snapshot
   v2.
2. **Ruling:** Paths and names are kept, not hashed — findings must name the file to fix; hashing
   breaks section joins (`projects`/`readiness` keys), trends, decision fingerprints and ledger
   scope; the mode protects content, not structure — a shared metadata-only snapshot still reveals
   project, repo, plugin and host names. A future `--hash-paths` goes on the roadmap.
3. **Ruling:** `claude_md_dead_refs` count as paths and are kept — they are bounded to
   path-character backtick tokens, at most 15 per file — up to 15 CLAUDE.md-derived path strings per
   file leak.
4. **Ruling:** Unknown-shape structural copies (`sandbox`, `model_settings`, `other.statusLine`,
   `last_update`) have their string leaves masked; keys, numbers and booleans are kept — values of
   unknown shape can hold commands, domains or prose — SEC-sandbox breadth and COST-model-default
   values become partial (plan 3's derived sandbox counts, if any, stay).
5. **Ruling:** The frontmatter keep-list is {`name`, `model`, `context`, `agent`,
   `disable-model-invocation`, `user-invocable`, `paths`}; every other key is masked — allowed-tools
   are rule text, like permissions, and the rest is prose — skill permission-grant review is not
   assessable in this mode.
6. **Ruling:** `--metadata-only` with `--clarity-pilot` is a usage error (exit 2) — the pilot reviews
   excerpts, which this mode masks — none beyond one message.
7. **Ruling:** Masking is one post-pass before `sanitize()`, not per collector — derived joins need
   the text first; a single choke point can be guarded by a registry test — text lives in process
   memory during collection (it is never written).
8. **Ruling:** Marker length is the collected (redacted, truncated) length, not the raw source length
   — the raw value is not retained — `first_prompt` lengths cap at 120, frictions at 400.
9. **Ruling:** The contextual detector runs inside `redact()`, in both modes; it keeps the label and
   replaces the value with `[REDACTED:context]` — every field-level redaction and `sanitize()` get it
   for free; the label is the useful "which variable is set literally" signal — over-redaction of
   high-entropy non-secrets under key-like labels (A1, cache keys) is accepted.
10. **Ruling:** Thresholds: secret class length 16–512, entropy ≥ 3.5 bits/char, a class rule, UUID,
    path, SCREAMING_SNAKE and word-like exclusions; password class length ≥ 6 with no entropy test —
    the negatives rest on structure, and entropy only separates random from repetitive values — a
    short or low-entropy secret under a non-password compound label (for example a 16-char hex key,
    ~3.3 bits) is missed; under the strong labels `SECRET_RE` still catches it.
11. **Ruling:** `secret-literal-in-rule` also fires on a contextual hit — a literal
    `AWS_SECRET_ACCESS_KEY=` in an allow rule is exactly SEC-secret-literal — more such findings
    appear, and the prune category grows accordingly.
12. **Ruling:** Handlers gain `server`/`tool` (mcp_tool) and `target_origin` (http,
    `scheme://host`, the same logic as `extensions.endpoint_origin`) in both modes, and `target` is
    masked for every type — SEC-hooks keeps host and server evidence, and the classification registry
    stays unconditional — an http hook's host is visible in metadata-only snapshots.
13. **Ruling:** `drift.py` gets no `--metadata-only` — its log already holds no text, and its
    fingerprints need rule text in memory — none.
14. **Ruling:** In metadata-only mode the model does not recover masked text from source files
    without an explicit per-item request, and exact before/after is read only after approval — the
    user chose privacy for the whole audit, not only for the snapshot file — proposals are less
    specific until approval.
15. **Ruling:** `redactions` counts occurrences in the final snapshot text — this is stateless and
    deterministic, with no counter threaded through the collectors — it is not a count of unique
    secrets (documented).
16. **Ruling:** `coverage.privacy` is optional in the schema, although the collector always emits it
    — making it required would need v2 — older snapshots lack it; readers treat that as `full`.
17. **Ruling:** Report `profile.privacy` is validated only when present, and the renderer shows it —
    additive to report v1 — none.
18. **Ruling:** Empty strings in masked fields also become markers (`0 chars`) — this keeps the
    registry rule "every string leaf is a marker or classified" exceptionless — a few more bytes.
19. **Ruling:** Hook matchers are kept as identifiers — they are tool-name patterns that plan 2A's
    matcher checks need — a matcher regex that names a project is visible.

## Sweep of plans 2A, 2B and 3

These land first and add snapshot fields: 2A adds redacted rule text for the wildcard, conflict and
hook-matcher checks; 2B adds MCP exposure metadata and per-tool error clusters; 3 adds `apply_ops`,
possibly with a derived sandbox summary. The last task finds every string field added since
`7135b8e`:

```
git diff 7135b8e -- plugins/setup-audit/skills/setup-audit/scripts plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json
```

It classifies each field in this spec's inventory table. It adds free text to `mask_snapshot`, adds
the rest to `KEPT_STRING_FIELDS`, and plants a canary (free text) or value (kept) for each field in
the end-to-end fixture. Expected classes:

- 2A rule text: free.
- 2B tool and server names and counts: id. Tool descriptions and error-message snippets: free.
  Fingerprint hashes: id.
- 3 derived sandbox counts and booleans: kept. Domain and path lists: masked per R4.

## Testing

Fake homes only (`FakeHome` in `tests/test_collect.py`); stdlib `unittest`.

- **Detector:** every T row is redacted with its label kept and is missed by `SECRET_RE` alone. Every
  N row comes back unchanged. A1 is redacted. The `shannon` reference values are 4.0 for
  `0123456789abcdef` and 0.0 for `aaaa`. The `sanitize` key check covers T11, and N-shaped keys are
  unchanged. `flags()` for T1 inside a `Bash(...)` rule includes `secret-literal-in-rule`.
- **Masking units:** marker format; a settings summary built by `summarize_settings` from a dict with
  every handler type, deny rules, a risky allow rule, nested sandbox, `modelSettings` and
  `statusLine`; the frontmatter keep-list; per-family counts; shared objects masked once.
- **End to end:** a canary fixture shows every canary in full mode (proving the fixture reaches the
  snapshot), no canary in metadata-only mode, the same list lengths, keys, paths and counts in both
  modes, the classification-registry walk, and `[REDACTED:context]` only in leaves that contain the
  planted label.
- **Collector:** `coverage.privacy` in both modes; the source and the limitation in metadata-only
  mode; the clarity conflict exits 2; drift's `build_snapshot` stays `full`.
- **Schema:** a valid `coverage.privacy` passes; a bad mode or a negative count is rejected; a
  snapshot without `privacy` is still valid.
- **Consumers:** the query banner appears only in metadata-only mode; `profile.privacy` is validated;
  the renderer badge appears only for metadata-only.
- **Red-proof:** disabling one mask makes the canary test fail; removing one registry entry makes the
  registry test fail.

Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`,
`git diff --check`, coverage ≥ 88.

## Out of scope

- Hashing or pseudonymizing paths and names (`--hash-paths`; roadmap).
- Metadata-only export of an existing full snapshot, i.e. converting after collection.
- Per-field provenance tags for free-text evidence (the remainder of the roadmap item).
- Detecting unlabelled opaque tokens; vendor-prefix additions to `SECRET_RE`.
- Model evaluations of the new SKILL.md guidance (paid; separate approval).
- `drift.py` flag.
