# apply_ops.py: deterministic sandbox settings changes

## Purpose

`scripts/apply_ops.py` applies approved `set` and `remove` operations to allowlisted `sandbox.*`
keys in settings files. It is a dry run unless `--apply --backup-dir DIR` is given. SKILL.md Step 5
item 7 requires it for every sandbox change; do not substitute Write/Edit.

```
python3 ${CLAUDE_SKILL_DIR}/scripts/apply_ops.py --ops <file> [--apply --backup-dir DIR] [--claude-dir DIR]
```

## Cache effect

Every op row in the plan and apply output carries `cache_effect` (`effect`, `label`, `source`,
`note`), from the table in `references/cache-effects.md`; the result carries `cache_effects_note`
and, with `--snapshot` and a possibly invalidating effect, a labelled `cache_estimate`. Sandbox keys
are `unknown`: settings reload mid-session, but the prompt-caching page does not say what they do to
the cache. Information only: no status, ordering or refusal depends on it.

## Sources

Keys, types and scopes: fetched 2026-09-29 and re-checked 2026-11-11, raw pages; refetch with `scripts/fetch_doc.py en/<page>.md <out>`:

- <https://code.claude.com/docs/en/settings-reference.md>
- <https://code.claude.com/docs/en/sandboxing.md>
- <https://code.claude.com/docs/en/settings.md>

`settings-reference.md` holds the per-key reference (Scope, Type, Default). A key documented after
that date is refused as `unknown_key` until the allowlist gets a row and a test (a code change).

## Ops file

Write it to `$TMPDIR`. It is parsed strictly (duplicate keys and non-finite numbers rejected), at
most 1 MiB.

```json
{"version": 1,
 "targets": [
  {"file": "~/code/app/.claude/settings.local.json",
   "expect_file": "sha256:3b1f…",
   "ops": [
    {"op": "set", "path": "sandbox.filesystem.allowWrite", "value": ["~/.cache/uv"],
     "expect": {"absent": true}},
    {"op": "set", "path": "sandbox.failIfUnavailable", "value": true,
     "expect": {"value": false}},
    {"op": "remove", "path": "sandbox.excludedCommands", "expect": {"sha256": "9c0e…"}}]}]}
```

- Top level: exactly `version` (1) and `targets` (1-20).
- Target: exactly `file`, `ops` (1-50) and optional `expect_file`. `file` is absolute or starts
  with `~/`.
- Op: exactly `op`, `path`, `expect`, plus `value` for `set` only. Paths are dotted leaf keys.
- `expect` has exactly one of `{"value": <json>}`, `{"sha256": "<64 hex>"}` (canonical-JSON
  SHA-256, as `ledger.fingerprint`) or `{"absent": true}`. `remove` with `absent` is invalid.
- `expect_file` is `"sha256:<64 hex>"` or `"absent"`. Copy it from the dry run's `file_sha256` for
  that target; `--apply` refuses a target without it.

## Targets

- User: `<claude config dir>/settings.json`. Project: `<dir>/.claude/settings.json`. Local:
  `<dir>/.claude/settings.local.json`. Anything else is `target_not_settings`.
- Managed settings are refused (`managed_refused`); managed changes go to the administrator.
- The target and its `.claude` directory must not be symlinks; there is no override.
- A missing target is created (exclusively, mode 0600, no backup, `created: true`) only when its
  parent directory exists and every op is a `set` with `{"absent": true}`.
- Project targets carry the warning `shared_project_file`; Step 5 item 3 still decides whether to
  edit a git-tracked file.
- A `reformat: true` plan means the write also normalizes whitespace (2-space indent, key order kept).

## Allowlist

Value kinds: `bool`; `str_list` (array of non-empty strings); `path_list` (same, plus the warning
`wildcard_ignored_on_linux` for an entry with `*`, `?` or `[` once a trailing `/**` is removed);
`port` (integer 1-65535, not boolean); `str_to_str_list`; `credential_files`; `credential_env`.

- `str_to_str_list`: an object whose keys are non-empty strings and whose values are `str_list`.
- `credential_files`: an array of objects with `path` (non-empty string) and `mode` (`deny` or
  `mask`). A `mask` entry may add `extract` (non-empty string), `onExtractNoMatch` (`warn`, `deny`
  or `error`), `decode` (`jwt`), `maskClaims` (non-empty `str_list`, needs `decode`),
  `maskDuplicates` (bool) and `injectHosts` (`str_list`). A `deny` entry takes no other field. A
  field outside this documented list is `unknown_credential_field` (fail closed).
- Every `mask` entry must list `injectHosts` (`inject_hosts_required`): without it the sandbox proxy
  would send the real value to every host in `sandbox.network.allowedDomains`. Each host is an exact
  lowercase DNS name, an IPv4 address or a canonical bare IPv6 address, with no wildcard, scheme,
  path, port or userinfo (`inject_host_invalid`), and must already appear verbatim in
  `sandbox.network.allowedDomains` of the same target file before the batch's ops (IPv6 in
  brackets there, as in sandboxing "Mask credentials"; `inject_host_not_allowed`). Adding the host
  is a separate apply the user approves on its own, so a batch that adds the host and the masked
  credential together is refused. A wildcard allowed-domain entry does not count. Raw docs checked 2026-11-11 (settings-reference
  `sandbox.credentials.envVars`/`files`, sandboxing "Mask credentials").
- While any `mask` entry without (or with an empty) `injectHosts` exists, an op that lets sandboxed
  traffic reach more destinations is refused (`widens_credential_injection`): the proxy substitutes
  such an entry's real value on requests to every host in `allowedDomains`, and network settings
  merge across scopes (sandboxing "Mask credentials", fetched 2026-11-11). The mask is looked for in
  the target file, in user `settings.json` (for a project or local target) and in managed settings
  (`managed-settings.json` and each `managed-settings.d/*.json`, the collector's file set), each
  read by shape only through a symlink as the collector reads it and never echoed. A source that
  exists but cannot be read or parsed (including a dangling symlink or an unlistable
  `managed-settings.d`) counts as holding one (fail closed). Judged against the target file before
  the batch, the refused ops are:
  - `sandbox.network.allowedDomains`, `allowUnixSockets`, `allowMachLookup`: a `set` that adds an
    entry the file does not list;
  - `sandbox.network.deniedDomains`: a `remove`, or a `set` that drops a listed entry (a denied
    entry blocks a host even under a broader allowed wildcard);
  - `sandbox.network.strictAllowlist`: a `remove` or a non-`true` `set` while it is `true` (off,
    hosts outside the allowlist are prompted for or, in bypass mode, allowed, and a repository's
    `allowedDomains` apply again);
  - `sandbox.network.httpProxyPort`, `socksProxyPort`: a `set` to a new port (once a port applies,
    `allowedDomains`, `deniedDomains` and `strictAllowlist` stop applying to that traffic, sandboxing
    "Custom proxy configuration");
  - `sandbox.network.allowAllUnixSockets`, `allowLocalBinding`, `sandbox.enableWeakerNetworkIsolation`:
    a `set` to `true` while not `true` (listed in sandboxing among the network keys that loosen the
    sandbox).
  Narrowing, keeping or tightening them is allowed. To proceed, first add `injectHosts` to the mask
  entry (its own approved apply, or the administrator's for managed settings), then widen.
- `credential_env`: the same with `name` instead of `path` and no `maskDuplicates`. `extract`
  together with `decode` is `invalid_value`, as is `decode` with an `onExtractNoMatch` other than
  `warn`.

| Key | Kind | Files | Notes |
|---|---|---|---|
| `sandbox.enabled` | bool | user, project, local |  |
| `sandbox.failIfUnavailable` | bool | user, project, local |  |
| `sandbox.autoAllowBashIfSandboxed` | bool | user, project, local |  |
| `sandbox.allowUnsandboxedCommands` | bool | user, project, local |  |
| `sandbox.excludedCommands` | str_list | user, project, local |  |
| `sandbox.enableWeakerNestedSandbox` | bool | user, project, local |  |
| `sandbox.enableWeakerNetworkIsolation` | bool | user, project, local |  |
| `sandbox.allowAppleEvents` | bool | user |  |
| `sandbox.allowNestedUserNamespaces` | bool | user | a project `true` is ignored; set refused in project/local files |
| `sandbox.ignoreViolations` | str_to_str_list | user, project, local |  |
| `sandbox.filesystem.allowWrite` | path_list | user, project, local | warns `wildcard_ignored_on_linux` |
| `sandbox.filesystem.denyWrite` | path_list | user, project, local | warns `wildcard_ignored_on_linux` |
| `sandbox.filesystem.denyRead` | str_list | user, project, local |  |
| `sandbox.filesystem.allowRead` | str_list | user, project, local |  |
| `sandbox.filesystem.disabled` | bool | user |  |
| `sandbox.network.allowUnixSockets` | str_list | user, project, local |  |
| `sandbox.network.allowAllUnixSockets` | bool | user, project, local |  |
| `sandbox.network.allowLocalBinding` | bool | user, project, local |  |
| `sandbox.network.allowMachLookup` | str_list | user, project, local |  |
| `sandbox.network.allowedDomains` | str_list | user, project, local |  |
| `sandbox.network.deniedDomains` | str_list | user, project, local |  |
| `sandbox.network.strictAllowlist` | bool | user |  |
| `sandbox.network.httpProxyPort` | port | user, project, local |  |
| `sandbox.network.socksProxyPort` | port | user, project, local |  |
| `sandbox.credentials.files` | credential_files | user, project, local | `mask` entries are user-only |
| `sandbox.credentials.envVars` | credential_env | user, project, local | `mask` entries are user-only |

Excluded keys are refused with `excluded_key`:

| Key | Reason |
|---|---|
| `sandbox.bwrapPath` | managed settings only |
| `sandbox.socatPath` | managed settings only |
| `sandbox.filesystem.allowManagedReadPathsOnly` | managed settings only |
| `sandbox.network.allowManagedDomainsOnly` | managed settings only |
| `sandbox.ripgrep` | points the sandbox at an executable |
| `sandbox.network.tlsTerminate` | names CA certificate and key files |
| `sandbox.credentials.allowPlaintextInject` | credential proxy tuning, not in this version |
| `sandbox.credentials.awsPairs` | credential proxy tuning, not in this version |
| `sandbox.credentials.sigv4` | credential proxy tuning, not in this version |

## Statuses and reasons

Target status: `planned`, `unchanged`, `rejected`, and after `--apply` `applied`, `blocked` or
`verify_failed`. Exit codes: 0 when every target is `planned`, `unchanged` or `applied`; 1 for any
other status or an invalid ops file (JSON still printed); 2 for usage errors such as `--apply`
without `--backup-dir`. Validation is all-or-nothing across targets; writes are per target.
`--apply` writes nothing at all when any target is rejected, lacks `expect_file` or has a stale
`expect_file` (that target is `changed_since_plan`, the others `not_applied_other_target_failed`).

Top-level `applied` only echoes the mode (whether `--apply` was given). A write happened only where
a target's `status` is `applied` and `verified` is `true`; never claim success from `applied`.

- `invalid_ops_file`: the ops file is missing, too large, not valid JSON (duplicate keys and non-finite numbers included) or structurally wrong; nothing is read (exit 1, top-level `error`).
- `duplicate_path`: the same path appears twice in one target.
- `duplicate_target`: the same file appears in two targets, including two spellings that resolve to one file (top-level `error`, no targets listed).
- `relative_path`: `file` is neither absolute nor `~/`-relative.
- `managed_refused`: the target is managed settings (managed directory, `managed-settings.json`, `managed-settings.d`); checked before any read.
- `target_not_settings`: the target is not a user, project or local settings file.
- `symlink`: the target or its `.claude` directory is a symlink (no override).
- `unreadable`: the target cannot be read or is not a regular file (for example a FIFO or directory).
- `too_large`: the target is larger than 8 MiB.
- `invalid_json`: the target is not UTF-8, not JSON, has duplicate keys, oversized integers or a non-object top level.
- `no_parent_directory`: a missing target whose parent directory does not exist.
- `not_allowlisted`: the path is outside `sandbox.`.
- `unknown_key`: a `sandbox.*` path that is not documented.
- `excluded_key`: a documented key on the excluded list (table above).
- `not_a_leaf`: a parent object (`sandbox`, `sandbox.filesystem`, `sandbox.network`, `sandbox.credentials`); address leaf keys.
- `scope_not_honored`: a `set` of a user-only key, or of a `mask` credential entry, in a project or local target; the docs say it is ignored there (`remove` is not checked).
- `invalid_value`: the value does not have the documented type.
- `unknown_credential_field`: a credential entry has a field outside the documented mask fields.
- `inject_hosts_required`: a `mask` credential entry has no (or an empty) `injectHosts`.
- `inject_host_invalid`: an `injectHosts` entry is not an exact host (wildcard, scheme, path, port, userinfo, upper case, non-canonical IPv6).
- `inject_host_not_allowed`: an `injectHosts` host is not already listed verbatim in `sandbox.network.allowedDomains` of the same file before the batch's ops.
- `widens_credential_injection`: the op widens sandbox egress (allowedDomains, deniedDomains, strictAllowlist, proxy ports, Unix sockets, Mach lookup, local binding, weaker network isolation; list above) while a `mask` entry without `injectHosts` exists in the target file, user `settings.json` or managed settings (or one of them cannot be checked); add `injectHosts` to the mask entry first.
- `precondition_mismatch`: the `expect` precondition does not hold; the row shows the redacted current value and `current_sha256` so the change can be re-planned.
- `absent`: `remove` of a key that does not exist.
- `type_conflict`: an intermediate path element exists but is not an object.
- `op_rejected`: target status when any of its op rows is rejected.
- `expect_file_missing`: `--apply` without `expect_file` on a target.
- `not_applied_other_target_failed`: `--apply` wrote nothing because another target was rejected or had a stale `expect_file`.
- `changed_since_plan`: the file hash or identity differs from the plan, a file was created after planning, or the target disappeared or stopped being a regular file.
- `backup_failed`: the backup could not be written; the target is untouched.
- `write_failed`: the write failed (a failed exclusive create is cleaned up); the backup is kept.
- `verify_failed`: the re-read document differs from the planned one; no automatic restore, the output names the backup.
- `backup_dir_symlink`: `--backup-dir` is a symlink; nothing is written (top-level `error`, and on the planned targets).
- `backup_dir_unusable`: `--backup-dir` cannot be created; nothing is written (top-level `error`, and on the planned targets).

## Protected paths

Sandboxing docs (raw page re-checked 2026-11-11): "Inside the directories that sandboxed commands can write to,
the sandbox still denies writes to the files Claude Code loads configuration and code from". With
the sandbox on, `--apply` from a sandboxed Bash call therefore usually fails earlier with
`backup_dir_unusable` (top-level `error`, because the backup directory is under `~/.claude/backups`),
or else with `backup_failed` or `write_failed`; report it blocked. Running outside the sandbox needs the user's approval.

## Verification and revert

Verification is file-level: the re-read document must equal the planned one. The effective
sandbox merges scopes ("When managed settings set a Boolean key such as `enabled` or
`failIfUnavailable`, that value overrides anything a developer sets", settings reference, raw page
re-checked 2026-11-11), so a managed value can
override the one written; the SKILL.md probe still runs.

Revert by copying the named backup over the target, or by deleting a `created` file.
