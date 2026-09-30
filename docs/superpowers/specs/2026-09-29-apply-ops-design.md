# Deterministic apply, sandbox first — design

Date: 2026-09-29. Status: scope decided by the user (generic engine, sandbox allowlist); spec
approved 2026-09-30 as a controller ruling during the unattended run (pre-flighted against the plan).
Roadmap item: "Deterministic apply" in `docs/roadmap.md` ("structured approved operations with
preconditions, backup, minimal mutation and verification. Start with sandbox settings; do not
redesign all apply paths at once").

## Goal

Today an approved sandbox change is a model-authored Write/Edit of a settings file, guarded only
by prose in SKILL.md Step 5 ("Back up first", "Minimal edits", "Check every setting's key and value
type"). Nothing checks that the model edited the key it showed the user, that the value has the
documented type, that the file did not change since the user saw it, or that nothing else moved.

A new helper `scripts/apply_ops.py` takes a small JSON file of structured operations (`set` or
`remove` at a dotted key path, each with a precondition on the current value), prints a plan (dry
run, the default), and with `--apply` backs the file up, writes the minimal change atomically and
verifies it by re-reading. Only allowlisted `sandbox.*` keys are accepted in this version; the
engine is generic so later work can widen the allowlist key by key. SKILL.md Step 5 item 7 must
use it for every sandbox change, with the same "no manual substitution" rule the skill already
applies to the permission pruner.

Success:

- A dry run never writes anything (no file, no backup, no temp file).
- `--apply` writes only when every target validated, every precondition held and every target's
  bytes still hash to the `expect_file` the dry run printed.
- After a write, the re-read document equals the planned document exactly (canonical JSON), so the
  op took effect and nothing else changed; otherwise the target is reported `verify_failed` with
  its backup path.
- Every red case below is refused with a named reason and leaves the target byte-identical:
  precondition mismatch, non-allowlisted key, symlinked target, file changed between plan and
  apply, invalid value type, remove of an absent key, managed or non-settings target, symlinked
  backup directory. Backups never collide or overwrite.
- SKILL.md item 7 names the helper and forbids manual substitution; a doc-sync test keeps
  `references/apply-ops.md` and the allowlist constant in step.

## Sources (raw pages, fetched 2026-09-29 with `curl -sL … .md`)

- `https://code.claude.com/docs/en/settings-reference.md` holds every `sandbox.*` key with Scope,
  Type and Default. (`settings.md` itself now mentions sandbox only once, at line 482; the key
  reference moved to `settings-reference.md`, which the plugin's `docs-map.md` already names.)
- `https://code.claude.com/docs/en/settings.md`: file scopes, reload behaviour.
- `https://code.claude.com/docs/en/sandboxing.md`: `/sandbox` writes, protected paths, credentials.

Quotes the design rests on (all fetched 2026-09-29):

- Scope meaning (settings-reference): "`User` is `~/.claude/settings.json`, `Project` is
  `.claude/settings.json`, `Local` is `.claude/settings.local.json`, and `Managed` is what your
  organization deploys. `Any file` means all four".
- `sandbox` (settings-reference): "Type: object with `enabled`, `failIfUnavailable`,
  `autoAllowBashIfSandboxed`, `excludedCommands`, `allowUnsandboxedCommands`,
  `enableWeakerNestedSandbox`, `enableWeakerNetworkIsolation`, `allowAppleEvents`, `bwrapPath`,
  `socatPath`, `ignoreViolations`, and `ripgrep`, plus the `filesystem`, `network`, and
  `credentials` objects".
- `sandbox.enabled` (settings-reference): "When you pick a mode in the `/sandbox` panel, Claude
  Code writes this key to `.claude/settings.local.json` for the current project; set it in
  `~/.claude/settings.json` to sandbox every project."
- `sandbox.bwrapPath` (settings-reference): "Scope: Managed. Claude Code reads it only from managed
  settings so that a user, project, or local file can't point the sandbox at a different binary."
- `sandbox.network.strictAllowlist` (settings-reference): "Scope: User or managed. A repository
  can't turn it on or off."
- `sandbox.credentials.files` / `envVars` (settings-reference): "Claude Code drops `mask` entries
  from project `.claude/settings.json` and local `.claude/settings.local.json`."
- Wildcards (settings-reference, sandbox path prefixes): "On Linux and WSL2, the sandbox mounts
  concrete paths, so Claude Code skips an entry that contains `*`, `?`, or `[` once the trailing
  `/**` is removed, and that entry has no effect."
- Merging (settings-reference, `sandbox`): "Claude Code takes a Boolean key's value from the
  highest-precedence settings scope that sets it, so a managed `enabled` or `failIfUnavailable`
  overrides anything a developer sets. It merges array keys across every settings scope the
  session loads".
- Reload (settings.md, "When edits take effect"): "Claude Code watches your settings files and
  reloads them when they change, so it applies most edits to the running session without a
  restart". Sandboxing.md line 195: "When you edit these filesystem lists during a session, Claude
  Code applies the change to the running session".
- Invalid values (settings.md): "**Settings Error**: a user, project, or local file has invalid
  JSON or a value the schema rejects. At the start of an interactive session Claude Code shows a
  dialog". And: "The schema can lag behind the newest CLI releases".
- Protected paths (sandboxing.md): "Inside the directories that sandboxed commands can write to,
  the sandbox still denies writes to the files Claude Code loads configuration and code from" —
  covering "the `.claude` settings files" in the working directory and above, and "In `~/.claude`,
  or the directory `CLAUDE_CONFIG_DIR` points to: most of its contents".

## Allowlist (data constant `SANDBOX_KEYS`, source and fetch date in the module)

Each entry: dotted path → (value kind, scopes where the docs say the key is honored). `ANY` =
user, project, local; `USER` = user only (the docs' "User or managed"; managed is never a target).

| Key | Kind | Scopes |
|---|---|---|
| `sandbox.enabled` | bool | ANY |
| `sandbox.failIfUnavailable` | bool | ANY |
| `sandbox.autoAllowBashIfSandboxed` | bool | ANY |
| `sandbox.allowUnsandboxedCommands` | bool | ANY |
| `sandbox.excludedCommands` | str_list | ANY |
| `sandbox.enableWeakerNestedSandbox` | bool | ANY |
| `sandbox.enableWeakerNetworkIsolation` | bool | ANY |
| `sandbox.allowAppleEvents` | bool | USER |
| `sandbox.ignoreViolations` | str_to_str_list | ANY |
| `sandbox.filesystem.allowWrite` | path_list | ANY |
| `sandbox.filesystem.denyWrite` | path_list | ANY |
| `sandbox.filesystem.denyRead` | str_list | ANY |
| `sandbox.filesystem.allowRead` | str_list | ANY |
| `sandbox.filesystem.disabled` | bool | USER |
| `sandbox.network.allowUnixSockets` | str_list | ANY |
| `sandbox.network.allowAllUnixSockets` | bool | ANY |
| `sandbox.network.allowLocalBinding` | bool | ANY |
| `sandbox.network.allowMachLookup` | str_list | ANY |
| `sandbox.network.allowedDomains` | str_list | ANY |
| `sandbox.network.deniedDomains` | str_list | ANY |
| `sandbox.network.strictAllowlist` | bool | USER |
| `sandbox.network.httpProxyPort` | port | ANY |
| `sandbox.network.socksProxyPort` | port | ANY |
| `sandbox.credentials.files` | credential_files | ANY (`mask` entries USER) |
| `sandbox.credentials.envVars` | credential_env | ANY (`mask` entries USER) |

Documented but excluded (`EXCLUDED_KEYS`, refused with reason `excluded_key` and the constant
reason text): `sandbox.bwrapPath`, `sandbox.socatPath`,
`sandbox.filesystem.allowManagedReadPathsOnly`, `sandbox.network.allowManagedDomainsOnly` (managed
only: no effect in a target this tool may write); `sandbox.ripgrep` (points the sandbox at an
executable); `sandbox.network.tlsTerminate` (CA certificate and key paths);
`sandbox.credentials.allowPlaintextInject`, `sandbox.credentials.awsPairs`,
`sandbox.credentials.sigv4` (credential-proxy tuning with cross-field rules; not in this version).
Parent objects (`sandbox`, `sandbox.filesystem`, `sandbox.network`, `sandbox.credentials`) are
refused with `not_a_leaf`. Any other `sandbox.*` path is `unknown_key`; any path outside
`sandbox.` is `not_allowlisted`.

Value kinds:

- `bool`: `true`/`false` only.
- `str_list` / `path_list`: a JSON array of non-empty strings (may be empty). `path_list` adds a
  plan warning `wildcard_ignored_on_linux` for an entry containing `*`, `?` or `[` after a trailing
  `/**` is removed (the docs' rule; macOS honours it, so it is a warning, not a refusal).
- `port`: integer (not boolean) 1–65535.
- `str_to_str_list`: object whose keys are non-empty strings and values are `str_list`.
- `credential_files`: array of objects with required `path` (non-empty string) and `mode`
  (`"deny"` or `"mask"`); a `mask` entry may add `extract` (string), `onExtractNoMatch`
  (`"warn"|"deny"|"error"`), `decode` (`"jwt"`), `maskClaims` (non-empty `str_list`, requires
  `decode`), `maskDuplicates` (bool), `injectHosts` (`str_list`). Any other field, or a mask field
  on a `deny` entry, is `invalid_value`.
- `credential_env`: as above with `name` instead of `path`, without `maskDuplicates`; `extract`
  and `decode` together, or `decode` with an `onExtractNoMatch` other than `"warn"`, is
  `invalid_value` (both rules quoted from the "Mask fields for environment variables" table).
- A `mask` entry, or a USER-scope key, in a project or local target is `scope_not_honored`.
  `remove` checks the allowlist but not the scope: removing a key the docs say is ignored in that
  file is harmless cleanup.

## Ops file (written by the model to `$TMPDIR`)

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

- Top level exactly `version` (1) and `targets` (1–20). Target exactly `file`, `ops` (1–50) and
  optional `expect_file` (`"sha256:<64 hex>"` or `"absent"`). Op exactly `op`, `path`, `expect`,
  plus `value` for `set` only. `expect` has exactly one of `{"value": <json>}`,
  `{"sha256": "<64 hex>"}` (the canonical-JSON SHA-256 that `ledger.fingerprint` computes) or
  `{"absent": true}`. `remove` with `{"absent": true}` is invalid. Duplicate paths within a target
  are `duplicate_path`. The same file twice is `duplicate_target`.
- Parsed with `report_state.load_json` (rejects duplicate keys and non-finite numbers); at most
  1 MiB. Structural errors refuse the whole file (`invalid_ops_file`, exit 1, nothing read).
- `file` is absolute or starts with `~/` (expanded against the collector's `HOME`).

## Targets

- User: `<claude config dir>/settings.json` (`$CLAUDE_CONFIG_DIR`, else `~/.claude`; `--claude-dir`
  overrides, as for the collector).
- Project: any `<dir>/.claude/settings.json`; local: any `<dir>/.claude/settings.local.json`
  (including `<claude config dir>/settings.local.json`).
- Everything else is `target_not_settings`. Anything under `collect.managed_directory()`, named
  `managed-settings.json`, or inside a `managed-settings.d` directory is `managed_refused`, checked
  before any read. Managed changes go to the administrator, as SKILL.md Step 1 already says.
- The target, and its immediate `.claude` directory, must not be symlinks (`symlink`); there is no
  `--allow-symlinks` override. The target is opened with `open_no_symlink`; larger than 8 MiB is
  `too_large`; not UTF-8, not JSON, duplicate keys or a non-object top level is `invalid_json`.
- A missing target is allowed only when its parent directory exists (else `no_parent_directory`)
  and every op is a `set` with `{"absent": true}` (planning against `{}` enforces this: a `remove`
  is `absent`, any other precondition is `precondition_mismatch`); it is then created exclusively (`O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600) with
  no backup (`backup: null`, `created: true`). Revert = delete the file.
- Project targets carry the warning `shared_project_file` (SKILL.md Step 5 item 3 still decides
  whether to edit a git-tracked file).

## Operation semantics (pure function on a deep copy)

- `set`: check the precondition against the current value (missing = absent); create missing
  intermediate objects (appended at the end of their parent); an intermediate that exists but is
  not an object is `type_conflict`. An existing key keeps its position; a new key is appended. When
  the current value already equals the new value (canonical JSON) the op is `unchanged`.
- `remove`: the key must exist (`absent` otherwise, even when the precondition would pass) and
  pass its precondition; delete it, then delete each ancestor object below the top level that this
  removal left empty. So a `set` into an absent subtree followed by the inverse `remove` restores
  the original document.
- A failed precondition is `precondition_mismatch`; the row then shows the redacted current value
  and its `current_sha256` so the model can re-plan. Ops apply in file order; paths are distinct
  leaves, so each precondition sees the original value.

## Plan output (stdout, JSON, indent 1 like the pruner)

```json
{"applied": false, "ok": true, "docs_fetched": "2026-09-29",
 "targets": [{"file": "~/code/app/.claude/settings.local.json", "kind": "local", "exists": true,
   "file_sha256": "sha256:3b1f…", "reformat": false, "status": "planned", "reason": "",
   "warnings": [], "backup": null, "created": false, "verified": null,
   "ops": [{"op": "set", "path": "sandbox.failIfUnavailable", "status": "planned",
            "reason": "", "before": false, "before_sha256": "…", "after": true}]}],
 "error": null}
```

- `before`/`after` pass through `collect.sanitize` (display only; hashes use raw values).
- Target `status`: `planned` (some op changes the file), `unchanged` (none does), `rejected`
  (target reason, or `op_rejected` when any op row is rejected), and after `--apply`: `applied`, `blocked` (reason:
  `expect_file_missing`, `changed_since_plan`, `symlink`, `backup_failed`, `write_failed`) or
  `verify_failed`.
- `reformat: true` when the unchanged document re-serialized with `json.dumps(indent=2,
  ensure_ascii=False) + "\n"` differs from the file's bytes: the write would also normalize
  whitespace, and the model must say so when showing the before/after.
- Exit 0 when every target is `planned`, `unchanged` or `applied`; 1 for any other status or an
  invalid ops file (the JSON is still printed, with top-level `error`); 2 for usage errors
  (argparse, e.g. `--apply` without `--backup-dir`).

## Apply (`--apply --backup-dir DIR`)

1. Plan every target exactly as the dry run does. If any target is not `planned`/`unchanged`, or
   any target lacks `expect_file`, write nothing (targets not otherwise failed become `blocked`
   with `not_applied_other_target_failed` or `expect_file_missing`), exit 1.
2. The backup directory is `abspath(expanduser(DIR))`; a symlink there is refused
   (`backup_dir_symlink`, nothing written); it is created with mode 0700 when missing (failure:
   `backup_dir_unusable`, nothing written).
3. Per `planned` target: `expect_file` must equal the planned `file_sha256`, else
   `changed_since_plan`. Re-open with `open_no_symlink`; `identity_of` must equal the plan's
   identity (`changed_since_plan`). `backup_from_fd` through that same fd (mkstemp, 0600, unique;
   failure → `backup_failed`, target untouched). `atomic_write(target, text, prefix='.apply_ops.',
   encoding='utf-8')` (failure → `write_failed`, backup kept). New files use exclusive creation
   instead (an existing file at that point → `changed_since_plan`).
4. Verify: re-open with `open_no_symlink`, parse, and compare `ledger.fingerprint` of the re-read
   document with the planned document. Equal → `applied`, `verified: true`; else `verify_failed`
   (no automatic restore; the output names the backup).
5. Targets are independent after step 1: a write failure in one does not undo another.

File-level verification is not runtime verification. The effective sandbox merges files by
precedence, and a managed value can override the one written; SKILL.md item 7's probe (a write
outside the project is blocked; needed caches are writable) stays mandatory.

## SKILL.md changes

Step 5 preamble, next to the pruner sentence (mirroring its wording): "For sandbox settings,
require a successful `apply_ops.py` dry run before its apply call; if either cannot execute, or the
helper refuses an op, follow the blocked-action guidance in Step 1 rather than manually editing
`sandbox` keys."

Item 7 becomes:

> 7. **Sandbox.** Check dependencies and platform prerequisites first (e.g. AppArmor on recent
>    Ubuntu). Change `sandbox.*` keys only with `apply_ops.py` (ops format, allowlist and reasons:
>    `references/apply-ops.md`): write the ops file to `$TMPDIR`, run
>    `python3 ${CLAUDE_SKILL_DIR}/scripts/apply_ops.py --ops <file>` (dry run), show each op's
>    before/after (and say so when `reformat` is true), copy each target's `file_sha256` into its
>    `expect_file`, then rerun with `--apply --backup-dir ~/.claude/backups/setup-audit-<timestamp>/`.
>    On `precondition_mismatch`, show the reported current value; re-plan only if the approved
>    change still makes sense. Never replace a refused or failed op with Write/Edit. Enable it
>    last (a separate ops file after the other sandbox keys) and probe it afterwards: a write
>    outside the project should be blocked, and package caches the user needs should be writable
>    (`sandbox.filesystem.allowWrite`). Once the sandbox is on it protects settings files, so a
>    later `--apply` from a sandboxed Bash call fails with `backup_failed` or `write_failed`:
>    report it blocked; running outside the sandbox needs the user's approval at the permission
>    prompt.

Item 8 (record) gains: "for `apply_ops.py`, the backup paths and `verified` come from its output".
Not added to `allowed-tools`: the helper writes configuration, so every call should reach the
user's permission prompt.

## Documentation

- New `references/apply-ops.md`: purpose, ops file format, target rules, the allowlist table
  (generated from nothing — a doc-sync test compares it with `SANDBOX_KEYS` and `EXCLUDED_KEYS`),
  "fetched 2026-09-29" with the three source URLs, statuses and reasons, exit codes, protected-path
  note, how to revert (copy the backup back; delete a `created` file).
- `references/checklist.md` SEC-sandbox: one line "Fix via `apply_ops.py` (Step 5 item 7)".
- `CHANGELOG.md` `[Unreleased]` → Added. `docs/roadmap.md`: mark the sandbox slice done, keep
  "extend the allowlist key by key" and "a model-based approved-apply eval for sandbox ops"
  (paid; needs separate approval) as follow-ups.
- `README.md` "What it reads, writes and sends": no change needed (it already says config is
  edited only for approved items, after backing up); add nothing.

## Rulings

- Ruling: operations address leaf keys by dotted path, never parent objects or array indices — why:
  every allowlisted key is a leaf with a documented type, names contain no dots, and leaf-only ops
  make the diff and the precondition exact — cost if wrong: replacing a whole `sandbox` block takes
  several ops (cheap to add a parent op later).
- Ruling: only `set` and `remove`; arrays are replaced whole under a precondition — why: the
  user's scope; the precondition guards a concurrent change and the plan shows the full before and
  after — cost if wrong: the model must restate existing entries to add one; an `append` op can be
  added without changing the file format version.
- Ruling: a precondition is mandatory on every op — why: it forces the model to state what it
  believes is there, which is what the user approved — cost if wrong: one extra dry run when the
  snapshot's redacted value differs from the raw one (the plan then prints `current_sha256`).
- Ruling: `--apply` requires `expect_file` on every target, copied from the dry run — why: plan
  and apply are separate processes, so the in-process identity check alone cannot prove the user
  saw this content; the hash makes the dry run a hard prerequisite and catches unrelated edits
  (e.g. Claude Code writing a "don't ask again" rule into `settings.local.json`) — cost if wrong:
  a harmless concurrent edit forces a second dry run.
- Ruling: validation is all-or-nothing across targets; writes are per target — why: a partially
  approved set of ops should never half-apply because one target was rejected up front; a write
  failure after others succeeded cannot be undone safely without racing — cost if wrong: after a
  mid-run write failure the user sees mixed `applied`/`blocked` rows and must decide.
- Ruling: unknown `sandbox.*` keys are refused (no override flag) — why: the docs list the object's
  keys and the schema check produces a Settings Error dialog; an unknown key is most likely a
  misnamed one, which is exactly the failure this tool exists to prevent — cost if wrong: a key
  documented after 2026-09-29 needs a code change (one table row plus a test) before the tool can
  write it.
- Ruling: some documented keys are excluded (managed-only keys, `ripgrep`, `tlsTerminate`,
  `allowPlaintextInject`, `awsPairs`, `sigv4`) — why: managed-only keys have no effect in a
  writable target; the others point at executables or key material or need cross-field
  validation — cost if wrong: those rare changes stay blocked rather than automated.
- Ruling: keys the docs honor only in user or managed settings are refused in project and local
  targets (`scope_not_honored`), and so are `mask` credential entries — why: the docs say they are
  ignored there, so the write would report success for a change that does nothing — cost if wrong:
  if a later release widens a scope, one table cell changes.
- Ruling: Linux-ignored wildcards in `allowWrite`/`denyWrite` are a warning, not a refusal — why:
  the docs say macOS honours them — cost if wrong: a Linux user writes an entry with no effect,
  but the plan warned and the probe would show it.
- Ruling: output is always `json.dumps(indent=2, ensure_ascii=False) + "\n"` with key order kept,
  and the plan flags `reformat` — why: the stdlib has no format-preserving JSON writer, the pruner
  and ledger already normalize this way, and flagging makes the side effect visible before
  approval — cost if wrong: a hand-formatted settings file loses its whitespace once.
- Ruling: `remove` deletes ancestors it leaves empty, and removing an absent key is an error —
  why: set-then-remove round-trips to the original document, and a remove that finds nothing
  means the model's picture of the file is wrong — cost if wrong: a user who wanted an empty
  `"sandbox": {}` kept loses it, only when the op itself emptied it.
- Ruling: a missing target may be created (exclusively, 0600, no backup) when all ops are
  `set`+`absent` — why: `/sandbox` itself writes `sandbox.enabled` to `settings.local.json`, which
  often does not exist yet, and SKILL.md prefers that file for personal changes — cost if wrong:
  none beyond an empty-file revert; exclusive creation cannot clobber a file created meanwhile.
- Ruling: symlinked targets are refused with no `--allow-symlinks` override (unlike the pruner) —
  why: user scope; a dotfile-managed symlink target is outside the path the user approved, and the
  sandbox docs themselves treat symlinks at settings paths as suspicious — cost if wrong: users
  with symlinked settings get a `blocked` row and must edit by hand with explicit authorization.
- Ruling: no automatic restore on `verify_failed` — why: the mismatch most likely means another
  writer raced the final rename; restoring would clobber that writer — cost if wrong: the user
  copies the named backup back by hand.
- Ruling: no derived sandbox summary in the snapshot — why: the snapshot already carries each
  file's `sandbox` object (sanitized) for analysis, and the dry run is the authoritative, raw view
  of the current value with hashes for preconditions; a second summary would be a third copy to
  keep in sync — cost if wrong: the model reads a nested object instead of a flat list; a summary
  can be added later as an additive v1 field.
- Ruling: reuse `ledger.fingerprint` for value hashes and `safe_write` for all file handling —
  why: one hash definition across helpers, and the symlink/identity/backup behaviour is already
  tested — cost if wrong: `apply_ops` imports `ledger` (and `collect` for paths and sanitizing),
  a slightly heavier import.
- Ruling: `apply_ops.py` is not added to SKILL.md `allowed-tools` — why: it writes configuration;
  each call should reach the permission prompt — cost if wrong: one prompt per call.

## Testing (fake homes only; `tests/test_apply_ops.py`)

- Allowlist and values: every kind accepts a valid value and rejects each invalid shape; bool vs
  int; port bounds and `true`; unknown, excluded, parent and non-sandbox paths; USER-scope key and
  `mask` entry in a local target; wildcard warning.
- Ops file: wrong version, extra field, duplicate JSON key, `set` without `value`, `remove` with
  `value` or with `absent`, duplicate path, duplicate target, relative path, oversize.
- Planning: set new/existing/nested/unchanged; key order preserved; remove prunes emptied
  ancestors; round trip; precondition by value, by sha256, by absent; mismatch shows
  `current_sha256`; `type_conflict`; `absent`; symlinked target and symlinked `.claude`;
  managed and non-settings targets refused before reading; invalid JSON and duplicate keys;
  missing target creatable only with `set`+`absent`; `reformat` detection. A dry run leaves the
  directory listing and bytes unchanged.
- Apply: success writes, backs up (0600, original bytes) and verifies; `expect_file` missing or
  stale → nothing written; identity change between plan and apply (mocked) →
  `changed_since_plan`; target swapped for a symlink → blocked; backup failure → target
  untouched; symlinked backup dir refused; two targets with the same basename and two runs in the
  same second get distinct backups, and pre-existing files in the backup dir are untouched;
  exclusive creation loses to a file created after planning; verify mismatch (mocked write) →
  `verify_failed` with backup named; one rejected target blocks all writes.
- CLI (subprocess, `HOME` and `CLAUDE_CONFIG_DIR` pointing into the fake home): dry run → copy
  `file_sha256` → apply → re-run apply reports `changed_since_plan`, and a fresh dry run reports
  `unchanged`; exit codes 0/1/2; a secret-looking string in a `credentials.envVars` `extract`
  pattern is shown sanitized.
- Docs: `apply-ops.md` lists exactly `SANDBOX_KEYS` and `EXCLUDED_KEYS` and "fetched 2026-09-29";
  SKILL.md item 7 names `apply_ops.py`, `--apply --backup-dir` and forbids Write/Edit
  substitution.

Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`,
`git diff --check`, coverage ≥ 88.

## Out of scope

- Keys outside `sandbox.*`; migrating the pruner, ledger or hook flows onto this engine.
- Managed settings, `~/.claude.json`, `--settings` files, Windows.
- Runtime probing of the sandbox (stays a SKILL.md step).
- A paid model eval of sandbox apply (roadmap follow-up).
- Snapshot schema changes (none needed).
