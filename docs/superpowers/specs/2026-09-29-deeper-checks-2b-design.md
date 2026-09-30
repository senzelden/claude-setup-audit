# Deeper checks 2B: MCP exposure metadata and tool-error clustering — design

Date: 2026-09-29. Status: draft for review.
Roadmap item: "Deeper checks" in `docs/roadmap.md` (the "MCP exposure metadata and recurring
tool-error clustering" half; the hook/permission half is plan 2A, which lands first).

## Goal

The audit judges MCP servers from their transport and host alone, and tool errors from a top-10
list of coarse session-metadata labels. Two additions, both deterministic and read-only:

1. **MCP exposure metadata.** For each inventoried server: what a user could learn about its
   exposure from local configuration alone, without connecting, authenticating or running
   anything. For example, whether it is a local process or remote, reached over cleartext or
   loopback, carries literal header or env values, sits in a tracked `.mcp.json`, is approved
   for the project or rejected, toggled off, named by permission rules, or named by
   allow or deny policy.
2. **Tool-error clustering.** Error counts and rates per built-in tool and per MCP server
   (with the failing tools per server), split into heuristic categories, from transcript
   `tool_use` and `tool_result` pairs.

Success criteria:
- Fixture servers produce every new field with the documented values.
- No output contains a secret value, URL path, query or userinfo, argument value, header
  value, env value, `headersHelper` command or error text.
- Fixture transcripts produce the exact per-tool and per-server counts, rates and categories.
- Copied records are deduplicated.
- Unmatched and unflagged results are counted, not classified.
- The snapshot validates against the extended v1 schema.

## Evidence

### Documentation (raw pages, fetched 2026-09-29 with `curl -sL https://code.claude.com/docs/en/<page>.md`)

`mcp.md`:
- "A JSON entry that has a `url` but no `type` is a configuration error, because Claude Code reads
  an entry with no `type` as a stdio server. Claude Code skips that server and reports ..."
- "Claude Code skips a `"type": "sdk"` entry in `.mcp.json`, `~/.claude.json`, or settings"
- "the `type` field accepts `streamable-http` as an alias for `http`"
- "The SSE (Server-Sent Events) transport is deprecated. Use HTTP servers instead, where available."
- WebSocket: "Use HTTP instead ... since HTTP supports OAuth and the `claude mcp add --transport`
  flag, while WebSocket supports neither."
- Reserved names: "Claude Code reserves the names of its built-in servers, including `workspace`,
  `claude-in-chrome`, `computer-use`, `Claude Preview`, and `Claude Browser`. If your configuration
  defines a server with a reserved name, Claude Code skips it at load time".
- Same name in several scopes: "if you define the same server name in more than one scope with
  different endpoints, Claude Code warns about the conflict ... Claude Code stores OAuth sign-ins
  per endpoint". Precedence: "Claude Code matches duplicates across the three scopes by name. It
  matches plugins and connectors by endpoint".
- An empty `url` "shows as `not configured` ... A plugin can include a placeholder entry like this
  ... so Claude Code doesn't report it as an error".
- Project scope: "In `claude -p` runs, Agent SDK sessions, and cloud sessions, Claude Code can't
  show that prompt: it loads project-scoped servers without asking." To keep a server out:
  "Add it to `disabledMcpjsonServers`, which blocks it in every permission mode."
- Workspace trust: "A cloned repository can't approve its own servers: `enableAllProjectMcpServers`
  or `enabledMcpjsonServers` committed to the project's `.claude/settings.json` is ignored in an
  untrusted folder". "A `disabledMcpjsonServers` entry in any settings file still rejects the
  server."
- Toggles: "When you toggle a server, Claude Code records your choice per project in
  `~/.claude.json`, in one of two lists": `disabledMcpServers` (opt-out for user, plugin, managed,
  claude.ai and default-on built-in servers) and `enabledMcpServers` (opt-in for default-off
  built-ins).
- `headersHelper`: "Claude Code executes a `headersHelper` as an arbitrary shell command. For a
  server in a project `.mcp.json` or at local scope, it runs the helper only after you accept the
  trust dialog". Trust flag: "set `projects["<path>"].hasTrustDialogAccepted` to `true` in
  `~/.claude.json`".
- Credential variables: "In a remote server's `url` and `headers`, Claude Code reads credential
  variables from your environment as empty rather than expanding them" (for example
  `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `AWS_BEARER_TOKEN_BEDROCK`, `NPM_TOKEN`).
- Failure detail: "Claude Code redacts credential-like text from this detail and never includes
  the expanded server URL, which can carry secrets." (Supports keeping URL paths and queries out.)
- OAuth scopes: "Set `oauth.scopes` to pin the scopes ... This is the supported way to restrict an
  MCP server to a security-team-approved subset". The client secret "is stored securely in your
  system keychain (macOS) or a credentials file, not in your config".
- Tool names: plugin tools are "`mcp__plugin_<plugin-name>_<server-name>__<tool-name>`, where any
  character outside `A-Z`, `a-z`, `0-9`, `_`, and `-` is replaced with `_`". The server itself
  "registers under the scoped name `plugin:<plugin-name>:<server-name>`". Prompt commands:
  "Claude Code replaces any character in the server name outside `A-Z`, `a-z`, `0-9`, `_`, and `-`
  with `_`".

`managed-mcp.md`:
- "Without `allowManagedMcpServersOnly`, allowlists from every settings scope merge, including a
  user's own `~/.claude/settings.json`, so a user can broaden what your allowlist permits.
  Denylists merge from every scope regardless."
- "A `serverName` entry, in either list, is not a security control."
- Entries are single-key objects: `serverUrl`, `serverCommand` or `serverName`. Unset
  `allowedMcpServers` means that all servers are allowed. An empty array means that no servers
  are allowed apart from the organization's own.

`settings-reference.md`:
- `disabledMcpjsonServers`: "Claude Code writes this key to `.claude/settings.local.json` when you
  reject a server in the approval dialog ... Rejection takes precedence over
  `enabledMcpjsonServers` and `enableAllProjectMcpServers`."
- `enableAllProjectMcpServers` / `enabledMcpjsonServers`: scope "Any file"; in an untrusted folder
  they are honored from user, managed and `--settings`, ignored in the shared project file.
- `disableClaudeAiConnectors`: "A `true` in any settings file applies".

`permissions.md`:
- "`mcp__puppeteer` matches any tool provided by the `puppeteer` server"; `mcp__puppeteer__*`
  matches all its tools.
- "When Claude Code loads a settings file, it skips any `mcp__` rule that has parentheses."
- "An unanchored allow glob such as `"*"`, `"B*"`, or `"mcp__*"` is skipped with a warning".
- "Tools from connectors Claude Code fetches itself appear as `mcp__claude_ai_<server>__<tool>`."

### Local data (read-only inspection, 2026-09-29; structure and counts only)

- Transcripts (2,959 main and subagent files): `tool_use` items in `assistant` records carry `id`
  and `name`. `tool_result` items in `user` records carry `tool_use_id` and `content` (a string, or
  a list of text blocks), and on most results `is_error`. Of 2,722 `is_error: true` results, 2,721
  paired with a `tool_use` id in the same file. About 30,800 results have no `is_error` key and
  about 52,500 have `false`.
- Error texts start in recognizable shapes (`Exit code N`, `<tool_use_error>…`, `Permission …`,
  `File does not exist`, sandbox setup failures inside `Exit code` results, and MCP server messages).
  These shapes are observed, not documented.
- `usage-data/session-meta/*.json` `tool_error_categories` holds only coarse labels (seen: `Other`,
  `Command Failed`). This is why today's `COST-tool-errors` cannot tell a failing MCP server
  from a failing test command.
- `~/.claude.json` `projects[<path>]` entries carry `enabledMcpjsonServers`,
  `disabledMcpjsonServers` and `hasTrustDialogAccepted` (all 22 local entries). The documented
  location of the first two is settings files; the `~/.claude.json` copy is undocumented.

## Rulings

- Ruling: Locality comes from the URL alone (`loopback`, `private_address`, `public_address`,
  `named_host`, `dynamic`, `invalid`); no DNS resolution. — Collection must not contact
  anything. — Cost if wrong: an internal hostname reads as `named_host`, so the audit cannot
  tell an intranet host from a public one without asking.
- Ruling: Allow and deny policy, approvals, toggles and scope precedence are recorded as per-source
  observations, never as an effective state. `serverName` entries are matched by name.
  `serverUrl` and `serverCommand` entries are counted but not evaluated. — `coverage.md` already
  forbids computing effective merges, and URL wildcard or command matching with `${VAR}`
  expansion from a "pinned environment" (managed-mcp.md) cannot be reproduced offline. — Cost if
  wrong: the audit may call a server "unrestricted" when a URL entry actually blocks it. The
  checklist says to check `mcp_policy` before any such claim.
- Ruling: The `~/.claude.json` `projects[<path>]` lists (`enabledMcpjsonServers`,
  `disabledMcpjsonServers`, `disabledMcpServers`, `enabledMcpServers`) and `hasTrustDialogAccepted`
  are collected with that file as their source. The first two are labeled by source only, not
  claimed as effective. — They are observed locally, the toggles and trust flag are documented
  there, and the approvals are a legacy location. — Cost if wrong: a stale legacy approval is
  cited as an observation. It is never presented as effective, so the harm is small.
- Ruling: `tool_prefix` applies the documented plugin normalization to every server. Characters
  outside `[A-Za-z0-9_-]` become `_`, and plugin servers use `plugin_<plugin>_<server>`.
  — The docs state it for plugin tools and prompt commands, and permissions.md shows claude.ai
  connectors as `mcp__claude_ai_<server>`. — Cost if wrong: a regular server with unusual
  characters fails to join its permission-rule and error rows. The row still exists, so this is a
  missed join, not a false claim.
- Ruling: The plugin name for `tool_prefix` is the manifest `name`, falling back to the registry
  key before `@`. — The docs define `<plugin-name>` as the plugin's name. The manifest `name` is
  that name, and registry keys are `<name>@<marketplace>`. — Cost if wrong: plugin server rows do
  not join. This is the same missed-join risk as the previous ruling.
- Ruling: Only `is_error: true` counts as an error. Results without the key are counted in
  `results_without_is_error` and are not classified. — Transcript format is undocumented, and
  guessing errors from text would inflate counts. — Cost if wrong: errors from older records
  without the flag are undercounted. The counter makes the gap visible.
- Ruling: Error categories are ordered regexes over the first 300 characters of the error text.
  Only the category name is kept; the text is never stored. — No documented error taxonomy
  exists, and the shapes were observed locally. — Cost if wrong: misclassification skews
  categories, but the total error and call counts stay exact. The checklist calls the categories
  heuristic.
- Ruling: `failure_rate` = (errors − denials) / calls, where denials are `permission_denied` and
  `user_rejected`. It is `null` under 5 calls. — A denied call is the permission system working,
  not the tool failing, and tiny samples produce misleading rates. — Cost if wrong: a server
  whose tools are always denied looks healthy. `denied` is reported alongside.
- Ruling: Main and subagent transcripts are combined, with the same deduplication as
  `mcp_calls_by_server` (project directory, `sessionId` or file fallback, tool id). — This keeps
  one consistent counting rule with the existing MCP call counts. — Cost if wrong: a
  subagent-only failure pattern is not separated. The harness section already splits spend.
- Ruling: Caps are 15 built-in tools (only those with errors), 15 MCP servers (with calls, sorted
  by errors then calls), 3 failing tools per server and 20 policy observations per server. Omitted
  counts are reported. — This keeps the snapshot selective (AGENTS.md: "analysis selective"). —
  Cost if wrong: a rare failing tool beyond the cap is only visible as a count.
- Ruling: `oauth.scopes` tokens are stored (sorted, at most 20, each at most 64 characters) along
  with the `oauth` key names. `clientId` values, secrets and metadata URLs are not stored. —
  Scope tokens are RFC 6749 identifiers, not credentials. They are the documented control for
  narrowing a server's access. — Cost if wrong: scope names reach the snapshot. They are not
  secrets and still pass `sanitize()`.
- Ruling: `plaintext_transport` (an `http`/`ws` scheme to a non-loopback host) is a
  recommendation-level signal. — The docs do not call cleartext unsafe. This is general
  transport-security practice. — Cost if wrong: the only harm is noise, and the checklist
  presents it as a recommendation.
- Ruling: Permission-rule validity (rules with parentheses, unanchored `mcp__*` allow globs,
  wildcard placement) stays in plan 2A. 2B only counts `mcp__` rules per server segment, with a
  glob segment counted as `*`. — This avoids two collectors judging the same rule. — Cost if
  wrong: a skipped rule is counted as a server rule. The checklist points at 2A's field.
- Ruling: Hook matchers written as `mcp__<server>__…` against plugin servers (which never fire,
  per mcp.md) belong to 2A's matcher validation. — 2A owns hook matcher checks. — Cost if wrong:
  none, as long as 2A covers it. If it does not, the check lands nowhere; recorded as a follow-up.
- Ruling: Name collisions are computed only among `local`, `project` and `user` servers applying
  to the same project, by name. Endpoints are compared by `transport` plus `endpoint_origin` or
  `executable`. — The docs match these three scopes by name and plugins or connectors by endpoint.
  The collector keeps no URL path. — Cost if wrong: two servers on one host with different paths
  read as `endpoint_origins_differ: false`.
- Ruling: The project `.mcp.json` git status uses the existing read-only `git_status`
  (`rev-parse`, `ls-files --error-unmatch`, `check-ignore`) once per file. — A literal header in a
  tracked `.mcp.json` is a committed credential, and git state is the evidence. — Cost if wrong:
  up to three extra git calls per project root that has `.mcp.json`.
- Ruling: The session-meta `tool_error_categories` stays unchanged. The new clustering is a
  separate transcript field. — The snapshot is additive within v1, and existing readers keep
  their meaning. — Cost if wrong: two error sources to explain. The checklist names which to cite.
- Ruling: claude.ai connectors and built-in servers are not configured locally, so they are not
  inventoried. They appear only as transcript `tool_prefix` rows (for example `claude_ai_*`).
  `disableClaudeAiConnectors` is captured in `mcp_policy`. — Nothing local describes them. —
  Cost if wrong: none. This is a stated coverage limit.

## Not supported by docs or local data (out of scope)

- Whether a server actually connected, was approved in the running session, or is authenticated.
  OAuth tokens and client secrets live in the keychain or a credentials file, which is never read.
- What tools a server exposes, whether they write to external systems, and per-tool
  `_meta["anthropic/requiresUserInteraction"]`. All of these need `tools/list`, which means
  connecting. "Write access" stays the model's judgement from names, OAuth scopes and permission
  rules.
- Effective allow and deny outcomes for `serverUrl` and `serverCommand` entries (see the
  rulings).
- A documented tool-error taxonomy. The categories are heuristic.

## Design

### A. Static exposure fields (`extensions.mcp_summary`)

Added to every collected server item. Existing fields and meanings are unchanged; `transport`
still reports the raw `type` or `stdio`.

| Field | Values | Rule |
|---|---|---|
| `transport_class` | `local_process`, `remote`, `skipped`, `unknown` | `stdio`/no type → `local_process`; `http`, `streamable-http`, `sse`, `ws` → `remote`; `sdk`, or a `url` with no `type` → `skipped` |
| `config_notes` | list of `url_without_type`, `sdk_type_skipped`, `sse_deprecated`, `reserved_name`, `empty_url_placeholder` | per the mcp.md quotes; the placeholder note is not a finding |
| `endpoint_locality` | `loopback`, `private_address`, `public_address`, `named_host`, `dynamic`, `invalid` | only when `url` is a non-empty string; `${` in the URL → `dynamic`; `localhost`/`*.localhost`/loopback IP → `loopback`; `ipaddress` private or link-local → `private_address` |
| `plaintext_transport` | bool | scheme `http` or `ws` and locality not `loopback` |
| `url_has_userinfo`, `url_has_query` | bool | from `urlsplit`; values never stored |
| `url_variable_references` | names | `${NAME}` / `${NAME:-…}` in the URL |
| `env_literal_keys`, `headers_literal_keys` | key names | keys whose non-empty string value has no `${…}` reference |
| `oauth_keys`, `oauth_scopes` | key names; scope tokens or `null` | only when `oauth` is an object |
| `plugin`, `tool_prefix` | strings | `tool_prefix` is always set; `plugin` only for plugin-scope servers |
| `file_git_status` | `tracked`, `untracked`, `ignored`, `not-a-git-repo`, `unknown` | project-scope servers only |

`extensions.mcp_name_collisions`: `[{name, project, scopes, endpoint_origins_differ}]`, capped at
100.

### B. Approvals, toggles, policy and permission observations

`collect.summarize_settings` gains two selected-field summaries (settings, project and managed
summaries all get them):

- `mcp_policy` (or `null` when no MCP key is present):
  - `enabledMcpjsonServers` and `disabledMcpjsonServers`: sorted unique names (at most 100), or
    `"invalid"`.
  - `enableAllProjectMcpServers`, `allowManagedMcpServersOnly` and `disableClaudeAiConnectors`:
    bool or `"invalid"`.
  - `allowedMcpServers` and `deniedMcpServers`: `{entries, by_key: {serverName|serverUrl|
    serverCommand|invalid: n}, server_names: [...≤50]}` or `"invalid"`. URL and command values are
    never copied.
- `mcp_permission_rules`: `{allow|ask|deny: {<server segment or "*">: count}}` for `mcp__` rules,
  with at most 50 segments per list.

`extensions.collect_extensions` adds `mcp_project_state`:
`[{project, source, enabledMcpjsonServers?, disabledMcpjsonServers?, disabledMcpServers?,
enabledMcpServers?, trust_accepted}]` for audited roots only. It holds names and a bool; other
`projects[...]` keys (costs, prompts, metrics) are never read into the snapshot.

`extensions.mcp_observations(servers, layers, project_state, display)` sets on each collected
server:
- `policy_observations`: a list of `{source, kind, value}`.
- `policy_observations_omitted`, when more than 20.
- For project-scope servers, `project_trust_accepted` (bool or `null`).

Layers are `(user|project|managed, project display path or None, settings summary)`. A project
layer applies only to servers of that project, or to servers without a project (user, managed,
user-installed plugin). The source then names that project's file. Kinds:

- Approvals, project-scope servers only: `approval_enabled`, `approval_rejected`,
  `approval_enable_all` (value bool).
- Policy name matches: `policy_allowed_by_name`, `policy_denied_by_name`.
- Toggles: `toggle_disabled`, `toggle_enabled`. These match the name or
  `plugin:<plugin>:<name>`.
- Permission rules (value = rule count): `permission_allow`, `permission_ask`,
  `permission_deny`, and `permission_{allow,ask,deny}_any_server` for `*` segments.

### C. Tool-error clustering (`transcripts.tool_errors`)

`collect_transcripts` pairs `tool_result` to `tool_use` by id within a file, over in-window
records of main and subagent files:

```
tool_errors: {
  error_results_paired, error_results_unmatched, results_without_is_error,
  by_tool:        [{tool, calls, errors, denied, failure_rate, categories}]          ≤15, errors > 0
  by_mcp_server:  [{server, calls, errors, denied, failure_rate, categories,
                    top_error_tools: [[tool, n], ≤3]}]                               ≤15, calls > 0
  omitted: {tools, mcp_servers}, min_calls_for_rate: 5,
  categories_basis, scope_note
}
```

`server` equals the `mcp_calls_by_server` key and the exposure `tool_prefix`, so exposure and
reliability join on it. Categories are applied in order, first match wins, on the text after a
leading `<tool_use_error>` tag:

1. `user_rejected`
2. `permission_denied`
3. `sandbox`
4. `timeout`
5. `nonzero_exit`
6. `validation`
7. `file_state`
8. `not_found`
9. `too_large`
10. `auth`
11. `connection`
12. `other`

Exact patterns are in the plan.

### D. Checklist

- **SEC-mcp-exposure** (new):
  - Literal values in a tracked project `.mcp.json`.
  - Userinfo or query in a remote URL.
  - Cleartext to a non-loopback host.
  - Project servers auto-approved (`approval_enable_all`, or loaded without asking in
    `-p`/SDK/cloud).
  - A project `headersHelper`, which is a repo-supplied shell command.
  - Permission allow rules on a server with external write reach.
  - Allowlist posture (merge without `allowManagedMcpServersOnly`; `serverName` is not a
    control).
  - Unpinned OAuth scopes on sensitive services.
  - A `url` reference to a credential variable that reads as empty.

  It cross-references `SEC-mcp`, `SEC-secret-literal` and `COST-tool-error-clusters`.
- **HYG-mcp-config** (new): `config_notes` (skipped, reserved or deprecated servers) and
  `mcp_name_collisions` with differing origins (separate OAuth sign-ins). An
  `empty_url_placeholder` is not a finding.
- **COST-tool-error-clusters** (new):
  - Cite `by_tool` and `by_mcp_server`.
  - Separate denials from failures.
  - A server with `failure_rate` ≥ 0.2 over ≥ 20 calls and `auth`/`connection` categories →
    fix its configuration or authentication (`claude mcp get <name>` shows an `Issue:` line), or
    propose removal together with its exposure.
  - Bash `sandbox` clusters → `SEC-sandbox` prerequisites.
  - `nonzero_exit` clusters → run and test commands (`RDY-test-loop`, CLAUDE.md).
  - `file_state` → an LRN pattern (edit before read).
  - The 0.2/20 threshold is a recommendation, and the categories are heuristic.
- `COST-tool-errors` points to the new field. `SEC-mcp` points to `SEC-mcp-exposure`.

### E. Contract and docs

- Schema v1, additive:
  - `$defs.mcp_server`: the `source` fields plus typed optional new fields.
  - `extensions.mcp_project_state` and `extensions.mcp_name_collisions`.
  - `transcripts.tool_errors`, where `failure_rate` is `["number","null"]`. The `number` type
    comes from the parked follow-ups that land first; without it, leave `failure_rate` untyped.
- `snapshot-format.md` and `coverage.md`: the new fields, their bases (docs fetched 2026-09-29;
  observed local structures), no DNS, no effective evaluation, no stored text.
- `CHANGELOG.md` `[Unreleased]` and `docs/roadmap.md`. README unchanged.

## Testing

All tests use temporary fake homes (`FakeHome`) and stay out of `tests/test_collect.py`, where 2A
adds tests: new `tests/test_mcp_exposure.py` and `tests/test_tool_errors.py`, plus
`tests/test_snapshot_contract.py` cases. Every privacy test plants an `opaque`/`sk-…` sentinel in
each value slot (URL path, query, userinfo, args, env value, header value, `clientId`,
`headersHelper`, error text) and asserts that it is absent from the serialized output.

## Privacy note for the later metadata-only mode

The new fields are names, counts, booleans, enums and OAuth scope tokens. The metadata-only plan
should list `oauth_scopes`, `*_literal_keys` and `policy_observations[].source` as free-text-ish
fields to review.

## Follow-ups (not in 2B)

- Ledger tool-error source (`ledger.md` v1 limit) using `tool_errors`.
- Drift signal for MCP failure rate.
- If 2A does not cover `mcp__<server>__` hook matchers on plugin servers, add it there.
