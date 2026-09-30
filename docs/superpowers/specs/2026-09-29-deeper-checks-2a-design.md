# Deeper checks 2A: rule shapes, hook validation, cross-layer conflicts — design

Date: 2026-09-29. Status: scope decided by the user; design rulings below await written-spec review.
Roadmap item: "Deeper checks" in `docs/roadmap.md` (the first three of its five parts: permission
wildcard placement, hook matcher validation, duplicate hooks/layer conflicts). MCP exposure metadata
and tool-error clustering stay out of scope (2B).

## Goal

Today the collector flags broad allow rules (`permissions.risky`) and lists hook handlers, but it
does not notice configuration that does not do what it reads: a `*` that approves more than the
rule suggests, a deny rule Claude Code never applies, a hook that can never fire, a matcher that is
silently ignored, or the same hook or rule working against itself across layers.
`HYG-hook-duplicates` exists only as prose, and its "runs twice" claim is wrong for settings files
(see the docs findings).

This work adds three deterministic, redacted, capped signals to the snapshot and five checklist
entries for them. All three are **static observations of configuration text**. The effects cited
("never fires", "fails open", "runs once") come from the quoted documentation, not from observed
runs. Proposals built on them are recommendations.

Success means:

- every documented problem shape in the tables below is flagged in a fixture;
- every listed valid pattern (negative cases) is not flagged;
- no raw hook command appears in the new conflict section;
- rule text is redacted and capped the way `permissions.risky` already is;
- the snapshot validates in schema v1 without the concurrent `number` type;
- the checklist cites only what the raw docs support.

## Documentation baseline (raw pages, `curl -sL …/<page>.md`, fetched 2026-09-29)

### permissions.md, "Wildcard patterns", "Match by input parameter", "Manage permissions", "Settings precedence"

- "Put the `*` after the subcommand. […] Claude Code matches everything before the first `*` as
  written, so those words are what limit the rule: `Bash(git log *)` allows only `git log`
  commands, and `Bash(git *)` allows every git command. Claude Code warns at startup about an
  allow rule with a `*` before the subcommand, such as `Bash(git * main)`."
- Table row: `Bash(git * main)` matches "`git merge main`, `git push origin main`,
  `git -c core.fsmonitor=<script> diff main`". The docs add: "That includes `-c`, which makes git
  run a program you name."
- "In `Bash(* --version)`, the `*` stands in for the program, so any program matches."
- "`Bash(ls *)` requires a space after `ls`, so `lsof` doesn't match. `Bash(ls*)` has no space, so
  it matches `lsof` too."
- "The `:*` suffix is an equivalent way to write a trailing wildcard, so `Bash(ls:*)` matches the
  same commands as `Bash(ls *)`." and "The `:*` form is only recognized at the end of a pattern. In
  a pattern like `Bash(git:* push)`, the colon is treated as a literal character and won't match
  git commands."
- "A `*` at the end, with a space before it, also matches the bare command. […] That holds only
  when the trailing `*` is the rule's only wildcard".
- "`Bash(*)` is equivalent to `Bash` and matches all Bash commands."
- Input-parameter rules: "Deny and ask rules can match a top-level input parameter on any built-in
  tool with `Tool(param:value)`." Then: "You can't match a tool's primary content field this way:
  `command` for Bash and PowerShell, `file_path` for Read, Edit, and Write, `path` for Grep and
  Glob, `notebook_path` for NotebookEdit, and `url` for WebFetch. A rule like `Bash(command:rm *)`
  would be bypassable by a compound command, so Claude Code ignores it and emits a startup
  warning." Also "Whitespace around the colon is ignored".
- "When Claude Code loads a settings file, it skips any `mcp__` rule that has parentheses."
- Tool-name globs: "Deny and ask rules also accept glob patterns in the tool-name position. The
  pattern must match the full tool name". Also: "An unanchored allow glob such as `"*"`, `"B*"`, or
  `"mcp__*"` is skipped with a warning and doesn't auto-approve anything."
- Order: "Rules are evaluated in order: deny, then ask, then allow. The first match in that order
  determines the outcome, and rule specificity doesn't change the order." Also: "a matching ask
  rule prompts even when a more specific allow rule also matches the same call."
- Across scopes: "if user settings allow a permission and project settings deny it, the deny rule
  blocks it. The reverse is also true: a user-level deny blocks a project-level allow, because deny
  rules from any scope are evaluated before allow rules."
- Home-local file: "`~/.claude/settings.local.json` is still local scope […], so Claude Code reads
  it only in sessions you start in your home directory itself, not in every project."

### errors.md, "Has a wildcard before the rest of the command"

- "Claude Code found a `Bash` allow rule whose `*` comes before a later word that determines which
  command it is, such as `Bash(git * main)` or `Bash(git -C * status *)`".
- "Claude Code doesn't warn about deny and ask rules with the same shape: it refuses or prompts for
  the extra commands they match rather than approving them. It also doesn't warn about rules whose
  subcommand comes before the first `*`, such as `Bash(git commit *)`, or rules in which no word
  other than an option follows the `*`, such as `Bash(git *)`, or about `:*` prefix rules such as
  `Bash(git:*)`."
- "Before v2.1.246, Claude Code accepted these rules without a warning."

### settings.md

- "an `allow` rule there doesn't outrank an `ask` rule from a project or managed file" (the
  local-file case of the evaluation order).

### hooks.md, "Matcher patterns", "Hook handler fields", "Hook locations", event table

- Matcher evaluation: `"*"`, `""`, or omitted mean "Match all". A matcher made of "Only letters,
  digits, `_`, `-`, spaces, `,`, and `|`" is an "Exact string, or list of exact strings separated
  by `|` or `,`". A matcher that "Contains any other character" is a "JavaScript regular
  expression, unanchored", "tested with JavaScript's `RegExp.prototype.test`".
- "`FileChanged` and `StopFailure` use a narrower exact-match set of letters, digits, `_`, and `|`
  only. A hyphen, space, or comma in a matcher for those two events keeps it on the
  regular-expression path, and only `|` separates alternatives."
- FileChanged: the matcher's value "is split on `|` and each segment is registered as a literal
  filename"; "Regex patterns are not useful here".
- "If you add a `matcher` field to an event without matcher support, it is silently ignored."
- "a matcher like `mcp__memory` or `mcp__brave-search` contains only exact-match characters, so it
  is compared as an exact string and matches no tool."
- The per-event matcher table (what each event's matcher filters). The events with "no matcher
  support" are `CwdChanged`, `UserPromptSubmit`, `PostToolBatch`, `Stop`, `TeammateIdle`,
  `TaskCreated`, `TaskCompleted`, `WorktreeCreate`, `WorktreeRemove` and `MessageDisplay`. The
  lifecycle table lists 33 events, and each has its own `### <Event>` section.
- Handler fields:
  - Common: `type`, `if`, `timeout`, `statusMessage`, `once`.
  - command: `command`, `args`, `async`, `asyncRewake`, `shell`.
  - http: `url`, `headers`, `allowedEnvVars`.
  - mcp_tool: `server`, `tool`, `input`.
  - prompt and agent: `prompt`, `model`.
  - `async`: "This field is only available on `type: "command"` hooks."
- `if`: "Only evaluated on tool events: `PreToolUse`, `PostToolUse`, `PostToolUseFailure`,
  `PermissionRequest`, and `PermissionDenied`. On other events, a hook with `if` set never runs."
- Duplicates: "All matching hooks run in parallel. If you define the same handler in more than one
  settings file, it runs once. A plugin's or skill's copy of the same handler stays separate." And
  "Hook entries merge across settings levels rather than replacing each other".
- The page does **not** say what happens to a matcher that is not a valid regular expression.
  (Searching the page for "invalid", "regex" and "regular expression" finds only the lines above.)

### Brief claims the raw pages did not support as stated

1. **The startup warning covers allow rules only.** Deny and ask rules of the same shape are not
   warned about and fail closed: Claude Code "refuses or prompts for the extra commands". So a
   "deny with a bad wildcard" fails open only for the literal-colon shape (`Bash(git:* push)`). It
   also fails open for the two ignored-rule shapes this design adds (primary-field parameter rules,
   `mcp__` rules with parentheses).
2. **`Bash(* --version)` falls outside the startup warning.** errors.md exempts rules where "no word
   other than an option follows the `*`". This is an inference from that wording. The rule is still
   flagged, as its own shape.
3. **`HYG-hook-duplicates` says a duplicate "runs twice".** That is wrong for settings files, where
   the same handler "runs once". It is right for a plugin's (or skill's) copy.
4. **Behavior for an invalid regex is undocumented.** The check claims only "not a valid regular
   expression".
5. **Deny > ask > allow across scopes is supported** (quotes above).

## Design

### (i) Permission rule shapes — `collect.py`, next to `RISKY_RULES` / `analyze_permissions`

`rule_shape_flags(rule) -> set[str]` returns every shape a rule has. `rule_shape_issues(perms)`
keeps the flags relevant to each list. Only flagged rules are stored, as `redact(rule)[:160]`, at
most 6 per flag per list. The result lands in each settings summary as
`permissions.rule_shape_issues`: `{list: {flag: [rules]}}`, where lists and flags appear only when
non-empty (`{}` when clean). Non-string rules are skipped.

| Flag | Lists | Shape (Bash rules unless noted) | Documented effect |
|---|---|---|---|
| `wildcard-before-subcommand` | allow | Exactly one non-option word before the first `*`-token, and a later non-option word that is not `*` (`git * main`, `git -C * status *`) | Options inserted at the `*` are approved; Claude Code warns when the later word is the subcommand |
| `wildcard-program` | allow | First token is exactly `*` and more tokens follow (`* --version`, `* --help *`) | "any program matches" |
| `star-joined-to-program` | allow | Single token, one `*`, at the end, directly after `[A-Za-z0-9_]` (`ls*`, `/usr/bin/ls*`) | also matches other programs (`lsof`) |
| `colon-star-literal` | allow, ask, deny | `:*` anywhere except the very end of the specifier (`git:* push`) | literal colon; "won't match git commands"; a deny/ask then fails open |
| `ignored-primary-field` | ask, deny | `Bash`/`PowerShell(command:`, `Read`/`Edit`/`Write(file_path:`, `Grep`/`Glob(path:`, `NotebookEdit(notebook_path:`, `WebFetch(url:` (any tool; whitespace around `:` allowed) | "can't match … this way"; `Bash(command:rm *)` is ignored with a startup warning — fails open |
| `mcp-rule-with-parentheses` | allow, ask, deny | starts `mcp__` and contains `(` | skipped when the settings file loads — a deny fails open, an allow does nothing |

Tokenization: strip the specifier. If it ends with `:*` and has no other `:*`, drop that suffix
(a prefix rule, never flagged for placement). Split the rest on whitespace. A token "is an option"
when it starts with `-`.

**Positive cases** (each yields exactly this set):

| Rule | Flags |
|---|---|
| `Bash(git * main)` | `{wildcard-before-subcommand}` |
| `Bash(git -C * status *)` | `{wildcard-before-subcommand}` |
| `Bash(* --version)` | `{wildcard-program}` |
| `Bash(* --help *)` | `{wildcard-program}` |
| `Bash(ls*)` | `{star-joined-to-program}` |
| `Bash(/usr/bin/ls*)` | `{star-joined-to-program}` |
| `Bash(git:* push)` | `{colon-star-literal}` |
| `Bash(command:rm *)` | `{ignored-primary-field}` |
| `Read(file_path : ~/.ssh/id_rsa)` | `{ignored-primary-field}` |
| `WebFetch(url:https://x.test/*)` | `{ignored-primary-field}` |
| `mcp__github__create_issue(repo:x)` | `{mcp-rule-with-parentheses}` |

**Negative cases** (each yields the empty set):

- `Bash`, `Bash(*)` (already `risky.wildcard-all`)
- `Bash(git *)`, `Bash(git:*)`, `Bash(git log *)`, `Bash(git commit *)`, `Bash(git log * main)`
- `Bash(npm run test:*)`, `Bash(ls *)`, `Bash(ls:*)`, `Bash(npm run build)`,
  `Bash(python3 -m pytest *)`
- `Bash(cat ./src/*)`, `Bash(./scripts/*)`, `Bash(git checkout feature-*)`,
  `Bash(git checkout feat*)`
- `Bash(timeout:*)`, `Bash(run_in_background:true)`, `Agent(model:*)`
- `Read(./.env)`, `Read(//etc/**)`, `Edit(src/**)`, `WebFetch(domain:example.com)`
- `mcp__github__get_*`, `mcp__*`

Per-list filtering means that `Bash(git * main)` in deny or ask is not flagged, because it fails
closed.

### (iii) Hook handler validation — new `scripts/config_checks.py`

This module is pure and stdlib-only. It holds:

- `HOOK_EVENTS`: the single data constant, `{event: (what the matcher filters | None, 'default' |
  'narrow' | None)}`, covering all 33 documented events. It carries the doc URL and the fetch date
  2026-09-29 in its comment. `TOOL_EVENTS` is derived from it (the five events whose matcher filters
  "tool name").
- `COMMON_FIELDS` / `TYPE_FIELDS`: the documented handler fields.

`handler_issues(event, matcher, handler) -> (issues, unknown_fields)` evaluates these in order:

| Issue | Condition |
|---|---|
| `unknown_event` | `event` not in `HOOK_EVENTS` (case-sensitive; `pretooluse` is unknown). The matcher is then not evaluated |
| `matcher_not_string` | matcher is present and not a string |
| `matcher_ignored` | event has no matcher support, and matcher is not omitted, `""` or `"*"` |
| `mcp_server_only_matcher` | tool event, exact-path matcher, and an alternative starts with `mcp__` with no further `__` (`mcp__memory`, `mcp__brave-search`) |
| `narrow_event_regex_path` | `StopFailure` matcher outside the narrow set but inside the default exact set (`rate_limit, overloaded`) |
| `invalid_regex` | regex-path matcher (not `FileChanged`) that Python `re.compile` rejects, unless it contains a construct where JavaScript and Python differ (then it is not judged) |
| `if_never_runs` | handler has `if` and the event is not a tool event |
| `unknown_type` | `type` not one of the five documented types (a missing `type` means command, as the collector already assumes) |
| `unknown_fields` | handler keys outside common + that type's fields; the sorted names (at most 10) go in `unknown_fields` |

JS-divergent constructs are skipped: `(?<` not followed by `=`/`!` (named group), backslash
escapes of `c e g h i j k l m o p q y z C E F G H I J K L M O P Q R T V X Y`, `\u` without 4 hex
digits, `\x` without 2, `\U`, `\N`, and back-references `\1`–`\9`.

`handler_fingerprint(event, matcher, handler)` is the first 16 hex characters of the SHA-256 of
`json.dumps([event, normalize_matcher(matcher), handler with type defaulted to "command"],
sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str)`.
`normalize_matcher` maps omitted, `""` and `"*"` to `"*"`.

`collect.hook_handler_entry` (used for settings files and, via `extensions.add_hooks`, for plugin
hooks) adds these fields to each handler:

- `fingerprint`: always.
- `issues` and `unknown_fields`: only when non-empty.
- `plugin_relative: true`: only when the handler's JSON contains `CLAUDE_PLUGIN_`.

**Negative cases** (no issue):

- Events: every documented event with no matcher.
- Match-all on a no-matcher event: `Stop` with `"*"`, `""` or omitted.
- Tool events: `Edit|Write`, `Edit, Write`, `^Notebook`, `^Edit$`, `mcp__memory__.*`,
  `mcp__.*__write.*`, `mcp__memory__create_entities`.
- Other events: `SubagentStart` `code-reviewer`, `SubagentStart` `^my-plugin:reviewer$`,
  `PreModelSwitch` `.*opus.*`, `Notification` `permission_prompt`, `SessionStart` `mcp__memory`
  (not a tool event).
- Narrow-set events: `StopFailure` `rate_limit|overloaded`, `FileChanged` `.envrc|.env`,
  `FileChanged` `^\.env`.
- JS-only regex constructs: `PreToolUse` `(?<tool>Bash)`, `PreToolUse` `\p{L}+`.
- `if`: on `PermissionDenied`.
- Fields: a command handler using all its documented fields; a prompt handler with `model`; a
  handler without `type`.

**Positive cases**:

| Event and matcher/handler | Issues |
|---|---|
| `pretooluse` | `unknown_event` |
| `Stop` + `Bash` | `matcher_ignored` |
| `UserPromptSubmit` + `.*` | `matcher_ignored` |
| `PreToolUse` + `*.py` | `invalid_regex` |
| `PreToolUse` + `Edit\|Write)` | `invalid_regex` |
| `PreToolUse` + `[Edit` | `invalid_regex` |
| `PreToolUse` + `mcp__memory` | `mcp_server_only_matcher` |
| `PreToolUse` + `Bash\|mcp__brave-search` | `mcp_server_only_matcher` |
| `StopFailure` + `rate_limit, overloaded` | `narrow_event_regex_path` |
| `Stop` + `if` | `if_never_runs` |
| command handler with `url` | `unknown_fields` (`['url']`) |
| http handler with `async` | `unknown_fields` (`['async']`) |
| `type: script` | `unknown_type` |
| `PreToolUse` + `['Bash']` | `matcher_not_string` |

### (ii) Cross-layer conflicts — `config_checks.py` + `collect.config_stacks`

**Stacks** are the files that apply together. Each is
`{name, settings: [{layer, path, permissions, handlers, enabled_plugins}], plugins: [{plugin, path,
handlers}]}`:

- `global`: managed summaries + `~/.claude/settings.json` (`user`) +
  `~/.claude/settings.local.json` (`local`; per the docs it is read only in home-directory
  sessions).
- One stack per `projects` entry that has settings: managed + user `settings.json` + that
  directory's `.claude/settings.json` (`project`) and `.claude/settings.local.json` (`local`).
- Plugins in a stack: `extensions.plugins` with `status: collected` whose effective enablement in
  that stack is `true`. Enablement is the value in the highest-precedence stack file that sets the
  key, in the order managed > local > project > user. A `project`/`local`-scope install counts only
  for its own project; the global stack takes `user`/`managed` scope only. Each plugin name is
  counted once, and its hooks come from `components[kind=hooks].handlers`.
- Raw rules come from `collect._RAW_PERMISSIONS[summary_path]`, a module-level table that
  `summarize_settings` fills and `build_snapshot` clears first. Raw rules never enter a summary dict,
  because summaries are serialized (also as `instructions.settings_candidates`).

**Permission overlaps.** For each allow rule in a stack, the first covering rule is picked, looking
first at every deny list in the stack and then at every ask list. `rule_covers(by, allow)` returns
`exact`, `tool` or `prefix`, or `None`, and proves coverage only in these cases:

- raw equality, or equality after normalizing Bash `:*` → ` *` and `Bash(*)` → `Bash` (amended 2026-09-30
  after task review: a param-shaped Bash deny such as `Bash(timeout:*)` matches by raw text only; for
  non-Bash tools with a specifier, equality is refused when the specifier starts with `!` (gitignore
  negation denies nothing), when it starts with a single `/` and the rules come from different settings
  files (anchored at each source's own directory), or when the denying file's deny/ask lists hold a `!`
  rule for that tool);
- a bare `by` naming the same tool (`tool`), or a bare tool-name glob with a single trailing `*`
  whose prefix starts the allow's tool name (`mcp__*`, `*`);
- Bash only: `by` with exactly one `*`, at its end:
  - ` *` (spaced), with prefix P: covers when the allow's literal text before its first `*` starts
    with `P + ' '`, or, for an allow with no `*`, equals P;
  - no space, with prefix P: covers when that literal text starts with P;
  - (an allow ending in a sole ` *` needs no extra bare-form check: it is implied; amended 2026-09-30).

Coverage is never computed in these cases:

- the allow is an `mcp__` rule with parentheses (Claude Code skips it);
- `by` is `Bash(<command|description|timeout|run_in_background>:…)`, the Bash tool's documented
  inputs, which is ambiguous as a parameter rule;
- path globs;
- mid-rule wildcards.

Each overlap entry records the stack, the allow side (layer, path, redacted rule), the covering side
(list, layer, path, redacted rule) and the match kind.

**Covering pairs** (`by`, allow → match):

| `by` | allow | match |
|---|---|---|
| `Bash(git push *)` | `Bash(git push *)` | `exact` |
| `Bash(ls *)` | `Bash(ls:*)` | `exact` |
| `Bash` | `Bash` | `exact` |
| `Bash(*)` | `Bash(npm test)` | `tool` |
| `Bash` | `Bash(npm test)` | `tool` |
| `Read` | `Read(./src/**)` | `tool` |
| `mcp__*` | `mcp__github__get_issue` | `tool` |
| `*` | `WebSearch` | `tool` |
| `Bash(git *)` | `Bash(git log *)` | `prefix` |
| `Bash(git *)` | `Bash(git)` | `prefix` |
| `Bash(git *)` | `Bash(git log*)` | `prefix` |
| `Bash(git*)` | `Bash(gitk)` | `prefix` |
| `Bash(git:*)` | `Bash(git status)` | `prefix` |

**Non-covering pairs** (`by`, allow; the answer is `None`):

| `by` | allow |
|---|---|
| `Bash(git *)` | `Bash(gitk)` |
| `Bash(git *)` | `Bash(git*)` |
| `Bash(git *)` | `Bash(* --version)` |
| `Bash(git push --force *)` | `Bash(git push *)` |
| `Bash(rm *)` | `Bash` |
| `Bash(timeout:*)` | `Bash(timeout 5 ls)` |
| `Read(./src/**)` | `Read(./src/a.py)` |
| `Bash(git * main)` | `Bash(git merge main)` |
| `mcp__github__*` | `mcp__gitlab__get` |
| `Bash(git push *)` | `mcp__github__push(x)` |
| `mcp__*` | `mcp__github__create(x)` |
| `Bash(git:* push)` | `Bash(git push)` |

**Hook duplicates.** Members of a stack are:

- every settings handler, as `(layer, path, plugin=None, entry)`;
- every plugin handler, as `('plugin', hooks file path, plugin name, entry)`.

Members are grouped by `(fingerprint, plugin name if entry.plugin_relative else None)`, and a group
with two or more members is a duplicate. Its `effect` is:

- `same_file` when all members share one path (the docs are silent on this case);
- else `separate_copies` when any member is a plugin (the docs: "stays separate");
- else `deduplicated` (the docs: "it runs once").

**Reporting once.** Stacks are processed in the order `global`, then projects sorted. A finding
whose identity has already been reported is skipped. For hooks the identity is the group key plus
its sorted member ids; for permissions it is the allow member plus the covering member. So a
user-vs-managed conflict appears once, under `global`.

### Snapshot shape (additive, schema v1)

```json
"config_conflicts": {
  "stacks": 2,
  "hook_duplicates": [{"stack": "global", "event": "PreToolUse", "matcher": "Bash", "type": "command",
     "fingerprint": "3f1c0a9b7e2d4c55", "effect": "separate_copies",
     "sources": [{"layer": "user", "path": "~/.claude/settings.json", "plugin": null},
                 {"layer": "plugin", "path": "~/.claude/plugins/cache/m/demo/1/hooks/hooks.json",
                  "plugin": "demo@market"}]}],
  "hook_duplicates_omitted": 0,
  "permission_overlaps": [{"stack": "~/repo",
     "allow": {"layer": "project", "path": "~/repo/.claude/settings.json", "rule": "Bash(git log *)"},
     "by": {"list": "ask", "layer": "project", "path": "~/repo/.claude/settings.json", "rule": "Bash(git *)"},
     "match": "prefix"}],
  "permission_overlaps_omitted": 0
}
```

Caps: 20 duplicate groups (10 sources each) and 30 overlaps, with `*_omitted` counts. Ordering is
deterministic (stack order, then event/matcher/fingerprint, or then allow path/rule). The schema
types this section with `object`/`array`/`string`/`integer`/`enum` only, so there is no dependency
on the concurrent `number` type. `permissions.rule_shape_issues` and the new handler fields live in
untyped settings items and need no schema change. The `coverage.sources` entry
`{source: "config_conflicts", status: collected|partial, basis: "static", omitted: n}` is `partial`
when anything was omitted.

### Privacy

- Hook duplicates carry fingerprints, event, matcher, type, layer and paths, never command text.
  The fingerprint joins to `hook_handlers[].fingerprint`, whose `target` already holds the redacted
  text.
- Rule text follows the `risky` convention: `redact()` and at most 160 characters.
- Unknown field names are keys. They pass through `sanitize()` like every key.
- A canary command string must not appear in `config_conflicts`.

## Checklist (`references/checklist.md`)

- **SEC-wildcard-placement** (`permissions.rule_shape_issues.allow`)
- **SEC-ineffective-deny** (`permissions.rule_shape_issues.deny` / `.ask`)
- **HYG-shadowed-allow** (`config_conflicts.permission_overlaps`)
- **HYG-hook-duplicates**, rewritten on `config_conflicts.hook_duplicates` with the corrected
  runs-once / stays-separate semantics
- **HYG-hook-config** (`hook_handlers[].issues`, and the same on plugin handlers)

Each entry says the evidence is static and cites the docs with the fetch date. The exact wording is
in plan Task 6.

## Rulings

- Ruling: `wildcard-before-subcommand` = exactly one non-option word before the first `*` plus a
  later non-option word — the startup warning is keyed to "the subcommand", which the collector
  cannot identify — cost if wrong: a single-command program such as `Bash(ls * foo)` is flagged
  (the checklist says to confirm), and `docker compose * up` is missed.
- Ruling: deny/ask lists get only the fail-open shapes (`colon-star-literal`,
  `ignored-primary-field`, `mcp-rule-with-parentheses`). These last two go beyond the brief's four
  shapes: they come from the same page, they are the same kind of fail-open rule, and they cost
  one regex each. Over-broad deny/ask shapes fail closed per errors.md — cost if wrong: a deny/ask
  that over-matches and causes extra prompts goes unreported.
- Ruling: `star-joined-to-program` only for a single-token specifier whose sole trailing `*` follows
  a word character; `wildcard-program` only when the first token is exactly `*` — so path and
  branch globs (`./scripts/*`, `feature-*`) stay clean — cost if wrong: `Bash(git log*)` and
  `Bash(*/gradlew build)` are missed.
- Ruling: the rule-shape code lives in `collect.py` beside `RISKY_RULES` (as requested); the hook
  constant, validation, fingerprints and conflict logic go in a new pure `config_checks.py`; the
  per-handler fields are added in `hook_handler_entry`, so settings and plugin handlers get them
  alike — collect.py is 1,600 lines and pure functions test in isolation — cost if wrong: two
  places to update, and every handler entry grows by about 30 characters.
- Ruling: plugin hooks for duplicates come from `extensions.plugins[].components` rather than
  `harness.hook_index` — hook_index keeps only command handlers and drops `if`/`args` — cost if
  wrong: extensions caps handlers at 100 per component, so a larger plugin can hide a duplicate.
- Ruling: handler identity = event + normalized matcher + the full handler object. Handlers that
  reference `CLAUDE_PLUGIN_*` group only within their own plugin. Effect classes: `deduplicated`,
  `separate_copies`, `same_file`. The docs do not define "same handler", and identical plugin-root
  text expands to different paths — cost if wrong: handlers that differ only in `timeout` or
  `statusMessage` are missed; if Claude Code's identity is looser, the `deduplicated` label is
  right, but fewer pairs are reported.
- Ruling: stacks are `global` (managed + user + home-local) plus one per collected project
  directory. Plugin enablement comes from the highest-precedence stack file. Each finding is
  reported once, under the first stack where it appears. This follows settings precedence and the
  home-local quote — cost if wrong: `--settings`, CLI flags, server-managed policy and
  force-enabled plugins are unseen, and nested project directories count as separate stacks.
- Ruling: overlaps are claimed only when coverage is provable (see the tables), with one entry per
  allow and deny preferred over ask. A deny shaped like a Bash parameter rule is never used for
  prefix coverage. The aim is no false positives — cost if wrong: path-glob and mid-wildcard
  overlaps are missed, so absence is not proof.
- Ruling: `invalid_regex` is judged with Python `re`, skipping JS-divergent constructs, and its
  effect is reported as undocumented. `FileChanged` matchers, a missing `type`, and `once` in
  settings are not flagged. The docs are silent or ambiguous on each — cost if wrong: JS-only
  errors (`(?i)`, possessive quantifiers) and a few documented-but-ignored fields are missed.

## Testing

Everything runs against fake homes (`FakeHome`). Most tests call pure functions on hand-built
inputs, and two call `build_snapshot` end to end.

- **Shapes**: each positive and negative case above; per-list filtering; the 6 cap; redaction
  (`sk-…` in a flagged rule); non-string rules skipped; the summary carries `{}` when clean.
- **Hooks**: each positive and negative case above; fingerprint stability (key order, matcher
  normalization), sensitivity (timeout, event), and 16-hex form; `plugin_relative`; a clean handler
  carries no `issues` key; malformed managed files still yield `invalid_settings` (the existing
  test).
- **Overlaps**: each covering and non-covering pair; deny preferred over ask; the same pair in
  `global` and a project reported once; other projects never paired; the 30 cap with `omitted`;
  redaction.
- **Duplicates**: each effect; matcher `None` ≡ `*`, `Bash` ≠ `Bash|Edit`; different timeout means
  no duplicate; two plugins with the same `${CLAUDE_PLUGIN_ROOT}` command means no duplicate; a
  disabled plugin is excluded; the 20-group and 10-source caps; a canary command absent from the
  output.
- **End to end**, one fixture:
  - user allow + home-local deny (a `global` overlap);
  - project ask covering a user allow and a project allow (two `~/repo` overlaps, `prefix`);
  - user + plugin handler (`global` `separate_copies`);
  - user + project handler with the plugin disabled by project-local `false` (`~/repo`
    `deduplicated`, which proves the precedence rule);
  - the section validates, and coverage has `config_conflicts`;
  - a second build on a clean home reports nothing (the side table was cleared);
  - with `--scope global`, `stacks == 1`.
- **Schema**: the collector output validates; `effect`, `layer`, `match` and `list` enum
  violations, a missing `fingerprint` and a negative omitted count are each rejected.

Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`,
`git diff --check`, coverage ≥ 88.

## Out of scope

- MCP exposure metadata and tool-error clustering (2B).
- Hooks in skill or agent frontmatter; `--settings`/CLI/server-managed policy; runtime activation.
- Validating tool names in matchers or rules against the tools reference; path-glob overlap;
  PowerShell wildcard semantics.
- Any apply path: these checks only produce evidence, and fixes go through the existing approved
  apply flow.
