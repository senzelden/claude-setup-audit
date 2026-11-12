# Lite audit checklist

Where to look, not a form to fill in. Skip checks that don't apply, and don't report a check that
passed. Check ids are the full `setup-audit` plugin's ids, so findings line up across the two
editions; the three ids under "Lite-only" exist only here.

Each check gives:

- **Read:** what to look at, always through `reading-rules.md` (settings by the line allowlist,
  MCP only from a pasted list, counts for logs);
- **Claims:** the `docs-snapshot.md` keys the check relies on. Quote the fetched page when the run
  fetched it; fall back to the snapshot otherwise. "Claims: none" marks lite's own recommendation,
  which the report labels as such;
- the default severity in parentheses after the id.

Evidence is file and key (or rule text for permission rules), never a value. A check whose input is
missing (no pasted MCP list, no pasted `claude --version`, a file "not read") is reported as "not
run" with the reason, not as passed.

Lite reads configuration only. These full-plugin checks need usage data, transcript analysis or
scripted scans and are left to the full plugin: `SEC-settings-in-git` (needs git), `SEC-mods` (needs
module code), `COST-long-sessions`, `COST-mcp-unused`, `COST-harness-overhead`, `COST-tool-errors`,
`COST-tool-error-clusters`, `COST-subscription-headroom`, `COST-model-scoped-limits`,
`COST-extra-usage`, `COST-limit-resets`, `COST-app-caching`, `LRN-friction`, `LRN-corrections`,
`LRN-interruptions`, `LRN-duplicate-memory`, `LRN-failure-loops`, `RDY-env-undeclared`,
`RDY-env-failfast`, `RDY-envrc-literal-secret` (lite never opens env files), `RDY-env-secret-backend`,
`RDY-test-data`, `RDY-boundaries`, `HYG-worktrees`, `HYG-plugin-footprint`. When the user asks about
one of these, say the full plugin covers it.

## Security (SEC-)

- `SEC-risky-allow` (high for the first group, medium otherwise). Read: `permissions.allow` in every
  settings file. Claims: `perm-eval-order`, `perm-hooks-dont-bypass`, `perm-unanchored-glob`.
  Weigh by blast radius: a bare `Bash`, `Bash(*)`, `sudo`, recursive `rm`; network tools with a
  wildcard (`curl *`, `wget *`, `WebFetch(domain:*)`), which let Claude send data anywhere without a
  prompt; interpreters with a wildcard (`python -c *`, `node -e *`); destructive or outward git
  (`git push --force *`, `git reset --hard *`), `gh api *`; `docker *`. Fix: remove or narrow, and
  add `deny` or `ask` rules for the dangerous forms; the same broad rule in many projects becomes one
  user-level rule. A blocking `PreToolUse` hook on the same matcher may already constrain the rule,
  but a hook's "allow" never overrides a deny or ask rule, so a hook doesn't replace a missing deny.
  An unanchored allow glob such as `"*"` approves nothing; report it under hygiene, not here.
- `SEC-wildcard-placement` (medium; high on git, interpreter or network rules). Read:
  `permissions.allow`. Claims: `perm-wildcard-stands-in`, `perm-trailing-space`. Allow rules whose
  `*` reaches further than the rule reads: a `*` after the program name followed by a later word
  (`Bash(git * main)` also matches `git -c <option> diff main`, which can make git run a program); a
  `*` in the program position (`Bash(* --version)`); no space before a trailing `*` (`Bash(ls*)` also
  matches `lsof`). Fix: put the `*` after the subcommand (`Bash(git log *)`), or `Bash(ls *)`.
- `SEC-ineffective-deny` (high when the rule guards secrets or destructive commands, medium
  otherwise). Read: `permissions.deny` and `permissions.ask`. Claims: `perm-colon-star-end-only`,
  `perm-primary-field`, `perm-mcp-parentheses`, `perm-file-rules`. Rules that don't block what they
  read as: `:*` in the middle (`Bash(git:* push)` matches nothing; fix `Bash(git push *)`);
  `Tool(param:value)` on a primary field (`Bash(command:rm *)` is ignored; fix `Bash(rm *)`); an
  `mcp__` rule with parentheses (skipped in settings files); a path rule on a tool other than `Read`
  or `Edit` (file checks match only `Read(...)` and `Edit(...)`; see `stale-strings.md`).
- `SEC-deny-baseline` (medium). Read: `permissions.deny` in every settings file. Claims:
  `perm-read-deny`, `perm-user-anchor`, `bp-never-rules`. No deny rules anywhere. Propose a small
  user-level baseline: `Read` denies for `.env` files, `~/.ssh/**`, `~/.aws/**` and credential files,
  plus force-push. Anchor user-level paths with `//` or `~/`; a single leading `/` anchors at the
  settings file's own location.
- `SEC-secret-literal` (high). Read: the secret-shaped count probes in `reading-rules.md` step 2.
  Claims: `settings-dont-ask-again`. A token-shaped string sits in an allow rule, hook command or hook
  URL, usually saved by "Yes, and don't ask again". Report file and count only; that file's rule,
  command and URL lines are then counted, not shown. Fix (by hand): rotate the credential, delete the rule, keep the secret in the environment or
  a secrets manager.
- `SEC-secret-env` (low). Read: `permissions.allow`. Claims: `settings-dont-ask-again`. An allow rule
  that pulls a dotenv file onto the command line (`source .env`, `$(cat .env)`, `export $(...)`), so
  values land in session logs. Fix: a script that reads the environment itself.
- `SEC-auto-mode` (raises the weight of other findings). Read: `permissions.defaultMode` and the
  `autoMode` key names. Claims: `settings-default-mode-scope`, `bp-deny-before-classifier`,
  `perm-disable-bypass`. With `auto` or `bypassPermissions` as the default in user or managed
  settings, fewer actions reach a human: raise risky allows and a missing sandbox by one step. Deny
  rules and `PreToolUse` hooks still apply before the classifier, so they are the controls to
  recommend. The same mode in a project or local file doesn't take effect (`HYG-scope-ignored`).
- `SEC-sandbox` (medium; high together with `SEC-auto-mode`). Read: the `sandbox` block of every
  settings file. Claims: `sandbox-fallback`, `sandbox-fail-if-unavailable`, `sandbox-nested-userns`,
  `sandbox-both-layers`. Check: no sandbox at all for autonomous or long sessions;
  `failIfUnavailable` unset or `false` (Claude Code runs unsandboxed when the sandbox can't start);
  `allowNestedUserNamespaces: true` in user or managed settings (turns off a security boundary; a
  repo can't turn it on, so a project `true` is ineffective); broad filesystem or network exceptions,
  or filesystem isolation without network isolation (both are needed). Sandbox changes loosen or
  tighten security: lite never applies a loosening; the user makes it by hand.
- `SEC-hooks` (medium). Read: `hooks` blocks in settings files and plugin `hooks/hooks.json` (hook
  scripts are not read). Claims: `hooks-full-permissions`, `hooks-on-failure`, `hooks-managed-only`.
  Weigh by handler type: `command` hooks run with the user's full permissions (flag ones that run
  code from outside the repo or plugin, or match every tool with a slow command); `http` hooks send
  each matching event's JSON to a URL (flag an unfamiliar host and a wide matcher; header names
  only, the `headers` block is skipped); `prompt` and `agent` hooks are another model call; an
  `mcp_tool` hook is as trustworthy as its server. A `PreToolUse` or `PermissionRequest` hook that
  exists to block something fails open unless it sets `"onFailure": "block"` (Claude Code 2.1.295+);
  propose that for guards only, never for loggers or formatters. If managed settings exist and don't
  set `allowManagedHooksOnly`, mention once that any project can add hooks.
- `SEC-mcp` (medium). Read: the pasted `claude mcp list` or `/mcp` output only. Claims:
  `mcp-list-status`, `security-mcp-beyond-file`. Unknown servers, servers that can write to external
  systems, and project servers the user didn't expect. Report names, transport and status only. No
  paste: "not run: no pasted MCP list".
- `SEC-mcp-exposure` (high in a shared project settings file, medium otherwise). Read:
  `enableAllProjectMcpServers`, `enabledMcpjsonServers` and `disabledMcpjsonServers` key names and
  lists in settings files. Claims: `mcp-project-approval`, `mcp-headless-loads`, `mcp-cloned-repo`.
  Approving all project servers means any server a teammate adds loads; in `claude -p`, SDK and cloud
  sessions project servers load without asking anyway. Fix: remove the blanket approval, list the
  wanted servers, or disable the unwanted ones. Credentials inside MCP config are not checked, because
  lite never opens MCP config files; say so.
- `SEC-install` (low; medium when many releases behind). Read: pasted `claude --version`. Claims:
  `changelog-version-check`. Compare with the newest changelog entry and count releases behind. No
  paste: "not run".
- `SEC-docs-only-constraint` (medium). Read: CLAUDE.md files, rules, `AGENTS.md`, plus
  `permissions.deny` and hooks. Claims: `bp-never-rules`, `bp-enforce-rules`. A "never read X" or
  "never run Y" line with no matching deny rule, hook or sandbox setting. Fix: the deny rule or hook;
  the prose line can then go.

## Cost & context (COST-)

- `COST-baseline` (info). Read: pasted `/context` if any; MCP server count from the paste;
  `enabledPlugins` names; CLAUDE.md and rules line counts; skill count. Claims: `memory-imports-load`,
  `costs-mcp-disable-unused`. What loads before the first answer, by contributor. Tokens only from a
  pasted `/context`; otherwise counts only, labelled "not measured". Record the numbers for the
  check-in.
- `COST-model-default` (medium). Read: the `model` key in settings files and agent frontmatter.
  Claims: `costs-model-choice`, `model-opusplan`. A top-tier model as the default for mostly routine
  work. Options: `opusplan`, a cheaper default with switching per task, or cheaper subagents
  (`COST-subagents`). Ask about the work before proposing.
- `COST-claude-md-size` (medium). Read: line counts of every CLAUDE.md, `CLAUDE.local.md`, loaded
  `AGENTS.md` and rule without `paths`. Claims: `memory-size-target`, `memory-imports-load`,
  `bp-file-layout`. Over about 200 lines per file. Fix: move area-specific guidance into nested
  CLAUDE.md files or path-scoped rules, procedures into skills, and drop descriptions of layout Claude
  can read itself. `@imports` load at launch too, so they don't save context.
- `COST-memory-index` (low). Read: count-only line count of each `MEMORY.md`. Claims:
  `memory-index-limit`. Over 200 lines: entries past the limit don't load. Bytes aren't measured
  (lite can't size a file), so say "lines only".
- `COST-skill-listing` (low). Read: skill frontmatter (`description`, `when_to_use`) for user,
  project and plugin skills; `skillListingBudgetFraction` key. Claims: `skills-listing-budget`,
  `skills-desc-cap`. Many skills or long descriptions crowd the listing, and an overflowing listing
  drops descriptions. Confirm with a pasted `/context` before claiming overflow; otherwise note
  "possible".
- `COST-startup-hooks` (low; medium for several). Read: `SessionStart` hooks in settings and plugin
  `hooks/hooks.json`. Claims: `hooks-session-start-context`, `hooks-output-cap`. Each one can add
  text to every session's context. Name the plugin or file; size isn't measured without a pasted
  `/context`.
- `COST-subagents` (low). Read: frontmatter of agent definitions (`~/.claude/agents/`,
  `.claude/agents/`, plugin agents). Claims: `subagent-model-frontmatter`, `costs-subagent-haiku`,
  `bp-subagents-cost`. Agents for routine tasks with no `model:` (they follow the main model) or a
  top-tier model. Fix: `model: haiku` or `sonnet` in that agent's frontmatter.
- `COST-cache-health` (low). Read: `promptCacheTtl`, `subagentPromptCacheTtl`, `idleCompaction` key
  names and values from the allowlisted setting lines. Claims: `env-prompt-cache-ttl`,
  `env-idle-compaction`. Config side only: lite can't see cache hits. Note a 1-hour TTL (writes cost
  more) or idle compaction turned off, and ask why. Environment-variable forms sit in the `env`
  block, which is not shown, and are not seen.

## Learning (LRN-)

Only when the user names a repeated mistake. No automatic discovery.

- `LRN-enforce` (medium). Read: CLAUDE.md files and rules for a line about the named mistake;
  count-only Grep of session logs for a fixed phrase of it. Claims: `bp-enforce-rules`,
  `bp-emphasis`. The rule exists but the mistake still recurs: propose a hook or deny rule rather
  than stronger wording. No rule yet: the lightest place that will hold (CLAUDE.md line, path-scoped
  rule, then hook).
- `LRN-contradiction` (medium). Read: every instruction surface that mentions the named topic
  (user and project CLAUDE.md, rules, `AGENTS.md`, skills). Claims: `memory-consistency`,
  `memory-agents-md-default`. Two surfaces disagree. Propose one canonical statement. An `AGENTS.md`
  next to a CLAUDE.md isn't read by default, so don't call that conflict active without saying so.
- `LRN-effectiveness` (info). Read: lite's own `applied.md` log and the same count-only Grep as at
  apply time. Claims: none. At the check-in, compare counts before and after the change; label it
  "counts compared, not proof".

## Agent readiness (RDY-)

Opt-in. Report a gap only when the user mentions the symptom or the fix is cheap; match the repo's
own stack and conventions.

- `RDY-first-run` (low). Read: Glob for `Makefile`, `justfile`, `package.json` scripts, version pin
  files (`.tool-versions`, `.python-version`, `.nvmrc`, `mise.toml`) and lockfiles. Claims: none. No
  single setup command or no version pins. Fix: one setup target in the tool the repo already uses.
- `RDY-env-invisible-to-claude` (medium). Read: Glob for `.envrc` (existence only, never opened) and
  `SessionStart` or `CwdChanged` hooks that mention `CLAUDE_ENV_FILE`. Claims: `hooks-env-file`. The
  repo loads variables when the user's shell enters the directory, which Claude's shell never does.
  Options: non-secret names through a `SessionStart` hook writing to `CLAUDE_ENV_FILE`; secrets only
  inside the specific scripts that need them (recommended); exporting everything is easiest but
  exposes every value to every command.
- `RDY-format-guardrails` (low). Read: Glob for formatter config and `.pre-commit-config.yaml`;
  `PostToolUse` hooks. Claims: `bp-enforce-rules`. A formatter is configured but nothing runs it
  automatically. Fix: a pre-commit hook for people and a `PostToolUse` format hook for Claude, using
  the repo's own formatter.
- `RDY-type-strictness` (low). Read: `tsconfig.json` `strict`, or the type checker's strict setting
  in `pyproject.toml`. Claims: none. Strict mode off; weigh by repo age.
- `RDY-test-loop` (medium). Read: count-only Grep of CLAUDE.md for the repo's test command; Glob
  for tests. Claims: `bp-pass-fail`, `bp-test-command`. The repo has tests but CLAUDE.md doesn't say
  how to run them (or how to run a fast subset). Fix: one line with the command.
- `RDY-adr` (low). Read: Glob for `docs/adr/` or `docs/decisions/`. Claims: none. Only when the user
  says Claude keeps re-deciding settled questions: propose decision records linked from CLAUDE.md.

## Hygiene (HYG-)

Always on.

- `HYG-settings-shape` (medium; high when the key is `permissions` or `hooks`). Read: the
  allowlisted lines and counts from the reading rules. Claims: `settings-strict-json`,
  `settings-error`, `settings-warning`, `settings-status`. A value of the wrong type (a `deny` entry
  that isn't a string, `permissions` that isn't an object) or a comment line (count `^\s*//`). Claude Code skips the entry or the file; ask the user to check `/status` or `claude doctor`.
- `HYG-scope-ignored` (low). Read: key names per settings file; the Scope column of the fetched
  `settings-reference` page. Claims: `settings-repo-ignored-keys`, `settings-default-mode-scope`. A
  key in a file where Claude Code ignores it (for example `permissions.defaultMode: auto` in a
  project file). Propose moving it to the file where it works. `env` variable names aren't read, so
  ignored env variables are not checked.
- `HYG-missing-hook-script` (high on `PreToolUse`, low otherwise). Read: the script path in each hook
  command; Glob for it (expand `$CLAUDE_PROJECT_DIR` and the plugin root by hand). Claims:
  `hooks-mistyped-path`. A hook that points at a missing file never does its job.
- `HYG-dead-refs` (low). Read: paths named in CLAUDE.md files; Glob for each. Claims: none. Paths
  that don't exist. Skip generated or ignored paths.
- `HYG-one-off-rules` (low). Read: count of `permissions.allow` entries. Claims:
  `settings-dont-ask-again`. More than about 50 allow rules, mostly exact commands saved from
  prompts, which hide the risky ones. Propose pruning the one-off ones.
- `HYG-stale-dirs` (low). Read: `permissions.additionalDirectories`; Glob each. Claims:
  `perm-additional-dirs`. Entries that no longer exist or come from another machine.
- `HYG-hook-duplicates` (low; medium when a plugin and a settings file both carry it). Read: hooks
  in all settings files and plugins. Claims: `hooks-dedup`. The same handler in several settings
  files runs once (clutter); a plugin's copy runs separately (double cost and side effects). Fix: drop
  the settings copy when a plugin provides the hook.
- `HYG-shadowed-allow` (low). Read: allow, ask and deny lists across all scopes. Claims:
  `perm-eval-order`. An allow rule that a deny or ask rule always matches first never takes effect
  (the usual cause of "I said don't ask again and it still asks"). Fix: remove the dead allow, or
  narrow the deny or ask if the allow was intended. Never propose loosening a managed rule.
- `HYG-hook-config` (high for a guard that never fires, low otherwise). Read: hook event names,
  matchers, `timeout`, `onFailure`. Claims: `hooks-matcher-ignored`, `hooks-timeout-default`,
  `settings-warning`, `hooks-on-failure`. Unknown event names (check the case) are skipped; a matcher
  on an event without matcher support is ignored, so the hook fires every time; a `timeout` above 600
  was probably written in milliseconds (the field is seconds); `onFailure` other than `"continue"`
  or `"block"`.
- `HYG-mcp-config` (medium for failing servers, low otherwise). Read: the pasted MCP list only.
  Claims: `mcp-list-status`, `mcp-sse-deprecated`. Servers that fail to connect or need
  authentication, servers on the deprecated SSE transport, and project servers left pending. Propose
  a fix or removal; never repeat URLs or arguments from the paste.

## New features (adopt)

Read: pasted `claude --version` and the fetched changelog. Claims: `changelog-version-check`. List
only features released after the user's version (or recent ones, if no version was pasted) that
address something this audit found, each with one line of cost and benefit. Park the rest. This
section is central to the comparison: say which current recommendations the user's setup predates.

## Lite-only

Part of hygiene, always on. Proposals here prefer removing or merging over adding. A proposal to add
a hook, skill, plugin or MCP server must say what it replaces or why nothing existing covers it.
Lite never recommends installing a large bundle wholesale, and adds nothing itself except its log.

- `HYG-lite-clutter-skills` (low). Read: skill frontmatter (`name`, `description`, `when_to_use`)
  across user, project and plugin skills. Claims: `skills-description-purpose`,
  `skills-listing-budget`. Skills whose descriptions trigger on the same requests, so Claude picks
  one at random or both crowd the listing. Fix: merge, or disable the weaker one.
- `HYG-lite-clutter-hooks` (low; medium when they conflict). Read: hooks on the same event and
  matcher across settings and plugins. Claims: `hooks-dedup`, `perm-hooks-dont-bypass`. Hooks that
  duplicate each other (two formatters, two loggers) or conflict (one approves what another blocks).
  Fix: keep one.
- `HYG-lite-clutter-overlap` (low). Read: `enabledPlugins` names, plugin component lists (Glob), and
  the pasted MCP list. Claims: `costs-mcp-cli`, `costs-mcp-disable-unused`. Plugins or MCP servers
  that duplicate each other or a built-in tool or CLI already allowed (for example a code-hosting MCP
  server next to an allowed `gh` command). MCP only from the paste. Fix: remove or disable one.
