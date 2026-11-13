Snapshot date: 2026-11-12

# Official docs snapshot (fallback only)

Verbatim quotes from the Claude Code docs pages, copied from the raw Markdown of each page on the
snapshot date. The newest changelog entry on that day was 2.1.322 (November 10, 2026). Pages are named
as in the docs site (`settings` is the settings overview, not the settings reference).

How to use it:

- The run fetches the current pages first. A key or rule found both in the fetch and here is
  "current docs". One found only in the fetch is "current docs, quote not confirmed". One found here
  but missing from a fetch that reached its section is re-fetched once, then marked "may have
  changed". One whose section WebFetch probably did not see (long pages are cut short) is "not in
  fetched portion; snapshot <date>".
- When the run falls back to this file (offline, WebFetch denied), the report header says so in plain
  words with the snapshot date above.
- Checks in `checklist.md` cite the claim keys below. A check whose claim is missing here is
  reported as "unverified" unless the fetched page quotes it.
- Each quote is copied exactly; links in the original are left out by quoting around them.

## Permissions

- `perm-eval-order` — Rules are evaluated in order: deny, then ask, then allow. The first match in that order determines the outcome, and rule specificity doesn't change the order. — page `permissions`
- `perm-trailing-space` — `Bash(ls *)` requires a space after `ls`, so `lsof` doesn't match. `Bash(ls*)` has no space, so it matches `lsof` too. — page `permissions`
- `perm-wildcard-stands-in` — In `Bash(git * main)`, it stands in for the subcommand, so Claude Code matches every git subcommand and every option before it. That includes `-c`, which makes git run a program you name. In `Bash(* --version)`, the `*` stands in for the program, so any program matches. — page `permissions`
- `perm-colon-star` — The `:*` suffix is an equivalent way to write a trailing wildcard, so `Bash(ls:*)` matches the same commands as `Bash(ls *)`. — page `permissions`
- `perm-colon-star-end-only` — The `:*` form is only recognized at the end of a pattern. In a pattern like `Bash(git:* push)`, the colon is treated as a literal character and won't match git commands. — page `permissions`
- `perm-primary-field` — A rule like `Bash(command:rm *)` would be bypassable by a compound command, so Claude Code ignores it and emits a startup warning. Use `Bash(rm *)`, `Read(./path)`, or `WebFetch(domain:host)` instead. — page `permissions`
- `perm-mcp-parentheses` — When Claude Code loads a settings file, it skips any `mcp__` rule that has parentheses. — page `permissions`
- `perm-unanchored-glob` — An unanchored allow glob such as `"*"`, `"B*"`, or `"mcp__*"` is skipped and doesn't auto-approve anything. — page `permissions`
- `perm-file-rules` — Claude Code checks file permissions against `Edit(path)` and `Read(path)` rules. — page `permissions`
- `perm-read-deny` — To block Claude's file tools from reading a file or directory, add a `Read` deny rule for its path, such as `Read(./.env)` or `Read(./secrets/**)` — page `permissions`
- `perm-user-anchor` — To write a rule in user settings that applies inside every project, use a `//` absolute path or a `~/` home-relative path instead. — page `permissions`
- `perm-disable-bypass` — To prevent `bypassPermissions` or `auto` mode from being used, set `permissions.disableBypassPermissionsMode` or `permissions.disableAutoMode` to `"disable"` — page `permissions`
- `perm-hooks-dont-bypass` — PreToolUse hook decisions don't bypass permission rules. Claude Code evaluates deny and ask rules regardless of what a PreToolUse hook returns: a matching deny rule blocks the call, and a matching ask rule still prompts even when the hook returned `"allow"` or `"ask"`. — page `permissions`
- `perm-additional-dirs` — Directories listed in `permissions.additionalDirectories` in a settings file grant file access only and don't load any of the configuration below. — page `permissions`

## Settings

- `settings-default-mode-scope` — values `auto` and `bypassPermissions` don't take effect from project or local settings; set them in user or managed settings instead, or pass `--permission-mode` for one session. Before v2.1.257, `bypassPermissions` took effect from any file. — page `settings`
- `settings-local-git` — Claude Code keeps it out of git when it creates the file; if you create it by hand, add it to `.gitignore` yourself — page `settings`
- `settings-dont-ask-again` — When Claude asks permission to run a Bash command and you choose "Yes, and don't ask again", Claude Code saves that approval as an `allow` rule in `.claude/settings.local.json`. — page `settings`
- `settings-strict-json` — Settings files are strict JSON: a `//` comment or a trailing comma is a syntax error — page `settings`
- `settings-error` — **Settings Error**: a user, project, or local file has invalid JSON or a value the schema rejects. — page `settings`
- `settings-warning` — **Settings Warning**: only individual entries fail, such as a malformed permission rule or an unknown hook event name. Claude Code skips those values and keeps the rest of the file in effect. — page `settings`
- `settings-repo-ignored-keys` — Those keys never apply from the shared file, apart from a few that a repository file can still switch off. — page `settings`
- `settings-status` — Run `/status` inside Claude Code to see which settings sources are active. — page `settings`

## Hooks

- `hooks-full-permissions` — Command hooks execute shell commands with your full user permissions. — page `hooks`
- `hooks-on-failure` — On most events, when a hook fails or times out, Claude Code still carries out the action. A policy hook with a wrong path or a crashing script then lets everything through. To block the action instead, set `"onFailure": "block"` on a `command` or `http` hook. Requires Claude Code v2.1.295 or later. — page `hooks`
- `hooks-mistyped-path` — When you set up a policy hook, watch for this notice on its first run, because a mistyped path in `settings.json` means the hook never runs. — page `hooks`
- `hooks-dedup` — If you define the same handler in more than one settings file, it runs once. A plugin's or skill's copy of the same handler stays separate. — page `hooks`
- `hooks-matcher-ignored` — If you add a `matcher` field to an event without matcher support, it is silently ignored. — page `hooks`
- `hooks-timeout-default` — Defaults: 600 for `command`, `http`, and `mcp_tool`; 30 for `prompt`; 60 for `agent`. — page `hooks`
- `hooks-managed-only` — Your user, project, local, and plugin hooks are blocked. Hooks from plugins force-enabled in managed settings `enabledPlugins` are exempt — page `hooks`
- `hooks-session-start-context` — Claude Code adds plain-text stdout as context that Claude can see and act on. — page `hooks`
- `hooks-output-cap` — A hook's `additionalContext`, `systemMessage`, and `initialUserMessage` strings, and its plain stdout, are capped at 10,000 characters — page `hooks`
- `hooks-env-file` — SessionStart hooks have access to the `CLAUDE_ENV_FILE` environment variable, which provides a file path where you can persist environment variables for the shell commands Claude runs later in the session. — page `hooks`

## Sandboxing

- `sandbox-fallback` — By default, when the platform doesn't support the sandbox or the dependency check at startup fails, Claude Code runs commands without sandboxing. — page `sandboxing`
- `sandbox-fail-if-unavailable` — **`failIfUnavailable`**: when the platform doesn't support the sandbox or the dependency check at startup fails, Claude Code refuses to start rather than falling back to unsandboxed execution — page `sandboxing`
- `sandbox-nested-userns` — If you set `allowNestedUserNamespaces` to `true`, you turn off a security boundary: code from a sandboxed command can end up running outside the sandbox. — page `sandboxing`
- `sandbox-both-layers` — Effective sandboxing requires both filesystem and network isolation. Without network isolation, a compromised agent could exfiltrate sensitive files like SSH keys. — page `sandboxing`

## MCP

- `mcp-list-status` — `claude mcp list` shows a health status next to each server it lists, such as `✔ Connected`, `! Needs authentication`, or `✘ Failed to connect`. — page `mcp`
- `mcp-sse-deprecated` — The SSE (Server-Sent Events) transport is deprecated. Use HTTP servers instead, where available. — page `mcp`
- `mcp-project-approval` — For security reasons, Claude Code prompts for approval in interactive sessions before using project-scoped servers from `.mcp.json` files. — page `mcp`
- `mcp-headless-loads` — Claude Code can't show that prompt: it loads project-scoped servers without asking. — page `mcp`
- `mcp-cloned-repo` — A cloned repository can't approve its own servers — page `mcp`
- `security-mcp-beyond-file` — so reviewing `.mcp.json` doesn't show every server a session can load. — page `security`

## Memory and instructions

- `memory-size-target` — **Size**: target under 200 lines per CLAUDE.md file. Longer files consume more context and reduce adherence. — page `memory`
- `memory-imports-load` — Imported files are expanded and loaded into context alongside the CLAUDE.md that references them. — page `memory`
- `memory-index-limit` — The first 200 lines of `MEMORY.md`, or the first 25KB, whichever comes first, are loaded at the start of every conversation. Content beyond that threshold is not loaded at session start. — page `memory`
- `memory-consistency` — **Consistency**: if two instructions contradict each other, Claude may pick one arbitrarily. — page `memory`
- `memory-agents-md-default` — By default, Claude reads `AGENTS.md` only when you have no `CLAUDE.md` in your working directory or above it. — page `memory`

## Skills and subagents

- `skills-description-purpose` — What the skill does and when to use it. Claude uses this to decide when to apply the skill. — page `skills`
- `skills-desc-cap` — the combined `description` and `when_to_use` text is truncated at 1,536 characters in the skill listing to reduce context usage. — page `skills`
- `skills-listing-budget` — The budget scales at 1% of the model's context window. — page `skills`
- `subagent-model-frontmatter` — The subagent definition's `model` frontmatter, where `inherit` selects the main conversation's model — page `sub-agents`

## Cost and models

- `costs-model-choice` — Sonnet handles most coding tasks well and costs less than Opus. Reserve Opus for complex architectural decisions or multi-step reasoning. — page `costs`
- `costs-subagent-haiku` — For simple subagent tasks, specify `model: haiku` in your — page `costs`
- `costs-mcp-cli` — **Prefer CLI tools when available**: Tools like `gh`, `aws`, `gcloud`, and `sentry-cli` are still more context-efficient than MCP servers because they don't add any per-tool listing. — page `costs`
- `costs-mcp-disable-unused` — **Disable unused servers**: Run `/mcp` to see configured servers and disable any you're not actively using. — page `costs`
- `model-opusplan` — Special mode that uses `opus` during plan mode, then switches to `sonnet` for execution — page `model-config`
- `env-idle-compaction` — Idle compaction is on by default for conversations that meet its conditions. To turn it off, set `idleCompaction` to `false`. — page `env-vars`
- `env-prompt-cache-ttl` — Takes precedence over the `promptCacheTtl` setting and over `ENABLE_PROMPT_CACHING_1H`, and `FORCE_PROMPT_CACHING_5M` overrides it. The API bills 1-hour cache writes at a higher rate. — page `env-vars`

## Best practices

- `bp-never-rules` — You can also tune what it treats as risky, and your org can turn it off entirely, so your "never" rules belong in deny rules or hooks. — page `best-practices`
- `bp-deny-before-classifier` — Deny and ask rules and `PreToolUse` hooks apply before the classifier sees anything, so a deny rule blocks in auto mode exactly like it does everywhere else. — page `best-practices`
- `bp-pass-fail` — Give Claude something it can run that comes back pass or fail. — page `best-practices`
- `bp-test-command` — If your repo already has one of these, the single most useful line in your `CLAUDE.md` is the command that runs it. — page `best-practices`
- `bp-enforce-rules` — For the few where "almost" isn't good enough, move them out of `CLAUDE.md` and into configuration that Claude Code (the harness) applies itself. — page `best-practices`
- `bp-emphasis` — If it's a rule that can't bend, turn it into a hook or a deny rule. If the line is getting lost in a long file, the file needs to be shorter. — page `best-practices`
- `bp-file-layout` — Claude reads the repo itself. Only write down what isn't in there. — page `best-practices`
- `bp-subagents-cost` — Subagents are still great for parallel work, keeping noisy output out of your way, and independent review, but each of those costs extra tokens. — page `best-practices`
- `security-untrusted` — Avoid piping untrusted content directly to Claude — page `security`

## Changelog

- `changelog-version-check` — Run `claude --version` to check your installed version. — page `changelog`
