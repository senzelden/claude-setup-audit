# Community GitHub repos publishing Claude Code best practices (state as of 2026-11-12)

Method and limits: star counts, pushed_at dates, descriptions and licenses come from the unauthenticated GitHub REST API (`https://api.github.com/repos/OWNER/REPO`, queried 2026-11-12). `pushed_at` is the last push of any kind, not "last meaningful commit". Repo text was read from raw.githubusercontent.com on 2026-11-12. Official-docs checks were done against `code.claude.com/docs/en/*.md` pages fetched raw on 2026-11-12. Not done: commit-history review, issue/PR review, Hacker News/Reddit citation counts (no search was run), full reads of every repo. Star counts of some repos look inflated or odd (see Gaps); treat stars as popularity, not quality.

## 1. Most-referenced, credible community repos (inventory)

### Takeaway
The credible sources for a config auditor are a small set: Trail of Bits' config repo (security-first, closest to an authoritative community reference), hesreallyhim's curated list (best for discovering tools), and three large guide repos (shanraisshan, luongnv89, FlorianBruniaux) that track official docs closely. Large "everything" bundles (ECC, wshobson/agents, VoltAgent subagents, obra/superpowers) are popular but are tool/workflow collections, not audit baselines.

### Cited Findings

Curated lists and guides
- hesreallyhim/awesome-claude-code: 57,869 stars, pushed 2026-11-12, license NOASSERTION. Hand-picked list of skills, agents, status lines, hooks, tooling, plugins. README says it was relaunched with emphasis on recommendations, and "legacy" entries are preserved but not updated in a README_ALTERNATIVES dir. Entries are one-paragraph descriptions by the submitter; includes security tools such as Gryph (safedep) and Parry-guard (self-described "early development") — [repo](https://github.com/hesreallyhim/awesome-claude-code), [API](https://api.github.com/repos/hesreallyhim/awesome-claude-code), [README](https://raw.githubusercontent.com/hesreallyhim/awesome-claude-code/main/README.md)
- shanraisshan/claude-code-best-practice: 69,004 stars, MIT, pushed 2026-11-12. Feature-by-feature best-practice pages (commands, agents, skills, hooks, workflows) with tips attributed to Boris Cherny (Anthropic). Links point at current code.claude.com pages. Recommends `/permissions` wildcard rules and auto mode "instead of dangerously-skip-permissions" — [repo](https://github.com/shanraisshan/claude-code-best-practice), [README](https://raw.githubusercontent.com/shanraisshan/claude-code-best-practice/main/README.md)
- luongnv89/claude-howto: 47,066 stars, MIT, pushed 2026-11-12. Visual, example-driven guide with copy-paste templates. README tracks recent changes: lists current hook events (e.g. SessionStart, Setup, StopFailure, SubagentStop, PreCompact, PostCompact, PreModelSwitch, ConfigChange, CwdChanged, FileChanged, InstructionsLoaded, Elicitation) and permission modes (`default`, `acceptEdits`, `plan`, `auto`, `dontAsk`, `bypassPermissions`); notes native installer and the npm-install deprecation — [repo](https://github.com/luongnv89/claude-howto), [README](https://raw.githubusercontent.com/luongnv89/claude-howto/main/README.md)
- FlorianBruniaux/claude-code-ultimate-guide: 6,423 stars, CC-BY-SA-4.0, pushed 2026-11-12. Self-described "430K+ lines": guides, hooks, skills, MCP, templates, quizzes. Size suggests breadth over vetting — [repo](https://github.com/FlorianBruniaux/claude-code-ultimate-guide), [API](https://api.github.com/repos/FlorianBruniaux/claude-code-ultimate-guide)
- wesammustafa/Claude-Code-Quest: 3,690 stars, pushed 2026-11-10, 3-level tutorial (topic claude-code-hooks/best-practices search results) — [API search](https://api.github.com/search/repositories?q=topic:claude-code-hooks&sort=stars)
- jnMetaCode/ai-coding-guide (553 stars, pushed 2026-11-09, bilingual tips), inmve/awesome-ai-coding-techniques (352, 2026-11-12) — [API search](https://api.github.com/search/repositories?q=topic:claude-code+topic:best-practices&sort=stars)

Security-oriented config
- trailofbits/claude-code-config: 2,148 stars, pushed 2026-08-24, no license field. "Opinionated defaults" for sandboxing, permissions, hooks, skills, MCP. Ships a `settings.json` with `$schema` (schemastore), deny rules for credential paths (`~/.ssh`, `~/.aws`, `~/.config/gh`, `~/.git-credentials`, `~/.kube`, `~/.npmrc`, wallet dirs), `enableAllProjectMcpServers: false`, telemetry-off env vars, and two PreToolUse Bash hooks (block `rm -rf`, block push to main) — [repo](https://github.com/trailofbits/claude-code-config), [settings.json](https://raw.githubusercontent.com/trailofbits/claude-code-config/main/settings.json), [README](https://raw.githubusercontent.com/trailofbits/claude-code-config/main/README.md)
- kenryu42/cc-safety-net: 2,008 stars, pushed 2026-11-12. Pre-execution guard that blocks destructive git/filesystem commands — [repo](https://github.com/kenryu42/cc-safety-net)
- eugene1g/agent-safehouse: 2,149 stars, pushed 2026-11-12. Local sandboxing for agents — [API search](https://api.github.com/search/repositories?q=topic:claude-code+topic:security&sort=stars)
- affaan-m/agentshield: 1,397 stars, pushed 2026-10-18. Scanner for agent configs/MCP servers (same maintainer as ECC, so partly self-promotional) — [API search](https://api.github.com/search/repositories?q=topic:claude-code+topic:security&sort=stars)
- karanb192/claude-code-hooks: 581 stars, pushed 2026-11-11, hooks + installable marketplace for safety/cost/observability — [API search](https://api.github.com/search/repositories?q=topic:claude-code+topic:hooks&sort=stars)
- nizos/tdd-guard 2,376 stars (2026-11-03); FailproofAI/failproofai 8,759 (2026-11-12) — [API search](https://api.github.com/search/repositories?q=topic:claude-code+topic:hooks&sort=stars)

Hooks, examples, starter kits
- disler/claude-code-hooks-mastery: 3,975 stars, pushed 2026-03-04, no license. Covers all hook events with diagrams; documents SubagentStop and PreCompact. Not updated since March 2026, so newer events/handler types likely missing — [repo](https://github.com/disler/claude-code-hooks-mastery), [README](https://raw.githubusercontent.com/disler/claude-code-hooks-mastery/main/README.md)
- ChrisWiles/claude-code-showcase: 6,084 stars, pushed 2026-01-06, no license. Full project example (hooks, skills, agents, commands, GH Actions). See conflicts section — [repo](https://github.com/ChrisWiles/claude-code-showcase)
- centminmod/my-claude-code-setup: 2,730 stars, MIT, pushed 2026-11-09. Starter template with CLAUDE.md "memory bank" system. (README fetch at `main/README.md` returned 404, so content not reviewed; the file may be named differently.) — [API](https://api.github.com/repos/centminmod/my-claude-code-setup)
- nadimtuhin/claude-token-optimizer: 653 stars, pushed 2026-11-09, trims session-start tokens via small CLAUDE.md (context-cost topic) — [API search](https://api.github.com/search/repositories?q=topic:claude-md&sort=stars)
- mksglu/context-mode: 33,984 stars, pushed 2026-11-12, plugin keeping tool output out of context (context-efficiency tool, not a guide) — [API search](https://api.github.com/search/repositories?q=topic:claude-code-hooks&sort=stars)

Subagent / skill / plugin collections (large, mostly bundles)
- wshobson/agents: 42,451 stars, MIT, pushed 2026-11-09; plugins/agents/skills authored once and generated for multiple tools — [API](https://api.github.com/repos/wshobson/agents)
- VoltAgent/awesome-claude-code-subagents: 26,506 stars, MIT, pushed 2026-11-02; "100+ specialized subagents" — [API](https://api.github.com/repos/VoltAgent/awesome-claude-code-subagents)
- obra/superpowers: 316,720 stars, MIT, pushed 2026-11-03; skills framework / methodology — [API](https://api.github.com/repos/obra/superpowers)
- affaan-m/ECC (formerly affaan-m/everything-claude-code; old URL returns "Moved Permanently"): 301,940 stars, pushed 2026-11-09; "agent harness performance optimization system" spanning Claude Code, Codex, Cursor, OpenCode — [API](https://api.github.com/repos/affaan-m/ECC), [README](https://raw.githubusercontent.com/affaan-m/ECC/main/README.md)
- ComposioHQ/awesome-claude-skills: 79,346 stars, no license, pushed 2026-09-18. travisvn/awesome-claude-skills: 15,796 stars, pushed 2026-04-28 — [API](https://api.github.com/repos/ComposioHQ/awesome-claude-skills), [API](https://api.github.com/repos/travisvn/awesome-claude-skills)

Anthropic-owned (excluded from list, noted separately)
- anthropics/claude-code: 155,434 stars, pushed 2026-11-11. Official repo (issues, changelog, plugins/examples). Use as authority alongside code.claude.com docs, not as community source — [API](https://api.github.com/repos/anthropics/claude-code)

### Inferences
- A config auditor should treat trailofbits/claude-code-config as the strongest community reference for permissions/sandbox/hook defaults, hesreallyhim's list as a discovery index, and the shanraisshan / luongnv89 guides as secondary because they cite official pages and track recent features.
- Repos pushed in the last two weeks are not necessarily accurate; recency here mostly reflects automated or bulk additions (e.g. 430K-line guide, 100+ agent bundles).

### Gaps
- No Hacker News / Reddit citation data gathered; "most referenced" is approximated by stars and topic ranking only.
- Last-commit dates are `pushed_at`, which can include non-substantive pushes; commit histories were not inspected.

## 2. Stale, link-dump, or vendor-flavored repos

### Takeaway
No major repo is pre-2026 stale, but several are static since early 2026 (hooks-mastery March, showcase January) and the bundles/lists are mostly unvetted breadth. Composio's list is vendor-associated.

### Cited Findings
- disler/claude-code-hooks-mastery: last push 2026-03-04, about eight months before this date; hook feature set documented there predates events that luongnv89's README lists as current (PreModelSwitch, StopFailure, InstructionsLoaded, etc.) — [API](https://api.github.com/repos/disler/claude-code-hooks-mastery), [claude-howto README](https://raw.githubusercontent.com/luongnv89/claude-howto/main/README.md)
- ChrisWiles/claude-code-showcase: last push 2026-01-06; uses deprecated/non-official constructs (section 3) — [API](https://api.github.com/repos/ChrisWiles/claude-code-showcase)
- travisvn/awesome-claude-skills: last push 2026-04-28 (about six months stale) and ComposioHQ/awesome-claude-skills last push 2026-09-18. ComposioHQ is a commercial tool-integration vendor (vendor-affiliation is my characterization from the owner name, not verified in the README) — [API](https://api.github.com/repos/ComposioHQ/awesome-claude-skills)
- hesreallyhim/awesome-claude-code: entries are submitter-written descriptions; list itself states legacy entries are no longer updated and some listed tools are self-described early-stage (Parry-guard) — [README](https://raw.githubusercontent.com/hesreallyhim/awesome-claude-code/main/README.md)
- Smaller lists: ccplugins/awesome-claude-code-plugins (1,005 stars, last push 2026-08-12), LangGPT/awesome-claude-code (274, 2026-05-24), croffasia/cc-blueprint-toolkit (196, last push 2025-11-26, the only 2025-dated one found) — [API search](https://api.github.com/search/repositories?q=topic:awesome-claude-code&sort=stars)
- parcadei/Continuous-Claude-v3: 3,949 stars, last push 2026-01-26 — [API search](https://api.github.com/search/repositories?q=topic:claude-code-hooks&sort=stars)
- Sub-100-star "checker"/"builder" repos in the `claude-code-settings` topic (e.g. OmriYaakov/managed-settings, 1 star; Turner-Levey/claude-code-hooks-settings-checker, 0 stars) are not credible references — [API search](https://api.github.com/search/repositories?q=topic:claude-code-settings&sort=stars)

### Inferences
- ECC and its sibling agentshield come from one maintainer with large self-referential scope, so treat their security/"instincts" claims as promotional until independently verified.

### Gaps
- Did not verify vendor ownership or sponsorship of any repo beyond names; no sponsorship disclosure review.

## 3. Conflicts with official docs (code.claude.com)

### Takeaway
Verified conflicts are concentrated in ChrisWiles/claude-code-showcase (deprecated key, non-official hook mechanisms). Trail of Bits' README overstates one limitation. Several suspected conflicts (colon wildcard syntax) turned out to be fine.

### Cited Findings
- showcase `settings.json` sets `"includeCoAuthoredBy": true`; the official settings reference marks it "Deprecated; use `attribution`" — [showcase settings](https://raw.githubusercontent.com/ChrisWiles/claude-code-showcase/main/.claude/settings.json); contradicted by [settings reference](https://code.claude.com/docs/en/settings-reference.md)
- showcase hooks read file path from `$CLAUDE_TOOL_INPUT_FILE_PATH`; the official hooks pages say command hooks receive JSON on stdin and a grep of the hooks and hooks-guide pages finds no `CLAUDE_TOOL_INPUT` variable — [showcase settings](https://raw.githubusercontent.com/ChrisWiles/claude-code-showcase/main/.claude/settings.json); contradicted by [hooks reference](https://code.claude.com/docs/en/hooks.md) and [hooks guide](https://code.claude.com/docs/en/hooks-guide.md)
- showcase README documents hook response format `{"block": true, "message": ..., "feedback": ...}`; official examples use `hookSpecificOutput.permissionDecision` ("deny") with `permissionDecisionReason`. Exit code 2 blocking (also used in showcase and Trail of Bits) is consistent with official behavior — [showcase README](https://raw.githubusercontent.com/ChrisWiles/claude-code-showcase/main/README.md); contradicted by [hooks guide](https://code.claude.com/docs/en/hooks-guide.md)
- showcase README line ~426 shows `"enableAllProjectMcpServers": true`. Not a syntax error, but officially the committed value is ignored in untrusted folders and approving all project MCP servers is a trust decision; Trail of Bits sets it false — [showcase README](https://raw.githubusercontent.com/ChrisWiles/claude-code-showcase/main/README.md); [MCP docs](https://code.claude.com/docs/en/mcp.md)
- Trail of Bits README says that without `/sandbox`, deny rules "only block Claude's built-in tools -- Bash commands bypass them." The official permissions page is more nuanced: Read/Edit deny rules also apply to recognized Bash file commands (`cat`, `head`, `tail`, `sed`, `tee`) and redirections, but not to commands that read files without naming them or to arbitrary subprocesses; OS-level enforcement needs the sandbox. So TOB is directionally right but overstated — [TOB README](https://raw.githubusercontent.com/trailofbits/claude-code-config/main/README.md); nuanced by [permissions docs](https://code.claude.com/docs/en/permissions.md)
- Trail of Bits settings use `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS` and `CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH`; these env names were not found in the fetched settings page (grep returned nothing in `settings.md`; the separate env-vars page was not checked), so unverified — [TOB settings](https://raw.githubusercontent.com/trailofbits/claude-code-config/main/settings.json)
- Not conflicts (checked): legacy `Bash(git:*)` / `Bash(npm:*)` syntax used by showcase is documented as equivalent to `Bash(git *)`; `.claude/commands/` is still shown in the official features list (commands and skills have been merged conceptually, but the path still works per official `.claude` directory page listing) — [permissions docs](https://code.claude.com/docs/en/permissions.md), [claude-directory](https://code.claude.com/docs/en/claude-directory.md)
- Pattern worth auditing for: official docs state `Bash(command:rm *)` style parameter-matching on a tool's primary field is ignored with a startup warning — [permissions docs](https://code.claude.com/docs/en/permissions.md). I did not find any repo using it.
- ECC README says Claude Code MCP toggles persist to `~/.claude.json`, and describes `beforeSubmitPrompt` (a Cursor-style event name, not a Claude Code hook event) — [ECC README](https://raw.githubusercontent.com/affaan-m/ECC/main/README.md). The `beforeSubmitPrompt` naming is Cursor-specific in my understanding; not verified against official docs here.

### Inferences
- A regression check for the audit tool: flag `includeCoAuthoredBy`, `$CLAUDE_TOOL_*` env use in hooks, and `{"block": true}` JSON as stale patterns copied from older community examples.

### Gaps
- Did not exhaustively diff each repo against official docs; only the repos and keys named above were checked. hooks-mastery, ultimate-guide, and ECC were only grep-scanned.
- Official env-var page not fetched for the two TOB env names.

## 4. Risky advice

### Takeaway
The riskiest mainstream advice is Trail of Bits running with `--dangerously-skip-permissions` as the default, though it is paired with sandboxing and deny rules. Other repos in the sample mostly steer away from it. Auto-approving project MCP servers appears in the showcase example.

### Cited Findings
- Trail of Bits README: defines `alias claude-yolo="claude --dangerously-skip-permissions"`, calls it "the recommended way to run Claude Code for maximum throughput", and states they run bypass-permissions mode; pairs with `/sandbox` and deny rules. Official docs: `bypassPermissions` should be used only in isolated environments such as containers/VMs and can be disabled via `permissions.disableBypassPermissionsMode` — [TOB README](https://raw.githubusercontent.com/trailofbits/claude-code-config/main/README.md); caution in [permissions docs](https://code.claude.com/docs/en/permissions.md)
- shanraisshan README tells readers to use `/permissions` wildcard rules and auto mode "instead of dangerously-skip-permissions" — the safer posture — [README](https://raw.githubusercontent.com/shanraisshan/claude-code-best-practice/main/README.md)
- showcase `enableAllProjectMcpServers: true` example: auto-approves all `.mcp.json` servers in a repo (see section 3) — [showcase README](https://raw.githubusercontent.com/ChrisWiles/claude-code-showcase/main/README.md)
- showcase hooks run `npm install` automatically whenever a `package.json` edit occurs and `npx prettier` / `npx tsc` per edit: execution of package-manager scripts triggered by model edits — [showcase settings](https://raw.githubusercontent.com/ChrisWiles/claude-code-showcase/main/.claude/settings.json)
- No grep hits for blanket `Bash(*)` allows, raw API keys, or secret-piping instructions in the README files scanned (howto, ultimate-guide, ECC, hooks-mastery, showcase, shanraisshan, TOB) — greps run 2026-11-12 on downloaded READMEs only; their linked example files were not scanned.
- Trail of Bits deny rules are a pattern-matching denylist (`Bash(rm -rf *)`, `Bash(sudo *)`, etc.); official docs say Bash patterns are bypassable by variants, and TOB itself adds hooks and the sandbox for that reason — [TOB settings](https://raw.githubusercontent.com/trailofbits/claude-code-config/main/settings.json), [permissions docs](https://code.claude.com/docs/en/permissions.md)

### Inferences
- A config auditor should treat "yolo alias" advice as acceptable only when a sandbox/container is verified, matching the official caveat, rather than flagging TOB's setup as simply wrong.
- Auto-install/auto-run hooks in example repos are a supply-chain surface worth flagging when copied.

### Gaps
- Did not scan sub-files (skills, agents, hook scripts) in ECC, wshobson/agents, VoltAgent, or the ultimate guide for risky patterns; bundles of this size very likely contain some.
- Star counts for some repos look anomalous (e.g. morluto/rea shows 455,013 stars in a security-topic search; obra/superpowers 316,720; ECC 301,940). I could not verify whether these are organic; do not rank by stars alone.
