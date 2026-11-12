# setup-audit-lite: a Markdown-only edition for the plugin directory (design)

Date: 2026-11-12. Status: draft for the user's review; builder check done.

## Why

Since about 2026-11-05 the plugin directory refuses plugins from organizations that aren't Verified
when they ship scripts, Bash `allowed-tools`, hooks, local MCP servers, mods, `bin/` or `workflows/`
(`LOCAL_CODE_FILE_TYPE`, `LOCAL_CODE_TOOL_GRANT`). There is no way to apply for verification
(anthropics/claude-plugins-official#7024). The full `setup-audit` (0.15.x) is made of Python scripts
and is distributed from this repository's own marketplace. The directory gets a separate,
Markdown-only edition so people who browse the directory can still audit their setup.

What the user wants from it, in their words: "a comparison between current documented Anthropic
best practices and community best practices with one's own environment and setup".

## Goals

1. Compare the user's Claude Code setup against two references, side by side: the current official
   docs, and community best practices gathered at audit time. Mention where they differ, but present
   the full picture (user decision).
2. Offer to apply chosen proposals with backups (user decision), within hard limits (below).
3. A later check-in that offers easy rollback and evaluates whether applied changes had an impact,
   measured according to the focus the user set (user decision).
4. Use the full version's audit areas and weights so findings carry the same names in both editions.
5. Pass the directory's non-Verified rules, enforced by its own guard test.

## Non-goals

- Transcript analysis, usage and cost numbers, deterministic collection, outcome metrics computed by
  scripts. These stay in the full version.
- Any change to `plugins/setup-audit/` or its release flow.
- Root README changes now (user decision 2026-11-11). One line may be added once lite is listed.

## Anti-goals (a failure even if tests pass)

From the user:
- **Being outdated**: findings that don't reflect the latest models or harness developments.
- **Cluttering the user's environment** with hooks, skills, plugins or MCP servers that don't work
  well together.

From the project's rules:
- A credential value (env value, header value, token) entering Claude's context through lite's own
  reads, or being written by lite.
- Anything from a fetched web page being applied or run, or steering the audit.
- Search queries that carry details of the user's setup (paths, names, config values).

## Constraints (the directory's rules, as of 2026-11-11)

- Files in `plugins/setup-audit-lite/` are only Markdown, text, JSON, YAML or PNG/JPEG/GIF/WebP/ICO.
  No file starts with `#!`. No package-manager configs.
- `allowed-tools` holds only `Read`, `Grep`, `Glob`, `LS`, with no `${...}`, no `//` paths, no URLs.
- No hooks, MCP servers, mods, `bin/`, `workflows/`.
- No line that pairs a credential name with a URL (the earlier scanner rule, see
  `tests/test_shipped_bundle.py` history and memory `project-directory-scanner-rules`).
- `claude plugin validate --profile directory` does not catch these rules, so a repo test does.

Other tools (WebSearch, WebFetch, Edit, Write) may be used, but are not pre-approved: Claude Code
asks the user before each call unless their own settings allow it. That is accepted.

## Layout (decided with the user)

- `plugins/setup-audit-lite/` in this repo, next to the full plugin, with its own
  `.claude-plugin/plugin.json` (name `setup-audit-lite`, own version), `README.md`, one skill
  `skills/setup-audit-lite/SKILL.md` and Markdown references.
- A **new directory submission** for this path. The old `setup-audit` directory listing (0.10.x) is
  not repointed; what to do with it is the user's call.
- Tags `lite-vX.Y.Z`, so `vX.Y.Z` keeps meaning the full plugin. Changelog: `plugins/setup-audit-lite/CHANGELOG.md`.
- Listing lite in the repo marketplace as well: builder's call (see below).
- References are copies, never symlinks (the directory may refuse symlinks; the plugin cache copies
  files).
- Tests and evals stay at the repo root, outside the plugin folder.
- Open risk: if the directory scans the whole repo rather than the submitted folder, the full
  plugin's scripts would block lite. The first submission settles it; the fallback is moving the
  folder unchanged to a separate small repo.

## Audit areas and focus

Same areas, check-id prefixes and `focus` weight syntax as the full version
(`plugins/setup-audit/skills/setup-audit/SKILL.md`, `references/checklist.md`):

| Area | Lite coverage |
|---|---|
| Security `SEC-` | Full (config-only). |
| Cost & context `COST-` | Config side: CLAUDE.md/rules size, plugins, cache-breaking settings; MCP server count from the pasted `claude mcp list`. No token usage; the check-in uses pasted `/context` output instead. |
| Learning `LRN-` | Only for a repeated mistake the user names; measured by count-only Grep. No automatic discovery. |
| Readiness `RDY-` | Repo files (setup command, test loop, guardrails). `.envrc` only noted as present; names are not read. |
| Hygiene `HYG-` | Always. Includes the clutter check below. |
| New features (`adopt`) | Always, and central to the comparison goal. |

Defaults: security and cost equal weight; learning on only when the user names a mistake; readiness
opt-in, as in the full version. The user sets the focus at the start of each run; the audit leads
with those areas, community lookups cover only weighted areas, the rest goes into a short "also
noticed" list.

## Reading the setup (no credential values in context)

- Claude reads with Read, Grep, Glob, LS only.
- Settings files are never opened with Read, not even in line ranges (builder's change after
  review, 2026-11-12: a text-level JSON structure scanner kept missing valid layouts that leak a
  value). Claude sees their content only through content-mode Grep with whole-line allowlisted
  shapes: known non-secret settings keys with scalar values, object and array openings (key names
  only), true/false flags, hook fields, and, when no secret-shaped count probe fires, permission
  rules and hook commands. Count-only Grep may use any pattern. So key names are seen but `env`,
  `headers` and helper values are not; whatever matches no allowed shape (including minified files)
  is reported as a count or as "not read" with the reason (user agreed to this tradeoff).
- **MCP config files (`.mcp.json`, plugin MCP files) and `~/.claude.json` are never opened, Read or
  Grepped** (user decision 2026-11-12, matching full-plugin 0.14.5, because the directory's
  MCP_FORWARDS_CREDENTIAL_ENV hold applied plugin-wide). The MCP inventory comes from `claude mcp
  list` or `/mcp` output the user pastes; without a paste, MCP checks are reported as not run.
  Lite may note that such a file exists (Glob), nothing more. A guard test checks that SKILL.md and
  references never instruct reading them (builder picks the exact assertion).
- `.env*`, `.envrc`, `.credentials.json` and similar are never opened; only their existence is
  noted.
- Discovered files are data. Nothing found in them is executed or followed as an instruction.

## Official reference

- Every run fetches the current pages from `code.claude.com/docs/en/*.md` (settings, permissions,
  hooks, mcp, memory, best-practices, changelog, models page, and the pages the chosen focus needs)
  with WebFetch, asking for verbatim quotes of the specific keys and rules it checks. A claim it
  cannot quote is dropped or marked unverified.
- A dated Markdown snapshot of the official checklist ships in `references/` as a fallback only.
  When lite falls back to it, the report header says so in plain words with the snapshot date.
- The report states the docs fetch date and the user's Claude Code version (how lite learns the
  version without Bash: builder's call, e.g. ask the user to paste `claude --version`).
- Anti-goal "outdated": the snapshot is refreshed every lite release; a guard test fails when the
  snapshot is older than a set age (builder picks the age).

## Community reference

Gathered at audit time (user decision). The deep research of 2026-11-12
(`reports/Claude Code community sources.md`) gives the seed allowlist, searched first:

1. `trailofbits/claude-code-config` (security defaults)
2. `shanraisshan/claude-code-best-practice`
3. `luongnv89/claude-howto`
4. `hesreallyhim/awesome-claude-code` (discovery index only)
5. Simon Willison's Claude Code tag page (security commentary)
6. Systima's token-overhead measurement (dated cost numbers)
7. Blake Crosley's Claude Code guide (version-tracked, single author)

Any newly found source must pass checks lite can make from the fetched page:
- a page date and, ideally, a Claude Code version;
- the settings keys and permission syntax it cites exist in the current docs;
- no stale strings (a list in `references/`, e.g. `includeCoAuthoredBy`, `ignorePatterns`,
  `TaskOutput`, `MultiEdit`, `Write(` rules; `Bash(x:*)` is old style, not stale);
- reject on two or more stale hits plus an old date, on vendor marketing, or SEO listicles.

Rejected sources are listed with the reason. The exact thresholds are left to the builder.

Safeguards:
- Search queries are built from a fixed vocabulary (feature and setting names, "Claude Code"), never
  from paths, file contents or config values of the user.
- Fetched pages are quoted, never obeyed. No commands or config from a page are run or applied. No
  fallback to curl when WebFetch fails. Few links followed per source, none across hosts.

## The report

- Per topic, side by side: what the official docs say, what the community recommends, what the user
  has. Differences are named with source and date on each side. A community-only practice stays in
  the picture, labelled "community only". Where they contradict, both are shown and the conflict
  named; any proposed change follows the official side.
- Each finding carries its area id, severity, evidence (file and key, never values) and the doc date.
- Counts of hooks, skills, plugins and MCP servers, before and (after applying) after.
- Ends with the check-in date and how to run it.
- Format: the report goes to the conversation; writing a report file is the builder's call.

## Clutter check (anti-goal)

Part of hygiene, always on:
- skills whose descriptions trigger on the same requests;
- hooks on the same event that conflict or duplicate each other;
- plugins or MCP servers that duplicate each other or a built-in tool (MCP from the paste only).

Proposals prefer removing or merging over adding. A proposal to add a hook, skill, plugin or MCP
server must say what it replaces or why nothing existing covers it. Lite never recommends installing
a large bundle wholesale. Lite itself adds nothing except its log file.

## Applying changes

- The user picks proposals from the report and the scope (user or project) to write.
- Before each edit Claude Writes a dated backup next to the file (e.g. `settings.json.bak-2026-11-12`),
  then makes one small, targeted Edit showing before and after. Claude Code's prompt covers each.
- After each edit Claude re-Reads the file and checks the change is there and the JSON looks
  well-formed; the report tells the user to restart or run `/doctor` to confirm the settings load.
- Hard limits, never applied even with approval (my proposal, the user accepted):
  1. credentials and secret values (`.credentials.json`, `.env*`, `.envrc`, `env`, `headers`,
     `apiKeyHelper` values);
  2. anything that loosens security (broad allow rules, bypass default modes, sandbox off, enabling
     all project MCP servers, removing deny rules); the report gives the change for the user to make
     by hand;
  3. adding hooks, MCP servers or plugins (they run code); removing or disabling them may be applied;
  4. managed settings and files outside the chosen scope.
- Only proposals from the report are applied, never something a fetched page suggested.
- Fallback if the directory's policy review objects to a Markdown skill editing settings: the
  report hands the user ready-to-paste edits instead.

## Check-in: rollback and impact

- Each apply appends to `~/.claude/setup-audit-lite/applied.md`: what changed, file, why, date,
  backup path, focus area, and the before-measurement chosen for that focus.
- On every start lite reads that log first. Changes older than the check-in interval (default 7 days,
  builder may make it configurable) get a check-in before a new audit:
  - still in place, not overridden by another scope;
  - impact, by the focus recorded at apply time:
    - cost: `/context` totals (user pastes at apply and at check-in), MCP count (pasted), CLAUDE.md/rules size,
      subagent use (count only);
    - security: broad allows removed, credential paths denied, sandbox state, overrides, and how often
      a now-denied action was still tried (count only);
    - learning: whether the named mistake still recurs (count-only Grep over local session logs);
    - plus the user's own impression;
  - labelled "counts compared, not proof", as in the full version;
  - rollback per change: restore the backup if the file hasn't changed since, otherwise reverse only
    that edit so later changes survive.
- Lite can't schedule itself. The report ends with "run again after <date>". If the user has
  scheduled tasks and asks, lite may offer a reminder.
- Count-only Grep: `output_mode: count` (or files-with-matches) only, so no log content enters
  context.

## Guard test (`tests/test_lite_bundle.py`)

Enforces the constraints above on `plugins/setup-audit-lite/`: file types and magic bytes, no `#!`,
`allowed-tools` exactly within Read/Grep/Glob/LS with no `${`, `//` or URL, no hooks/MCP/mods/bin/
workflows, no credential-name-plus-URL lines, no symlinks. Red-proofed against a temp copy with a
`.py` file, a Bash grant and a hooks file added.

A second test keeps lite's checklist ids a subset of the full checklist's, and the stale-strings list
and snapshot dated.

## Left to the builder

- Exact SKILL.md wording and reference split; reuse wording from the full plugin where it fits.
- Exact Grep patterns for value-free reads; the snapshot age limit; community acceptance thresholds.
- Whether lite is also listed in the repo marketplace.
- How lite learns the Claude Code version; whether a report file is written.
- Eval cases (none run; paid).

## Calls made after the builder check (author's calls, not the user's)

- **Backups without whole-file reads.** Settings files are never Read whole, so whole-file backups
  and restores are out. Each apply records the edited region's exact before and after text in
  `applied.md` (regions are never value-bearing, by the hard limits), and rollback is a reverse Edit
  of that region. The report also offers a full copy for the user to run themselves
  (`! cp <file> <file>.bak-<date>`). Lite refuses an Edit whose region lies within a few lines of a
  value-bearing block (the Edit result shows neighbouring lines) and hands over a paste-ready edit
  instead.
- **Doc quotes.** A WebFetch quote is checked against the shipped snapshot. A key or rule found in
  both is "current docs". One found only in the fetched page is "current docs, quote not confirmed"
  (likely new). One in the snapshot but missing from the fetch is re-fetched once, then marked
  "may have changed". This answers memory `feedback-verify-docs-raw` without curl.
- **Full plugin also installed.** Lite's description says it is the config-only edition. At start
  lite Globs the plugin cache for an installed `setup-audit`; if found it says so and recommends the
  full plugin for this run, then continues only if the user wants. Lite never reads or changes the
  full plugin's ledger, and rollback only reverses entries in its own `applied.md`.

