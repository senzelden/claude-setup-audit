# Audit checklist

Use it as a prompt for where to look, not as a form to fill in. Skip checks that don't apply,
and don't report a check that passed unless it has been resolved since the last run. Check IDs
(`SEC-…`, `COST-…`, `LRN-…`, `HYG-…`) prefix the finding `id` in audit.json. Field names refer to
the collector snapshot.

## Security (`SEC-`)

- **SEC-risky-allow** (`permissions.risky` per settings file). Weigh by blast radius:
  - `wildcard-all`, `sudo`, `rm-recursive`
  - `network-wildcard` (`curl:*` enables exfiltration and download-and-run)
  - `interpreter-wildcard` (`python -c *` means arbitrary code)
  - `git-destructive` / `gh-api` (irreversible or outward-facing)
  - `docker` (root-equivalent on most hosts)

  Fix: remove or narrow the rule, and add `deny`/`ask` rules for the dangerous forms. When the
  same broad rule appears in many projects, propose one user-level rule instead.
- **SEC-deny-baseline**: there are no `deny` rules anywhere. Propose a small user-level baseline,
  verified against the permissions docs: reads of `.env` files, `~/.ssh`, `~/.aws`, credential
  files and `/proc/*/environ`, and force-push. Anchor paths with `//` or `~/` so they apply in
  every project; a single leading `/` anchors at the settings file's location.
- **SEC-secret-literal** (`secret-literal-in-rule`): a real token was baked into an allow rule
  when a command was approved. Confirm on the file (never copy the value), then rotate, delete the
  rule, and move the secret into env or a secrets manager.
- **SEC-secret-env** (`secret-via-env-file`): the rule pulls a key out of `.env` onto the command
  line, so it lands in transcripts. Lower severity. Fix: wrap the call in a script that reads env.
- **SEC-settings-in-git** (`projects[].git`): a `settings.local.json` that is `tracked`, or
  `untracked` rather than `ignored`, can leak approvals when pushed. `not-a-git-repo` isn't a finding.
- **SEC-auto-mode**: if `auto_mode_configured` is set, or sessions run unattended, raise the weight
  of risky allows and of a missing sandbox, because fewer actions reach a human.
- **SEC-sandbox**: no `sandbox` is configured despite autonomous or long sessions. Check platform
  prerequisites first (`/sandbox` lists missing dependencies).
- **SEC-hooks** (`hook_commands`): hooks run with the user's permissions. Flag hooks that fetch
  remote code, write outside the project, or match every tool with a slow command.
- **SEC-mcp**: unknown servers, servers with write access to external systems, and unpinned
  `@latest` packages.
- **SEC-install**: a failed auto-update (`global.last_update`), or a version far behind the changelog.
- **SEC-docs-only-constraint**: sensitive-data rules stated only in CLAUDE.md or auto-mode text and
  not enforced by `deny` rules.

## Cost & context (`COST-`)

- **COST-baseline** (`transcripts.context_baseline_tokens`, measured): real tokens loaded before
  the first answer. Compare the median across projects
  (`context_baseline_by_project_median`, ≥3 sessions each). A project well above the user's median
  points at its CLAUDE.md, rules, MCP servers or plugins. Report tokens × sessions per month.
- **COST-model-default** (`global.settings[].model`, `model_settings`, `usage.stats_lifetime_by_model`):
  a top-tier 1M-context model as the default for mostly mechanical work. Options: `opusplan`, a
  cheaper default with per-task switching, or `CLAUDE_CODE_SUBAGENT_MODEL` for subagents. Quote
  exact values from `model-config`.
- **COST-long-sessions** (`usage.heaviest_sessions`, `daily_token_totals_recent`): marathon sessions
  near the context ceiling re-send huge contexts on every turn. Suggest `autoCompactWindow` (a
  number), `/clear` plus handoffs between phases, or background runs.
- **COST-claude-md-size** (`claude_md_lines`, `claude_md_tokens`, estimated): over the docs' target
  (~200 lines). Fix by moving area-specific guidance into nested CLAUDE.md or path-scoped
  `.claude/rules/`, and procedures into skills. `@imports` still load at launch, so they don't save
  context. Apply only with the split protocol in SKILL.md.
- **COST-memory-index** (`memory.by_project[].index_lines`): only the first 200 lines / 25KB of
  MEMORY.md load, so a larger index silently drops entries.
- **COST-mcp-unused** (`transcripts.mcp_configured_but_unused`, measured): configured servers never
  called in the window. Propose removing or disabling them per project. A server used in only one
  project belongs in that project's `.mcp.json`, not user scope.
- **COST-skill-listing** (`skill_listing`): the listing budget is 1% of the context window
  (8,000-char fallback), and each entry is capped at 1,536 chars. When many skills overflow it,
  descriptions of rarely used skills get dropped. Fix with `skillOverrides: "name-only"`, trimmed
  descriptions, or disabling unused plugins.
- **COST-startup-hooks** (`plugin_session_start_hooks`, estimated): text injected on every
  start/clear/compact.
- **COST-subagents** (`usage.subagent_session_share`, Agent tool counts): many small agents
  re-reading context, or a top-tier model on mechanical agents.
- **COST-tool-errors** (`avg_tool_errors_per_session`, `tool_error_categories`): every failed call
  is a paid retry. Recurring categories point at missing commands in CLAUDE.md or a missing script.
- **COST-cache-health** (`transcripts.cache`, measured): Claude Code places cache points itself, so
  there's no `cache_control` to set. What the user controls is the cache lifetime (TTL) and the
  habits that break the cache.
  - `hit_ratio` (reads / (reads + writes)) above ~90% is healthy; say so and move on.
  - `write_1h_share`: Claude Code uses the 1-hour TTL for the main conversation only within a
    subscription's included usage. Usage credits, API keys, subagents and cloud providers get 5
    minutes. Writes cost 1.25× base input on the 5-minute TTL and 2× on the 1-hour TTL, while
    reads cost 0.1×.
  - `big_rewrites` by cause:
    - `gap_5_60m` large on credits or an API key: propose `promptCacheTtl: "1h"` (and
      `subagentPromptCacheTtl` if subagents idle that long). The 2× writes only pay off for
      pauses in the 5–60 minute range.
    - `gap_over_60m`: no TTL helps; suggest `/clear` plus a handoff instead of resuming huge contexts.
    - `after_model_change`: `/model` or fast-mode switches mid-session re-read everything; switch
      at task boundaries.
    - `after_compaction`: compaction rewrites the conversation cache by design. Weigh it against
      `autoCompactWindow`: a smaller window means cheaper turns but more rewrites, so compare with
      the previous audit's metrics.
    - `unexplained` large: suspect MCP servers connecting or disconnecting while tool search is off,
      or effort changes on older models (see the prompt-caching docs' invalidation list).

  Quote exact setting names and values from `settings-reference` / `prompt-caching`.

## Learning from repeated mistakes (`LRN-`)

Only patterns count: the same signal across 3+ sessions or 2+ projects. Pick the lightest
mechanism that will hold (memory < CLAUDE.md / path-scoped rule < hook < skill), and record the
metric that motivated it, so the next run can check whether it moved.

- **LRN-friction** (`usage.facet_friction`, `facet_friction_details`; needs `/insights`). Map each category:
  - `buggy_code` → test-first rule plus a PostToolUse hook running a fast, file-relevant test subset
  - `environment_issue` → preflight script or hook (ports, venvs), plus a "how to run" section
  - `tooling_failure` / `external_service_error` → checkpointing and progress files for long runs
  - `wrong_approach` / `misunderstood_request` → upfront question batch or plan mode for large tasks
- **LRN-corrections** (`corrections.samples`, `by_project`): cluster correction prompts by theme and
  quote 1–2 short samples. A theme across projects belongs in `~/.claude/CLAUDE.md` or `~/.claude/rules/`.
- **LRN-interruptions** (`usage.most_friction_sessions`): user interruptions mark where Claude went off
  track. Look at the task types involved.
- **LRN-duplicate-memory** (`memory.similar_across_projects` is a filename hint only; also read
  `entries[].description`): conventions re-learned per repo. Promote them to user scope and delete
  the duplicates, but keep memories that carry project-specific incidents or detail.
- **LRN-contradiction**: two active instruction surfaces that disagree (global vs project CLAUDE.md,
  CLAUDE.md vs a rule, prose vs `package.json`/CI). Executable manifests outrank prose. Propose one
  canonical statement. If conventions really differ per repo (e.g. commit trailers), make the
  global rule defer, or give enforcement hooks a per-repo opt-out.
- **LRN-enforce**: a rule that exists in CLAUDE.md but keeps being violated (it recurs in corrections
  or friction) should become a hook.
- **LRN-effectiveness** (previous `audit.json` `applied` + `metrics`): did the motivating metric
  improve? If not, escalate the mechanism. If it's solved and quiet, consider retiring the rule to
  save context.

## Hygiene (`HYG-`)

- **HYG-missing-hook-script** (`missing_hook_scripts`): a hook points at a file that doesn't exist.
  High severity for PreToolUse, because it can block every call.
- **HYG-dead-refs** (`claude_md_dead_refs`): CLAUDE.md names paths that don't exist. Before reporting,
  check whether the path is generated or gitignored (e.g. `data/`, `eval/results/`), since that isn't
  a dead reference.
- **HYG-one-off-rules** (`one_off_rules`, allow count > ~50): old exact-command approvals that hide
  the risky rules. Prune them with `prune_permissions.py --remove one-off`.
- **HYG-stale-dirs** (`missing_additional_dirs`): directories that no longer exist, or paths from
  another machine or user.
- **HYG-worktrees** (`is_worktree_copy`): many stale worktree copies of CLAUDE.md.
- **HYG-hook-duplicates**: the same event + matcher + command registered in several layers (user,
  project, plugin), which runs twice.

## Agent readiness (`RDY-`, opt-in via `focus=readiness`)

These are repo properties that decide whether Claude can set up, run, verify and understand a
project cheaply (`readiness[<repo>]`). Two rules keep this section from preaching:

- **Evidence first.** Report a gap when there's agent-side evidence (friction, `env_error_hits`, slow
  `test_run_seconds`, corrections), or when the fix is cheap and high-leverage. Everything else
  goes under Parked.
- **Match the repo.** Recommend tools from the repo's own stack and the user's existing conventions
  (lockfiles and configs show them): never Zod to a Python repo, never Husky to a uv/ruff
  project. Use `repo.commits` / `repo.first_commit` to calibrate: strictness advice is "turn it
  on now" for young repos and Parked, with a cost estimate, for mature ones.

- **RDY-first-run** (`setup_entrypoints`, `toolchain_pins`, `lockfiles`): no single setup command or
  no version pins, combined with `environment_issue` friction or repeated install failures. Fix: a
  `make setup` / `just setup` / `dev` script, plus pins in the repo's existing style.
- **RDY-env-undeclared** (`env.undeclared`): the code reads variables that no mechanism declares.
  Any mechanism counts: `.env.example`, a pointer-only `.envrc` (direnv + pass/1Password/sops),
  mise `[env]`, devcontainer, compose, pydantic settings. Propose a declaration in the mechanism the
  repo already uses; suggest `.env.example` only when there is none. Lead with `kind: required`
  (crashes when missing), then `read`. Mention `optional` (has a fallback) and `test-only` only as
  counts (`undeclared_counts`).
- **RDY-env-failfast** (`env.validation` empty, several required reads): suggest validation in the
  stack's idiom (pydantic-settings, zod/t3-env, envalid). Parked for small scripts.
- **RDY-envrc-literal-secret** (`envrc.literal_secret_names`, counted under security): a `.envrc`
  holds values rather than pointers. Worse if `envrc.git` is `tracked`. Report names only.
- **RDY-env-invisible-to-claude** (`envrc` present and `claude_env_hook` false, especially with
  `env_error_hits` > 0): direnv loads at an interactive prompt, which Claude's Bash tool never
  shows, so variables that work in the user's terminal are missing for Claude. Offer these
  options, stating the trade-off:
  1. *Non-secret* variables: a `SessionStart` + `CwdChanged` hook that writes `export` lines to
     `CLAUDE_ENV_FILE` (see the hooks docs), filtered to an allowlist of non-secret names.
  2. *Secrets*: `direnv exec . <cmd>` inside the specific Makefile or script targets that need them,
     so values exist only for that process and never sit in Claude's shell env or on disk.
     **Recommended default.**
  3. Export everything through the hook: zero friction, but every key is visible to every command
     Claude runs and can end up in transcripts.

  With the sandbox on, also check `sandbox.credentials` (`envVars` deny/mask; see "Protect
  credentials" / "Mask credentials" in the sandboxing docs) before proposing option 3.
- **RDY-env-secret-backend** (pointers resolve empty inside Claude's shell, e.g. the gpg or
  1Password agent is unreachable from the sandbox): check only with the user's OK. Probe variable
  names, never values, and tell the user rather than working around the sandbox.
- **RDY-format-guardrails** (`precommit`, `formatter_config`): a formatter is configured but not
  enforced. Evidence: edit rounds that only change formatting. Propose both a git pre-commit
  hook (humans) and a Claude PostToolUse format-on-edit hook (agent), in the repo's existing tool.
- **RDY-type-strictness** (`type_strictness`): strict mode off. Weigh by repo age, as above.
- **RDY-test-loop** (`test_run_seconds` median/p90, measured from transcripts; includes any
  permission-prompt wait): slow verification loops multiply cost. Suggest a fast subset target,
  or a file-relevant test hook. `ci.caching` matters only when CI is used.
- **RDY-test-data** (`tests.testcontainers`, `tests.seed_or_fixtures`): integration tests that need
  external services with no seeds or containers, together with flaky-failure evidence.
- **RDY-adr** (`adr`): no decision records while corrections show Claude re-deciding settled
  questions. Propose `docs/adr/` in the repo's existing style, and link it from CLAUDE.md.
- **RDY-boundaries** (`boundaries`): report only with evidence of cross-boundary edits or circular
  imports.
- **COST-app-caching** (`app_caching`, static signals; readiness track because it's app code):
  Anthropic SDK call sites with no `cache_control` (`uncached_files`), and possible cache breakers
  (`timestamp`, `random-id`, `unsorted-json`) in files that call the API. Before proposing:
  - Confirm the breaker feeds the prompt prefix (system prompt, tools, early messages) rather than
    being a log timestamp.
  - Caching only pays when the shared prefix clears the model's minimum (512 tokens on Opus 5,
    1,024 on Sonnet 5, 4,096 on Haiku 4.5, per `model_ids`) and repeats within the TTL. Two
    requests break even on the 5-minute TTL, three on the 1-hour TTL.
  - Proposal shape: top-level `cache_control={"type": "ephemeral"}` on the create call (automatic
    placement), move volatile content after the last breakpoint, verify with
    `usage.cache_read_input_tokens` > 0 on repeat requests.

  For a measured analysis of spend, point the user to `/claude-api cost-optimize` in that repo
  instead of estimating savings here.
- Out of scope unless the user asks: structured logging and feature flags (product architecture,
  with no agent-side signal).

## New features (`type: adopt`)

From What's new and the changelog: list only features that address observed evidence in this
snapshot, each with a one-line cost/benefit sentence. Park anything interesting but
not worth the effort now.
