# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A `claude plugin eval` suite (`plugins/setup-audit/evals/`), so trigger accuracy and output
  quality are measured, not assumed.**
  - Six `trigger` cases: three natural requests that should fire the skill (usage limits,
    config security, recurring mistakes) and three near misses that shouldn't (a code security
    review, writing a CLAUDE.md, an API prompt-caching how-to). First pass: 6/6 at one run each,
    about $0.46.
  - Two `quality` cases that build a fake Claude Code config with a scaffold script:
    - a read-only security audit that must flag a curl wildcard, a fake bearer token baked into a
      rule and the missing deny baseline, must never repeat the token, and must never edit config
    - a readiness audit that must treat a `pass`-pointer `.envrc` as the declaration, flag an
      undeclared `DATABASE_URL`, and offer `direnv exec`

  `evals/README.md` gives the cheap way to run each tier.
- **`--claude-dir` and `CLAUDE_CONFIG_DIR` support in the collector.** Users who relocate Claude
  Code's config directory were previously audited against an empty `~/.claude`.

### Changed

- **The skill's own workflow is now followed on small requests.** The first quality runs showed two
  gaps:
  - "Is my repo ready for Claude Code to work in?" didn't trigger the skill at all, because the
    description never mentioned readiness.
  - Once triggered, the skill explored the repo by hand instead of running the collector and
    reading the checklist.

  The description now covers readiness, and a short "do these first, in order" block at the top
  of SKILL.md requires the collector and the checklist before any analysis.
- **Measured result of the quality tier after these fixes (one run each, Sonnet 5):**
  - `audit-flags-risky-permissions`: 1.00 with the plugin vs 0.63 without. Without it, Claude
    repeated the fake token and skipped deny rules.
  - `readiness-envrc-pointers`: 1.00 vs 0.50. Without it, Claude missed that `.envrc` variables
    don't reach Claude's shell.

  Mean Δ +0.44, about $0.91 per run of the tier.

### Fixed

- **The collector is no longer denied in non-interactive sessions.** The skill ran it as
  `CLAUDE_CONFIG_DIR=… python3 …`, and the environment prefix stops a command matching allowlists
  such as `Bash(python3 *)`. SKILL.md now says to pass `--claude-dir` and never to prefix the command.
- **Eval graders now measure what they claim:**
  - `collector-ran` requires the collector's success line in the transcript, not just an attempt
    (a denied call used to pass).
  - `no-settings-writes` matches the Write target path only, not report text that mentions
    `settings.json`.
  - The readiness judge rubric no longer fails a reply that mentions `.env.example` as a secondary
    alternative.
- **`Bash(python3 -c *)` is now flagged as an interpreter wildcard.** Only the quoted form
  `python3 -c ' *` was caught, so the unquoted form, which grants the same arbitrary-code access,
  passed silently. The eval fixture exposed it. `node -e *` is covered too.

## [0.2.0] - 2026-09-15

### Added

- **Prompt-cache health (`COST-cache-health`), measured from your transcripts.** Claude Code
  places cache breakpoints itself, so there is no `cache_control` for a user to set. The check
  covers what users *do* control: the cache lifetime, and habits that break the cache. It reports:
  - the hit ratio
  - the share of cache writes on the 1-hour vs the 5-minute TTL
  - large mid-session cache rewrites, classified by cause: idle 5–60 minutes, idle over an hour,
    model switch, compaction (from `compact_boundary` records), unexplained

  `promptCacheTtl: "1h"` is proposed only when the gap pattern and billing make its 2× write
  price pay off. Usage is counted once per message id, because one API response can be written as
  several transcript lines, and counting lines roughly doubled the write total on real data.
  On the author's machine over 30 days: a 97.9% hit ratio and 70 large rewrites, of which only 17
  fall in the 5–60 minute window a longer TTL could save.

- **Prompt caching in your own API code (`COST-app-caching`, readiness track).** It lists
  Anthropic SDK call sites without `cache_control`, possible cache breakers in files that call
  the API (timestamps, random IDs, `json.dumps` without `sort_keys`), and the model IDs in use,
  since each model has its own minimum cacheable prefix (512 tokens on Opus 5, 4,096 on Haiku
  4.5). These are static signals and are reported as leads to confirm, not as proven waste. A
  measured spend analysis is handed off to `/claude-api cost-optimize`.

## [0.1.1] - 2026-09-15

### Changed

- **The README now documents the agent-readiness track that 0.1.0 already shipped:** first run,
  the env contract (including direnv/`.envrc` pointer setups and whether those variables reach
  Claude's shell), guardrails, measured test-loop time, and context. The plugin description and
  keywords mention it too.

## [0.1.0] - 2026-09-15

First release.

### Added

- **The `setup-audit` skill.** Run profile options: `focus` (weights for security, cost, learning,
  readiness), `depth` (`quick` or `full`), `scope`, `mode` (`audit`, `propose`, `apply`) and
  `report_dir`.
  - Findings cite a file or a measured number, and have stable ids.
  - Reports are written as Markdown plus `audit.json`, so the next run can compare against this one.
  - `decisions.yaml` suppresses deliberate choices until their `review_after` date.
  - Approved fixes are applied one at a time, with a before/after shown and a backup made first.

- **A deterministic collector,** so the model's tokens go into analysis rather than file
  discovery. It finds projects from Claude Code's own records (transcript `cwd`), not from an
  assumed folder layout, and it redacts secret-looking values. It covers:
  - the context baseline, measured from the input and cache tokens of each session's first turn
  - MCP servers configured but never called
  - skill-listing size against the documented caps
  - hooks pointing at missing scripts
  - dead paths in CLAUDE.md files
  - duplicated memories across projects
  - risky permission rules, which separate secrets baked into a rule from rules that only pull a
    key out of `.env`

- **Agent readiness (opt-in).** Checks whether Claude can set up, run, verify and understand a repo:
  - **The env contract.** Compares the variables code reads against the variables declared by any
    mechanism (`.env.example`, direnv `.envrc` including `pass` pointers, mise, devcontainer,
    compose, pydantic settings). Undeclared ones are graded `required` / `read` / `optional` /
    `test-only`.
  - **Whether `.envrc` variables reach Claude's non-interactive shell.** They didn't on the
    author's machine.
  - Setup entry points, toolchain pins, guardrails, type strictness, ADRs, and test-run time
    measured from transcripts.

- **Bundled scripts:**
  - `prune_permissions.py`: preview by default, backups on `--apply`, skips unreadable files
  - `split_coverage.py`: measures how much of a CLAUDE.md survived a split
  - `query_snapshot.py`: read-only snapshot queries

### Fixed

Found in the first end-to-end run, before this release was tagged:

- **Reports can no longer be lost when Claude Code refuses to write under `~/.claude`.** A
  `report_dir` option was added, with a stated fallback to a temporary folder.
- **The audit no longer needs arbitrary-code permission.** Ad-hoc `python3 -c` snapshot reads are
  replaced by the pre-allowed, read-only `query_snapshot.py`.

[Unreleased]: https://github.com/senzelden/claude-setup-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/senzelden/claude-setup-audit/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/senzelden/claude-setup-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/senzelden/claude-setup-audit/releases/tag/v0.1.0
