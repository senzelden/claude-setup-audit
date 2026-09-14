# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
