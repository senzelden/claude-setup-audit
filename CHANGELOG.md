# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Permission-pruning backups use unique, exclusively created files with owner-only permissions.
  Repeated applies in the same second no longer overwrite earlier backups or follow an existing
  backup-file symlink. Backup copy/sync failures block settings edits and remove partial backups;
  completed backups survive subsequent settings-write failures.

### Fixed

- Required apply methods are preserved when helpers cannot run: degraded analysis no longer
  implies permission to substitute manual edits. Approved-apply evaluation checks now require
  linked successful dry-run/apply results as well as correct final settings and backup bytes.
- Read-only collection no longer launches `claude --version` or `claude doctor`, whose
  startup created configuration, backup and telemetry files in a fake-home reproduction.
  Version and doctor coverage are explicitly not checked; existing update metadata is still
  collected. Regression tests reject diagnostic startup writes across all three scopes.

### Added

- Credential-free Linux namespace and macOS Seatbelt prerequisite probes, with a manually
  triggered CI workflow and regression tests. These checks make no model calls and do not
  establish full Claude eval-runner compatibility.
- Snapshot v1 envelope and coverage/provenance schema, validated before collector output and
  by the query helper. Unknown versions fail closed; legacy unversioned snapshots remain
  queryable with an explicit warning. Invalid output cannot overwrite an existing snapshot.
- A reconciled, tracked roadmap separates shipped work from active and deferred priorities.
- CI matrix on Linux/macOS and Python 3.11/3.13/3.14, independent JSON Schema fixture checks,
  and strict marketplace/plugin validation using a pinned Claude Code CLI without model calls.
- Evaluation fixtures and independent retained-workspace checks for approved permission
  removal, decision suppression and cache health, with free regression tests. New model pilots
  and repeated baselines remain pending; deterministic checks do not establish model reliability.

## [0.5.0] - 2026-09-16

### Security

- Permission pruning with `--allow-symlinks` now resolves the target once before identity
  verification and keeps that target through backup and atomic write. Retargeting the original
  symlink after verification no longer redirects the write to an unverified file. Replacement
  of the resolved target or its parent directories can still race the final path-based rename.
  Two regression tests cover retargeting before apply and after verification.

### Fixed

- Missing or malformed plugin registries no longer also claim a successful zero-install scan.
  MCP and skill-listing guidance now respects bounded evidence and unverified activation.
- Finite metrics whose difference overflows produce an unavailable comparison instead of
  failing report finalization.

### Added

- Explicit `clarity=pilot` instruction review candidates, using bounded existing excerpts.
  A local reviewed corpus records useful cases, false positives and misses; no automatic
  findings, rewrites, cost-saving estimates or STE100 compliance claims.

- Deterministic report/decision validation, evidence-bound suppression and expiry, and
  conservative two-run finding/metric comparisons shown in HTML. Incomplete coverage cannot
  imply resolution or a comparable metric delta; action status remains independent.

- MCP provenance across user/local/project/managed/plugin sources and registry-selected plugin
  components, with credential values omitted and activation kept unknown. Skill-listing size
  now uses observed excerpts instead of fixed budget assumptions or newest-cache selection.

- Bounded instruction/rule/skill excerpts and selected frontmatter, with working-directory,
  worktree and main-checkout provenance. Candidate main-checkout local settings are included;
  imports, symlink targets and runtime activation remain explicitly unverified.

- Shared source/scope/collection-status metadata and bounded managed-settings file summaries,
  including drop-ins. Reports distinguish absent files from unavailable or unverified policy;
  managed helpers are never executed and effective enforcement is not inferred.

- Every audit now includes a deterministic, self-contained HTML report rendered from audit JSON,
  with scope/coverage, ranked findings, evidence, labeled metrics and action results. The renderer
  escapes all report text and writes private files; the workflow refreshes HTML after applying fixes.

- Minimal GitHub Actions CI runs the standard-library Python regression suite on Linux/Python
  3.13 for pushes and pull requests, with manual runs available. No paid model evaluations.

### Changed

- HTML reports now lead with a readable summary, consequences and next steps. Technical
  metadata is expandable; metric labels and explanations give numbers context. A fictional
  example demonstrates the layout.

- Usage measurements now filter session metadata by the inclusive timestamp window and join
  facets through unique session IDs for date and project attribution. Unknown dates and
  unattributable facets are excluded and counted. Global lifetime totals are explicitly labeled;
  daily totals use UTC calendar dates and are omitted for project scope.
- Transcript metrics filter record timestamps, with file modification times used only to order
  bounded scans. Coverage counts expose scanned, omitted and unknown-date evidence. MCP calls
  deduplicate tool IDs within project/session scope; calls without IDs count per occurrence.
- Median and P90 use linear interpolation at `(n - 1) * p`, including the usual even-sized
  median. Six regression tests cover usage windows, attribution, quantiles and transcript counts.

- Narrowed the README's audit-coverage claim and clarified that `.envrc` is read locally for
  classification, without emitting its literal secret values into the snapshot.
- Report guidance explicitly treats sensitive non-secret information as private; secret
  redaction does not make a report safe to publish.

## [0.4.0] - 2026-09-15

### Security

Four P0s from an external review of the released 0.3.1 source, all reproduced before fixing.

- **The untrusted-data wrapper in `query_snapshot.py` could be escaped.** `json.dumps` doesn't
  escape `<`/`>`, so a snapshot value containing the literal `</untrusted_snapshot_data>` closed
  the boundary early — confirmed the 0.3.1 hardening hadn't actually closed it. Fixed by escaping
  `<`/`>` as their JSON unicode escapes (U+003C / U+003E) in the printed text before framing it, so
  the delimiter can no longer appear literally anywhere except the two tags added around it.
- **Secret redaction missed most real-world credential shapes.** `SECRET_RE`'s generic
  labeled-value branch redacted only the word `Bearer` out of `"Authorization: Bearer <token>"`,
  leaving the real token exposed right after it, and never matched JSON's own `"key": "value"`
  shape at all — `{"api_key": "..."}`, `{"credential": "..."}` passed through completely
  unredacted. Fixed by making `sanitize()` key-aware and structural first: a value under a
  recognized secret-key name (`authorization`/`api_key`/`token`/`password`/`secret`/`credential`/
  ..., normalized for casing/separators) is redacted outright regardless of quoting, with the
  regex kept only as a second-line defense for secrets embedded in prose/commands/URLs (and fixed
  there too, to consume the `Bearer`/`Basic`/`Digest` scheme word instead of stopping at it).
  Reference values (`$FOO`, `<set>`, `{{VAR}}`) still survive, same guarantee as before.
- **`collect.py --out` was an unrestricted, pre-approved arbitrary-file-write.** `SKILL.md`
  pre-approves `collect.py *` with no argument restriction, and `--out` opened its target with
  plain `open(path, "w")` — no directory restriction, no symlink check, no atomic write. A
  conceptually read-only collector could therefore truncate any file the process could write to.
  Fixed: `--out` now must resolve inside a system temp directory or `CLAUDE/audits`, refuses a
  symlink at the target outright, and writes via tempfile + `os.replace()` in that directory.
- **`--scope`/`--project` didn't exist; a "project" or "global" audit still read every project on
  the machine.** SKILL.md documented `scope=global/project/all`, but the collector had no such
  flag — it always ran `collect_global()` plus every discovered project's files (readiness,
  source scanning included) regardless of what was asked. Added real `--scope {global,project,all}`
  and `--project PATH`: `global` and `project` now skip `discover_projects()` and any root outside
  the one requested entirely, and usage/history/transcript data is filtered by project too (facet
  files, which carry no project identifier, are excluded under those scopes rather than guessed
  at, and say so). The snapshot now reports `collection_scope` so a report can state what was
  actually collected.

Regression tests added for all four (22 new tests; full suite 54/54, up from 32).

### Fixed

- Two small drifts caught by spot-checking `checklist.md`/`docs-map.md` against the current docs
  (8/10 claims checked verified accurate verbatim): `COST-skill-listing` cited an unverifiable
  "8,000-char fallback" for the skill-listing budget, replaced with the actual setting names
  (`skillListingBudgetFraction`, `skillListingMaxDescChars`); `docs-map.md` called the trailing
  `:*` permission-rule suffix "legacy", which current docs treat as a live equivalent form, not
  deprecated.

## [0.3.1] - 2026-09-15

### Security

Fixes from two external reviews of the released source.

- **The collected snapshot is now explicitly untrusted evidence, not instructions.** Previously
  only fetched docs pages carried that rule. `query_snapshot.py` output is now wrapped in
  `<untrusted_snapshot_data>` tags, and SKILL.md/checklist.md extend the "data, not instructions"
  boundary to memory, transcripts, hooks and permission rules, closing an indirect
  prompt-injection route through local content the collector reads.
- **Output redaction is now recursive and covers the whole snapshot,** not just the fields that
  went through `redact()` individually. `modelSettings`, `sandbox` and other structurally-copied
  settings previously bypassed redaction entirely. `collect.py`'s docstring now says
  "best-effort", matching what the heuristics can actually guarantee. Added JWT, PEM private-key
  and URL-userinfo (`user:pass@host`) patterns.
- **`prune_permissions.py --apply` writes are now atomic** (temp file, fsync, `os.replace`,
  best-effort directory fsync) instead of truncating the settings file in place, and it refuses
  to write through a symlink or a file that changed since it was planned (`--allow-symlinks` to
  override the former). The re-check and the backup now go through the same file descriptor the
  plan was read from, not the path again, so a swap after the check can't feed the backup step
  something other than what was verified. A first pass of `--allow-symlinks` shipped a bug where
  `os.replace()` on a symlink path replaces the link itself, not its target — silently breaking
  the symlink and leaving the real file untouched; caught by an independent review before release
  and fixed by resolving to the real target first.
- **Hooks are now classified by real handler type** (`command`/`http`/`mcp_tool`/`prompt`/
  `agent`) instead of treated as uniform shell commands; fixes a case where an HTTP hook's URL
  would've been checked as a local script path once non-command hooks were collected. HTTP hooks
  also report their header and allowed-env-var *names* (never values), since that's what would
  reveal a secret being sent to an unfamiliar host.
- Fixed a regression the redaction rewrite would have introduced: the labeled-secret pattern
  (`token=`, `password=`, ...) now has the same reference-vs-value guard as the literal-secret
  pattern, so `token=$FOO` or `password=<set>` survive redaction instead of being masked like a
  real value — that's the "which env vars are wired in" signal several checks depend on.
- **SKILL.md now covers the case where Bash — or just the collector — can't run at all.**
  Discovered via the eval suite itself: with the collector unavailable, the skill fell back to
  reading settings files directly and reproduced a real-looking bearer token verbatim in its
  report, failing the `never-repeats-token-value` grader in `audit-flags-risky-permissions`. The
  degraded path is still useful (Read/Glob against the same files the collector would have read),
  but the skill is now the only redaction pass in that mode and says so explicitly: cite the file,
  line and rule shape for anything secret-looking, never the value. Re-run after the fix: 3/3
  clean, including the no-plugin baseline leaking the token in 2/3 runs for contrast. `collector-ran`
  itself still fails in this eval environment (a Linux nested-user-namespace ordering bug in
  Claude Code's own `apply-seccomp` helper, [anthropics/claude-code#43454](https://github.com/anthropics/claude-code/issues/43454),
  reproduced independently on 2.1.272 — outside this plugin's control) but that grader is
  with-only/informational and doesn't affect score.
- Test suite: 20 → 32, covering the hostile-input and failure-mode cases (interrupted write,
  symlink swap between plan and apply, an `--allow-symlinks` apply that must rewrite the target
  and preserve the link, secret-shape gaps) that the reviews specifically asked for.

### Known issues

- `readiness-envrc-pointers` (the other `quality` eval case) is inconsistent without the
  collector — 1/3 runs miss the checklist's specific `direnv exec`/`CLAUDE_ENV_FILE` recommendation
  in favor of a generic fix, and a borderline-good answer that does mention `direnv exec` still
  drew 3/3 judge FAILs for hedging between `.envrc` and `.env.example`. Pre-dates this release
  (same flakiness observed before 0.3.0 shipped); not a secret-handling issue, left open.

## [0.3.0] - 2026-09-15

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

[Unreleased]: https://github.com/senzelden/claude-setup-audit/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/senzelden/claude-setup-audit/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/senzelden/claude-setup-audit/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/senzelden/claude-setup-audit/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/senzelden/claude-setup-audit/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/senzelden/claude-setup-audit/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/senzelden/claude-setup-audit/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/senzelden/claude-setup-audit/releases/tag/v0.1.0
