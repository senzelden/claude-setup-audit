# setup-audit-lite 0.1.0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Markdown-only plugin `plugins/setup-audit-lite/` that compares a user's Claude Code setup
with current official docs and vetted community practice, applies chosen fixes with region backups,
and checks in later with rollback and focus-based impact, while passing the directory's
non-Verified rules.

**Architecture:** One skill (`SKILL.md`) that runs the workflow, plus Markdown references that hold
the rules Claude follows (reading without values, sources, checklist, report, apply log). Python
tests at the repo root enforce the directory rules and the cross-edition invariants; the plugin
itself contains no code.

**Tech Stack:** Markdown, JSON; Python 3 stdlib `unittest` for repo tests; `claude plugin validate --strict`.

**Spec:** `docs/superpowers/specs/2026-11-12-setup-audit-lite-design.md` (approved 2026-11-12).

## Global Constraints

- Files under `plugins/setup-audit-lite/`: only `.md`, `.txt`, `.json`, `.yaml`/`.yml`, `.png`, `.jpg`/`.jpeg`, `.gif`, `.webp`, `.ico`. No file starts with `#!`. No package-manager configs (`package.json`, `pyproject.toml`, `requirements*.txt`, lockfiles). No symlinks.
- `allowed-tools`: only `Read`, `Grep`, `Glob`, `LS`; no `${`, no `//`, no `://`.
- No `hooks/`, `bin/`, `workflows/`, `.mcp.json`, `mcpServers`, `hooks` or mods keys in the plugin.
- No single shipped file names a credential source (`.claude.json`, `.envrc`, `.credentials.json`, `direnv`, an UPPERCASE name containing `TOKEN`/`SECRET`/`PASSWORD`/`API_KEY` or ending `_KEY`) and also contains `http://` or `https://` (memory `directory-scanner-rules`). URLs live only in files that name no credential source.
- No shipped file refers to an image or font path; the listing icon, if any, sits at `.claude-plugin/icon.png` with no `icon` field.
- MCP config files and `~/.claude.json` are never opened, Read or Grepped; the MCP inventory comes from pasted `claude mcp list` / `/mcp` output.
- Settings files are never Read whole; `.env*`, `.envrc`, `.credentials.json` are never opened.
- Nothing from a fetched page is applied or run; no curl fallback; search queries use a fixed vocabulary only.
- Check-id prefixes `SEC-`, `COST-`, `LRN-`, `RDY-`, `HYG-` and `focus` syntax as in the full plugin; lite ids are a subset of the full checklist's ids, except ids under a "lite-only" heading.
- Lite version `0.1.0`; tag `lite-v0.1.0` is made by the user, not by the build. Changelog `plugins/setup-audit-lite/CHANGELOG.md`.
- `plugins/setup-audit/` is not modified. Root README is not modified.
- Session rules: no `rm -rf`, no deleting temp dirs, no sleep/pgrep polling loops, no push, tag or release. Stage explicit paths; commit trailer `Assisted-by: Claude:claude-opus-5-5`. Leave AGENTS.md, CODEX-SETUP.md and the untracked root placeholders alone.
- Gate: `python3 -m unittest discover -s tests` from the repo root, plus `claude plugin validate --strict` on `plugins/setup-audit-lite` and on the marketplace, both on a clean export (`git archive HEAD | tar -x -C "$TMPDIR/..."`).

## Review Focus

1. **Inline or minified settings JSON** (`"env": {"A": "x"}` on one line, or the whole file on one line): a line-number Grep would return the value. Expected: reading rules detect it with a count-only Grep and report the file "not read". Pinned in Task 2 (`reading-rules.md` assertions).
2. **A pasted `claude mcp list` carrying a token in a URL or argument.** Expected: SKILL.md tells the user to redact before pasting, and the report never repeats URLs, args or values from the paste, only server names and transport. Pinned in Task 3.
3. **Rollback after the user edited the file again** (the recorded before/after text no longer matches). Expected: no forced write; lite reports the mismatch and hands over the manual reversal. Pinned in Task 3 (`applied-log.md` assertions).
4. **Offline, WebFetch denied, or search denied.** Expected: the snapshot fallback with the plain-words header and its date; community section says "not gathered" rather than inventing sources. Pinned in Task 3.
5. **A shipped file that pairs a credential-source word with a URL** (easy to introduce while writing prose). Expected: the guard test fails. Pinned in Task 1 with a red-proof.

---

### Task 1: Plugin skeleton and directory guard tests

**Files:**
- Create: `plugins/setup-audit-lite/.claude-plugin/plugin.json`
- Create: `plugins/setup-audit-lite/README.md` (short; install, what it reads, link to the full plugin's marketplace install line). It contains URLs, so it names no credential source: "what it never reads" is phrased by category ("credential files, env files, MCP config") and the exact file list lives in `reading-rules.md`.
- Create: `plugins/setup-audit-lite/CHANGELOG.md` (`## [0.1.0] - Unreleased`)
- Create: `plugins/setup-audit-lite/skills/setup-audit-lite/SKILL.md` (frontmatter and a one-line placeholder body; Task 3 writes the body)
- Modify: `.claude-plugin/marketplace.json` (add the lite entry, `source: ./plugins/setup-audit-lite`)
- Test: `tests/test_lite_bundle.py`

**Interfaces:**
- Produces: `LITE = ROOT / 'plugins/setup-audit-lite'`; helper `bundle_problems(root: Path) -> list[str]` in `tests/test_lite_bundle.py` returning one message per violated constraint; Tasks 2–3 add assertions to this file.
- `plugin.json`: `name` `setup-audit-lite`, `displayName` `Setup Audit Lite`, `version` `0.1.0`, same author/homepage/repository/license as the full plugin, keywords without credential-source words. Description says it is the config-only edition and the full plugin covers usage, transcripts and scripted checks.
- SKILL.md frontmatter: `name: setup-audit-lite`, `allowed-tools: Read Grep Glob LS`, a description that names config-only comparison against official docs and community practice, and says to prefer the full `setup-audit` when it is installed.

- [ ] **Step 1:** Fetch `https://claude.com/docs/plugins/pre-submission-checklist.md` raw with curl into `$TMPDIR` and note any rule not in Global Constraints in the task report (do not widen the plugin to match; ask the controller).
- [ ] **Step 2: Write the failing tests** in `tests/test_lite_bundle.py`:
  - `test_bundle_passes` — `bundle_problems(LITE) == []`.
  - `test_allowed_tools_exact` — parsed frontmatter `allowed-tools` split on whitespace is a subset of `{'Read','Grep','Glob','LS'}`.
  - `test_manifest_fields` — `name`, `version == '0.1.0'`, no `icon`, `hooks`, `mcpServers` keys.
  - `test_listed_in_marketplace` — marketplace has an entry `setup-audit-lite` with source `./plugins/setup-audit-lite`, and the `setup-audit` entry is unchanged.
  - Red-proofs, each copying `LITE` to a temp dir with `shutil.copytree(..., symlinks=True)` and adding one violation, asserting `bundle_problems` names it: a `scripts/x.py`; a `notes.md` starting `#!`; `allowed-tools: Read Bash(ls *)`; `allowed-tools: Read(${CLAUDE_SKILL_DIR}/x)`; a `hooks/hooks.json`; a `bin/` dir; a `package.json`; a symlink; one `.md` containing both `.envrc` and `https://example.invalid`; a `.md` containing `![x](icon.png)`.
- [ ] **Step 3: Run** `python3 -m unittest tests.test_lite_bundle -v`. Expected: FAIL (plugin missing).
- [ ] **Step 4: Implement** `bundle_problems` (walk with `os.walk(followlinks=False)`, check `os.path.islink`, extensions, first two bytes, frontmatter, forbidden names and keys, the credential+URL pairing per file, image/font references) and create the skeleton files.
- [ ] **Step 5: Run** the test file, then the gate. Expected: PASS; `claude plugin validate --strict` clean for `plugins/setup-audit-lite` and the marketplace on a clean export.
- [ ] **Step 6: Commit** `tests/test_lite_bundle.py`, the new plugin files and `.claude-plugin/marketplace.json`.

### Task 2: References: checklist, reading rules, sources, docs snapshot

**Files:**
- Create: `plugins/setup-audit-lite/skills/setup-audit-lite/references/checklist.md`
- Create: `.../references/reading-rules.md`
- Create: `.../references/sources.md`
- Create: `.../references/docs-snapshot.md`
- Create: `.../references/stale-strings.md`
- Test: `tests/test_lite_bundle.py` (new classes)

**Interfaces:**
- Consumes: `LITE`, `bundle_problems` (Task 1). Raw docs pages fetched by the controller into `$TMPDIR/docs-2026-11-12/` (settings, permissions, hooks, mcp, memory, best-practices, changelog, sandboxing, env-vars, models page, plugins-reference, skills, sub-agents).
- Produces, for Task 3 to cite by file name:
  - `checklist.md`: sections `## Security (SEC-)`, `## Cost & context (COST-)`, `## Learning (LRN-)`, `## Agent readiness (RDY-)`, `## Hygiene (HYG-)`, `## New features (adopt)`, `## Lite-only`. Each check: backticked id, what to read (by the reading rules), the official claim key it relies on, severity. Ids outside `## Lite-only` must exist in `plugins/setup-audit/skills/setup-audit/references/checklist.md`. `## Lite-only` holds `HYG-lite-clutter-skills`, `HYG-lite-clutter-hooks`, `HYG-lite-clutter-overlap` (spec "Clutter check").
  - `reading-rules.md`: the value-free reading algorithm (below); names credential-source files; **contains no URL**.
  - `sources.md`: official page list (by page name, base URL once), the seven community sources with URLs, acceptance and rejection criteria, query vocabulary, injection safeguards; **names no credential source**.
  - `docs-snapshot.md`: first line `Snapshot date: 2026-11-12`, then one entry per claim `` `<claim-key>` — <verbatim quote> — page `<page>` ``. Only quotes copied from the raw pages.
  - `stale-strings.md`: table `| string | status | since | replacement |` with at least `includeCoAuthoredBy`, `ignorePatterns`, `TaskOutput`, `taskOutputMaxChars`, `MultiEdit`, `Write(`, `/output-style`, `permissionExplainerEnabled`, `teammateDefaultModel`; `Bash(x:*)` listed with status `old style, still valid`. Versions taken from the raw changelog; any not confirmed there is dropped.
- Reading algorithm for `reading-rules.md` (decided here, the implementer words it):
  1. Glob for the file; never open the never-open list.
  2. Count-only Grep (`output_mode: count`) for an inline value block: `"(env|headers)"\s*:\s*\{[^}\s]` and for `apiKeyHelper` / `awsAuthRefresh` / `awsCredentialExport` / `otelHeadersHelper` lines. Count > 0 for an inline block, or the file having one non-empty line (count of `.`), means the file is "not read" except for key names via rule 4.
  3. Line-number Grep (`-n`, content mode) only for patterns whose matching lines cannot carry a value: `"(env|headers)"\s*:\s*\{\s*$` and `^\s*\},?\s*$`. The value block runs from an opening line to the first closing-brace line after it.
  4. Read the file in line ranges that skip every value block and every helper line; record key names seen.
  5. Anything not cleanly split: "not read" with the reason, in the report's coverage list.

- [ ] **Step 1: Write the failing tests:**
  - `test_lite_ids_subset_of_full` — every backticked id matching `^(SEC|COST|LRN|RDY|HYG)-[a-z0-9-]+$` in lite `checklist.md` outside `## Lite-only` appears in the full checklist.
  - `test_lite_only_ids_present` — the three `HYG-lite-clutter-*` ids exist under `## Lite-only`.
  - `test_snapshot_dated_and_fresh` — first line parses as `Snapshot date: YYYY-MM-DD`; age vs today ≤ 120 days (intentional reminder to refresh each release).
  - `test_snapshot_has_no_stale_string_as_current` — no `stale-strings.md` string (status not `old style, still valid`) occurs in a snapshot quote.
  - `test_reading_rules_cover_inline_and_minified` — `reading-rules.md` contains the count-only inline pattern, the single-line check and the word "not read" (Review Focus 1).
  - `test_reading_rules_forbid_mcp_and_claude_json` — `reading-rules.md` lists `.mcp.json` and `.claude.json` as never opened, and no file under `LITE` contains an instruction line matching `(?i)\b(read|grep|open)\b.*(\.mcp\.json|\.claude\.json)` that lacks `never`/`not` (spec "MCP config files").
  - `test_sources_lists_seed_allowlist` — the seven seed sources from the spec appear in `sources.md`.
  - Red-proofs: a copy of `checklist.md` with a made-up `SEC-not-a-real-check` fails the subset check; a snapshot dated 2026-01-01 fails freshness.
- [ ] **Step 2: Run** them. Expected: FAIL.
- [ ] **Step 3: Write the five references.** Wording for checks may follow the full checklist where it fits, rewritten for config-only reading. Every snapshot quote is grepped from `$TMPDIR/docs-2026-11-12/`; a claim with no quote is left out.
- [ ] **Step 4: Run** the tests and `bundle_problems` (pairing rule!). Expected: PASS.
- [ ] **Step 5: Commit** the references and the test changes.

### Task 3: SKILL.md workflow, report format, apply log and check-in

**Files:**
- Modify: `plugins/setup-audit-lite/skills/setup-audit-lite/SKILL.md` (body)
- Create: `.../references/report-format.md`
- Create: `.../references/applied-log.md`
- Test: `tests/test_lite_bundle.py` (new class)

**Interfaces:**
- Consumes: the five references from Task 2, by file name.
- Produces: the log path `~/.claude/setup-audit-lite/applied.md` and its entry format (defined in `applied-log.md`): heading `## <YYYY-MM-DD> <check-id>`, then fields `file`, `scope`, `focus`, `why`, `before` (fenced, exact text), `after` (fenced, exact text), `measure` (name + before value), `status` (`applied` | `rolled-back` | `kept`).

SKILL.md steps, in order (the implementer writes the prose; these are the decisions):
1. Read `applied.md` if it exists; entries older than 7 days with `status: applied` get the check-in (step 9) first. A missing or unparseable log means "no check-ins", said in one line.
2. Glob `~/.claude/plugins/cache/*/setup-audit/*/.claude-plugin/plugin.json`; if found, say the full plugin is installed and recommend it for this run; continue only if the user wants.
3. Ask the focus (`focus=` weights, defaults as the spec) and scope; ask for one paste: `claude --version` and `claude mcp list` (or `/mcp`), with "remove tokens, URLs with keys and arguments before pasting". Without the paste: version unknown, MCP checks "not run".
4. Read the setup per `reading-rules.md`.
5. Official: WebFetch the pages the focus needs, asking for verbatim quotes; verify each quote against `docs-snapshot.md` with the spec's three labels. If fetches fail or are denied: snapshot fallback with the header line "Official docs could not be fetched; this audit uses the bundled snapshot from <date> and may be out of date."
6. Community: per `sources.md`, seed list first, generic queries only, vetting, rejected sources listed; if search/fetch is unavailable: "Community practice not gathered this run."
7. Report per `report-format.md`: header (date, docs date, Claude Code version or "unknown", focus, fallback line if any), per-topic official / community / yours, conflicts named, findings ranked (severity × focus weight), clutter check, counts of hooks/skills/plugins/MCP, coverage ("not read" list), check-in date. The report never repeats values, URLs or args from the MCP paste.
8. Apply: user picks; hard limits from the spec (verbatim list); refuse edits within 3 lines of a value block and give a paste-ready edit; one Edit per change showing before/after; re-Read the edited range; append the log entry; suggest `! cp <file> <file>.bak-<date>` before the first edit and `/doctor` after.
9. Check-in per entry: still present (Grep the `after` text count-only), not overridden (other scopes), impact by recorded focus (spec list), the user's impression, "counts compared, not proof"; offer rollback = Edit `after` → `before`; if `after` is no longer found, report the mismatch and give the manual reversal, never force (Review Focus 3); update `status`.
10. Report file: only if the user asks, Write `setup-audit-lite-report-<date>.md` in the current directory.

- [ ] **Step 1: Write the failing tests** (class `SkillWorkflow`):
  - `test_skill_cites_every_reference` — each file in `references/` is named in SKILL.md.
  - `test_hard_limits_listed` — SKILL.md contains the four hard-limit headings or bullets (credentials, loosening security, adding hooks/MCP/plugins, managed settings/outside scope).
  - `test_snapshot_fallback_line` — SKILL.md contains the exact fallback header sentence above (Review Focus 4).
  - `test_community_unavailable_line` — contains "Community practice not gathered this run." (Review Focus 4).
  - `test_mcp_paste_redaction` — SKILL.md asks to remove tokens before pasting, and `report-format.md` says values, URLs and args from the paste are never repeated (Review Focus 2).
  - `test_rollback_never_forces` — `applied-log.md` defines all eight fields and states that a missing `after` text gets a manual reversal, not a write (Review Focus 3).
  - `test_full_plugin_detection` — SKILL.md contains the Glob pattern above.
  - `test_no_curl_fallback` — SKILL.md says not to fall back to curl, and no shipped file contains `Bash(`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Write** SKILL.md body, `report-format.md`, `applied-log.md`. Keep SKILL.md under 500 lines; put detail in references.
- [ ] **Step 4: Run** the tests and the whole gate (bundle rules, strict validate on a clean export). Expected: PASS.
- [ ] **Step 5: Commit.**

### Task 4: Docs and local release

**Files:**
- Modify: `plugins/setup-audit-lite/CHANGELOG.md` (`## [0.1.0] - 2026-11-12`, what it is, what it reads and never reads, limits, "Validation and limits")
- Modify: `plugins/setup-audit-lite/README.md` (final)
- Modify: `docs/roadmap.md` ("Next project: directory lite plugin" → "Built: setup-audit-lite 0.1.0", plus open risk: whole-repo scan, policy view on settings edits)
- Create (git-ignored): `.release-notes/notes-lite-0.1.0.md`; top entry in `.release-notes/session-handoff.md`
- Move: `reports/Claude Code community sources.md` → `docs/research/2026-11-12-community-sources.md` and `research_notes/Claude Code community sources/*.md` → `docs/research/2026-11-12-community-sources-notes/` (use `git mv` after `git add`, or plain `mv`; no deletion of anything else). Commit them.

- [ ] **Step 1:** Write the docs.
- [ ] **Step 2:** Run the gate on a clean export. Expected: all tests OK, strict validate clean at plugin and marketplace level.
- [ ] **Step 3:** Commit on the branch. No tag, no push.

### Task 5: Final whole-branch review

A fresh reviewer reads `main..HEAD` against the spec, its anti-goals and the Global Constraints (with special attention to the credential+URL pairing and to any instruction that could make Claude read a value). One fix wave, a scoped re-review, rulings for residuals.
