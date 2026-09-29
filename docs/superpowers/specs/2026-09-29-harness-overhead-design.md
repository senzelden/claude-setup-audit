# Self-modifying harness overhead — design

Date: 2026-09-29. Status: approved in conversation; awaiting written-spec review.
Roadmap item: "Self-modifying harness overhead" in `docs/roadmap.md`.

## Goal

`COST-startup-hooks` today guesses injected context from the size of `skills/using-*/SKILL.md`
(`collect.py` `plugin_session_start_hooks`), a heuristic that fits one plugin family. The
transcript reader ignores attachment records and never sums subagent usage, and nothing tracks
how the skill listing grows.

This work measures, from transcripts in the window: text that hooks inject per session and which
plugin injected it, the size and growth of the skill listing, subagent token spend, and the mix of
interactive vs SDK sessions. It statically flags enabled plugin hooks that invoke a model. All of
this is observed evidence; the model judges it with the checklist and proposes changes that still
need approval.

Success: fixture runs show matched, ambiguous and unattributed injection sources; a growing skill
listing yields first/last/max; subagent usage is summed only inside the window; a hook script that
runs `claude -p` is flagged by file, line and pattern id; truncated or malformed input gives
`complete: false`; no transcript content, hook output or script text reaches the snapshot.

## Evidence that shaped the design (local probe, 2026-09-29)

Metadata-only probe of this machine's transcripts (types, key names, sizes; no content kept):

- `attachment` records of type `hook_additional_context` carry `hookEvent`, `hookName`,
  `toolUseID`, `content`. `hook_success` records carry the same ids plus `command`, `exitCode`,
  `durationMs`. `hookName` is e.g. `SessionStart:startup`; it does not name the plugin, but the
  command (`"${CLAUDE_PLUGIN_ROOT}/hooks/run-hook.cmd" session-start`) can be matched against a
  plugin's `hooks.json`.
- 38 of 300 recent main transcripts had injected hook context; SessionStart median ~3.4k chars
  per record, fired again on `clear` and `compact`.
- Every session has an initial `skill_listing` attachment with `skillCount` and `content`. Across
  the probe it grew from 12 skills / ~5.8k chars to 79 skills / ~29.8k chars. **This disconfirms
  the roadmap note that skill-count growth needs the ledger's history**: transcripts already hold
  a time series.
- 361 of the 400 most recent main transcripts have `entrypoint: sdk-py`, 37 `cli`, 2 `sdk-cli`.
  SDK sessions cannot be told apart from the user's own automation, so they are reported as shares,
  never labeled "reflection".
- 1,480 subagent transcripts exist under `projects/*/*/subagents/`.

The transcript record format is not documented by Anthropic. Every field above is treated as
optional; absence means "not observed", never zero.

## Decisions (user, 2026-09-29)

1. Reflection: observed facts only. Static scan of enabled plugins' hook commands/scripts for
   model invocations, summed subagent usage, and entrypoint shares. No attribution of SDK sessions
   to hooks or plugins, no "reflection" label.
2. Skill growth: from transcripts (per-session `skill_listing`) plus labeled report metrics so the
   existing two-run trend logic yields cross-run deltas. The ledger is not changed.
3. Attribution: pair `hook_additional_context` with `hook_success` by `toolUseID`, match the
   command against enabled plugins' `hooks.json`; none → `unattributed`, several → `ambiguous`.
   Never guess.
4. Fix `candidate_skills` inflation in scope: count only `SKILL.md`, not every `.md` under a
   plugin's `skills/` directory.

## Approach

Extend the existing single pass in `collect_transcripts` (it already walks up to 400 main and 1,600
subagent files, newest first, filtered by record timestamp) instead of a second script, so file
limits, window and redaction logic are shared. Plugin hook indexing and the static scan go in a
new, pure module.

## Components

| Unit | Responsibility | Writes |
|---|---|---|
| `scripts/harness.py` (new) | Build the enabled-plugin hook index (plugin, event, matcher, command) from registry `installPath`; match a transcript command to plugins; static scan of hook commands and referenced scripts for model-invocation patterns | nothing |
| `scripts/collect.py` | In `collect_transcripts`: accumulate attachment signals per main session, sum subagent usage, count entrypoints; assemble `harness_overhead`; switch `plugin_session_start_hooks` to the registry path | snapshot only |
| `scripts/extensions.py` | Count only `SKILL.md` as a skill component; expose per-plugin skill counts | nothing |
| `references/snapshot.schema.json`, `snapshot-format.md` | Optional typed `harness_overhead` section | — |
| `references/checklist.md`, `coverage.md`, `SKILL.md` | Measured `COST-startup-hooks`, new `COST-harness-overhead`, report metrics, limits | — |

## Snapshot: `harness_overhead` (optional, additive within v1)

Shape only; the numbers are illustrative and not mutually consistent. `entrypoints` counts main
files scanned; `sessions_scanned` counts main sessions with at least one record in the window.

```json
{
  "window_days": 30,
  "sessions_scanned": 212,
  "complete": true,
  "incomplete_reasons": [],
  "injected_context": {
    "sessions_with_injection": 38,
    "sources": [
      {"plugin": "superpowers@claude-plugins-official", "attribution": "matched",
       "hook_event": "SessionStart", "sessions": 36, "records": 68,
       "chars_per_session_median": 3453, "chars_per_session_p90": 6906,
       "est_tokens_per_session_median": 863}
    ]
  },
  "skill_listing_series": {
    "sessions": 197,
    "first": {"date": "2026-08-31", "skill_count": 12, "chars": 5837},
    "last": {"date": "2026-09-29", "skill_count": 79, "chars": 29782},
    "max": {"skill_count": 79, "chars": 29782},
    "sdk_sessions_excluded": 15,
    "per_plugin_skills": [{"plugin": "superpowers@claude-plugins-official", "skills": 14}]
  },
  "subagent_spend": {
    "subagent_files_scanned": 640,
    "sessions_with_subagents": 58,
    "subagent_tokens_per_session_median": 120000,
    "main_tokens_per_session_median": 450000,
    "main_tokens_median_in_subagent_sessions": 2100000,
    "entrypoints": {"cli": 37, "sdk-py": 361, "sdk-cli": 2, "other": 0}
  },
  "model_spawning_hooks": [
    {"plugin": "example@market", "hook_event": "Stop", "file": "hooks/reflect.sh",
     "line": 12, "pattern": "claude_print"}
  ]
}
```

Rules:

- **Session unit.** Per-session totals, not per record: SessionStart fires on startup, clear and
  compact, so a session can carry several injections. Medians/p90 are over sessions with at least
  one record from that source.
- **Characters, estimated tokens.** Characters are measured; tokens are `chars // 4`, labeled
  estimated (same convention as existing estimates). Non-string `content` is measured as its
  compact JSON length.
- **Attribution.** Index each enabled plugin's `hooks/hooks.json` (and inline `hooks` in its
  manifest, if present) from the registry `installPath`. A command matches a plugin when the
  recorded command string equals a registered command string. Unpaired injection records (no
  `hook_success` with the same `toolUseID`) and user/project hooks are `unattributed`; the source
  key is then `(null, hook_event)`. Command strings are not stored.
  Real-data finding (2026-09-29): SessionStart `hook_additional_context.toolUseID` is the literal
  event name while its `hook_success.toolUseID` is a UUID, so 69 of 69 SessionStart injections were
  unpaired. After exact pairing fails, the candidates are the commands of `hook_success` records in
  the same file with the same `hookEvent` and non-empty `stdout`; candidates that match no plugin
  (user/project hooks) drop out; one plugin left is `matched`, several (or an ambiguous command)
  `ambiguous`, none `unattributed`. The index also reads manifest `hooks` given as a path string or
  a list of paths and inline objects, resolved inside the plugin root with the scan's containment
  rules.
- **Skill listing.** Only the first `skill_listing` with `isInitial` true per main session. Dates are
  the record's day (UTC). `per_plugin_skills` comes from the inventory, not transcripts: enabled
  plugins only, once each. The series covers main sessions whose entrypoint does not start with
  `sdk-` (SDK sessions list different skills); `sdk_sessions_excluded` counts the others, and
  only-SDK listings give `null` with `not_observed`.
- **Subagent spend.** Sum `input_tokens + cache_creation_input_tokens + cache_read_input_tokens +
  output_tokens` of assistant records inside the window, per parent session directory. Main-session
  totals use the same formula over non-sidechain records, so the two are comparable. Duplicate
  message ids (streamed chunks) are counted once, as the existing MCP deduplication does.
  `main_tokens_median_in_subagent_sessions` is the main-token median over the sessions that have
  subagent tokens, so the subagent median is compared with like sessions.
- **Entrypoints.** First user/assistant record per main file; unknown values go to `other`.
- **Static scan.** For each enabled plugin hook: the command string, plus any file it references
  that resolves inside the plugin root (after `${CLAUDE_PLUGIN_ROOT}` substitution; symlinks and
  paths escaping the root are skipped and make the scan incomplete), read up to 64 KiB. Patterns
  (ids): `claude_print` (`claude` followed by `-p` or `--print`), `agent_sdk_py`
  (`claude_agent_sdk`), `agent_sdk_js` (`@anthropic-ai/claude-agent-sdk`), `anthropic_client`
  (`anthropic.Anthropic(`, `new Anthropic(`, `api.anthropic.com`). Commented-out lines (`#`, `//`)
  are skipped. Only file (relative to plugin root), line and pattern id are emitted.
- **Completeness.** `complete: false` with reasons (`main_file_cap`, `subagent_file_cap`,
  `malformed_records`, `plugin_registry_unreadable`, `plugin_root_unreadable`,
  `hook_file_unreadable`, `script_unresolved`, `script_truncated`, `transcripts_not_read`) when any
  applies. The registry reason covers a missing or malformed `installed_plugins.json` or an enabled
  plugin without rows; the hook-file reason covers a hooks file that is a symlink, escapes the root,
  is unreadable, not an object or above 1 MiB. Global scope reads no transcripts
  (`transcripts_not_read`), so the section then holds only static signals. No `skill_listing` records at all yields `skill_listing_series: null` with reason
  `not_observed`, which is reported but does not make the section incomplete.
- **Privacy.** No content, command strings, script text, prompt text or hook output is stored.
  Plugin names, relative script paths, counts, sizes and dates only.

## Existing behavior changed

- `plugin_session_start_hooks` resolves plugins through the registry `installPath` (as
  `extensions.py` does) instead of newest-mtime cache directories, and reads enabled plugins from
  every settings layer the collector already reads. The `est_injected_tokens` estimate is kept as
  a fallback and labeled `basis: file_size_estimate`.
- `extensions.py` component collection counts a skill only as `skills/<name>/SKILL.md`; other `.md`
  files under `skills/` are references, not skills. `candidate_skills` drops accordingly.

## Checks and report metrics

- **`COST-startup-hooks`**: uses `injected_context` when any session in the window has records;
  falls back to the file-size estimate otherwise and says so. Evidence names plugin, event,
  sessions and median estimated tokens per session.
- **`COST-harness-overhead`** (new): judged by the model from `skill_listing_series`,
  `per_plugin_skills`, `model_spawning_hooks` and `subagent_spend`. The checklist entry gives the
  thresholds to consider (listing size against the documented skill-description budget, re-fetched
  during implementation; growth from first to last; any model-spawning hook; subagent share of
  tokens) and forbids calling SDK sessions "reflection" or attributing them to a plugin.
- Report metrics (labeled, `source: harness_overhead`, new coverage family `harness_overhead`):
  `skills.listing_count` (last), `skills.listing_chars` (last),
  `hooks.injected_tokens_per_session_median` (estimated). The existing `finalize` logic then
  computes deltas against the previous report when units, basis, source and coverage match.

## Documentation

During implementation, re-fetch and record with date: the hooks reference (SessionStart
`additionalContext`, events that re-fire on clear/compact) and the skills page (description
listing budget). Record in `references/coverage.md` that the transcript attachment format is
undocumented and observed, and that absence is "not observed".

## Testing

All fixtures use temporary fake homes (`tests/test_collect.py` patterns); nothing reads real
`~/.claude`. Each test is red-proofed by breaking the rule it guards.

- Injection: matched, ambiguous (two plugins with the same command), unattributed (user hook; no
  paired `hook_success`); a session with startup + compact counts as one session with summed
  characters; records outside the window are ignored.
- Skill listing: non-initial listings ignored; first/last/max across sessions; no listings →
  `null` + `not_observed`.
- Subagent spend: window filter, duplicate message ids counted once, sidechain records in main
  files excluded from main totals.
- Entrypoints: unknown value → `other`.
- Static scan: each pattern id; commented lines skipped; symlink and root-escaping paths skipped
  and marked incomplete; file size cap.
- File caps reached → `complete: false` with the right reason.
- Privacy: a secret-looking string placed in hook content, command and script is absent from the
  serialized snapshot.
- `candidate_skills`: a plugin with `skills/a/SKILL.md` and `skills/a/reference.md` counts one skill.
- `plugin_session_start_hooks`: registry `installPath` wins over a newer-mtime stale cache copy.
- Schema: `tests/check_snapshot_schema.py` accepts the new section and rejects wrong types.

Gate: `python3 -m unittest discover -s tests -v`, schema check, `git diff --check`, coverage ≥ 88.

## Out of scope

- Linking SDK/headless sessions to the hook or plugin that spawned them.
- A persistent multi-run history file; cross-run growth uses report metrics only.
- Running hook commands to measure their output.
- Automatic removal or disabling of plugins; any change stays an approved proposal.
