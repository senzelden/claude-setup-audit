# Subscription usage (0.13.0) — design

Date: 2026-10-27. Status: user-scoped 2026-10-26/27 through two question batches (answers below);
the written design is approved under the user's standing "plan and build 0.13.0 now".

## Intent

The user is on a claude.ai subscription and wants to know whether their usage makes the most of
it: is weekly allowance left on the table, do model-scoped limits bite while other families sit
idle, are extra-usage settings sensible, and are occasional limit resets ("Use your limit reset to
reset it now") being noticed and used. Today setup-audit says nothing about plan limits.

## Decisions (user)

- Sources: an **opt-in status-line logger** the user wires in themselves (the plugin never installs
  it, as with drift mode), and **documented limit messages** found in transcripts.
  Not used: transcript credit-weight estimates, the cached `~/.claude.json` usage snapshot, plan
  tier or extra-usage flags from `~/.claude.json` (all undocumented).
- Resets: detect an **early reset** from the log; without the log, say plainly that resets are not
  observable locally.
- Scope: unused weekly headroom; model mix against model-scoped limits; extra-usage settings.
- Extra usage: **documented evidence only** (settings keys and documented messages). Plan tier,
  usage-credit limit and balance, and available resets are reported as not observable.
- Logger form: it is the `statusLine` command itself, prints its own short line, and can wrap
  another status-line command after `--` (printing that command's output instead).
- After the build, wire the logger into the user's own `~/.claude/settings.json` with a backup and
  a rendered check (a one-off personal config change, not plugin behaviour).
- Stop before push: merge into local `main` with a prepared 0.13.0 bump.

## Documentation grounding (fetched 2026-10-26/27 from code.claude.com/docs/en/*.md, raw)

- `statusline`: `rate_limits.five_hour|seven_day.{used_percentage (0-100), resets_at (epoch s)}`;
  `rate_limits.spend_limit.{used_percentage (may exceed 100), resets_at, used_usd?, limit_usd?,
  period?}` behind a Claude apps gateway. `rate_limits` appears only for Pro/Max subscribers (or a
  gateway spend limit) and only after the first API response; each window may be absent; "Claude
  Code drops a window once its `resets_at` time passes". The script runs at session start, on each
  assistant message, after `/compact`, on mode changes, optional `refreshInterval`, and when a
  window reaches `resets_at`; updates debounce at 300 ms and an in-flight script is cancelled by a
  newer update.
- `errors` ("Usage limits"): `You've hit your session limit · resets …`, `… weekly limit …`,
  `… Opus limit …`, `… Sonnet limit …`; session and weekly limits are shared across models, Opus and
  Sonnet limits apply per family. Warning `You've used 85% of your session limit · resets …`.
  Spend: `You've hit your monthly spend limit`, `… individual spend limit`, `… org's monthly spend
  limit`, `… channel's monthly spend limit`, `You've hit your team's shared budget`, `You've hit your
  individual usage limit`. Entitlement: `Usage credits required for 1M context`. Fable consent:
  `Fable … limit reached · continuing on Fable … uses usage credits, and the prompt to confirm went
  unanswered` / `Fable … now uses usage credits · the prompt to confirm went unanswered`.
- `interactive-mode`: an automatic wait is recorded in the conversation as `Usage limit reached ·
  continuing automatically at 3:45pm · esc to cancel`.
- `settings-reference`: `autoContinueAtUsageLimit`, `fastMode`, `fastModePerSessionOptIn`.
- `costs`: `/usage` shows plan bars and a usage breakdown with recommendations; `/usage-credits`
  manages usage credits on Pro/Max. Limit resets (`clau.de/reset`) are **not documented**.
- Observed, undocumented (this machine): API-side failures appear as assistant records with
  `isApiErrorMessage: true`, `message.model: "<synthetic>"`, a top-level `error` class, and the
  message text in `message.content[0].text`. No limit message exists in the retained transcripts,
  so the limit-message shape is unverified; matching is on documented text in any assistant or
  system record text, not on the wrapper.

## Goals

1. `scripts/rate_limit_log.py`: a stdlib status-line command that appends changed `rate_limits`
   values to a guarded JSON Lines log and prints a short status line.
2. Collector: read that log (read-only) and derive per-window headroom and early resets; scan
   transcripts for documented limit messages; summarize model mix by family; collect the documented
   extra-usage settings keys. One new optional top-level snapshot field, `subscription`.
3. Checklist items and SKILL/report guidance that turn these into evidence-backed proposals, each
   saying what is measured, inferred or not observable.
4. Docs: a reference page for the logger (run, wiring, log format, privacy), coverage labels for
   the undocumented parts, roadmap and changelog.

## Non-goals and anti-goals

- No credit-weight or dollar estimate of plan consumption; no reading of `~/.claude.json` for
  this feature.
- The plugin installs nothing: no status line, hook, schedule or background process.
- Never claim a reset was granted or used without log evidence; never claim the user is (or is not)
  a subscriber from the absence of data.
- Anti-goal: a logger that slows or breaks the user's status line. It must print within the
  status line's budget even when the log is unwritable, and never print a traceback.
- Anti-goal: a log that grows without bound or holds anything beyond numbers and timestamps.

## Logger (`scripts/rate_limit_log.py`)

- Invocation: `python3 <plugin dir>/skills/setup-audit/scripts/rate_limit_log.py [--log PATH]
  [-- COMMAND ...]`. Reads the status-line JSON from stdin (bounded read, e.g. 1 MB).
- Extracts only `rate_limits.{five_hour,seven_day,spend_limit}` with `used_percentage` and
  `resets_at` as finite numbers (other fields and types ignored; `spend_limit.period` kept only if
  one of `daily|weekly|monthly`; USD fields are not logged).
- Appends `{"version":1,"at":"<UTC ISO>","windows":{"five_hour":{"used_percentage":23.5,
  "resets_at":1738425600},...}}` only when, for some window, `resets_at` differs from the last
  logged entry or `floor(used_percentage)` differs, or a window appeared/disappeared. "Last logged"
  is read from the file's tail (bounded, e.g. the last 4 KB). Concurrent sessions may write a
  duplicate; the reader tolerates it.
- Path rule and file handling reuse `drift_log`'s guard (`check_path`/`append`): default
  `<CLAUDE config dir>/audits/rate-limits.jsonl`, directory inside the audits dir or a system temp
  dir, symlink refused, 0600 file, 0700 audits dir, interrupted-line isolation.
- Bound: when the log reaches 2 MB, rename it to `rate-limits.jsonl.1` (replacing an older one)
  before appending. The reader reads `.1` then the live file.
- Output: without `--`, one line such as `5h 23% · 7d 41% (resets Mon 00:00)`, or nothing when
  `rate_limits` is absent; times in local time. With `--`, run COMMAND with the same stdin bytes
  (no shell), a short timeout, and print its stdout; on its failure print the own line.
- Never raises: any logging error is swallowed (status line still prints), exit 0. Invalid
  arguments: exit 2 with usage on stderr.

## Collector

- `--rate-limit-log PATH` (read-only), mirroring `--drift-log` (same path guard; `status`
  `absent|collected|invalid`). SKILL.md passes the default path when the file exists.
- `subscription` snapshot field (all optional, additive, typed in `snapshot.schema.json`):
  - `log`: `status`, `path` (display form, path-hashing family), `entries`, `malformed`,
    `first_at`, `last_at`.
  - `windows.five_hour|seven_day|spend_limit`: windows grouped by `resets_at`; `closed` (windows
    whose `resets_at` is before the last entry), and for closed windows `peak_used_pct`
    distribution (min/median/max), `unused_at_close_pct` (100 − last observed, with the median lead
    time in hours between the last observation and `resets_at` so staleness is visible),
    `reached_100`, `reached_85`; `current` (the open window's last value and `resets_at`).
  - `early_resets`: per window kind, events where a new `resets_at` appears and `used_percentage`
    drops while the entry's time is before the previous window's `resets_at`; each event with
    dates (UTC), previous and new percentage. Basis string: inferred from the log; resets are
    undocumented; a plan or account change looks the same.
  - `limit_events` (transcripts, in window, user's own sessions; plugin-spawned excluded via M1's
    mechanism): counts per documented kind (`session`, `weekly`, `opus`, `sonnet`, `warning_85`
    with the window named, `auto_continue_wait`, `spend_limit`, `credits_required_1m`,
    `fable_consent_unanswered`), sessions affected, first/last UTC dates; main vs subagent counts.
    Only the kind is stored, never the message text.
  - `model_mix`: requests and tokens by family (`opus`, `sonnet`, `haiku`, `fable`, `other`) in
    the window from the existing request accounting, with shares; main and subagent separately.
  - `extra_usage`: the documented keys found in collected settings (`autoContinueAtUsageLimit`,
    `fastMode`, `fastModePerSessionOptIn`, with the settings file), counts of spend/credit messages
    (from `limit_events`), and `not_observable: ["plan tier", "usage-credit balance and limit",
    "available limit resets"]`.
- Privacy: no new free text. New string leaves are classified in `privacy.py`; the log path joins a
  `--hash-paths` family.

## Checklist and report

- `COST-subscription-headroom` (log, measured): median weekly `unused_at_close_pct` ≥ 50% over at
  least 3 closed weekly windows → information that a substantial share of the plan went unused
  (with the staleness lead time); frequent `reached_100`/hits → recommend `/usage` breakdown,
  `autoContinueAtUsageLimit`, scheduling heavy fan-outs. Without the log: recommend wiring it
  (one optional proposal), state the gap.
- `COST-model-scoped-limits` (transcripts): Opus or Sonnet limit hits while another family has a
  small share → suggest switching family for overflow (documented: family limits are separate;
  switching re-reads the conversation with no cache hits) or subagent model settings.
- `COST-extra-usage` (settings + messages): spend-limit hits, unanswered Fable consent, 1M credit
  entitlement errors → the documented remedies (`/usage-credits`, `dialogExpiry`, `/model`,
  `CLAUDE_CODE_DISABLE_1M_CONTEXT`). Never infer plan tier.
- `COST-limit-resets` (log, inferred): early resets listed with dates; without the log, "not
  observable locally".
- Thresholds (50%, 3 windows) are recommendations, not documented limits; say so.

## Constraints

Shared rules of `docs/superpowers/plans/2026-10-25-0.11.0.md` apply (stdlib, deterministic,
read-only audit, fake-home tests that fail without the change, doc claims cite page and fetch date,
undocumented shapes labelled in `references/coverage.md`). Gate: `python3 -m unittest discover -s
tests` and `python3 tests/check_snapshot_schema.py`.

## Rulings after the builder check (2026-10-27, mine)

- Ruling: staleness. The logger only sees the plan while Claude Code runs here, and usage elsewhere
  (claude.ai, other devices) also counts, so `100 − last observed` is an upper bound on unused
  headroom. A closed window counts toward `COST-subscription-headroom` only if its last
  observation is at most 24 h (seven_day) or 1 h (five_hour) before `resets_at`. Excluded windows
  are counted separately (`stale_excluded`) and the finding says "at most". Cost if wrong: an
  overstated or missing headroom finding.
- Ruling: limit-message matching is anchored. Match only when the record is an assistant record with
  `message.model == "<synthetic>"` or `isApiErrorMessage: true`, or a `system` record, and the
  text *starts with* a documented prefix (after whitespace). Ordinary assistant text, user text and
  tool results never match, because transcripts about this feature quote the strings. The wrapper
  is still unverified for limit messages, so the coverage label stays "observed, undocumented
  wrapper; documented text". Cost if wrong: real limit messages in another wrapper are missed
  (under-count, never over-count).
- Ruling: early reset = for one window kind, consecutive entries where the new `resets_at` is later
  than the previous one, the entry's time is before the previous `resets_at`, the previous
  `used_percentage` was at least 10 and it dropped by at least 10 points. The basis names the
  look-alikes (an account or plan switch, several accounts sharing one log). Cost if wrong: a
  reset misreported. The finding is labelled as inferred.
- Ruling: "small share" in `COST-model-scoped-limits` = under 10% of window requests; this is a
  recommendation, not a documented limit.
- Ruling: model mix extends the existing `request_params.{main,agent,...}.by_model` accounting
  (family buckets derived from those counts; add a token tally if the existing pass lacks one).
  `fastMode` and `fastModePerSessionOptIn` are not yet collected: add them, with
  `autoContinueAtUsageLimit`, to the settings summary's `other` keys.
- Ruling: wiring. The user has no `statusLine` today (checked 2026-10-26), so nothing needs to be
  wrapped. Wire `python3 ~/code/claude-setup-audit/plugins/setup-audit/skills/setup-audit/scripts/rate_limit_log.py`
  (the checkout on `main` is stable; the marketplace cache path is versioned). The controller makes
  this edit with the Edit tool under the user's permission prompt, after a backup. Words after `--`
  are passed as argv (the `statusLine.command` string itself is shell-parsed by Claude Code).

## Left to the builder

Module split (a pure `subscription_usage.py` analysis module is expected), exact field names
within the shape above, the status line's exact text, timeout values, test layout.
