# Vetting community sources of Claude Code advice at audit time (research as of 2026-11-12)

Method note: docs on code.claude.com were fetched on 2026-11-12 (WebFetch summaries plus raw `curl` of the changelog .md, which is ~1.2 MB and covers versions through 2.1.322, Nov 2026). Changelog version/date pairs below were read directly from the raw file. Search-result claims from secondary blogs are marked as such.

## 1. Which objective signals distinguish credible sources, and which can be checked from a fetched page alone?

### Takeaway
The strongest checkable signals are agreement with the current official settings reference/changelog (key names, permission syntax, versions) and a dated page that postdates the features it describes. Author identity, maintenance and popularity are weak for this domain and mostly need extra fetches (repo page), not just the advice page. No official Anthropic vetting standard for community sources exists in what I found.

### Cited Findings
- The official changelog is a single machine-readable page with per-version dates (e.g. 2.0.62 = December 9, 2025; 2.1.277 = September 18, 2026; 2.1.322 is the newest seen, with entries dated Nov 2026), and raw markdown is fetchable at `https://code.claude.com/docs/en/changelog.md` (~1.2M chars; WebFetch only reads 100,000 chars per call, so a skill should use offset paging or target-specific greps via curl is not available to it; Grep over a locally cached copy is) — [changelog](https://code.claude.com/docs/en/changelog)
- WebFetch reads at most 100,000 characters per call, summarises through a separate model call (lossy), and returns a text notice (no follow) when a URL redirects to another host — [Tools reference, WebFetch behavior](https://code.claude.com/docs/en/tools-reference.md)
- The settings reference is the canonical key list, with each key's scope, default and deprecation note; it is ~458K chars, so a skill must page it or search it by key — [Settings reference](https://code.claude.com/docs/en/settings-reference.md)
- The published JSON schema (schemastore) "can lag behind the newest CLI releases, so a validation warning on a recently documented key doesn't mean your configuration is invalid" — so schema absence alone is not a rejection signal for a key — [Settings](https://code.claude.com/docs/en/settings.md)
- Claude Code itself surfaces unknown/rejected entries (`claude doctor`; "Settings Warning" for malformed permission rules or unknown hook event names) — a source whose snippets trigger these is demonstrably stale or wrong — [Settings](https://code.claude.com/docs/en/settings.md)
- Maintenance-activity precedent from a comparable tool: OpenSSF Scorecard "Maintained" (risk High) gives top score for >=1 commit/week over previous 90 days, lowest if archived, and only applies to GitHub projects older than 90 days; Code-Review does not count bot or AI reviews; Signed-Releases "does not verify the signatures" — [Scorecard checks.md](https://raw.githubusercontent.com/ossf/scorecard/main/docs/checks.md). Note Scorecard measures software supply-chain hygiene, not advice quality; reusing thresholds for a blog/gist is an adaptation.

### Inferences
Concrete accept criteria checkable from the fetched page alone (no extra network):
1. Page carries a visible publish/update date within the last ~6 months AND names a Claude Code version (or states a model/feature that exists only after a known changelog version). Reject if the newest feature it mentions predates major changes below.
2. Every settings key / env var / permission rule it cites exists in the current settings reference/env-vars page (a local Grep of the fetched official page text by key name). Any key found in the "removed/deprecated" list (section 2) is a stale flag; a key found nowhere is an "unverified" flag, not an automatic reject (docs and schema lag).
3. Permission rules parse under current syntax (`ToolName(specifier)`, `Edit(...)` rather than `Write(...)`/`MultiEdit(...)`).
4. It links to code.claude.com/docs pages (citation of official docs) and those links resolve to current paths.
5. Content is advice (a config + rationale), not a bare command to run.
Needs a second fetch (not page-alone): repo last-commit date/archived status, author identity/affiliation (Anthropic employee, docs/plugin maintainer), star counts, issue responsiveness. Treat these as tie-breakers, not gates, because no source I found validates them for Claude Code advice.

### Gaps
- No official or peer-reviewed standard for "credible Claude Code community source"; the above criteria are derived, not published.
- Could not verify whether Anthropic publishes a list of trusted community resources (docs index at `https://code.claude.com/docs/llms.txt` exists per the page header but was not enumerated).
- Star counts/author-identity predictive value for advice quality: no evidence found.

## 2. Red flags: stale or low-quality advice; concrete renamed/removed items

### Takeaway
A dated list of verifiable renames/removals (below) lets a skill flag stale sources by simple string match. No reliable primary source exists for detecting AI-generated SEO listicles or affiliate marketing; those must be judged by heuristics, not evidence.

### Cited Findings (all dates from the changelog/settings reference, read 2026-11-12)
- `includeCoAuthoredBy`: deprecated; `attribution` setting added in 2.0.62 (December 9, 2025) "(deprecates includeCoAuthoredBy)"; settings reference says "Deprecated; use `attribution` to hide or change commit and PR attribution" — [changelog](https://code.claude.com/docs/en/changelog), [settings reference](https://code.claude.com/docs/en/settings-reference.md). Secondary blogs confirm that once `attribution.commit/pr` is set the old key is ignored (one source hints at a condition under which it is still read; unverified) — [search results](https://deku.posstree.com/en/generative_ai/claude-code-attribution/)
- `ignorePatterns`, `allowedTools`, `env`, `todoFeatureEnabled` in `.claude.json`: removed in 2.0.8 (October 4, 2025), "configure these in your settings.json"; `ignorePatterns` had been migrated to deny permissions in 2.0.35 (November 6, 2025 changelog entry "Migrated `ignorePatterns` from project config to deny permissions") — [changelog](https://code.claude.com/docs/en/changelog)
- `/allowed-tools` renamed `/permissions`, and `allowedTools`/`ignorePatterns` migrated from `.claude.json` to `settings.json` (version 1.0.7, 2025) — [changelog](https://code.claude.com/docs/en/changelog)
- `taskOutputMaxChars` setting and `TASK_MAX_OUTPUT_LENGTH`: no effect; the TaskOutput tool was removed in 2.1.277 (September 18, 2026), after deprecation in 2.1.83 (March 25, 2026) in favour of Read on the output file — [changelog](https://code.claude.com/docs/en/changelog), [settings reference](https://code.claude.com/docs/en/settings-reference.md)
- `permissionExplainerEnabled` removed in v2.1.257; `teammateDefaultModel` removed in v2.1.234; `keybindingFlavor` deprecated, no effect; `disableArtifact` deprecated in favour of `enableArtifact` — [settings reference](https://code.claude.com/docs/en/settings-reference.md)
- Windows managed settings fallback `C:\ProgramData\ClaudeCode\managed-settings.json` deprecated in 2.1.2 (January 9, 2026) and removed as a breaking change in a later release (2.1.7x range; header not captured) — use `C:\Program Files\ClaudeCode\managed-settings.json` — [changelog](https://code.claude.com/docs/en/changelog)
- `/output-style` deprecated in 2.1.73 (March 11, 2026), use `/config`; output style fixed at session start for prompt caching. (Earlier flip-flop: deprecated Oct 21, 2025 in 2.0.25 then "un-deprecated" in 2.0.30-ish — the exact un-deprecate version was not captured.) — [changelog](https://code.claude.com/docs/en/changelog)
- Legacy `MultiEdit` and `Write(...)` rules: docs say "use `Edit(docs/**)` in place of `Write(docs/**)`" and call MultiEdit "legacy" — [Permissions](https://code.claude.com/docs/en/permissions.md)
- Bash rule suffix `:*` is NOT removed: "The `:*` suffix is an equivalent way to write a trailing wildcard, so `Bash(ls:*)` matches the same commands as `Bash(ls *)`", only recognized at the end of a pattern (`Bash(git:* push)` treats the colon literally). Docs now write the space form. A source using `:*` should be flagged "old style, still works", not "wrong" — [Permissions](https://code.claude.com/docs/en/permissions.md)
- Fast mode for Opus 4.8 deprecated 2026-10-30, removal 2026-11-30 (changelog 2.1.316, Oct 31, 2026) — a near-term staleness marker — [changelog](https://code.claude.com/docs/en/changelog)
- Recent additions a stale source would miss: `permissions.blockWritesOutsideWorkingDirectories` (2.1.314), `permissions.blockReadsOutsideWorkingDirectories` (2.1.257), `permissions.denyInsteadOfPrompting` (2.1.319, Nov 6, 2026), and the defaultMode rule that `auto`/`bypassPermissions` no longer take effect from project/local settings (bypassPermissions restricted since v2.1.257) — [Settings](https://code.claude.com/docs/en/settings.md), [changelog](https://code.claude.com/docs/en/changelog)
- Behavioural change a source may get wrong: an exact Bash `ask` rule is refused (not prompted) when a broader `deny` covers it (2.1.319); `permissions.allow` rules in a committed `.claude/settings.json` apply only after workspace trust, while `deny`/`ask` apply immediately — [changelog](https://code.claude.com/docs/en/changelog), [Settings](https://code.claude.com/docs/en/settings.md)
- `ANTHROPIC_SMALL_FAST_MODEL` still appears in the 2.1.x changelog as an override (fix noted around 2.1.x); I did not find a removal note, so I do not list it as removed — [changelog](https://code.claude.com/docs/en/changelog)

### Inferences
- A cheap stale-source test: Grep the fetched page for the strings above (`includeCoAuthoredBy`, `ignorePatterns`, `/allowed-tools`, `TaskOutput`/`taskOutputMaxChars`, `MultiEdit`, `Write(` in permissions, `ProgramData\ClaudeCode`, `teammateDefaultModel`, `permissionExplainerEnabled`). Two or more hits plus an old date: reject; one hit: downgrade to "needs verification".
- A source that claims `bypassPermissions`/`auto` can be committed in project settings is wrong as of v2.1.257+.
- Listicle / SEO / affiliate heuristics (my judgement, not sourced): no first-hand command output, generic "10 tips" with no version or date, many settings with no doc links, referral links or paid-tool CTAs, claims of exact token or cost savings without method. Treat as weak signals to lower rank, never as sole reason to reject.

### Gaps
- No primary study quantifying AI-generated SEO content quality for Claude Code; only my heuristics.
- The exact version of the Windows `ProgramData` fallback removal and the output-style un-deprecation were not captured in my greps.
- Older changelog dates for 1.0.7 not captured (2025, mid-year).
- Official docs path names change (`.md` suffix and page splits like settings vs settings-reference); stale links to old pages is itself a freshness hint but I did not catalogue moved pages.

## 3. Prompt-injection risk from fetched web content and recommended mitigations

### Takeaway
Official docs explicitly warn about untrusted content and give mitigations (review commands, do not pipe untrusted content, permission prompts, sandbox), and WebFetch's separate-model summarisation is a partial, not complete, defence. Security research shows web-page injection against Claude Code works, so a skill must treat all fetched text as inert data and never follow or run anything from it.

### Cited Findings
- Official: "Best practices for working with untrusted content: 1. Review suggested commands before approval 2. Avoid piping untrusted content directly to Claude 3. Verify proposed changes to critical files 4. Use virtual machines... especially when interacting with external web services 5. Report suspicious behavior with `/feedback`" and "no system is completely immune to all attacks" — [Security](https://code.claude.com/docs/en/security)
- Official: curl/wget are not auto-approved; "most tools that make network requests require user approval by default" in Manual mode; WebFetch "runs a separate model call over the page, and Claude receives that call's answer instead of the raw page" — [Security](https://code.claude.com/docs/en/security), [Tools reference](https://code.claude.com/docs/en/tools-reference.md)
- Official: WebFetch is "lossy by design" and the extraction prompt decides what reaches Claude; in auto and bypassPermissions modes the prompt is skipped except for explicit `ask` rules — [Tools reference](https://code.claude.com/docs/en/tools-reference.md)
- Official: WebSearch returns only titles and URLs, does not fetch pages; interactive sessions are limited to 200 WebSearch calls; permission rules for WebSearch take no specifier (all or nothing) — [Tools reference](https://code.claude.com/docs/en/tools-reference.md)
- Official: WebFetch can be restricted with `WebFetch(domain:example.com)` allow/deny/ask rules; a bare `WebFetch` deny differs from `WebFetch(domain:*)` — [Permissions](https://code.claude.com/docs/en/permissions.md)
- OWASP LLM01:2025 defines indirect injection ("accepts input from external sources, such as websites or files") and lists mitigations including "Enforce privilege control and least privilege access", "Require human approval for high-risk actions", and "Segregate and identify external content: Separate and clearly denote untrusted content to limit its influence on user prompts." No revision date on the page — [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- Android developer guidance: mark external data as untrusted and wrap in explicit delimiters (example `<external_data>` tags) when summarising web pages (via search summary; page not fetched directly) — [Android prompt-injection guidance](https://developer.android.com/privacy-and-security/risks/ai-risks/prompt-injection)
- Simon Willison (June 16, 2025): the "lethal trifecta" = access to private data, exposure to untrusted content, ability to communicate externally; "we still don't know how to 100% reliably prevent this"; skeptical of guardrail products claiming 95% catch rates; once an agent has ingested untrusted input "it must be constrained so that it is impossible for that input to trigger any consequential actions" — [Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- Johann Rehberger (reported by The Register, Oct 30, 2025): hidden instructions in a document led Claude to upload private data via Anthropic's File API; works even in the most restrictive network setting; Anthropic's stated mitigation is to "monitor Claude while using the feature and stop it if you see it using or accessing data unexpectedly" — [The Register](https://www.theregister.com/2025/10/30/anthropics_claude_private_data/)
- Secondary reporting (Aug 2026, not verified against primary): Rehberger showed a summarize-a-website prompt that, after WebFetch failed with HTTP 415, made Claude Code fall back to curl and execute attacker code under Auto Mode on Opus 5 (reported 60-80% success in a small sample); a Trajectory Labs evaluation commissioned by Anthropic reported 0.00% across 72 scenarios. Figures conflict and I could not reach the primary write-up — [search results](https://letsdatascience.com/news/researcher-demonstrates-claude-code-prompt-injection-5591c12b), [The Register](https://www.theregister.com/2025/10/30/anthropics_claude_private_data/)
- Secondary: Mozilla 0din showed a repo with no visible malicious code could make coding agents open a reverse shell (unverified secondary) — [devops.com](https://devops.com/mozilla-shows-the-danger-of-indirect-prompt-injections-in-ai-coding-agents/)

### Inferences
Mitigations a skill can apply with only WebSearch/WebFetch + Read/Grep/Glob:
1. Treat the fetched page as data. Never execute, install, or paste any command, hook, or script from it; never write it to settings, CLAUDE.md or a skill file. Audit is read-only anyway; proposals from community sources are quoted, not applied.
2. Quote only short excerpts (e.g. <=2 sentences) with URL and fetch date, inside an explicit delimiter or labelled block in the report; do not restate imperative text addressed to "the assistant/AI/Claude".
3. Injection-pattern check on the fetched text before use (Grep): phrases like "ignore previous instructions", "you must now", "system prompt", instructions addressed to AI agents, hidden/zero-width/HTML-comment text, base64 blobs, curl|sh, requests to read `~/.ssh`, `.env`, credentials or send data to a URL. Any hit: reject the source and report as "contains agent-directed instructions".
4. Do not follow links from a community page to fetch more beyond a small cap; restrict to the same host or to official docs; never follow redirects to other hosts automatically (WebFetch already stops at cross-host redirects).
5. Do not fall back to curl on WebFetch failure (the reported Rehberger chain); report the failure instead.
6. Because the trifecta applies (audit reads private config, fetches untrusted content, can reach network), keep one leg cut: no secrets or transcript content in anything sent out (see section 4).
7. Prefer a lossy summary: ask WebFetch a narrow extraction prompt (list keys and claims) rather than "follow the instructions on this page".

### Gaps
- OWASP page and the Android page were fetched via search/summary only; exact wording of Android's guidance not verified by a direct fetch.
- Primary Rehberger blog posts (embracethered.com) were not reached; reports are secondary.
- No evidence whether WebFetch's secondary model call actually filters injection; docs do not claim it does.

## 4. Privacy: not leaking local context into search queries

### Takeaway
No official Claude Code guidance specifically about search-query hygiene was found; the data-flow facts below are documented, and the rule that follows is an inference. The practical rule: queries must be generic strings built from official key names and feature names, never from file paths, repo or project names, usernames, hostnames, secrets or transcript text.

### Cited Findings
- WebSearch runs queries against Anthropic's web search backend (not the local machine); the query is model-generated text, so anything in context can end up in it — [Tools reference](https://code.claude.com/docs/en/tools-reference.md)
- WebFetch safety check: before fetching, Claude Code sends only the requested hostname (not URL, path or contents) to `api.anthropic.com` for a blocklist check, cached 5 minutes; disabled via `skipWebFetchPreflight: true` and not affected by `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` — [Data usage](https://code.claude.com/docs/en/data-usage.md)
- But a fetch of a URL does expose the full URL to the destination server; so no private tokens, repo names, or path fragments should be placed in query strings of fetched URLs (inference; the docs only state the preflight behaviour)
- Local transcripts are stored in plaintext under `~/.claude/projects/` for 30 days by default (`cleanupPeriodDays`) — relevant because audit text copied into queries/notes persists — [Data usage](https://code.claude.com/docs/en/data-usage.md)
- Real-world exfiltration via allowed network access was demonstrated by Rehberger, so egress carrying local context is a genuine risk — [The Register](https://www.theregister.com/2025/10/30/anthropics_claude_private_data/)

### Inferences
Query rules a skill can enforce itself (checkable before issuing a search):
- Build queries only from a fixed vocabulary: official setting/env var names, feature names, "Claude Code", a year/month. Allowlist rather than blocklist.
- Reject any query containing: absolute/relative paths, `~`, `@`, `://`, a string appearing in the user's config values (e.g. repo names, MCP server names, hook script names, internal hostnames), anything matching secret shapes, or text copied from CLAUDE.md/transcripts/memory.
- Search for the generic class ("Claude Code PreToolUse hook matcher best practices"), not the user's custom name, even if they use a rare plugin; if only a private name would work, ask the user first.
- Report to the user which queries were sent (an audit trail).

### Gaps
- No official statement of what Anthropic's search backend logs about queries; not found.
- No published guidance on query privacy for coding-agent search specifically; rules above are my design.

## 5. How comparable tools label official vs community recommendations

### Takeaway
I could verify only partial precedents; most comparable-tool documentation fetches failed or returned secondary summaries. What is verifiable: OpenSSF Scorecard attaches a risk level and explicit evidence thresholds per check, and Android/OWASP guidance prescribes marking untrusted content. A labeled-provenance presentation is therefore a design recommendation, not a cited industry standard.

### Cited Findings
- OpenSSF Scorecard labels each check with a Risk level (Maintained=High, Code-Review=High, Signed-Releases=High, Security-Policy=Medium) and documents scoring evidence, and notes limits (signatures not verified) — [Scorecard checks.md](https://raw.githubusercontent.com/ossf/scorecard/main/docs/checks.md). Sonatype notes Scorecard periodically changes checks so scores shift between versions (secondary) — [Sonatype](https://www.sonatype.com/state-of-the-software-supply-chain/open-source-security-practices)
- OWASP: "Separate and clearly denote untrusted content" — [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- Claude Code itself separates origin classes: official-source plugins keep `allowed-tools` pre-approval under `allowManagedPermissionRulesOnly`, while "plugins from marketplaces, claude.ai and npm" do not, unless managed settings vouch for them (2.1.x changelog entries) — [changelog](https://code.claude.com/docs/en/changelog). Also Anthropic "does not security-audit or manage any MCP server" and reviews directory connectors against listing criteria — [Security](https://code.claude.com/docs/en/security)

### Inferences (recommended presentation, not sourced precedent)
- Two visibly separate sections or columns: "Official (code.claude.com, fetched date, changelog version)" and "Community (unverified)". Never merge a community claim into an official statement.
- Each community item carries: source URL, fetched date, page date, claims-checked-against-official result (verified / contradicted / not found in docs), vetting flags (stale-key hits, agent-directed text hits), and a confidence label. Community items never raise a recommendation's rank on their own; at most "worth reading", with official docs as the authority when they disagree.
- Quote, don't paraphrase imperative text; no auto-apply; applying any change still goes through the plugin's existing user approval with backups.
- Cap the number of community items per report and show rejected sources with reasons so the user can audit the vetting.

### Gaps
- Fetches of ESLint, Trivy, Checkov, Lighthouse, kube-linter docs for official vs community labeling were not completed (one Trivy URL 404); no verified statement about how those tools label community rules.
- No documented tool found that vets web-sourced advice at run time; this appears to be an unoccupied niche (absence not proven).
