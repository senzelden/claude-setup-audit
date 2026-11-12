# Claude Code community blog posts and long-form guides (state as of 2026-11-12)

Method note: ~19 tool calls (WebSearch, WebFetch summaries via a small model, HN Algolia API). Fetch summaries are model-condensed, so dates and counts below are as reported by the fetch, not independently checked. Several searches returned mostly SEO pages, which is itself a finding. Not reached: Latent Space, Pragmatic Engineer, Hamel Husain, Jesse Vincent, Armin Ronacher 2026 posts (no 2026 primary hits). apiiro.com returned 403.

## Q1. Which practitioner posts are most cited (URL, author, dates, reach, topics)?

### Takeaway
The most credible, widely read practitioner material found is thin on config topics. High-reach posts are workflow essays (Boris Tane, Feb 2026) or measurements (Systima, Jul 2026). Simon Willison is the best curator and security commentator. Anthropic's own docs have absorbed the original "best practices" post. Most high-point HN items tagged "claude code" are news, bug reports or leaks, not config guides.

### Cited Findings
- Boris Tane, "How I use Claude Code: Separation of planning and execution", published Feb 11, 2026 (page shows no updated date); HN 976 points / 591 comments (2026-02-22). Topics: research.md -> plan.md -> annotation cycle -> implement; one long session relying on auto-compaction. Does not cover permissions, hooks or CLAUDE.md. — [post](https://boristane.com/blog/how-i-use-claude-code/); [HN data](https://hn.algolia.com/api/v1/search?query=claude%20code&tags=story&numericFilters=points%3E300&hitsPerPage=40)
- Systima, "Claude Code sends 33k tokens before reading the prompt; OpenCode sends 7k", 2026-07-12, no individual author; HN 706 points / 395 comments. Measured via logging proxy on Claude Code 2.1.207 vs OpenCode 1.17.18: about 33k vs 7k fixed tokens (tool schemas about 24k of the 33k), MCP about 1.0-1.4k tokens per small server per request, 72KB instruction file about 20k tokens per request, two-way subagent fan-out 513k vs 121k tokens (about 4.2x). Caveats: single machine, small samples, gateway swapped a newer model snapshot, simple quality task. Topics: context, cost, MCP, subagents. — [post](https://systima.ai/blog/claude-code-vs-opencode-token-overhead)
- Simon Willison (simonwillison.net) tag page is the best running log. Relevant 2026 entries: "How we contain Claude across products" (2026-05-30); "Auto mode is now the default in Claude Code for Pro, Max, and Team plans" (2026-08-08, quotes Anthropic evals "none of the 720 attack attempts succeeded", with his skepticism); "Breaking Claude Code Opus 5 Auto Mode" (2026-08-27, Johann Rehberger bypass, advice: run unattended agents in container/VM/OS sandbox); "AGENTS.md support in Claude Code" (2026-09-18); "Boris Cherny on the bar for Claude-written production code" (2026-09-11); "How the Claude Code team does code review" (2026-10-16); "A Fireside Chat with Cat and Thariq" (2026-07-21); "Letting Fable use its own judgement" (2026-07-03, subagent delegation to cheaper models). Mostly quotes/commentary, not how-to guides. — [tag page](https://simonwillison.net/tags/claude-code/)
- Simon Willison, "Claude Code in Bun in Rust", 2026-07-19; HN 608 points / 852 comments (technical inspection, not config advice). — [post](https://simonwillison.net/2026/Jul/19/claude-code-in-bun-in-rust/)
- Arpan Patel, "Claude Code as a Daily Driver: Claude.md, Skills, Subagents, Plugins, and MCPs", published 2026-05-26; HN 451 points / 254 comments (2026-05-27). Covers CLAUDE.md (short, cut lines whose removal causes no mistake), skills (`disable-model-invocation` for side-effecting ones), read-only reviewer subagent, few MCP servers. Thin on permissions. No updated date. — [post](https://arps18.github.io/posts/claude-code-mastery/)
- Blake Crosley, "Claude Code CLI: The Complete Guide — Hooks, MCP, Skills": reportedly last updated 2026-11-11 and current to v2.1.322 (2026-11-10); about 186,000 words. Versioned notes (Opus 5.5 default, auto mode as starting mode from v2.1.283-284, AGENTS.md fallback v2.1.277/281, `denyInsteadOfPrompting` v2.1.319). Companion post "Claude Code Hooks Explained". Only first 100k of about 500k characters read; claims are the author's own and not verified. — [guide](https://blakecrosley.com/guides/claude-code); [hooks post](https://blakecrosley.com/blog/claude-code-hooks-explained)
- cubic.dev (Alex Mercer), "Claude Code hooks: every event, with examples to copy", published Oct 16/17, 2026 (page's own dates conflict), says it follows Anthropic docs as of Oct 12, 2026; lists 33 hook events; states `PreToolUse` deny blocks even in `bypassPermissions`, and that `claude -p`/Agent SDK treats the folder as trusted so repo hooks run without prompt. cubic sells a code-review product used in its fourth example (vendor bias). — [post](https://www.cubic.dev/blog/claude-code-hooks)
- Apiiro, "Claude Code's 'Don't Ask Again' exposes passwords in 1,122 public GitHub files", HN 626 points / 429 comments (2026-11-07). Security vendor research on committed permission-allow entries; page returned 403 so contents unverified here. Vendor-authored. — [post](https://apiiro.com/blog/coding-agents-leaking-secrets-github-dont-ask-again)
- Other high-HN practitioner/analysis posts, mostly not config guides: alex000kim, source leak analysis (2026-03-31, 1376 pts); "Claude Code Unpacked: a visual guide" ccunpacked.dev (2026-04-01, 1128 pts); symmetrybreak.ing "Claude Code is being dumbed down?" (2026-02-11, 1085 pts); mihaileric.com "How to code Claude Code in 200 lines" (2026-01-08, 816 pts); amplifying.ai "What Claude Code chooses" (2026-02-26, 611 pts); Claude Code cheat sheet cc.storyfox.cz (2026-03-23, 699 pts). — [HN data](https://hn.algolia.com/api/v1/search?query=claude%20code&tags=story&numericFilters=points%3E300&hitsPerPage=40)
- Armin Ronacher (lucumr.pocoo.org): "A Year Of Vibes" (2025-12-22). Secondary summaries say he runs permissions-off in a container and prefers CLI scripts/Makefile over most MCP; summaries are low quality and wording unverified. — [post](https://lucumr.pocoo.org/2025/12/22/a-year-of-vibes/); [secondary](https://self.md/people/armin-ronacher-agentic-coding/)
- Web search for "Claude Code best practices" is dominated by SEO/vendor posts (eesel.ai, axify.io, felo.ai, aiorg.dev, claudedirectory.org, meetzest.com, iwoszapar.com, smartscope.blog); I did not vet them individually. — [search results listing e.g. axify](https://axify.io/blog/claude-code-best-practices)

### Inferences
- Reach on HN correlates with news/controversy or hands-on measurement, not config guidance; the best config guidance is the official docs plus a few long vendor-neutral guides.
- For a setup-audit tool, Willison (security/auto mode), Systima (token overhead) and Rehberger (via Willison) are the best external evidence anchors; Crosley is useful as version-tracking cross-check but single-author and unverified.

### Gaps
- No primary 2026 posts found from Latent Space, Pragmatic Engineer, Hamel Husain, Jesse Vincent, Ronacher; absence may reflect search limits, not absence of posts.
- HN points for Crosley, cubic and Patel-only-through-HN; no citation counts beyond HN.
- Apiiro content not read.

## Q2. Which posts are stale, vendor marketing or SEO listicles?

### Takeaway
Anything from 2025 predates auto mode being the default, the 1M-token window, AGENTS.md fallback and Opus/Sonnet 5.x, so context-management and permission advice is likely stale. Many top search hits for "best practices" are SEO listicles or vendor content.

### Cited Findings
- Anthropic's own April 2025 post (anthropic.com/engineering/claude-code-best-practices, HN 614 pts, 2025-04-19) now returns 308 Permanent Redirect to code.claude.com/docs/en/best-practices; the original text is superseded. — [redirect](https://www.anthropic.com/engineering/claude-code-best-practices)
- sixhobbits "Claude Code is all you need" (2025-08-11, 851 pts) and Puzzmo "6 weeks of Claude Code" (2025-07-31, 581 pts) predate Claude Code 2.0 (2025-09-29), auto mode (2026-03-25) and the 5.x models; treat as historical. — [HN data](https://hn.algolia.com/api/v1/search?query=claude%20code&tags=story&numericFilters=points%3E300&hitsPerPage=40)
- Boris Tane (Feb 2026): "The built-in plan mode sucks" and "no degradation past 50% context" are anecdotal, tied to a model/version at the time. No updated date. — [post](https://boristane.com/blog/how-i-use-claude-code/)
- Arpan Patel (May 2026) references Opus 4.7, `CLAUDE_CODE_AUTO_COMPACT_WINDOW=400000`, "300-400k token context-rot threshold", `--bare` "10x faster"; the official page now names Opus 5.5 default and says running out of context is rare. — [post](https://arps18.github.io/posts/claude-code-mastery/); [official](https://code.claude.com/docs/en/best-practices)
- Systima numbers are a July 2026 snapshot on 2.1.207 (current is about 2.1.322); also says Claude Code ignored AGENTS.md in the tested version, which changed with the Sep 2026 AGENTS.md fallback. — [Systima](https://systima.ai/blog/claude-code-vs-opencode-token-overhead); [Willison](https://simonwillison.net/2026/Sep/18/thariq-shihipar/)
- Vendor content to weight accordingly: cubic.dev (code-review product), Apiiro (security vendor), claude.com/blog customer stories (JPMorganChase Nov 9, Curative Nov 10, J.Crew Nov 12, 2026 - marketing, no config guidance). — [claude.com/blog](https://claude.com/blog)
- Search-result listicles (eesel.ai, axify.io "39 best practices", felo.ai, aiorg.dev, claudedirectory.org, etc.) mostly paraphrase Anthropic's docs; a "Munder Difflin" post explicitly says it summarizes Anthropic's docs. — [Munder Difflin](https://munderdiffl.in/blog/claude-code-best-practices/)

### Inferences
- Staleness heuristic: anything citing Opus 4.x, "context is your main constraint", or ALL CAPS emphasis tips predates the current docs.

### Gaps
- Did not individually read the SEO listicles; classification is from titles/snippets and the search tool's own caveats.

## Q3. Where does post advice conflict with current official docs?

### Takeaway
The official best-practices page now contains a "What you can stop doing" table that explicitly retires popular advice from 2025-era guides.

### Cited Findings
- Old advice "context window is your main constraint, manage it aggressively" is retired: most current models have 1M tokens and automatic compaction; `/clear` between tasks still recommended. Conflicts with 2025 guides and with Patel's context-rot threshold tuning. — [official best practices](https://code.claude.com/docs/en/best-practices)
- "Add IMPORTANT/ALL CAPS" is retired: emphasis makes Claude over-apply; use a hook or deny rule for non-negotiable rules. — [official](https://code.claude.com/docs/en/best-practices)
- "Use subagents to protect context" and "delegate to a subagent for a better answer" are retired; subagents cost extra tokens (consistent with Systima's 4.2x measurement). — [official](https://code.claude.com/docs/en/best-practices); [Systima](https://systima.ai/blog/claude-code-vs-opencode-token-overhead)
- `think hard`/`think harder` keywords are plain prompt text; effort is the control (`ultrathink` still works per turn). "Keep going / don't be lazy" prompts discouraged; use `/goal` or a Stop hook. — [official](https://code.claude.com/docs/en/best-practices)
- "Describe architecture and file layout in CLAUDE.md" is retired: write only what Claude can't see. — [official](https://code.claude.com/docs/en/best-practices)
- Official page: new terminal and VS Code sessions start in auto mode; non-interactive `-p` needs `--permission-mode auto`. Guides describing manual/prompting as the default are outdated. Crosley matches this (non-interactive stays manual unless configured). — [official](https://code.claude.com/docs/en/best-practices); [Crosley](https://blakecrosley.com/guides/claude-code)
- Official: deny rules and PreToolUse hooks run before the classifier; auto mode is a model judgement, so "never" rules belong in deny rules/hooks/sandbox. Consistent with cubic's precedence claim; contradicts any post equating auto mode with safety (cf. Rehberger bypass). — [official](https://code.claude.com/docs/en/best-practices); [Willison 2026-08-27](https://simonwillison.net/2026/Aug/27/breaking-claude-code-opus-5-auto-mode/)
- Official: AGENTS.md is read when no CLAUDE.md exists (changelog thread HN 741 pts, 2026-09-18). Posts stating Claude Code ignores AGENTS.md (Systima, July 2026 version) are version-stale. — [HN item listing](https://hn.algolia.com/api/v1/search?query=claude%20code&tags=story&numericFilters=points%3E300&hitsPerPage=40)
- Unverified against docs (flag for checking in the audit): cubic's 600s default hook timeout, "eight consecutive Stop hook blocks", `onFailure: "block"` (v2.1.295), "mods can approve a call a hook blocked", 33 event count; Patel's `agent: read-only` frontmatter, `/loop` 3 days, `claude project purge`. — [cubic](https://www.cubic.dev/blog/claude-code-hooks); [Patel](https://arps18.github.io/posts/claude-code-mastery/)
- Crosley "Opus 5.5 default" agrees with official docs naming Opus 5.5 at medium effort default. — [official](https://code.claude.com/docs/en/best-practices)

### Inferences
- Official docs are quickly changing; a post more than about 3 months old (pre-Aug 2026) likely mentions a model or default that has changed.

### Gaps
- Did not diff against the permissions, hooks, MCP and memory reference pages individually; only the best-practices page was read (51KB).

## Q4. Which authors/sites update posts when Claude Code changes?

### Takeaway
Only Crosley's guide visibly tracks versions (updated 2026-11-11, per-version notes). Anthropic's docs replace the old engineering post in place. Willison dates each entry and rarely edits (a running log, not a guide). Most others show no updated date.

### Cited Findings
- Crosley guide: updated 2026-11-11, states current as of v2.1.322 with per-version notes. — [guide](https://blakecrosley.com/guides/claude-code)
- Anthropic: engineering best-practices post replaced via 308 redirect to the docs page, which carries current defaults (auto mode, Opus 5.5, 1M window). — [redirect](https://www.anthropic.com/engineering/claude-code-best-practices)
- Tane and Patel show no updated date. cubic gives only a "docs as of Oct 12, 2026" reference date and conflicting publication dates. Systima explicitly labels results a July 2026 snapshot. — [Tane](https://boristane.com/blog/how-i-use-claude-code/); [cubic](https://www.cubic.dev/blog/claude-code-hooks); [Systima](https://systima.ai/blog/claude-code-vs-opencode-token-overhead)
- A GitHub repo "claude-code-setup-guide" advertises a July 2026 snapshot (not verified). — [repo](https://github.com/AlexandrG539/claude-code-setup-guide)

### Inferences
- Dated-snapshot posts (Systima, Willison) are more trustworthy for "as of" claims than undated evergreen guides.

### Gaps
- No longitudinal check (e.g. Wayback) of whether any author revised posts; "track record" only inferable from visible dates.

## Official Anthropic posts (dates as listed on anthropic.com/engineering, fetched 2026-11-12)

Listing shows 24 of 28 posts; URLs below are as shown on the page (relative paths shown as /research/...; the HN-linked canonical engineering URLs use /engineering/, e.g. april-23-postmortem), so confirm the exact path before linking.
- Claude Code: Best practices for agentic coding, Apr 18, 2025 (now redirects to docs).
- Beyond permission prompts: making Claude Code more secure and autonomous (sandboxing), Oct 20, 2025.
- Equipping agents for the real world with Agent Skills, Oct 16, 2025.
- Effective context engineering for AI agents, Sep 29, 2025.
- Code execution with MCP: building more efficient agents, Nov 4, 2025.
- Writing effective tools for agents, Sep 11, 2025.
- A postmortem of three recent issues, Sep 17, 2025.
- How we built Claude Code auto mode: a safer way to skip permissions, Mar 25, 2026.
- An update on recent Claude Code quality reports, Apr 23, 2026 (HN 942 pts).
- How we contain Claude across products, May 25, 2026.
- Redesigning source control at Anthropic, Oct 13, 2026; The components of agent memory, Nov 6, 2026.
- Also agents-related: Effective harnesses for long-running agents (Nov 26, 2025), Harness design for long-running application development (Mar 24, 2026), Scaling Managed Agents (Apr 8, 2026), Building a C compiler with parallel Claudes (Feb 5, 2026).
— [anthropic.com/engineering](https://www.anthropic.com/engineering); [HN listing for postmortem URL](https://hn.algolia.com/api/v1/search?query=claude%20code&tags=story&numericFilters=points%3E300&hitsPerPage=40)
- claude.com/blog Claude Code-tagged posts (as of Nov 12, 2026 view of 11 of 318): customer stories and the Fable 5.2 / Mythos 5.2 release (Nov 9, 2026); none are best-practice guides. — [claude.com/blog](https://claude.com/blog)
- Official canonical guide now: [code.claude.com/docs/en/best-practices](https://code.claude.com/docs/en/best-practices).
