# Setup Audit for Claude Code

An evidence-backed auditor for your **whole** Claude Code setup. It reads your user and
per-project settings, permissions, hooks, MCP servers, skills, plugins, CLAUDE.md files, memory,
and usage and transcript data, and compares them with the **current** official docs. You get a
short, ranked list of fixes for:

- **Security**: risky standing permissions, secrets baked into rules, missing deny rules, broken
  hooks, sandbox gaps.
- **Cost & context**: your *measured* per-session context baseline, oversized CLAUDE.md files,
  unused MCP servers, skill-listing overflow, model and compaction settings.
- **Learning from repeated mistakes**: recurring friction and corrections across sessions and
  projects, turned into the lightest mechanism that stops them (memory → rule → hook → skill),
  and re-measured on the next run.

Proposals are applied only when you approve them, with backups and verification.

## Install

```
/plugin marketplace add senzelden/claude-setup-audit
/plugin install setup-audit@claude-setup-audit
```

## Use

Ask naturally ("audit my Claude Code setup", "why is Claude Code so expensive?") or invoke it
directly:

```
/setup-audit:setup-audit focus=security depth=quick mode=audit
```

| Option | Values | Default |
|---|---|---|
| `focus` | `security`, `cost`, `learning`, `readiness`, or weights such as `cost:2,readiness:1` | equal; `readiness` opt-in |
| `depth` | `quick` (local snapshot only) · `full` (plus docs diff and what's new) | `full` |
| `scope` | `global` · `project` · `all` | `all` |
| `mode` | `audit` (read-only) · `propose` (report + diffs, then ask) · `apply` | `propose` |
| `report_dir` | where reports and trend data are kept | `~/.claude/audits` |

**Cost:** the local snapshot is a deterministic script that takes a few seconds. The model's
analysis is the main cost. For reference, a `depth=quick scope=project mode=audit` run on
Sonnet took about 4.5 minutes and ~$0.73 on one real machine. A `full` audit of all projects
reads more and costs more.

**Where reports go:** Claude Code protects files under `~/.claude`, so interactive sessions ask
you to approve the first write. In headless runs, point `report_dir` at a folder you own, or the
report goes to a temporary folder.

Deliberate choices can be recorded in `~/.claude/audits/decisions.yaml` with a `review_after`
date, so they aren't re-flagged until then.

## What it reads, writes and sends

- **Reads** `~/.claude/` (settings, plugins, memory, transcripts, `usage-data` if you ran
  `/insights`, prompt history) and `.claude/` + CLAUDE.md in projects you've used with Claude Code.
- **Writes** reports to `~/.claude/audits/` (`*-audit.md` and a machine-readable `*-audit.json`
  used for trends). It edits config only for approved items, after backing up to
  `~/.claude/backups/`.
- **Sends** nothing except requests for the public Claude Code docs pages (`depth=full`).
- Reports contain paths, rule text and memory excerpts. **Review them before sharing.**

## Measured, not guessed

Where possible it uses real numbers rather than character-count estimates. For example, the
context baseline is the sum of input and cache tokens of each session's first turn, taken from
your transcripts. The report labels every figure as measured or estimated.

## Prior art and credits

This project stands on ideas from these open-source tools. We reimplemented the ideas rather than
copying code, and we recommend them if you need a deeper, specialised tool:

| Idea | From |
|---|---|
| Report categories incl. *Parked*, per-item confirm before applying | [sam-illingworth/audit-setup](https://github.com/sam-illingworth/audit-setup) (MIT) |
| Decisions file for deliberate divergences | [hazzap123/clauditor](https://github.com/hazzap123/clauditor) (MIT) |
| Permission risk grouping and cleanup | [OpenVanta/GrantGuard](https://github.com/OpenVanta/GrantGuard) (MIT) |
| Dead references in CLAUDE.md, backtesting rules against sessions | [agent-clinic/claude-md-doctor](https://github.com/agent-clinic/claude-md-doctor) (MIT) |
| Unused MCP servers from transcript tool calls | [thomaschill/unclog](https://github.com/thomaschill/unclog) (MIT) |
| Dead hook scripts, cross-layer conflicts, write-blindness | [fedius01/ccinspect](https://github.com/fedius01/ccinspect) (MIT) |
| Eager vs lazy context cost, duplicate descriptions | [emreyildirim/claude-config-auditor](https://github.com/emreyildirim/claude-config-auditor) (MIT) |
| Measured improvement loop, one-shot edit rate | [adelaidasofia/claude-performance](https://github.com/adelaidasofia/claude-performance) (MIT) |
| Error fingerprint clustering, promotion with decay | [lisn0/learned-behavior](https://github.com/lisn0/learned-behavior) (MIT) |
| Propose-JSON fix flow with before/after | [aliksir/neko-harness-doctor](https://github.com/aliksir/neko-harness-doctor) (MIT) |
| audit / propose / apply modes, contradiction tracing | [into-the-intraverse/claude-perfectionist](https://github.com/into-the-intraverse/claude-perfectionist) (MIT) |
| Score trend across runs | [imadAttar/kaizen](https://github.com/imadAttar/kaizen) (idea only; no license file, nothing reused) |

## License

MIT, see [LICENSE](LICENSE).
