# Applied-change log

Lite records every change it makes or hands over in one Markdown file, so a later run can check in
on it, measure its effect and roll it back. The log is lite's own: it never reads or changes the
full `setup-audit` plugin's ledger, and rollback only reverses entries in this file.

Path: `~/.claude/setup-audit-lite/applied.md`. Lite adds nothing to the user's setup except its log
and its backups directory under `~/.claude/setup-audit-lite/`. Claude Code asks before each write
under `~/.claude`; if the user declines or the write is refused, say the log was not written and
show the entry in the conversation so the user can keep it.

When the log doesn't exist yet, the first entry creates it: Write the title line
`# setup-audit-lite applied changes`, a blank line, then the entry. Later entries are appended.

## What never goes into the log

The log holds the same kind of text as the report: file paths, key names, rule text and exact
before and after text that lite was shown. It never holds a value lite was not shown, and never a
credential:

- For files lite Read whole (CLAUDE.md, rules, skills, agents, commands, output styles, memory
  files), `before` and `after` are the exact text of the edited region. If that region holds
  anything secret-shaped, don't edit it and don't log it; report it instead.
- For settings files (handed over, never edited), `before`, `after`, `added` and `removed` contain
  only text from lines that the line allowlist in `reading-rules.md` showed, plus the new lines lite
  proposes. A line that was counted but not shown never appears, not even partly. A hand-over that
  could only be described in words has `not shown (described in why)` in all four fields.
- For changes to something on the never-opened list (an MCP server removal), `before`, `after`,
  `added` and `removed` are `not shown (described in why)` and `why` names the server and the
  command or panel used.
- Changes under hard limit 1 (credentials and secret values) get no log entry: the report gives the
  user manual steps without values.

## Backups

All backups go outside the project. Each entry has its own backup, taken right before that
entry's change, so two changes to the same file on the same day never share one:

`~/.claude/setup-audit-lite/backups/<YYYY-MM-DD>/<check-id>__<slug>`

- the date is the entry heading's date;
- the check id is the heading's check id, with a `:` target slug written as `_`
  (`SEC-risky-allow_git-push`);
- the slug is the file's absolute path with every `/` replaced by `__` (so
  `/home/me/code/shop/CLAUDE.md` becomes `__home__me__code__shop__CLAUDE.md`);
- Glob for the path first (existence only). If it exists (the same check on the same file on the
  same day), add `-2`, then `-3`, and so on. An existing backup is never overwritten.

The chosen path goes into the entry's `backup` field. No backup is ever written next to the edited
file or inside the project.

- Path A (files lite Read whole): lite Writes the backup from a full Read of the file made right
  before this entry's Edit.
- Path B (settings and other never-Read files): lite suggests a copy for the user to run before
  making the change,
  `! mkdir -p ~/.claude/setup-audit-lite/backups/<YYYY-MM-DD> && cp <file> ~/.claude/setup-audit-lite/backups/<YYYY-MM-DD>/<check-id>__<slug>`.
- No backup (`backup: none`): changes to something on the never-opened list, and hand-overs whose
  suggested copy isn't there: after the user says they ran it, Glob the suggested path (existence
  only); if nothing is there, record `none`.

The backups directory is on the never-opened list in `reading-rules.md`: lite never Reads or Greps
it, not even with a count, because a copied settings file holds the same values as the original.
When an entry becomes `kept` or `rolled-back`, offer to remove that entry's own backup (the path
in its `backup` field) with `! rm <backup path>`, which the user runs: one file, never a directory,
and never another entry's backup.

## File layout

The title line, then entries, oldest first. Each entry:

````markdown
## 2026-11-12 COST-claude-md-size

- `file`: ~/code/shop/CLAUDE.md
- `scope`: project
- `focus`: cost
- `why`: CLAUDE.md is 340 lines; the release procedure moved into the existing release skill.
- `before`:

  ```text
  ## Release
  1. Bump the version in pyproject.
  2. Tag and push.
  ```

- `after`:

  ```text
  ## Release
  Use the release skill.
  ```

- `added`:
  - `Use the release skill\.`
- `removed`:
  - `1\. Bump the version in pyproject\.`
  - `2\. Tag and push\.`
- `backup`: ~/.claude/setup-audit-lite/backups/2026-11-12/COST-claude-md-size____home__me__code__shop__CLAUDE.md
- `measure`: CLAUDE.md lines = 340
- `status`: applied
````

## Fields

The heading is `## <YYYY-MM-DD> <check-id>`: the date the change was applied or handed over and the
check id from `checklist.md` (with a short target slug after a colon when one check produced several
changes, e.g. `SEC-risky-allow:git-push`). Then these eleven fields, in this order:

- `file`: the absolute path of the edited file, with `~` for the home directory.
- `scope`: `user`, `project` or `local` (the settings scope or where the instruction file lives).
- `focus`: the area whose weight the change served at apply time: `security`, `cost`, `learning`,
  `readiness` or `hygiene`. The check-in measures impact by this area.
- `why`: one line: the finding and what the change does. No values.
- `before`: a fenced block with the exact text before the change, or `not shown (described in why)`.
- `after`: a fenced block with the exact text after the change, or `not shown (described in why)`.
- `added`: one Grep pattern per line the change adds or rewrites (its new form), as a list, or
  `none`, `not distinctive` or `not shown (described in why)`.
- `removed`: one Grep pattern per line the change removes or rewrites (its old form), as a list, or
  `none`, `not distinctive` or `not shown (described in why)`.
- `backup`: the path of this entry's own backup (see "Backups"), or `none`.
- `measure`: the before-measurement for the focus, as `<name> = <value>` (see "Measures" below), or
  `none` when the focus has no countable measure.
- `status`: one of the statuses below.

Lines a check-in adds after `status`:

- `checked`: `<YYYY-MM-DD>: <name> = <value now>; <still in place | not found | overridden in
  <file>>; user: <the user's impression in a few words>`. A later check-in replaces it.
- `rollback`: `pending`, while a handed-over reversal waits for the user (see "Rollback"). Removed
  when the reversal is confirmed.

Rules for `before` and `after` (what the user sees, and the reverse Edit on Path A):

- Copy the text exactly, including indentation. Use a fence longer than any run of backticks inside
  the text (three backticks unless the text itself contains a fence).
- When a change adds or removes whole lines, include one unchanged neighbouring line in both blocks
  as an anchor, so neither block is empty and the region is unique in the file. For settings, the
  anchor must itself be a line the allowlist showed. If no shown line is next to the change, the
  side without the changed line is `none (line added)` or `none (line removed)`, and the `why`
  line names the JSON path.
- One entry per change. Several changes to the same file are several entries.

Rules for `added` and `removed` (what the check-in and the rollback confirmation Grep):

- Each pattern is the core string of one changed line, not the whole line, so a re-format (by
  `/permissions`, `/config` or an editor) doesn't break it: for a permission rule, the quoted rule
  (`"Bash\(git push \*\)"`); for a setting, the quoted key, colon and value (`"model"\s*:\s*"opus"`);
  for an instruction line, its text without indentation or list marker.
- Regex metacharacters are escaped, so the pattern is used exactly as recorded.
- Each pattern must be distinctive in `file` when the entry is written: an `added` pattern counts 0
  there before the change, a `removed` pattern counts 1. Check this with count-only Grep (for
  Path A, by the Read). If no part of a line is distinctive, write `not distinctive` instead of the
  list, and the check-in falls back to the Read (Path A) or the user's word.
- A line that is rewritten appears in both lists: its new form under `added`, its old form under
  `removed`.

## Statuses

- `applied`: lite made the change with Edit, after writing the backup. Only for files lite Read
  whole.
- `handed-over`: a settings file, or anything else lite never Reads whole or never opens. Lite gave
  the user a paste-ready edit (JSON path, exact before and after lines, and the `/permissions` or
  `/config` route where one exists) or, for an MCP server, `claude mcp remove <name>` or the `/mcp`
  panel; the user made the change, or will.
- `rolled-back`: the change is no longer in place: reversed by lite at a check-in, reversed by the
  user and confirmed, or (for a hand-over) never made. The `checked` line says which.
- `kept`: the user confirmed at a check-in that the change stays. Kept entries get no more
  check-ins.

## Check-in

Entries with status `applied` or `handed-over` whose heading date is 7 or more days old get a
check-in at the start of the next run, and so does any entry with `rollback: pending` (the user can
also ask for a check-in any time). Per entry:

1. **Still present.**
   - Count-only Grep (`output_mode: count`) of each `added` and `removed` pattern in `file`. "Still
     in place" means every `added` pattern is found and every `removed` pattern counts 0. Anything
     else is "not found" (the change was undone or edited again); say which pattern differed.
   - A file lite may Read whole: also Read the region and compare it with `after`.
   - The check-in never Greps a file on the never-opened list, not even with a count. For those
     (an MCP server removal), presence comes from a fresh names-only `claude mcp list` paste, or
     from asking the user.
   - An entry whose texts are `not shown (described in why)`: ask the user whether the change is
     still in place.
2. **Not overridden.** For a settings change, look for the same key or rule in the other scopes'
   settings files with the reading rules (count-only Grep for the key name, the allowlist for shown
   lines). A removed allow rule that is still present in another scope, or a key that a higher-
   precedence file sets differently, is "overridden in <file>". For instruction files, look for a
   contradicting line in the other CLAUDE.md files and rules that load in the same project.
3. **Impact,** by the recorded `focus`, measured the same way as `measure` (below). Show before and
   after side by side and label the comparison "counts compared, not proof".
4. **The user's impression:** ask in one question whether the change helped, got in the way or made
   no difference.
5. **Decide:** keep (`kept`), roll back (below), or leave it for the next run (status unchanged).
   Update the entry with one Edit (old text from its heading through its last line) and add or
   replace the `checked` line. After `kept` or `rolled-back`, offer the `! rm` of that entry's
   backup.

## Measures

Recorded at apply time in `measure`, compared at the check-in. All counts, never content.

Session-log measures count sessions, not hits, and leave out every session that ran lite (the apply
session, the current one and earlier audits), as `reading-rules.md`, "Counting", describes: the
files that match the phrase minus the files that match `setup-audit-lite`, both from
`files_with_matches`.

- **cost:** the `/context` total the user pastes at apply time and again at the check-in; the MCP
  server count from a pasted `claude mcp list`; CLAUDE.md and rules line counts (count-only Grep for
  `^`); subagent use as sessions that call the agent tool (session-log measure above).
- **security:** number of broad allow rules (from shown rule lines); whether credential paths are
  denied (count of `Read` deny rules for them); sandbox state (the `enabled` and `failIfUnavailable`
  lines); overrides found in other scopes; and how often a now-denied action was still tried
  (session-log measure above, for a fixed phrase of the action).
- **learning:** how often the named mistake still recurs: the session-log measure above over the
  local session logs (`~/.claude/projects/**/*.jsonl`) with the same fixed phrase as at apply time.
  Record the phrase in `measure` (`sessions with "<phrase>" = 12 (setup-audit-lite sessions
  excluded)`) so the check-in repeats the same count; the phrase comes from the user's own words,
  never from config values.
- **readiness and hygiene:** the count the finding was about (missing hook scripts, dead paths,
  one-off allow rules, duplicate hooks), or `none`.

Session logs are never Read; only counted, as `reading-rules.md` says.

## Rollback

Lite only rolls back entries in this log, one entry at a time, after the user picks it.

**Status `applied` (lite edited the file):** Read the whole file first.

1. Prefer the reverse Edit: if the `after` text occurs exactly once, one Edit from `after` to
   `before`, so later changes to the file survive. Re-Read the region to confirm, and count-only
   Grep the patterns: every `removed` pattern is found again and every `added` pattern counts 0.
2. A full restore only when the reverse Edit can't apply and the file is otherwise unchanged:
   `after` occurs more than once, and the user confirms they haven't edited the file since. The
   entry's backup holds the file as it was just before this entry's change, so restoring it also
   undoes every later edit to the file: offer it only when no later entry on the same file is still
   in place (any status but `rolled-back`); otherwise use the reverse Edit or the manual reversal. Lite never Reads the backup,
   so the restore is a copy for the user to run: `! cp <the entry's backup path> <file>`.
3. If the `after` text is no longer found, lite reports the mismatch and hands over the manual
   reversal; it never forces a write. The same holds when `after` occurs more than once and the
   file has changed since: show both texts and say where the user should make the change.

**Status `handed-over` (a settings file or another never-Read file):** give a paste-ready reversal:
the JSON path, the exact `after` lines to replace and the `before` lines to put back, and the
`/permissions` or `/config` route where one exists. For an entry described in words, describe the
reversal in words. For an MCP server removal, say the user re-adds it from their own records (lite
never saw its configuration; adding a server is hard limit 3, so lite gives no add command). Lite
never edits the file itself.

The entry keeps status `handed-over` and gets a `rollback: pending` line until the user confirms,
in the same run, that they made the reversal. Then confirm it: count-only Grep of the patterns,
with the roles swapped (reversed means every `removed` pattern is found and every `added` pattern
counts 0), or the user's word for a file on the never-opened list, an entry described in words or
patterns marked `not distinctive`. Only then set `rolled-back` and remove the `rollback` line. If the user doesn't
confirm in this run, the pending line stays and the next run checks it again.

After a rollback write the `checked` line and suggest `/doctor` (or a restart) after any settings
change so the user sees that the settings still load.

## Reading the log

At the start of each run, Read the log if it exists. A missing log means "No applied-change log;
no check-ins due." An entry that doesn't follow the layout above (a heading without a date and
check id, or a missing `status`) is unparseable. Skip only those entries, say in one line how many
were skipped ("N log entries could not be parsed and were skipped."), and check in on the rest.
Never rewrite or repair the log without the user asking.
