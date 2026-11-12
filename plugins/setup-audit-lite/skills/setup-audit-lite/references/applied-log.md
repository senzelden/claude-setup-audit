# Applied-change log

Lite records every change it makes or hands over in one Markdown file, so a later run can check in
on it, measure its effect and roll it back. The log is lite's own: it never reads or changes the
full `setup-audit` plugin's ledger, and rollback only reverses entries in this file.

Path: `~/.claude/setup-audit-lite/applied.md`. It is the only file lite adds to the user's setup.
Claude Code asks before each write under `~/.claude`; if the user declines or the write is refused,
say the log was not written and show the entry in the conversation so the user can keep it.

## What never goes into the log

The log holds the same kind of text as the report: file paths, key names, rule text and exact
before and after text that lite was shown. It never holds a value lite was not shown, and never a
credential:

- For files lite may Read whole (CLAUDE.md, rules, skills, agents, commands, output styles, memory
  files), `before` and `after` are the exact text of the edited region. If that region holds
  anything secret-shaped, don't edit it and don't log it; report it instead.
- For settings files (handed over, never edited), `before` and `after` contain only lines that the
  line allowlist in `reading-rules.md` showed, plus the new lines lite proposes. A line that was
  counted but not shown never appears, not even partly.
- Changes under hard limit 1 (credentials and secret values) get no log entry: the report gives the
  user manual steps without values.

## File layout

The file starts with one title line, `# setup-audit-lite applied changes`, followed by entries,
oldest first. Each entry:

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

- `measure`: CLAUDE.md lines = 340
- `status`: applied
````

## Fields

The heading is `## <YYYY-MM-DD> <check-id>`: the date the change was applied or handed over and the
check id from `checklist.md` (with a short target slug after a colon when one check produced several
changes, e.g. `SEC-risky-allow:git-push`). Then these eight fields, in this order:

- `file`: the absolute path of the edited file, with `~` for the home directory.
- `scope`: `user`, `project` or `local` (the settings scope or where the instruction file lives).
- `focus`: the area whose weight the change served at apply time: `security`, `cost`, `learning`,
  `readiness` or `hygiene`. The check-in measures impact by this area.
- `why`: one line: the finding and what the change does. No values.
- `before`: a fenced block with the exact text before the change.
- `after`: a fenced block with the exact text after the change.
- `measure`: the before-measurement for the focus, as `<name> = <value>` (see "Measures" below), or
  `none` when the focus has no countable measure.
- `status`: one of the statuses below.

A check-in adds one more line after `status`:

- `checked`: `<YYYY-MM-DD>: <name> = <value now>; <still in place | not found | overridden in
  <file>>; user: <the user's impression in a few words>`. A later check-in replaces it.

Rules for `before` and `after`:

- Copy the text exactly, including indentation. Use a fence longer than any run of backticks inside
  the text (three backticks unless the text itself contains a fence).
- When a change adds or removes whole lines, include one unchanged neighbouring line in both blocks
  as an anchor, so neither block is empty and the region is unique in the file. For settings, the
  anchor must itself be a line the allowlist showed; if no shown line is next to the change, the
  block holds only the changed line and the `why` line names the JSON path.
- One entry per change. Several changes to the same file are several entries.

## Statuses

- `applied`: lite made the change with Edit, after writing a dated backup (`<file>.bak-<YYYY-MM-DD>`,
  the heading's date) next to the file. Only for files lite may Read whole.
- `handed-over`: a settings file or any other file lite never Reads whole. Lite gave the user a
  paste-ready edit (JSON path, exact before and after lines, and the `/permissions` or `/config`
  route where one exists); the user made the change, or will.
- `rolled-back`: the change is no longer in place: reversed by lite at a check-in, reversed by hand,
  or (for a hand-over) never made. The `checked` line says which.
- `kept`: the user confirmed at a check-in that the change stays. Kept entries get no more
  check-ins.

## Check-in

Entries with status `applied` or `handed-over` whose heading date is 7 or more days old get a
check-in at the start of the next run (the user can also ask for one any time). Per entry:

1. **Still present.** Count-only Grep (`output_mode: count`) of each non-empty line of the `after`
   text in `file`, with regex metacharacters escaped. Every line found means "still in place". For a
   file lite may Read whole, Read the region instead and compare it exactly.
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
   Update the entry with one Edit (old text from its heading through its `status` line) and add or
   replace the `checked` line.

## Measures

Recorded at apply time in `measure`, compared at the check-in. All counts, never content.

- **cost:** the `/context` total the user pastes at apply time and again at the check-in; the MCP
  server count from a pasted `claude mcp list`; CLAUDE.md and rules line counts (count-only Grep for
  `^`); subagent use as a count (count-only Grep of session logs for the agent tool name).
- **security:** number of broad allow rules (from shown rule lines); whether credential paths are
  denied (count of `Read` deny rules for them); sandbox state (the `enabled` and `failIfUnavailable`
  lines); overrides found in other scopes; and how often a now-denied action was still tried
  (count-only Grep of session logs for a fixed phrase of the action).
- **learning:** how often the named mistake still recurs: count-only Grep of the local session logs
  (`~/.claude/projects/**/*.jsonl`) with the same fixed phrase as at apply time. Record the phrase in
  `measure` (`log hits for "<phrase>" = 12`) so the check-in repeats the same count; the phrase comes
  from the user's own words, never from config values.
- **readiness and hygiene:** the count the finding was about (missing hook scripts, dead paths,
  one-off allow rules, duplicate hooks), or `none`.

Session logs are never Read; only counted, as `reading-rules.md` says.

## Rollback

Lite only rolls back entries in this log, one entry at a time, after the user picks it.

**Status `applied` (lite edited the file):**

1. Read the file and its backup (`<file>.bak-<date>` from the heading). If the file equals the
   backup with only this entry's `before` replaced by `after`, nothing else changed since: Write the
   backup's content back over the file.
2. Otherwise, if the `after` text occurs exactly once, reverse only this edit: one Edit from `after`
   to `before`, so later changes to the file survive. Re-Read the region to confirm.
3. If the `after` text is no longer found, lite reports the mismatch and hands over the manual
   reversal; it never forces a write. The same holds when `after` occurs more than once: show both
   texts and say where the user should make the change.

**Status `handed-over` (a settings file or another never-Read file):** give a paste-ready reversal:
the JSON path, the exact `after` lines to replace and the `before` lines to put back, and the
`/permissions` or `/config` route where one exists. Lite never edits the file itself. At the next
check-in, a count-only Grep of the `before` lines confirms the reversal.

After a rollback set `status` to `rolled-back` and write the `checked` line. Suggest `/doctor` (or a
restart) after any settings change so the user sees that the settings still load.

## Reading the log

At the start of each run, Read the log if it exists. A missing log means "No applied-change log;
no check-ins due." A log whose entries don't follow the layout above (a heading without a date and
check id, or a missing `status`) is unparseable for those entries: say "The applied-change log
could not be parsed; no check-ins this run." in one line, and never rewrite or repair it without
the user asking.
