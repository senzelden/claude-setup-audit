# Harness Overhead Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure from transcripts the context that hooks inject (attributed to plugins), the growth of the skill listing, subagent spend and entrypoint mix, and flag enabled plugin hooks that invoke a model, in a new optional `harness_overhead` snapshot section.

**Architecture:** `collect_transcripts` keeps its single bounded pass and adds raw per-file accumulators under a private `_harness` key. A new pure module `scripts/harness.py` builds the enabled-plugin hook index from the registry, matches commands, scans hook scripts statically and assembles the section; `collect.main` wires it and pops `_harness` before serialization. Skill counting is fixed in `extensions.py`.

**Tech Stack:** Python 3.11+ standard library only; `unittest`; the bundled snapshot schema evaluator (`snapshot_contract.py`).

**Spec:** `docs/superpowers/specs/2026-09-29-harness-overhead-design.md`

## Global Constraints

- Stdlib only. No new dependencies.
- Tests use temporary fake homes (`FakeHome` in `tests/test_collect.py`); never read the real `~/.claude`.
- No transcript content, hook output, command strings or script text in the snapshot. Plugin names, relative script paths, counts, sizes and dates only.
- Transcript attachment fields are undocumented: every field is optional; absence means "not observed", never zero.
- Tokens are `chars // 4` and labeled estimated. Medians/p90 use `collect.pct` and are rounded to `int` (the schema evaluator has no `number` type).
- Snapshot stays version 1; `harness_overhead` is optional and additive.
- Static scan reads at most 64 KiB per script; symlinks and paths escaping the plugin root are skipped and mark the scan incomplete.
- Commits: stage explicit paths; message ends with exactly one trailer `Assisted-by: Claude:claude-opus-5-5`.
- Gate: `python3 -m unittest discover -s tests -v`, `python3 tests/check_snapshot_schema.py`, `git diff --check`, coverage ≥ 88 (see `docs/development.md` for the coverage command).
- Bash sandbox is broken in this environment (seccomp); run commands with the sandbox disabled.

Paths below: `S = plugins/setup-audit/skills/setup-audit`.

## Review Focus

1. A hook command recorded with different quoting/whitespace than `hooks.json` → `unattributed`, never a wrong plugin. (Task 2 test `test_near_miss_command_is_unattributed`.)
2. A transcript with an injection record but no paired `hook_success` → counted as `unattributed`, not dropped. (Task 5 test `test_unpaired_injection_is_unattributed`.)
3. A session with injections on startup and compact → one session, summed chars. (Task 5 test `test_startup_and_compact_sum_to_one_session`.)
4. `skillCount` missing or a string → that listing ignored, not a crash. (Task 4 test `test_bad_skill_listing_fields_are_ignored`.)
5. Streamed assistant records sharing a message id → counted once for both main and subagent tokens. (Task 4 test `test_duplicate_message_ids_counted_once`.)

---

### Task 1: Count only `SKILL.md` as a plugin skill

**Files:**
- Modify: `S/scripts/extensions.py` (`component_files`, the `paths.extend(...)` line)
- Test: `tests/test_extensions.py`

**Interfaces:**
- Produces: plugin `components` entries with `kind == 'skills'` exist only for files named `SKILL.md`. Task 5 counts them per plugin.

- [ ] **Step 1: Write the failing test** (append to `ExtensionInventory`)

```python
    def test_only_skill_md_counts_as_a_skill(self):
        root = os.path.join(self.claude, 'plugins/cache/market/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'demo@market': [{'scope': 'user', 'installPath': root, 'version': '1'}]}})
        self.write('.claude/plugins/cache/market/demo/1/.claude-plugin/plugin.json', {'name': 'demo'})
        self.write('.claude/plugins/cache/market/demo/1/skills/a/SKILL.md', '---\ndescription: A\n---\nBody')
        self.write('.claude/plugins/cache/market/demo/1/skills/a/reference.md', 'Reference doc')
        self.write('.claude/plugins/cache/market/demo/1/agents/helper.md', '---\nname: helper\n---\nAgent')
        plugin = self.scan()['plugins'][0]
        skills = [c for c in plugin['components'] if c['kind'] == 'skills']
        self.assertEqual([os.path.basename(c['source']) for c in skills], ['SKILL.md'])
        self.assertEqual(len([c for c in plugin['components'] if c['kind'] == 'agents']), 1)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_extensions.ExtensionInventory.test_only_skill_md_counts_as_a_skill -v`
Expected: FAIL (`['SKILL.md', 'reference.md']` or reversed != `['SKILL.md']`).

- [ ] **Step 3: Implement**

In `component_files`, replace the `paths.extend(...)` line:

```python
            wanted = (lambda f: f == 'SKILL.md') if kind == 'skills' else (lambda f: f.endswith('.md'))
            paths.extend(os.path.join(directory, f) for f in sorted(files) if wanted(f))
```

- [ ] **Step 4: Run the extensions and collect tests**

Run: `python3 -m unittest tests.test_extensions tests.test_collect -v`
Expected: PASS. If a test asserted the old inflated count, it is asserting the bug: update it and say so in the commit body.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/extensions.py tests/test_extensions.py
git commit -m "Count only SKILL.md as a plugin skill

Reference files under a skill directory inflated candidate_skills.

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 2: Hook index from the plugin registry, command matching, startup-hook estimate

**Files:**
- Create: `S/scripts/harness.py`
- Modify: `S/scripts/collect.py` (`collect_global`, `plugin_session_start_hooks`, `main`)
- Test: `tests/test_harness.py` (new)

**Interfaces:**
- Produces:
  - `harness.hook_index(claude: str, settings: list[dict]) -> tuple[list[dict], list[str]]` — entries `{"plugin": str, "version": str, "root": str, "event": str, "matcher": str|None, "command": str, "source": str}` (`source` = absolute path of the `hooks.json` or `plugin.json` it came from); second value is sorted incomplete reasons (`"plugin_root_unreadable"`). Only plugins with a `True` value in any settings layer's `enabled_plugins`. Raw commands stay in memory; callers never serialize them.
  - `harness.match_command(index: list[dict], command: str|None) -> tuple[str|None, str]` — `(plugin, "matched")`, `(None, "ambiguous")`, `(None, "unattributed")`.
  - `collect.plugin_session_start_hooks(index: list[dict]) -> list[dict]` — `{"plugin", "version", "matchers", "est_injected_tokens", "basis": "file_size_estimate"}`.

- [ ] **Step 1: Write the failing tests** (`tests/test_harness.py`)

```python
"""Harness overhead: hook index, attribution, static scan, assembly. Fake homes only."""
import json
import os
import time
import unittest
from test_collect import FakeHome, collect
import harness


def install(t, name='demo', market='market', version='1', hooks=None, files=None, enabled=True, manifest=None):
    root = os.path.join(t.claude, 'plugins', 'cache', market, name, version)
    reg_path = os.path.join(t.claude, 'plugins', 'installed_plugins.json')
    reg = json.load(open(reg_path)) if os.path.exists(reg_path) else {'version': 2, 'plugins': {}}
    reg['plugins'][f'{name}@{market}'] = [{'scope': 'user', 'installPath': root, 'version': version}]
    t.write('.claude/plugins/installed_plugins.json', reg)
    t.write(os.path.relpath(os.path.join(root, '.claude-plugin', 'plugin.json'), t.home),
            manifest or {'name': name})
    if hooks is not None:
        t.write(os.path.relpath(os.path.join(root, 'hooks', 'hooks.json'), t.home), {'hooks': hooks})
    for rel, text in (files or {}).items():
        t.write(os.path.relpath(os.path.join(root, rel), t.home), text)
    return root, {'path': 'settings.json', 'enabled_plugins': {f'{name}@{market}': enabled}}


def session_start(command):
    return {'SessionStart': [{'matcher': 'startup', 'hooks': [{'type': 'command', 'command': command}]}]}


class HookIndex(FakeHome):
    def test_registry_install_path_wins_over_newer_cache_copy(self):
        root, s = install(self, hooks=session_start('"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" start'),
                          files={'skills/using-demo/SKILL.md': 'x' * 400})
        stale = os.path.join(self.claude, 'plugins/cache/market/demo/2/hooks/hooks.json')
        self.write(os.path.relpath(stale, self.home), {'hooks': session_start('stale')})
        future = time.time() + 1000
        os.utime(stale, (future, future))
        index, reasons = harness.hook_index(self.claude, [s])
        self.assertEqual([e['command'] for e in index], ['"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" start'])
        self.assertEqual(index[0]['root'], root)
        self.assertEqual(reasons, [])
        found = collect.plugin_session_start_hooks(index)
        self.assertEqual(found, [{'plugin': 'demo@market', 'version': '1', 'matchers': ['startup'],
                                  'est_injected_tokens': 100, 'basis': 'file_size_estimate'}])

    def test_disabled_plugin_and_inline_manifest_hooks(self):
        install(self, name='off', hooks=session_start('a'), enabled=False)
        _, s = install(self, name='inline', manifest={'name': 'inline', 'hooks': {'hooks': session_start('b')}})
        index, _ = harness.hook_index(self.claude, [s, {'enabled_plugins': {'off@market': False}}])
        self.assertEqual([(e['plugin'], e['command']) for e in index], [('inline@market', 'b')])

    def test_root_outside_plugin_storage_is_incomplete(self):
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'ext@market': [{'scope': 'user', 'installPath': '/elsewhere', 'version': '1'}]}})
        index, reasons = harness.hook_index(self.claude, [{'enabled_plugins': {'ext@market': True}}])
        self.assertEqual((index, reasons), ([], ['plugin_root_unreadable']))

    def test_match_command(self):
        index = [{'plugin': 'a@m', 'command': 'run'}, {'plugin': 'b@m', 'command': 'run'},
                 {'plugin': 'c@m', 'command': 'only-c'}]
        self.assertEqual(harness.match_command(index, 'only-c'), ('c@m', 'matched'))
        self.assertEqual(harness.match_command(index, 'run'), (None, 'ambiguous'))
        self.assertEqual(harness.match_command(index, None), (None, 'unattributed'))

    def test_near_miss_command_is_unattributed(self):
        index = [{'plugin': 'c@m', 'command': '"${CLAUDE_PLUGIN_ROOT}/x.sh" start'}]
        self.assertEqual(harness.match_command(index, '${CLAUDE_PLUGIN_ROOT}/x.sh start'), (None, 'unattributed'))
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_harness -v`
Expected: ERROR `ModuleNotFoundError: No module named 'harness'`.

- [ ] **Step 3: Implement `harness.py` (index and matching)**

```python
"""Harness overhead: plugin hook index, command attribution, static hook scan, assembly.

Reads the plugin registry and hook files only; never runs a hook. Raw command strings stay in
memory for matching and are never part of the returned snapshot section.
"""
import json
import os

MAX_HOOK_FILE = 1024 * 1024


def _json(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            data = json.loads(f.read(MAX_HOOK_FILE + 1)[:MAX_HOOK_FILE])
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _entries(plugin, version, root, source, data):
    hooks = data.get('hooks', data) if isinstance(data, dict) else None
    out = []
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict):
                continue
            for h in group.get('hooks', []) if isinstance(group.get('hooks'), list) else []:
                if isinstance(h, dict) and isinstance(h.get('command'), str):
                    out.append(dict(plugin=plugin, version=version, root=root, event=event,
                                    matcher=group.get('matcher'), command=h['command'], source=source))
    return out


def hook_index(claude, settings):
    """Hook commands of enabled plugins, resolved through the registry installPath."""
    enabled = {k for s in settings for k, v in (s.get('enabled_plugins') or {}).items() if v is True}
    registry = (_json(os.path.join(claude, 'plugins', 'installed_plugins.json')) or {}).get('plugins')
    storage = os.path.realpath(os.path.join(claude, 'plugins'))
    index, reasons = [], set()
    for name in sorted(enabled):
        rows = registry.get(name) if isinstance(registry, dict) else None
        for row in rows if isinstance(rows, list) else []:
            root = row.get('installPath') if isinstance(row, dict) else None
            if (not isinstance(root, str) or not os.path.isabs(root)
                    or not os.path.realpath(root).startswith(storage + os.sep) or not os.path.isdir(root)):
                reasons.add('plugin_root_unreadable')
                continue
            version = str(row.get('version', 'unknown'))
            manifest_path = os.path.join(root, '.claude-plugin', 'plugin.json')
            inline = (_json(manifest_path) or {}).get('hooks')
            if isinstance(inline, dict):
                index += _entries(name, version, root, manifest_path, inline)
            hooks_path = os.path.join(root, 'hooks', 'hooks.json')
            if os.path.isfile(hooks_path) and not os.path.islink(hooks_path):
                index += _entries(name, version, root, hooks_path, _json(hooks_path) or {})
    return index, sorted(reasons)


def match_command(index, command):
    """Exact string match only; a near miss is unattributed, never guessed."""
    if not isinstance(command, str):
        return None, 'unattributed'
    plugins = {e['plugin'] for e in index if e['command'] == command}
    if len(plugins) == 1:
        return plugins.pop(), 'matched'
    return None, ('ambiguous' if plugins else 'unattributed')
```

- [ ] **Step 4: Rewrite `plugin_session_start_hooks` in `collect.py` and wire it**

Add `import harness` next to `import extensions`. Delete the `out["plugin_session_start_hooks"] = ...` line from `collect_global`. Replace the function:

```python
def plugin_session_start_hooks(index):
    """Enabled plugins with SessionStart hooks, with a file-size fallback estimate.

    Measured injection comes from transcripts (harness_overhead.injected_context); this estimate
    is only the fallback when no session in the window recorded injected context.
    """
    found = {}
    for e in index:
        if e['event'] != 'SessionStart':
            continue
        item = found.setdefault(e['plugin'], {'plugin': e['plugin'], 'version': e['version'], 'matchers': [],
                                              'root': e['root']})
        item['matchers'].append(e['matcher'])
    out = []
    for item in found.values():
        root = item.pop('root')
        # Rough payload size: files the plugin's session-start hook script is likely to inject.
        injected = sum(os.path.getsize(p) for p in glob.glob(os.path.join(root, "skills", "using-*", "SKILL.md")))
        out.append(dict(item, est_injected_tokens=injected // 4 or None, basis='file_size_estimate'))
    return sorted(out, key=lambda x: x['plugin'])
```

In `main()`, directly after the `settings = ...` line:

```python
    hook_index, hook_index_reasons = harness.hook_index(CLAUDE, settings)
    snap["global"]["plugin_session_start_hooks"] = plugin_session_start_hooks(hook_index)
```

- [ ] **Step 5: Run the tests**

Run: `python3 -m unittest tests.test_harness tests.test_collect -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/harness.py plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_harness.py
git commit -m "Index enabled plugin hooks through the registry

Startup-hook estimates no longer guess the live copy from cache mtimes and now read
enabled plugins from every settings layer.

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 3: Static scan for model-invoking hooks

**Files:**
- Modify: `S/scripts/harness.py`
- Test: `tests/test_harness.py`

**Interfaces:**
- Consumes: `hook_index` entries (Task 2).
- Produces: `harness.scan_hooks(index: list[dict]) -> tuple[list[dict], list[str]]` — findings `{"plugin", "hook_event", "file", "line", "pattern"}` (`file` relative to the plugin root; `line` is `None` when the match is in the command string itself, then `file` is the relative hooks/manifest path); reasons subset of `script_unresolved`, `script_truncated`. Findings are deduplicated and sorted.

- [ ] **Step 1: Write the failing tests** (append)

```python
class StaticScan(FakeHome):
    def scan(self, hooks, files):
        _, s = install(self, hooks=hooks, files=files)
        index, _ = harness.hook_index(self.claude, [s])
        return harness.scan_hooks(index)

    def stop(self, command):
        return {'Stop': [{'hooks': [{'type': 'command', 'command': command}]}]}

    def test_each_pattern_in_a_referenced_script(self):
        script = '#!/bin/sh\n# claude -p "commented out"\necho hi\nclaude -p "reflect" > out\n'
        py = 'import os\nfrom claude_agent_sdk import query\n'
        js = "import x from '@anthropic-ai/claude-agent-sdk'\nconst c = new Anthropic()\n"
        found, reasons = self.scan(
            {'Stop': [{'hooks': [{'type': 'command', 'command': 'bash "${CLAUDE_PLUGIN_ROOT}/hooks/r.sh"'},
                                 {'type': 'command', 'command': 'python3 ${CLAUDE_PLUGIN_ROOT}/hooks/r.py'},
                                 {'type': 'command', 'command': 'node $CLAUDE_PLUGIN_ROOT/hooks/r.mjs'}]}]},
            {'hooks/r.sh': script, 'hooks/r.py': py, 'hooks/r.mjs': js})
        self.assertEqual(reasons, [])
        self.assertEqual([(f['file'], f['line'], f['pattern']) for f in found], [
            ('hooks/r.mjs', 1, 'agent_sdk_js'), ('hooks/r.mjs', 2, 'anthropic_client'),
            ('hooks/r.py', 2, 'agent_sdk_py'), ('hooks/r.sh', 4, 'claude_print')])
        self.assertTrue(all(f['plugin'] == 'demo@market' and f['hook_event'] == 'Stop' for f in found))

    def test_pattern_in_the_command_itself(self):
        found, _ = self.scan(self.stop('claude --print "summarize"'), {})
        self.assertEqual([(f['file'], f['line'], f['pattern']) for f in found],
                         [('hooks/hooks.json', None, 'claude_print')])

    def test_similar_words_do_not_match(self):
        found, _ = self.scan(self.stop('claude-setup -p x; myclaude --print'), {})
        self.assertEqual(found, [])

    def test_symlink_escape_missing_and_truncation(self):
        outside = self.write('outside.sh', 'claude -p x\n')
        root, s = install(self, hooks=self.stop('sh ${CLAUDE_PLUGIN_ROOT}/hooks/link.sh; '
                                                 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/../../../../outside.sh; '
                                                 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/missing.sh; '
                                                 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/big.sh'),
                          files={'hooks/big.sh': 'x\n' * 40000 + 'claude -p late\n'})
        os.symlink(outside, os.path.join(root, 'hooks', 'link.sh'))
        index, _ = harness.hook_index(self.claude, [s])
        found, reasons = harness.scan_hooks(index)
        self.assertEqual(found, [])
        self.assertEqual(reasons, ['script_truncated', 'script_unresolved'])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_harness.StaticScan -v`
Expected: ERROR `AttributeError: module 'harness' has no attribute 'scan_hooks'`.

- [ ] **Step 3: Implement** (append to `harness.py`; add `import re` and `import shlex` at the top)

```python
MAX_SCRIPT = 64 * 1024
# Word boundaries exclude names such as claude-setup or myclaude.
PATTERNS = (
    ('claude_print', re.compile(r'(?<![\w.-])claude(?![\w.-])[^\n|;&]*?\s(?:-p|--print)(?![\w-])')),
    ('agent_sdk_py', re.compile(r'\bclaude_agent_sdk\b')),
    ('agent_sdk_js', re.compile(r'@anthropic-ai/claude-agent-sdk')),
    ('anthropic_client', re.compile(r'anthropic\.Anthropic\(|new Anthropic\(|api\.anthropic\.com')),
)
ROOT_VARS = ('${CLAUDE_PLUGIN_ROOT}', '$CLAUDE_PLUGIN_ROOT')


def _matches(text):
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(('#', '//')):
            continue
        for pattern_id, rx in PATTERNS:
            if rx.search(line):
                yield number, pattern_id


def _script_paths(command, root):
    expanded = command
    for var in ROOT_VARS:
        expanded = expanded.replace(var, root)
    try:
        tokens = shlex.split(expanded, comments=False)
    except ValueError:
        tokens = expanded.split()
    for token in tokens:
        for part in token.split(';'):
            if part.startswith(root + os.sep) or part.startswith(root + '/..'):
                yield part


def scan_hooks(index):
    """Flag hook commands and plugin-local scripts that invoke a model. Never runs anything."""
    found, reasons = set(), set()
    for e in index:
        root = e['root']
        for _, pattern_id in _matches(e['command']):
            found.add((e['plugin'], e['event'], os.path.relpath(e['source'], root), None, pattern_id))
        for raw in _script_paths(e['command'], root):
            path = os.path.abspath(raw)
            real_root = os.path.realpath(root)
            if (not path.startswith(os.path.abspath(root) + os.sep) or os.path.islink(path)
                    or not os.path.realpath(path).startswith(real_root + os.sep) or not os.path.isfile(path)):
                reasons.add('script_unresolved')
                continue
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    text = f.read(MAX_SCRIPT + 1)
            except OSError:
                reasons.add('script_unresolved')
                continue
            if len(text) > MAX_SCRIPT:
                reasons.add('script_truncated')
                text = text[:MAX_SCRIPT]
            for line, pattern_id in _matches(text):
                found.add((e['plugin'], e['event'], os.path.relpath(path, root), line, pattern_id))
    rows = sorted(found, key=lambda r: (r[0], r[2], r[3] or 0, r[4]))
    return [dict(plugin=p, hook_event=ev, file=f, line=ln, pattern=pid) for p, ev, f, ln, pid in rows], sorted(reasons)
```

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest tests.test_harness -v`
Expected: PASS. Red-proof: temporarily delete the `startswith(('#', '//'))` skip and confirm `test_each_pattern_in_a_referenced_script` fails; restore.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/harness.py tests/test_harness.py
git commit -m "Flag enabled plugin hooks that invoke a model

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 4: Raw harness signals in the transcript pass

**Files:**
- Modify: `S/scripts/collect.py` (`collect_transcripts`)
- Test: `tests/test_harness.py`

**Interfaces:**
- Produces: `collect_transcripts(...)["_harness"]` (private, popped in `main`, Task 5) with:
  - `"sessions": int` — main files with ≥1 in-window record
  - `"injections": list[tuple[str, str, str|None, int]]` — `(main_path, hook_event, tool_use_id, chars)`
  - `"commands": dict[tuple[str, str], str]` — `(main_path, tool_use_id) -> command` from `hook_success`
  - `"listings": list[tuple[float, int, int]]` — `(timestamp, skill_count, chars)`, first initial listing per main file
  - `"entrypoints": Counter` — first in-window user/assistant `entrypoint` per main file; non-string → `"other"`
  - `"main_tokens": dict[tuple[str, str], int]`, `"sub_tokens": dict[tuple[str, str], int]` — keyed `(project_dir, session_id)`; input + cache creation + cache read + output
  - `"malformed": int` — lines that are not a JSON object (main and subagent files)

- [ ] **Step 1: Write the failing tests** (append; helpers reused by Task 5)

```python
def now_iso(offset=0):
    return collect.datetime.fromtimestamp(time.time() + offset, collect.timezone.utc).isoformat()


def attachment(kind, **fields):
    return {'type': 'attachment', 'timestamp': now_iso(), 'attachment': dict(type=kind, **fields)}


def assistant(msg_id, tokens, sidechain=False, entrypoint='cli'):
    return {'type': 'assistant', 'timestamp': now_iso(), 'isSidechain': sidechain, 'entrypoint': entrypoint,
            'message': {'id': msg_id, 'usage': {'input_tokens': tokens, 'cache_creation_input_tokens': 0,
                                                'cache_read_input_tokens': 0, 'output_tokens': 0}}}


class TranscriptSignals(FakeHome):
    def put(self, rel, records, extra=''):
        self.write('.claude/projects/' + rel, '\n'.join(json.dumps(r) for r in records) + extra)

    def test_attachments_entrypoints_and_tokens(self):
        self.put('-p/s1.jsonl', [
            attachment('hook_success', toolUseID='t1', command='run', hookEvent='SessionStart'),
            attachment('hook_additional_context', toolUseID='t1', hookEvent='SessionStart', content='x' * 40),
            attachment('skill_listing', isInitial=True, skillCount=12, content='y' * 100),
            attachment('skill_listing', isInitial=False, skillCount=99, content='z'),
            assistant('m1', 10, entrypoint='sdk-py'), assistant('m2', 5, sidechain=True)])
        self.put('-p/s1/subagents/a.jsonl', [assistant('s1', 7), assistant('s2', 3)])
        old = attachment('hook_additional_context', toolUseID='t9', hookEvent='SessionStart', content='old')
        old['timestamp'] = now_iso(-40 * 86400)
        self.put('-p/s2.jsonl', [old])
        h = collect.collect_transcripts(days=30)['_harness']
        main = os.path.join(self.claude, 'projects', '-p', 's1.jsonl')
        self.assertEqual(h['sessions'], 1)
        self.assertEqual(h['injections'], [(main, 'SessionStart', 't1', 40)])
        self.assertEqual(h['commands'], {(main, 't1'): 'run'})
        self.assertEqual([(c, n) for _, c, n in h['listings']], [(12, 100)])
        self.assertEqual(dict(h['entrypoints']), {'sdk-py': 1})
        self.assertEqual(h['main_tokens'], {('-p', 's1'): 10})
        self.assertEqual(h['sub_tokens'], {('-p', 's1'): 10})

    def test_duplicate_message_ids_counted_once(self):
        self.put('-p/s1.jsonl', [assistant('m1', 10), assistant('m1', 10)])
        self.put('-p/s1/subagents/a.jsonl', [assistant('s1', 7), assistant('s1', 7)])
        h = collect.collect_transcripts(days=30)['_harness']
        self.assertEqual((h['main_tokens'], h['sub_tokens']), ({('-p', 's1'): 10}, {('-p', 's1'): 7}))

    def test_bad_skill_listing_fields_are_ignored(self):
        self.put('-p/s1.jsonl', [attachment('skill_listing', isInitial=True, skillCount='12', content='y'),
                                 attachment('skill_listing', isInitial=True, skillCount=3, content=None)])
        self.assertEqual([(c, n) for _, c, n in collect.collect_transcripts(days=30)['_harness']['listings']],
                         [(3, 0)])

    def test_malformed_lines_and_non_string_content(self):
        self.put('-p/s1.jsonl', [attachment('hook_additional_context', toolUseID=None, hookEvent='Stop',
                                            content={'k': 'v'}), [1, 2]], extra='\n{not json')
        h = collect.collect_transcripts(days=30)['_harness']
        self.assertEqual(h['malformed'], 2)
        self.assertEqual(h['injections'][0][1:], ('Stop', None, len('{"k":"v"}')))
        self.assertEqual(dict(h['entrypoints']), {})
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_harness.TranscriptSignals -v`
Expected: ERROR `KeyError: '_harness'`.

- [ ] **Step 3: Implement in `collect_transcripts`**

Before the `for path in top + sub:` loop:

```python
    raw = {"sessions": 0, "injections": [], "commands": {}, "listings": [], "entrypoints": Counter(),
           "main_tokens": defaultdict(int), "sub_tokens": defaultdict(int), "malformed": 0}
```

At the top of the per-file body (next to `pending = {}`):

```python
        if is_top:
            session_key = (proj_key, os.path.splitext(os.path.basename(path))[0])
        else:  # projects/<project>/<session>/subagents/<agent>.jsonl
            session_dir = os.path.dirname(os.path.dirname(path))
            session_key = (os.path.basename(os.path.dirname(session_dir)), os.path.basename(session_dir))
        seen_ids, in_window, listed, entry_seen = set(), False, False, False
```

Replace the JSON parse fallbacks so malformed lines are counted:

```python
                    try:
                        record = json.loads(line)
                    except ValueError:
                        record = None
                    if not isinstance(record, dict):
                        raw["malformed"] += bool(line.strip())
                        record = {}
```

Directly after the window `continue` block (record is in the window), add:

```python
                    if is_top and not in_window:
                        in_window = True
                        raw["sessions"] += 1
                    harness_record(raw, record, path, session_key, is_top, seen_ids)
                    if is_top and not entry_seen and record.get("type") in ("user", "assistant"):
                        entry_seen = True
                        ep = record.get("entrypoint")
                        if isinstance(ep, str):
                            raw["entrypoints"][ep] += 1
                    if is_top and not listed and record.get("type") == "attachment":
                        listed = harness_listing(raw, record, timestamp)
```

Add module-level helpers after `_coverage`:

```python
def harness_record(raw, record, path, session_key, is_top, seen_ids):
    """Accumulate hook attachments and token totals for harness_overhead (in-memory only)."""
    a = record.get("attachment") if record.get("type") == "attachment" else None
    if is_top and isinstance(a, dict):
        tool_id = a.get("toolUseID") if isinstance(a.get("toolUseID"), str) else None
        if a.get("type") == "hook_additional_context" and isinstance(a.get("hookEvent"), str):
            content = a.get("content")
            size = len(content) if isinstance(content, str) else len(json.dumps(content, separators=(",", ":")))
            raw["injections"].append((path, a["hookEvent"], tool_id, size))
        elif a.get("type") == "hook_success" and tool_id and isinstance(a.get("command"), str):
            raw["commands"][(path, tool_id)] = a["command"]
    if record.get("type") == "assistant" and (not is_top or not record.get("isSidechain")):
        msg = record.get("message") if isinstance(record.get("message"), dict) else {}
        usage = msg.get("usage") if isinstance(msg.get("usage"), dict) else None
        if usage is None:
            return
        # Streamed chunks share a message id; records without an id are never deduplicated.
        if msg.get("id") is not None:
            if msg["id"] in seen_ids:
                return
            seen_ids.add(msg["id"])
        total = sum(v for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens",
                                "output_tokens") if type(v := usage.get(k)) is int)
        raw["main_tokens" if is_top else "sub_tokens"][session_key] += total


def harness_listing(raw, record, timestamp):
    """First initial skill_listing of a main session; returns True once one is recorded."""
    a = record.get("attachment")
    if not isinstance(a, dict) or a.get("type") != "skill_listing" or a.get("isInitial") is not True:
        return False
    if type(a.get("skillCount")) is not int:
        return False
    content = a.get("content")
    raw["listings"].append((timestamp, a["skillCount"], len(content) if isinstance(content, str) else 0))
    return True
```

Add `"_harness": raw` to the returned dict.

- [ ] **Step 4: Run the tests**

Run: `python3 -m unittest tests.test_harness tests.test_collect -v`
Expected: PASS (existing `Transcripts` tests unchanged).

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_harness.py
git commit -m "Accumulate hook, skill-listing and token signals in the transcript pass

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 5: Assemble `harness_overhead`, wire it, schema and coverage

**Files:**
- Modify: `S/scripts/harness.py`, `S/scripts/collect.py` (`main`, `snapshot_coverage`), `S/references/snapshot.schema.json`
- Test: `tests/test_harness.py`

**Interfaces:**
- Consumes: `_harness` (Task 4), `hook_index`/`match_command` (Task 2), `scan_hooks` (Task 3), plugin skill components (Task 1), `collect.pct`.
- Produces: `harness.assemble(raw, index, index_reasons, extension_inventory, transcript_coverage, window_days, pct) -> dict` matching the spec's shape; snapshot key `harness_overhead`; coverage source `harness_overhead` (`collected` or `partial` with `reason` = comma-joined reasons).

- [ ] **Step 1: Write the failing tests** (append)

```python
def cover(main_omitted=0, sub_omitted=0, sub_scanned=0):
    return {'main_files': {'omitted': main_omitted}, 'subagent_files': {'omitted': sub_omitted, 'scanned': sub_scanned}}


def raw_signals(**over):
    raw = {'sessions': 0, 'injections': [], 'commands': {}, 'listings': [], 'entrypoints': {},
           'main_tokens': {}, 'sub_tokens': {}, 'malformed': 0}
    raw.update(over)
    return raw


class Assemble(unittest.TestCase):
    index = [{'plugin': 'a@m', 'command': 'run-a', 'event': 'SessionStart'},
             {'plugin': 'b@m', 'command': 'dup', 'event': 'SessionStart'},
             {'plugin': 'c@m', 'command': 'dup', 'event': 'SessionStart'}]

    def build(self, raw, coverage=None, inventory=None, reasons=()):
        return harness.assemble(raw, self.index, list(reasons), inventory or {'plugins': []},
                                coverage or cover(), 30, collect.pct, scan=lambda index: ([], []))

    def test_startup_and_compact_sum_to_one_session(self):
        raw = raw_signals(sessions=1, injections=[('s1', 'SessionStart', 't1', 3000), ('s1', 'SessionStart', 't2', 1000)],
                          commands={('s1', 't1'): 'run-a', ('s1', 't2'): 'run-a'})
        src = self.build(raw)['injected_context']['sources']
        self.assertEqual(src, [{'plugin': 'a@m', 'attribution': 'matched', 'hook_event': 'SessionStart',
                                'sessions': 1, 'records': 2, 'chars_per_session_median': 4000,
                                'chars_per_session_p90': 4000, 'est_tokens_per_session_median': 1000}])

    def test_unpaired_injection_is_unattributed_and_ambiguous_is_kept_apart(self):
        raw = raw_signals(sessions=2, injections=[('s1', 'Stop', None, 10), ('s2', 'SessionStart', 't', 20)],
                          commands={('s2', 't'): 'dup'})
        rows = {(r['attribution'], r['hook_event']): r for r in self.build(raw)['injected_context']['sources']}
        self.assertEqual(set(rows), {('unattributed', 'Stop'), ('ambiguous', 'SessionStart')})
        self.assertIsNone(rows[('ambiguous', 'SessionStart')]['plugin'])
        self.assertEqual(self.build(raw)['injected_context']['sessions_with_injection'], 2)

    def test_skill_listing_series_and_per_plugin_skills(self):
        raw = raw_signals(listings=[(2000.0, 79, 29782), (1000.0, 12, 5837), (1500.0, 90, 20000)])
        inv = {'plugins': [{'name': 'a@m', 'components': [{'kind': 'skills'}, {'kind': 'skills'}, {'kind': 'agents'}]},
                           {'name': 'b@m', 'components': [{'kind': 'hooks'}]}]}
        series = self.build(raw, inventory=inv)['skill_listing_series']
        self.assertEqual(series['sessions'], 3)
        self.assertEqual(series['first'], {'date': '1970-01-01', 'skill_count': 12, 'chars': 5837})
        self.assertEqual(series['last']['skill_count'], 79)
        self.assertEqual(series['max'], {'skill_count': 90, 'chars': 20000})
        self.assertEqual(series['per_plugin_skills'], [{'plugin': 'a@m', 'skills': 2}])

    def test_no_listings_is_null_and_not_observed(self):
        out = self.build(raw_signals())
        self.assertIsNone(out['skill_listing_series'])
        self.assertEqual(out['incomplete_reasons'], ['not_observed'])
        self.assertTrue(out['complete'])

    def test_subagent_spend_and_entrypoints(self):
        raw = raw_signals(entrypoints={'cli': 2, 'sdk-py': 1, 'weird': 1},
                          main_tokens={('p', 's1'): 100, ('p', 's2'): 300}, sub_tokens={('p', 's1'): 50})
        spend = self.build(raw, coverage=cover(sub_scanned=4))['subagent_spend']
        self.assertEqual(spend, {'subagent_files_scanned': 4, 'sessions_with_subagents': 1,
                                 'subagent_tokens_per_session_median': 50, 'main_tokens_per_session_median': 200,
                                 'entrypoints': {'cli': 2, 'sdk-py': 1, 'sdk-cli': 0, 'other': 1}})

    def test_caps_malformed_and_index_reasons_make_it_incomplete(self):
        out = self.build(raw_signals(malformed=1, listings=[(1.0, 1, 1)]),
                         coverage=cover(main_omitted=1, sub_omitted=2), reasons=['plugin_root_unreadable'])
        self.assertFalse(out['complete'])
        self.assertEqual(out['incomplete_reasons'], ['main_file_cap', 'malformed_records',
                                                     'plugin_root_unreadable', 'subagent_file_cap'])


class EndToEnd(FakeHome):
    def test_snapshot_has_valid_private_harness_section(self):
        secret = 'sk-ant-api03-' + 'A' * 40
        _, s = install(self, hooks=session_start(f'echo {secret}'), files={'hooks/x.sh': f'TOKEN={secret}\n'})
        self.write('.claude/settings.json', {'enabledPlugins': s['enabled_plugins']})
        self.write('.claude/projects/-p/s1.jsonl', '\n'.join(json.dumps(r) for r in [
            attachment('hook_success', toolUseID='t1', command=f'echo {secret}', hookEvent='SessionStart'),
            attachment('hook_additional_context', toolUseID='t1', hookEvent='SessionStart', content=secret),
            attachment('skill_listing', isInitial=True, skillCount=2, content=secret)]))
        out = os.path.join(self.home, 'snap.json')
        with unittest.mock.patch('sys.argv', ['collect.py', '--claude-dir', self.claude, '--out', out]), \
                unittest.mock.patch.object(collect, '_write_snapshot',
                                           lambda path, text: open(path, 'w').write(text)):
            collect.main()
        text = open(out).read()
        self.assertNotIn(secret, text)
        self.assertNotIn('echo', json.dumps(json.loads(text)['harness_overhead']))
        section = json.loads(text)['harness_overhead']
        self.assertEqual(section['injected_context']['sources'][0]['plugin'], 'demo@market')
        self.assertEqual(section['skill_listing_series']['last']['skill_count'], 2)
        sources = {c['source']: c for c in json.loads(text)['coverage']['sources']}
        self.assertIn('harness_overhead', sources)
```

Add `import unittest.mock` at the top of `tests/test_harness.py`.

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest tests.test_harness.Assemble tests.test_harness.EndToEnd -v`
Expected: ERROR `AttributeError: module 'harness' has no attribute 'assemble'`.

- [ ] **Step 3: Implement `assemble`** (append to `harness.py`; add `from collections import defaultdict` and `from datetime import datetime, timezone`)

```python
ENTRYPOINTS = ('cli', 'sdk-py', 'sdk-cli')


def _int(value):
    return None if value is None else int(round(value))


def _day(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d')


def assemble(raw, index, index_reasons, extension_inventory, transcript_coverage, window_days, pct, scan=None):
    """Build the harness_overhead snapshot section from in-memory transcript signals."""
    reasons = set(index_reasons)
    if transcript_coverage['main_files'].get('omitted'):
        reasons.add('main_file_cap')
    if transcript_coverage['subagent_files'].get('omitted'):
        reasons.add('subagent_file_cap')
    if raw['malformed']:
        reasons.add('malformed_records')

    per_session = defaultdict(lambda: defaultdict(int))  # source key -> session path -> chars
    records = defaultdict(int)
    for path, event, tool_id, chars in raw['injections']:
        plugin, attribution = match_command(index, raw['commands'].get((path, tool_id)) if tool_id else None)
        key = (plugin, attribution, event)
        per_session[key][path] += chars
        records[key] += 1
    sources = []
    for (plugin, attribution, event), sessions in per_session.items():
        values = list(sessions.values())
        median = pct(values, 0.5)
        sources.append(dict(plugin=plugin, attribution=attribution, hook_event=event, sessions=len(values),
                            records=records[(plugin, attribution, event)],
                            chars_per_session_median=_int(median), chars_per_session_p90=_int(pct(values, 0.9)),
                            est_tokens_per_session_median=_int(median / 4)))
    sources.sort(key=lambda s: (-s['sessions'], s['plugin'] or '', s['attribution'], s['hook_event']))

    listings = sorted(raw['listings'])
    per_plugin = [dict(plugin=p['name'], skills=n) for p in extension_inventory.get('plugins', [])
                  if (n := sum(1 for c in p.get('components', []) if c.get('kind') == 'skills'))]
    if listings:
        first, last = listings[0], listings[-1]
        top = max(listings, key=lambda x: (x[1], x[2]))
        series = dict(sessions=len(listings),
                      first=dict(date=_day(first[0]), skill_count=first[1], chars=first[2]),
                      last=dict(date=_day(last[0]), skill_count=last[1], chars=last[2]),
                      max=dict(skill_count=top[1], chars=top[2]), per_plugin_skills=per_plugin)
    else:
        series = None
        reasons.add('not_observed')

    entry = {k: 0 for k in ENTRYPOINTS + ('other',)}
    for name, count in raw['entrypoints'].items():
        entry[name if name in ENTRYPOINTS else 'other'] += count
    sub = [v for v in raw['sub_tokens'].values() if v]
    spend = dict(subagent_files_scanned=transcript_coverage['subagent_files'].get('scanned', 0),
                 sessions_with_subagents=len(sub),
                 subagent_tokens_per_session_median=_int(pct(sub, 0.5)),
                 main_tokens_per_session_median=_int(pct([v for v in raw['main_tokens'].values() if v], 0.5)),
                 entrypoints=entry)

    spawning, scan_reasons = (scan or scan_hooks)(index)
    reasons.update(scan_reasons)
    return dict(window_days=window_days, sessions_scanned=raw['sessions'],
                # not_observed is reported but is not a collection gap.
                complete=not (reasons - {'not_observed'}),
                incomplete_reasons=sorted(reasons),
                injected_context=dict(sessions_with_injection=len({p for p, *_ in raw['injections']}),
                                      sources=sources),
                skill_listing_series=series, subagent_spend=spend, model_spawning_hooks=spawning)
```

- [ ] **Step 4: Wire into `collect.main` and `snapshot_coverage`**

In `main()`, after `snap['skill_listing'] = ...`:

```python
    snap["harness_overhead"] = harness.assemble(
        snap["transcripts"].pop("_harness"), hook_index, hook_index_reasons, snap["extensions"],
        snap["transcripts"]["coverage"], a.days, pct)
```

In `snapshot_coverage`, after the usage/transcripts loop:

```python
    harness_section = snap.get("harness_overhead")
    if harness_section:
        reasons = harness_section["incomplete_reasons"]
        sources.append(source_coverage("harness_overhead", scope,
                                      "collected" if harness_section["complete"] else "partial",
                                      **({"reason": ",".join(reasons)} if reasons else {})))
```

(`snapshot_coverage` is called after `harness_overhead` is set; keep that order.)

- [ ] **Step 5: Add the schema section** in `snapshot.schema.json` `properties`, after `ledger_signals`:

```json
    "harness_overhead": {
      "type": "object",
      "required": ["window_days", "sessions_scanned", "complete", "incomplete_reasons", "injected_context",
                   "skill_listing_series", "subagent_spend", "model_spawning_hooks"],
      "properties": {
        "window_days": {"type": "integer", "minimum": 1},
        "sessions_scanned": {"type": "integer", "minimum": 0},
        "complete": {"type": "boolean"},
        "incomplete_reasons": {"type": "array", "items": {"enum": ["main_file_cap", "subagent_file_cap",
          "malformed_records", "plugin_root_unreadable", "script_unresolved", "script_truncated", "not_observed"]}},
        "injected_context": {
          "type": "object",
          "required": ["sessions_with_injection", "sources"],
          "properties": {
            "sessions_with_injection": {"type": "integer", "minimum": 0},
            "sources": {"type": "array", "items": {
              "type": "object",
              "required": ["plugin", "attribution", "hook_event", "sessions", "records",
                           "chars_per_session_median", "chars_per_session_p90", "est_tokens_per_session_median"],
              "properties": {
                "plugin": {"type": ["string", "null"]},
                "attribution": {"enum": ["matched", "ambiguous", "unattributed"]},
                "hook_event": {"type": "string"},
                "sessions": {"type": "integer", "minimum": 1},
                "records": {"type": "integer", "minimum": 1},
                "chars_per_session_median": {"type": "integer", "minimum": 0},
                "chars_per_session_p90": {"type": "integer", "minimum": 0},
                "est_tokens_per_session_median": {"type": "integer", "minimum": 0}
              }}}
          }
        },
        "skill_listing_series": {"type": ["object", "null"]},
        "subagent_spend": {
          "type": "object",
          "required": ["subagent_files_scanned", "sessions_with_subagents", "subagent_tokens_per_session_median",
                       "main_tokens_per_session_median", "entrypoints"],
          "properties": {
            "subagent_files_scanned": {"type": "integer", "minimum": 0},
            "sessions_with_subagents": {"type": "integer", "minimum": 0},
            "subagent_tokens_per_session_median": {"type": ["integer", "null"]},
            "main_tokens_per_session_median": {"type": ["integer", "null"]},
            "entrypoints": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}
          }
        },
        "model_spawning_hooks": {"type": "array", "items": {
          "type": "object",
          "required": ["plugin", "hook_event", "file", "line", "pattern"],
          "properties": {
            "plugin": {"type": "string"}, "hook_event": {"type": "string"}, "file": {"type": "string"},
            "line": {"type": ["integer", "null"]},
            "pattern": {"enum": ["claude_print", "agent_sdk_py", "agent_sdk_js", "anthropic_client"]}
          }}}
      }
    }
```

If `snapshot_contract` rejects `enum` inside `items` without `type`, add `"type": "string"` to those two `items` objects.

- [ ] **Step 6: Add a schema rejection test** to `tests/test_snapshot_contract.py`, following its existing style for `ledger_signals` (find the test that mutates a valid snapshot and asserts `SnapshotError`): set `harness_overhead` to a valid section, then set `incomplete_reasons` to `["bogus"]` and assert rejection; set `subagent_spend.entrypoints.cli` to `-1` and assert rejection.

- [ ] **Step 7: Run tests and the schema check**

Run: `python3 -m unittest discover -s tests -v && python3 tests/check_snapshot_schema.py`
Expected: PASS. Red-proof: in `assemble`, sum per record instead of per session (`per_session[key][(path, tool_id)]`) and confirm `test_startup_and_compact_sum_to_one_session` fails; restore.

- [ ] **Step 8: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/harness.py plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json tests/test_harness.py tests/test_snapshot_contract.py
git commit -m "Add the harness_overhead snapshot section

Measured injected context per plugin, skill listing series, subagent spend, entrypoint
shares and model-invoking hooks, with coverage and schema.

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 6: Checks, documentation and release notes

**Files:**
- Modify: `S/references/checklist.md` (COST section), `S/references/coverage.md`, `S/references/snapshot-format.md`, `S/SKILL.md` (check list near line 150 and the metrics guidance), `CHANGELOG.md` (`[Unreleased]`), `docs/roadmap.md`
- Test: none new; the full gate.

**Interfaces:**
- Consumes: section and field names from Task 5, verbatim.

- [ ] **Step 1: Re-fetch documentation.** Fetch `https://code.claude.com/docs/en/hooks.md` (SessionStart `additionalContext`, which `source` values re-fire on clear/compact) and `https://code.claude.com/docs/en/skills.md` (skill listing/description budget; settings named `skillListingBudgetFraction`, `skillListingMaxDescChars` in the current checklist). Note each fact with "fetched 2026-09-29". If a fact contradicts the spec (e.g. SessionStart does not re-fire on compact), stop and report it instead of writing around it.

- [ ] **Step 2: `checklist.md`.** Replace the `COST-startup-hooks` bullet:

```markdown
- **COST-startup-hooks** (`harness_overhead.injected_context`, measured; fallback
  `global.plugin_session_start_hooks`, `basis: file_size_estimate`): context injected by hooks per
  session. Use the measured source rows when any session in the window has them, and say which
  basis you used. Evidence: plugin (or `ambiguous`/`unattributed`), event, sessions and median
  estimated tokens per session (chars/4). SessionStart re-fires on <values from Step 1>.
```

Add after it:

```markdown
- **COST-harness-overhead** (`harness_overhead`, measured and static): judge together
  - skill listing growth (`skill_listing_series` first → last, and `last.chars` against the
    documented listing budget from <skills page, fetched 2026-09-29>), with `per_plugin_skills`
    naming the largest contributors;
  - `model_spawning_hooks`: an enabled plugin hook that runs `claude -p`, the Agent SDK or the
    Anthropic API spends tokens outside the session; cite file, line and pattern id;
  - `subagent_spend`: subagent median tokens per session against the main-session median.
  `entrypoints` are shares only: never call SDK sessions "reflection" or attribute them to a plugin
  or hook. Treat `complete: false` and its `incomplete_reasons` as limits on every claim. Record
  metrics `skills.listing_count` (unit `skills`), `skills.listing_chars` (unit `chars`) and
  `hooks.injected_tokens_per_session_median` (unit `tokens`, basis `estimated`), all with
  `source: harness_overhead.<field>`, so the next audit gets deltas.
```

- [ ] **Step 3: `coverage.md`.** Add a `harness_overhead` paragraph: fields come from undocumented transcript attachment records (`hook_additional_context`, `hook_success`, `skill_listing`), observed 2026-09-29; absence means not observed; attribution is exact command-string match against registry-resolved enabled plugins; each `incomplete_reasons` value and what it means; nothing stored is content, command text or script text.

- [ ] **Step 4: `snapshot-format.md`.** Add under Compatibility, like `ledger_signals`: "`harness_overhead`: optional; counts, sizes, dates, plugin names, relative script paths and pattern ids. Additive within snapshot v1." Also note `global.plugin_session_start_hooks` entries gained `basis`.

- [ ] **Step 5: `SKILL.md`.** Where COST-startup-hooks is listed as estimated (around line 150), say measured with estimate fallback and add COST-harness-overhead.

- [ ] **Step 6: `CHANGELOG.md` `[Unreleased]`.** Added: measured harness overhead (injected context per plugin, skill listing series, subagent spend, entrypoint shares, model-invoking hook scan) and `COST-harness-overhead`. Changed: startup-hook estimate resolves plugins through the registry and all settings layers. Fixed: `candidate_skills` counted every `.md` under a plugin's `skills/`.

- [ ] **Step 7: `docs/roadmap.md`.** Update the "Self-modifying harness overhead" bullet to state it is implemented on the branch (unreleased) and that skill growth comes from transcripts, not the ledger.

- [ ] **Step 8: Run the full gate**

Run: `python3 -m unittest discover -s tests -v && python3 tests/check_snapshot_schema.py && git diff --check`, then the coverage command from `docs/development.md`.
Expected: all pass; coverage ≥ 88.

- [ ] **Step 9: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/references/checklist.md plugins/setup-audit/skills/setup-audit/references/coverage.md plugins/setup-audit/skills/setup-audit/references/snapshot-format.md plugins/setup-audit/skills/setup-audit/SKILL.md CHANGELOG.md docs/roadmap.md
git commit -m "Document measured harness overhead checks

Assisted-by: Claude:claude-opus-5-5"
```
