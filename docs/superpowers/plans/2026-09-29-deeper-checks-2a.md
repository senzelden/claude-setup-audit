# Deeper Checks 2A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three static, redacted, capped configuration signals and five checklist entries:
- permission rule shapes that match more than they read, or that Claude Code ignores;
- hook handlers that can't fire, or that are misconfigured, per the hooks docs;
- cross-layer conflicts: duplicate hooks, and allow rules shadowed by deny or ask rules.

**Architecture:**
- **Rule shapes** live in `collect.py` beside `RISKY_RULES` and land in each settings summary as `permissions.rule_shape_issues`.
- **Hook validation, fingerprints and conflict detection** go in a new pure module, `scripts/config_checks.py`, which holds the doc-dated `HOOK_EVENTS` constant.
- **Per-handler fields** are added in `collect.hook_handler_entry`, so settings and plugin handlers are treated alike.
- **Conflicts** are built by `collect.config_stacks(snap)`. Raw rules reach it through a module-level `_RAW_PERMISSIONS` table that `build_snapshot` clears first. The result becomes a new optional top-level `config_conflicts` section.

**Tech Stack:** Python 3.11+ standard library; `unittest`; the bundled snapshot schema evaluator.

**Spec:** `docs/superpowers/specs/2026-09-29-deeper-checks-2a-design.md`

## Global Constraints

- **Environment and safety**
  - Stdlib only.
  - Tests use temporary fake homes (`FakeHome` in `tests/test_collect.py`). Never read or write the real `~/.claude`.
  - Never run the collector against the real home.
- **Privacy**
  - Rule text is stored only as `redact(rule)[:160]`, the `permissions.risky` convention.
  - Hook conflict entries carry fingerprints, never command text.
  - Rule-shape caps: 6 rules per flag per list.
  - Conflict caps: 30 overlaps, 20 duplicate groups, 10 sources per group, with `*_omitted` counts.
- **Schema**
  - The snapshot stays version 1. `config_conflicts` is optional and additive.
  - Use only the schema types `object`, `array`, `string`, `integer`, `boolean`, `null` and `enum`. Do **not** use `number`: another branch adds it concurrently.
  - `permissions.rule_shape_issues` and the new handler fields live in untyped settings items and need no schema change.
- **Doc-grounded values**
  - Every documented value used comes from the raw pages fetched on 2026-09-29 and quoted in the spec.
  - Task 6 re-fetches the raw pages with `curl -sL https://code.claude.com/docs/en/<page>.md` (never WebFetch). If a quoted sentence changed, stop and report it.
- **Focused test runs**
  - Run focused tests as `python3 -m unittest discover -s tests -p test_config_checks.py -v`. `tests/` is not a package.
  - The new test file imports helpers from `test_collect` the way `test_managed_settings.py` does.
- **Gate**, all four must pass:
  - `python3 -m unittest discover -s tests`
  - `python3 tests/check_snapshot_schema.py` (needs `jsonschema`; `uvx --with jsonschema python tests/check_snapshot_schema.py` works)
  - `git diff --check`
  - coverage ≥ 88: `uvx --from coverage==7.16.2 coverage run -m unittest discover -s tests`, then `coverage report | tail -1`, then `coverage erase`. Never delete coverage files with a glob `rm`.
- **Commits**
  - Stage explicit paths only.
  - The message ends with exactly one trailer: `Assisted-by: Claude:<your model id>`.
  - Never stage `AGENTS.md`, `CODEX-SETUP.md` or `.superpowers/`.
  - Do not push, tag or switch branches.
- **Tooling:** Bash sandbox is broken in this environment; run commands with the sandbox disabled.
- **Line numbers:** `collect.py` line numbers drift. Anchor edits on function names (`analyze_permissions`, `hook_handler_entry`, `summarize_settings`, `discover_projects`, `build_snapshot`, `snapshot_coverage`).

Paths: `S = plugins/setup-audit/skills/setup-audit`.

## Review Focus

1. **No false positives on valid patterns.** Every negative case in the spec's tables has a test (Task 1 `test_valid_patterns_are_not_flagged`, Task 2 `test_valid_matchers_are_not_flagged`, Task 3 `test_non_covering_pairs`).
2. **Deny/ask fail-open only.** `Bash(git * main)` in deny or ask is not flagged. `Bash(git:* push)` in deny is. (Task 1 `test_lists_keep_only_their_relevant_flags_capped_and_redacted`.)
3. **Duplicate semantics follow the docs.** Settings-only → `deduplicated`; with a plugin → `separate_copies`; one file → `same_file`. Two plugins with the same `${CLAUDE_PLUGIN_ROOT}` command are not duplicates. (Task 4.)
4. **Plugin enablement follows precedence.** A project-local `false` beats a user `true`, which turns `separate_copies` in `global` into `deduplicated` in the project stack. (Task 5 `test_layers_precedence_and_report_once`.)
5. **Raw rules never enter the snapshot.** No command text appears in `config_conflicts`, and a second build on a clean home reports nothing, which proves `_RAW_PERMISSIONS` was cleared. (Task 5.)

---

### Task 1: Permission rule shapes

**Files:**
- Modify: `S/scripts/collect.py` (new constants and functions directly after `RISKY_RULES`; one line in `analyze_permissions`)
- Create: `tests/test_config_checks.py`

**Interfaces:**
- Produces:
  - `collect.rule_shape_flags(rule: str) -> set[str]`
  - `collect.rule_shape_issues(perms: dict) -> dict[str, dict[str, list[str]]]`
  - `collect.RULE_SHAPE_LISTS`
  - `analyze_permissions(...)["rule_shape_issues"]`

- [ ] **Step 1: Write the failing tests** (`tests/test_config_checks.py`, new file)

```python
"""Deeper configuration checks: rule shapes, hook handler validation, cross-layer conflicts.

Fake homes only; never the real ~/.claude.
"""
import unittest
from test_collect import FakeHome, collect


class RuleShapes(unittest.TestCase):
    def test_documented_shapes_are_flagged(self):
        cases = {
            'Bash(git * main)': {'wildcard-before-subcommand'},
            'Bash(git -C * status *)': {'wildcard-before-subcommand'},
            'Bash(* --version)': {'wildcard-program'},
            'Bash(* --help *)': {'wildcard-program'},
            'Bash(ls*)': {'star-joined-to-program'},
            'Bash(/usr/bin/ls*)': {'star-joined-to-program'},
            'Bash(git:* push)': {'colon-star-literal'},
            'Bash(command:rm *)': {'ignored-primary-field'},
            'Read(file_path : ~/.ssh/id_rsa)': {'ignored-primary-field'},
            'WebFetch(url:https://x.test/*)': {'ignored-primary-field'},
            'mcp__github__create_issue(repo:x)': {'mcp-rule-with-parentheses'},
        }
        for rule, expected in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(collect.rule_shape_flags(rule), expected)

    def test_valid_patterns_are_not_flagged(self):
        for rule in ('Bash', 'Bash(*)', 'Bash(git *)', 'Bash(git:*)', 'Bash(git log *)', 'Bash(git commit *)',
                     'Bash(git log * main)', 'Bash(npm run test:*)', 'Bash(ls *)', 'Bash(ls:*)',
                     'Bash(npm run build)', 'Bash(python3 -m pytest *)', 'Bash(cat ./src/*)', 'Bash(./scripts/*)',
                     'Bash(git checkout feature-*)', 'Bash(git checkout feat*)', 'Bash(timeout:*)',
                     'Bash(run_in_background:true)', 'Agent(model:*)', 'Read(./.env)', 'Read(//etc/**)',
                     'Edit(src/**)', 'WebFetch(domain:example.com)', 'mcp__github__get_*', 'mcp__*'):
            with self.subTest(rule=rule):
                self.assertEqual(collect.rule_shape_flags(rule), set())

    def test_lists_keep_only_their_relevant_flags_capped_and_redacted(self):
        perms = {'allow': ['Bash(git * main)', 'Bash(git:* push)', 'Bash(npm run *)', 1],
                 'deny': ['Bash(git * main)', 'Bash(git:* push)', 'Bash(command:rm *)'],
                 'ask': ['Bash(ls*)', 'mcp__github__create_issue(repo:x)']}
        self.assertEqual(collect.rule_shape_issues(perms), {
            'allow': {'colon-star-literal': ['Bash(git:* push)'],
                      'wildcard-before-subcommand': ['Bash(git * main)']},
            'deny': {'colon-star-literal': ['Bash(git:* push)'],
                     'ignored-primary-field': ['Bash(command:rm *)']},
            'ask': {'mcp-rule-with-parentheses': ['mcp__github__create_issue(repo:x)']}})
        many = {'allow': [f'Bash(tool{i} * main)' for i in range(8)]}
        self.assertEqual(len(collect.rule_shape_issues(many)['allow']['wildcard-before-subcommand']), 6)
        stored = collect.rule_shape_issues({'allow': ['Bash(sk-abcdefghijklmnopqrstuv * main)']})
        self.assertEqual(stored['allow']['wildcard-before-subcommand'], ['Bash([REDACTED] * main)'])
        self.assertEqual(collect.rule_shape_issues({'allow': ['Bash(git status)']}), {})


class RuleShapesInSummary(FakeHome):
    def test_summary_carries_rule_shape_issues(self):
        flagged = self.write('.claude/settings.json', {'permissions': {'allow': ['Bash(ls*)'],
                                                                         'deny': ['Bash(git:* push)']}})
        clean = self.write('p/.claude/settings.json', {'permissions': {'allow': ['Bash(git status)']}})
        self.assertEqual(collect.summarize_settings(flagged)['permissions']['rule_shape_issues'],
                         {'allow': {'star-joined-to-program': ['Bash(ls*)']},
                          'deny': {'colon-star-literal': ['Bash(git:* push)']}})
        self.assertEqual(collect.summarize_settings(clean)['permissions']['rule_shape_issues'], {})
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest discover -s tests -p test_config_checks.py -v`
Expected: ERROR `AttributeError: module 'collect' has no attribute 'rule_shape_flags'`.

- [ ] **Step 3: Implement** (in `collect.py`, directly after the `RISKY_RULES` list)

```python
# permissions.md "Wildcard patterns" / "Match by input parameter" and errors.md "Has a wildcard before
# the rest of the command", fetched 2026-09-29. See references/checklist.md SEC-wildcard-placement.
PRIMARY_FIELD_RULE = re.compile(r"(?:(?:Bash|PowerShell)\(\s*command|(?:Read|Edit|Write)\(\s*file_path"
                                r"|(?:Grep|Glob)\(\s*path|NotebookEdit\(\s*notebook_path|WebFetch\(\s*url)\s*:")
FAIL_OPEN = ("colon-star-literal", "ignored-primary-field", "mcp-rule-with-parentheses")
# Deny/ask shapes that over-match fail closed (errors.md), so only fail-open shapes are kept there.
RULE_SHAPE_LISTS = {
    "allow": ("wildcard-before-subcommand", "wildcard-program", "star-joined-to-program",
              "colon-star-literal", "mcp-rule-with-parentheses"),
    "ask": FAIL_OPEN,
    "deny": FAIL_OPEN,
}


def rule_shape_flags(rule):
    """Every documented misleading shape of one rule; rule_shape_issues keeps those relevant per list."""
    flags = set()
    rule = rule.strip()
    if rule.startswith("mcp__") and "(" in rule:
        flags.add("mcp-rule-with-parentheses")
    if PRIMARY_FIELD_RULE.match(rule):
        flags.add("ignored-primary-field")
    m = re.fullmatch(r"Bash\((.*)\)", rule, re.S)
    if not m:
        return flags
    body = m.group(1).strip()
    if body.endswith(":*"):
        body = body[:-2]  # a trailing :* is the documented prefix form
    if ":*" in body:
        flags.add("colon-star-literal")
    tokens = body.split()
    starred = [i for i, t in enumerate(tokens) if "*" in t]
    if not starred or body == "*":
        return flags
    first = starred[0]
    if first == 0:
        if tokens[0] == "*" and len(tokens) > 1:
            flags.add("wildcard-program")
    else:
        words = [t for t in tokens[:first] if not t.startswith("-")]
        later = [t for t in tokens[first + 1:] if not t.startswith("-") and t != "*"]
        if len(words) == 1 and later:
            flags.add("wildcard-before-subcommand")
    if len(tokens) == 1 and body.count("*") == 1 and re.fullmatch(r"[^*]*[A-Za-z0-9_]\*", body):
        flags.add("star-joined-to-program")
    return flags


def rule_shape_issues(perms):
    """{list: {flag: [redacted rules, at most 6]}} for flagged rules only; {} when clean."""
    out = {}
    for name, wanted in RULE_SHAPE_LISTS.items():
        flagged = defaultdict(list)
        for rule in perms.get(name, []) or []:
            if isinstance(rule, str):
                for flag in sorted(rule_shape_flags(rule) & set(wanted)):
                    flagged[flag].append(redact(rule)[:160])
        if flagged:
            out[name] = {k: v[:6] for k, v in sorted(flagged.items())}
    return out
```

In `analyze_permissions`, add this entry to the returned dict after `"risky"`:

```python
        "rule_shape_issues": rule_shape_issues(perms),
```

`redact` is defined later in the module but is only called at runtime, so this ordering is fine.

- [ ] **Step 4: Run the tests**

Run the focused file, then the full suite once.
Expected: PASS. `test_managed_settings.test_invalid_and_oversized_files` still yields `invalid_settings` for `{"permissions":{"allow":[1]}}`, because `RISKY_RULES` raises before the new code runs.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_config_checks.py
git commit -m "Flag permission rule shapes that match more than they read

Assisted-by: Claude:<model-id>"
```

---

### Task 2: Hook event constant, handler validation and fingerprints

**Files:**
- Create: `S/scripts/config_checks.py`
- Modify: `S/scripts/collect.py` (`import config_checks`; `hook_handler_entry`)
- Test: `tests/test_config_checks.py`

**Interfaces:**
- Produces:
  - `config_checks.HOOK_EVENTS`
  - `config_checks.TOOL_EVENTS`
  - `config_checks.COMMON_FIELDS` / `TYPE_FIELDS`
  - `config_checks.normalize_matcher(m) -> str | object`
  - `config_checks.handler_fingerprint(event, matcher, handler) -> str` (16 lowercase hex)
  - `config_checks.handler_issues(event, matcher, handler) -> tuple[list[str], list[str]]`
  - `hook_handler_entry` entries gain:
    - `fingerprint`: always.
    - `issues` and `unknown_fields`: only when non-empty.
    - `plugin_relative: True`: only when the handler JSON contains `CLAUDE_PLUGIN_`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_config_checks.py`; add `import config_checks` under the existing imports)

```python
def hook_issues(event, matcher=None, **handler):
    handler.setdefault('type', 'command')
    handler.setdefault('command', 'true')
    return config_checks.handler_issues(event, matcher, handler)[0]


class HookHandlerChecks(unittest.TestCase):
    def test_every_documented_event_is_known_without_a_matcher(self):
        for event in config_checks.HOOK_EVENTS:
            with self.subTest(event=event):
                self.assertEqual(hook_issues(event), [])
        self.assertEqual(config_checks.TOOL_EVENTS, {'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
                                                     'PermissionRequest', 'PermissionDenied'})

    def test_documented_problems_are_flagged(self):
        cases = [
            (('pretooluse', 'Bash'), ['unknown_event']),
            (('Stop', 'Bash'), ['matcher_ignored']),
            (('UserPromptSubmit', '.*'), ['matcher_ignored']),
            (('PreToolUse', '*.py'), ['invalid_regex']),
            (('PreToolUse', 'Edit|Write)'), ['invalid_regex']),
            (('PreToolUse', '[Edit'), ['invalid_regex']),
            (('PreToolUse', 'mcp__memory'), ['mcp_server_only_matcher']),
            (('PreToolUse', 'Bash|mcp__brave-search'), ['mcp_server_only_matcher']),
            (('StopFailure', 'rate_limit, overloaded'), ['narrow_event_regex_path']),
            (('PreToolUse', ['Bash']), ['matcher_not_string']),
        ]
        for (event, matcher), expected in cases:
            with self.subTest(event=event, matcher=matcher):
                self.assertEqual(hook_issues(event, matcher), expected)

    def test_valid_matchers_are_not_flagged(self):
        for event, matcher in (
                ('PreToolUse', 'Edit|Write'), ('PreToolUse', 'Edit, Write'), ('PreToolUse', '^Notebook'),
                ('PreToolUse', '^Edit$'), ('PreToolUse', 'mcp__memory__.*'), ('PreToolUse', 'mcp__.*__write.*'),
                ('PreToolUse', 'mcp__memory__create_entities'), ('SubagentStart', 'code-reviewer'),
                ('SubagentStart', '^my-plugin:reviewer$'), ('PreModelSwitch', '.*opus.*'),
                ('Notification', 'permission_prompt'), ('SessionStart', 'mcp__memory'),
                ('StopFailure', 'rate_limit|overloaded'), ('FileChanged', '.envrc|.env'),
                ('FileChanged', r'^\.env'), ('PreToolUse', '(?<tool>Bash)'), ('PreToolUse', r'\p{L}+'),
                ('Stop', '*'), ('Stop', ''), ('Stop', None)):
            with self.subTest(event=event, matcher=matcher):
                self.assertEqual(hook_issues(event, matcher), [])

    def test_if_on_non_tool_events_never_runs(self):
        self.assertEqual(hook_issues('Stop', **{'if': 'Bash(git *)'}), ['if_never_runs'])
        self.assertEqual(hook_issues('PermissionDenied', 'Bash', **{'if': 'Bash(git *)'}), [])

    def test_handler_fields(self):
        check = config_checks.handler_issues
        full = {'type': 'command', 'command': 'x', 'args': [], 'async': True, 'asyncRewake': False,
                'shell': 'bash', 'timeout': 5, 'statusMessage': 's', 'once': True, 'if': 'Bash(x)'}
        self.assertEqual(check('PreToolUse', 'Bash', full), ([], []))
        self.assertEqual(check('PreToolUse', 'Bash', {'type': 'command', 'command': 'x', 'url': 'u'}),
                         (['unknown_fields'], ['url']))
        self.assertEqual(check('PreToolUse', 'Bash', {'type': 'http', 'url': 'u', 'async': True}),
                         (['unknown_fields'], ['async']))
        self.assertEqual(check('Stop', None, {'type': 'prompt', 'prompt': 'p', 'model': 'm'}), ([], []))
        self.assertEqual(check('Stop', None, {'type': 'script', 'command': 'x'}), (['unknown_type'], []))
        self.assertEqual(check('Stop', None, {'command': 'x'}), ([], []))
        self.assertEqual(check('Stop', 'Bash', {'type': 'command', 'command': 'x', 'colour': 'r'}),
                         (['matcher_ignored', 'unknown_fields'], ['colour']))

    def test_fingerprint(self):
        fp = config_checks.handler_fingerprint
        same = {fp('PreToolUse', None, {'command': 'a', 'type': 'command'}),
                fp('PreToolUse', '*', {'type': 'command', 'command': 'a'}),
                fp('PreToolUse', '', {'command': 'a'})}
        self.assertEqual(len(same), 1)
        self.assertRegex(same.pop(), r'^[0-9a-f]{16}$')
        self.assertNotEqual(fp('PreToolUse', 'Bash', {'command': 'a', 'timeout': 5}),
                            fp('PreToolUse', 'Bash', {'command': 'a'}))
        self.assertNotEqual(fp('PostToolUse', 'Bash', {'command': 'a'}), fp('PreToolUse', 'Bash', {'command': 'a'}))


class HookFieldsInSummary(FakeHome):
    def test_handler_entries_carry_checks(self):
        path = self.write('.claude/settings.json', {'hooks': {
            'Stop': [{'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': 'x', 'colour': 'r'}]}],
            'PreToolUse': [{'matcher': '[', 'hooks': [{'type': 'command', 'command': 'ok.sh'}]}],
            'SessionStart': [{'hooks': [{'type': 'command', 'command': '${CLAUDE_PLUGIN_ROOT}/s.sh'}]}]}})
        handlers = {h['event']: h for h in collect.summarize_settings(path)['hook_handlers']}
        self.assertEqual(handlers['Stop']['issues'], ['matcher_ignored', 'unknown_fields'])
        self.assertEqual(handlers['Stop']['unknown_fields'], ['colour'])
        self.assertEqual(handlers['PreToolUse']['issues'], ['invalid_regex'])
        self.assertNotIn('issues', handlers['SessionStart'])
        self.assertNotIn('unknown_fields', handlers['SessionStart'])
        self.assertTrue(handlers['SessionStart']['plugin_relative'])
        self.assertNotIn('plugin_relative', handlers['Stop'])
        self.assertRegex(handlers['Stop']['fingerprint'], r'^[0-9a-f]{16}$')
```

- [ ] **Step 2: Run to verify it fails**

Run the focused file.
Expected: ERROR `ModuleNotFoundError: No module named 'config_checks'`.

- [ ] **Step 3: Implement `S/scripts/config_checks.py`**

```python
"""Static configuration checks: hook handler validation and fingerprints, cross-layer conflicts.

Pure functions over settings JSON and collector summaries. Stdlib only; never runs a hook.
Documentation baseline: https://code.claude.com/docs/en/hooks.md and
https://code.claude.com/docs/en/permissions.md, both fetched 2026-09-29.
"""
import hashlib
import json
import re
import warnings

DOCS_FETCHED = '2026-09-29'
DEFAULT, NARROW = 'default', 'narrow'
# hooks.md (fetched 2026-09-29), "Hook lifecycle" event table and "Matcher patterns":
# event -> (what the matcher filters, exact-match character set). (None, None) = "no matcher
# support"; there "If you add a `matcher` field to an event without matcher support, it is
# silently ignored." FileChanged and StopFailure use the narrower exact set (letters, digits, _, |).
HOOK_EVENTS = {
    'PreToolUse': ('tool name', DEFAULT),
    'PostToolUse': ('tool name', DEFAULT),
    'PostToolUseFailure': ('tool name', DEFAULT),
    'PermissionRequest': ('tool name', DEFAULT),
    'PermissionDenied': ('tool name', DEFAULT),
    'SessionStart': ('how the session started', DEFAULT),
    'Setup': ('which CLI flag triggered setup', DEFAULT),
    'SessionEnd': ('why the session ended', DEFAULT),
    'Notification': ('notification type', DEFAULT),
    'SubagentStart': ('agent type', DEFAULT),
    'SubagentStop': ('agent type', DEFAULT),
    'PreCompact': ('what triggered compaction', DEFAULT),
    'PostCompact': ('what triggered compaction', DEFAULT),
    'PreModelSwitch': ('model name', DEFAULT),
    'PostModelSwitch': ('model name', DEFAULT),
    'ConfigChange': ('configuration source', DEFAULT),
    'DirectoryAdded': ('how the directory was added', DEFAULT),
    'FileChanged': ('literal filenames to watch', NARROW),
    'StopFailure': ('error type', NARROW),
    'InstructionsLoaded': ('load reason', DEFAULT),
    'UserPromptExpansion': ('command name', DEFAULT),
    'Elicitation': ('MCP server name', DEFAULT),
    'ElicitationResult': ('MCP server name', DEFAULT),
    'CwdChanged': (None, None),
    'UserPromptSubmit': (None, None),
    'PostToolBatch': (None, None),
    'Stop': (None, None),
    'TeammateIdle': (None, None),
    'TaskCreated': (None, None),
    'TaskCompleted': (None, None),
    'WorktreeCreate': (None, None),
    'WorktreeRemove': (None, None),
    'MessageDisplay': (None, None),
}
TOOL_EVENTS = frozenset(e for e, (filters, _) in HOOK_EVENTS.items() if filters == 'tool name')
# hooks.md "Hook handler fields" (fetched 2026-09-29).
COMMON_FIELDS = frozenset({'type', 'if', 'timeout', 'statusMessage', 'once'})
TYPE_FIELDS = {
    'command': frozenset({'command', 'args', 'async', 'asyncRewake', 'shell'}),
    'http': frozenset({'url', 'headers', 'allowedEnvVars'}),
    'mcp_tool': frozenset({'server', 'tool', 'input'}),
    'prompt': frozenset({'prompt', 'model'}),
    'agent': frozenset({'prompt', 'model'}),
}
EXACT = {DEFAULT: re.compile(r'[A-Za-z0-9_\- ,|]*'), NARROW: re.compile(r'[A-Za-z0-9_|]*')}
# Constructs JavaScript accepts (or reads differently) where Python's re errors: not judged.
JS_DIVERGENT = re.compile(r'\(\?<(?![=!])|\\(?:[ceghijklmopqyzCEFGHIJKLMOPQRTVXY]|u(?![0-9A-Fa-f]{4})'
                          r'|x(?![0-9A-Fa-f]{2})|[UN1-9])')


def normalize_matcher(matcher):
    """Omitted, "" and "*" all match everything (hooks.md "Matcher patterns")."""
    return '*' if matcher is None or matcher in ('', '*') else matcher


def handler_fingerprint(event, matcher, handler):
    """First 16 hex of SHA-256 over event, normalized matcher and the whole handler (type defaulted)."""
    body = dict(handler)
    body.setdefault('type', 'command')
    text = json.dumps([event, normalize_matcher(matcher), body], sort_keys=True,
                      separators=(',', ':'), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()[:16]


def _matcher_issues(event, spec, matcher):
    if matcher is None or matcher in ('', '*'):
        return []
    if not isinstance(matcher, str):
        return ['matcher_not_string']
    filters, charset = spec
    if filters is None:
        return ['matcher_ignored']
    if EXACT[charset].fullmatch(matcher):
        parts = [p.strip() for p in re.split(r'[|,]' if charset == DEFAULT else r'\|', matcher)]
        if event in TOOL_EVENTS and any(p.startswith('mcp__') and '__' not in p[5:] for p in parts):
            return ['mcp_server_only_matcher']
        return []
    if event == 'FileChanged':
        return []  # the watch list reads segments as literal filenames (hooks.md "FileChanged")
    issues = []
    if charset == NARROW and EXACT[DEFAULT].fullmatch(matcher):
        issues.append('narrow_event_regex_path')
    if not JS_DIVERGENT.search(matcher):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                re.compile(matcher)
        except re.error:
            issues.append('invalid_regex')
    return issues


def handler_issues(event, matcher, handler):
    """(issues, unknown_fields) for one handler; see references/checklist.md HYG-hook-config."""
    spec = HOOK_EVENTS.get(event)
    issues = ['unknown_event'] if spec is None else _matcher_issues(event, spec, matcher)
    if spec is not None and 'if' in handler and event not in TOOL_EVENTS:
        issues.append('if_never_runs')
    kind = handler.get('type', 'command')
    unknown = []
    if kind not in TYPE_FIELDS:
        issues.append('unknown_type')
    else:
        unknown = sorted(str(k) for k in handler if k not in COMMON_FIELDS | TYPE_FIELDS[kind])[:10]
        if unknown:
            issues.append('unknown_fields')
    return issues, unknown
```

In `collect.py`, add `import config_checks` after `import clarity`. Then replace the final `return {...}` of `hook_handler_entry` with:

```python
    issues, unknown = config_checks.handler_issues(event, matcher, x)
    entry = {"event": event, "matcher": matcher, "type": kind, "target": redact(target)[:200], **extra,
             "fingerprint": config_checks.handler_fingerprint(event, matcher, x)}
    if issues:
        entry["issues"] = issues
    if unknown:
        entry["unknown_fields"] = unknown
    if "CLAUDE_PLUGIN_" in json.dumps(x, default=str):
        entry["plugin_relative"] = True
    return entry
```

Keep the docstring accurate: extend it with one sentence naming the added fields.

- [ ] **Step 4: Run the tests**

Run the focused file, then the full suite.
Expected: PASS. `test_collect.HookClassification`, `test_extensions` and `test_managed_settings` stay green; `{"hooks": 1}` still yields `invalid_settings`.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/config_checks.py plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_config_checks.py
git commit -m "Validate hook events, matchers and handler fields against the hooks docs

Assisted-by: Claude:<model-id>"
```

---

### Task 3: Provable rule coverage and permission overlaps

**Files:**
- Modify: `S/scripts/config_checks.py`
- Test: `tests/test_config_checks.py`

**Interfaces:**
- Produces:
  - `config_checks.rule_covers(by: str, allow: str) -> 'exact' | 'tool' | 'prefix' | None`
  - `config_checks.permission_overlaps(stacks, redact, cap=30) -> (list, omitted)`
  - `config_checks.MAX_OVERLAPS = 30`, `MAX_DUPLICATES = 20`, `MAX_SOURCES = 10`
- Stack shape (built by Task 5, hand-built in tests): `{'name': str, 'settings': [{'layer', 'path', 'permissions': {'allow','ask','deny'}, 'handlers', 'enabled_plugins'}], 'plugins': [{'plugin', 'path', 'handlers'}]}`

- [ ] **Step 1: Write the failing tests** (append)

```python
def sfile(layer, path, allow=(), ask=(), deny=(), handlers=()):
    return {'layer': layer, 'path': path, 'handlers': list(handlers), 'enabled_plugins': {},
            'permissions': {'allow': list(allow), 'ask': list(ask), 'deny': list(deny)}}


def stack(name, *files, plugins=()):
    return {'name': name, 'settings': list(files), 'plugins': list(plugins)}


USER, MANAGED, PROJECT = '~/.claude/settings.json', '/etc/claude-code/managed-settings.json', '~/app/.claude/settings.json'


class RuleCoverage(unittest.TestCase):
    def test_covering_pairs(self):
        for by, allow, match in (
                ('Bash(git push *)', 'Bash(git push *)', 'exact'), ('Bash(ls *)', 'Bash(ls:*)', 'exact'),
                ('Bash', 'Bash', 'exact'), ('Bash(*)', 'Bash(npm test)', 'tool'), ('Bash', 'Bash(npm test)', 'tool'),
                ('Read', 'Read(./src/**)', 'tool'), ('mcp__*', 'mcp__github__get_issue', 'tool'),
                ('*', 'WebSearch', 'tool'), ('Bash(git *)', 'Bash(git log *)', 'prefix'),
                ('Bash(git *)', 'Bash(git)', 'prefix'), ('Bash(git *)', 'Bash(git log*)', 'prefix'),
                ('Bash(git*)', 'Bash(gitk)', 'prefix'), ('Bash(git:*)', 'Bash(git status)', 'prefix')):
            with self.subTest(by=by, allow=allow):
                self.assertEqual(config_checks.rule_covers(by, allow), match)

    def test_non_covering_pairs(self):
        for by, allow in (
                ('Bash(git *)', 'Bash(gitk)'), ('Bash(git *)', 'Bash(git*)'), ('Bash(git *)', 'Bash(* --version)'),
                ('Bash(git push --force *)', 'Bash(git push *)'), ('Bash(rm *)', 'Bash'),
                ('Bash(timeout:*)', 'Bash(timeout 5 ls)'), ('Read(./src/**)', 'Read(./src/a.py)'),
                ('Bash(git * main)', 'Bash(git merge main)'), ('mcp__github__*', 'mcp__gitlab__get'),
                ('Bash(git push *)', 'mcp__github__push(x)'), ('mcp__*', 'mcp__github__create(x)'),
                ('Bash(git:* push)', 'Bash(git push)'), (None, 'Bash'), ('Bash(', 'Bash')):
            with self.subTest(by=by, allow=allow):
                self.assertIsNone(config_checks.rule_covers(by, allow))


class PermissionOverlaps(unittest.TestCase):
    def overlaps(self, *stacks):
        return config_checks.permission_overlaps(list(stacks), collect.redact)

    def test_deny_or_ask_in_any_layer_shadows_allow_and_is_reported_once(self):
        user = sfile('user', USER, allow=['Bash(git push *)', 'Bash(git log *)'])
        managed = sfile('managed', MANAGED, deny=['Bash(git push *)'])
        found, omitted = self.overlaps(stack('global', managed, user),
                                       stack('~/app', managed, user, sfile('project', PROJECT, ask=['Bash(git *)'])))
        self.assertEqual(omitted, 0)
        self.assertEqual(found, [
            {'stack': 'global', 'allow': {'layer': 'user', 'path': USER, 'rule': 'Bash(git push *)'},
             'by': {'list': 'deny', 'layer': 'managed', 'path': MANAGED, 'rule': 'Bash(git push *)'}, 'match': 'exact'},
            {'stack': '~/app', 'allow': {'layer': 'user', 'path': USER, 'rule': 'Bash(git log *)'},
             'by': {'list': 'ask', 'layer': 'project', 'path': PROJECT, 'rule': 'Bash(git *)'}, 'match': 'prefix'}])

    def test_deny_is_preferred_over_ask_and_same_file_counts(self):
        found, _ = self.overlaps(stack('global', sfile('user', USER, allow=['Bash(git push *)'],
                                                       ask=['Bash(git *)'], deny=['Bash(git push *)'])))
        self.assertEqual([(o['by']['list'], o['match']) for o in found], [('deny', 'exact')])

    def test_other_projects_are_never_paired(self):
        self.assertEqual(self.overlaps(stack('~/a', sfile('project', '~/a/.claude/settings.json', allow=['Bash(x)'])),
                                       stack('~/b', sfile('project', '~/b/.claude/settings.json', deny=['Bash(x)']))),
                         ([], 0))

    def test_cap_and_redaction(self):
        found, omitted = self.overlaps(stack('global', sfile('user', USER, allow=[f'Bash(t{i})' for i in range(35)],
                                                             deny=['Bash'])))
        self.assertEqual((len(found), omitted), (30, 5))
        secret = 'Bash(sk-abcdefghijklmnopqrstuv *)'
        found, _ = self.overlaps(stack('global', sfile('user', USER, allow=[secret], deny=[secret])))
        self.assertEqual(found[0]['allow']['rule'], 'Bash([REDACTED] *)')
        self.assertEqual(found[0]['by']['rule'], 'Bash([REDACTED] *)')
```

- [ ] **Step 2: Run to verify it fails**

Expected: ERROR `AttributeError: module 'config_checks' has no attribute 'rule_covers'`.

- [ ] **Step 3: Implement** (append to `config_checks.py`)

```python
MAX_OVERLAPS, MAX_DUPLICATES, MAX_SOURCES = 30, 20, 10
BASH_PARAMS = ('command', 'description', 'timeout', 'run_in_background')  # hooks.md Bash tool input
RULE_RE = re.compile(r'([^()]+?)(?:\((.*)\))?', re.S)


def _parse(rule):
    """(tool, specifier or None, is_bash_param_rule); None for unparseable rules.

    permissions.md: `Bash(*)` is equivalent to `Bash`; a trailing `:*` equals a trailing ` *`.
    """
    m = RULE_RE.fullmatch(rule.strip()) if isinstance(rule, str) else None
    if not m:
        return None
    tool, spec = m.group(1).strip(), m.group(2)
    param = False
    if tool == 'Bash' and spec is not None:
        spec = spec.strip()
        param = bool(re.match(r'(%s)\s*:' % '|'.join(BASH_PARAMS), spec))
        if spec == '*':
            spec = None
        elif spec.endswith(':*') and ':*' not in spec[:-2]:
            spec = spec[:-2] + ' *'
    return tool, spec, param


def rule_covers(by, allow):
    """'exact' | 'tool' | 'prefix' when every call `allow` matches is provably matched by `by`.

    Conservative: path globs and mid-rule wildcards are never compared, and a deny shaped like a
    Bash input-parameter rule (`Bash(timeout:*)`) is ambiguous, so it only matches exactly.
    """
    b, a = _parse(by), _parse(allow)
    if not b or not a:
        return None
    (btool, bspec, bparam), (atool, aspec, _) = b, a
    if atool.startswith('mcp__') and aspec is not None:
        return None  # "it skips any `mcp__` rule that has parentheses"
    if (btool, bspec) == (atool, aspec):
        return 'exact'
    if bspec is None:
        if btool == atool:
            return 'tool'
        if btool.count('*') == 1 and btool.endswith('*') and atool.startswith(btool[:-1]):
            return 'tool'
        return None
    if btool != atool or atool != 'Bash' or aspec is None or bparam:
        return None
    if bspec.count('*') != 1 or not bspec.endswith('*'):
        return None
    spaced = bspec.endswith(' *')
    prefix = bspec[:-2] if spaced else bspec[:-1]

    def ok(text, open_ended):
        if spaced:  # `git *` matches `git` and `git ...`, not `gitk`
            return text.startswith(prefix + ' ') or (not open_ended and text == prefix)
        return text.startswith(prefix)

    literal = aspec.split('*', 1)[0]
    bare = aspec[:-2] if aspec.endswith(' *') and aspec.count('*') == 1 else None
    if not ok(literal, '*' in aspec) or (bare is not None and not ok(bare, False)):
        return None
    return 'prefix'


def permission_overlaps(stacks, redact, cap=MAX_OVERLAPS):
    """Allow rules a deny or ask rule in the same stack always matches first; each pair reported once.

    permissions.md: "Rules are evaluated in order: deny, then ask, then allow", across all scopes.
    """
    seen, found = set(), []
    for stack in stacks:
        files = stack['settings']
        candidates = [(lst, f, rule) for lst in ('deny', 'ask') for f in files
                      for rule in f['permissions'].get(lst, [])]
        for f in files:
            for allow in f['permissions'].get('allow', []):
                for lst, by_file, by in candidates:
                    match = rule_covers(by, allow)
                    if match:
                        break
                else:
                    continue
                key = (f['path'], allow, by_file['path'], lst, by)
                if key in seen:
                    continue
                seen.add(key)
                found.append({'stack': stack['name'],
                              'allow': {'layer': f['layer'], 'path': f['path'], 'rule': redact(allow)[:160]},
                              'by': {'list': lst, 'layer': by_file['layer'], 'path': by_file['path'],
                                     'rule': redact(by)[:160]},
                              'match': match})
    return found[:cap], max(0, len(found) - cap)
```

- [ ] **Step 4: Run the tests.** Focused file. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/config_checks.py tests/test_config_checks.py
git commit -m "Detect allow rules shadowed by deny or ask rules in the same stack

Assisted-by: Claude:<model-id>"
```

---

### Task 4: Duplicate hooks across layers

**Files:**
- Modify: `S/scripts/config_checks.py`
- Test: `tests/test_config_checks.py`

**Interfaces:**
- Consumes: handler entries from `collect.hook_handler_entry` (Task 2): `event`, `matcher`, `type`, `fingerprint`, `plugin_relative`.
- Produces:
  - `config_checks.hook_duplicates(stacks, redact, cap=20) -> (list, omitted)`
  - `config_checks.conflicts(stacks, redact) -> dict`, with keys `stacks`, `hook_duplicates`, `hook_duplicates_omitted`, `permission_overlaps` and `permission_overlaps_omitted`

- [ ] **Step 1: Write the failing tests** (append)

```python
def entry(event, matcher, **handler):
    handler.setdefault('type', 'command')
    return collect.hook_handler_entry(event, matcher, handler)


class HookDuplicates(unittest.TestCase):
    def dups(self, *stacks):
        return config_checks.hook_duplicates(list(stacks), collect.redact)

    def test_effects_follow_the_docs(self):
        lint = entry('PreToolUse', 'Bash', command='lint.sh CANARY-cmd-7f3a')
        found, omitted = self.dups(stack('~/app', sfile('user', USER, handlers=[lint]),
                                         sfile('project', PROJECT, handlers=[lint])))
        self.assertEqual(omitted, 0)
        self.assertEqual(found, [{'stack': '~/app', 'event': 'PreToolUse', 'matcher': 'Bash', 'type': 'command',
                                  'fingerprint': lint['fingerprint'], 'effect': 'deduplicated',
                                  'sources': [{'layer': 'user', 'path': USER, 'plugin': None},
                                              {'layer': 'project', 'path': PROJECT, 'plugin': None}]}])
        self.assertNotIn('CANARY-cmd-7f3a', str(found))
        plugin = {'plugin': 'demo@m', 'path': '~/.claude/plugins/c/hooks/hooks.json', 'handlers': [lint]}
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[lint]), plugins=[plugin]))
        self.assertEqual(found[0]['effect'], 'separate_copies')
        self.assertEqual(found[0]['sources'][1], {'layer': 'plugin', 'path': plugin['path'], 'plugin': 'demo@m'})
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[lint, lint])))
        self.assertEqual(found[0]['effect'], 'same_file')

    def test_identity(self):
        local = '~/.claude/settings.local.json'
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[entry('Stop', None, command='x')]),
                                   sfile('local', local, handlers=[entry('Stop', '*', command='x')])))
        self.assertEqual(found[0]['matcher'], '*')
        for a, b in ((entry('PreToolUse', 'Bash', command='x'), entry('PreToolUse', 'Bash|Edit', command='x')),
                     (entry('PreToolUse', 'Bash', command='x', timeout=5), entry('PreToolUse', 'Bash', command='x'))):
            self.assertEqual(self.dups(stack('global', sfile('user', USER, handlers=[a]),
                                             sfile('local', local, handlers=[b]))), ([], 0))

    def test_plugin_root_commands_group_only_within_their_plugin(self):
        start = entry('SessionStart', None, command='${CLAUDE_PLUGIN_ROOT}/hooks/start.sh')
        plugins = [{'plugin': 'a@m', 'path': 'pa', 'handlers': [start]},
                   {'plugin': 'b@m', 'path': 'pb', 'handlers': [start]}]
        self.assertEqual(self.dups(stack('global', plugins=plugins)), ([], 0))

    def test_reported_once_and_capped(self):
        lint = entry('PreToolUse', 'Bash', command='lint.sh')
        g = stack('global', sfile('managed', MANAGED, handlers=[lint]), sfile('user', USER, handlers=[lint]))
        a = stack('~/app', sfile('managed', MANAGED, handlers=[lint]), sfile('user', USER, handlers=[lint]),
                  sfile('project', PROJECT))
        found, _ = self.dups(g, a)
        self.assertEqual([d['stack'] for d in found], ['global'])
        files = [sfile('user', f'f{i}', handlers=[entry('PreToolUse', 'Bash', command=f'c{j}') for j in range(25)])
                 for i in range(2)]
        self.assertEqual([len(x) if isinstance(x, list) else x for x in self.dups(stack('global', *files))], [20, 5])
        found, _ = self.dups(stack('global', *[sfile('user', f'f{i}', handlers=[lint]) for i in range(12)]))
        self.assertEqual(len(found[0]['sources']), 10)

    def test_conflicts_section_shape(self):
        section = config_checks.conflicts([stack('global', sfile('user', USER))], collect.redact)
        self.assertEqual(section, {'stacks': 1, 'hook_duplicates': [], 'hook_duplicates_omitted': 0,
                                   'permission_overlaps': [], 'permission_overlaps_omitted': 0})
```

- [ ] **Step 2: Run to verify it fails**

Expected: ERROR `AttributeError: module 'config_checks' has no attribute 'hook_duplicates'`.

- [ ] **Step 3: Implement** (append to `config_checks.py`)

```python
def hook_duplicates(stacks, redact, cap=MAX_DUPLICATES):
    """Identical handlers in more than one place within a stack; each group reported once.

    hooks.md: "If you define the same handler in more than one settings file, it runs once. A
    plugin's or skill's copy of the same handler stays separate." Handlers that reference
    CLAUDE_PLUGIN_* expand per plugin, so they group only within their own plugin.
    """
    seen, found = set(), []
    for stack in stacks:
        members = [(f['layer'], f['path'], None, h) for f in stack['settings'] for h in f['handlers']]
        members += [('plugin', p['path'], p['plugin'], h) for p in stack['plugins'] for h in p['handlers']]
        groups = {}
        for layer, path, plugin, h in members:
            key = (h['fingerprint'], plugin if h.get('plugin_relative') else None)
            groups.setdefault(key, []).append((layer, path, plugin, h))
        for key, group in groups.items():
            if len(group) < 2:
                continue
            ids = tuple(sorted((layer, path, plugin or '') for layer, path, plugin, _ in group))
            if (key, ids) in seen:
                continue
            seen.add((key, ids))
            paths = {path for _, path, _, _ in group}
            effect = ('same_file' if len(paths) == 1 else
                      'separate_copies' if any(layer == 'plugin' for layer, *_ in group) else 'deduplicated')
            first = group[0][3]
            found.append({'stack': stack['name'], 'event': redact(str(first['event'])),
                          'matcher': redact(str(normalize_matcher(first['matcher'])))[:200],
                          'type': redact(str(first['type'])), 'fingerprint': key[0], 'effect': effect,
                          'sources': [{'layer': layer, 'path': path, 'plugin': plugin}
                                      for layer, path, plugin, _ in group][:MAX_SOURCES]})
    return found[:cap], max(0, len(found) - cap)


def conflicts(stacks, redact):
    """The snapshot's config_conflicts section."""
    hooks, hooks_omitted = hook_duplicates(stacks, redact)
    perms, perms_omitted = permission_overlaps(stacks, redact)
    return {'stacks': len(stacks), 'hook_duplicates': hooks, 'hook_duplicates_omitted': hooks_omitted,
            'permission_overlaps': perms, 'permission_overlaps_omitted': perms_omitted}
```

- [ ] **Step 4: Run the tests.** Focused file. Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/config_checks.py tests/test_config_checks.py
git commit -m "Find duplicate hook handlers across settings layers and plugins

Assisted-by: Claude:<model-id>"
```

---

### Task 5: Collector wiring, stacks, schema and coverage

**Files:**
- Modify: `S/scripts/collect.py`: `_RAW_PERMISSIONS`, `LAYER_RANK`, `summarize_settings`, new `_stack_file` / `_file_layer` / `_stack_plugins` / `config_stacks` before `discover_projects`, plus `build_snapshot` and `snapshot_coverage`
- Modify: `S/references/snapshot.schema.json` (`$defs.config_layer`, optional `config_conflicts`)
- Test: `tests/test_config_checks.py`, `tests/test_snapshot_contract.py`

**Interfaces:**
- Consumes: `config_checks.conflicts` (Task 4); `snap['extensions']['plugins']` (existing).
- Produces:
  - `collect.config_stacks(snap) -> list[stack]`
  - `snap['config_conflicts']`
  - the coverage source `{'source': 'config_conflicts', 'scope': <requested>, 'status': 'collected'|'partial', 'basis': 'static', 'omitted': int}`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_config_checks.py`, and add `import argparse, copy, json, os` and `from unittest import mock` to the imports:

```python
class ConfigConflictsEndToEnd(FakeHome):
    def build(self, *argv):
        ap = argparse.ArgumentParser()
        collect.add_collection_args(ap)
        a = ap.parse_args(['--claude-dir', self.claude, *argv])
        collect.apply_collection_args(ap, a)
        with mock.patch.object(collect, 'managed_directory', return_value=os.path.join(self.home, 'managed')):
            return collect.build_snapshot(a)

    def fixture(self):
        hooks = {'PreToolUse': [{'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': 'lint.sh CANARY-7f3a'}]}]}
        self.write('.claude/settings.json', {'permissions': {'allow': ['Bash(git push *)']}, 'hooks': hooks,
                                             'enabledPlugins': {'demo@market': True}})
        self.write('.claude/settings.local.json', {'permissions': {'deny': ['Bash(git push *)']}})
        self.write('repo/.claude/settings.json', {'permissions': {'allow': ['Bash(git log *)'], 'ask': ['Bash(git *)']},
                                                  'hooks': hooks})
        self.write('repo/.claude/settings.local.json', {'enabledPlugins': {'demo@market': False}})
        root = os.path.join(self.claude, 'plugins/cache/market/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'demo@market': [{'scope': 'user', 'installPath': root, 'version': '1'}]}})
        self.write('.claude/plugins/cache/market/demo/1/hooks/hooks.json', {'hooks': hooks})
        return os.path.join(self.home, 'repo')

    def test_layers_precedence_and_report_once(self):
        root = self.fixture()
        snap = self.build('--scope', 'project', '--project', root)
        cc = snap['config_conflicts']
        self.assertEqual(cc['stacks'], 2)
        # global: the user hook and the enabled plugin's copy both run; ~/repo: project-local false
        # disables the plugin, so the user and project copies are one deduplicated handler.
        self.assertEqual([(d['stack'], d['effect']) for d in cc['hook_duplicates']],
                         [('global', 'separate_copies'), ('~/repo', 'deduplicated')])
        # home-local deny applies only to home-directory sessions; in ~/repo the project ask shadows.
        self.assertEqual([(o['stack'], o['allow']['rule'], o['by']['list'], o['by']['layer'], o['match'])
                          for o in cc['permission_overlaps']],
                         [('global', 'Bash(git push *)', 'deny', 'local', 'exact'),
                          ('~/repo', 'Bash(git push *)', 'ask', 'project', 'prefix'),
                          ('~/repo', 'Bash(git log *)', 'ask', 'project', 'prefix')])
        self.assertNotIn('CANARY-7f3a', json.dumps(cc))
        self.assertIn('config_conflicts', [s['source'] for s in snap['coverage']['sources']])
        for rel in ('.claude/settings.json', '.claude/settings.local.json', 'repo/.claude/settings.json'):
            os.remove(os.path.join(self.home, rel))
        again = self.build('--scope', 'project', '--project', root)['config_conflicts']
        self.assertEqual((again['permission_overlaps'], again['hook_duplicates']), ([], []))

    def test_global_scope_has_one_stack(self):
        self.fixture()
        self.assertEqual(self.build('--scope', 'global')['config_conflicts']['stacks'], 1)
```

Append to `tests/test_snapshot_contract.py` (class `SnapshotContract`):

```python
    def test_config_conflicts_are_optional_and_checked(self):
        snap = self.snapshot()
        self.assertEqual(snap["config_conflicts"]["stacks"], 1)
        snap["config_conflicts"] = {
            "stacks": 1, "hook_duplicates_omitted": 0, "permission_overlaps_omitted": 0,
            "hook_duplicates": [{"stack": "global", "event": "PreToolUse", "matcher": "Bash", "type": "command",
                                 "fingerprint": "0123456789abcdef", "effect": "deduplicated",
                                 "sources": [{"layer": "user", "path": "~/.claude/settings.json", "plugin": None}]}],
            "permission_overlaps": [{"stack": "global",
                                     "allow": {"layer": "user", "path": "~/.claude/settings.json", "rule": "Bash(x)"},
                                     "by": {"list": "deny", "layer": "managed", "path": "/etc/m.json", "rule": "Bash"},
                                     "match": "tool"}]}
        contract.validate_snapshot(snap)
        contract.validate_snapshot({k: v for k, v in snap.items() if k != "config_conflicts"})
        for mutate in (lambda c: c["hook_duplicates"][0].update(effect="bogus"),
                       lambda c: c["hook_duplicates"][0].pop("fingerprint"),
                       lambda c: c["hook_duplicates"][0]["sources"][0].update(layer="bogus"),
                       lambda c: c["permission_overlaps"][0].update(match="bogus"),
                       lambda c: c["permission_overlaps"][0]["by"].update(list="allow"),
                       lambda c: c.update(permission_overlaps_omitted=-1),
                       lambda c: c.update(stacks=0)):
            altered = copy.deepcopy(snap)
            mutate(altered["config_conflicts"])
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)
```

- [ ] **Step 2: Run to verify it fails**

Run both focused files.
Expected: `KeyError: 'config_conflicts'`.

- [ ] **Step 3: Implement in `collect.py`**

Directly above `summarize_settings`:

```python
# Settings display path -> raw allow/ask/deny rules of that file, filled by summarize_settings and
# cleared by build_snapshot. Read only by config_stacks(); never serialized (summaries are).
_RAW_PERMISSIONS = {}
LAYER_RANK = {"user": 0, "project": 1, "local": 2, "managed": 3}  # settings precedence, lowest first
```

In `summarize_settings`, make these three changes:

1. Bind `perms = d.get("permissions", {}) or {}` before `settings_dir = ...`.
2. Rename the returned dict to `summary = {...}` and pass `analyze_permissions(perms)`.
3. After the dict, add these lines, keeping exception behavior for malformed files unchanged (analyze_permissions still raises first):

```python
    # Raw rules for config_stacks(); never part of a summary, which is serialized.
    _RAW_PERMISSIONS[summary["path"]] = {k: [r for r in (perms.get(k) if isinstance(perms.get(k), list) else [])
                                            if isinstance(r, str)] for k in ("allow", "ask", "deny")}
    return summary
```

Directly above `discover_projects`:

```python
def _stack_file(summary, layer):
    enabled = summary.get("enabled_plugins")
    return {"layer": layer, "path": summary["path"],
            "permissions": _RAW_PERMISSIONS.get(summary["path"], {"allow": [], "ask": [], "deny": []}),
            "handlers": summary.get("hook_handlers") or [],
            "enabled_plugins": enabled if isinstance(enabled, dict) else {}}


def _file_layer(summary, shared):
    return "local" if summary["path"].endswith("settings.local.json") else shared


def _stack_plugins(plugins, files, root):
    """Enabled plugins' hook handlers for one stack; enablement from the highest-precedence file."""
    out, seen = [], set()
    for p in plugins:
        name = p.get("name")
        if name in seen or p.get("status") != "collected":
            continue
        if p.get("scope") in ("project", "local"):
            project = p.get("project")
            if root is None or not isinstance(project, str) or project.replace(HOME, "~") != root:
                continue
        values = sorted(((LAYER_RANK[f["layer"]], f["enabled_plugins"][name]) for f in files
                         if name in f["enabled_plugins"]), key=lambda v: v[0])
        if not values or values[-1][1] is not True:
            continue
        seen.add(name)
        for c in p.get("components", []):
            if c.get("kind") == "hooks" and c.get("handlers"):
                out.append({"plugin": name, "path": c["source"].replace(HOME, "~"), "handlers": c["handlers"]})
    return out


def config_stacks(snap):
    """Settings files that apply together: global (managed, user, home-local) and one per project.

    permissions.md: ~/.claude/settings.local.json is read only in sessions started in the home
    directory, so project stacks leave it out.
    """
    managed = [_stack_file(s, "managed") for s in snap["managed_settings"]["settings"]]
    user = [_stack_file(s, _file_layer(s, "user")) for s in snap["global"]["settings"]]
    plugins = snap["extensions"]["plugins"]
    stacks = [{"name": "global", "settings": managed + user,
               "plugins": _stack_plugins(plugins, managed + user, None)}]
    for name in sorted(snap["projects"]):
        own = [_stack_file(s, _file_layer(s, "project")) for s in snap["projects"][name].get("settings", [])]
        if own:
            files = managed + [f for f in user if f["layer"] == "user"] + own
            stacks.append({"name": name, "settings": files, "plugins": _stack_plugins(plugins, files, name)})
    return stacks
```

In `build_snapshot`:
- make `_RAW_PERMISSIONS.clear()` the first statement;
- directly after the `snap['extensions'] = extensions.collect_extensions(...)` assignment, add:

```python
    snap["config_conflicts"] = config_checks.conflicts(config_stacks(snap), redact)
```

In `snapshot_coverage`, before `sources.extend(snap.get("instructions", {}).get("sources", []))`:

```python
    conflicts = snap.get("config_conflicts")
    if conflicts:
        omitted = conflicts["hook_duplicates_omitted"] + conflicts["permission_overlaps_omitted"]
        sources.append(source_coverage("config_conflicts", scope, "partial" if omitted else "collected",
                                      basis="static", omitted=omitted))
```

**Schema** (`snapshot.schema.json`). Add `"config_layer": {"enum": ["managed", "user", "project", "local", "plugin"]}` to `$defs`, and add this optional property next to `drift_signals`, without adding it to `required`:

```json
    "config_conflicts": {
      "type": "object",
      "required": ["stacks", "hook_duplicates", "hook_duplicates_omitted", "permission_overlaps",
                   "permission_overlaps_omitted"],
      "properties": {
        "stacks": {"type": "integer", "minimum": 1},
        "hook_duplicates": {"type": "array", "items": {
          "type": "object",
          "required": ["stack", "event", "matcher", "type", "fingerprint", "effect", "sources"],
          "properties": {
            "stack": {"type": "string"}, "event": {"type": "string"}, "matcher": {"type": "string"},
            "type": {"type": "string"}, "fingerprint": {"type": "string"},
            "effect": {"enum": ["deduplicated", "separate_copies", "same_file"]},
            "sources": {"type": "array", "items": {
              "type": "object", "required": ["layer", "path", "plugin"],
              "properties": {"layer": {"$ref": "#/$defs/config_layer"}, "path": {"type": "string"},
                             "plugin": {"type": ["string", "null"]}}}}}}},
        "hook_duplicates_omitted": {"type": "integer", "minimum": 0},
        "permission_overlaps": {"type": "array", "items": {
          "type": "object", "required": ["stack", "allow", "by", "match"],
          "properties": {
            "stack": {"type": "string"},
            "allow": {"type": "object", "required": ["layer", "path", "rule"],
                      "properties": {"layer": {"$ref": "#/$defs/config_layer"}, "path": {"type": "string"},
                                     "rule": {"type": "string"}}},
            "by": {"type": "object", "required": ["list", "layer", "path", "rule"],
                   "properties": {"list": {"enum": ["deny", "ask"]}, "layer": {"$ref": "#/$defs/config_layer"},
                                  "path": {"type": "string"}, "rule": {"type": "string"}}},
            "match": {"enum": ["exact", "tool", "prefix"]}}}},
        "permission_overlaps_omitted": {"type": "integer", "minimum": 0}
      }
    },
```

- [ ] **Step 4: Run the tests**

Run both focused files, then the full suite, then `python3 tests/check_snapshot_schema.py`.
Expected: PASS. If any existing test pins the exact list of `coverage.sources` names, extend it with `config_conflicts` rather than weakening it.

These results were checked on a scratch copy of the committed tree on 2026-09-29:
- the fixture above produced exactly the asserted overlaps and duplicates;
- the existing suite stayed green;
- `check_snapshot_schema.py` passed with `jsonschema`.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json tests/test_config_checks.py tests/test_snapshot_contract.py
git commit -m "Add config_conflicts to the snapshot from per-project settings stacks

Assisted-by: Claude:<model-id>"
```

---

### Task 6: Documentation

**Files:**
- Modify:
  - `S/references/checklist.md`
  - `S/references/snapshot-format.md`
  - `S/references/coverage.md`
  - `S/SKILL.md`
  - `README.md`
  - `CHANGELOG.md` (`[Unreleased]`)
  - `docs/roadmap.md`
- Create: `docs/superpowers/specs/2026-09-29-deeper-checks-2a-design.md` and `docs/superpowers/plans/2026-09-29-deeper-checks-2a.md`, if the controller has not already committed them.

- [ ] **Step 1: Re-verify the docs (raw only)**

```bash
curl -sL https://code.claude.com/docs/en/permissions.md | grep -n -F -e 'warns at startup' -e 'only recognized at the end' -e 'so any program matches' -e 'matches `lsof` too' -e 'skips any `mcp__` rule' -e 'ignores it and emits a startup warning' -e 'deny, then ask, then allow'
curl -sL https://code.claude.com/docs/en/errors.md | grep -n -F -e "doesn't warn about deny and ask rules" -e 'Before v2.1.246'
curl -sL https://code.claude.com/docs/en/hooks.md | grep -n -F -e 'it runs once' -e 'silently ignored' -e 'never runs' -e 'matches no tool' -e 'narrower exact-match set'
```

Each command must print at least one line per pattern. If a sentence is gone or changed, stop and report the difference, because a constant or a checklist claim would need a ruling. Record "fetched <date>" with the date of this run.

- [ ] **Step 2: `checklist.md`**

In the Security section, directly after the SEC-risky-allow block, add:

```markdown
- **SEC-wildcard-placement** (`permissions.rule_shape_issues.allow`, static; permissions docs "Wildcard
  patterns", fetched 2026-09-29): allow rules whose `*` reaches further than the rule reads.
  - `wildcard-before-subcommand`: a `*` after only the program name, followed by a later word
    (`Bash(git * main)`, `Bash(git -C * status *)`). The `*` also matches options inserted there:
    `git -c core.fsmonitor=<script> diff main` makes git run a program. Claude Code (v2.1.246+) warns
    at startup when the later word is the subcommand; the collector can't tell a subcommand from an
    argument, so confirm before proposing. Fix: the exact value, or one rule per subcommand with the
    `*` after it (`Bash(git status *)`).
  - `wildcard-program`: `*` in the program position (`Bash(* --version)`) matches any program.
  - `star-joined-to-program`: no space before the trailing `*` (`Bash(ls*)` also matches `lsof`).
    Fix: `Bash(ls *)`.
  - `colon-star-literal`, `mcp-rule-with-parentheses`: the rule does nothing as written (hygiene).
  Weigh together with SEC-risky-allow: a flagged git, interpreter or network rule is worse.
- **SEC-ineffective-deny** (`permissions.rule_shape_issues.deny` / `.ask`, static): deny or ask rules
  Claude Code doesn't apply as written, so the block or prompt the user expects never happens.
  - `colon-star-literal`: `:*` only works at the end; in `Bash(git:* push)` the colon is literal
    and the rule matches no git command. Fix: `Bash(git push *)`.
  - `ignored-primary-field`: `Tool(param:value)` on a primary content field (`command`, `file_path`,
    `path`, `notebook_path`, `url`). The docs say these can't be matched this way; for
    `Bash(command:rm *)` they say Claude Code ignores the rule and warns at startup. Fix:
    `Bash(rm *)`, `Read(./path)`, `WebFetch(domain:host)`.
  - `mcp-rule-with-parentheses`: settings files skip `mcp__` rules with parentheses; parameter
    matching on MCP tools needs `--disallowedTools`.
  Other wildcard shapes in deny/ask match more rather than less (Claude Code refuses or prompts for
  the extra commands, errors docs), so they aren't flagged. Severity is high when the rule guards
  secrets or destructive commands.
```

In the Hygiene section, replace the existing `HYG-hook-duplicates` bullet, and add the other two bullets after it:

```markdown
- **HYG-hook-duplicates** (`config_conflicts.hook_duplicates`, static): the same handler (event,
  matcher, whole handler object; `fingerprint` joins to `hook_handlers[].fingerprint` for the
  redacted command) in several places of one stack. Per the hooks docs (fetched 2026-09-29), the
  same handler in more than one settings file runs once (`effect: deduplicated`: clutter, low); a
  plugin's copy stays separate (`separate_copies`: it runs twice, double cost and side effects,
  medium, higher on `PreToolUse`/`SessionStart`); `same_file`: the docs don't say, report as
  clutter. Fix: drop the settings copy when a plugin provides the hook. Under
  `allow_managed_hooks_only` or `disableAllHooks`, check which copies actually run first.
- **HYG-shadowed-allow** (`config_conflicts.permission_overlaps`, static): an allow rule that a
  deny or ask rule in the same stack always matches first. Rules are evaluated deny, then ask, then
  allow, across every scope (permissions docs), so the allow never takes effect: with `by.list: deny`
  the call is blocked; with `ask` it still prompts (the usual cause of "I said don't ask again and it
  still asks"). `match`: `exact`, `tool` (a bare or tool-glob rule) or `prefix` (a Bash trailing
  wildcard). Only provable coverage is reported; path globs and mid-rule wildcards aren't compared,
  so absence isn't proof. Fix: remove the dead allow, or narrow the deny/ask if the allow was
  intended; never propose loosening a managed rule.
- **HYG-hook-config** (`hook_handlers[].issues` / `unknown_fields`, the same fields on
  `extensions.plugins[].components[].handlers[]`, static; hooks docs fetched 2026-09-29): hook
  configuration that doesn't do what it reads.
  - Never fires: `unknown_event` (not a documented event; check case, e.g. `pretooluse`),
    `if_never_runs` (`if` on a non-tool event), `mcp_server_only_matcher` (`mcp__server` without
    `__.*` is compared exactly and matches no tool).
  - Fires more than intended: `matcher_ignored` (a matcher on an event without matcher support is
    silently ignored, so the hook runs on every occurrence), `narrow_event_regex_path` (a
    `StopFailure` matcher with a comma, space or hyphen is a regex, not a list; only `|` separates).
  - Unclear: `invalid_regex` (doesn't compile; checked with Python `re`, JS-only constructs skipped;
    what Claude Code does with it is undocumented, so say "invalid", not "ignored"),
    `matcher_not_string`, `unknown_type`, `unknown_fields` (not in the documented fields for that
    handler type; name the field, don't claim it's ignored).
  A guard that never fires (a `PreToolUse` or security hook) is high severity; the rest is hygiene.
```

- [ ] **Step 3: `snapshot-format.md`**

Add this Compatibility bullet after the `drift_signals` bullet:

```markdown
- `config_conflicts` (always emitted by current collectors, optional in the schema):
  - `stacks`;
  - `hook_duplicates` (stack, event, normalized matcher, type, 16-hex `fingerprint`, `effect`,
    sources with layer/path/plugin);
  - `permission_overlaps` (stack, allow and covering rule with layer/path, redacted rule text,
    covering list, `match`);
  - `*_omitted` counts.

  Settings summaries also carry:
  - `permissions.rule_shape_issues`;
  - handler `fingerprint`, and `issues`/`unknown_fields`/`plugin_relative` when present.

  Additive within snapshot v1.
```

- [ ] **Step 4: `coverage.md`**

Add a "Configuration checks" section after "Harness overhead". Cover:
- The coverage source `config_conflicts` (`collected`, or `partial` when caps omitted entries; `basis: static`).
- Stacks: `global` is managed + user + home-local; each collected project directory is managed + user `settings.json` + its own files.
- Plugin enablement comes from the highest-precedence file in the stack (managed > local > project > user).
- Limitations:
  - `--settings`, CLI flags, server/MDM policy and skill/agent frontmatter hooks are not seen;
  - nested project directories are separate stacks;
  - overlaps cover only exact, tool and single-trailing-wildcard Bash cases;
  - extension handler caps (100 per component) can hide a duplicate.
- The documentation baseline: the permissions, errors and hooks pages with the Step 1 fetch date. Say that the collector never runs hooks or evaluates rules against real commands.

- [ ] **Step 5: `SKILL.md`**

In the measured/estimated list, add:

```markdown
- Static (configuration text only): `permissions.rule_shape_issues`, hook handler `issues`, and
  `config_conflicts`. Their effects come from the quoted docs, not observed runs; say so.
```

- [ ] **Step 6: `README.md`**

In the Security bullet (around line 15), add "wildcards that match more than they read, deny rules Claude Code ignores". Where the README lists hygiene items (if it does), add "hooks that can never fire, duplicate hooks and shadowed allow rules". Keep the wording short.

- [ ] **Step 7: `CHANGELOG.md` `[Unreleased]` and `docs/roadmap.md`**

Append under the existing headings; another branch edits `[Unreleased]` too.

CHANGELOG, under Added:
- Permission rule-shape checks (`permissions.rule_shape_issues`; `SEC-wildcard-placement`, `SEC-ineffective-deny`).
- Hook handler validation against the hooks docs (per-handler `issues`, `fingerprint`; `HYG-hook-config`).
- Cross-layer `config_conflicts`: duplicate hooks and shadowed allow rules (`HYG-hook-duplicates` is now evidence-backed; `HYG-shadowed-allow`).

CHANGELOG, under Changed:
- `HYG-hook-duplicates` no longer claims settings-file duplicates run twice (the hooks docs: they run once; plugin copies stay separate).

Roadmap: in "Deeper checks", mark hook matcher validation, duplicate hooks/layer conflicts and permission wildcard placement implemented (unreleased). Keep MCP exposure metadata and recurring tool-error clustering as remaining work.

- [ ] **Step 8: Gate**

Run the full suite, the schema check, `git diff --check`, and coverage ≥ 88.

- [ ] **Step 9: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/references/checklist.md plugins/setup-audit/skills/setup-audit/references/snapshot-format.md plugins/setup-audit/skills/setup-audit/references/coverage.md plugins/setup-audit/skills/setup-audit/SKILL.md README.md CHANGELOG.md docs/roadmap.md
git commit -m "Document rule-shape, hook-config and cross-layer conflict checks

Assisted-by: Claude:<model-id>"
```

---

## Final review (after Task 6)

Review the whole branch against the spec, in particular:

- **Negative cases:** every spec negative case has a test.
- **Privacy:** no raw hook command in `config_conflicts`. `_RAW_PERMISSIONS` is never serialized; grep the snapshot of the Task 5 fixture for `CANARY`.
- **Doc claims:** checklist claims match the raw quotes. Nothing is labeled "ignored" where the docs say nothing.
- **Schema:** it uses no `number` type.
- **Size:** measure snapshot growth on the Task 5 fixture (serialized size before and after) and report it.
