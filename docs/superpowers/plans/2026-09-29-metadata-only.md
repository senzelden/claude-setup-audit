# Metadata-Only Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A contextual secret detector in both modes, plus an opt-in `collect.py --metadata-only`. The
flag replaces every free-text snapshot field with a `[metadata-only: N chars]` marker and records the
mode in `coverage.privacy`. The model guidance, report validation and renderer know the mode.

**Architecture:** A new stdlib module `scripts/privacy.py` holds the detector, which is called from
`collect.redact()`/`sanitize()` and the `secret-literal-in-rule` risk flag. It also holds the masking
post-pass `mask_snapshot()`, called once in `build_snapshot()` before `sanitize()`, and the string
classification registry `KEPT_STRING_FIELDS`, which a test enforces on a canary fake home.

**Tech Stack:** Python 3.11+ standard library; `unittest`; the bundled snapshot schema evaluator.

**Spec:** `docs/superpowers/specs/2026-09-29-metadata-only-design.md` (field inventory, detector
thresholds, fixture table and rulings R1–R19 live there; this plan does not repeat them).

## Global Constraints

- Stdlib only. Tests use temporary fake homes (`FakeHome` in `tests/test_collect.py`). Never read or
  write the real `~/.claude`, and never run the collector against the real home. The canary tests
  patch `collect.managed_directory` to a path inside the fake home, so `/etc/claude-code` is never
  read.
- Snapshot stays version 1. Only additive changes: optional `coverage.privacy` and new handler
  fields. Never change an existing field's type (masked values stay strings).
- Masking never changes dict keys, numbers, booleans or `null`, and never changes a list's length.
- Detector constants are fixed: `CONTEXT_MIN_LEN = 16`, `CONTEXT_MAX_LEN = 512`,
  `PASSWORD_MIN_LEN = 6`, `ENTROPY_MIN = 3.5`. If a spec fixture lands on the wrong side, stop and
  report. Do not retune silently. Any change stays within 3.2–4.0 and updates spec ruling 10.
- Never add a free-text field to `KEPT_STRING_FIELDS` to make a test pass. Classify it per the spec
  inventory.
- Commits: explicit paths; the message ends with exactly one trailer
  `Assisted-by: Claude:<model-id>`. Never stage `AGENTS.md`, `CODEX-SETUP.md` or `.superpowers/`.
  Do not push, tag or switch branches.
- Focused tests: `python3 -m unittest discover -s tests -p test_privacy.py -v` (`tests/` is not a
  package).
- Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`,
  `git diff --check`, coverage ≥ 88: run
  `uvx --from coverage==7.16.2 coverage run -m unittest discover -s tests`, then
  `uvx --from coverage==7.16.2 coverage report | tail -1`, then
  `uvx --from coverage==7.16.2 coverage erase`. Never use a glob `rm`.
- The Bash sandbox is broken in this environment; run commands with the sandbox disabled.
- Existing tests that assert exact `hook_handler_entry` dicts or full coverage objects will need the
  new keys. Update those expectations; do not loosen assertions.

Paths: `S = plugins/setup-audit/skills/setup-audit`.

## Review Focus

1. `-e AWS_SECRET_ACCESS_KEY=<v>`: the flag branch must not consume the label, so the value is
   still redacted (Task 1 `test_true_positives`, row T10).
2. The same session dict appears in `heaviest_sessions` and `most_friction_sessions` before
   serialization. It must be masked once, with the marker length equal to the original (Task 2
   `test_shared_objects_are_masked_once`).
3. The metadata-only snapshot of the canary home must contain no canary. The full one must contain
   all of them, otherwise the first check proves nothing (Task 4).
4. Every string leaf of the metadata-only canary snapshot must be a marker or classified (Task 4
   `test_every_string_leaf_is_classified`).
5. `claude_env_hook` must still be computed from unmasked hook commands in metadata-only mode (Task 3
   `test_env_hook_join_runs_before_masking`).

---

### Task 1: Contextual secret detector (both modes)

**Files:**
- Create: `S/scripts/privacy.py`
- Modify: `S/scripts/collect.py` (`redact`, `sanitize`, `RISKY_RULES` entry `secret-literal-in-rule`)
- Test: `tests/test_privacy.py` (new), `tests/test_collect.py` (one test)

**Interfaces:**
- Produces:
  - `privacy.CONTEXT_TOKEN = "[REDACTED:context]"`
  - `privacy.shannon(s: str) -> float` (bits per character; `""` gives 0.0)
  - `privacy.label_segments(label: str) -> list[str]` (camelCase split, then `[_.\-]+` split, lowercased, leading dashes stripped, empties dropped)
  - `privacy.contextual_secret(label: str, value: str) -> bool` (the spec's class, qualifier and value rules)
  - `privacy.contextual_redact(text: str) -> str`
  - `privacy.contextual_search(text: str) -> bool` (`contextual_redact(text) != text`)
- Consumes: nothing new.

- [ ] **Step 1: Write the failing tests** (`tests/test_privacy.py`)

```python
"""Privacy: contextual secret detection and metadata-only masking. Fake homes only."""
import json
import unittest
from test_collect import FakeHome, collect, flags
import privacy

AWS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
TRUE_POSITIVES = [  # (input, secret value, label that must survive) -- spec table T1-T10
    (f'export AWS_SECRET_ACCESS_KEY={AWS}', AWS, 'AWS_SECRET_ACCESS_KEY='),
    ('STRIPE_SECRET_KEY=sk_prod_4eC39HqLyjWDarjtT1zdp7dc', 'sk_prod_4eC39HqLyjWDarjtT1zdp7dc', 'STRIPE_SECRET_KEY='),
    ('SECRET_KEY = "Zx9fK2mQ7vL1pR8tW3yB6nD4"', 'Zx9fK2mQ7vL1pR8tW3yB6nD4', 'SECRET_KEY = "'),
    ('curl --api-token 9fK2mQ7vL1pR8tW3yB6nD4hJ https://api.example.com', '9fK2mQ7vL1pR8tW3yB6nD4hJ', '--api-token '),
    ('mysql --password hunter22x -h db', 'hunter22x', '--password '),
    ('GITHUB_PAT=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF',
     'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF', 'GITHUB_PAT='),
    ('sessionKey: 7Hq2LmX9pRt4VzK8wN3b', '7Hq2LmX9pRt4VzK8wN3b', 'sessionKey: '),
    ('curl -H "X-Auth: 3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c" https://x.example', '3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c', 'X-Auth: '),
    ('https://b.s3.amazonaws.com/f?X-Amz-Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024',
     'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024', 'X-Amz-Signature='),
    (f'docker run -e AWS_SECRET_ACCESS_KEY={AWS} app', AWS, 'AWS_SECRET_ACCESS_KEY='),
]
MUST_NOT_FLAG = [  # spec table N1-N25
    'git checkout 3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
    'commit_sha=3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
    'session_id=550e8400-e29b-41d4-a716-446655440000',
    'claude --resume 550e8400-e29b-41d4-a716-446655440000',
    'key_file=/home/user/.ssh/id_ed25519',
    'ssh_key: ~/.ssh/id_ed25519',
    'api_key_env=ANTHROPIC_API_KEY_BACKUP',
    'SIGNING_KEY=PROD_SIGNING_KEY_2026',
    'max_tokens=4096',
    'image=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
    'cacheKey: release-2026-09-29-build',
    'sort_keys=True',
    'hotkey: ctrl+shift+k',
    'session=2026-09-29T10:00:00Z',
    '--token-file ./secrets/ci.token',
    'fingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8',
    'signature_hash=9b74c9897bac770ffc029102a200c5de',
    'session_key=aaaaaaaa11111111',
    'auth_token_2=abababababababab12',
    'KEYBINDINGS=vim',
    '/home/u/code/token-service/src/auth_middleware.py',
    'OPENAI_API_KEY=$(pass show openai)',
    'password_file=/run/secrets/db',
    '--session-id 7c9e6679-7425-40de-944b-e07fc1f90ae7',
    '[metadata-only: 143 chars]',
]


class ContextualDetection(unittest.TestCase):
    def test_true_positives(self):
        for text, secret, label in TRUE_POSITIVES:
            with self.subTest(text=text[:40]):
                self.assertIn(secret, collect.SECRET_RE.sub('[REDACTED]', text))  # the gap this closes
                out = collect.redact(text)
                self.assertNotIn(secret, out)
                self.assertIn(label + privacy.CONTEXT_TOKEN, out)

    def test_must_not_flag(self):
        for text in MUST_NOT_FLAG:
            with self.subTest(text=text[:40]):
                self.assertEqual(collect.redact(text), text)

    def test_accepted_over_redaction(self):
        text = 'cache_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        self.assertEqual(collect.redact(text), 'cache_key=' + privacy.CONTEXT_TOKEN)

    def test_shannon_reference_values(self):
        self.assertAlmostEqual(privacy.shannon('0123456789abcdef'), 4.0)
        self.assertEqual(privacy.shannon('aaaa'), 0.0)
        self.assertEqual(privacy.shannon(''), 0.0)

    def test_label_segments(self):
        self.assertEqual(privacy.label_segments('sessionKey'), ['session', 'key'])
        self.assertEqual(privacy.label_segments('--api-token'), ['api', 'token'])
        self.assertEqual(privacy.label_segments('AWS_SECRET_ACCESS_KEY'), ['aws', 'secret', 'access', 'key'])

    def test_sanitize_checks_json_key_value_pairs(self):
        out = collect.sanitize({'AWS_SECRET_ACCESS_KEY': AWS, 'session_cwd': '/tmp/app',
                                'commit_sha': '3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c', 'api_key': '$FOO'})
        self.assertEqual(out['AWS_SECRET_ACCESS_KEY'], privacy.CONTEXT_TOKEN)
        self.assertEqual(out['session_cwd'], '/tmp/app')
        self.assertEqual(out['commit_sha'], '3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c')
        self.assertEqual(out['api_key'], '$FOO')
```

Add to `tests/test_collect.py` `RiskClassification`:

```python
    def test_contextual_literal_secret_flags_secret_literal_in_rule(self):
        self.assertIn('secret-literal-in-rule',
                      flags('Bash(export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY && aws s3 ls)'))
        self.assertNotIn('secret-literal-in-rule', flags('Bash(export AWS_PROFILE=dev)'))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v`
Expected: ERROR `ModuleNotFoundError: No module named 'privacy'`.

- [ ] **Step 3: Implement the detector in `S/scripts/privacy.py`**

```python
"""Privacy helpers: contextual secret detection (both modes) and metadata-only masking. Stdlib only."""
import math
import re
from collections import Counter

CONTEXT_TOKEN = '[REDACTED:context]'
CONTEXT_MIN_LEN, CONTEXT_MAX_LEN, PASSWORD_MIN_LEN, ENTROPY_MIN = 16, 512, 6, 3.5
PASSWORD_WORDS = {'password', 'passwd', 'pwd', 'passphrase', 'pass'}
SECRET_WORDS = {'key', 'secret', 'token', 'auth', 'credential', 'credentials', 'creds', 'signature',
                'sig', 'cookie', 'session', 'pat', 'apikey'}
QUALIFIERS = {'id', 'ids', 'name', 'names', 'file', 'path', 'dir', 'url', 'uri', 'env', 'var', 'type',
              'kind', 'format', 'count', 'len', 'length', 'size', 'max', 'min', 'limit', 'ttl', 'sha',
              'hash', 'digest', 'commit', 'rev', 'checksum', 'fingerprint', 'etag', 'hint', 'header',
              'field', 'prefix', 'mode', 'source', 'ref', 'version', 'expiry', 'expires'}
VALUE_CHARS = r'A-Za-z0-9+/_.~=-'
CONTEXT_RE = re.compile(
    r'(?<![\w.-])(?:(?P<flag>--?[A-Za-z][\w.-]{0,63})(?:\s+|=)'
    r'|(?P<label>[A-Za-z][\w.-]{0,63})["\']?\s*[:=]\s*)'
    rf'["\']?(?P<value>[{VALUE_CHARS}]{{{PASSWORD_MIN_LEN},{CONTEXT_MAX_LEN}}})(?![{VALUE_CHARS}:])')
UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')
SNAKE_RE = re.compile(r'[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\Z')
FILE_END_RE = re.compile(r'\.[a-z]{1,5}\Z')


def shannon(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def label_segments(label):
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', label.lstrip('-'))
    return [s for s in re.split(r'[_.\-]+', spaced.lower()) if s]


def _label_class(label):
    segments = label_segments(label)
    if any(s in QUALIFIERS for s in segments):
        return None
    if any(s in PASSWORD_WORDS or s.endswith(('password', 'passwd')) for s in segments):
        return 'password'
    if any(s in SECRET_WORDS or s.endswith(('key', 'secret', 'token')) for s in segments):
        return 'secret'
    return None


def _excluded(value):
    return (value.startswith(('_', '/', '~', '.')) or FILE_END_RE.search(value) is not None
            or SNAKE_RE.match(value) is not None)


def _word_like(value):
    parts = [p for p in re.split(r'[-_.]', value) if p]
    return (all(p.isdigit() or (p.isalpha() and p.islower()) for p in parts)
            and sum(p.isalpha() and len(p) >= 3 for p in parts) >= 2)


def contextual_secret(label, value):
    """True when `value` next to `label` looks like a literal secret (spec: contextual detector)."""
    kind = _label_class(label)
    if kind is None or _excluded(value):
        return False
    if kind == 'password':
        return len(value) >= PASSWORD_MIN_LEN
    if not CONTEXT_MIN_LEN <= len(value) <= CONTEXT_MAX_LEN or UUID_RE.match(value) or _word_like(value):
        return False
    has_digit = any(c.isdigit() for c in value)
    mixed_case = any(c.islower() for c in value) and any(c.isupper() for c in value)
    return (has_digit or mixed_case) and shannon(value) >= ENTROPY_MIN


def contextual_redact(text):
    def replace(m):
        label = m.group('flag') or m.group('label')
        if not contextual_secret(label, m.group('value')):
            return m.group(0)
        return m.group(0)[:m.start('value') - m.start()] + CONTEXT_TOKEN
    return CONTEXT_RE.sub(replace, text)


def contextual_search(text):
    return contextual_redact(text) != text
```

- [ ] **Step 4: Wire it into `collect.py`**

- `import privacy` next to the other script imports.
- `redact(text)` becomes `return privacy.contextual_redact(SECRET_RE.sub("[REDACTED]", text))`.
- In `sanitize()`, after the `SECRET_KEY_NAMES` branch, add
  `elif isinstance(k, str) and isinstance(v, str) and privacy.contextual_secret(k, v): out[key] = privacy.CONTEXT_TOKEN`.
- Replace the `("secret-literal-in-rule", LITERAL_SECRET_RE)` entry with an object whose `.search`
  is truthy when either matches:

```python
class _AnyOf:
    """`.search` over several matchers, so RISKY_RULES keeps its (name, rx) shape for callers."""
    def __init__(self, *searches):
        self._searches = searches
    def search(self, text):
        return any(s(text) for s in self._searches)

# in RISKY_RULES:
    ("secret-literal-in-rule", _AnyOf(LITERAL_SECRET_RE.search, privacy.contextual_search)),
```

- [ ] **Step 5: Run the focused tests, then the full suite**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v` and `python3 -m unittest discover -s tests -p test_collect.py -v`, then `python3 -m unittest discover -s tests`.
Expected: PASS. If an existing test changes output because the detector now fires, read it. A real
secret shape means the expectation should be updated and mentioned in the commit. A must-not-flag
shape means the detector must be fixed.

- [ ] **Step 6: Record measured entropies in the spec**

Print `privacy.shannon(value)` for T1–T10, A1, N18 and N19. Replace the "≈" values in the spec's
T-table with the measured values, rounded to three decimals. If any TP measures below 3.5, stop and
report.

- [ ] **Step 7: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/privacy.py plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_privacy.py tests/test_collect.py docs/superpowers/specs/2026-09-29-metadata-only-design.md
git commit -m "Detect secrets by context next to key-like names

Assisted-by: Claude:<model-id>"
```

---

### Task 2: Handler identifiers and the masking functions

**Files:**
- Modify: `S/scripts/collect.py` (`hook_handler_entry`)
- Modify: `S/scripts/privacy.py` (markers, masking)
- Test: `tests/test_privacy.py` (`MaskingUnits`), `tests/test_collect.py` (handler fields)

**Interfaces:**
- Produces:
  - `hook_handler_entry` output gains `server`, `tool` (type `mcp_tool`) and `target_origin` (type
    `http`: `scheme://host` for http/https/ws/wss URLs with a host, else `dynamic_or_unknown`;
    `invalid_url` on `ValueError`, the same as `extensions.mcp_summary`). Both modes.
  - `privacy.MARKER_RE = re.compile(r'\[metadata-only: \d+ chars\]\Z')`,
    `privacy.MARKER_FORMAT = '[metadata-only: N chars]'`, and `privacy.marker(s) -> str`.
  - `privacy.mask_value(v, counter, family) -> str` returns `v` unchanged when it already matches
    `MARKER_RE`; otherwise it returns `marker(v)` and adds 1 to `counter[family]`.
  - `privacy.mask_leaves(obj, counter, family)` returns a copy with every string leaf masked; keys,
    numbers, booleans and `None` are unchanged.
  - `privacy.mask_handler(h, counter)` masks `target` in place (family `hook_targets`).
  - `privacy.mask_settings(s, counter)` works in place on one `summarize_settings` dict:
    - `hook_commands[*]` → family `hook_commands`
    - `hook_handlers[*]` → `mask_handler`
    - `missing_hook_scripts[*]` → `missing_hook_scripts`
    - `sandbox` → `mask_leaves`, family `sandbox`
    - `model_settings` → `model_settings`
    - `other.statusLine` → `status_line`
    - `permissions.deny[*]` → `permission_deny`
    - `permissions.risky[flag][*]` → `permission_risky`
  - `privacy.FRONTMATTER_KEEP = frozenset({'name', 'model', 'context', 'agent', 'disable-model-invocation', 'user-invocable', 'paths'})`
    and `privacy.mask_frontmatter(fm, counter)` (in place, family `frontmatter`).
  - `privacy.mask_snapshot(snap) -> dict[str, int]` works in place and returns family counts
    (`dict(counter)`). Locations:
    - settings summaries: `global.settings`, `managed_settings.settings`, `projects.*.settings`,
      `instructions.settings_candidates`
    - `global.last_update` → `mask_leaves`, family `last_update`
    - `usage.heaviest_sessions[*].first_prompt` and `usage.most_friction_sessions[*].first_prompt`
      → `first_prompt`
    - `usage.facet_friction_details[*]` → `facet_friction_details`
    - `corrections.samples[*].text` → `correction_samples`
    - `memory.by_project.*.entries[*].description` → `memory_descriptions`
    - `instructions.entries[*]` and `extensions.plugins[*].components[*]`: `excerpt` → `excerpts`,
      plus `frontmatter` → `mask_frontmatter`
    - `components[*].handlers[*]` → `mask_handler`
    - Absent sections are skipped (`corrections` can be `{}`).

- [ ] **Step 1: Write the failing tests**

`tests/test_collect.py`:

```python
class HookHandlerIdentifiers(unittest.TestCase):
    def test_mcp_tool_and_http_handlers_carry_identifiers(self):
        mcp = collect.hook_handler_entry('PreToolUse', 'Bash', {'type': 'mcp_tool', 'server': 'srv', 'tool': 'check'})
        self.assertEqual((mcp['server'], mcp['tool']), ('srv', 'check'))
        http = collect.hook_handler_entry('Stop', None, {'type': 'http', 'url': 'https://hooks.example.com/p?q=1'})
        self.assertEqual(http['target_origin'], 'https://hooks.example.com')
        self.assertEqual(collect.hook_handler_entry('Stop', None, {'type': 'http', 'url': '$URL'})['target_origin'],
                         'dynamic_or_unknown')
        self.assertNotIn('target_origin', collect.hook_handler_entry('Stop', None, {'command': 'x'}))
```

`tests/test_privacy.py`:

```python
from collections import Counter
import copy

SETTINGS = {
    'model': 'opus', 'modelSettings': {'opus': {'note': 'free text', 'budget': 3}},
    'statusLine': {'type': 'command', 'command': 'print-status --verbose'},
    'sandbox': {'enabled': True, 'network': {'allowedDomains': ['a.example.com', 'b.example.com']}},
    'permissions': {'allow': ['Bash(sudo ls)', 'Bash(curl:*)'], 'deny': ['Bash(rm -rf /)', 'Read(.env)'],
                    'defaultMode': 'acceptEdits', 'additionalDirectories': ['~/shared']},
    'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
        {'type': 'command', 'command': 'echo hi'},
        {'type': 'http', 'url': 'https://hooks.example.com/x', 'headers': {'X-Token': '$T'}},
        {'type': 'prompt', 'prompt': 'judge this'},
        {'type': 'mcp_tool', 'server': 'srv', 'tool': 'check'}]}]},
}


class MaskingUnits(unittest.TestCase):
    def test_marker_format(self):
        self.assertEqual(privacy.marker('abc'), '[metadata-only: 3 chars]')
        self.assertTrue(privacy.MARKER_RE.match(privacy.marker('')))

    def test_mask_settings_summary(self):
        s = collect.summarize_settings('/tmp/x/settings.json', data=copy.deepcopy(SETTINGS))
        before = copy.deepcopy(s)
        c = Counter()
        privacy.mask_settings(s, c)
        self.assertTrue(all(privacy.MARKER_RE.match(v) for v in s['hook_commands']))
        self.assertEqual(len(s['hook_commands']), len(before['hook_commands']))
        for h, b in zip(s['hook_handlers'], before['hook_handlers']):
            self.assertTrue(privacy.MARKER_RE.match(h['target']))
            for k in ('event', 'matcher', 'type', 'server', 'tool', 'target_origin', 'header_keys'):
                self.assertEqual(h.get(k), b.get(k))
        self.assertEqual(sorted(s['permissions']['risky']), sorted(before['permissions']['risky']))
        for flag, rules in s['permissions']['risky'].items():
            self.assertEqual(len(rules), len(before['permissions']['risky'][flag]))
            self.assertTrue(all(privacy.MARKER_RE.match(r) for r in rules))
        self.assertEqual(len(s['permissions']['deny']), s['permissions']['deny_count'])
        self.assertTrue(all(privacy.MARKER_RE.match(r) for r in s['permissions']['deny']))
        self.assertIs(s['sandbox']['enabled'], True)
        self.assertTrue(all(privacy.MARKER_RE.match(d) for d in s['sandbox']['network']['allowedDomains']))
        self.assertEqual(s['model_settings']['opus']['budget'], 3)
        self.assertTrue(privacy.MARKER_RE.match(s['model_settings']['opus']['note']))
        self.assertTrue(privacy.MARKER_RE.match(s['other']['statusLine']['command']))
        for k in ('path', 'keys', 'env_keys', 'model', 'hooks'):
            self.assertEqual(s[k], before[k])
        self.assertEqual(s['permissions']['default_mode'], 'acceptEdits')
        self.assertEqual(s['permissions']['additional_dirs'], ['~/shared'])
        self.assertEqual(c['hook_targets'], 4)
        self.assertEqual(c['permission_deny'], 2)

    def test_mask_frontmatter_keeps_identifier_keys_only(self):
        fm = {'name': 's', 'model': 'haiku', 'paths': 'src/**', 'description': 'd', 'when_to_use': 'w',
              'allowed-tools': 'Bash(x)', 'hooks': 'h', 'unknown-key': 'u'}
        privacy.mask_frontmatter(fm, Counter())
        self.assertEqual((fm['name'], fm['model'], fm['paths']), ('s', 'haiku', 'src/**'))
        for k in ('description', 'when_to_use', 'allowed-tools', 'hooks', 'unknown-key'):
            self.assertTrue(privacy.MARKER_RE.match(fm[k]), k)

    def test_shared_objects_are_masked_once(self):
        session = {'project': '~/app', 'first_prompt': 'hello there'}
        snap = {'usage': {'heaviest_sessions': [session], 'most_friction_sessions': [session],
                          'facet_friction_details': []}}
        counts = privacy.mask_snapshot(snap)
        self.assertEqual(session['first_prompt'], '[metadata-only: 11 chars]')
        self.assertEqual(counts['first_prompt'], 1)

    def test_mask_snapshot_skips_absent_sections_and_counts_families(self):
        snap = {'corrections': {}, 'memory': {'by_project': {'p': {'entries': [{'file': 'a.md', 'description': ''}]}}},
                'instructions': {'entries': [{'source': '/x/CLAUDE.md', 'excerpt': 'abc', 'frontmatter': {}}]}}
        counts = privacy.mask_snapshot(snap)
        self.assertEqual(snap['memory']['by_project']['p']['entries'][0],
                         {'file': 'a.md', 'description': '[metadata-only: 0 chars]'})
        self.assertEqual(counts, {'memory_descriptions': 1, 'excerpts': 1})
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v`
Expected: FAIL/ERROR `AttributeError: module 'privacy' has no attribute 'marker'` (and a `KeyError`
for `server` in the collect test).

- [ ] **Step 3: Implement**

- In `hook_handler_entry`, add `server`/`tool` to `extra` for `mcp_tool`. For `http`, add
  `target_origin` using `urllib.parse.urlsplit`, with the same branch logic as
  `extensions.mcp_summary`. Do not import extensions; duplicate the four lines, or move a helper
  `url_origin(url)` into `privacy.py` and use it from both. Choose the latter only if
  `extensions.py` changes stay a one-line import.
- In `privacy.py`, implement the interfaces above. Mask in place, and use `mask_value` everywhere so
  the `MARKER_RE` skip covers shared objects.

- [ ] **Step 4: Run the focused tests, then the full suite**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v`, then
`python3 -m unittest discover -s tests`.
Expected: PASS. Update any existing exact-dict handler expectations to include the new keys.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/privacy.py plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_privacy.py tests/test_collect.py
git commit -m "Add hook handler identifiers and metadata-only masking functions

Assisted-by: Claude:<model-id>"
```

---

### Task 3: `--metadata-only` flag, `coverage.privacy` and schema

**Files:**
- Modify: `S/scripts/collect.py` (`build_snapshot`, `main`)
- Modify: `S/references/snapshot.schema.json` (optional `coverage.properties.privacy`, exactly as in the spec)
- Test: `tests/test_privacy.py` (`CollectorMode`), `tests/test_snapshot_contract.py`

**Interfaces:**
- Consumes: `privacy.mask_snapshot`, `privacy.MARKER_FORMAT`, `privacy.CONTEXT_TOKEN`.
- Produces:
  - `main()` adds `ap.add_argument("--metadata-only", action="store_true", help="replace free text with length markers (prompts, rules, hook commands, descriptions, excerpts)")`
    and, after `apply_collection_args`, calls
    `ap.error("--metadata-only cannot be combined with --clarity-pilot (the pilot reviews excerpt text)")`
    when both flags are set. The flag is not added to `add_collection_args`, so `drift.py` does not
    get it.
  - `build_snapshot(a)`:
    - `metadata_only = getattr(a, 'metadata_only', False)`; raise
      `ValueError('metadata-only excludes the clarity pilot')` when it is set together with
      `clarity_pilot`.
    - After the `mcp_configured_but_unused_note` assignment, run
      `replaced = privacy.mask_snapshot(snap) if metadata_only else {}`.
    - Set `snap["coverage"]["privacy"] = {"mode": "metadata-only" if metadata_only else "full",
      "free_text": "replaced" if metadata_only else "collected", "marker": privacy.MARKER_FORMAT,
      "replaced_fields": replaced, "redactions": {}}`.
    - In metadata-only mode, also append the source
      `source_coverage("free_text_fields", scope, "not_checked", reason="metadata_only_mode")` and
      the spec's limitation sentence.
    - After `text = json.dumps(sanitize(snap), ...)` and `snap = json.loads(text)`, set
      `snap["coverage"]["privacy"]["redactions"] = {"pattern_or_key": text.count("[REDACTED]"),
      "contextual": text.count(privacy.CONTEXT_TOKEN)}`, then `validate_snapshot(snap)`.

- [ ] **Step 1: Write the failing tests**

`tests/test_privacy.py`:

```python
import argparse
import contextlib
import io
import os
from datetime import datetime, timedelta, timezone
from unittest import mock


def args(**kw):
    base = dict(roots=[], days=30, claude_dir=None, scope='all', project=None)
    return argparse.Namespace(**{**base, **kw})


class PatchedHome(FakeHome):
    """Fake home whose managed-settings directory is inside it (never /etc/claude-code). No tests here,
    so subclasses don't re-run each other's tests."""
    def setUp(self):
        super().setUp()
        p = mock.patch.object(collect, 'managed_directory', lambda: os.path.join(self.home, 'managed'))
        p.start()
        self.addCleanup(p.stop)


class CollectorMode(PatchedHome):
    def test_full_mode_records_privacy_full(self):
        snap = collect.build_snapshot(args())
        p = snap['coverage']['privacy']
        self.assertEqual((p['mode'], p['free_text'], p['replaced_fields']), ('full', 'collected', {}))
        self.assertNotIn('free_text_fields', [s['source'] for s in snap['coverage']['sources']])

    def test_metadata_mode_records_mode_source_and_limitation(self):
        self.write('.claude/settings.json', {'permissions': {'deny': ['Bash(rm -rf /)']}})
        snap = collect.build_snapshot(args(metadata_only=True))
        p = snap['coverage']['privacy']
        self.assertEqual((p['mode'], p['free_text']), ('metadata-only', 'replaced'))
        self.assertEqual(p['replaced_fields']['permission_deny'], 1)
        src = [s for s in snap['coverage']['sources'] if s['source'] == 'free_text_fields']
        self.assertEqual((src[0]['status'], src[0]['reason']), ('not_checked', 'metadata_only_mode'))
        self.assertTrue(any(l.startswith('Metadata-only mode:') for l in snap['coverage']['limitations']))

    def test_redaction_counts_and_secret_absent(self):
        secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        self.write('.claude/settings.json', {'hooks': {'Stop': [{'hooks': [
            {'type': 'command', 'command': f'AWS_SECRET_ACCESS_KEY={secret} ./sync.sh'}]}]}})
        for mode in (False, True):
            snap = collect.build_snapshot(args(metadata_only=mode))
            self.assertNotIn(secret, json.dumps(snap))
        full = collect.build_snapshot(args())
        self.assertGreaterEqual(full['coverage']['privacy']['redactions']['contextual'], 1)

    def test_env_hook_join_runs_before_masking(self):
        app = os.path.join(self.home, 'code', 'app')
        self.write('code/app/.envrc', 'use_pass TOKEN x\n')
        self.write('.claude/settings.json', {'hooks': {'SessionStart': [{'hooks': [
            {'type': 'command', 'command': 'direnv export bash > "$CLAUDE_ENV_FILE"'}]}]}})
        snap = collect.build_snapshot(args(roots=[app], metadata_only=True))
        self.assertIs(snap['readiness'][app.replace(self.home, '~')]['claude_env_hook'], True)

    def test_metadata_only_with_clarity_pilot_is_a_usage_error(self):
        with mock.patch('sys.argv', ['collect.py', '--claude-dir', self.claude, '--metadata-only', '--clarity-pilot']), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as cm:
            collect.main()
        self.assertEqual(cm.exception.code, 2)

    def test_drift_arguments_stay_full(self):
        snap = collect.build_snapshot(args())  # drift's namespace has no metadata_only attribute
        self.assertEqual(snap['coverage']['privacy']['mode'], 'full')
```

`tests/test_snapshot_contract.py` (follow the file's existing helper for building a minimal valid
snapshot):

```python
    def test_coverage_privacy_is_optional_and_typed(self):
        snap = <minimal valid snapshot>
        validate_snapshot(snap)                                   # absent: still valid (older snapshots)
        snap['coverage']['privacy'] = {'mode': 'metadata-only', 'free_text': 'replaced',
                                       'marker': '[metadata-only: N chars]',
                                       'replaced_fields': {'first_prompt': 2}, 'redactions': {'contextual': 0}}
        validate_snapshot(snap)
        for bad in ({'mode': 'partial'}, {'replaced_fields': {'x': -1}}, {'free_text': 'maybe'}):
            broken = copy.deepcopy(snap)
            broken['coverage']['privacy'].update(bad)
            with self.assertRaises(SnapshotError):
                validate_snapshot(broken)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v`
Expected: FAIL `KeyError: 'privacy'`. The clarity test fails because it exits with a code other than 2
(unrecognized argument), so check the code, not just `SystemExit`.

- [ ] **Step 3: Implement** the interfaces above and the schema block from the spec. Place the
  masking call after the readiness join, so that `claude_env_hook` reads unmasked `hook_commands`.

- [ ] **Step 4: Run the focused tests, the schema check and the full suite**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v`,
`python3 -m unittest discover -s tests -p test_snapshot_contract.py -v`,
`python3 tests/check_snapshot_schema.py`, then `python3 -m unittest discover -s tests`.
Expected: PASS. The drift test `test_build_snapshot_matches_main_output` must still pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json tests/test_privacy.py tests/test_snapshot_contract.py
git commit -m "Add collect.py --metadata-only and record the privacy mode in coverage

Assisted-by: Claude:<model-id>"
```

---

### Task 4: Canary fake home and the classification registry

**Files:**
- Modify: `S/scripts/privacy.py` (`KEPT_STRING_FIELDS`, `path_matches`)
- Test: `tests/test_privacy.py` (`EndToEnd`)

**Interfaces:**
- Produces:
  - `privacy.path_matches(path: tuple, pattern: tuple) -> bool`. `"*"` matches one key or index;
    `"**"` (last element only) matches any remainder. Literal strings never match list indices.
  - `privacy.KEPT_STRING_FIELDS: tuple[tuple, ...]` is the spec inventory's keep rows as patterns.
    Settings-summary suffixes are expanded over the four settings prefixes; handler suffixes over
    settings `hook_handlers` and `extensions.plugins.*.components.*.handlers`; entry suffixes over
    `instructions.entries` and `extensions.plugins.*.components`. Start from this list and change
    it only via the spec inventory:

```python
SETTINGS_PREFIXES = (('global', 'settings', '*'), ('managed_settings', 'settings', '*'),
                     ('projects', '*', 'settings', '*'), ('instructions', 'settings_candidates', '*'))
HANDLER_KEEP = (('event',), ('matcher',), ('type',), ('server',), ('tool',), ('target_origin',),
                ('header_keys', '*'), ('allowed_env_vars', '*'))
SETTINGS_KEEP = (('path',), ('scope',), ('keys', '*'), ('model',), ('env_keys', '*'), ('hooks', '*', '*'),
                 ('permissions', 'default_mode'), ('permissions', 'additional_dirs', '*'),
                 ('permissions', 'missing_additional_dirs', '*'), ('other', 'outputStyle'),
                 ('other', 'autoUpdates')) + tuple(('hook_handlers', '*') + h for h in HANDLER_KEEP)
ENTRY_KEEP = tuple((k,) for k in ('source', 'scope', 'status', 'kind', 'relation', 'active_state',
                                  'reason', 'frontmatter_status', 'estimate_basis')) \
    + tuple(('frontmatter', k) for k in FRONTMATTER_KEEP)
SUBTREES = (('collection_scope', '**'), ('readiness', '**'), ('harness_overhead', '**'), ('coverage', '**'),
            ('ledger_signals', '**'), ('drift_signals', '**'), ('skill_listing', '**'),
            ('managed_settings', 'sources', '**'), ('instructions', 'sources', '**'),
            ('instructions', 'contexts', '**'), ('instructions', 'agents_md_setting_observed', '**'),
            ('extensions', 'sources', '**'), ('global', 'plugin_session_start_hooks', '**'),
            ('memory', 'similar_across_projects', '**'))
SINGLE = (('generated',), ('previous_audits', '*'), ('managed_settings', 'effective_policy'),
          ('global', 'version'), ('global', 'doctor'),
          *(('global', k, '*') for k in ('skills', 'agents', 'commands', 'mcp_user', 'installed_plugins')),
          *(('projects', '*', k, '*') for k in ('claude_md_dead_refs', 'mcp_servers', 'skills', 'agents',
                                                'commands', 'hooks', 'git')),
          ('memory', 'by_project', '*', 'entries', '*', 'file'),
          *(('usage', k) for k in ('coverage_note', 'window_note', 'stats_scope_note', 'facets_scope_note',
                                   'latest_insights_report')),
          ('usage', 'daily_token_totals_recent', '*', 'date'),
          *(('usage', k, '*', '*') for k in ('top_tools', 'tool_error_categories', 'sessions_per_project',
                                             'facet_friction')),
          *(('usage', s, '*', k) for s in ('heaviest_sessions', 'most_friction_sessions') for k in ('project', 'start')),
          ('corrections', 'by_project', '*', '*'), ('corrections', 'samples', '*', 'project'),
          *(('transcripts', k) for k in ('coverage_note', 'window_note', 'quantile_method', 'mcp_count_note',
                                         'mcp_configured_but_unused_note')),
          *(('transcripts', k, '*', '*') for k in ('context_baseline_by_project_median', 'mcp_calls_by_server')),
          ('transcripts', 'mcp_configured_but_unused', '*'),
          ('instructions', 'limitations', '*'), ('extensions', 'limitations', '*'),
          *(('extensions', 'mcp_servers', '*', k) for k in ('source', 'scope', 'status', 'name', 'project',
                'active_state', 'representation', 'transport', 'executable', 'package_version_evidence',
                'endpoint_origin', 'endpoint_detail', 'reason')),
          *(('extensions', 'mcp_servers', '*', k, '*') for k in ('env_keys', 'headers_keys',
                'env_variable_references', 'headers_variable_references', 'credential_mechanisms')),
          *(('extensions', 'plugins', '*', k) for k in ('name', 'scope', 'project', 'version', 'active_state',
                                                        'source', 'status', 'reason')),
          ('extensions', 'plugins', '*', 'manifest_keys', '*'),
          ('extensions', 'plugins', '*', 'enablement_observations', '*', 'source'))
KEPT_STRING_FIELDS = (SUBTREES + SINGLE
    + tuple(p + s for p in SETTINGS_PREFIXES for s in SETTINGS_KEEP)
    + tuple(p + s for p in (('instructions', 'entries', '*'), ('extensions', 'plugins', '*', 'components', '*'))
            for s in ENTRY_KEEP)
    + tuple(('extensions', 'plugins', '*', 'components', '*', 'handlers', '*') + h for h in HANDLER_KEEP))
```

- [ ] **Step 1: Write the failing tests** (`tests/test_privacy.py`)

```python
CANARIES = ('zcfirstprompt', 'zcfriction', 'zccorrection', 'zcmemorydesc', 'zcclaudemd', 'zcrulebody',
            'zcskilldesc', 'zcskillwhen', 'zcskilltools', 'zcskillbody', 'zchookcmd', 'zchttppath',
            'zcprompthook', 'zcriskyrule', 'zcdenyrule', 'zcsandboxvalue', 'zcmodelsetting', 'zcstatusline',
            'zclastupdate', 'zcmissingscript', 'zcpluginskill', 'zcpluginhook')


def leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leaves(v, path + (i,))
    else:
        yield path, obj


class EndToEnd(PatchedHome):
    def plant(self):
        when = datetime.now(timezone.utc) - timedelta(days=1)
        app = os.path.join(self.home, 'code', 'app')
        self.write('code/app/CLAUDE.md', 'Project notes zcclaudemd\n')
        self.write('.claude/CLAUDE.md', 'Global zcclaudemd\n')
        self.write('.claude/rules/r.md', 'Rule zcrulebody\n')
        self.write('.claude/skills/s/SKILL.md', '---\nname: s\ndescription: zcskilldesc\nwhen_to_use: zcskillwhen\n'
                   'allowed-tools: Bash(zcskilltools)\n---\nBody zcskillbody\n')
        self.write('.claude/.last-update-result.json', {'status': 'failed', 'error': 'zclastupdate'})
        self.write('.claude/usage-data/session-meta/s1.json', {
            'session_id': 's1', 'start_time': when.strftime('%Y-%m-%dT%H:%M:%SZ'), 'project_path': app,
            'first_prompt': 'please zcfirstprompt', 'tool_counts': {'Bash': 2}, 'output_tokens': 10})
        self.write('.claude/usage-data/facets/s1.json', {'session_id': 's1', 'friction_counts': {'buggy_code': 1},
                                                          'friction_detail': 'zcfriction happened', 'outcome': 'achieved'})
        self.write('.claude/history.jsonl', json.dumps({'display': 'no, zccorrection', 'project': app,
                                                        'timestamp': int(when.timestamp() * 1000), 'sessionId': 's1'}) + '\n')
        self.write('.claude/projects/-code-app/memory/note.md', '---\ndescription: zcmemorydesc\n---\n')
        self.write('.claude/projects/-code-app/memory/MEMORY.md', '- note\n')
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1.0.0')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'p@m': [
            {'scope': 'user', 'installPath': root, 'version': '1.0.0'}]}})
        self.write(os.path.relpath(os.path.join(root, '.claude-plugin', 'plugin.json'), self.home), {'name': 'p'})
        self.write(os.path.relpath(os.path.join(root, 'skills', 'x', 'SKILL.md'), self.home),
                   '---\nname: x\ndescription: zcpluginskill\n---\nzcpluginskill\n')
        self.write(os.path.relpath(os.path.join(root, 'hooks', 'hooks.json'), self.home), {'hooks': {'PreToolUse': [
            {'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': 'echo zcpluginhook'}]}]}})
        self.write('.claude/settings.json', {
            'model': 'opus', 'modelSettings': {'opus': {'note': 'zcmodelsetting'}},
            'statusLine': {'type': 'command', 'command': 'zcstatusline'},
            'sandbox': {'enabled': True, 'network': {'allowedDomains': ['zcsandboxvalue.example.com']}},
            'enabledPlugins': {'p@m': True},
            'permissions': {'allow': ['Bash(sudo zcriskyrule)', f'Bash(export AWS_SECRET_ACCESS_KEY={AWS} && aws s3 ls)'],
                            'deny': ['Bash(zcdenyrule)']},
            'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
                {'type': 'command', 'command': 'echo zchookcmd'},
                {'type': 'command', 'command': '/nonexistent/zcmissingscript.sh'},
                {'type': 'http', 'url': 'https://hooks.example.com/zchttppath', 'headers': {'X-Token': '$TOK'}},
                {'type': 'prompt', 'prompt': 'zcprompthook'},
                {'type': 'mcp_tool', 'server': 'srv', 'tool': 'check'}]}]}})

    def snapshots(self):
        self.plant()
        return collect.build_snapshot(args()), collect.build_snapshot(args(metadata_only=True))

    def test_full_mode_carries_every_canary(self):  # proves the fixture reaches the snapshot
        full, _ = self.snapshots()
        text = json.dumps(full)
        self.assertEqual([c for c in CANARIES if c not in text], [])

    def test_metadata_mode_carries_no_canary_and_no_secret(self):
        full, meta = self.snapshots()
        text = json.dumps(meta)
        self.assertEqual([c for c in CANARIES if c in text], [])
        self.assertNotIn(AWS, text + json.dumps(full))

    def test_metadata_mode_keeps_structure(self):
        full, meta = self.snapshots()
        fs, ms = full['global']['settings'][0], meta['global']['settings'][0]
        for k in ('hook_commands', 'hook_handlers', 'missing_hook_scripts'):
            self.assertEqual(len(fs[k]), len(ms[k]), k)
        self.assertEqual({f: len(v) for f, v in fs['permissions']['risky'].items()},
                         {f: len(v) for f, v in ms['permissions']['risky'].items()})
        self.assertEqual(sorted(full['projects']), sorted(meta['projects']))
        self.assertEqual(sorted(full['readiness']), sorted(meta['readiness']))
        self.assertEqual(full['corrections']['count'], meta['corrections']['count'])
        self.assertEqual(len(full['corrections']['samples']), len(meta['corrections']['samples']))
        self.assertEqual(len(full['usage']['heaviest_sessions']), len(meta['usage']['heaviest_sessions']))

    def test_every_string_leaf_is_classified(self):
        _, meta = self.snapshots()
        unclassified = sorted({'.'.join('*' if isinstance(p, int) else p for p in path)
                               for path, v in leaves(meta) if isinstance(v, str)
                               and not privacy.MARKER_RE.match(v)
                               and not any(privacy.path_matches(path, pat) for pat in privacy.KEPT_STRING_FIELDS)})
        self.assertEqual(unclassified, [], 'classify these in the spec inventory, then mask or keep them')

    def test_context_token_only_where_planted(self):
        full, _ = self.snapshots()
        hits = [v for _, v in leaves(full) if isinstance(v, str) and privacy.CONTEXT_TOKEN in v]
        self.assertTrue(hits)
        self.assertTrue(all('AWS_SECRET_ACCESS_KEY=' in v for v in hits), 'contextual false positive')
```

`test_every_string_leaf_is_classified` reports patterns, never values. Some dict keys (project
paths, memory keys) appear in the pattern text; that is fine, because they are paths.

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest discover -s tests -p test_privacy.py -v`
Expected: ERROR `AttributeError: module 'privacy' has no attribute 'path_matches'`. After
`path_matches` exists, the registry test may list unclassified paths. Classify each one against the
spec inventory. If a path is not in the inventory, add a row to the spec first. The fixture may also
miss a canary (for example, a plugin that is not selected, or a facet that is not joined). Fix the
fixture, not the assertion.

- [ ] **Step 3: Implement** `path_matches` and `KEPT_STRING_FIELDS` in `privacy.py`.

- [ ] **Step 4: Red-proof both guards**

1. Comment out the `first_prompt` masking in `mask_snapshot`. Expect
   `test_metadata_mode_carries_no_canary_and_no_secret` to fail with `['zcfirstprompt']`. Revert.
2. Delete `('usage', k, '*', '*')` for `top_tools` from `SINGLE`. Expect
   `test_every_string_leaf_is_classified` to name `usage.top_tools.*.*`. Revert.

Run `git diff` afterwards to confirm both are reverted.

- [ ] **Step 5: Run the full suite and the gate** (`python3 -m unittest discover -s tests`, schema
  check, `git diff --check`)

- [ ] **Step 6: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/privacy.py tests/test_privacy.py
git commit -m "Guard metadata-only mode with a canary home and a string classification registry

Assisted-by: Claude:<model-id>"
```

---

### Task 5: Consumers and documentation

**Files:**
- Modify: `S/scripts/query_snapshot.py`, `S/scripts/report_state.py`, `S/scripts/render_report.py`
- Modify: `S/SKILL.md`, `S/references/report-format.md`, `S/references/checklist.md`,
  `S/references/coverage.md`, `S/references/snapshot-format.md`, `README.md`, `CHANGELOG.md`,
  `docs/roadmap.md`
- Test: `tests/test_privacy.py` (query banner), `tests/test_report_state.py`,
  `tests/test_render_report.py`

**Interfaces:**
- `query_snapshot.py`: after validation, when
  `node.get('coverage', {}).get('privacy', {}).get('mode') == 'metadata-only'`, print this fixed
  line to stdout before the `<untrusted_snapshot_data>` block:
  `privacy mode: metadata-only (free text replaced by [metadata-only: N chars] markers; do not reconstruct it)`.
  This happens for every query path. Print nothing extra in full mode.
- `report_state._validate_report`: when `'privacy' in profile`, require
  `profile['privacy'] in ('full', 'metadata-only')`, else `ReportError('invalid profile privacy')`.
- `render_report.render`: when `profile.privacy == 'metadata-only'`, append
  `<p class="badge">Metadata-only collection · prompt, rule and instruction text were not collected</p>`
  after the example badge. Also replace the footer sentence with "Private report — metadata-only
  collection; paths and names are still included. Review before sharing."

- [ ] **Step 1: Write the failing tests**

- `test_privacy.py` `QueryBanner(PatchedHome)`: write a `build_snapshot(args(metadata_only=True))`
  result to `self.home/snap.json`, then run `query_snapshot.main()` with
  `mock.patch('sys.argv', ['query_snapshot.py', path])` and captured stdout. Assert that the first
  line equals the banner. Repeat with a full snapshot and assert that stdout starts with
  `<untrusted_snapshot_data>`.
- `test_report_state.py`: a minimal valid report with `profile.privacy = 'metadata-only'` validates;
  `'hidden'` raises `ReportError` with message `invalid profile privacy`.
- `test_render_report.py`: the badge text is in `render(report)` only when `profile.privacy` is
  `metadata-only`; the footer variant likewise.

- [ ] **Step 2: Run to verify they fail**, **Step 3: Implement**, **Step 4: Run to verify they pass**
  (the three focused test files, then the full suite).

- [ ] **Step 5: Documentation**

- `SKILL.md`:
  - Step 0 table row: `| privacy | full or metadata-only (free text replaced by length markers; paths and names kept) | full |`,
    plus one sentence mapping "don't read my prompts" and "metadata only" to it.
  - Step 1: "With `privacy=metadata-only`, add `--metadata-only`. It cannot be combined with
    `clarity=pilot`; tell the user and run with clarity off."
  - After the untrusted-data paragraph, a paragraph that states the spec's model rules (the
    "Model and report guidance" section):
    - read `coverage.privacy.mode` first;
    - markers mean the text was not collected, so never guess, paraphrase or reconstruct it;
    - do not open transcripts, history, memory or instruction files to recover it unless the user
      asks for that specific item;
    - cite the file, field, flag and count;
    - in propose mode, describe the change's shape, and read the exact before/after only after
      approval in Step 5;
    - mark checks that need text `partial`/`not_checked` with a caveat;
    - record `profile.privacy`.
  - Under Boundaries, extend the private-reports bullet: metadata-only reports still contain paths
    and names.
- `report-format.md`: add `"privacy": "full"` to the example `profile`. Add a bullet: `profile.privacy`
  is optional (`full`/`metadata-only`); a metadata-only report quotes no collected text; evidence
  cites fields, flags and counts.
- `checklist.md`: one paragraph under the intro that lists the partial, not-checked and unaffected
  checks from the spec.
- `coverage.md`: a new "Privacy" section covering `coverage.privacy` (fields, occurrence-count
  semantics), the `free_text_fields` source, the marker grammar and what stays (paths, names,
  counts). It also covers the contextual detector (what it catches and misses, the
  `[REDACTED:context]` token) and says that redaction remains best-effort.
- `snapshot-format.md`: a Compatibility bullet: optional `coverage.privacy`; marker strings replace
  free text in metadata-only snapshots (type-preserving, `\[metadata-only: \d+ chars\]`); handler
  `server`/`tool`/`target_origin`; `[REDACTED:context]`. Additive within v1.
- `README.md`: an options-table row for `privacy`, and a "Privacy mode" paragraph under "What it
  reads, writes and sends": what is replaced, what stays, detection in both modes, still review
  before sharing.
- `CHANGELOG.md` `[Unreleased]` → `### Added`: metadata-only collection
  (`collect.py --metadata-only`, `privacy=metadata-only`) with `coverage.privacy`; contextual secret
  detection in both modes; handler `server`/`tool`/`target_origin`. `### Changed`:
  `secret-literal-in-rule` also fires on contextual hits.
- `docs/roadmap.md`: in the Privacy item, mark metadata-only collection and contextual detection
  done (this release). Keep "fuller provenance for free-text evidence" and add "optional path/name
  hashing (`--hash-paths`)" as the remainder.

- [ ] **Step 6: Gate and commit**

Run the full gate. Then:

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/query_snapshot.py plugins/setup-audit/skills/setup-audit/scripts/report_state.py plugins/setup-audit/skills/setup-audit/scripts/render_report.py plugins/setup-audit/skills/setup-audit/SKILL.md plugins/setup-audit/skills/setup-audit/references/report-format.md plugins/setup-audit/skills/setup-audit/references/checklist.md plugins/setup-audit/skills/setup-audit/references/coverage.md plugins/setup-audit/skills/setup-audit/references/snapshot-format.md README.md CHANGELOG.md docs/roadmap.md tests/test_privacy.py tests/test_report_state.py tests/test_render_report.py
git commit -m "Teach the audit, report and renderer about metadata-only snapshots

Assisted-by: Claude:<model-id>"
```

---

### Task 6: Sweep string fields added by plans 2A, 2B and 3

**Files:**
- Modify: `S/scripts/privacy.py` (`mask_snapshot`, `KEPT_STRING_FIELDS`)
- Modify: `docs/superpowers/specs/2026-09-29-metadata-only-design.md` (inventory rows)
- Test: `tests/test_privacy.py` (fixture canaries and kept values for the new fields)

- [ ] **Step 1: List the candidates**

```bash
git diff 7135b8e -- plugins/setup-audit/skills/setup-audit/scripts plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json
git log --oneline 7135b8e..HEAD
```

In the diff, list every new snapshot field that can hold a string: new keys in dicts the collectors
return (`collect.py`, `inventory.py`, `extensions.py`, `harness.py`, any new module the collector
calls); schema additions with `"type": "string"` or a type list containing `"string"`; and string
lists. Include changes to `summarize_settings`, `analyze_permissions` and `hook_handler_entry`
shapes. Plan 3 `apply_ops` fields that never reach the snapshot are out of scope; confirm they
don't reach it.

- [ ] **Step 2: Classify each field** (id / enum / path / const / free) and add a row to the spec
  inventory table. Expected classes:
  - 2A redacted rule text for the wildcard, conflict and hook-matcher checks: free. Its rule-kind or
    flag names: enum.
  - 2B MCP exposure: server and tool names and counts are id; tool descriptions are free.
    Per-tool error clusters: tool names and counts are id; fingerprint hashes are id; error message
    text or snippets are free.
  - 3 derived sandbox summary: counts and booleans are kept; domain and path lists are masked (R4).
  If a plan was not merged, say so in the commit message.

- [ ] **Step 3: Extend the fixture first (RED)**

For each free field, plant a new `zc…` canary in `EndToEnd.plant()` and add it to `CANARIES`. For
each kept field, plant a value that reaches it. Run:
`python3 -m unittest discover -s tests -p test_privacy.py -v`.
Expected: `test_metadata_mode_carries_no_canary_and_no_secret` lists the new free canaries, and
`test_every_string_leaf_is_classified` lists the new kept paths. If
`test_full_mode_carries_every_canary` fails, the fixture does not reach the field; fix the fixture.

- [ ] **Step 4: Implement (GREEN)**

Mask the free fields in `mask_snapshot`, with a new family name each. Add the kept fields to
`KEPT_STRING_FIELDS`. If 2A added redacted rule text alongside `permissions.risky`, that is rule
text: mask it (spec decision 2). Also check that `test_context_token_only_where_planted` still
passes: new fields must not trigger contextual false positives.

- [ ] **Step 5: Update docs.** Add the new families to the `coverage.md` Privacy section and the
  affected-check list in `checklist.md`/SKILL.md, if a check lost text evidence.

- [ ] **Step 6: Gate and commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/privacy.py tests/test_privacy.py docs/superpowers/specs/2026-09-29-metadata-only-design.md plugins/setup-audit/skills/setup-audit/references/coverage.md plugins/setup-audit/skills/setup-audit/references/checklist.md
git commit -m "Classify snapshot fields added since 7135b8e for metadata-only mode

Assisted-by: Claude:<model-id>"
```

---

## Final whole-branch review

Check against the spec's Success list:

- canary absent and present;
- every string classified;
- T and N tables;
- `coverage.privacy` in both modes;
- the clarity conflict;
- drift unchanged;
- docs consistent across SKILL.md, report-format.md, coverage.md, snapshot-format.md and README.

Run the full gate, including coverage ≥ 88. Spot-check one metadata-only snapshot from the canary
fixture by eye with `query_snapshot.py`, and confirm the banner and markers. Never run it against
the real home.
