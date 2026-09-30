# Deeper Checks 2B Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add locally observable MCP exposure metadata to each inventoried server:
- transport class, config notes, locality, cleartext, URL flags, literal keys, OAuth scopes
- tool prefix, `.mcp.json` git status
- approval, toggle, policy and permission observations, name collisions

Add per-built-in-tool and per-MCP-server tool-error clustering from transcripts. Add three
checklist ids that use them.

**Architecture:**
- `extensions.mcp_summary` gains static fields.
- `collect.summarize_settings` gains `mcp_policy` and `mcp_permission_rules` summaries.
- `extensions.collect_extensions` gains `mcp_project_state` and `mcp_name_collisions`.
- A new `extensions.mcp_observations` joins them per server; `build_snapshot` calls it.
- `collect_transcripts` pairs `tool_result` to `tool_use` by id within each file and emits
  `transcripts.tool_errors` via a pure `tool_error_summary`.
- Schema v1 grows additively.

**Tech Stack:** Python 3.11+ standard library (`ipaddress`, `urllib.parse`, `re`, `collections`); `unittest`; the bundled schema evaluator.

**Spec:** `docs/superpowers/specs/2026-09-29-deeper-checks-2b-design.md`

## Global Constraints

- **Prerequisites:** plan 2A and the parked follow-ups (`fix/parked-followups`, which adds the
  schema `number` type) are merged first.
  - Rebase onto them before Task 1.
  - If `summarize_settings` or `analyze_permissions` changed under 2A, keep 2B's additions as
    separate helpers plus two new keys in the `summarize_settings` return dict. Do not edit 2A's
    code.
  - If the `number` type is missing, leave `failure_rate` untyped in the schema.
- **Read-only:** never connect to, authenticate or run an MCP server, `headersHelper` or
  command. No DNS lookups.
- **Never serialize:** URL path, query, userinfo, argument values, env or header values,
  `clientId`, `headersHelper` text, allow or deny `serverUrl`/`serverCommand` values, or
  tool-error text. Only names, counts, booleans, enums and OAuth scope tokens (at most 20, each at
  most 64 characters).
- **Test files:** tests use temporary fake homes (`FakeHome` from `tests/test_collect.py`) and
  never touch the real `~/.claude`. New tests go in `tests/test_mcp_exposure.py`,
  `tests/test_tool_errors.py` and `tests/test_snapshot_contract.py`. Do not add to
  `tests/test_collect.py`, where 2A adds tests.
- **Snapshot:** stays version 1. Every new field is optional and additive. Existing fields keep
  their meaning (`transport` still reports the raw `type` or `stdio`; `tool_error_categories`
  and `mcp_calls_by_server` are unchanged).
- **Caps:**
  - 15 built-in tools (only those with errors), 15 MCP servers (with calls), 3 failing tools per
    server
  - 20 policy observations per server
  - 100 names per list, 50 permission segments per list, 50 `server_names`
  - 100 collision rows
- **Commits:** stage explicit paths. The message ends with exactly one trailer,
  `Assisted-by: Claude:claude-opus-5-5`. Never stage `AGENTS.md`, `CODEX-SETUP.md` or
  `.superpowers/`. Do not push, tag or switch branches.
- **Commands:**
  - Focused tests: `python3 -m unittest discover -s tests -p test_x.py -v` (`tests/` is not a
    package).
  - Gate: `python3 -m unittest discover -s tests`, `python3 tests/check_snapshot_schema.py`,
    `git diff --check`, and coverage ≥ 88
    (`uvx --from coverage==7.16.2 coverage run -m unittest discover -s tests`, then
    `uvx --from coverage==7.16.2 coverage report | tail -1`, then
    `uvx --from coverage==7.16.2 coverage erase`). Never use a glob `rm`.
  - Bash sandbox is broken here; run commands with the sandbox disabled.
- **Doc claims:** cite raw pages only (`curl -sL https://code.claude.com/docs/en/<page>.md |
  grep …`), fetched 2026-09-29. No WebFetch summaries.

Paths: `S = plugins/setup-audit/skills/setup-audit`.

## Review Focus

1. A URL with userinfo and a query, and headers, env and oauth `clientId` holding sentinels →
   no sentinel in the output (Task 1 `test_literal_keys_and_oauth`,
   `test_remote_locality_and_url_flags`).
2. A server with a `url` but no `type` → `transport_class: skipped` with `url_without_type`, and
   `transport` unchanged (Task 1 `test_config_notes_and_transport_class`).
3. A project settings layer from project Q never produces observations for a project-scope server
   in project P (Task 2 `test_observations_join_layers_state_and_rules`).
4. A resumed-session copy of a failing call counts once. A result whose `tool_use` is unknown is
   counted as unmatched, not attributed (Task 3 `test_dedup_window_and_subagents`,
   `test_unmatched_and_unflagged_results`).
5. Error text containing a secret-shaped string never reaches the snapshot (Task 3
   `test_error_text_is_never_stored`).

---

### Task 1: Static MCP exposure fields

**Files:**
- Modify: `S/scripts/extensions.py` (`mcp_summary`, `collect_extensions`, new helpers), `S/scripts/collect.py` (`build_snapshot`: pass `git_status=git_status`)
- Test: `tests/test_mcp_exposure.py` (new)

**Interfaces:**
- Produces:
  - `extensions.tool_prefix(name, plugin=None) -> str`
  - `extensions.endpoint_locality(url) -> str`
  - `extensions.name_collisions(servers) -> list`
  - `mcp_summary(..., project=None, plugin=None)`
  - `collect_extensions(..., hook_summary, git_status=None)`, whose return dict gains
    `mcp_name_collisions`
  - new server keys: `transport_class`, `config_notes`, `endpoint_locality`,
    `plaintext_transport`, `url_has_userinfo`, `url_has_query`, `url_variable_references`,
    `env_literal_keys`, `headers_literal_keys`, `oauth_keys`, `oauth_scopes`, `tool_prefix`,
    `plugin`, `file_git_status`

- [ ] **Step 1: Write the failing tests** (`tests/test_mcp_exposure.py`)

```python
"""MCP exposure metadata and policy observations with fake homes; never connects or runs servers."""
import argparse
import json
import os
from unittest import mock
from test_collect import FakeHome, collect
import extensions

SENTINELS = ('opaque', 'sk-sentinel0123456789')


class ExposureFields(FakeHome):
    def scan(self, roots=(), git_status=None):
        return extensions.collect_extensions(self.home, self.claude, list(roots), [], None, [], [],
                                             collect.redact, collect.hook_handler_entry, git_status=git_status)

    def servers(self, mapping, roots=()):
        self.write('.claude.json', {'mcpServers': mapping})
        return {s['name']: s for s in self.scan(roots)['mcp_servers']}

    def test_remote_locality_and_url_flags(self):
        s = self.servers({
            'priv': {'type': 'http', 'url': 'http://10.0.0.5:8080/opaque?key=opaque'},
            'cred': {'type': 'http', 'url': 'https://user:opaque@example.com/x'},
            'loop': {'type': 'http', 'url': 'http://localhost:3000/mcp'},
            'v6': {'type': 'ws', 'url': 'ws://[::1]:9/'},
            'named': {'type': 'ws', 'url': 'wss://mcp.example.com'},
            'dyn': {'type': 'http', 'url': '${BASE:-https://x.example}/mcp'},
            'pub': {'type': 'http', 'url': 'https://8.8.8.8/mcp'}})
        expected = {'priv': ('private_address', True, False, True), 'cred': ('named_host', False, True, False),
                    'loop': ('loopback', False, False, False), 'v6': ('loopback', False, False, False),
                    'named': ('named_host', False, False, False), 'dyn': ('dynamic', False, False, False),
                    'pub': ('public_address', False, False, False)}
        for name, want in expected.items():
            got = tuple(s[name][k] for k in ('endpoint_locality', 'plaintext_transport',
                                             'url_has_userinfo', 'url_has_query'))
            self.assertEqual(got, want, name)
        self.assertEqual(s['dyn']['url_variable_references'], ['BASE'])
        self.assertEqual(s['priv']['transport_class'], 'remote')
        self.assertNotIn('opaque', json.dumps(s))

    def test_config_notes_and_transport_class(self):
        s = self.servers({
            'notype': {'url': 'https://x.example/mcp'}, 'sdk': {'type': 'sdk'},
            'old': {'type': 'sse', 'url': 'https://a.example/sse'}, 'workspace': {'command': 'node'},
            'placeholder': {'type': 'http', 'url': ''},
            'alias': {'type': 'streamable-http', 'url': 'https://a.example/mcp'},
            'local': {'command': 'node', 'args': ['opaque']}, 'weird': {'type': ['http']}})
        self.assertEqual({n: (v['transport_class'], v['config_notes']) for n, v in s.items()}, {
            'notype': ('skipped', ['url_without_type']), 'sdk': ('skipped', ['sdk_type_skipped']),
            'old': ('remote', ['sse_deprecated']), 'workspace': ('local_process', ['reserved_name']),
            'placeholder': ('remote', ['empty_url_placeholder']), 'alias': ('remote', []),
            'local': ('local_process', []), 'weird': ('unknown', [])})
        self.assertEqual(s['alias']['transport'], 'streamable-http')
        self.assertEqual(s['notype']['transport'], 'stdio')  # existing meaning unchanged
        self.assertNotIn('endpoint_locality', s['placeholder'])
        self.assertNotIn('endpoint_locality', s['local'])

    def test_literal_keys_and_oauth(self):
        s = self.servers({
            'api': {'type': 'http', 'url': 'https://a.example/mcp',
                    'env': {'API_KEY': 'opaque', 'BASE': '${BASE}', 'EMPTY': ''},
                    'headers': {'Authorization': 'Bearer ${TOKEN}', 'X-Key': 'sk-sentinel0123456789'},
                    'oauth': {'clientId': 'opaque', 'callbackPort': 8080,
                              'scopes': 'chat:write channels:read chat:write'},
                    'headersHelper': 'echo opaque'},
            'port': {'type': 'http', 'url': 'https://b.example/mcp', 'oauth': {'callbackPort': 1}}})
        api = s['api']
        self.assertEqual(api['env_literal_keys'], ['API_KEY'])
        self.assertEqual(api['headers_literal_keys'], ['X-Key'])
        self.assertEqual(api['oauth_keys'], ['callbackPort', 'clientId', 'scopes'])
        self.assertEqual(api['oauth_scopes'], ['channels:read', 'chat:write'])
        self.assertIn('headersHelper_configured', api['credential_mechanisms'])
        self.assertIsNone(s['port']['oauth_scopes'])
        self.assertNotIn('oauth_keys', self.servers({'x': {'command': 'node'}})['x'])
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, json.dumps(s))

    def test_tool_prefix_and_plugin_identity(self):
        one = os.path.join(self.claude, 'plugins/cache/market/my.plugin/1')
        two = os.path.join(self.claude, 'plugins/cache/market/other/1')
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {
            'my.plugin@market': [{'scope': 'user', 'installPath': one}],
            'other@market': [{'scope': 'user', 'installPath': two}]}})
        self.write('.claude/plugins/cache/market/my.plugin/1/.claude-plugin/plugin.json',
                   {'name': 'my.plugin', 'mcpServers': {'db tools': {'command': 'node'}}})
        self.write('.claude/plugins/cache/market/other/1/.claude-plugin/plugin.json', {})
        self.write('.claude/plugins/cache/market/other/1/.mcp.json', {'mcpServers': {'s': {'command': 'node'}}})
        self.write('.claude.json', {'mcpServers': {'claude.ai x': {'command': 'node'}}})
        by = {s['name']: s for s in self.scan()['mcp_servers']}
        self.assertEqual((by['db tools']['tool_prefix'], by['db tools']['plugin']),
                         ('plugin_my_plugin_db_tools', 'my.plugin'))
        self.assertEqual((by['s']['tool_prefix'], by['s']['plugin']), ('plugin_other_s', 'other'))
        self.assertEqual(by['claude.ai x']['tool_prefix'], 'claude_ai_x')
        self.assertNotIn('plugin', by['claude.ai x'])

    def test_name_collisions(self):
        p, q = os.path.join(self.home, 'p'), os.path.join(self.home, 'q')
        self.write('.claude.json', {
            'mcpServers': {'gh': {'type': 'http', 'url': 'https://a.example/mcp'}, 'same': {'command': 'node'}},
            'projects': {p: {'mcpServers': {'gh': {'type': 'http', 'url': 'https://b.example/mcp'},
                                            'same': {'command': 'node'}}},
                         q: {'mcpServers': {'x': {'command': 'node'}}}}})
        self.write('p/.mcp.json', {'mcpServers': {'gh': {'type': 'http', 'url': 'https://b.example/mcp'},
                                                  'x': {'command': 'node'}}})
        self.assertEqual(self.scan([p, q])['mcp_name_collisions'], [
            {'name': 'gh', 'project': p, 'scopes': ['local', 'project', 'user'], 'endpoint_origins_differ': True},
            {'name': 'same', 'project': p, 'scopes': ['local', 'user'], 'endpoint_origins_differ': False}])

    def test_project_mcp_json_git_status(self):
        root = os.path.join(self.home, 'repo')
        self.write('repo/.mcp.json', {'mcpServers': {'a': {'command': 'node'}, 'b': {'command': 'node'}}})
        self.write('.claude.json', {'mcpServers': {'u': {'command': 'node'}}})
        calls = []
        result = self.scan([root], git_status=lambda r, rel: calls.append((r, rel)) or 'tracked')
        self.assertEqual(calls, [(root, '.mcp.json')])
        by = {s['name']: s for s in result['mcp_servers']}
        self.assertEqual((by['a']['file_git_status'], by['b']['file_git_status']), ('tracked', 'tracked'))
        self.assertNotIn('file_git_status', by['u'])
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_mcp_exposure.py -v`
Expected: ERROR `TypeError: collect_extensions() got an unexpected keyword argument 'git_status'`.

- [ ] **Step 3: Implement in `extensions.py`**

```python
import ipaddress
from collections import defaultdict

# mcp.md, fetched 2026-09-29: reserved built-in names ("including"; not exhaustive), remote types
# (streamable-http is an alias of http), and the tool-name normalization for plugin servers.
RESERVED_NAMES = frozenset({'workspace', 'claude-in-chrome', 'computer-use', 'Claude Preview', 'Claude Browser'})
REMOTE_TYPES = frozenset({'http', 'streamable-http', 'sse', 'ws'})
VAR_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z_0-9]*)(?::-[^}]*)?\}')


def tool_prefix(name, plugin=None):
    """Server segment of mcp__<segment>__<tool>: chars outside [A-Za-z0-9_-] become '_'."""
    norm = lambda s: re.sub(r'[^A-Za-z0-9_-]', '_', s)  # noqa: E731
    return f'plugin_{norm(plugin)}_{norm(name)}' if plugin else norm(name)


def endpoint_locality(url):
    """Locality from the URL text alone; never resolves names."""
    if '${' in url:
        return 'dynamic'
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return 'invalid'
    if not host:
        return 'invalid'
    if host == 'localhost' or host.endswith('.localhost'):
        return 'loopback'
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return 'named_host'
    if ip.is_loopback:
        return 'loopback'
    if ip.is_private or ip.is_link_local:
        return 'private_address'
    return 'public_address'
```

In `mcp_summary(name, config, path, scope, redact, project=None, plugin=None)`:
- Replace the inline `${…}` regex in the env/headers loop with `VAR_RE`.
- Keep every existing line and meaning.
- Before `return item`, append:

```python
    declared = config.get('type')
    declared = declared if declared is None or isinstance(declared, str) else '<invalid>'
    has_url = 'url' in config
    notes = []
    if declared is None and has_url:
        notes.append('url_without_type')
    if declared == 'sdk':
        notes.append('sdk_type_skipped')
    if declared == 'sse':
        notes.append('sse_deprecated')
    if name in RESERVED_NAMES:
        notes.append('reserved_name')
    if declared in REMOTE_TYPES and url == '':
        notes.append('empty_url_placeholder')
    item['config_notes'] = notes
    item['transport_class'] = ('skipped' if declared == 'sdk' or (declared is None and has_url) else
                               'remote' if declared in REMOTE_TYPES else
                               'local_process' if declared in (None, 'stdio') else 'unknown')
    if isinstance(url, str) and url:
        item['endpoint_locality'] = endpoint_locality(url)
        try:
            parts = urlsplit(url)
            scheme, userinfo, query = parts.scheme, '@' in parts.netloc, bool(parts.query)
        except ValueError:
            scheme, userinfo, query = '', False, False
        item['url_has_userinfo'], item['url_has_query'] = userinfo, query
        item['plaintext_transport'] = scheme in ('http', 'ws') and item['endpoint_locality'] != 'loopback'
        item['url_variable_references'] = sorted({m.group(1) for m in VAR_RE.finditer(url)})
    for key in ('env', 'headers'):
        values = config.get(key)
        if isinstance(values, dict):
            item[key + '_literal_keys'] = sorted(k for k, v in values.items()
                                                 if isinstance(v, str) and v and not VAR_RE.search(v))
    oauth = config.get('oauth')
    if isinstance(oauth, dict):
        item['oauth_keys'] = sorted(k for k in oauth if isinstance(k, str))
        scopes = oauth.get('scopes')
        item['oauth_scopes'] = sorted({s[:64] for s in scopes.split()})[:20] if isinstance(scopes, str) else None
    item['tool_prefix'] = tool_prefix(name, plugin)
    if plugin:
        item['plugin'] = redact(plugin)
```

`url` is the existing `url = config.get('url')` local. Move that assignment above this block if
needed.

`collect_extensions(home, claude, roots, contexts, managed_dir, managed_sources, settings, redact, hook_summary, git_status=None)`:
- `servers_from(data, path, scope, project=None, key='mcpServers', bare=False, plugin=None)`
  passes `plugin` to `mcp_summary`.
- Project `.mcp.json`:

```python
        path = os.path.join(root, '.mcp.json')
        before = len(servers)
        servers_from(json_object(path, 'project', sources), path, 'project', root)
        if git_status and len(servers) > before:
            state = git_status(root, '.mcp.json')
            for server in servers[before:]:
                server['file_git_status'] = state
```

- Plugin loop, after `manifest = json_object(...)`:
  `plugin_name = manifest.get('name') if isinstance(manifest.get('name'), str) and manifest.get('name') else name.split('@')[0]`.
  Pass `plugin=plugin_name` to both plugin `servers_from` calls.
- Add `mcp_name_collisions=name_collisions(servers)` to the return dict.

```python
def name_collisions(servers):
    """Same name in local/project/user scope for one project (mcp.md: matched by name there)."""
    rows = [s for s in servers if s.get('status') == 'collected' and s.get('scope') in ('user', 'local', 'project')]
    shared = [s for s in rows if s['scope'] == 'user']
    out = []
    for project in sorted({s['project'] for s in rows if s.get('project')}):
        group = defaultdict(list)
        for s in shared + [s for s in rows if s['scope'] != 'user' and s.get('project') == project]:
            group[s['name']].append(s)
        for name in sorted(group):
            scopes = sorted({s['scope'] for s in group[name]})
            if len(scopes) > 1:
                ends = {(s.get('transport'), s.get('endpoint_origin') or s.get('executable')) for s in group[name]}
                out.append(dict(name=name, project=project, scopes=scopes, endpoint_origins_differ=len(ends) > 1))
    return out[:MAX_ENTRIES]
```

In `collect.build_snapshot`, pass `git_status=git_status` to `extensions.collect_extensions`.

- [ ] **Step 4: Run focused and full tests**

Run: `python3 -m unittest discover -s tests -p test_mcp_exposure.py -v && python3 -m unittest discover -s tests -p test_extensions.py -v`
Expected: PASS. `test_scopes_and_credentials` still passes unchanged.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/extensions.py plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_mcp_exposure.py
git commit -m "Record locally observable MCP exposure metadata

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 2: Approval, toggle, policy and permission observations per server

**Files:**
- Modify: `S/scripts/collect.py` (new `mcp_policy`, `_mcp_policy_list`, `mcp_permission_rules`; two keys in `summarize_settings`; `build_snapshot` wiring), `S/scripts/extensions.py` (`mcp_project_state` in `collect_extensions`; new `mcp_observations`)
- Test: `tests/test_mcp_exposure.py`

**Interfaces:**
- Consumes (Task 1): server keys `tool_prefix`, `plugin`, `scope`, `project`, `status`.
- Produces:
  - Settings summary keys `mcp_policy` (dict or `None`) and `mcp_permission_rules` (dict).
  - `extensions.collect_extensions(...)['mcp_project_state']`.
  - `extensions.mcp_observations(servers, layers, project_state, display) -> None`, which
    mutates servers to add `policy_observations`, `policy_observations_omitted` and
    `project_trust_accepted`. It uses `OBS_LIMIT = 20`.

- [ ] **Step 1: Write the failing tests** (append to `tests/test_mcp_exposure.py`)

```python
def parsed(*argv):
    ap = argparse.ArgumentParser()
    collect.add_collection_args(ap)
    a = ap.parse_args(list(argv))
    collect.apply_collection_args(ap, a)
    return a


class PolicyObservations(FakeHome):
    scan = ExposureFields.scan  # reuse the helper without re-running ExposureFields' tests

    def test_settings_mcp_policy_shape(self):
        path = self.write('.claude/settings.json', {
            'enabledMcpjsonServers': ['b', 'a', 'a'], 'disabledMcpjsonServers': 'x',
            'enableAllProjectMcpServers': True, 'allowManagedMcpServersOnly': 'yes',
            'allowedMcpServers': [{'serverName': 'gh'}, {'serverUrl': 'https://u:opaque@x.example/*'},
                                  {'serverCommand': ['npx', 'opaque']}, {'bad': 1},
                                  {'serverName': 'a', 'serverUrl': 'b'}],
            'deniedMcpServers': 'nope'})
        s = collect.summarize_settings(path)
        self.assertEqual(s['mcp_policy'], {
            'enabledMcpjsonServers': ['a', 'b'], 'disabledMcpjsonServers': 'invalid',
            'enableAllProjectMcpServers': True, 'allowManagedMcpServersOnly': 'invalid',
            'allowedMcpServers': {'entries': 5, 'by_key': {'invalid': 2, 'serverCommand': 1, 'serverName': 1,
                                                           'serverUrl': 1}, 'server_names': ['gh']},
            'deniedMcpServers': 'invalid'})
        self.assertNotIn('opaque', json.dumps(s))
        other = self.write('.claude/settings.local.json', {'model': 'x'})
        self.assertIsNone(collect.summarize_settings(other)['mcp_policy'])

    def test_permission_rules_are_counted_per_server_segment(self):
        rules = collect.mcp_permission_rules({
            'allow': ['mcp__github__get_*', 'mcp__github', 'mcp__*', 'Bash(ls)', 'mcp__plugin_demo_db__query',
                      'mcp__', 7],
            'deny': ['mcp__slack__post(channel:x)']})
        self.assertEqual(rules, {'allow': {'*': 1, 'github': 2, 'plugin_demo_db': 1}, 'deny': {'slack': 1}})

    def test_project_state_keeps_only_mcp_lists_and_trust(self):
        root = os.path.join(self.home, 'repo')
        self.write('.claude.json', {'projects': {
            root: {'enabledMcpjsonServers': ['db'], 'disabledMcpjsonServers': [],
                   'disabledMcpServers': ['plugin:demo:x'], 'enabledMcpServers': ['computer-use'],
                   'hasTrustDialogAccepted': False, 'lastCost': 12.5, 'lastSessionFirstPrompt': 'opaque'},
            '/elsewhere': {'hasTrustDialogAccepted': True}}})
        state = self.scan([root])['mcp_project_state']
        self.assertEqual(state, [{'project': root, 'source': os.path.join(self.home, '.claude.json'),
                                  'enabledMcpjsonServers': ['db'], 'disabledMcpjsonServers': [],
                                  'disabledMcpServers': ['plugin:demo:x'], 'enabledMcpServers': ['computer-use'],
                                  'trust_accepted': False}])
        self.assertNotIn('opaque', json.dumps(state))

    def test_observations_join_layers_state_and_rules(self):
        P = '/h/p'
        servers = [
            {'status': 'collected', 'scope': 'project', 'name': 'db', 'project': P, 'tool_prefix': 'db'},
            {'status': 'collected', 'scope': 'user', 'name': 'gh', 'project': None, 'tool_prefix': 'gh'},
            {'status': 'collected', 'scope': 'plugin', 'name': 'x', 'project': None, 'plugin': 'demo',
             'tool_prefix': 'plugin_demo_x'},
            {'status': 'unavailable', 'scope': 'user', 'name': 'broken', 'project': None}]
        layers = [
            ('user', None, {'path': '~/.claude/settings.json', 'mcp_policy': None,
                            'mcp_permission_rules': {'allow': {'gh': 1, '*': 1}}}),
            ('project', '~/p', {'path': '~/p/.claude/settings.local.json',
                                'mcp_policy': {'enabledMcpjsonServers': ['db']}, 'mcp_permission_rules': {}}),
            ('project', '~/q', {'path': '~/q/.claude/settings.json',
                                'mcp_policy': {'enableAllProjectMcpServers': True},
                                'mcp_permission_rules': {'deny': {'plugin_demo_x': 2}}}),
            ('managed', None, {'path': '/etc/claude-code/managed-settings.json',
                               'mcp_policy': {'deniedMcpServers': {'entries': 1, 'by_key': {'serverName': 1},
                                                                   'server_names': ['gh']}},
                               'mcp_permission_rules': {}})]
        state = [{'project': P, 'source': '/h/.claude.json', 'disabledMcpServers': ['plugin:demo:x'],
                  'trust_accepted': False}]
        extensions.mcp_observations(servers, layers, state, lambda p: p.replace('/h', '~'))
        obs = lambda i: [(o['source'], o['kind'], o['value']) for o in servers[i]['policy_observations']]  # noqa: E731
        self.assertEqual(obs(0), [('~/.claude/settings.json', 'permission_allow_any_server', 1),
                                  ('~/p/.claude/settings.local.json', 'approval_enabled', True)])
        self.assertIs(servers[0]['project_trust_accepted'], False)
        self.assertEqual(obs(1), [('~/.claude/settings.json', 'permission_allow', 1),
                                  ('~/.claude/settings.json', 'permission_allow_any_server', 1),
                                  ('/etc/claude-code/managed-settings.json', 'policy_denied_by_name', True)])
        self.assertEqual(obs(2), [('~/.claude/settings.json', 'permission_allow_any_server', 1),
                                  ('~/q/.claude/settings.json', 'permission_deny', 2),
                                  ('~/.claude.json#projects[~/p]', 'toggle_disabled', True)])
        self.assertNotIn('policy_observations', servers[3])
        self.assertNotIn('project_trust_accepted', servers[1])

    def test_observation_cap(self):
        servers = [{'status': 'collected', 'scope': 'user', 'name': 'gh', 'project': None, 'tool_prefix': 'gh'}]
        layers = [('project', f'~/p{i}', {'path': f'~/p{i}/.claude/settings.json', 'mcp_policy': None,
                                          'mcp_permission_rules': {'allow': {'gh': 1}}}) for i in range(25)]
        extensions.mcp_observations(servers, layers, [], lambda p: p)
        self.assertEqual((len(servers[0]['policy_observations']), servers[0]['policy_observations_omitted']), (20, 5))

    def test_snapshot_carries_observations(self):
        root = os.path.join(self.home, 'repo')
        self.write('repo/.mcp.json', {'mcpServers': {'db': {'command': 'node', 'args': ['opaque']}}})
        self.write('repo/.claude/settings.local.json', {'enabledMcpjsonServers': ['db'],
                                                        'permissions': {'allow': ['mcp__db__query']}})
        self.write('.claude.json', {'projects': {root: {'hasTrustDialogAccepted': True}}})
        with mock.patch.object(collect, 'git_status', return_value='tracked'):
            snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--scope', 'project', '--project', root))
        db = next(s for s in snap['extensions']['mcp_servers'] if s['name'] == 'db')
        seen = {(o['source'], o['kind'], o['value']) for o in db['policy_observations']}
        self.assertIn(('~/repo/.claude/settings.local.json', 'approval_enabled', True), seen)
        self.assertIn(('~/repo/.claude/settings.local.json', 'permission_allow', 1), seen)
        self.assertIs(db['project_trust_accepted'], True)
        self.assertEqual(db['file_git_status'], 'tracked')
        self.assertNotIn('opaque', json.dumps(snap))
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_mcp_exposure.py -v`
Expected: `KeyError: 'mcp_policy'` and `AttributeError` for `mcp_permission_rules` / `mcp_observations`.

- [ ] **Step 3: Implement**

`collect.py` (near `analyze_permissions`, as separate helpers; do not edit 2A's code):

```python
# settings-reference.md and managed-mcp.md, fetched 2026-09-29. Shapes only: allow/deny URL and
# command values are never copied, and no effective policy is computed.
MCP_POLICY_LISTS = ("enabledMcpjsonServers", "disabledMcpjsonServers")
MCP_POLICY_FLAGS = ("enableAllProjectMcpServers", "allowManagedMcpServersOnly", "disableClaudeAiConnectors")


def _mcp_policy_list(value):
    if not isinstance(value, list):
        return "invalid"
    kinds, names = Counter(), set()
    for entry in value:
        key = next(iter(entry)) if isinstance(entry, dict) and len(entry) == 1 else None
        kinds[key if key in ("serverName", "serverUrl", "serverCommand") else "invalid"] += 1
        if key == "serverName" and isinstance(entry[key], str):
            names.add(entry[key])
    return {"entries": len(value), "by_key": dict(sorted(kinds.items())), "server_names": sorted(names)[:50]}


def mcp_policy(d):
    out = {}
    for key in MCP_POLICY_LISTS:
        if key in d:
            v = d[key]
            out[key] = sorted({x for x in v if isinstance(x, str)})[:100] if isinstance(v, list) else "invalid"
    for key in MCP_POLICY_FLAGS:
        if key in d:
            out[key] = d[key] if isinstance(d[key], bool) else "invalid"
    for key in ("allowedMcpServers", "deniedMcpServers"):
        if key in d:
            out[key] = _mcp_policy_list(d[key])
    return out or None


def mcp_permission_rules(perms):
    """Count mcp__ rules per server segment (a glob segment counts as '*'); rule validity is 2A's."""
    out = {}
    for kind in ("allow", "ask", "deny"):
        counts = Counter()
        for rule in perms.get(kind) or []:
            if not isinstance(rule, str):
                continue
            tool = rule.split("(", 1)[0].strip()
            if tool.startswith("mcp__"):
                segment = tool.split("__")[1]
                if segment:
                    counts["*" if "*" in segment else segment] += 1
        if counts:
            out[kind] = dict(sorted(counts.items())[:50])
    return out
```

In `summarize_settings`'s return dict, add
`"mcp_policy": mcp_policy(d), "mcp_permission_rules": mcp_permission_rules(d.get("permissions", {}) or {}),`.

`extensions.py`:

```python
PROJECT_STATE_LISTS = ('enabledMcpjsonServers', 'disabledMcpjsonServers', 'disabledMcpServers', 'enabledMcpServers')
OBS_LIMIT = 20
```

In `collect_extensions`, replace the local-scope block with:

```python
    project_state = []
    for root in project_paths:
        entry = local.get(root) if isinstance(local, dict) else None
        if isinstance(entry, dict):
            servers_from(entry, user_path, 'local', root)
            state = {'project': root, 'source': user_path}
            for key in PROJECT_STATE_LISTS:
                if isinstance(entry.get(key), list):
                    state[key] = sorted({x for x in entry[key] if isinstance(x, str)})[:100]
            trust = entry.get('hasTrustDialogAccepted')
            state['trust_accepted'] = trust if isinstance(trust, bool) else None
            project_state.append(state)
        # (existing project .mcp.json block from Task 1 follows unchanged)
```

Add `mcp_project_state=project_state[:MAX_ENTRIES]` to the return dict. Then:

```python
def mcp_observations(servers, layers, project_state, display):
    """Per-source observations for each collected server; never an effective state.

    layers: (user|project|managed, project display path or None, settings summary). A project layer
    applies to servers of that project, or to servers without a project (then its source names it).
    """
    for s in servers:
        if s.get('status') != 'collected':
            continue
        project = display(s['project']) if s.get('project') else None
        obs = []
        for layer, where, summary in layers:
            if layer == 'project' and project is not None and where != project:
                continue
            src = summary.get('path', '?')
            policy = summary.get('mcp_policy') or {}
            if s['scope'] == 'project':
                for key, kind in (('enabledMcpjsonServers', 'approval_enabled'),
                                  ('disabledMcpjsonServers', 'approval_rejected')):
                    if isinstance(policy.get(key), list) and s['name'] in policy[key]:
                        obs.append(dict(source=src, kind=kind, value=True))
                if isinstance(policy.get('enableAllProjectMcpServers'), bool):
                    obs.append(dict(source=src, kind='approval_enable_all',
                                    value=policy['enableAllProjectMcpServers']))
            for key, kind in (('allowedMcpServers', 'policy_allowed_by_name'),
                              ('deniedMcpServers', 'policy_denied_by_name')):
                shape = policy.get(key)
                if isinstance(shape, dict) and s['name'] in shape.get('server_names', []):
                    obs.append(dict(source=src, kind=kind, value=True))
            rules = summary.get('mcp_permission_rules') or {}
            for kind in ('allow', 'ask', 'deny'):
                counts = rules.get(kind) or {}
                if counts.get(s.get('tool_prefix')):
                    obs.append(dict(source=src, kind=f'permission_{kind}', value=counts[s['tool_prefix']]))
                if counts.get('*'):
                    obs.append(dict(source=src, kind=f'permission_{kind}_any_server', value=counts['*']))
        names = {s['name']} | ({f"plugin:{s['plugin']}:{s['name']}"} if s.get('plugin') else set())
        for state in project_state:
            where = display(state['project'])
            if project is not None and where != project:
                continue
            src = f"{display(state['source'])}#projects[{where}]"
            if s['scope'] == 'project':
                for key, kind in (('enabledMcpjsonServers', 'approval_enabled'),
                                  ('disabledMcpjsonServers', 'approval_rejected')):
                    if s['name'] in state.get(key, []):
                        obs.append(dict(source=src, kind=kind, value=True))
                s['project_trust_accepted'] = state.get('trust_accepted')
            for key, kind in (('disabledMcpServers', 'toggle_disabled'), ('enabledMcpServers', 'toggle_enabled')):
                if names & set(state.get(key, [])):
                    obs.append(dict(source=src, kind=kind, value=True))
        if s['scope'] == 'project':
            s.setdefault('project_trust_accepted', None)
        s['policy_observations'] = obs[:OBS_LIMIT]
        if len(obs) > OBS_LIMIT:
            s['policy_observations_omitted'] = len(obs) - OBS_LIMIT
```

In `collect.build_snapshot`, right after `snap['extensions'] = ...`:

```python
    layers = ([("user", None, s) for s in snap["global"]["settings"]]
              + [("project", p, s) for p, e in snap["projects"].items() for s in e.get("settings", [])]
              + [("managed", None, s) for s in snap["managed_settings"]["settings"]])
    extensions.mcp_observations(snap["extensions"]["mcp_servers"], layers,
                                snap["extensions"]["mcp_project_state"], lambda p: p.replace(HOME, "~"))
```

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest discover -s tests -p test_mcp_exposure.py -v && python3 -m unittest discover -s tests`
Expected: PASS. The contract producer tests still validate, because the fields are untyped until
Task 4.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py plugins/setup-audit/skills/setup-audit/scripts/extensions.py tests/test_mcp_exposure.py
git commit -m "Observe MCP approvals, toggles, policy and permission rules per server

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 3: Per-tool and per-MCP-server tool-error clustering

**Files:**
- Modify: `S/scripts/collect.py` (constants, `tool_error_category`, `_tool_key`, `tool_error_record`, `tool_error_summary`, `collect_transcripts`)
- Test: `tests/test_tool_errors.py` (new)

**Interfaces:**
- Produces:
  - `collect.tool_error_category(content) -> str`
  - `collect.tool_error_summary(stats) -> dict`
  - The `transcripts.tool_errors` object (shape in the spec, section C).
  - Constants `TOOL_ERROR_LIMIT = 15`, `MIN_CALLS_FOR_RATE = 5` and
    `DENIAL_CATEGORIES = {"user_rejected", "permission_denied"}`.

- [ ] **Step 1: Write the failing tests** (`tests/test_tool_errors.py`)

```python
"""Per-tool and per-MCP-server tool-error clustering from fake transcripts; error text is never stored."""
import json
from unittest import mock
from test_collect import FakeHome, collect

NOW = 1789473600  # 2026-09-15 12:00 UTC


def stamp(offset=0):
    return collect.datetime.fromtimestamp(NOW + offset, collect.timezone.utc).isoformat()


def use(tid, name, session="s"):
    return {"type": "assistant", "sessionId": session, "timestamp": stamp(),
            "message": {"content": [{"type": "tool_use", "id": tid, "name": name, "input": {}}]}}


def result(tid, text, is_error=True, session="s", offset=0):
    item = {"type": "tool_result", "tool_use_id": tid, "content": text}
    if is_error is not None:
        item["is_error"] = is_error
    return {"type": "user", "sessionId": session, "timestamp": stamp(offset), "message": {"content": [item]}}


class ToolErrors(FakeHome):
    def transcript(self, rel, records):
        self.write(f".claude/projects/{rel}", "\n".join(map(json.dumps, records)))

    def run(self, full=False):
        with mock.patch.object(collect.time, "time", return_value=NOW):
            t = collect.collect_transcripts(1)
        return t if full else t["tool_errors"]

    def test_builtin_counts_rate_and_denials(self):
        self.transcript("-a/s.jsonl", [use(f"b{i}", "Bash") for i in range(6)] + [
            result("b0", "Exit code 1\nboom"), result("b1", "Exit code 2"),
            result("b2", "Permission to use Bash with command x has been denied."),
            result("b3", "ok", is_error=False)])
        t = self.run()
        self.assertEqual(t["by_tool"], [{"tool": "Bash", "calls": 6, "errors": 3, "denied": 1, "failure_rate": 0.333,
                                         "categories": {"nonzero_exit": 2, "permission_denied": 1}}])
        self.assertEqual((t["error_results_paired"], t["error_results_unmatched"], t["results_without_is_error"]),
                         (3, 0, 0))
        self.assertEqual(t["min_calls_for_rate"], 5)

    def test_mcp_servers_cluster_with_failing_tools(self):
        self.transcript("-a/s.jsonl", [use(f"c{i}", "mcp__github__create_issue") for i in range(3)]
                        + [use(f"r{i}", "mcp__github__read") for i in range(2)]
                        + [use("q0", "mcp__plugin_demo_db__query")]
                        + [result("c0", [{"type": "text", "text": "MCP error -32001: 401 Unauthorized"}]),
                           result("c1", "403 Forbidden"), result("q0", "connect ECONNREFUSED 127.0.0.1:5432")])
        t = self.run()
        self.assertEqual(t["by_mcp_server"], [
            {"server": "github", "top_error_tools": [["create_issue", 2]], "calls": 5, "errors": 2, "denied": 0,
             "failure_rate": 0.4, "categories": {"auth": 2}},
            {"server": "plugin_demo_db", "top_error_tools": [["query", 1]], "calls": 1, "errors": 1, "denied": 0,
             "failure_rate": None, "categories": {"connection": 1}}])
        self.assertEqual(t["by_tool"], [])

    def test_unmatched_and_unflagged_results(self):
        self.transcript("-a/s.jsonl", [use("a", "Read"), result("zzz", "File does not exist."),
                                       result("a", "fine", is_error=None)])
        t = self.run()
        self.assertEqual((t["error_results_paired"], t["error_results_unmatched"], t["results_without_is_error"]),
                         (0, 1, 1))
        self.assertEqual(t["by_tool"], [])

    def test_error_text_is_never_stored(self):
        self.transcript("-a/s.jsonl", [use("x", "Bash"),
                                       result("x", "Exit code 1 sk-sentinel0123456789 UNIQUE-ERROR-TEXT")])
        full = self.run(full=True)
        full.pop("_harness")  # in-memory raw with tuple keys; consumed and dropped by build_snapshot
        text = json.dumps(full, default=str)
        self.assertNotIn("sk-sentinel0123456789", text)
        self.assertNotIn("UNIQUE-ERROR-TEXT", text)

    def test_dedup_window_and_subagents(self):
        failing = [use("d", "Edit", session="s1"),
                   result("d", "<tool_use_error>String to replace not found</tool_use_error>", session="s1")]
        self.transcript("-a/s1.jsonl", failing)
        self.transcript("-a/copy.jsonl", failing)  # resumed copy, same sessionId
        self.transcript("-a/old.jsonl", [use("o", "Edit", session="s2"),
                                         result("o", "Exit code 1", session="s2", offset=-2 * 86400)])
        self.transcript("-a/sess/subagents/agent-1.jsonl", [use("g", "Grep", session="s9"),
                                                            result("g", "Exit code 2", session="s9")])
        t = self.run()
        self.assertEqual([(r["tool"], r["calls"], r["errors"], r["categories"]) for r in t["by_tool"]],
                         [("Edit", 2, 1, {"file_state": 1}), ("Grep", 1, 1, {"nonzero_exit": 1})])

    def test_tool_cap(self):
        records = []
        for i in range(17):
            records += [use(f"t{i}", f"Tool{i:02d}"), result(f"t{i}", "Exit code 1")]
        self.transcript("-a/s.jsonl", records)
        t = self.run()
        self.assertEqual((len(t["by_tool"]), t["omitted"]["tools"], t["by_tool"][0]["tool"]), (15, 2, "Tool00"))

    def test_categories_are_ordered_first_match(self):
        cases = [
            ("Exit code 1\nbwrap: setting up uid map: Permission denied", "sandbox"),
            ("Exit code 2\nls: cannot access 'x': No such file or directory", "nonzero_exit"),
            ("Exit code 124\nCommand timed out after 2m", "timeout"),
            ("The user doesn't want to proceed with this tool use.", "user_rejected"),
            ("Permission to use Bash with command rm -rf x has been denied.", "permission_denied"),
            ("<tool_use_error>InputValidationError: Edit failed</tool_use_error>", "validation"),
            ("<tool_use_error>File has not been read yet. Read it first.</tool_use_error>", "file_state"),
            ("File does not exist. Note: your current working directory is /x.", "not_found"),
            ("File content (3.2MB) exceeds maximum allowed size (256KB).", "too_large"),
            ([{"type": "text", "text": "MCP error -32001: 401 Unauthorized"}], "auth"),
            ([{"type": "text", "text": "MCP error -32000: Connection closed"}], "connection"),
            ("Something unexpected", "other"),
            (None, "other")]
        for content, want in cases:
            self.assertEqual(collect.tool_error_category(content), want, content)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python3 -m unittest discover -s tests -p test_tool_errors.py -v`
Expected: `KeyError: 'tool_errors'` and `AttributeError: ... 'tool_error_category'`.

- [ ] **Step 3: Implement in `collect.py`**

```python
# Heuristic categories over the first 300 characters of an is_error tool_result, after a leading
# <tool_use_error> tag. Shapes observed in local transcripts on 2026-09-29; Claude Code documents no
# tool-error taxonomy. First match wins. Only the category name is kept, never the text.
TOOL_ERROR_CATEGORIES = [
    ("user_rejected", re.compile(r"doesn.t want to (proceed|take this action)|user rejected", re.I)),
    ("permission_denied", re.compile(r"^Permission (for this action|to use)\b")),
    ("sandbox", re.compile(r"\b(bwrap|apply-seccomp|sandbox-exec|seatbelt)\b", re.I)),
    ("timeout", re.compile(r"timed out|\btimeout\b", re.I)),
    ("nonzero_exit", re.compile(r"^Exit code \d+")),
    ("validation", re.compile(r"InputValidationError|does not match (the )?required|invalid (input|arguments?|params)", re.I)),
    ("file_state", re.compile(r"has not been read yet|has been modified since|String to replace not found", re.I)),
    ("not_found", re.compile(r"does not exist|No such file|ENOENT|\bnot found\b", re.I)),
    ("too_large", re.compile(r"exceeds (the )?maximum|too large|too long", re.I)),
    ("auth", re.compile(r"\b(401|403)\b|unauthori[sz]ed|forbidden|authenticat", re.I)),
    ("connection", re.compile(r"ECONNREFUSED|ECONNRESET|ENOTFOUND|not connected|"
                              r"connection (closed|refused|reset|error)|fetch failed", re.I)),
]
DENIAL_CATEGORIES = {"user_rejected", "permission_denied"}
TOOL_ERROR_LIMIT = 15
MIN_CALLS_FOR_RATE = 5
BUILTIN_TOOL_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")


def tool_error_category(content):
    if isinstance(content, list):
        content = " ".join(b["text"] for b in content if isinstance(b, dict) and isinstance(b.get("text"), str))
    text = re.sub(r"^\s*<tool_use_error>\s*", "", content[:300] if isinstance(content, str) else "")
    return next((name for name, rx in TOOL_ERROR_CATEGORIES if rx.search(text)), "other")


def _tool_key(name):
    if name.startswith("mcp__"):
        parts = name.split("__")
        return ("mcp", parts[1], "__".join(parts[2:])[:64]) if len(parts) >= 3 and parts[1] else ("builtin", "other")
    return ("builtin", name if BUILTIN_TOOL_RE.fullmatch(name) else "other")


def _tool_error_stats():
    return {"calls": Counter(), "errors": Counter(), "denied": Counter(), "categories": defaultdict(Counter),
            "seen_calls": set(), "seen_results": set(), "unmatched": 0, "no_flag": 0}


def tool_error_record(record, path, names, stats):
    """Count tool calls and is_error results of one in-window record (main or subagent file)."""
    if record.get("type") not in ("assistant", "user"):
        return
    msg = record.get("message")
    items = msg.get("content", record.get("content")) if isinstance(msg, dict) else record.get("content")
    if not isinstance(items, list):
        return
    session = record.get("sessionId")
    scope = (os.path.dirname(path), session if isinstance(session, str) and session else path)
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "tool_use" and isinstance(item.get("name"), str):
            key, tool_id = _tool_key(item["name"]), item.get("id")
            if isinstance(tool_id, str) and tool_id:
                names[tool_id] = key
                if (scope, tool_id) in stats["seen_calls"]:
                    continue
                stats["seen_calls"].add((scope, tool_id))
            stats["calls"][key] += 1
        elif item.get("type") == "tool_result":
            if "is_error" not in item:
                stats["no_flag"] += 1
                continue
            if item["is_error"] is not True:
                continue
            tool_id = item.get("tool_use_id")
            key = names.get(tool_id) if isinstance(tool_id, str) else None
            if key is None:
                stats["unmatched"] += 1
                continue
            if (scope, tool_id) in stats["seen_results"]:
                continue
            stats["seen_results"].add((scope, tool_id))
            category = tool_error_category(item.get("content"))
            stats["errors"][key] += 1
            stats["categories"][key][category] += 1
            stats["denied"][key] += category in DENIAL_CATEGORIES


def tool_error_summary(stats):
    def row(keys, **extra):
        calls = sum(stats["calls"][k] for k in keys)
        errors = sum(stats["errors"][k] for k in keys)
        denied = sum(stats["denied"][k] for k in keys)
        categories = Counter()
        for k in keys:
            categories.update(stats["categories"].get(k, {}))
        rate = round((errors - denied) / calls, 3) if calls >= MIN_CALLS_FOR_RATE else None
        return dict(extra, calls=calls, errors=errors, denied=denied, failure_rate=rate,
                    categories=dict(sorted(categories.items())))
    order = lambda r: (-r["errors"], -r["calls"], r.get("tool") or r.get("server"))  # noqa: E731
    tools = sorted((row([k], tool=k[1]) for k in stats["errors"] if k[0] == "builtin"), key=order)
    by_server = defaultdict(list)
    for k in stats["calls"]:
        if k[0] == "mcp":
            by_server[k[1]].append(k)
    servers = []
    for server, keys in by_server.items():
        failing = sorted(((k[2], stats["errors"][k]) for k in keys if stats["errors"][k]), key=lambda kv: (-kv[1], kv[0]))
        servers.append(row(keys, server=server, top_error_tools=[list(kv) for kv in failing[:3]]))
    servers.sort(key=order)
    return {
        "error_results_paired": sum(stats["errors"].values()),
        "error_results_unmatched": stats["unmatched"],
        "results_without_is_error": stats["no_flag"],
        "by_tool": tools[:TOOL_ERROR_LIMIT],
        "by_mcp_server": servers[:TOOL_ERROR_LIMIT],
        "omitted": {"tools": max(0, len(tools) - TOOL_ERROR_LIMIT),
                    "mcp_servers": max(0, len(servers) - TOOL_ERROR_LIMIT)},
        "min_calls_for_rate": MIN_CALLS_FOR_RATE,
        "categories_basis": "Heuristic text patterns observed 2026-09-29; error text is not stored.",
        "scope_note": ("Main and subagent transcripts in the window; is_error true only; paired by tool id within a "
                       "file; deduplicated by project directory, sessionId (file fallback) and tool id. "
                       "failure_rate excludes permission_denied and user_rejected; null under min_calls_for_rate."),
    }
```

In `collect_transcripts`:
- Create `tool_stats = _tool_error_stats()` next to `seen_mcp`.
- Set `names = {}` per file, next to `pending = {}`.
- After `harness_record(raw, record, path, session_key, is_top, seen_ids)`, call
  `tool_error_record(record, path, names, tool_stats)`.
- Add `"tool_errors": tool_error_summary(tool_stats),` to the returned dict.

The existing `mcp_calls_by_server` loop stays unchanged.

- [ ] **Step 4: Run tests**

Run: `python3 -m unittest discover -s tests -p test_tool_errors.py -v && python3 -m unittest discover -s tests`
Expected: PASS. Existing transcript tests keep their coverage counts.

- [ ] **Step 5: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/scripts/collect.py tests/test_tool_errors.py
git commit -m "Cluster tool errors per built-in tool and per MCP server

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 4: Snapshot schema, contract tests and format docs

**Files:**
- Modify: `S/references/snapshot.schema.json`, `S/references/snapshot-format.md`, `S/references/coverage.md`
- Test: `tests/test_snapshot_contract.py`

- [ ] **Step 1: Write the failing test** (append to `SnapshotContract` in `tests/test_snapshot_contract.py`)

```python
    def test_mcp_exposure_and_tool_errors_are_checked(self):
        snap = self.snapshot()
        snap["extensions"]["mcp_servers"] = [{
            "source": "/h/.claude.json", "scope": "user", "status": "collected", "transport_class": "remote",
            "config_notes": [], "endpoint_locality": "named_host", "plaintext_transport": False,
            "oauth_scopes": None, "tool_prefix": "gh", "file_git_status": "tracked",
            "project_trust_accepted": None,
            "policy_observations": [{"source": "~/.claude/settings.json", "kind": "permission_allow", "value": 2}]}]
        snap["extensions"]["mcp_project_state"] = [{"project": "/h/p", "source": "/h/.claude.json",
                                                    "trust_accepted": None}]
        snap["extensions"]["mcp_name_collisions"] = [{"name": "gh", "project": "/h/p", "scopes": ["local", "user"],
                                                      "endpoint_origins_differ": True}]
        snap["transcripts"]["tool_errors"] = {
            "error_results_paired": 1, "error_results_unmatched": 0, "results_without_is_error": 0,
            "by_tool": [{"tool": "Bash", "calls": 6, "errors": 1, "denied": 0, "failure_rate": 0.167,
                         "categories": {"nonzero_exit": 1}}],
            "by_mcp_server": [{"server": "gh", "calls": 1, "errors": 0, "denied": 0, "failure_rate": None,
                               "categories": {}, "top_error_tools": []}],
            "omitted": {"tools": 0, "mcp_servers": 0}, "min_calls_for_rate": 5}
        contract.validate_snapshot(snap)
        server = lambda s: s["extensions"]["mcp_servers"][0]  # noqa: E731
        errors = lambda s: s["transcripts"]["tool_errors"]  # noqa: E731
        for mutate in (lambda s: server(s).update(transport_class="bogus"),
                       lambda s: server(s).update(endpoint_locality="moon"),
                       lambda s: server(s).update(config_notes=["nope"]),
                       lambda s: server(s).update(file_git_status="maybe"),
                       lambda s: server(s)["policy_observations"][0].pop("kind"),
                       lambda s: server(s)["policy_observations"][0].update(value="2"),
                       lambda s: s["extensions"]["mcp_project_state"][0].update(trust_accepted="yes"),
                       lambda s: s["extensions"]["mcp_name_collisions"][0].update(scopes=["plugin"]),
                       lambda s: errors(s)["by_tool"][0].update(failure_rate="x"),
                       lambda s: errors(s)["by_tool"][0].update(calls=-1),
                       lambda s: errors(s)["by_mcp_server"][0]["categories"].update(auth=-1),
                       lambda s: errors(s).pop("omitted")):
            altered = copy.deepcopy(snap)
            mutate(altered)
            with self.assertRaises(contract.SnapshotError):
                contract.validate_snapshot(altered)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest discover -s tests -p test_snapshot_contract.py -v`
Expected: FAIL `AssertionError: SnapshotError not raised` (the fields are untyped).

- [ ] **Step 3: Extend the schema** (only keywords the evaluator supports: `type`, `enum`, `const`, `minimum`, `required`, `properties`, `additionalProperties`, `items`, `$ref`)

- `$defs.mcp_server`: copy every property of `$defs.source` (same `required`: `source`, `scope`,
  `status`) and add:

```json
"transport_class": {"enum": ["local_process", "remote", "skipped", "unknown"]},
"config_notes": {"type": "array", "items": {"enum": ["url_without_type", "sdk_type_skipped", "sse_deprecated", "reserved_name", "empty_url_placeholder"]}},
"endpoint_locality": {"enum": ["loopback", "private_address", "public_address", "named_host", "dynamic", "invalid"]},
"plaintext_transport": {"type": "boolean"},
"url_has_userinfo": {"type": "boolean"},
"url_has_query": {"type": "boolean"},
"url_variable_references": {"type": "array", "items": {"type": "string"}},
"env_literal_keys": {"type": "array", "items": {"type": "string"}},
"headers_literal_keys": {"type": "array", "items": {"type": "string"}},
"oauth_keys": {"type": "array", "items": {"type": "string"}},
"oauth_scopes": {"type": ["array", "null"], "items": {"type": "string"}},
"tool_prefix": {"type": "string"},
"plugin": {"type": "string"},
"file_git_status": {"enum": ["tracked", "untracked", "ignored", "not-a-git-repo", "unknown"]},
"project_trust_accepted": {"type": ["boolean", "null"]},
"policy_observations": {"type": "array", "items": {"type": "object", "required": ["source", "kind", "value"], "properties": {
  "source": {"type": "string"},
  "kind": {"enum": ["approval_enabled", "approval_rejected", "approval_enable_all", "policy_allowed_by_name", "policy_denied_by_name", "toggle_disabled", "toggle_enabled", "permission_allow", "permission_ask", "permission_deny", "permission_allow_any_server", "permission_ask_any_server", "permission_deny_any_server"]},
  "value": {"type": ["boolean", "integer"]}}}},
"policy_observations_omitted": {"type": "integer", "minimum": 0}
```

- `extensions.properties.mcp_servers.items` → `{"$ref": "#/$defs/mcp_server"}`. Add optional
  `extensions` properties:

```json
"mcp_project_state": {"type": "array", "items": {"type": "object", "required": ["project", "source", "trust_accepted"], "properties": {
  "project": {"type": "string"}, "source": {"type": "string"},
  "enabledMcpjsonServers": {"type": "array", "items": {"type": "string"}},
  "disabledMcpjsonServers": {"type": "array", "items": {"type": "string"}},
  "disabledMcpServers": {"type": "array", "items": {"type": "string"}},
  "enabledMcpServers": {"type": "array", "items": {"type": "string"}},
  "trust_accepted": {"type": ["boolean", "null"]}}}},
"mcp_name_collisions": {"type": "array", "items": {"type": "object", "required": ["name", "project", "scopes", "endpoint_origins_differ"], "properties": {
  "name": {"type": "string"}, "project": {"type": ["string", "null"]},
  "scopes": {"type": "array", "items": {"enum": ["user", "local", "project"]}},
  "endpoint_origins_differ": {"type": "boolean"}}}}
```

- `$defs.tool_error_row`, and an optional `transcripts.properties.tool_errors`:

```json
"tool_error_row": {"type": "object", "required": ["calls", "errors", "denied", "failure_rate", "categories"], "properties": {
  "tool": {"type": "string"}, "server": {"type": "string"},
  "calls": {"type": "integer", "minimum": 0}, "errors": {"type": "integer", "minimum": 0},
  "denied": {"type": "integer", "minimum": 0}, "failure_rate": {"type": ["number", "null"]},
  "categories": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
  "top_error_tools": {"type": "array", "items": {"type": "array"}}}}
```

```json
"tool_errors": {"type": "object", "required": ["error_results_paired", "error_results_unmatched", "results_without_is_error", "by_tool", "by_mcp_server", "omitted", "min_calls_for_rate"], "properties": {
  "error_results_paired": {"type": "integer", "minimum": 0},
  "error_results_unmatched": {"type": "integer", "minimum": 0},
  "results_without_is_error": {"type": "integer", "minimum": 0},
  "by_tool": {"type": "array", "items": {"$ref": "#/$defs/tool_error_row"}},
  "by_mcp_server": {"type": "array", "items": {"$ref": "#/$defs/tool_error_row"}},
  "omitted": {"type": "object", "required": ["tools", "mcp_servers"], "properties": {
    "tools": {"type": "integer", "minimum": 0}, "mcp_servers": {"type": "integer", "minimum": 0}}},
  "min_calls_for_rate": {"type": "integer", "minimum": 1}}}
```

If the `number` type is not available (the prerequisite is missing), drop the `type` of
`failure_rate` and remove the `failure_rate="x"` mutation from the test.

- [ ] **Step 4: Docs.**
  - `snapshot-format.md` Compatibility list: one bullet: "`extensions.mcp_servers[]` exposure
    fields, `extensions.mcp_project_state`, `extensions.mcp_name_collisions` and
    `transcripts.tool_errors`: optional; names, counts, booleans, enums and OAuth scope tokens
    only; additive within snapshot v1."
  - `coverage.md` "MCP and plugins": a paragraph stating:
    - The exposure fields come from configuration text only. Locality needs no DNS, and nothing
      is connected, authenticated or executed.
    - URL path, query, userinfo, argument, env, header, `clientId` and `headersHelper` values are
      never copied.
    - Approvals, toggles, allow and deny policy, and permission rules are per-source
      observations, not effective state. `serverUrl`/`serverCommand` entries are counted, not
      evaluated.
    - The `~/.claude.json` `projects[...]` approval lists are an undocumented location observed
      on 2026-09-29. The toggles and `hasTrustDialogAccepted` are documented there.
    - `tool_prefix` uses the documented plugin normalization for every server.
    - Collisions compare origins only.
    - Documentation checked 2026-09-29: `mcp.md`, `managed-mcp.md`, `settings-reference.md`,
      `permissions.md`.

    Plus a short "Tool errors" paragraph:
    - Pairing is within a file, and only `is_error: true` counts.
    - Categories are heuristic text patterns observed 2026-09-29, and the text is not stored.
    - The dedup rule and the caps (15/15/3, rate from 5 calls).
    - The session-meta `tool_error_categories` remain separate and coarse.

- [ ] **Step 5: Run tests and the schema check**

Run: `python3 -m unittest discover -s tests && python3 tests/check_snapshot_schema.py`
Expected: PASS. The producer tests validate the real collector output against the new types.

- [ ] **Step 6: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/references/snapshot.schema.json plugins/setup-audit/skills/setup-audit/references/snapshot-format.md plugins/setup-audit/skills/setup-audit/references/coverage.md tests/test_snapshot_contract.py
git commit -m "Type MCP exposure and tool-error fields in the snapshot schema

Assisted-by: Claude:claude-opus-5-5"
```

---

### Task 5: Checklist, changelog, roadmap, gate and read-only smoke run

**Files:**
- Modify: `S/references/checklist.md`, `CHANGELOG.md` (`[Unreleased]`), `docs/roadmap.md`

- [ ] **Step 1: Re-verify doc quotes.**
  - Run `curl -sL https://code.claude.com/docs/en/mcp.md | grep -n "no \`type\`\|reserves the names\|can't show that prompt\|arbitrary shell command\|oauth.scopes"`.
  - Run `curl -sL https://code.claude.com/docs/en/managed-mcp.md | grep -n "not a security control\|broaden what your allowlist"`.
  - If any quoted sentence changed, stop and report the change instead of editing around it.

- [ ] **Step 2: `checklist.md`.** Under Security, after `SEC-mcp`, add:

```markdown
- **SEC-mcp-exposure** (`extensions.mcp_servers[]` exposure fields, `policy_observations`,
  `settings[].mcp_policy`; static, never connected). Weigh, citing field and source:
  - `headers_literal_keys` / `env_literal_keys` on a `project` server whose `file_git_status` is
    `tracked`: a committed credential is likely. Confirm on the file (never copy the value), then
    handle as `SEC-secret-literal`.
  - `url_has_userinfo` or `url_has_query` on a remote server: a credential may sit in the URL.
    Prefer headers with `${VAR}` references. Credential variables such as `ANTHROPIC_API_KEY` in a
    remote `url`/`headers` read as empty (mcp.md), so `url_variable_references` naming one means a
    broken server, not a leak.
  - `plaintext_transport`: tokens and tool traffic in cleartext to a non-loopback host.
    Recommendation-level; the docs do not rate it.
  - A `project` server with `approval_enable_all: true` or `approval_enabled`: any server a
    teammate adds to `.mcp.json` loads. In `claude -p`, SDK and cloud sessions, project servers
    load without asking (mcp.md). Propose `disabledMcpjsonServers` for unwanted ones. Committed
    approvals are ignored in an untrusted folder, so cite `project_trust_accepted`.
  - `headersHelper_configured` on a `project` server: a repo-supplied shell command that runs
    once the folder is trusted.
  - `permission_allow` (or `permission_allow_any_server`) on a server that writes to external
    systems: calls run without a prompt. `mcp__*` in allow is skipped by Claude Code; rule
    validity is reported by the permission-rule checks, not here.
  - Allowlist posture, once per audit and only in an organization context: `allowedMcpServers`
    without `allowManagedMcpServersOnly` merges user allowlists, and a `serverName` entry "is not
    a security control" (managed-mcp.md). `serverUrl`/`serverCommand` entries are not evaluated
    here, so never claim a server is unrestricted without checking them.
  - `oauth_scopes: null` on a sensitive remote service: suggest pinning `oauth.scopes`, the
    documented way to restrict a server.
  Cross-check reliability through `tool_prefix` = `transcripts.tool_errors.by_mcp_server[].server`.
```

Under Hygiene, add:

```markdown
- **HYG-mcp-config** (`config_notes`, `extensions.mcp_name_collisions`): `url_without_type`
  (Claude Code skips the server; add `"type": "http"`), `sdk_type_skipped`, `reserved_name`
  (skipped at load), `sse_deprecated` (switch to `http`), and the same name in several scopes with
  `endpoint_origins_differ: true` (OAuth sign-ins are stored per endpoint, so sign-in state differs
  between projects). `empty_url_placeholder` is a documented placeholder, not a finding.
```

Under Cost & context, after `COST-tool-errors`, add the following and change `COST-tool-errors`
to end with "Prefer `transcripts.tool_errors` (see `COST-tool-error-clusters`) when present.":

```markdown
- **COST-tool-error-clusters** (`transcripts.tool_errors`, measured; categories heuristic): cite
  `by_tool` and `by_mcp_server` counts, never error text (none is stored). Separate `denied`
  (permission prompts refused or rules denying) from failures; `failure_rate` already excludes
  them and is `null` under `min_calls_for_rate` calls.
  - An MCP server with `failure_rate` >= 0.2 over >= 20 calls and mostly `auth`/`connection`:
    fix authentication or configuration (`claude mcp get <name>` shows an `Issue:` line), or
    propose removal together with its `SEC-mcp-exposure` fields. The thresholds are a
    recommendation.
  - Bash `sandbox`: sandbox prerequisites (`SEC-sandbox`), not the commands.
  - `nonzero_exit` clusters: missing run or test commands (`RDY-test-loop`, CLAUDE.md).
  - `file_state` recurring: an edit-before-read habit; an `LRN-` pattern if it spans 3+ sessions.
  - `validation`: malformed tool calls; check for a tool or server whose schema confuses the model.
  `error_results_unmatched` and `results_without_is_error` bound the evidence; say so when large.
```

- [ ] **Step 3: `CHANGELOG.md` `[Unreleased]` → `### Added`:**
  - "MCP exposure metadata per server:
    - transport class, config notes, endpoint locality, cleartext and URL flags, literal key
      names, OAuth scopes, tool prefix and `.mcp.json` git status
    - per-source approval, toggle, policy and permission observations, and same-name collisions

    Nothing is connected or executed, and no values are stored. New checks `SEC-mcp-exposure`
    and `HYG-mcp-config`."
  - "`transcripts.tool_errors`: error counts, failure rates and heuristic categories per built-in
    tool and per MCP server, from `tool_use`/`tool_result` pairs; error text is not stored. New
    check `COST-tool-error-clusters`."

- [ ] **Step 4: `docs/roadmap.md`.** In "Deeper checks", mark "MCP exposure metadata and
  recurring tool-error clustering" implemented (unreleased). Record the follow-ups from the spec:
  a ledger tool-error source, a drift signal for MCP failure rate, and the plugin-server hook
  matcher check if 2A did not cover it.

- [ ] **Step 5: Gate.** Run the full suite, `python3 tests/check_snapshot_schema.py`,
  `git diff --check`, and coverage ≥ 88 (then `coverage erase`).

- [ ] **Step 6: Read-only smoke run** (the user allowed read-only smoke runs against the real
  home):
  - Run `python3 plugins/setup-audit/skills/setup-audit/scripts/collect.py --scope all --out "$TMPDIR/2b-smoke.json"`.
  - Then run `python3 plugins/setup-audit/skills/setup-audit/scripts/query_snapshot.py "$TMPDIR/2b-smoke.json" transcripts.tool_errors`
    (or `python3 -c` with `json.load`) and confirm:
    - `by_tool` and `by_mcp_server` are non-empty and capped.
    - Every `mcp_servers[]` item has `tool_prefix` and `transport_class`.
    - Neither `?` query strings nor `@` userinfo appear in any `endpoint_origin`.
  - Report counts only. Delete the file by explicit name (`rm "$TMPDIR/2b-smoke.json"`); never
    commit it or copy content into the repo.

- [ ] **Step 7: Commit**

```bash
git add plugins/setup-audit/skills/setup-audit/references/checklist.md CHANGELOG.md docs/roadmap.md
git commit -m "Document MCP exposure and tool-error cluster checks

Assisted-by: Claude:claude-opus-5-5"
```

## Final review (whole branch)

- `git diff main --stat` touches only:
  - `extensions.py`, `collect.py`
  - `snapshot.schema.json`, `snapshot-format.md`, `coverage.md`, `checklist.md`
  - `CHANGELOG.md`, `docs/roadmap.md`
  - `tests/test_mcp_exposure.py`, `tests/test_tool_errors.py`, `tests/test_snapshot_contract.py`
- No change to 2A's functions beyond the two added `summarize_settings` keys.
- Grep the diff for `urlsplit(` uses that return `path`/`query` values: none may be serialized.
