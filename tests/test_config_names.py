"""config_names and the rule behind it: the audit reads no credential-bearing file or value. Fake homes only."""
import ast
import io
import json
import os
import re
import unittest
from unittest import mock
from test_collect import FakeHome, SCRIPTS, collect
from test_drift import parsed
import config_checks
import config_names

CANARY = 'CANARY-9f3e'
CANARY_NAME = 'CANARY_NAME'
HELPER_KEYS = ('apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'otelHeadersHelper', 'gcpAuthRefresh')

# Heuristic for test_no_script_opens_credential_files (AST, every shipped scripts/*.py, none excepted):
# a string constant naming ~/.claude.json or .envrc is flagged when it is an argument of a call that
# opens or loads a file (open, os.open, read_json_object, json_object, load_json, read_text,
# read_bytes, _read, json.load), or when it is assigned to a variable in a scope that makes such a
# call. Constants used for classification, os.stat / git_status calls, messages and docstrings pass.
SENSITIVE_NAMES = ('.claude.json', '.envrc', '.credentials.json')
OPENERS = {'open', 'read_json_object', 'json_object', 'load_json', 'read_text', 'read_bytes', '_read', 'load'}


def _call_name(node):
    func = node.func
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ''


def _scopes(tree):
    """Node lists to inspect: the module body without its functions, then each function whole."""
    yield [n for top in tree.body if not isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef))
           for n in ast.walk(top)]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield list(ast.walk(node))


def shipped_trees():
    for name in sorted(os.listdir(SCRIPTS)):
        if name.endswith('.py'):
            with open(os.path.join(SCRIPTS, name)) as f:
                yield name, ast.parse(f.read())


def _sensitive_constants(root, docs=()):
    return [n for n in ast.walk(root) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docs and any(s in n.value for s in SENSITIVE_NAMES)]


def credential_file_opens(tree):
    hits = []
    for nodes in _scopes(tree):
        docs = {id(n.value) for n in nodes if isinstance(n, ast.Expr)}  # docstrings and bare strings
        calls = [n for n in nodes if isinstance(n, ast.Call) and _call_name(n) in OPENERS]
        for call in calls:  # the name is passed straight to the call
            hits += [c.lineno for arg in [*call.args, *(k.value for k in call.keywords)]
                     for c in _sensitive_constants(arg, docs)]
        if calls:  # the name is built into a variable that the same scope may then open
            hits += [c.lineno for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
                     for c in _sensitive_constants(n.value, docs)]
    # a module-level constant holding the name, referenced inside any opener call's arguments
    constants = {t.id for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
                 and _sensitive_constants(n.value) for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
                 if isinstance(t, ast.Name)}
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_name(n) in OPENERS):
        hits += [x.lineno for arg in [*call.args, *(k.value for k in call.keywords)]
                 for x in ast.walk(arg) if isinstance(x, ast.Name) and x.id in constants]
    return hits


CREDENTIAL_KEYS = ('env', 'headers', 'oauth', 'credentials', *HELPER_KEYS)
KEYCHAIN_SHAPES = ('security find-generic-password', 'find-generic-password', 'find-internet-password',
                   'secret-tool', 'keyring', 'libsecret', 'gnome-keyring', 'kwallet')


def keychain_uses(tree):
    """Imports of a keyring library, or string constants naming a keychain command (not docstrings)."""
    docs = {id(n.value) for n in ast.walk(tree) if isinstance(n, ast.Expr)}
    hits = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            hits += [n.lineno for a in n.names if a.name.split('.')[0] == 'keyring']
        elif isinstance(n, ast.ImportFrom) and (n.module or '').split('.')[0] == 'keyring':
            hits.append(n.lineno)
        elif (isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs
              and any(s in n.value for s in KEYCHAIN_SHAPES)):
            hits.append(n.lineno)
    return hits


def credential_value_reads(tree):
    hits = []
    allowed = {id(n) for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
               and f.name == 'documented_env_set'
               for n in ast.walk(f)}
    for node in ast.walk(tree):
        if id(node) in allowed:
            continue
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and node.slice.value in CREDENTIAL_KEYS:
            hits.append(node.lineno)
        elif (isinstance(node, ast.Call) and _call_name(node) == 'get' and node.args
              and isinstance(node.args[0], ast.Constant) and node.args[0].value in CREDENTIAL_KEYS):
            hits.append(node.lineno)
        elif (isinstance(node, ast.Name) and node.id == 'mapping_names') or (
                isinstance(node, ast.Attribute) and node.attr == 'mapping_names'):
            hits.append(node.lineno)
    return hits


class StaticGuards(unittest.TestCase):
    def test_no_script_opens_credential_files(self):
        for name, tree in shipped_trees():
            self.assertEqual(credential_file_opens(tree), [], name)

    def test_open_guard_catches_known_shapes(self):
        for code in ("def f(home):\n    return load_json(os.path.join(home, '.claude.json'))",
                     "def f(root):\n    p = root + '/.envrc'\n    with open(p) as h:\n        return h.read()",
                     "def f(home):\n    return read_json_object(f'{home}/.claude.json')",
                     "P = '.envrc'\ntext = Path(P).read_text()",
                     "CJ = '.claude.json'\ndef f(home):\n    return load_json(os.path.join(home, CJ))"):
            self.assertTrue(credential_file_opens(ast.parse(code)), code)
        for code in ("def f(root):\n    return os.path.isfile(os.path.join(root, '.envrc'))",
                     "def f(root):\n    return git_status(root, '.envrc')",
                     "NAMES = ('.mcp.json', '.claude.json')\ndef f(base):\n    return base in NAMES"):
            self.assertFalse(credential_file_opens(ast.parse(code)), code)

    def test_open_guard_catches_credentials_file_and_keychain_shapes(self):
        for code in ("def f(home):\n    return load_json(os.path.join(home, '.claude', '.credentials.json'))",
                     "P = '.credentials.json'\ntext = Path(P).read_text()"):
            self.assertTrue(credential_file_opens(ast.parse(code)), code)
        for code in ("subprocess.run(['security', 'find-generic-password', '-s', 'x'])",
                     "subprocess.run(['secret-tool', 'lookup', 'a', 'b'])",
                     "import keyring", "from keyring import get_password"):
            self.assertTrue(keychain_uses(ast.parse(code)), code)
        self.assertFalse(keychain_uses(ast.parse('"""Never calls secret-tool."""\nx = 1')))

    def test_no_script_uses_the_keychain(self):
        for name, tree in shipped_trees():
            self.assertEqual(keychain_uses(tree), [], name)

    def test_no_script_reads_credential_values(self):
        for name, tree in shipped_trees():
            self.assertEqual(credential_value_reads(tree), [], name)

    def test_value_guard_catches_known_shapes(self):
        for code in ("x = d.get('env')", 'x = d.get("headers")', "x = d['env']", 'x = d["headers"]',
                     "x = d.get('oauth')", "x = d['oauth']", "x = d.get('apiKeyHelper')",
                     "x = sb['credentials']", "x = d.get('awsAuthRefresh')", "mapping_names(d)", "config_names.mapping_names(d)"):
            self.assertTrue(credential_value_reads(ast.parse(code)), code)
        for code in ("x = d.get('envrc')", "x = d['headersHelper']", "KEYS = ('env', 'headers')"):
            self.assertFalse(credential_value_reads(ast.parse(code)), code)


class DocsBoundaryRule(unittest.TestCase):
    """SKILL.md carries the never-open rule for Claude's own reads (the fallback path has no collector)."""
    SKILL = os.path.join(os.path.dirname(SCRIPTS), 'SKILL.md')

    def boundary_bullet(self):
        with open(self.SKILL, encoding='utf-8') as f:
            text = f.read()
        section = text[text.index('\n## Boundaries'):]
        bullets = [b for b in re.split(r'\n- ', section) if b.lstrip().startswith('Never open')]
        self.assertEqual(len(bullets), 1, 'Boundaries must hold one "Never open" rule')
        return ' '.join(bullets[0].split())

    def test_never_open_rule_lists_the_files_and_keys(self):
        bullet = self.boundary_bullet()
        for item in ('~/.claude.json', '~/.claude/.credentials.json', '.envrc', '.env.*', 'devcontainer', 'compose',
                     'mise', 'OS keychain', '`env`', '`headers`', '`oauth`', 'any helper-command setting',
                     'API-key, cloud-auth and telemetry-header helpers', '`claude mcp get`'):
            self.assertIn(item, bullet)

    def test_never_open_rule_describes_helpers_by_family_not_key_name(self):
        with open(self.SKILL, encoding='utf-8') as f:
            text = f.read()
        for key in HELPER_KEYS:
            self.assertNotIn(key, text)

    def test_docs_never_tell_claude_to_run_mcp_get_or_probe_secrets(self):
        refs = os.path.join(os.path.dirname(SCRIPTS), 'references')
        for name in os.listdir(refs):
            if name.endswith('.md'):
                with open(os.path.join(refs, name), encoding='utf-8') as f:
                    text = ' '.join(f.read().split())
                self.assertNotIn('RDY-env-secret-backend', text, name)
                for m in re.finditer(r'claude mcp get', text):
                    self.assertRegex(text[m.start():m.start() + 160], r'themselves|Claude never runs', name)


class FakeHomeCanary(FakeHome):
    def build(self):
        root = os.path.join(self.home, 'repo')
        server = {'type': 'http', 'url': 'https://mcp.example.com/p', 'oauth': {'clientId': CANARY},
                  'env': {CANARY_NAME: CANARY}, 'headers': {CANARY_NAME: CANARY}}
        self.write('.claude.json', {'mcpServers': {'usersrv': server},
                                    'projects': {root: {'mcpServers': {'localsrv': server},
                                                        'hasTrustDialogAccepted': True}}})
        self.write('repo/.mcp.json', {'mcpServers': {'projectsrv': server}})
        hook = {'type': 'http', 'url': 'https://hooks.example.com/h', 'headers': {CANARY_NAME: CANARY},
                'allowedEnvVars': [CANARY_NAME]}
        settings = {'env': {CANARY_NAME: CANARY, 'CLAUDE_CODE_SUBAGENT_MODEL': CANARY, 'HOME': CANARY},
                    'hooks': {'Stop': [{'hooks': [hook]}]},
                    'sandbox': {'enabled': True, 'credentials': {
                        'envVars': [{'name': CANARY_NAME, 'mode': 'mask'}],
                        'files': [{'path': f'~/{CANARY}/hosts.yml', 'mode': 'deny'}]}}}
        for key in HELPER_KEYS:
            settings[key] = f'cat /home/{CANARY}/{key}'
        for helper in ('apiKeyHelper', 'otelHeadersHelper'):
            self.assertIn(helper, settings)
        self.write('.claude/settings.json', settings)
        self.write('repo/.claude/settings.json', settings)
        self.write('repo/mise.toml', f'[env]\n{CANARY_NAME} = "{CANARY}"\n')
        self.write('repo/.devcontainer/devcontainer.json', json.dumps({'containerEnv': {CANARY_NAME: CANARY}}))
        self.write('repo/docker-compose.yml', f'services:\n  a:\n    environment:\n      - {CANARY_NAME}={CANARY}\n')
        self.write('repo/.envrc', f'export {CANARY_NAME}={CANARY}-long-enough\nuse_pass CANARY_PASS x\n')
        return root, server, hook, settings

    def test_fake_home_canary(self):
        root, *_ = self.build()
        opened = []
        real_open, real_os_open = open, os.open

        def spy_open(file, *args, **kwargs):
            opened.append(str(file))
            return real_open(file, *args, **kwargs)

        def spy_os_open(path, *args, **kwargs):
            opened.append(str(path))
            return real_os_open(path, *args, **kwargs)

        with mock.patch('builtins.open', spy_open), mock.patch.object(io, 'open', spy_open), \
                mock.patch('os.open', spy_os_open):
            snap = json.dumps(collect.build_snapshot(parsed('--claude-dir', self.claude, '--roots', root)))
        self.assertFalse([p for p in opened if p.endswith(
            ('.claude.json', '.envrc', 'mise.toml', 'devcontainer.json', 'docker-compose.yml'))])
        self.assertTrue(any(p.endswith('.mcp.json') for p in opened))  # not vacuous: other configs are read
        for text in (CANARY, CANARY_NAME, 'CANARY_PASS', 'usersrv', 'localsrv'):
            self.assertNotIn(text, snap)
        self.assertIn('projectsrv', snap)

    def test_settings_sandbox_credentials_are_dropped_and_helpers_presence_only(self):
        root, *_ = self.build()
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--roots', root))
        text = json.dumps(snap)
        self.assertNotIn(CANARY, text)
        self.assertNotIn(CANARY_NAME, text)
        found = [s for s in snap['global']['settings'] if 'sandbox' in s]
        found += [s for p in snap['projects'].values() for s in p.get('settings', []) if 'sandbox' in s]
        self.assertGreaterEqual(len(found), 2)
        for s in found:
            self.assertNotIn('sandbox_credentials_configured', s)  # 0.14.4: not even presence
            self.assertEqual(s['sandbox'], {'enabled': True})
            self.assertTrue(set(HELPER_KEYS) <= set(s['keys']))  # key presence is allowed, values are not
        entry = next(iter(snap['readiness'].values()))
        self.assertEqual(entry['env']['env_files_not_read'],
                         ['mise.toml', '.devcontainer/devcontainer.json', 'docker-compose.yml'])

    def test_helpers_return_no_canary(self):
        _, server, hook, settings = self.build()
        for value in (config_names.server_facts(server), config_names.server_map({'mcpServers': {'a': server}}),
                      config_names.hook_handler_view(hook), config_names.documented_env_set(settings, ['CLAUDE_CODE_SUBAGENT_MODEL'])):
            self.assertNotIn(CANARY, repr(value))
            self.assertNotIn(CANARY_NAME, repr(value))
        self.assertEqual(config_names.server_facts(server)['configured_mechanisms'], ['oauth'])

    def test_envrc_presence_only(self):
        root, *_ = self.build()
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--roots', root))
        entry = next(iter(snap['readiness'].values()))
        self.assertEqual(set(entry['envrc']), {'present', 'git'})
        self.assertIs(entry['envrc']['present'], True)
        self.assertIs(entry['env']['envrc_not_read'], True)
        self.assertNotIn('.envrc', entry['env']['declared_via'])
        os.remove(os.path.join(root, '.envrc'))
        snap = collect.build_snapshot(parsed('--claude-dir', self.claude, '--roots', root))
        entry = next(iter(snap['readiness'].values()))
        self.assertIsNone(entry['envrc'])
        self.assertNotIn('envrc_not_read', entry['env'])


class DocumentedEnvSet(unittest.TestCase):
    def test_documented_env_set(self):
        settings = {'env': {'B': '1', 'A': '2', 'OTHER': CANARY}}
        self.assertEqual(config_names.documented_env_set(settings, ['A', 'B', 'C']), ['A', 'B'])
        self.assertEqual(config_names.documented_env_set(settings, iter(['OTHER'])), ['OTHER'])
        for bad in ({}, {'env': ['A']}, {'env': None}, None, 'text'):
            self.assertEqual(config_names.documented_env_set(bad, ['A']), [])


class HookFingerprintHasNoCredentialFields(unittest.TestCase):
    """Rule: an http hook fingerprint depends on neither headers nor allowedEnvVars."""

    def handler(self, **extra):
        return {'type': 'http', 'url': 'https://hooks.example.com/h', 'timeout': 5, **extra}

    def test_header_and_env_var_fields_never_change_fingerprint(self):
        fp = config_checks.handler_fingerprint
        base = fp('Stop', None, self.handler())
        for extra in ({'headers': {'A': CANARY}}, {'headers': {'B': ''}}, {'allowedEnvVars': [CANARY_NAME]},
                      {'headers': ['x'], 'allowedEnvVars': 7}):
            self.assertEqual(fp('Stop', None, self.handler(**extra)), base, extra)
        self.assertNotEqual(fp('Stop', None, self.handler(timeout=6)), base)

    def test_view_drops_the_fields_and_leaves_the_handler(self):
        handler = self.handler(headers={'B': CANARY}, allowedEnvVars=[CANARY_NAME])
        self.assertEqual(config_names.hook_handler_view(handler), self.handler())
        self.assertIn('headers', handler)


class HookEntryIgnoresCredentialFields(unittest.TestCase):
    """Rule: nothing in a hook entry derives from an http hook's headers or allowedEnvVars."""

    def entry(self, **extra):
        handler = {'type': 'http', 'url': 'https://hooks.example.com/h', **extra}
        return collect.hook_handler_entry('Stop', None, handler)

    def test_entry_is_identical_with_and_without_credential_fields(self):
        base = self.entry()
        for extra in ({'headers': {'Authorization': 'Bearer ${CLAUDE_PLUGIN_TOKEN}'}},
                      {'allowedEnvVars': ['CLAUDE_PLUGIN_ROOT']},
                      {'headers': {CANARY_NAME: CANARY}, 'allowedEnvVars': [CANARY_NAME]}):
            self.assertEqual(self.entry(**extra), base, extra)
        self.assertNotIn('plugin_relative', base)

    def test_plugin_relative_still_comes_from_other_fields(self):
        handler = {'type': 'http', 'url': 'https://h.example.com/${CLAUDE_PLUGIN_ROOT}/x'}
        self.assertIs(collect.hook_handler_entry('Stop', None, handler)['plugin_relative'], True)


if __name__ == '__main__':
    unittest.main()

