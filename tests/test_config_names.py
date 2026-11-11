"""config_names: the one names-only reader of credential-bearing configuration. Fake homes only."""
import ast
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


class MappingNames(unittest.TestCase):
    def test_mapping_names(self):
        got = config_names.mapping_names({'A': 'sk-canary', 'B': '${TOKEN_VAR}', 'C': ''})
        self.assertEqual(got, {'keys': ['A', 'B', 'C'], 'literal_keys': ['A'],
                               'variable_references': ['TOKEN_VAR']})
        self.assertNotIn('sk-canary', repr(got))

    def test_non_mapping_has_no_names(self):
        self.assertIsNone(config_names.mapping_names(['A=sk-canary']))
        self.assertIsNone(config_names.mapping_names(None))


class UserMcpServerNames(FakeHome):
    def test_non_object_claude_json_has_no_names(self):
        for data in ([1], 'text', 7, {'mcpServers': ['a']}):
            self.write('.claude.json', data)
            self.assertEqual(config_names.user_mcp_server_names(self.home), [], data)
        self.write('.claude.json', {'mcpServers': {'b': {}, 'a': {}}})
        self.assertEqual(config_names.user_mcp_server_names(self.home), ['a', 'b'])


class CanaryNeverLeaves(FakeHome):
    """A canary value in every credential-bearing source never leaves config_names or reaches the snapshot."""

    def test_canary_never_leaves_module(self):
        root = os.path.join(self.home, 'repo')
        server = {'type': 'http', 'url': f'https://mcp.example.com/p?k={CANARY}',
                  'env': {'MCP_ENV_NAME': CANARY, 'MCP_REF_NAME': '${MCP_VAR}'},
                  'headers': {'X-Mcp-Header': CANARY}, 'args': ['--key', CANARY],
                  'oauth': {'clientId': CANARY, 'scopes': 'read'}}
        self.write('.claude.json', {'mcpServers': {'usersrv': server},
                                    'projects': {root: {'mcpServers': {'localsrv': server},
                                                        'hasTrustDialogAccepted': True}}})
        self.write('repo/.mcp.json', {'mcpServers': {'projectsrv': server}})
        hook = {'type': 'http', 'url': 'https://hooks.example.com/h', 'headers': {'X-Hook-Header': CANARY}}
        settings = {'env': {'SETTINGS_ENV_NAME': CANARY},
                    'hooks': {'Stop': [{'hooks': [hook]}]}}
        self.write('.claude/settings.json', settings)
        self.write('repo/.claude/settings.json', settings)
        self.write('repo/.envrc', f'export ENVRC_API_KEY={CANARY}-long-enough\nexport PLAIN_NAME={CANARY}\n')
        managed_dir = os.path.join(self.home, 'managed')
        self.write('managed/managed-mcp.json', {'mcpServers': {'managedsrv': server}})
        plugin_root = os.path.join(self.claude, 'plugins/cache/market/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'demo@market': [{'scope': 'user', 'installPath': plugin_root, 'version': '1'}]}})
        self.write('.claude/plugins/cache/market/demo/1/.claude-plugin/plugin.json',
                   {'name': 'demo', 'mcpServers': {'inlinesrv': server}})
        self.write('.claude/plugins/cache/market/demo/1/.mcp.json', {'pluginfilesrv': server})

        returns = [config_names.mapping_names(server['env']), config_names.mapping_names(server['headers']),
                   config_names.server_facts(server), config_names.user_mcp_state(self.home),
                   config_names.user_mcp_server_names(self.home), config_names.settings_env_names(settings),
                   config_names.hook_header_names(hook), config_names.envrc_names(root)]
        for value in returns:
            self.assertNotIn(CANARY, repr(value))
        # Not vacuous: the names did come through.
        self.assertIn('MCP_ENV_NAME', repr(returns[3]))
        self.assertIn('ENVRC_API_KEY', repr(returns[-1]))

        returns.append(config_names.server_map({'mcpServers': {'managedsrv': server}}))
        returns.append(config_names.hook_handler_view(hook))
        for value in returns[-2:]:
            self.assertNotIn(CANARY, repr(value))

        with mock.patch.object(collect, 'managed_directory', lambda: managed_dir):
            snap = json.dumps(collect.build_snapshot(parsed('--claude-dir', self.claude, '--roots', root)))
        self.assertNotIn(CANARY, snap)
        for name in ('MCP_ENV_NAME', 'X-Mcp-Header', 'SETTINGS_ENV_NAME', 'X-Hook-Header', 'ENVRC_API_KEY',
                     'usersrv', 'localsrv', 'projectsrv', 'managedsrv', 'inlinesrv', 'pluginfilesrv'):
            self.assertIn(name, snap)


# Static guard. Heuristic (line-based regexes over every scripts/*.py except config_names.py):
#   1. a string literal ending in '.claude.json' or '.envrc' ("~/.claude.json", f"{home}/.envrc", ...) passed to a path/read call: os.path.join, open,
#      Path, any *load*/*read* function (load_json, json_object, read_text, _read, ...), or a
#      pathlib "/ '.claude.json'" join. Mentions elsewhere (classification tables such as
#      cache_effects' file-name rows, git_status(root, '.envrc'), comments, source labels) pass.
#   2. subscripting or .get() with the literal key 'env' or 'headers' (["env"], .get('headers'), ...).
#   3. a loop over a literal tuple/list that starts with 'env' or 'headers' (for key in ('env', ...)),
#      the shape the pre-0.13.1 extensions.py used to read both mappings.
# Comment lines are skipped. The guard targets reads, so it cannot see a read written through a
# variable key; it pins the known shapes and keeps reviewers pointed at config_names.py.
SENSITIVE_FILE = r"""['"][^'"\n]*(?:\.claude\.json|\.envrc)['"]"""
GUARD_PATTERNS = (
    re.compile(r'(?:\bjoin|\bopen|\bPath|\w*(?:load|read)\w*|json_object)\([^#]*' + SENSITIVE_FILE),
    re.compile(r'/\s*' + SENSITIVE_FILE),
    re.compile(r"""(?:\.get\(\s*|\[\s*)['"](?:env|headers)['"]"""),
    re.compile(r"""\bfor\s+\w+\s+in\s+[(\[]\s*['"](?:env|headers)['"]"""),
)


def guard_violations(scripts_dir):
    hits = []
    for name in sorted(os.listdir(scripts_dir)):
        if not name.endswith('.py') or name == 'config_names.py':
            continue
        with open(os.path.join(scripts_dir, name)) as f:
            for number, line in enumerate(f, 1):
                if line.lstrip().startswith('#'):
                    continue
                if any(p.search(line) for p in GUARD_PATTERNS):
                    hits.append(f'{name}:{number}: {line.strip()}')
    return hits


class OnlyModuleReadsSensitiveSources(unittest.TestCase):
    def test_only_module_reads_sensitive_sources(self):
        self.assertEqual(guard_violations(os.path.abspath(SCRIPTS)), [])

    def test_guard_catches_known_read_shapes(self):
        shapes = ("user = load_json(os.path.join(HOME, '.claude.json'))",
                  'text = _read(root, ".envrc")',
                  "p = Path(home) / '.claude.json'",
                  'headers = x.get("headers")',
                  "env = data['env']",
                  "for key in ('env', 'headers'):",
                  'data = load_json(os.path.expanduser("~/.claude.json"))',
                  'f = open(f"{home}/.claude.json")',
                  "text = Path(root, 'sub/.envrc').read_text()")
        allowed = ("if base in ('.mcp.json', '.claude.json'):",
                   '"git": git_status(root, ".envrc")}',
                   'sources.append(".envrc")',
                   "'http': frozenset({'url', 'headers', 'allowedEnvVars'}),")
        for line in shapes:
            self.assertTrue(any(p.search(line) for p in GUARD_PATTERNS), line)
        for line in allowed:
            self.assertFalse(any(p.search(line) for p in GUARD_PATTERNS), line)


# AST guard (ported from 0.14.0, now with the names-only reader excepted): a string constant naming a
# credential-bearing file is flagged when it is an argument of a call that opens or loads a file, when
# it is assigned in a scope that makes such a call, or when a module-level constant holding it is
# passed to such a call. Classification tables, os.stat / git_status calls and docstrings pass.
OPENERS = {'open', 'read_json_object', 'json_object', 'load_json', 'read_text', 'read_bytes', '_read', 'load'}
# file name -> the only scripts allowed to open it (empty: none may)
OPEN_ALLOWED = {'.claude.json': {'config_names.py'}, '.envrc': {'config_names.py'}, '.credentials.json': set(),
                '.mcp.json': {'extensions.py', 'collect.py'}, 'managed-mcp.json': {'extensions.py'}}
KEYCHAIN_SHAPES = ('security find-generic-password', 'find-generic-password', 'find-internet-password',
                   'secret-tool', 'keyring', 'libsecret', 'gnome-keyring', 'kwallet')


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


def _named(root, names, docs=()):
    return [n for n in ast.walk(root) if isinstance(n, ast.Constant) and isinstance(n.value, str)
            and id(n) not in docs and any(n.value.endswith(s) for s in names)]


def file_opens(tree, names):
    """Line numbers where the tree opens a file whose name ends in one of ``names``."""
    hits = []
    for nodes in _scopes(tree):
        docs = {id(n.value) for n in nodes if isinstance(n, ast.Expr)}  # docstrings and bare strings
        calls = [n for n in nodes if isinstance(n, ast.Call) and _call_name(n) in OPENERS]
        for call in calls:
            hits += [c.lineno for arg in [*call.args, *(k.value for k in call.keywords)]
                     for c in _named(arg, names, docs)]
        if calls:
            hits += [c.lineno for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
                     for c in _named(n.value, names, docs)]
    constants = {t.id for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign)) and n.value is not None
                 and _named(n.value, names) for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
                 if isinstance(t, ast.Name)}
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_name(n) in OPENERS):
        hits += [x.lineno for arg in [*call.args, *(k.value for k in call.keywords)]
                 for x in ast.walk(arg) if isinstance(x, ast.Name) and x.id in constants]
    return hits


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


class OnlyNamedModulesOpenCredentialFiles(unittest.TestCase):
    """Rule: ~/.claude.json and .envrc are opened only by config_names.py, MCP config files only by
    the inventory loaders, ~/.claude/.credentials.json and the OS keychain by no script."""

    def test_only_allowed_scripts_open_credential_bearing_files(self):
        for name, tree in shipped_trees():
            for target, allowed in OPEN_ALLOWED.items():
                if name not in allowed:
                    self.assertEqual(file_opens(tree, (target,)), [], f'{name} opens {target}')

    def test_not_vacuous_the_allowed_readers_do_open_them(self):
        trees = dict(shipped_trees())
        self.assertTrue(file_opens(trees['config_names.py'], ('.claude.json',)))
        self.assertTrue(file_opens(trees['config_names.py'], ('.envrc',)))
        self.assertTrue(file_opens(trees['extensions.py'], ('.mcp.json',)))

    def test_open_guard_catches_known_shapes(self):
        names = tuple(OPEN_ALLOWED)
        for code in ("def f(home):\n    return load_json(os.path.join(home, '.claude.json'))",
                     "def f(root):\n    p = root + '/.envrc'\n    with open(p) as h:\n        return h.read()",
                     "def f(home):\n    return read_json_object(f'{home}/.claude.json')",
                     "P = '.envrc'\ntext = Path(P).read_text()",
                     "CJ = '.claude.json'\ndef f(home):\n    return load_json(os.path.join(home, CJ))",
                     "def f(home):\n    return load_json(os.path.join(home, '.claude', '.credentials.json'))"):
            self.assertTrue(file_opens(ast.parse(code), names), code)
        for code in ("def f(root):\n    return os.path.isfile(os.path.join(root, '.envrc'))",
                     "def f(root):\n    return git_status(root, '.envrc')",
                     "NAMES = ('.mcp.json', '.claude.json')\ndef f(base):\n    return base in NAMES"):
            self.assertFalse(file_opens(ast.parse(code), names), code)

    def test_no_script_uses_the_keychain(self):
        for name, tree in shipped_trees():
            self.assertEqual(keychain_uses(tree), [], name)

    def test_keychain_guard_catches_known_shapes(self):
        for code in ("subprocess.run(['security', 'find-generic-password', '-s', 'x'])",
                     "subprocess.run(['secret-tool', 'lookup', 'a', 'b'])",
                     "import keyring", "from keyring import get_password"):
            self.assertTrue(keychain_uses(ast.parse(code)), code)
        self.assertFalse(keychain_uses(ast.parse('"""Never calls secret-tool."""\nx = 1')))


class DocsBoundaryRule(unittest.TestCase):
    """SKILL.md carries the never-open rule for Claude's own reads; only the collector reads names-only."""
    SKILL = os.path.join(os.path.dirname(SCRIPTS), 'SKILL.md')

    def bullets(self, start):
        with open(self.SKILL, encoding='utf-8') as f:
            text = f.read()
        section = text[text.index('\n## Boundaries'):]
        found = [' '.join(b.split()) for b in re.split(r'\n- ', section) if b.lstrip().startswith(start)]
        self.assertEqual(len(found), 1, f'Boundaries must hold one "{start}" rule')
        return found[0]

    def test_never_open_rule_lists_the_files_and_keys(self):
        bullet = self.bullets('Never open')
        for item in ('~/.claude.json', '~/.claude/.credentials.json', '.envrc', '.env.*', 'devcontainer', 'compose',
                     'mise', 'MCP config files', 'OS keychain', '`env`', '`headers`', '`oauth`', '`apiKeyHelper`',
                     'helper-command', 'names-only', '`scripts/config_names.py`', '`claude mcp list`',
                     'never run `claude mcp get`'):
            self.assertIn(item, bullet)

    def test_secret_backend_probe_asks_every_run_and_prints_no_value(self):
        bullet = self.bullets('`RDY-env-secret-backend`')
        for item in ('every run', 'ask the user in that run', 'set or unset', 'never prints'):
            self.assertIn(item, bullet)

    def test_docs_never_tell_claude_to_run_mcp_get(self):
        refs = os.path.join(os.path.dirname(SCRIPTS), 'references')
        for name in os.listdir(refs):
            if name.endswith('.md'):
                with open(os.path.join(refs, name), encoding='utf-8') as f:
                    text = ' '.join(f.read().split())
                for m in re.finditer(r'claude mcp get', text):
                    self.assertRegex(text[m.start():m.start() + 160], r'themselves|Claude never runs', name)


class HookEntryNeverUsesHeaderValues(unittest.TestCase):
    """Rule (ported from 0.14.0): nothing in a hook entry derives from an http hook's header values."""

    def entry(self, headers):
        handler = {'type': 'http', 'url': 'https://hooks.example.com/h', 'headers': headers}
        return collect.hook_handler_entry('Stop', None, handler)

    def test_entry_is_identical_whatever_the_header_values(self):
        base = self.entry({'Authorization': 'x'})
        for value in ('Bearer ${CLAUDE_PLUGIN_TOKEN}', CANARY, ''):
            self.assertEqual(self.entry({'Authorization': value}), base, value)
        self.assertNotIn('plugin_relative', base)
        self.assertEqual(base['header_keys'], ['Authorization'])

    def test_plugin_relative_still_comes_from_other_fields(self):
        handler = {'type': 'http', 'url': 'https://h.example.com/${CLAUDE_PLUGIN_ROOT}/x'}
        self.assertIs(collect.hook_handler_entry('Stop', None, handler)['plugin_relative'], True)


class HookFingerprintHasNoHeaderValues(unittest.TestCase):
    """Rule: an http hook fingerprint depends on header names, never on header values."""

    def handler(self, headers):
        return {'type': 'http', 'url': 'https://hooks.example.com/h', 'timeout': 5, 'headers': headers}

    def test_header_value_never_changes_fingerprint(self):
        fp = config_checks.handler_fingerprint
        base = fp('Stop', None, self.handler({'Authorization': 'Bearer one', 'X-Id': 'a'}))
        for value in ('Bearer two', CANARY, '', '${TOKEN}'):
            self.assertEqual(fp('Stop', None, self.handler({'Authorization': value, 'X-Id': 'a'})), base, value)
        self.assertNotEqual(fp('Stop', None, self.handler({'X-Other': 'Bearer one', 'X-Id': 'a'})), base)
        self.assertNotEqual(fp('Stop', None, self.handler({'Authorization': 'Bearer one'})), base)

    def test_fingerprint_hashes_the_names_only_view(self):
        handler = self.handler({'B': CANARY, 'A': CANARY})
        self.assertEqual(config_names.hook_handler_view(handler)['headers'], ['A', 'B'])
        config_checks.handler_fingerprint('Stop', None, handler)
        self.assertEqual(handler['headers'], {'B': CANARY, 'A': CANARY})  # caller's handler untouched


if __name__ == '__main__':
    unittest.main()
