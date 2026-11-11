import ast
import contextlib
import io
import json
import os
import re
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/setup-audit'
ICON = PLUGIN / '.claude-plugin/icon.png'

from test_collect import FakeHome, collect  # noqa: E402  (puts the scripts on sys.path)
import config_names  # noqa: E402
from unittest import mock  # noqa: E402

# Plugin directory rule (claude.com/docs/plugins/pre-submission-checklist, fetched 2026-10-27): a
# bundled image referenced from the plugin is held for a reviewer.
IMAGE_OR_FONT_PATH = re.compile(r'\.(png|jpe?g|gif|webp|woff2?|ttf|otf|ico)\b', re.I)
SCRIPTS = PLUGIN / 'skills/setup-audit/scripts'

# Stdlib modules that can open a connection (or load one by name); urllib.parse only parses URLs.
NETWORK_MODULES = ('socket', 'socketserver', 'ssl', 'http', 'urllib.request', 'urllib.error', 'ftplib',
                   'smtplib', 'imaplib', 'poplib', 'nntplib', 'telnetlib', 'xmlrpc', 'asyncio',
                   'webbrowser', 'importlib')
# The one script allowed to make a network request, and the one host it may reach.
NETWORK_SCRIPT = 'fetch_doc.py'
DOCS_HOST = 'code.claude.com'
URL_HOST = re.compile(r'[a-z][a-z0-9+.-]*://[^/\s"\'<>]*', re.I)


def imported_modules(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == 'urllib':
                yield from ('urllib.' + a.name for a in node.names)
            else:
                yield node.module
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '__import__'
              and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            yield node.args[0].value


def network_modules(tree):
    return sorted(m for m in imported_modules(tree)
                  if any(m == n or m.startswith(n + '.') for n in NETWORK_MODULES))


SPAWNERS = {'subprocess': {'run', 'Popen', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput'},
            'os': {'system', 'popen', 'execl', 'execle', 'execlp', 'execlpe', 'execv', 'execve', 'execvp',
                   'execvpe', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe', 'spawnv', 'spawnve', 'spawnvp',
                   'spawnvpe', 'posix_spawn', 'posix_spawnp', 'startfile'},
            'asyncio': {'create_subprocess_exec', 'create_subprocess_shell'},
            'pty': {'spawn'}}
# The one documented exception: rate_limit_log.py runs the status-line command the user wrote after
# `--` in their own statusLine setting (plugin README "Runs"), passed through as an argv list.
SPAWN_ALLOWANCES = {('rate_limit_log.py', 'command')}


def spawn_problems(name, tree):
    """Process launches in a script that do not run a literal `git` argv (empty when all do)."""
    aliases = {}  # local name -> module, for `from subprocess import run` and `import subprocess as sp`
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module in SPAWNERS:
            aliases.update({(a.asname or a.name): n.module for a in n.names if a.name in SPAWNERS[n.module]})
        elif isinstance(n, ast.Import):
            aliases.update({(a.asname or a.name): a.name for a in n.names if a.name in SPAWNERS})
    problems = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and aliases.get(f.value.id, f.value.id) in SPAWNERS \
                and f.attr in SPAWNERS[aliases.get(f.value.id, f.value.id)]:
            module, func = aliases.get(f.value.id, f.value.id), f.attr
        elif isinstance(f, ast.Name) and f.id in aliases and aliases[f.id] in SPAWNERS and f.id in SPAWNERS[aliases[f.id]]:
            module, func = aliases[f.id], f.id
        else:
            continue
        where = f'line {n.lineno}: {module}.{func}'
        if module != 'subprocess' or func not in ('run', 'Popen', 'call', 'check_call', 'check_output'):
            problems.append(where + ' is never allowed')
            continue
        if any(k.arg == 'shell' for k in n.keywords):
            problems.append(where + ' passes shell=')
            continue
        argv = n.args[0] if n.args else next((k.value for k in n.keywords if k.arg == 'args'), None)
        if isinstance(argv, ast.Name) and (name, argv.id) in SPAWN_ALLOWANCES:
            continue
        if not (isinstance(argv, (ast.List, ast.Tuple)) and argv.elts and isinstance(argv.elts[0], ast.Constant)
                and argv.elts[0].value == 'git'):
            problems.append(where + ' does not run a literal git argv')
    return problems


def host_problems(tree):
    """Why fetch_doc.py could reach a host other than DOCS_HOST (empty when it can't)."""
    problems = []
    consts = {t.id: n.value.value for n in tree.body if isinstance(n, ast.Assign)
              and isinstance(n.value, ast.Constant) for t in n.targets if isinstance(t, ast.Name)}
    if consts.get('HOST') != DOCS_HOST:
        problems.append(f'HOST is {consts.get("HOST")!r}')
    if consts.get('BASE') != f'https://{DOCS_HOST}/docs/':
        problems.append(f'BASE is {consts.get("BASE")!r}')
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ('HOST', 'BASE') for t in n.targets) \
                and not isinstance(n.value, ast.Constant):
            problems.append(f'line {n.lineno}: HOST/BASE is computed')
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            problems += [f'line {n.lineno}: URL to {m.group(0)}' for m in URL_HOST.finditer(n.value)
                         if m.group(0) != f'https://{DOCS_HOST}']
    # The redirect check must compare the hostname with the HOST constant.
    if not any(isinstance(n, ast.Compare) and isinstance(n.left, ast.Attribute) and n.left.attr == 'hostname'
               and any(isinstance(c, ast.Name) and c.id == 'HOST' for c in n.comparators) for n in ast.walk(tree)):
        problems.append('no hostname == HOST check')
    return problems


def shipped_text_files():
    for path in sorted(PLUGIN.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path != ICON:
            yield path, path.read_text(encoding='utf-8')


class ShippedBundleTests(unittest.TestCase):
    def test_no_evals_in_plugin(self):
        self.assertFalse((PLUGIN / 'evals').exists())
        self.assertTrue((ROOT / 'evals/README.md').is_file())

    def test_listing_icon_at_default_path(self):
        # The directory picks up .claude-plugin/icon.png without a manifest field: square PNG,
        # 512 to 2048 px, under 2 MB.
        data = ICON.read_bytes()
        self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
        width, height = struct.unpack('>II', data[16:24])
        self.assertEqual(width, height)
        self.assertTrue(512 <= width <= 2048, width)
        self.assertLess(len(data), 2 * 1024 * 1024)

    def test_no_shipped_file_refers_to_an_image_or_font(self):
        for path, text in shipped_text_files():
            self.assertIsNone(IMAGE_OR_FONT_PATH.search(text), path.relative_to(ROOT))

    def test_only_fetch_doc_imports_network_modules(self):
        scripts = sorted(SCRIPTS.glob('*.py'))
        self.assertIn(NETWORK_SCRIPT, [p.name for p in scripts])
        for path in scripts:
            found = network_modules(ast.parse(path.read_text(encoding='utf-8')))
            if path.name == NETWORK_SCRIPT:
                self.assertEqual(found, ['urllib.error', 'urllib.request'], path.name)
            else:
                self.assertEqual(found, [], path.name)

    def test_network_module_check_catches_the_stdlib_senders(self):
        tree = ast.parse('import os, socket\nimport urllib.parse, urllib.request\nfrom http import client\n'
                         'from asyncio import open_connection\nimport importlib\n__import__("ssl")\n'
                         'from urllib.parse import urlsplit\nimport xmlrpc.client\n')
        self.assertEqual(network_modules(tree),
                         ['asyncio', 'http', 'importlib', 'socket', 'ssl', 'urllib.request', 'xmlrpc.client'])

    def test_only_git_is_spawned(self):
        launches = 0
        for path in sorted(SCRIPTS.glob('*.py')):
            tree = ast.parse(path.read_text(encoding='utf-8'))
            self.assertEqual(spawn_problems(path.name, tree), [], path.name)
            launches += sum(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'run'
                            and isinstance(n.func.value, ast.Name) and n.func.value.id == 'subprocess'
                            for n in ast.walk(tree))
        self.assertGreaterEqual(launches, 5)  # not vacuous: the git queries and the status-line command

    def test_spawn_check_catches_other_commands(self):
        for code in ("import subprocess\nsubprocess.run(['curl', 'https://x.example'])",
                     "import subprocess\nsubprocess.Popen(('curl', '-s', u))",
                     "from subprocess import check_output\ncheck_output(['sh', '-c', 'curl x'])",
                     "import subprocess as sp\nsp.run(['curl', 'x'])",
                     "import subprocess\ncmd = ['curl']\nsubprocess.run(cmd)",
                     "import subprocess\nsubprocess.run('git status', shell=True)",
                     "import subprocess\nsubprocess.run(['git', 'x'], shell=True)",
                     "import os\nos.system('curl x')",
                     "import os\nos.execvp('curl', ['curl'])",
                     "import subprocess\nsubprocess.getoutput('curl x')"):
            self.assertTrue(spawn_problems('collect.py', ast.parse(code)), code)
        self.assertTrue(spawn_problems('collect.py', ast.parse('import subprocess\nsubprocess.run(command)')))
        self.assertFalse(spawn_problems('rate_limit_log.py', ast.parse('import subprocess\nsubprocess.run(command)')))
        self.assertFalse(spawn_problems('collect.py', ast.parse("import subprocess\nsubprocess.run(['git', '-C', r])")))

    def test_fetch_doc_host_is_the_fixed_docs_host(self):
        self.assertEqual(host_problems(ast.parse((SCRIPTS / NETWORK_SCRIPT).read_text(encoding='utf-8'))), [])

    def test_host_check_catches_other_hosts(self):
        text = (SCRIPTS / NETWORK_SCRIPT).read_text(encoding='utf-8')
        for old, new in (('HOST = "code.claude.com"', 'HOST = "docs.example.com"'),
                         ('HOST = "code.claude.com"', 'HOST = os.environ.get("H", "code.claude.com")'),
                         ('BASE = "https://code.claude.com/docs/"', 'BASE = "https://example.com/docs/"'),
                         ('parts.hostname == HOST', 'parts.hostname.endswith("claude.com")'),
                         ('TIMEOUT = 20', 'TIMEOUT = 20\nMIRROR = "https://mirror.example/x"')):
            self.assertIn(old, text)
            self.assertTrue(host_problems(ast.parse(text.replace(old, new))), new)


class NoCredentialValueReachesTheSnapshot(FakeHome):
    """Rule: a full collect writes names, counts and labels from credential-bearing sources, never a value.

    Sentinels are plain lowercase words, so the secret-pattern redaction cannot hide them: only the
    names-only reads (config_names.py and its loaders) keep them out.
    """
    VALUES = ('zqvsettingsenv', 'zqvlocalenv', 'zqvhookheader', 'zqvhelpercmd', 'zqvenvrcplain',
              'zqvenvrcliteralvalue', 'zqvprojmcpenv', 'zqvprojmcpheader', 'zqvusermcpenv', 'zqvusermcpheader',
              'zqvlocalmcpenv', 'zqvlocalmcpheader', 'zqvoauthclient', 'zqvmanagedmcpenv', 'zqvpluginmcpheader',
              'zqvmiseenv', 'zqvdevcontainerenv', 'zqvcomposeenv')
    NAMES = ('ZQ_SETTINGS_ENV', 'X-Zq-Hook', 'ZQ_ENVRC_API_KEY', 'ZQ_PROJ_ENV', 'X-Zq-Proj',
             'zqusersrv', 'zqlocalsrv', 'zqprojsrv', 'zqmanagedsrv', 'zqpluginsrv')

    def seed(self):
        root = os.path.join(self.home, 'repo')
        hook = {'type': 'http', 'url': 'https://hooks.example.com/h', 'headers': {'X-Zq-Hook': 'zqvhookheader'},
                'allowedEnvVars': ['ZQ_SETTINGS_ENV']}
        self.write('.claude/settings.json', {'env': {'ZQ_SETTINGS_ENV': 'zqvsettingsenv'},
                                             'apiKeyHelper': 'zqvhelpercmd',
                                             'hooks': {'Stop': [{'hooks': [hook]}]}})
        self.write('repo/.claude/settings.local.json', {'env': {'ZQ_LOCAL_ENV': 'zqvlocalenv'}})
        self.write('repo/.envrc', 'export ZQ_ENVRC_PLAIN=zqvenvrcplain\nexport ZQ_ENVRC_API_KEY=zqvenvrcliteralvalue\n')
        self.write('repo/.mcp.json', {'mcpServers': {'zqprojsrv': {
            'command': 'npx', 'env': {'ZQ_PROJ_ENV': 'zqvprojmcpenv'}, 'headers': {'X-Zq-Proj': 'zqvprojmcpheader'}}}})
        self.write('.claude.json', {
            'mcpServers': {'zqusersrv': {'type': 'http', 'url': 'https://mcp.example.com/m',
                                         'env': {'ZQ_USER_ENV': 'zqvusermcpenv'},
                                         'headers': {'X-Zq-User': 'zqvusermcpheader'},
                                         'oauth': {'clientId': 'zqvoauthclient'}}},
            'projects': {root: {'mcpServers': {'zqlocalsrv': {
                'command': 'x', 'env': {'ZQ_LOCAL_MCP': 'zqvlocalmcpenv'},
                'headers': {'X-Zq-Local': 'zqvlocalmcpheader'}}}}}})
        self.write('managed/managed-mcp.json', {'mcpServers': {'zqmanagedsrv': {
            'command': 'x', 'env': {'ZQ_MANAGED': 'zqvmanagedmcpenv'}}}})
        install = os.path.join(self.claude, 'plugins/cache/m/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {
            'demo@m': [{'scope': 'user', 'installPath': install, 'version': '1'}]}})
        self.write('.claude/plugins/cache/m/demo/1/.claude-plugin/plugin.json', {'name': 'demo'})
        self.write('.claude/plugins/cache/m/demo/1/.mcp.json', {'mcpServers': {'zqpluginsrv': {
            'type': 'http', 'url': 'https://p.example.com', 'headers': {'X-Zq-Plugin': 'zqvpluginmcpheader'}}}})
        self.write('repo/mise.toml', '[env]\nZQ_MISE = "zqvmiseenv"\n')
        self.write('repo/.devcontainer/devcontainer.json', json.dumps({'containerEnv': {'ZQ_DEV': 'zqvdevcontainerenv'}}))
        self.write('repo/docker-compose.yml', 'services:\n  a:\n    environment:\n      - ZQ_COMPOSE=zqvcomposeenv\n')
        return root

    def collect_text(self, *flags):
        root = self.seed()
        out = os.path.join(self.home, 'snap.json')
        argv = ['collect.py', '--claude-dir', self.claude, '--roots', root, '--out', out, *flags]
        with mock.patch.object(collect, 'managed_directory', return_value=os.path.join(self.home, 'managed')), \
                mock.patch.object(collect, '_out_allowed_dirs', return_value=[self.home]), \
                mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
            collect.main()
        with open(out, encoding='utf-8') as f:
            return f.read()

    def leaks(self, text):
        return [v for v in self.VALUES if v in text]

    def test_full_collect_holds_names_but_no_value(self):
        for flags in ((), ('--metadata-only',), ('--hash-paths',)):
            text = self.collect_text(*flags)
            self.assertEqual(self.leaks(text), [], flags)
            if not flags:  # not vacuous: every source was read, names-only
                for name in self.NAMES:
                    self.assertIn(name, text)

    def test_canary_catches_a_bypassed_names_only_reader(self):
        real = config_names.mapping_names

        def leaky(mapping):
            names = real(mapping)
            if names is not None:
                names['keys'] = sorted(f'{k}={v}' for k, v in mapping.items())
            return names

        with mock.patch.object(config_names, 'mapping_names', leaky):
            self.assertTrue(self.leaks(self.collect_text()))


class RiskyRulePatterns(unittest.TestCase):
    # collect.py builds these two patterns from named command lists (a regex that inlines download
    # and interpreter commands reads to the scan as download-and-run); the regexes are unchanged.
    def test_patterns_unchanged(self):
        sys.path.insert(0, str(PLUGIN / 'skills/setup-audit/scripts'))
        import collect
        patterns = dict((flag, rx.pattern) for flag, rx in collect.RISKY_RULES if hasattr(rx, 'pattern'))
        self.assertEqual(patterns['network-wildcard'],
                         r"Bash\((curl|wget|nc|ssh|scp|rsync)[ :]\*?\*?\)|Bash\((curl|wget)[: ]\*")
        self.assertEqual(patterns['interpreter-wildcard'],
                         r"Bash\((python3?|node|bash|sh|npx|uv run|\.venv/bin/python)[ :]*(-[ce]\s*['\"]?\s*)?\*")


if __name__ == '__main__':
    unittest.main()
