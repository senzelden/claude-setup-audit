"""config_names: the one names-only reader of credential-bearing configuration. Fake homes only."""
import json
import os
import re
import unittest
from test_collect import FakeHome, SCRIPTS, collect
from test_drift import parsed
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

        returns = [config_names.mapping_names(server['env']), config_names.mapping_names(server['headers']),
                   config_names.server_facts(server), config_names.user_mcp_state(self.home),
                   config_names.user_mcp_server_names(self.home), config_names.settings_env_names(settings),
                   config_names.hook_header_names(hook), config_names.envrc_names(root)]
        for value in returns:
            self.assertNotIn(CANARY, repr(value))
        # Not vacuous: the names did come through.
        self.assertIn('MCP_ENV_NAME', repr(returns[3]))
        self.assertIn('ENVRC_API_KEY', repr(returns[-1]))

        snap = json.dumps(collect.build_snapshot(parsed('--claude-dir', self.claude, '--roots', root)))
        self.assertNotIn(CANARY, snap)
        for name in ('MCP_ENV_NAME', 'X-Mcp-Header', 'SETTINGS_ENV_NAME', 'X-Hook-Header', 'ENVRC_API_KEY',
                     'usersrv', 'localsrv', 'projectsrv'):
            self.assertIn(name, snap)


# Static guard. Heuristic (line-based regexes over every scripts/*.py except config_names.py):
#   1. a quoted '.claude.json' or '.envrc' literal passed to a path/read call: os.path.join, open,
#      Path, any *load*/*read* function (load_json, json_object, read_text, _read, ...), or a
#      pathlib "/ '.claude.json'" join. Mentions elsewhere (classification tables such as
#      cache_effects' file-name rows, git_status(root, '.envrc'), comments, source labels) pass.
#   2. subscripting or .get() with the literal key 'env' or 'headers' (["env"], .get('headers'), ...).
#   3. a loop over a literal tuple/list that starts with 'env' or 'headers' (for key in ('env', ...)),
#      the shape the pre-0.13.1 extensions.py used to read both mappings.
# Comment lines are skipped. The guard targets reads, so it cannot see a read written through a
# variable key; it pins the known shapes and keeps reviewers pointed at config_names.py.
SENSITIVE_FILE = r"""['"](?:\.claude\.json|\.envrc)['"]"""
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
                  "for key in ('env', 'headers'):")
        allowed = ("if base in ('.mcp.json', '.claude.json'):",
                   '"git": git_status(root, ".envrc")}',
                   'sources.append(".envrc")',
                   "'http': frozenset({'url', 'headers', 'allowedEnvVars'}),")
        for line in shapes:
            self.assertTrue(any(p.search(line) for p in GUARD_PATTERNS), line)
        for line in allowed:
            self.assertFalse(any(p.search(line) for p in GUARD_PATTERNS), line)


if __name__ == '__main__':
    unittest.main()
