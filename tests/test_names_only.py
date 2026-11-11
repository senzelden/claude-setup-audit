"""Tests for the names-only collector fallback. Stdlib only; fake homes, never the real ~/.claude."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SCRIPTS = os.path.join(os.path.dirname(__file__), '..', 'plugins', 'setup-audit', 'skills', 'setup-audit', 'scripts')
sys.path.insert(0, os.path.abspath(SCRIPTS))

import names_only  # noqa: E402

VALUES = ('zqvsettingsenv', 'zqvhookheader', 'zqvhelpercmd', 'zqvprojmcpenv', 'zqvprojmcpheader',
          'zqvusermcpenv', 'zqvusermcpheader', 'zqvlocalmcpenv', 'zqvoauthclient', 'zqvmanagedmcpenv',
          'zqvpluginmcpheader', 'zqvmanagedsettingsenv', 'zqvlocalsettingsenv', 'zqvurlpath', 'zqvarg')
NAMES = ('ZQ_SETTINGS_ENV', 'X-Zq-Hook', 'ZQ_PROJ_ENV', 'X-Zq-Proj', 'zqusersrv', 'zqprojsrv',
         'zqmanagedsrv', 'zqpluginsrv', 'ZQ_MANAGED_SETTINGS', 'ZQ_LOCAL_SETTINGS')


class Fake(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.realpath(self.tmp.name)
        self.claude = os.path.join(self.home, '.claude')
        self.root = os.path.join(self.home, 'repo')
        self.managed = os.path.join(self.home, 'managed')

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, content):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content if isinstance(content, str) else json.dumps(content))
        return path

    def seed(self):
        hook = {'type': 'http', 'url': 'https://hooks.example.com/h', 'headers': {'X-Zq-Hook': 'zqvhookheader'},
                'allowedEnvVars': ['ZQ_SETTINGS_ENV']}
        self.write('.claude/settings.json', {
            'env': {'ZQ_SETTINGS_ENV': 'zqvsettingsenv'}, 'apiKeyHelper': 'zqvhelpercmd',
            'permissions': {'allow': ['Bash(git status)', 'Bash(curl -H "Authorization: Bearer abcdef0123456789abcdef0123" x)'],
                            'deny': ['Read(./.env)']},
            'hooks': {'Stop': [{'hooks': [hook]}]}, 'enabledPlugins': {'demo@m': True}})
        self.write('repo/.claude/settings.local.json', {'env': {'ZQ_LOCAL_SETTINGS': 'zqvlocalsettingsenv'}})
        self.write('repo/.mcp.json', {'mcpServers': {'zqprojsrv': {
            'command': 'npx', 'args': ['zqvarg'], 'env': {'ZQ_PROJ_ENV': 'zqvprojmcpenv'},
            'headers': {'X-Zq-Proj': 'zqvprojmcpheader'}}}})
        self.write('.claude.json', {
            'mcpServers': {'zqusersrv': {'type': 'http', 'url': 'https://mcp.example.com/zqvurlpath',
                                         'env': {'ZQ_USER_ENV': 'zqvusermcpenv'},
                                         'headers': {'X-Zq-User': 'zqvusermcpheader'},
                                         'oauth': {'clientId': 'zqvoauthclient'}}},
            'projects': {self.root: {'mcpServers': {'zqlocal': {'command': 'x', 'env': {'K': 'zqvlocalmcpenv'}}}}}})
        self.write('managed/managed-mcp.json', {'mcpServers': {'zqmanagedsrv': {
            'command': 'x', 'env': {'ZQ_MANAGED': 'zqvmanagedmcpenv'}}}})
        self.write('managed/managed-settings.json', {'env': {'ZQ_MANAGED_SETTINGS': 'zqvmanagedsettingsenv'}})
        install = os.path.join(self.claude, 'plugins/cache/m/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {
            'demo@m': [{'scope': 'user', 'installPath': install, 'version': '1'}]}})
        self.write('.claude/plugins/cache/m/demo/1/.mcp.json', {'mcpServers': {'zqpluginsrv': {
            'type': 'http', 'url': 'https://p.example.com', 'headers': {'X-Zq-Plugin': 'zqvpluginmcpheader'}}}})

    def run_tool(self, **kw):
        args = dict(home=self.home, claude_dir=self.claude, roots=[self.root], managed_dir=self.managed)
        args.update(kw)
        return names_only.run(**args)

    def entry(self, result, suffix):
        return next(e for e in result['files'] if e['path'].endswith(suffix))


class NoValueInOutput(Fake):
    def test_sentinel_values_never_appear_and_names_do(self):
        self.seed()
        text = json.dumps(self.run_tool())
        self.assertEqual([v for v in VALUES if v in text], [])
        self.assertNotIn('abcdef0123456789abcdef0123', text)
        for name in NAMES:
            self.assertIn(name, text)

    def test_cli_output_is_the_same_and_valid_json(self):
        self.seed()
        argv = ['names_only.py', '--claude-dir', self.claude, '--project', self.root]
        with mock.patch.object(names_only, 'HOME', self.home), mock.patch.object(names_only, 'managed_directory',
                                                                               return_value=self.managed), \
                mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()) as out:
            names_only.main()
        self.assertEqual([v for v in VALUES if v in out.getvalue()], [])
        for name in NAMES:
            self.assertIn(name, out.getvalue())
        json.loads(out.getvalue())

    def test_red_proof_the_test_fails_when_the_names_only_path_leaks(self):
        self.seed()
        real = names_only.key_names

        def leaky(mapping):
            return sorted(f'{k}={v}' for k, v in mapping.items())

        self.assertEqual(real({'A': 'zqvsettingsenv'}), ['A'])
        with mock.patch.object(names_only, 'key_names', leaky):
            text = json.dumps(self.run_tool())
        self.assertTrue([v for v in VALUES if v in text])

    def test_shape_types_lengths_and_redacted_rules(self):
        self.seed()
        entry = self.entry(self.run_tool(), os.path.join('.claude', 'settings.json'))
        self.assertEqual(entry['status'], 'ok')
        by_path = {k['path']: k for k in entry['keys']}
        self.assertEqual(by_path['permissions.allow']['types'], ['array'])
        self.assertEqual(by_path['permissions.allow']['max_length'], 2)
        self.assertEqual(by_path['env']['types'], ['object'])
        self.assertEqual(entry['names']['env'], ['ZQ_SETTINGS_ENV'])
        self.assertEqual(entry['names']['hooks.Stop[].hooks[].headers'], ['X-Zq-Hook'])
        self.assertIn('Bash(git status)', entry['rules']['permissions.allow'])
        self.assertIn('Read(./.env)', entry['rules']['permissions.deny'])

    def test_user_claude_json_goes_through_config_names(self):
        self.seed()
        entry = self.entry(self.run_tool(), '.claude.json')
        self.assertEqual(entry['status'], 'ok')
        self.assertIn('zqusersrv', entry['servers'])
        self.assertIn('zqlocal', json.dumps(entry['projects']))


class Statuses(Fake):
    def test_missing(self):
        result = self.run_tool()
        self.assertEqual(self.entry(result, os.path.join('repo', '.mcp.json'))['status'], 'missing')

    def test_malformed_file_is_not_json_and_not_echoed(self):
        self.write('.claude/settings.json', '{"env": {"ZQ_X": "zqvsettingsenv"')
        self.write('repo/.mcp.json', '[1, 2]')
        result = self.run_tool()
        entry = self.entry(result, os.path.join('.claude', 'settings.json'))
        self.assertEqual(entry['status'], 'not_json')
        self.assertNotIn('zqvsettingsenv', json.dumps(result))
        self.assertEqual(self.entry(result, os.path.join('repo', '.mcp.json'))['status'], 'not_json')

    def test_pathologically_deep_json_is_not_json_not_a_crash(self):
        self.write('.claude/settings.json', '[' * 200000 + ']' * 200000)
        self.assertEqual(self.entry(self.run_tool(), os.path.join('.claude', 'settings.json'))['status'], 'not_json')

    def test_symlinked_file_is_refused_and_target_not_read(self):
        target = self.write('elsewhere/real.json', {'env': {'ZQ_X': 'zqvsettingsenv'}})
        os.makedirs(self.claude, exist_ok=True)
        os.symlink(target, os.path.join(self.claude, 'settings.json'))
        result = self.run_tool()
        entry = self.entry(result, os.path.join('.claude', 'settings.json'))
        self.assertEqual(entry['status'], 'symlink_refused')
        self.assertNotIn('ZQ_X', json.dumps(result))

    def test_symlinked_directory_is_refused(self):
        target = self.write('elsewhere/settings.json', {'env': {'ZQ_X': 'zqvsettingsenv'}})
        os.symlink(os.path.dirname(target), os.path.join(self.home, 'linkedrepo'))
        result = self.run_tool(roots=[os.path.join(self.home, 'linkedrepo')])
        self.assertNotIn('ZQ_X', json.dumps(result))

    def test_too_large(self):
        self.write('.claude/settings.json', {'env': {'ZQ_BIG': 'zqvsettingsenv'}, 'pad': 'x' * 5000})
        with mock.patch.object(names_only, 'MAX_BYTES', 1000):
            result = self.run_tool()
        self.assertEqual(self.entry(result, os.path.join('.claude', 'settings.json'))['status'], 'too_large')
        self.assertNotIn('ZQ_BIG', json.dumps(result))


class Caps(Fake):
    def test_deep_nesting_is_capped(self):
        deep = cur = {}
        for _ in range(60):
            cur['a'] = {}
            cur = cur['a']
        self.write('.claude/settings.json', deep)
        entry = self.entry(self.run_tool(), os.path.join('.claude', 'settings.json'))
        self.assertEqual(entry['status'], 'ok')
        self.assertTrue(entry['truncated'])
        self.assertLessEqual(max(k['path'].count('.') for k in entry['keys']), names_only.MAX_DEPTH)

    def test_wide_objects_and_long_rule_lists_are_capped(self):
        self.write('.claude/settings.json', {'wide': {f'k{i}': 1 for i in range(5000)},
                                             'permissions': {'allow': [f'Bash(cmd{i})' for i in range(5000)]}})
        entry = self.entry(self.run_tool(), os.path.join('.claude', 'settings.json'))
        self.assertTrue(entry['truncated'])
        self.assertLessEqual(len(entry['keys']), names_only.MAX_KEYS)
        self.assertLessEqual(len(entry['rules']['permissions.allow']), names_only.MAX_RULES)

    def test_symlink_loop_in_plugin_registry_is_harmless(self):
        os.makedirs(os.path.join(self.claude, 'plugins'))
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {'x@m': [{'installPath': '/etc', 'scope': 'user'}]}})
        self.assertTrue(self.run_tool()['files'])


if __name__ == '__main__':
    unittest.main()
