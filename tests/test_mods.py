"""Mods inventory: a static, bounded scan of a plugin's hooks.json `modules` entry. Fake homes only."""
import os
import copy
from unittest import mock

from test_collect import FakeHome, collect
import extensions
import privacy

MOD = """
import { helper } from './x.js';
// on('commented.event', ...) and $.fs.write in a comment may show up: the scan is heuristic
export default ({ on, $ }) => {
  on('tool.call', 'Bash', async (e) => { const t = await $.fs.read('SECRET_PATH_LITERAL'); return t; });
  on("prompt.submit", () => $.http.fetch('https://literal.example/SECRET_URL'));
  on('settings.read', (s) => { $.env.get('SECRET_ENV_NAME'); return s; });
  on('not valid!', () => 1);
  $.process.run('rm', ['-rf', 'x']);
};
"""


class ModInventory(FakeHome):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.claude, 'plugins/cache/market/modp/1')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'modp@market': [{'scope': 'user', 'installPath': self.root, 'version': '1'}]}})
        self.write('.claude/plugins/cache/market/modp/1/.claude-plugin/plugin.json', {'name': 'modp'})

    def hooks(self, data):
        self.write('.claude/plugins/cache/market/modp/1/hooks/hooks.json', data)

    def mod_file(self, rel, text):
        return self.write('.claude/plugins/cache/market/modp/1/' + rel, text)

    def scan(self):
        return extensions.collect_extensions(self.home, self.claude, [], [], None, [], [],
                                             collect.redact, collect.hook_handler_entry)

    def mod(self, result=None):
        result = result or self.scan()
        comps = [c for c in result['plugins'][0]['components'] if c.get('mod')]
        self.assertEqual(len(comps), 1)
        return comps[0]['mod'], result

    def test_events_and_calls_are_names_only(self):
        self.hooks({'modules': ['mod.js']})
        self.mod_file('hooks/mod.js', MOD)
        mod, result = self.mod()
        self.assertEqual(mod['module'], 'mod.js')
        self.assertTrue(mod['exists'])
        self.assertEqual(mod['bytes'], len(MOD.encode()))
        self.assertEqual(mod['events'], ['commented.event', 'prompt.submit', 'settings.read', 'tool.call'])
        self.assertEqual(mod['calls'], ['env.get', 'fs.read', 'fs.write', 'http.fetch', 'process.run'])
        self.assertFalse(mod['truncated'])
        for secret in ('SECRET_PATH_LITERAL', 'SECRET_URL', 'SECRET_ENV_NAME', 'rm', 'literal.example', 'not valid'):
            self.assertNotIn(secret, str(result['plugins']))
        comp = next(c for c in result['plugins'][0]['components'] if c.get('mod'))
        self.assertEqual(comp['handlers'], [])
        self.assertTrue(any('settings.read' in s and 'effective' in s for s in result['limitations']))

    def test_typescript_module_next_to_settings_hooks(self):
        self.hooks({'modules': ['../mods/m.ts'], 'hooks': {'Stop': [{'hooks': [
            {'type': 'command', 'command': 'echo hi'}]}]}})
        self.mod_file('mods/m.ts', "export default ({on,$}: any) => { on('session.append', () => $.mcp.call('s','t')); };")
        mod, result = self.mod()
        self.assertEqual((mod['events'], mod['calls']), (['session.append'], ['mcp.call']))
        comp = next(c for c in result['plugins'][0]['components'] if c.get('mod'))
        self.assertEqual(len(comp['handlers']), 1)
        self.assertFalse(any('effective' in s and 'settings.read' in s for s in result['limitations']))

    def test_module_outside_root_is_refused(self):
        secret = self.write('outside.js', "on('leaked.event', () => $.fs.read(1))")
        self.hooks({'modules': ['../../../../../../../outside.js']})
        mod, result = self.mod()
        self.assertEqual(mod['reason'], 'outside_plugin_root')
        self.assertEqual((mod['events'], mod['calls'], mod['exists']), ([], [], False))
        self.assertNotIn('leaked', str(result))
        self.hooks({'modules': [secret]})
        self.assertEqual(self.mod()[0]['reason'], 'outside_plugin_root')

    def test_symlinked_module_is_refused(self):
        target = self.write('target.js', "on('leaked.event', () => 1)")
        link = os.path.join(self.root, 'hooks/mod.js')
        os.makedirs(os.path.dirname(link), exist_ok=True)
        os.symlink(target, link)
        self.hooks({'modules': ['mod.js']})
        mod, result = self.mod()
        self.assertEqual(mod['reason'], 'outside_plugin_root')
        self.assertNotIn('leaked', str(result))

    def test_fifo_is_not_read_and_does_not_block(self):
        path = os.path.join(self.root, 'hooks/mod.js')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.mkfifo(path)
        self.hooks({'modules': ['mod.js']})
        mod, _ = self.mod()
        self.assertEqual(mod['reason'], 'not_regular_file')
        self.assertEqual(mod['events'], [])

    def test_missing_module_and_bad_extension(self):
        self.hooks({'modules': ['nope.js']})
        mod, _ = self.mod()
        self.assertEqual((mod['exists'], mod['reason']), (False, 'absent'))
        self.mod_file('hooks/mod.py', "on('x.y', 1)")
        self.hooks({'modules': ['mod.py']})
        mod, _ = self.mod()
        self.assertEqual(mod['reason'], 'unsupported_extension')
        self.assertEqual(mod['events'], [])

    def test_oversized_module_is_truncated_at_the_cap(self):
        text = "on('early.event', 1);\n" + 'x' * 400 + "\non('late.event', 1);\n"
        self.mod_file('hooks/mod.js', text)
        self.hooks({'modules': ['mod.js']})
        with mock.patch.object(extensions, 'MOD_MAX_BYTES', 200):
            mod, _ = self.mod()
        self.assertTrue(mod['truncated'])
        self.assertEqual(mod['events'], ['early.event'])
        self.assertEqual(mod['bytes'], len(text.encode()))

    def test_name_lists_are_capped_and_flagged(self):
        self.mod_file('hooks/mod.js', ''.join(f"on('e{i:03}', 1);" for i in range(30)))
        self.hooks({'modules': ['mod.js']})
        with mock.patch.object(extensions, 'MOD_MAX_NAMES', 5):
            mod, _ = self.mod()
        self.assertEqual(mod['events'], [f'e{i:03}' for i in range(5)])
        self.assertTrue(mod['truncated'])

    def test_non_mod_plugin_is_unchanged(self):
        self.hooks({'hooks': {'Stop': [{'hooks': [{'type': 'command', 'command': 'echo hi'}]}]}})
        result = self.scan()
        comps = result['plugins'][0]['components']
        self.assertTrue(comps and all('mod' not in c for c in comps))
        self.assertEqual(comps[0]['kind'], 'hooks')
        self.assertEqual(len(comps[0]['handlers']), 1)
        self.assertEqual(len(result['limitations']), 3)

    def test_malformed_modules_value_does_not_break_hooks(self):
        self.hooks({'modules': 'mod.js'})
        mod, _ = self.mod()
        self.assertEqual(mod['reason'], 'invalid_modules')

    def test_metadata_only_keeps_names_and_nothing_else(self):
        self.hooks({'modules': ['mod.js']})
        self.mod_file('hooks/mod.js', MOD)
        snap = {'extensions': self.scan()}
        privacy.mask_snapshot(snap)
        comp = next(c for c in snap['extensions']['plugins'][0]['components'] if c.get('mod'))
        self.assertEqual(comp['mod']['events'], ['commented.event', 'prompt.submit', 'settings.read', 'tool.call'])
        self.assertIn('fs.read', comp['mod']['calls'])
        self.assertTrue(comp['mod']['module'].startswith('[metadata-only'))
        self.assertNotIn('SECRET', str(snap))

    def test_scanning_never_executes_or_imports(self):
        marker = os.path.join(self.home, 'ran')
        self.mod_file('hooks/mod.js', f"require('fs').writeFileSync({marker!r}, '1')")
        self.hooks({'modules': ['mod.js']})
        with mock.patch.object(extensions, 'subprocess', create=True) as sp:
            self.scan()
        self.assertFalse(os.path.exists(marker))
        sp.run.assert_not_called()


class ModSettings(FakeHome):
    def test_mod_policy_keys_are_booleans_only(self):
        path = self.write('.claude/settings.json', {
            'allowManagedModsOnly': True, 'prependPlugins': ['SECRETPLUGIN@m'], 'appendPlugins': []})
        s = collect.summarize_settings(path, managed=True)
        self.assertEqual(s['mods'], {'allow_managed_mods_only': True, 'prepend_plugins': True,
                                      'append_plugins': False})
        self.assertNotIn('SECRETPLUGIN', str(s))
        plain = collect.summarize_settings(self.write('.claude/s2.json', {'model': 'x'}))
        self.assertEqual(plain['mods'], {'allow_managed_mods_only': False, 'prepend_plugins': False,
                                          'append_plugins': False})
