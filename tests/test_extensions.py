"""Extension provenance and credential non-disclosure with fake homes."""
import os
from test_collect import FakeHome, collect
import extensions


class ExtensionInventory(FakeHome):
    def scan(self, roots=(), settings=()):
        return extensions.collect_extensions(self.home, self.claude, roots, [], None, [],
                                              settings, collect.redact, collect.hook_handler_entry)

    def test_scopes_and_credentials(self):
        root = os.path.join(self.home, 'repo')
        remote = {'type': 'http', 'url': 'https://user:opaque@example.com/opaque?token=opaque',
                  'headers': {'Authorization': 'opaque'}, 'env': {'AUTH': '${AUTH_TOKEN:-opaque}'}}
        self.write('.claude.json', {'mcpServers': {'user': remote}, 'projects': {
            root: {'mcpServers': {'local': {'command': 'npx', 'args': ['server@1.2.3', 'opaque']}}},
            '/other': {'mcpServers': {'OTHER_PRIVATE_SERVER': remote}}}})
        self.write('repo/.mcp.json', {'mcpServers': {'project': remote}})
        result = self.scan([root])
        self.assertEqual({s['scope'] for s in result['mcp_servers']}, {'user', 'local', 'project'})
        self.assertNotIn('opaque', str(result))
        self.assertNotIn('OTHER_PRIVATE_SERVER', str(result))
        local = next(s for s in result['mcp_servers'] if s['scope'] == 'local')
        self.assertEqual(local['package_version_evidence'], 'exact_version_shape')
        self.assertEqual(result['mcp_servers'][0]['endpoint_origin'], 'https://example.com')
        self.assertEqual([s['scope'] for s in self.scan()['mcp_servers']], ['user'])

    def test_plugin_registry_selects_version_and_never_executes(self):
        root = os.path.join(self.claude, 'plugins/cache/market/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'demo@market': [{'scope': 'user', 'installPath': root, 'version': '1'}]}})
        self.write('.claude/plugins/cache/market/demo/1/.claude-plugin/plugin.json',
                   {'name': 'demo', 'mcpServers': {'test': {'command': 'node', 'args': ['opaque']}},
                    'hooks': {'hooks': {'SessionStart': [{'hooks': [{'type': 'command', 'command': 'echo hello'}]}]}}})
        self.write('.claude/plugins/cache/market/demo/1/skills/test/SKILL.md', '---\nallowed-tools: Bash(*)\n---\nKeep it safe.')
        self.write('.claude/plugins/cache/market/demo/2/skills/test/SKILL.md', 'NEWER BUT NOT SELECTED')
        settings = [{'path': 'settings.json', 'enabled_plugins': {'demo@market': False}}]
        result = self.scan(settings=settings)
        self.assertNotIn('NEWER BUT NOT SELECTED', str(result))
        self.assertNotIn('opaque', str(result))
        plugin = result['plugins'][0]
        self.assertEqual(plugin['enablement_observations'][0]['value'], False)
        self.assertEqual(plugin['active_state'], 'unknown')
        self.assertTrue(any(c.get('frontmatter', {}).get('allowed-tools') == 'Bash(*)' for c in plugin['components']))
        self.assertEqual(result['mcp_servers'][0]['scope'], 'plugin')

    def test_external_component_and_unknown_registry_do_not_read_arbitrary_paths(self):
        root = os.path.join(self.claude, 'plugins/cache/p/1')
        self.write('private.json', {'mcpServers': {'PRIVATE': {'command': 'private'}}})
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {'p@m': [
            {'scope': 'user', 'installPath': root}, {'scope': 'user', 'installPath': self.home}]}})
        self.write('.claude/plugins/cache/p/1/.claude-plugin/plugin.json', {'mcpServers': os.path.join(self.home, 'private.json')})
        result = self.scan()
        self.assertNotIn('PRIVATE', str(result))
        self.assertTrue(any(s.get('reason') == 'external_component_path' for s in result['sources']))
        self.assertEqual(result['plugins'][1]['status'], 'not_checked')

    def test_malformed_servers_and_limit(self):
        self.write('.claude.json', {'mcpServers': {'broken': [], 'valid': {'command': 'node'}}})
        from unittest import mock
        with mock.patch.object(extensions, 'MAX_ENTRIES', 1):
            result = self.scan()
        self.assertEqual(result['mcp_servers'][0]['status'], 'unavailable')
        self.assertTrue(any(s.get('reason') == 'server_limit' for s in result['sources']))
