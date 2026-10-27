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
                  'headers': {'Authorization': 'opaque'}, 'env': {'AUTH': '${AUTH_TOKEN:-opaque}'},
                  'oauth': {'clientId': 'opaque', 'scopes': 'opaque'}}
        self.write('.claude.json', {'mcpServers': {'USER_PRIVATE_SERVER': remote}, 'projects': {
            root: {'mcpServers': {'LOCAL_PRIVATE_SERVER': remote}}}})
        self.write('repo/.mcp.json', {'mcpServers': {'project': remote}})
        result = self.scan([root])
        self.assertEqual({s['scope'] for s in result['mcp_servers']}, {'project'})  # ~/.claude.json is not read
        self.assertFalse([s for s in result['sources'] if s['source'].endswith('.claude.json')])
        for text in ('opaque', 'USER_PRIVATE_SERVER', 'LOCAL_PRIVATE_SERVER', 'AUTH', 'Authorization'):
            self.assertNotIn(text, str(result))
        server = result['mcp_servers'][0]
        self.assertEqual(server['endpoint_origin'], 'https://example.com')
        self.assertEqual(server['credential_mechanisms'], ['oauth_configured'])  # key presence only
        for removed in ('env_keys', 'headers_keys', 'env_literal_keys', 'headers_literal_keys', 'oauth_keys',
                        'oauth_scopes', 'url_variable_references', 'project_trust_accepted'):
            self.assertNotIn(removed, server)
        self.assertNotIn('mcp_project_state', result)
        self.assertNotIn('mcp_name_collisions', result)
        self.assertEqual(self.scan()['mcp_servers'], [])

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

    def test_missing_or_malformed_registry_does_not_claim_zero_installs_collected(self):
        for content in (None, '{', '{}', '{"plugins": []}'):
            if content is not None:
                self.write('.claude/plugins/installed_plugins.json', content)
            result = self.scan()
            self.assertFalse(any('scanned' in src for src in result['sources']
                                 if 'installed_plugins.json' in src['source']))
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {}})
        result = self.scan()
        self.assertTrue(any(src.get('scanned') == 0 for src in result['sources']))

    def test_malformed_servers_and_limit(self):
        root = os.path.join(self.home, 'repo')
        self.write('repo/.mcp.json', {'mcpServers': {'broken': [], 'valid': {'command': 'node'}}})
        from unittest import mock
        with mock.patch.object(extensions, 'MAX_ENTRIES', 1):
            result = self.scan([root])
        self.assertEqual(result['mcp_servers'][0]['status'], 'unavailable')
        self.assertTrue(any(s.get('reason') == 'server_limit' for s in result['sources']))

    def test_only_skill_md_counts_as_a_skill(self):
        root = os.path.join(self.claude, 'plugins/cache/market/demo/1')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'demo@market': [{'scope': 'user', 'installPath': root, 'version': '1'}]}})
        self.write('.claude/plugins/cache/market/demo/1/.claude-plugin/plugin.json', {'name': 'demo'})
        self.write('.claude/plugins/cache/market/demo/1/skills/a/SKILL.md', '---\ndescription: A\n---\nBody')
        self.write('.claude/plugins/cache/market/demo/1/skills/a/reference.md', 'Reference doc')
        self.write('.claude/plugins/cache/market/demo/1/agents/helper.md', '---\nname: helper\n---\nAgent')
        plugin = self.scan()['plugins'][0]
        skills = [c for c in plugin['components'] if c['kind'] == 'skills']
        self.assertEqual([os.path.basename(c['source']) for c in skills], ['SKILL.md'])
        self.assertEqual(len([c for c in plugin['components'] if c['kind'] == 'agents']), 1)


class HooksFileShapes(FakeHome):
    def add(self, data):
        plugin = {'components': []}
        extensions.add_hooks(plugin, data, 'hooks/hooks.json', lambda ev, m, h: {'event': ev})
        return plugin['components'][0]

    def test_a_modules_only_hooks_file_is_collected_with_no_handlers(self):
        # A JS-module hooks file has no event table; it isn't scanned (0.14.3) but it isn't unreadable.
        c = self.add({'modules': ['hooks/mod.js']})
        self.assertEqual((c['status'], c['handlers']), ('collected', []))

    def test_an_event_table_without_a_hooks_key_is_still_read(self):
        c = self.add({'Stop': [{'hooks': [{'type': 'command', 'command': 'x'}]}]})
        self.assertEqual((c['status'], [h['event'] for h in c['handlers']]), ('collected', ['Stop']))
