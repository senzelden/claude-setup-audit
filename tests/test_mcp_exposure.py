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

    def test_malformed_values_are_skipped_not_fatal(self):
        long_name = 'n' * 300
        s = self.servers({
            'notdict': 'oops', 'listcfg': ['x'],
            'badurl': {'type': 'http', 'url': 42, 'args': 'nope', 'command': ['node']},
            'badoauth': {'type': 'http', 'url': 'https://a.example', 'oauth': {'scopes': ['a'], 'x': 1}},
            'badmaps': {'command': 'node', 'env': ['A'], 'headers': 'h', 'args': {'a': 1}},
            'v6bad': {'type': 'http', 'url': 'http://[::1'},
            long_name: {'command': 'node'}})
        self.assertEqual(s['notdict']['status'], 'unavailable')
        self.assertEqual(s['listcfg']['status'], 'unavailable')
        self.assertEqual((s['badurl']['transport_class'], s['badurl']['argument_count']), ('remote', None))
        self.assertNotIn('endpoint_locality', s['badurl'])
        self.assertIsNone(s['badoauth']['oauth_scopes'])
        self.assertNotIn('env_literal_keys', s['badmaps'])
        self.assertNotIn('headers_literal_keys', s['badmaps'])
        self.assertEqual(s['v6bad']['endpoint_locality'], 'invalid')
        self.assertEqual(len(s[long_name]['tool_prefix']), 120)

    def test_prefix_and_scope_names_are_redacted_and_capped(self):
        secret = 'sk-sentinel0123456789'
        s = self.servers({secret: {'type': 'http', 'url': 'https://a.example',
                                   'oauth': {'scopes': secret + ' ' + 'z' * 100}}})
        server = next(iter(s.values()))
        self.assertNotIn(secret, json.dumps([server['tool_prefix'], server['oauth_scopes']]))
        self.assertTrue(all(len(x) <= 64 for x in server['oauth_scopes']))


    def test_tool_prefix_does_not_launder_secrets(self):
        canary = 'CANARY0123456789abcdef'
        names = ['Bearer ' + canary, 'api_key=' + canary, 'token: ' + canary]
        s = self.servers({n: {'command': 'node'} for n in names})
        self.assertNotIn(canary, json.dumps(s))
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {'p@m': [
            {'scope': 'user', 'installPath': os.path.join(self.claude, 'plugins/cache/m/p/1')}]}})
        self.write('.claude/plugins/cache/m/p/1/.claude-plugin/plugin.json',
                   {'name': 'api_key=' + canary, 'mcpServers': {n: {'command': 'node'} for n in names}})
        self.assertNotIn(canary, json.dumps(self.scan()['mcp_servers']))

    def test_backslash_authority_is_not_loopback(self):
        s = self.servers({
            'a': {'type': 'http', 'url': 'http://evil.com\\@localhost/'},
            'b': {'type': 'ws', 'url': 'ws://evil.com\\@127.0.0.1/'}})
        for n in 'ab':
            self.assertEqual((s[n]['endpoint_locality'], s[n]['plaintext_transport']), ('named_host', True), n)
            self.assertEqual(s[n]['endpoint_origin'], ('http' if n == 'a' else 'ws') + '://evil.com')

    def test_localhost_subdomain_is_named_host(self):
        s = self.servers({'a': {'type': 'http', 'url': 'http://x.localhost/'},
                          'b': {'type': 'http', 'url': 'http://localhost/'}})
        self.assertEqual((s['a']['endpoint_locality'], s['b']['endpoint_locality']), ('named_host', 'loopback'))

    def test_lists_are_capped_and_variable_names_redacted(self):
        env = {f'K{i:03}': 'lit' for i in range(150)}
        var = 'TOK_CANARY' + 'x' * 200
        s = self.servers({'a': {'type': 'http', 'url': 'https://a.example/${%s}' % var, 'env': env, 'headers': env}})['a']
        self.assertEqual((len(s['env_literal_keys']), len(s['headers_literal_keys'])), (100, 100))
        self.assertEqual([len(v) for v in s['url_variable_references']], [120])
        secret = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2'
        s = self.servers({'a': {'type': 'http', 'url': 'https://a.example/${%s}' % secret}})['a']
        self.assertNotIn(secret, json.dumps(s))


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

    def test_stored_names_are_redacted_and_capped(self):
        secret = 'sk-sentinel0123456789'
        path = self.write('.claude/settings.json', {
            'enabledMcpjsonServers': [secret, 'n' * 500],
            'allowedMcpServers': [{'serverName': secret}, {'serverName': 'm' * 500}],
            'permissions': {'allow': [f'mcp__{secret}__x', 'mcp__' + 'p' * 500]}})
        s = collect.summarize_settings(path)
        self.assertNotIn(secret, json.dumps(s))
        for name in s['mcp_policy']['enabledMcpjsonServers'] + s['mcp_policy']['allowedMcpServers']['server_names'] \
                + list(s['mcp_permission_rules']['allow']):
            self.assertLessEqual(len(name), extensions.NAME_CAP)

    def test_permission_rules_are_counted_per_server_segment(self):
        rules = collect.mcp_permission_rules({
            'allow': ['mcp__github__get_*', 'mcp__github', 'mcp__*', 'Bash(ls)', 'mcp__plugin_demo_db__query',
                      'mcp__', 7],
            'deny': ['mcp__slack__post']})
        self.assertEqual(rules, {'allow': {'*': 1, 'github': 2, 'plugin_demo_db': 1}, 'deny': {'slack': 1}})

    def test_permission_rules_with_parentheses_are_skipped_like_claude_code(self):
        # permissions.md: loading a settings file "skips any `mcp__` rule that has parentheses".
        rules = collect.mcp_permission_rules({
            'allow': ['mcp__gh__x(arg)', 'mcp__gh'], 'deny': ['mcp__slack__post(channel:x)']})
        self.assertEqual(rules, {'allow': {'gh': 1}})

    def test_permission_rules_tolerate_malformed_shapes(self):
        self.assertEqual(collect.mcp_permission_rules(['mcp__a']), {})
        self.assertEqual(collect.mcp_permission_rules({'allow': 'mcp__a', 'deny': {'x': 1}, 'ask': [None, 3]}), {})
        self.assertEqual(collect.mcp_permission_rules({'allow': ['mcp__a', None]}), {'allow': {'a': 1}})

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

    def test_non_string_plugin_project_path_is_treated_as_missing(self):
        self.write('.claude/plugins/installed_plugins.json', {'plugins': {
            'a@m': [{'scope': 'user', 'projectPath': ['x'], 'installPath': '/nowhere'},
                    {'scope': 'project', 'projectPath': 7, 'installPath': '/nowhere'}]}})
        plugins = self.scan()['plugins']
        self.assertEqual([(p['scope'], p['project']) for p in plugins], [('user', None)])
        servers = [{'status': 'collected', 'scope': 'plugin', 'name': 'x', 'project': plugins[0]['project'],
                    'tool_prefix': 'x'}]
        extensions.mcp_observations(servers, [], [], lambda p: p)
        self.assertEqual(servers[0]['policy_observations'], [])

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

    def test_observation_cap_keeps_managed_policy(self):
        servers = [{'status': 'collected', 'scope': 'user', 'name': 'gh', 'project': None, 'tool_prefix': 'gh'}]
        layers = [('project', f'~/p{i}', {'path': f'~/p{i}/.claude/settings.json', 'mcp_policy': None,
                                          'mcp_permission_rules': {'allow': {'gh': 1}}}) for i in range(25)]
        layers.append(('managed', None, {'path': '/etc/claude-code/managed-settings.json',
                                         'mcp_policy': {'deniedMcpServers': {'server_names': ['gh']}},
                                         'mcp_permission_rules': {}}))
        extensions.mcp_observations(servers, layers, [], lambda p: p)
        kept = servers[0]['policy_observations']
        self.assertEqual((len(kept), servers[0]['policy_observations_omitted']), (20, 6))
        self.assertIn('policy_denied_by_name', [o['kind'] for o in kept])
        self.assertEqual([o['source'] for o in kept[:-1]], [f'~/p{i}/.claude/settings.json' for i in range(19)])

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
