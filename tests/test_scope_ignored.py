"""Settings keys and env names a project or local file can't set (HYG-scope-ignored).

Fake homes only. Doc table: settings-reference.md and env-vars.md, fetched 2026-10-24.
"""
import json

from test_collect import FakeHome, collect
from test_privacy import PatchedHome, args
import config_checks as cc


def keys(layer, data):
    return {(e['key'], e['scope']) for e in cc.scope_ignored(layer, data)[0]}


def env(layer, names):
    return {e['name']: e['reason'] for e in cc.scope_ignored(layer, {'env': dict.fromkeys(names, '1')})[1]}


class SettingsScopes(FakeHome):
    def test_each_scope_class_is_ignored_where_the_docs_say(self):
        cases = {  # key -> (scope class, layers that ignore it)
            'axScreenReader': ('user_or_managed', {'project', 'local'}),
            'allowManagedHooksOnly': ('managed', {'user', 'project', 'local'}),
            'claudeInChromeDefaultEnabled': ('global_config', {'user', 'project', 'local'}),
            'syncClaudeAiSkills': ('user_local_managed', {'project'}),
            'worktree.location': ('user', {'project', 'local'}),
        }
        for key, (klass, ignored_in) in cases.items():
            data = {}
            node = data
            *parents, leaf = key.split('.')
            for p in parents:
                node = node.setdefault(p, {})
            node[leaf] = True
            for layer in ('user', 'project', 'local', 'managed'):
                with self.subTest(key=key, layer=layer):
                    self.assertEqual(keys(layer, data), {(key, klass)} if layer in ignored_in else set())

    def test_nested_keys_match_at_their_nested_path(self):
        self.assertEqual(keys('project', {'sandbox': {'network': {'strictAllowlist': True, 'allowedDomains': ['x']}}}),
                         {('sandbox.network.strictAllowlist', 'user_or_managed')})
        self.assertEqual(keys('project', {'autoMode': {'classifyAllShell': True}}),
                         {('autoMode', 'user_or_managed')})  # the parent already covers the nested key
        self.assertEqual(keys('project', {'sandbox': {'enabled': True}, 'strictAllowlist': True}), set())

    def test_required_keys_are_in_the_table(self):
        for key in ('axScreenReader', 'autoMode', 'modelPicker', 'skipAutoPermissionPrompt', 'forceLoginGatewayUrl',
                    'processWrapper', 'prependPlugins', 'appendPlugins', 'sshConfigs', 'claudeInChromeDefaultEnabled',
                    'sandbox.network.strictAllowlist', 'sandbox.filesystem.disabled',
                    'sandbox.allowAppleEvents', 'sandbox.allowNestedUserNamespaces'):
            with self.subTest(key=key):
                self.assertIn(key, cc.SETTINGS_SCOPES)

    def test_table_covers_the_sandbox_keys_apply_ops_restricts_to_user(self):
        import apply_ops
        for key, (_, scopes) in apply_ops.SANDBOX_KEYS.items():
            if scopes == apply_ops.USER:
                with self.subTest(key=key):
                    self.assertIn(cc.SETTINGS_SCOPES.get(key), ('user_or_managed', 'user'))

    def test_keys_absent_from_the_table_or_null_are_never_flagged(self):
        self.assertEqual(keys('project', {'model': 'x', 'permissions': {'allow': []}, 'madeUpKey': 1,
                                          'env': {'A': 'b'}, 'hooks': {}}), set())
        self.assertEqual(keys('project', {'axScreenReader': None}), set())
        self.assertEqual(cc.scope_ignored('project', 'not a dict'), ([], []))
        self.assertEqual(cc.scope_ignored('project', {'sandbox': 3, 'env': [1]}), ([], []))

    def test_unknown_layer_is_not_flagged(self):
        self.assertEqual(cc.scope_ignored('plugin', {'axScreenReader': True}), ([], []))


class EnvNames(FakeHome):
    def test_project_and_local_ignore_the_documented_names(self):
        names = ['CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_TMPDIR', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'XDG_CONFIG_HOME',
                 'XDG_ANYTHING', 'SystemRoot', 'ProgramFiles', 'ProgramFiles(x86)', 'OTEL_LOG_RAW_API_BODIES',
                 'ENABLE_BETA_TRACING_DETAILED', 'BETA_TRACING_ENDPOINT', 'CLAUDE_CODE_PROCESS_WRAPPER',
                 'CLAUDE_CODE_SYNC_SKILLS', 'CLAUDE_CODE_SYNC_PLUGINS', 'CLAUDE_CODE_PLUGIN_CACHE_DIR',
                 'CLAUDE_CODE_PLUGIN_SEED_DIR', 'CLAUDE_AX_SCREEN_READER', 'CLAUDE_AX_STARTUP_QUIET_MS',
                 'CLAUDE_CODE_USER_DIALOG_TIMEOUT_MS', 'CLAUDE_CODE_DISABLE_ATTACHMENTS',
                 'CLAUDE_CODE_DISABLE_FILE_MENTIONS']
        for layer in ('project', 'local'):
            with self.subTest(layer=layer):
                self.assertEqual(env(layer, names), dict.fromkeys(names, 'project_local'))
        for layer in ('user', 'managed'):
            with self.subTest(layer=layer):
                self.assertEqual(env(layer, names), {})

    def test_names_ignored_from_every_file_except_managed(self):
        names = ['CLAUDE_CODE_REMOTE', 'CLAUDE_CODE_ACCOUNT_UUID', 'CLAUDE_CODE_MESSAGING_SOCKET',
                 'CLAUDE_CODE_MESSAGING_TOKEN', 'CLAUDE_CODE_PROJECT_DIR_NAME', 'CLAUDE_CODE_RESTRICTED']
        for layer in ('user', 'project', 'local'):
            with self.subTest(layer=layer):
                self.assertEqual(env(layer, names), dict.fromkeys(names, 'every_file'))
        self.assertEqual(env('managed', names), {})

    def test_telemetry_group_is_conditional_where_an_off_value_still_applies(self):
        conditional = ['OTEL_LOGS_EXPORTER', 'OTEL_METRICS_EXPORTER', 'OTEL_TRACES_EXPORTER', 'OTEL_LOG_USER_PROMPTS',
                       'OTEL_LOG_TOOL_CONTENT', 'OTEL_LOG_TOOL_DETAILS']
        definite = ['CLAUDE_CODE_ENABLE_TELEMETRY', 'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA',
                    'ENABLE_ENHANCED_TELEMETRY_BETA', 'OTEL_LOG_ASSISTANT_RESPONSES',
                    'OTEL_EXPORTER_OTLP_ENDPOINT', 'OTEL_EXPORTER_OTLP_METRICS_HEADERS',
                    'OTEL_EXPORTER_OTLP_LOGS_PROTOCOL', 'OTEL_EXPORTER_OTLP_CERTIFICATE',
                    'OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY', 'OTEL_EXPORTER_OTLP_INSECURE',
                    'OTEL_EXPORTER_PROMETHEUS_HOST', 'OTEL_EXPORTER_PROMETHEUS_PORT']
        for layer in ('project', 'local'):
            got = env(layer, conditional + definite)
            self.assertEqual({n for n, r in got.items() if r == 'telemetry_unless_off'}, set(conditional))
            self.assertEqual({n for n, r in got.items() if r == 'project_local'}, set(definite))
        self.assertEqual(env('user', conditional + definite), {})

    def test_otlp_pattern_needs_the_documented_suffix(self):
        self.assertEqual(env('project', ['OTEL_EXPORTER_OTLP_TIMEOUT', 'OTEL_SERVICE_NAME', 'MY_OTEL_EXPORTER_OTLP_ENDPOINT',
                                         'OTEL_EXPORTER_OTLP_ENDPOINT_X']), {})
        for name in ('OTEL_EXPORTER_OTLP_METRICS_CLIENT_CERTIFICATE', 'OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY',
                     'OTEL_EXPORTER_OTLP_TRACES_CERTIFICATE'):
            self.assertEqual(env('project', [name]), {name: 'project_local'})

    def test_managed_settings_log_toggle_is_ignored_if_1(self):
        self.assertEqual(env('local', ['OTEL_LOG_MANAGED_SETTINGS']), {'OTEL_LOG_MANAGED_SETTINGS': 'ignored_if_1'})
        self.assertEqual(env('user', ['OTEL_LOG_MANAGED_SETTINGS']), {})

    def test_cfc_is_ignored_only_as_one_so_it_is_its_own_reason(self):
        self.assertEqual(env('project', ['CLAUDE_CODE_ENABLE_CFC']), {'CLAUDE_CODE_ENABLE_CFC': 'ignored_if_1'})
        self.assertEqual(env('user', ['CLAUDE_CODE_ENABLE_CFC']), {})

    def test_other_names_and_odd_shapes_are_not_flagged(self):
        self.assertEqual(env('project', ['PATH', 'MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL', 'xdg_lower', 'CLAUDE_AX']), {})
        self.assertEqual(cc.scope_ignored('project', {'env': {1: 'x'}}), ([], []))


class SummaryAndSnapshot(PatchedHome):
    def summary(self, rel):
        return collect.summarize_settings(self.write(rel, self.body))

    body = {'axScreenReader': True, 'model': 'x', 'env': {'HOME': '/x', 'FOO': 'zcvalue'}}

    def test_user_layer_survives_an_unnormalized_config_dir(self):
        for spelled in (self.claude + '/', self.claude + '/../.claude'):
            collect.CLAUDE = spelled
            with self.subTest(config_dir=spelled):
                self.assertNotIn('scope_ignored_keys', self.summary('.claude/settings.json'))

    def test_layer_comes_from_the_file_location(self):
        self.assertEqual([k['key'] for k in self.summary('repo/.claude/settings.json')['scope_ignored_keys']],
                         ['axScreenReader'])
        self.assertEqual([k['key'] for k in self.summary('repo/.claude/settings.local.json')['scope_ignored_keys']],
                         ['axScreenReader'])
        user = self.summary('.claude/settings.json')
        self.assertNotIn('scope_ignored_keys', user)
        self.assertNotIn('ignored_env_keys', user)
        self.assertEqual(self.summary('.claude/settings.local.json')['ignored_env_keys'],
                         [{'name': 'HOME', 'reason': 'project_local'}])

    def test_managed_file_is_never_flagged_and_empty_results_are_omitted(self):
        path = self.write('m/managed-settings.json', self.body)
        self.assertNotIn('scope_ignored_keys', collect.summarize_settings(path, data=self.body, managed=True))
        clean = collect.summarize_settings(self.write('r3/.claude/settings.json', {'model': 'x'}))
        self.assertNotIn('scope_ignored_keys', clean)
        self.assertNotIn('ignored_env_keys', clean)

    def test_metadata_only_keeps_the_fixed_vocabulary_names(self):
        self.write('.claude/settings.json', {})
        self.write('repo/.claude/settings.json', self.body)
        snap = collect.build_snapshot(args(roots=[self.home + '/repo'], metadata_only=True))
        text = json.dumps(snap)
        self.assertNotIn('zcvalue', text)
        proj = next(iter(snap['projects'].values()))['settings'][0]
        self.assertEqual(proj['scope_ignored_keys'], [{'key': 'axScreenReader', 'scope': 'user_or_managed'}])
        self.assertEqual(proj['ignored_env_keys'], [{'name': 'HOME', 'reason': 'project_local'}])
        self.assertEqual(snap['coverage']['privacy']['replaced_fields'].get('unclassified', 0), 0)

    def test_schema_types_the_new_fields(self):
        import snapshot_contract as contract
        self.write('repo/.claude/settings.json', self.body)
        snap = collect.build_snapshot(args(roots=[self.home + '/repo']))
        contract.validate_snapshot(snap)
        snap['global']['settings'] = [{'ignored_env_keys': [{'name': 'HOME', 'reason': 'made-up'}]}]
        with self.assertRaises(contract.SnapshotError):
            contract.validate_snapshot(snap)
