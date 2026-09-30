"""Privacy: contextual secret detection. Fake homes only; no test here touches ~/.claude."""
import argparse
import contextlib
import copy
import io
import json
import os
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from unittest import mock

from test_collect import FakeHome, collect  # also puts the plugin scripts directory on sys.path
import privacy

AWS = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
# (input, secret value, label that must survive, measured entropy in bits/char or None) -- T1-T10
TRUE_POSITIVES = [
    (f'export AWS_SECRET_ACCESS_KEY={AWS}', AWS, 'AWS_SECRET_ACCESS_KEY=', 4.663),
    ('STRIPE_SECRET_KEY=sk_prod_4eC39HqLyjWDarjtT1zdp7dc', 'sk_prod_4eC39HqLyjWDarjtT1zdp7dc',
     'STRIPE_SECRET_KEY=', 4.601),
    ('SECRET_KEY = "Zx9fK2mQ7vL1pR8tW3yB6nD4"', 'Zx9fK2mQ7vL1pR8tW3yB6nD4', 'SECRET_KEY = "', 4.585),
    ('curl --api-token 9fK2mQ7vL1pR8tW3yB6nD4hJ https://api.example.com', '9fK2mQ7vL1pR8tW3yB6nD4hJ',
     '--api-token ', 4.585),
    ('mysql --password hunter22x -h db', 'hunter22x', '--password ', None),
    ('GITHUB_PAT=github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF',
     'github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEF', 'GITHUB_PAT=', 5.338),
    ('sessionKey: 7Hq2LmX9pRt4VzK8wN3b', '7Hq2LmX9pRt4VzK8wN3b', 'sessionKey: ', 4.322),
    ('curl -H "X-Auth: 3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c" https://x.example',
     '3f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c', 'X-Auth: ', 3.906),
    ('https://b.s3.amazonaws.com/f?X-Amz-Signature='
     'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024',
     'fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024', 'X-Amz-Signature=', 3.824),
    (f'docker run -e AWS_SECRET_ACCESS_KEY={AWS} app', AWS, 'AWS_SECRET_ACCESS_KEY=', 4.663),
]
MUST_NOT_FLAG = [  # N1-N27
    'git checkout 3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
    'commit_sha=3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
    'session_id=550e8400-e29b-41d4-a716-446655440000',
    'claude --resume 550e8400-e29b-41d4-a716-446655440000',
    'key_file=/home/user/.ssh/id_ed25519',
    'ssh_key: ~/.ssh/id_ed25519',
    'api_key_env=ANTHROPIC_API_KEY_BACKUP',
    'SIGNING_KEY=PROD_SIGNING_KEY_2026',
    'max_tokens=4096',
    'image=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
    'cacheKey: release-2026-09-29-build',
    'sort_keys=True',
    'hotkey: ctrl+shift+k',
    'session=2026-09-29T10:00:00Z',
    '--token-file ./secrets/ci.token',
    'fingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8',
    'signature_hash=9b74c9897bac770ffc029102a200c5de',
    'session_key=aaaaaaaa11111111',
    'auth_token_2=abababababababab12',
    'KEYBINDINGS=vim',
    '/home/u/code/token-service/src/auth_middleware.py',
    'OPENAI_API_KEY=$(pass show openai)',
    'password_file=/run/secrets/db',
    '--session-id 7c9e6679-7425-40de-944b-e07fc1f90ae7',
    '[metadata-only: 143 chars]',
    'npx jest --passWithNoTests --coverage',
    'psql --password --host db',
    'primaryKey: userAccountId2026',  # N28-N31 added 2026-09-30
    'export AUTH_PROVIDER=GoogleOAuth2Provider',
    'publicKey: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE',
    'sortKey=createdAtTimestamp2',
]


class ContextualDetection(unittest.TestCase):
    def test_true_positives(self):
        for text, secret, label, _ in TRUE_POSITIVES:
            with self.subTest(text=text[:40]):
                self.assertIn(secret, collect.SECRET_RE.sub('[REDACTED]', text))  # the gap this closes
                out = collect.redact(text)
                self.assertNotIn(secret, out)
                self.assertIn(label + privacy.CONTEXT_TOKEN, out)

    def test_must_not_flag(self):
        for text in MUST_NOT_FLAG:
            with self.subTest(text=text[:40]):
                self.assertEqual(collect.redact(text), text)

    def test_accepted_over_redaction(self):
        text = 'cache_key=9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
        self.assertEqual(collect.redact(text), 'cache_key=' + privacy.CONTEXT_TOKEN)
        self.assertAlmostEqual(privacy.shannon(text.split('=')[1]), 3.786, places=3)

    def test_password_label_already_redacted_by_secret_re_stays_unchanged(self):  # A2
        text = 'password: required'
        first = collect.SECRET_RE.sub('[REDACTED]', text)
        self.assertEqual(privacy.contextual_redact(first), first)  # the contextual pass adds nothing
        self.assertEqual(collect.redact(text), first)

    def test_password_class_uses_last_label_segment(self):
        self.assertTrue(privacy.contextual_secret('PGPASSWORD', 'hunter22x'))
        self.assertTrue(privacy.contextual_secret('--db-password', 'hunter22x'))
        self.assertTrue(privacy.contextual_secret('--pass', 'hunter22x'))
        self.assertFalse(privacy.contextual_secret('--passWithNoTests', 'somevalue'))
        self.assertFalse(privacy.contextual_secret('--password', '--host'))

    def test_measured_entropies(self):
        for text, secret, _, expected in TRUE_POSITIVES:
            if expected is not None:
                with self.subTest(text=text[:40]):
                    self.assertAlmostEqual(privacy.shannon(secret), expected, places=3)
                    self.assertGreaterEqual(privacy.shannon(secret), privacy.ENTROPY_MIN)
        self.assertAlmostEqual(privacy.shannon('aaaaaaaa11111111'), 1.000, places=3)  # N18
        self.assertAlmostEqual(privacy.shannon('abababababababab12'), 1.503, places=3)  # N19

    def test_shannon_reference_values(self):
        self.assertAlmostEqual(privacy.shannon('0123456789abcdef'), 4.0)
        self.assertEqual(privacy.shannon('aaaa'), 0.0)
        self.assertEqual(privacy.shannon(''), 0.0)

    def test_label_segments(self):
        self.assertEqual(privacy.label_segments('sessionKey'), ['session', 'key'])
        self.assertEqual(privacy.label_segments('--api-token'), ['api', 'token'])
        self.assertEqual(privacy.label_segments('AWS_SECRET_ACCESS_KEY'),
                         ['aws', 'secret', 'access', 'key'])

    def test_contextual_search(self):
        self.assertTrue(privacy.contextual_search(f'AWS_SECRET_ACCESS_KEY={AWS}'))
        self.assertFalse(privacy.contextual_search('AWS_PROFILE=dev'))

    def test_sanitize_leaves_references_and_spaced_values_alone(self):
        env = {'POSTGRES_PASSWORD': '${POSTGRES_PASSWORD}', 'PGPASSWORD': '$(pass show pg)',
               'DB_PASSWORD': '<set in vault>', 'API_KEY': '{{secrets.API_KEY_V2}}',
               'GITHUB_PERSONAL_ACCESS_TOKEN': '${GITHUB_PAT_2026}',
               'session': 'sess-2026-09-29 16:04 /home/u/proj'}
        self.assertEqual(collect.sanitize({'env': env}), {'env': env})
        self.assertEqual(collect.sanitize({'DB_PASSWORD': 'hunter22x'})['DB_PASSWORD'],
                         privacy.CONTEXT_TOKEN)
        self.assertTrue(privacy.contextual_secret('password', 'correct horse battery'))

    def test_sanitize_checks_json_key_value_pairs(self):
        out = collect.sanitize({'AWS_SECRET_ACCESS_KEY': AWS, 'session_cwd': '/tmp/app',
                                'commit_sha': '3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c',
                                'api_key': '$FOO'})
        self.assertEqual(out['AWS_SECRET_ACCESS_KEY'], privacy.CONTEXT_TOKEN)
        self.assertEqual(out['session_cwd'], '/tmp/app')
        self.assertEqual(out['commit_sha'], '3f1c0a9b7e2d4c55a1b2c3d4e5f60718293a4b5c')
        self.assertEqual(out['api_key'], '$FOO')


SETTINGS = {
    'model': 'opus', 'modelSettings': {'opus': {'note': 'free text', 'budget': 3}},
    'statusLine': {'type': 'command', 'command': 'print-status --verbose'},
    'sandbox': {'enabled': True, 'network': {'allowedDomains': ['a.example.com', 'b.example.com']}},
    'permissions': {'allow': ['Bash(sudo ls)', 'Bash(curl:*)'], 'deny': ['Bash(rm -rf /)', 'Read(.env)'],
                    'defaultMode': 'acceptEdits', 'additionalDirectories': ['~/shared']},
    'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
        {'type': 'command', 'command': 'echo hi'},
        {'type': 'http', 'url': 'https://hooks.example.com/x', 'headers': {'X-Token': '$T'}},
        {'type': 'prompt', 'prompt': 'judge this'},
        {'type': 'mcp_tool', 'server': 'srv', 'tool': 'check'}]}]},
}


class MaskingUnits(unittest.TestCase):
    def test_marker_format(self):
        self.assertEqual(privacy.marker('abc'), '[metadata-only: 3 chars]')
        self.assertTrue(privacy.MARKER_RE.match(privacy.marker('')))

    def test_mask_settings_summary(self):
        s = collect.summarize_settings('/tmp/x/settings.json', data=copy.deepcopy(SETTINGS))
        before = copy.deepcopy(s)
        c = Counter()
        privacy.mask_settings(s, c)
        self.assertTrue(all(privacy.MARKER_RE.match(v) for v in s['hook_commands']))
        self.assertEqual(len(s['hook_commands']), len(before['hook_commands']))
        for h, b in zip(s['hook_handlers'], before['hook_handlers']):
            self.assertTrue(privacy.MARKER_RE.match(h['target']))
            for k in ('event', 'matcher', 'type', 'server', 'tool', 'target_origin', 'header_keys'):
                self.assertEqual(h.get(k), b.get(k))
        self.assertEqual(sorted(s['permissions']['risky']), sorted(before['permissions']['risky']))
        for flag, rules in s['permissions']['risky'].items():
            self.assertEqual(len(rules), len(before['permissions']['risky'][flag]))
            self.assertTrue(all(privacy.MARKER_RE.match(r) for r in rules))
        self.assertEqual(len(s['permissions']['deny']), s['permissions']['deny_count'])
        self.assertTrue(all(privacy.MARKER_RE.match(r) for r in s['permissions']['deny']))
        self.assertIs(s['sandbox']['enabled'], True)
        self.assertTrue(all(privacy.MARKER_RE.match(d) for d in s['sandbox']['network']['allowedDomains']))
        self.assertEqual(s['model_settings']['opus']['budget'], 3)
        self.assertTrue(privacy.MARKER_RE.match(s['model_settings']['opus']['note']))
        self.assertTrue(privacy.MARKER_RE.match(s['other']['statusLine']['command']))
        for k in ('path', 'keys', 'env_keys', 'model', 'hooks'):
            self.assertEqual(s[k], before[k])
        self.assertEqual(s['permissions']['default_mode'], 'acceptEdits')
        self.assertEqual(s['permissions']['additional_dirs'], ['~/shared'])
        self.assertEqual(c['hook_targets'], 4)
        self.assertEqual(c['permission_deny'], 2)

    def test_mask_frontmatter_keeps_identifier_keys_only(self):
        fm = {'name': 's', 'model': 'haiku', 'paths': 'src/**', 'description': 'd', 'when_to_use': 'w',
              'allowed-tools': 'Bash(x)', 'hooks': 'h', 'unknown-key': 'u'}
        privacy.mask_frontmatter(fm, Counter())
        self.assertEqual((fm['name'], fm['model'], fm['paths']), ('s', 'haiku', 'src/**'))
        for k in ('description', 'when_to_use', 'allowed-tools', 'hooks', 'unknown-key'):
            self.assertTrue(privacy.MARKER_RE.match(fm[k]), k)

    def test_shared_objects_are_masked_once(self):
        session = {'project': '~/app', 'first_prompt': 'hello there'}
        snap = {'usage': {'heaviest_sessions': [session], 'most_friction_sessions': [session],
                          'facet_friction_details': []}}
        counts = privacy.mask_snapshot(snap)
        self.assertEqual(session['first_prompt'], '[metadata-only: 11 chars]')
        self.assertEqual(counts['first_prompt'], 1)

    def test_mask_snapshot_skips_absent_sections_and_counts_families(self):
        snap = {'corrections': {}, 'memory': {'by_project': {'p': {'entries': [{'file': 'a.md', 'description': ''}]}}},
                'instructions': {'entries': [{'source': '/x/CLAUDE.md', 'excerpt': 'abc', 'frontmatter': {}}]}}
        counts = privacy.mask_snapshot(snap)
        self.assertEqual(snap['memory']['by_project']['p']['entries'][0],
                         {'file': 'a.md', 'description': '[metadata-only: 0 chars]'})
        self.assertEqual(counts, {'memory_descriptions': 1, 'excerpts': 1})


def args(**kw):
    base = dict(roots=[], days=30, claude_dir=None, scope='all', project=None)
    return argparse.Namespace(**{**base, **kw})


class PatchedHome(FakeHome):
    """Fake home whose managed-settings directory is inside it (never /etc/claude-code). It defines no
    tests, so subclasses do not re-run each other's tests."""

    def setUp(self):
        super().setUp()
        p = mock.patch.object(collect, 'managed_directory', lambda: os.path.join(self.home, 'managed'))
        p.start()
        self.addCleanup(p.stop)


class CollectorMode(PatchedHome):

    def test_full_mode_records_privacy_full(self):
        snap = collect.build_snapshot(args())
        p = snap['coverage']['privacy']
        self.assertEqual((p['mode'], p['free_text'], p['replaced_fields']), ('full', 'collected', {}))
        self.assertNotIn('free_text_fields', [s['source'] for s in snap['coverage']['sources']])

    def test_metadata_mode_records_mode_source_and_limitation(self):
        self.write('.claude/settings.json', {'permissions': {'deny': ['Bash(rm -rf /)']}})
        snap = collect.build_snapshot(args(metadata_only=True))
        p = snap['coverage']['privacy']
        self.assertEqual((p['mode'], p['free_text']), ('metadata-only', 'replaced'))
        self.assertEqual(p['marker'], privacy.MARKER_FORMAT)
        self.assertEqual(p['replaced_fields']['permission_deny'], 1)
        src = [s for s in snap['coverage']['sources'] if s['source'] == 'free_text_fields']
        self.assertEqual((src[0]['status'], src[0]['reason'], src[0]['scope']),
                         ('not_checked', 'metadata_only_mode', 'all'))
        self.assertTrue(any(x.startswith('Metadata-only mode:') for x in snap['coverage']['limitations']))

    def test_redaction_counts_and_secret_absent(self):
        secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        self.write('.claude/settings.json', {'hooks': {'Stop': [{'hooks': [
            {'type': 'command', 'command': f'AWS_SECRET_ACCESS_KEY={secret} ./sync.sh'}]}]}})
        for mode in (False, True):
            snap = collect.build_snapshot(args(metadata_only=mode))
            self.assertNotIn(secret, json.dumps(snap))
        full = collect.build_snapshot(args())
        text = json.dumps(full)
        redactions = full['coverage']['privacy']['redactions']
        self.assertGreaterEqual(redactions['contextual'], 1)
        # Non-overlapping: '[REDACTED:context]' does not contain '[REDACTED]'.
        self.assertEqual(redactions, {'pattern_or_key': text.count('[REDACTED]'),
                                      'contextual': text.count(privacy.CONTEXT_TOKEN)})
        self.assertEqual(text.count('[REDACTED'), sum(redactions.values()))

    def test_env_hook_join_runs_before_masking(self):
        app = os.path.join(self.home, 'code', 'app')
        self.write('code/app/.envrc', 'use_pass TOKEN x\n')
        self.write('.claude/settings.json', {'hooks': {'SessionStart': [{'hooks': [
            {'type': 'command', 'command': 'direnv export bash > "$CLAUDE_ENV_FILE"'}]}]}})
        snap = collect.build_snapshot(args(roots=[app], metadata_only=True))
        self.assertIs(snap['readiness'][app.replace(self.home, '~')]['claude_env_hook'], True)

    def test_metadata_only_with_clarity_pilot_is_a_usage_error(self):
        argv = ['collect.py', '--claude-dir', self.claude, '--metadata-only', '--clarity-pilot']
        with mock.patch('sys.argv', argv), contextlib.redirect_stderr(io.StringIO()) as err, \
                self.assertRaises(SystemExit) as cm:
            collect.main()
        self.assertEqual(cm.exception.code, 2)
        self.assertIn('--metadata-only cannot be combined with --clarity-pilot', err.getvalue())

    def test_build_snapshot_refuses_metadata_only_with_clarity_pilot(self):
        with self.assertRaisesRegex(ValueError, 'metadata-only excludes the clarity pilot'):
            collect.build_snapshot(args(metadata_only=True, clarity_pilot=True))

    def test_drift_arguments_stay_full(self):
        ap = argparse.ArgumentParser()
        collect.add_collection_args(ap)  # the argument set drift.py uses
        ns = ap.parse_args(['--claude-dir', self.claude])
        self.assertFalse(hasattr(ns, 'metadata_only'))
        self.assertEqual(collect.build_snapshot(ns)['coverage']['privacy']['mode'], 'full')


def settings_with(tag, hooks=True):
    """A settings file whose every masked location carries a canary made from `tag`."""
    body = {
        'model': 'opus', f'modelSettings': {'opus': {'note': f'zcmodelsetting{tag}'}},
        'statusLine': {'type': 'command', 'command': f'zcstatusline{tag}'},
        'sandbox': {'enabled': True, 'network': {'allowedDomains': [f'zcsandboxvalue{tag}.example.com']}},
        'permissions': {'allow': [f'Bash(sudo zcriskyrule{tag})'], 'deny': [f'Bash(zcdenyrule{tag})']}}
    if hooks:
        body['hooks'] = {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
            {'type': 'command', 'command': f'echo zchookcmd{tag}'},
            {'type': 'command', 'command': f'/nonexistent/zcmissingscript{tag}.sh'},
            {'type': 'http', 'url': f'https://hooks.example.com/zchttppath{tag}', 'headers': {'X-Token': '$TOK'}},
            {'type': 'prompt', 'prompt': f'zcprompthook{tag}'},
            {'type': 'mcp_tool', 'server': f'srv{tag}', 'tool': 'check'}]}]}
    return body


SETTINGS_TAGS = ('', 'managed', 'project', 'local')  # global, managed, project, session-local candidate
CANARIES = tuple(f'{name}{tag}' for tag in SETTINGS_TAGS
                 for name in ('zcmodelsetting', 'zcstatusline', 'zcsandboxvalue', 'zcriskyrule', 'zcdenyrule',
                              'zchookcmd', 'zcmissingscript', 'zchttppath', 'zcprompthook')) + (
    'zcfirstprompt', 'zcfrictionmost', 'zcfriction', 'zccorrection', 'zcmemorydesc', 'zcclaudemd', 'zcrulebody',
    'zcskilldesc', 'zcskillwhen', 'zcskilltools', 'zcskillbody', 'zclastupdate', 'zcpluginskill',
    'zcpluginwhen', 'zcplugincmd', 'zcpluginhttp', 'zcpluginprompt', 'zcpluginhookfm', 'zcskillhooks')


def leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leaves(v, path + (i,))
    else:
        yield path, obj


def shape(obj):
    """Keys and list lengths of `obj`, with every leaf value erased."""
    if isinstance(obj, dict):
        return {k: shape(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [shape(v) for v in obj]
    return None


def pattern_of(path):
    return '.'.join('*' if isinstance(p, int) else p for p in path)


class EndToEnd(PatchedHome):
    """Full mode carries every canary; metadata-only mode carries none. Only `snapshots()` mutates state."""

    def plant(self):
        when = datetime.now(timezone.utc) - timedelta(days=1)
        stamp = when.strftime('%Y-%m-%dT%H:%M:%SZ')
        app = os.path.join(self.home, 'code', 'app')
        self.write('code/app/CLAUDE.md', 'Project notes zcclaudemd\n')
        self.write('.claude/CLAUDE.md', 'Global zcclaudemd\n')
        self.write('.claude/rules/r.md', 'Rule zcrulebody\n')
        self.write('.claude/skills/s/SKILL.md', '---\nname: s\ndescription: zcskilldesc\nwhen_to_use: zcskillwhen\n'
                   'allowed-tools: Bash(zcskilltools)\nhooks: zcskillhooks\n---\nBody zcskillbody\n')
        self.write('.claude/.last-update-result.json', {'status': 'failed', 'error': 'zclastupdate'})
        for i, (sid, prompt, detail) in enumerate((('s1', 'zcfirstprompt', 'zcfriction'),
                                                   ('s2', 'other', 'zcfrictionmost'))):
            self.write(f'.claude/usage-data/session-meta/{sid}.json', {
                'session_id': sid, 'start_time': stamp, 'project_path': app, 'first_prompt': f'please {prompt}',
                'tool_counts': {'Bash': 2}, 'output_tokens': 10 + 100 * (1 - i)})
            self.write(f'.claude/usage-data/facets/{sid}.json', {
                'session_id': sid, 'friction_counts': {'buggy_code': 1 + i}, 'friction_detail': f'{detail} happened',
                'outcome': 'achieved'})
        self.write('.claude/history.jsonl', json.dumps({
            'display': 'no, zccorrection', 'project': app, 'timestamp': int(when.timestamp() * 1000),
            'sessionId': 's1'}) + '\n')
        self.write('.claude/projects/-code-app/memory/note.md', '---\ndescription: zcmemorydesc\n---\n')
        self.write('.claude/projects/-code-app/memory/MEMORY.md', '- note\n')
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1.0.0')

        def plugin_file(*parts):
            return os.path.relpath(os.path.join(root, *parts), self.home)

        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'p@m': [
            {'scope': 'user', 'installPath': root, 'version': '1.0.0'}]}})
        self.write(plugin_file('.claude-plugin', 'plugin.json'), {'name': 'p'})
        self.write(plugin_file('skills', 'x', 'SKILL.md'), '---\nname: x\ndescription: zcpluginskill\n'
                   'when_to_use: zcpluginwhen\nhooks: zcpluginhookfm\n---\nzcpluginskill\n')
        self.write(plugin_file('hooks', 'hooks.json'), {'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
            {'type': 'command', 'command': 'echo zcplugincmd'},
            {'type': 'http', 'url': 'https://hooks.example.com/zcpluginhttp'},
            {'type': 'prompt', 'prompt': 'zcpluginprompt'}]}]}})
        self.write('.claude/settings.json', {**settings_with(''), 'enabledPlugins': {'p@m': True},
                   'permissions': {**settings_with('')['permissions'],
                                   'allow': ['Bash(sudo zcriskyrule)',
                                             f'Bash(export AWS_SECRET_ACCESS_KEY={AWS} && aws s3 ls)']}})
        self.write('managed/managed-settings.json', settings_with('managed'))
        self.write('code/app/.claude/settings.json', settings_with('project'))
        self.write('code/app/.claude/settings.local.json', settings_with('local'))

    def snapshots(self):
        self.plant()
        app = os.path.join(self.home, 'code', 'app')
        return (collect.build_snapshot(args(roots=[app])),
                collect.build_snapshot(args(roots=[app], metadata_only=True)))

    def test_full_mode_carries_every_canary(self):  # proves the fixture reaches every masked location
        full, _ = self.snapshots()
        text = json.dumps(full)
        self.assertEqual([c for c in CANARIES if c not in text], [])
        for section in (full['global']['settings'], full['managed_settings']['settings'],
                        next(iter(full['projects'].values()))['settings'], full['instructions']['settings_candidates']):
            self.assertTrue(section)

    def test_metadata_mode_carries_no_canary_and_no_secret(self):
        full, meta = self.snapshots()
        text = json.dumps(meta)
        self.assertEqual([c for c in CANARIES if c in text], [])
        self.assertNotIn(AWS, text + json.dumps(full))

    def test_metadata_mode_keeps_structure(self):
        full, meta = self.snapshots()
        # Same dict keys, list lengths, kept paths and kept values everywhere except `coverage`, which
        # records the mode itself.
        full, meta = ({k: v for k, v in snap.items() if k != 'coverage'} for snap in (full, meta))
        self.assertEqual(shape(full), shape(meta))
        self.assertEqual(self.kept(full), self.kept(meta))
        self.assertTrue(self.kept(meta))

    @staticmethod
    def kept(snap):
        return sorted((pattern_of(p), v) for p, v in leaves(snap) if isinstance(v, str)
                      and any(privacy.path_matches(p, k) for k in privacy.KEPT_STRING_FIELDS))

    def test_every_string_leaf_is_classified(self):
        _, meta = self.snapshots()
        unclassified = sorted({pattern_of(path) for path, v in leaves(meta) if isinstance(v, str)
                               and not privacy.MARKER_RE.match(v)
                               and not any(privacy.path_matches(path, pat) for pat in privacy.KEPT_STRING_FIELDS)})
        self.assertEqual(unclassified, [], 'classify these in the spec inventory, then mask or keep them')

    def test_context_token_only_where_planted(self):
        full, _ = self.snapshots()
        hits = [v for _, v in leaves(full) if isinstance(v, str) and privacy.CONTEXT_TOKEN in v]
        self.assertTrue(hits)
        self.assertTrue(all('AWS_SECRET_ACCESS_KEY=' in v for v in hits), 'contextual false positive')

    def test_every_handler_type_target_is_masked(self):
        full, meta = self.snapshots()
        types = lambda snap: {h['type']: h['target'] for h in snap['global']['settings'][0]['hook_handlers']}  # noqa: E731
        self.assertEqual(set(types(full)), {'command', 'http', 'prompt', 'mcp_tool'})
        self.assertEqual({t: privacy.MARKER_RE.match(v) is not None for t, v in types(meta).items()},
                         {t: True for t in types(full)})


class PathMatching(unittest.TestCase):
    def test_star_matches_one_key_or_index(self):
        self.assertTrue(privacy.path_matches(('a', 3, 'b'), ('a', '*', 'b')))
        self.assertFalse(privacy.path_matches(('a', 'b'), ('a', '*', 'b')))
        self.assertFalse(privacy.path_matches(('a', 'b', 'c'), ('a', '*')))

    def test_literals_never_match_list_indices(self):
        self.assertFalse(privacy.path_matches(('a', 0), ('a', '0')))

    def test_double_star_matches_any_remainder(self):
        self.assertTrue(privacy.path_matches(('a', 1, 'b', 'c'), ('a', '**')))
        self.assertTrue(privacy.path_matches(('a',), ('a', '**')))
        self.assertFalse(privacy.path_matches(('b', 'c'), ('a', '**')))


if __name__ == '__main__':
    unittest.main()
