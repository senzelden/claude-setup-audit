"""--hash-paths: path-like kept strings become `h:<12 hex>` HMAC tags. Fake homes only."""
import contextlib
import io
import json
import os
import re
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from test_privacy import PatchedHome, args  # also puts the plugin scripts directory on sys.path
import collect
import ledger
import privacy
import prune_permissions
import snapshot_contract

TAG_RE = re.compile(r'h:[0-9a-f]{12}\Z')
USER, PROJ = 'zcuserhome', 'zcprojalpha'
CANARIES = (USER, PROJ, 'zcmemfile', 'zcauditname', 'zcsdkfile', 'zcpluginroot', 'zcmissingdir')


class CanaryHome(PatchedHome):
    """HOME is `<tmp>/zcuserhome`, so the 'username' sits in every absolute and dash-encoded path."""

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp.name, USER)
        self.claude = os.path.join(self.home, '.claude')
        os.makedirs(os.path.join(self.claude, 'projects'))
        collect.HOME, collect.CLAUDE = self.home, self.claude
        self.root = os.path.join(self.home, 'code', PROJ)
        self.key = re.sub(r'[^A-Za-z0-9]', '-', self.root)
        self.salt_file = os.path.join(self.tmp.name, 'salt')
        with open(self.salt_file, 'w') as f:
            f.write('a-long-enough-test-salt-value-one\n')
        self.plant()

    def plant(self):
        when = datetime.now(timezone.utc) - timedelta(days=1)
        stamp = when.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        later = (when + timedelta(seconds=30)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
        self.write(f'code/{PROJ}/CLAUDE.md', 'See `docs/zcdeadref.md`\n')
        self.write(f'code/{PROJ}/docs/README.md', 'docs')
        self.write(f'code/{PROJ}/src/zcsdkfile.py', 'from anthropic import Anthropic\nAnthropic().messages.create()\n')
        self.write(f'code/{PROJ}/.claude/settings.json', {
            'permissions': {'additionalDirectories': [os.path.join(self.home, 'zcmissingdir')]},
            'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
                {'type': 'command', 'command': f'bash {self.root}/run.sh'}]}]}})
        self.write('.claude/settings.json', {'model': 'opus', 'hooks': {'SessionStart': [{'hooks': [
            {'type': 'command', 'command': f'{self.home}/hooks/missing.sh'}]}]},
            'enabledPlugins': {'p@m': True}})
        self.write(f'.claude/projects/{self.key}/memory/zcmemfile.md', '---\ndescription: d\n---\n')
        self.write(f'.claude/projects/{self.key}/memory/MEMORY.md', '- note\n')
        self.write('.claude/audits/zcauditname-2026-10-01.md', 'old report')
        self.write('.claude/usage-data/session-meta/s1.json', {
            'session_id': 's1', 'start_time': stamp, 'project_path': self.root, 'first_prompt': 'hi',
            'tool_counts': {'Bash': 1}, 'output_tokens': 5})
        self.write('.claude/history.jsonl', json.dumps({
            'display': 'no, wrong', 'project': self.root, 'timestamp': int(when.timestamp() * 1000),
            'sessionId': 's1'}) + '\n')
        records = [
            {'type': 'assistant', 'sessionId': 't1', 'timestamp': stamp, 'message': {'content': [
                {'type': 'tool_use', 'id': 't1', 'name': 'Bash', 'input': {'command': 'uv run pytest -q'}}]}},
            {'type': 'user', 'sessionId': 't1', 'timestamp': later, 'message': {'content': [
                {'type': 'tool_result', 'tool_use_id': 't1', 'content': "KeyError: 'DATABASE_URL'"}]}}]
        self.write(f'.claude/projects/{self.key}/t1.jsonl', '\n'.join(map(json.dumps, records)))
        plugin = os.path.join(self.claude, 'plugins', 'cache', 'm', 'zcpluginroot', '1.0.0')
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {'p@m': [
            {'scope': 'user', 'installPath': plugin, 'version': '1.0.0'}]}})
        self.write(os.path.relpath(os.path.join(plugin, '.claude-plugin', 'plugin.json'), self.home), {'name': 'p'})
        self.write(os.path.relpath(os.path.join(plugin, 'hooks', 'hooks.json'), self.home), {'hooks': {
            'PostToolUse': [{'matcher': 'Edit', 'hooks': [{'type': 'command', 'command': 'echo hi'}]}]}})
        self.write(f'code/{PROJ}/.mcp.json', {'mcpServers': {'srv': {'command': 'npx'}}})

    def snap(self, **kw):
        return collect.build_snapshot(args(roots=[self.root], **kw))

    def hashed(self, **kw):
        kw.setdefault('hash_salt_file', self.salt_file)
        return self.snap(hash_paths=True, **kw)


class Canaries(CanaryHome):
    def test_unhashed_snapshots_carry_the_canaries(self):  # the fixture reaches every family
        text = json.dumps(self.snap())
        self.assertEqual([c for c in CANARIES if c not in text], [])

    def test_no_canary_survives_in_either_mode(self):
        for mode in ({}, {'metadata_only': True}):
            with self.subTest(mode=mode):
                text = json.dumps(self.hashed(**mode))
                self.assertEqual([c for c in CANARIES if c in text], [])
                self.assertNotIn(self.tmp.name, text)

    def test_per_run_salt_snapshot_hides_canaries_too(self):
        self.assertEqual([c for c in CANARIES if c in json.dumps(self.snap(hash_paths=True))], [])

    def test_dead_refs_are_hashed_but_the_excerpt_text_is_free_text(self):
        plain, hashed = self.snap(), self.hashed()
        self.assertEqual(plain['projects'][f'~/code/{PROJ}']['claude_md_dead_refs'], ['docs/zcdeadref.md'])
        (refs,) = [p['claude_md_dead_refs'] for p in hashed['projects'].values()]
        self.assertEqual([bool(TAG_RE.match(r)) for r in refs], [True])
        self.assertIn('zcdeadref', json.dumps(hashed))  # full mode keeps the CLAUDE.md excerpt itself
        self.assertNotIn('zcdeadref', json.dumps(self.hashed(metadata_only=True)))

    def test_hashed_values_have_the_tag_shape(self):
        snap = self.hashed()
        for key in snap['projects']:
            self.assertRegex(key, TAG_RE)
        self.assertRegex(snap['coverage']['projects_collected'][0], TAG_RE)
        self.assertRegex(snap['global']['settings'][0]['path'], TAG_RE)


class Joins(CanaryHome):
    def test_project_root_joins_survive_hashing(self):
        snap = self.hashed()
        (tag,) = snap['projects']
        self.assertEqual(set(snap['readiness']), {tag})
        self.assertEqual(snap['coverage']['projects_collected'], [tag])
        self.assertEqual(snap['collection_scope']['projects_collected'], 1)
        self.assertEqual(snap['usage']['heaviest_sessions'][0]['project'], tag)
        self.assertEqual(snap['corrections']['samples'][0]['project'], tag)
        self.assertEqual(snap['corrections']['by_project'][0][0], tag)
        self.assertEqual(snap['usage']['sessions_per_project'][0][0], tag)
        self.assertEqual(set(snap['memory']['by_project']), {tag})  # transcript key of the root maps to its tag
        self.assertEqual(set(snap['transcripts']['env_error_hits_by_project']), {tag})
        self.assertEqual(set(snap['transcripts']['test_run_seconds_by_project']), {tag})

    def test_readiness_env_join_ran_before_hashing(self):
        plain, hashed = self.snap(), self.hashed()
        (rp,), (rh,) = plain['readiness'].values(), hashed['readiness'].values()
        self.assertEqual(rp['env_error_hits'], 1)
        self.assertEqual(rh['env_error_hits'], 1)
        self.assertEqual(rp['test_run_seconds'], rh['test_run_seconds'])

    def test_equal_inputs_hash_equal_across_runs_with_a_salt_file(self):
        first, second = self.hashed(), self.hashed()
        self.assertEqual(list(first['projects']), list(second['projects']))
        self.assertEqual(first['global']['settings'][0]['path'], second['global']['settings'][0]['path'])

    def test_home_relative_and_absolute_forms_hash_equal(self):
        h = privacy.PathHasher(b'k' * 16, '/h/u')
        self.assertEqual(h('~/code/app'), h('/h/u/code/app'))
        self.assertEqual(h('/h/u/code/app/'), h('/h/u/code/app'))
        self.assertNotEqual(h('/h/u/code/app'), h('/h/u/code/other'))

    def test_different_salts_differ(self):
        other = os.path.join(self.tmp.name, 'salt2')
        with open(other, 'w') as f:
            f.write('another-long-enough-salt-value-two')
        a, b = self.hashed(), self.hashed(hash_salt_file=other)
        self.assertNotEqual(list(a['projects']), list(b['projects']))

    def test_per_run_salts_differ(self):
        a, b = self.snap(hash_paths=True), self.snap(hash_paths=True)
        self.assertNotEqual(list(a['projects']), list(b['projects']))


class Coverage(CanaryHome):
    def test_records_families_and_salt_kind_but_never_the_salt(self):
        for kw, kind in (({}, 'file'), ({'hash_salt_file': None}, 'per_run')):
            snap = self.hashed(**kw)
            p = snap['coverage']['privacy']
            self.assertIs(p['hashed_paths'], True)
            self.assertEqual(p['hash_salt'], kind)
            self.assertEqual(set(p['hashed_path_families']), set(privacy.PATH_FAMILIES))
            self.assertNotIn('a-long-enough-test-salt', json.dumps(snap))
            snapshot_contract.validate_snapshot(snap)

    def test_unhashed_snapshot_says_nothing_about_hashing(self):
        self.assertNotIn('hashed_paths', self.snap()['coverage']['privacy'])

    def test_metadata_only_and_hash_paths_together(self):
        snap = self.hashed(metadata_only=True)
        p = snap['coverage']['privacy']
        self.assertEqual((p['mode'], p['hashed_paths']), ('metadata-only', True))
        self.assertTrue(p['replaced_fields'])
        self.assertEqual(p['hashed_path_families']['project_roots'] > 0, True)

    def test_limitation_mentions_hashed_paths(self):
        self.assertTrue(any('hash' in x.lower() for x in self.hashed()['coverage']['limitations']))


class Vocabulary(CanaryHome):
    def test_fixed_vocabulary_is_never_hashed(self):
        snap = self.hashed()
        g = snap['global']['settings'][0]
        self.assertEqual(g['model'], 'opus')
        self.assertIn('hooks', g['keys'])
        self.assertEqual({h['event'] for h in g['hook_handlers']}, {'SessionStart'})
        self.assertEqual(snap['global']['installed_plugins'], ['p@m'])
        self.assertEqual(snap['snapshot_version'], 1)

    def test_hashing_leaves_vocabulary_only_data_unchanged(self):
        snap = {'global': {'settings': [{'scope': 'user', 'model': 'opus', 'keys': ['hooks'], 'env_keys': ['A_B'],
                                         'hook_handlers': [{'event': 'PreToolUse', 'matcher': 'Bash'}]}]},
                'transcripts': {'request_params': {'basis': 'x'}}}
        before = json.dumps(snap)
        privacy.hash_paths(snap, privacy.PathHasher(b'k' * 16, '/h'), [])
        self.assertEqual(json.dumps(snap), before)

    def test_no_path_pattern_targets_api_vocabulary(self):
        banned = {'event', 'model', 'keys', 'env_keys', 'matcher', 'type', 'scope', 'name', 'tool', 'fingerprint'}
        for pats in list(privacy.PATH_FAMILIES.values()):
            for pat in pats['leaves'] + pats.get('maybe', ()) + pats.get('keys', ()):
                self.assertNotIn(pat[-1], banned, pat)

    def test_already_hashed_values_are_not_rehashed(self):
        h = privacy.PathHasher(b'k' * 16, '/h')
        tag = h('/h/x')
        self.assertEqual(h(tag), tag)


class SaltFile(CanaryHome):
    def run_main(self, *argv):
        err = io.StringIO()
        with mock.patch.object(sys, 'argv', ['collect.py', '--days', '30', '--scope', 'global', *argv]), \
                contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                collect.main()
        return cm.exception.code, err.getvalue()

    def test_missing_salt_file_fails_and_is_never_created(self):
        path = os.path.join(self.tmp.name, 'nope')
        code, err = self.run_main('--hash-paths', '--hash-salt-file', path)
        self.assertNotIn(code, (0, None))
        self.assertIn('salt', err)
        self.assertFalse(os.path.exists(path))

    def test_empty_whitespace_short_and_unreadable_salts_fail(self):
        for name, content in (('empty', ''), ('blank', ' \n\n'), ('short', 'abc\n')):
            path = os.path.join(self.tmp.name, name)
            with open(path, 'w') as f:
                f.write(content)
            with self.subTest(name=name):
                code, err = self.run_main('--hash-paths', '--hash-salt-file', path)
                self.assertNotIn(code, (0, None))
                self.assertIn('salt', err)
        code, err = self.run_main('--hash-paths', '--hash-salt-file', self.tmp.name)  # a directory
        self.assertNotIn(code, (0, None))
        self.assertIn('salt', err)

    def test_salt_file_without_hash_paths_is_a_usage_error(self):
        code, err = self.run_main('--hash-salt-file', self.salt_file)
        self.assertNotIn(code, (0, None))
        self.assertIn('--hash-paths', err)

    def test_build_snapshot_raises_for_a_bad_salt_file(self):
        with self.assertRaises(privacy.SaltError):
            self.snap(hash_paths=True, hash_salt_file=os.path.join(self.tmp.name, 'nope'))

    def test_trailing_newline_does_not_change_the_salt(self):
        other = os.path.join(self.tmp.name, 'nonl')
        with open(other, 'w') as f:
            f.write('a-long-enough-test-salt-value-one')
        self.assertEqual(list(self.hashed()['projects']), list(self.hashed(hash_salt_file=other)['projects']))

    def test_cli_writes_a_valid_hashed_snapshot(self):
        out = os.path.join(self.tmp.name, 'snap.json')
        with mock.patch.object(sys, 'argv', ['collect.py', '--scope', 'project', '--project', self.root, '--out', out,
                                              '--hash-paths', '--hash-salt-file', self.salt_file]), \
                contextlib.redirect_stdout(io.StringIO()):
            collect.main()
        with open(out) as f:
            text = f.read()
        self.assertEqual([c for c in CANARIES if c in text], [])
        snapshot_contract.validate_snapshot(json.loads(text))


class Consumers(CanaryHome):
    def test_ledger_refuses_a_hashed_project_scope_snapshot(self):
        snap = collect.build_snapshot(args(scope='project', project=self.root, hash_paths=True))
        with self.assertRaises(ledger.LedgerError):
            ledger.snapshot_scope(snap)

    def test_ledger_still_scopes_a_hashed_global_snapshot(self):
        snap = collect.build_snapshot(args(scope='global', hash_paths=True))
        self.assertEqual(ledger.snapshot_scope(snap)[1], set())

    def test_prune_permissions_refuses_a_hashed_snapshot(self):
        out = os.path.join(self.tmp.name, 's.json')
        with open(out, 'w') as f:
            json.dump(self.hashed(), f)
        with self.assertRaises(SystemExit):
            prune_permissions.settings_files(out)

    def test_query_snapshot_banner_mentions_hashed_paths(self):
        import query_snapshot
        out = os.path.join(self.tmp.name, 's.json')
        with open(out, 'w') as f:
            json.dump(self.hashed(), f)
        buf = io.StringIO()
        with mock.patch.object(sys, 'argv', ['q', out, 'coverage', 'privacy']), contextlib.redirect_stdout(buf):
            query_snapshot.main()
        self.assertIn('hashed paths', buf.getvalue())


class Scrub(CanaryHome):
    def test_known_roots_inside_free_text_are_replaced_in_full_mode(self):
        text = json.dumps(self.hashed())
        self.assertNotIn(self.root, text)
        self.assertNotIn(self.home, text)
        self.assertIn('/run.sh', text)  # the rest of the collected command text is kept

    def test_scrub_ignores_tiny_needles(self):
        snap = {'x': 'a/b', 'k/': 1}
        privacy.scrub_known_paths(snap, privacy.PathHasher(b'k' * 16, '/'), ['/'])
        self.assertEqual(snap, {'x': 'a/b', 'k/': 1})


class Docs(unittest.TestCase):
    SKILL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         'plugins', 'setup-audit', 'skills', 'setup-audit')

    def read(self, *parts):
        with open(os.path.join(self.SKILL, *parts), encoding='utf-8') as f:
            return f.read()

    def test_snapshot_format_lists_every_family(self):
        text = self.read('references', 'snapshot-format.md')
        self.assertEqual([f for f in privacy.PATH_FAMILIES if f'`{f}`' not in text], [])
        for word in ('hashed_paths', 'hash_salt', '--hash-salt-file', 'h:<12 hex>'):
            self.assertIn(word, text)

    def test_skill_offers_the_flags_and_never_creating_a_salt(self):
        skill = self.read('SKILL.md')
        self.assertIn('| `hash_paths` |', skill)
        self.assertIn('--hash-paths', skill)
        self.assertIn('--hash-salt-file', skill)
        self.assertIn('Never create or print a salt', skill)

    def test_coverage_documents_what_degrades(self):
        self.assertIn('`--hash-paths`', self.read('references', 'coverage.md'))


if __name__ == '__main__':
    unittest.main()
