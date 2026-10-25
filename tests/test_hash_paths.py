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

import test_privacy
from test_privacy import PatchedHome, args  # also puts the plugin scripts directory on sys.path
import collect
import ledger
import privacy
import prune_permissions
import snapshot_contract

TAG_RE = re.compile(r'h:[0-9a-f]{12}\Z')
USER, PROJ = 'zcuserhome', 'zcprojalpha'
LOOP_CANARIES = ('zcloopfile', 'zcloopcmd')  # planted in a loop transcript; must never reach any snapshot
CANARIES = (USER, PROJ, 'zcmemfile', 'zcauditname', 'zcsdkfile', 'zcpluginroot', 'zcmissingdir', 'zcenvmodule',
            'zcotherproj', 'zcmodfile')


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
        self.write(os.path.relpath(os.path.join(plugin, 'hooks', 'zcmodfile.js'), self.home), "on('tool.call', f)\n")
        self.write(os.path.relpath(os.path.join(plugin, 'hooks', 'hooks.json'), self.home), {'modules': ['zcmodfile.js'], 'hooks': {
            'PostToolUse': [{'matcher': 'Edit', 'hooks': [{'type': 'command', 'command': 'echo hi'}]}],
            'PreToolUse': [{'matcher': 'Bash', 'hooks': [
                {'type': 'command', 'command': '"${CLAUDE_PLUGIN_ROOT}/hooks/zcdecider.sh"'}]}]}})
        self.write(os.path.relpath(os.path.join(plugin, 'hooks', 'zcdecider.sh'), self.home),
                   'echo \'{"permissionDecision": "allow"}\'\n')
        self.write(f'code/{PROJ}/.mcp.json', {'mcpServers': {'srv': {'command': 'npx'}}})
        self.write(f'code/{PROJ}/src/zcenvmodule.py', 'import os\nX = os.environ["ZC_NEEDED"]\n')
        other = re.sub(r'[^A-Za-z0-9]', '-', os.path.join(self.home, 'code', 'zcotherproj'))
        self.write(f'.claude/projects/{other}/memory/zcmemfile.md', '---\ndescription: d\n---\n')
        loop = [{'type': 'user', 'timestamp': stamp, 'message': {'content': 'fix it'}}]
        for i in range(3):  # a failing edit-and-test loop whose command and file name carry canaries
            loop += [{'type': 'assistant', 'timestamp': stamp, 'message': {'id': f'l{i}', 'content': [
                {'type': 'tool_use', 'id': f'e{i}', 'name': 'Edit', 'input': {'file_path': f'{self.root}/src/zcloopfile.py'}},
                {'type': 'tool_use', 'id': f'c{i}', 'name': 'Bash', 'input': {'command': 'make zcloopcmd'}}]}},
                     {'type': 'user', 'timestamp': later, 'toolUseResult': {}, 'message': {'content': [
                         {'type': 'tool_result', 'tool_use_id': f'c{i}', 'is_error': True, 'content': 'Exit code 1'}]}}]
        self.write(f'.claude/projects/{self.key}/loop.jsonl', '\n'.join(map(json.dumps, loop)))
        other_key = re.sub(r'[^A-Za-z0-9]', '-', os.path.join(self.home, 'code', 'zcotherproj'))
        self.write(f'.claude/projects/{other_key}/loop.jsonl', '\n'.join(map(json.dumps, loop)))  # a project not collected
        for i in range(3):  # three assistant turns with usage give a per-project context baseline
            self.write(f'.claude/projects/{self.key}/b{i}.jsonl', json.dumps({
                'type': 'assistant', 'sessionId': f'b{i}', 'timestamp': stamp,
                'message': {'content': [], 'usage': {'input_tokens': 10 + i}}}))

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

    def test_failure_loop_text_is_never_stored_and_its_project_key_is_hashed(self):
        for mode in ({}, {'hash_paths': True}, {'hash_paths': True, 'metadata_only': True}):
            with self.subTest(mode=mode):
                snap = self.snap(**mode)
                loops = snap['transcripts']['failure_loops']
                self.assertEqual((loops['turns_with_loop'], loops['command_heads']), (2, {'make': 2}))
                self.assertEqual([c for c in LOOP_CANARIES if c in json.dumps(snap)], [])
                if mode.get('hash_paths'):
                    self.assertEqual([k for k in loops['by_project'] if not TAG_RE.match(k)], [])

    def test_per_run_salt_snapshot_hides_canaries_too(self):
        self.assertEqual([c for c in CANARIES if c in json.dumps(self.snap(hash_paths=True))], [])

    def test_dead_refs_are_hashed_but_the_excerpt_text_is_free_text(self):
        plain, hashed = self.snap(), self.hashed()
        self.assertEqual(plain['projects'][f'~/code/{PROJ}']['claude_md_dead_refs'], ['docs/zcdeadref.md'])
        (refs,) = [p['claude_md_dead_refs'] for p in hashed['projects'].values()]
        self.assertEqual([bool(TAG_RE.match(r)) for r in refs], [True])
        self.assertIn('zcdeadref', json.dumps(hashed))  # full mode keeps the CLAUDE.md excerpt itself
        self.assertNotIn('zcdeadref', json.dumps(self.hashed(metadata_only=True)))

    def decider_handler(self, snap):
        (h,) = [h for p in snap['extensions']['plugins'] for c in p['components'] for h in c.get('handlers', [])
                if h.get('decides_permissions')]
        return h

    def test_decision_file_is_a_plugin_path_that_is_hashed_and_masked(self):
        # The hook command text is free text (it names the script too); the new decision_file field is
        # a path family of its own.
        self.assertEqual(self.decider_handler(self.snap())['decision_file'], 'hooks/zcdecider.sh')
        self.assertRegex(self.decider_handler(self.hashed())['decision_file'], TAG_RE)
        meta = self.decider_handler(self.hashed(metadata_only=True))
        self.assertRegex(meta['decision_file'], privacy.MARKER_RE)
        self.assertEqual((meta['decides_permissions'], meta['decision_basis']), (True, 'static_scan'))

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
        self.assertIn(tag, snap['memory']['by_project'])  # transcript key of the root maps to its tag
        self.assertEqual(set(snap['transcripts']['env_error_hits_by_project']), {tag})
        self.assertEqual(set(snap['transcripts']['test_run_seconds_by_project']), {tag})
        self.assertIn(tag, snap['transcripts']['failure_loops']['by_project'])

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


class Review(CanaryHome):
    """Findings of the 0.11.0 M4 review: joins that leaked or broke, and the fail-closed sweep."""

    def pair(self, snap):
        (pair,) = snap['memory']['similar_across_projects']
        return pair

    def test_unhashed_similar_pairs_keep_their_shape_and_add_parts(self):
        pair = self.pair(self.snap())
        other = re.sub(r'[^A-Za-z0-9]', '-', os.path.join(self.home, 'code', 'zcotherproj'))
        self.assertEqual({pair['a'], pair['b']}, {f'{self.key}/zcmemfile.md', f'{other}/zcmemfile.md'})
        self.assertEqual((pair['shared'], pair['shared_count']), (['zcmemfile'], 1))
        self.assertEqual({pair['a_file'], pair['b_file']}, {'zcmemfile.md'})

    def test_similar_pairs_share_tags_with_projects_and_memory_files(self):
        for mode in ({}, {'metadata_only': True}):
            with self.subTest(mode=mode):
                snap = self.hashed(**mode)
                pair = self.pair(snap)
                (root_tag,) = snap['projects']
                (entry,) = snap['memory']['by_project'][root_tag]['entries']
                self.assertIn(root_tag, (pair['a_project'], pair['b_project']))
                self.assertEqual({pair['a_file'], pair['b_file']}, {entry['file']})
                self.assertEqual(pair['shared'], [])
                self.assertEqual(pair['shared_count'], 1)
                for k in ('a', 'b', 'a_project', 'b_project', 'a_file', 'b_file'):
                    self.assertRegex(pair[k], TAG_RE)
                self.assertNotIn('zcmemfile', json.dumps(snap['memory']['similar_across_projects']))

    def test_env_undeclared_files_are_hashed(self):
        for mode in ({}, {'metadata_only': True}):
            with self.subTest(mode=mode):
                snap = self.hashed(**mode)
                (readiness,) = snap['readiness'].values()
                files = [f for u in readiness['env']['undeclared'] for f in u['files']]
                self.assertTrue(files)
                self.assertEqual([f for f in files if not TAG_RE.match(f)], [])
                self.assertGreater(snap['coverage']['privacy']['hashed_path_families']['referenced_files'], 0)

    def test_context_baseline_project_gets_the_root_tag(self):
        for mode in ({}, {'metadata_only': True}):
            with self.subTest(mode=mode):
                snap = self.hashed(**mode)
                (root_tag,) = snap['projects']
                rows = snap['transcripts']['context_baseline_by_project_median']
                self.assertEqual([r[0] for r in rows], [root_tag])

    def test_collection_scope_project_joins_with_projects(self):
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.home)  # a relative --project: its own hash would not equal the resolved root's
        snap = collect.build_snapshot(args(scope='project', project=f'code/{PROJ}', hash_paths=True,
                                           hash_salt_file=self.salt_file))
        self.assertEqual([snap['collection_scope']['project']], list(snap['projects']))

    def test_scrub_counts_are_recorded(self):
        fams = self.hashed()['coverage']['privacy']['hashed_path_families']
        self.assertGreater(fams['free_text_scrubbed'], 0)  # the hook command carries the project root
        self.assertEqual(fams['other_paths'], 0)

    def test_scrub_respects_path_boundaries(self):
        h = privacy.PathHasher(b'k' * 16, '/h/u')
        snap = {'x': 'run /h/u/code/app2/x then /h/u/code/app/y; "/h/u/code/app"'}
        privacy.scrub_known_paths(snap, h, privacy.path_needles('/h/u', [], ['/h/u/code/app']),
                                  ['/h/u', '/h/u/code/app'])
        app, home = h('/h/u/code/app'), h('/h/u')
        self.assertEqual(snap['x'], f'run {home}/code/app2/x then {app}/y; "{app}"')

    def test_scrub_treats_any_non_name_character_as_a_boundary(self):
        h = privacy.PathHasher(b'k' * 16, '/h/u')
        app, home = h('/h/u/code/app'), h('/h/u')
        cases = {'cd /h/u/code/app&&ls': f'cd {app}&&ls', 'x >/h/u/code/app>log': f'x >{app}>log',
                 '/h/u/code/app|wc': f'{app}|wc', 'see /h/u/code/app.': f'see {app}.',
                 '/h/u/code/app\\x': f'{app}\\x', '/h/u/code/app.bak/x': f'{home}/code/app.bak/x',
                 '/h/u/code/app-old': f'{home}/code/app-old'}
        for raw, want in cases.items():
            snap = {'x': raw}
            privacy.scrub_known_paths(snap, h, privacy.path_needles('/h/u', [], ['/h/u/code/app']),
                                      ['/h/u', '/h/u/code/app'])
            self.assertEqual(snap['x'], want, raw)

    def test_paths_frontmatter_is_hashed(self):
        h = privacy.PathHasher(b'k' * 16, '/h/u')
        raw = '\n  - "src/zcpkg/core.py"\n  - "tests/**"'
        snap = {'instructions': {'entries': [{'frontmatter': {'paths': raw, 'name': 'zcrule'}}]},
                'extensions': {'plugins': [{'components': [{'frontmatter': {'paths': ['src/zcpkg/**']}}]}]}}
        privacy.hash_paths(snap, h, [])
        fm = snap['instructions']['entries'][0]['frontmatter']
        self.assertEqual(fm, {'paths': h(raw), 'name': 'zcrule'})
        self.assertEqual(snap['extensions']['plugins'][0]['components'][0]['frontmatter']['paths'],
                         [h('src/zcpkg/**')])

    def test_scrub_maps_dash_encoded_roots_to_the_root_tag(self):
        h = privacy.PathHasher(b'k' * 16, '/h/u')
        snap = {'m': {'x': 'dir -h-u-code-app/memory', '-h-u-code-app': 1}}
        privacy.scrub_known_paths(snap, h, privacy.path_needles('/h/u', [], ['/h/u/code/app']),
                                  ['/h/u', '/h/u/code/app'])
        self.assertEqual(snap, {'m': {'x': f"dir {h('/h/u/code/app')}/memory", h('/h/u/code/app'): 1}})

    def test_unclaimed_path_like_kept_strings_and_keys_are_hashed(self):
        h = privacy.PathHasher(b'k' * 16, '/h/u')
        snap = {'collection_scope': {'new_field': 'a/b/c', 'url': 'https://x.example/p', 'basis': 'collected_chars/4',
                                     'prose': 'one/two words', 'word': 'plain', 'nested': {'rel/key': ['d\\e']}}}
        counts = privacy.hash_paths(snap, h, [])
        scope = snap['collection_scope']
        self.assertEqual(scope['new_field'], h('a/b/c'))
        self.assertEqual((scope['url'], scope['basis'], scope['prose'], scope['word']),
                         ('https://x.example/p', 'collected_chars/4', 'one/two words', 'plain'))
        self.assertEqual(scope['nested'], {h('rel/key'): [h('d\\e')]})
        self.assertEqual(counts['other_paths'], 3)


class FailClosed(PatchedHome):
    """Every path-like string in a hashed snapshot is a tag or a documented exception."""

    def plant(self):
        test_privacy.EndToEnd.plant(self)
        stamp = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        self.write('code/app/src/zcenv.py', 'import os\nX = os.environ["ZC_NEEDED"]\n')
        self.write('.claude/projects/-code-zcotherproj/memory/note.md', '---\ndescription: d\n---\n')
        for i in range(3):
            self.write(f'.claude/projects/-code-app/b{i}.jsonl', json.dumps({
                'type': 'assistant', 'sessionId': f'b{i}', 'timestamp': stamp,
                'message': {'content': [], 'usage': {'input_tokens': 10 + i}}}))

    @staticmethod
    def documented_exception(path, value, full_mode):
        if '://' in value or privacy.BASIS_RE.match(value):  # URL origins and targets, `collected_chars/4`
            return True
        if any(c.isspace() for c in value) and (path[-1] == 'mcp_configured_but_unused_note'
                                                or (len(path) > 2 and path[1] == 'limitations')
                                                or path[0] == 'coverage' and path[1] == 'limitations'):
            return True  # fixed explanatory sentences
        return full_mode and ('hook_commands' in path or path[-1] == 'target')  # documented free text

    def strays(self, snap, full_mode):
        found = []

        def walk(o, path):
            if isinstance(o, str):
                if privacy.path_like(o) and not TAG_RE.match(o) and not self.documented_exception(path, o, full_mode):
                    found.append(('value', path, o))
            elif isinstance(o, dict):
                for k, v in o.items():
                    if privacy.path_like(k) and not TAG_RE.match(k):
                        found.append(('key', path, k))
                    walk(v, path + (k,))
            elif isinstance(o, list):
                for i, v in enumerate(o):
                    walk(v, path + (i,))
        walk(snap, ())
        return found

    def test_no_path_like_string_survives_outside_tags_and_documented_exceptions(self):
        self.plant()
        app = os.path.join(self.home, 'code', 'app')
        for mode in ({}, {'metadata_only': True}):
            with self.subTest(mode=mode):
                snap = collect.build_snapshot(args(roots=[app], hash_paths=True, **mode))
                self.assertEqual(self.strays(snap, not mode), [])
                self.assertTrue(snap['memory']['similar_across_projects'])
                self.assertTrue(snap['transcripts']['context_baseline_by_project_median'])
                self.assertTrue(any(u['files'] for r in snap['readiness'].values() for u in r['env']['undeclared']))


class Coverage(CanaryHome):
    def test_records_families_and_salt_kind_but_never_the_salt(self):
        for kw, kind in (({}, 'file'), ({'hash_salt_file': None}, 'per_run')):
            snap = self.hashed(**kw)
            p = snap['coverage']['privacy']
            self.assertIs(p['hashed_paths'], True)
            self.assertEqual(p['hash_salt'], kind)
            self.assertEqual(set(p['hashed_path_families']), {*privacy.PATH_FAMILIES, *privacy.EXTRA_COUNTERS})
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
        self.assertEqual([f for f in (*privacy.PATH_FAMILIES, *privacy.EXTRA_COUNTERS) if f'`{f}`' not in text], [])
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
