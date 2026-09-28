"""Bounded instruction inventory using temporary homes and repositories."""
import os
import subprocess
from unittest import mock
from test_collect import FakeHome, collect
import inventory


class InstructionInventory(FakeHome):
    def scan(self, roots=None, contexts=None):
        return inventory.collect_instructions(self.home, self.claude, roots or [], contexts or [],
                                               None, collect.redact, collect.summarize_settings)

    def test_rules_local_skills_and_metadata(self):
        root = os.path.join(self.home, 'repo')
        self.write('repo/CLAUDE.local.md', 'Private project instructions')
        self.write('repo/.claude/rules/nested/api.md', '---\npaths:\n  - "src/**"\n---\nUse tests.')
        self.write('repo/.claude/skills/test/SKILL.md', '---\nallowed-tools: Bash(*)\nhooks:\n  SessionStart: []\n---\nRun tests.')
        result = self.scan([root])
        self.assertEqual({e['kind'] for e in result['entries']}, {'instruction', 'rule', 'skill'})
        rule = next(e for e in result['entries'] if e['kind'] == 'rule')
        self.assertIn('src/**', rule['frontmatter']['paths'])
        skill = next(e for e in result['entries'] if e['kind'] == 'skill')
        self.assertEqual(skill['frontmatter']['allowed-tools'], 'Bash(*)')
        self.assertEqual(skill['active_state'], 'unknown')

    def test_symlinks_imports_and_bounds(self):
        root = os.path.join(self.home, 'repo')
        secret = self.write('outside.md', 'DO NOT COLLECT')
        self.write('repo/CLAUDE.md', '@../outside.md\n' + 'x' * 40000)
        os.symlink(secret, os.path.join(root, 'CLAUDE.local.md'))
        result = self.scan([root])
        self.assertNotIn('DO NOT COLLECT', str(result))
        self.assertTrue(next(e for e in result['entries'] if e['source'].endswith('/CLAUDE.md'))['truncated'])
        self.assertTrue(any(e['status'] == 'not_checked' for e in result['entries']))
        with mock.patch.object(inventory, 'MAX_FILES', 1):
            self.assertTrue(any(s.get('reason') == 'file_limit' for s in self.scan([root])['sources']))

    def test_global_does_not_walk_project_and_ancestors_do_not_scan_siblings(self):
        self.write('repo/CLAUDE.md', 'PROJECT')
        self.write('sibling/CLAUDE.md', 'UNRELATED')
        self.write('CLAUDE.md', 'ANCESTOR')
        root = os.path.join(self.home, 'repo')
        self.assertNotIn('PROJECT', str(self.scan()))
        result = self.scan([root], [inventory.git_context(root)])
        self.assertIn('ANCESTOR', str(result))
        self.assertNotIn('UNRELATED', str(result))

    def test_worktree_discovery_retains_cwd_and_main_local_settings(self):
        root = os.path.join(self.home, 'repo')
        os.makedirs(root)
        def git(*args):
            subprocess.run(['git', '-C', root, *args], check=True, capture_output=True)
        git('init')
        git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '--allow-empty', '-m', 'init')
        worktree = os.path.join(self.home, 'linked')
        git('worktree', 'add', '-b', 'test', worktree)
        cwd = os.path.join(worktree, 'sub')
        os.makedirs(cwd)
        self.write('linked/CLAUDE.local.md', 'WORKTREE')
        self.write('repo/.claude/settings.local.json', {'permissions': {'allow': ['Bash(*)']}})
        self.write('.claude/projects/test/session.jsonl', '{"cwd":' + __import__('json').dumps(cwd) + '}\n')
        roots, contexts = collect.discover_projects(with_context=True)
        self.assertEqual(roots, [worktree])
        self.assertEqual(contexts[0]['session_cwd'], cwd)
        self.assertEqual(contexts[0]['main_checkout'], root)
        result = self.scan(roots, contexts)
        self.assertIn('WORKTREE', str(result))
        self.assertEqual(result['settings_candidates'][0]['permissions']['allow_count'], 1)


class AgentsMdInventory(FakeHome):
    def setUp(self):
        super().setUp()
        # Hermetic: files outside the fake home (e.g. an AGENTS.md above TMPDIR) do not exist.
        real = inventory.read_text
        def read_text(path, *args, **kwargs):
            if not os.path.abspath(path).startswith(self.home + os.sep):
                return None, dict(status='absent')
            return real(path, *args, **kwargs)
        patcher = mock.patch.object(inventory, 'read_text', read_text)
        patcher.start()
        self.addCleanup(patcher.stop)

    def scan(self, roots=None, contexts=None, managed_dir=None):
        return inventory.collect_instructions(self.home, self.claude, roots or [], contexts or [],
                                               managed_dir, collect.redact, collect.summarize_settings)

    def paths(self, result):
        return {e['source']: e for e in result['entries'] if e['kind'] == 'instruction'}

    def test_walk_inventories_agents_md_with_unknown_state(self):
        root = os.path.join(self.home, 'repo')
        self.write('repo/AGENTS.md', 'Root agents')
        self.write('repo/.claude/AGENTS.md', 'Dot agents')
        self.write('repo/pkg/AGENTS.md', 'Nested agents')
        self.write('repo/AGENTS.local.md', 'Not read by Claude Code')
        entries = self.paths(self.scan([root]))
        for rel in ('AGENTS.md', '.claude/AGENTS.md', 'pkg/AGENTS.md'):
            entry = entries[os.path.join(root, rel)]
            self.assertEqual(entry['active_state'], 'unknown')
            self.assertEqual(entry['scope'], 'project')
        self.assertNotIn(os.path.join(root, 'AGENTS.local.md'), entries)

    def test_ancestor_loop_inventories_agents_md(self):
        self.write('AGENTS.md', 'Ancestor agents')
        self.write('.claude/AGENTS.md', 'Ancestor dot agents')
        cwd = os.path.join(self.home, 'repo')
        os.makedirs(cwd)
        entries = self.paths(self.scan([cwd], [inventory.git_context(cwd)]))
        for rel in ('AGENTS.md', '.claude/AGENTS.md'):
            entry = entries[os.path.join(self.home, rel)]
            self.assertEqual(entry['scope'], 'ancestor')
            self.assertEqual(entry['active_state'], 'unknown')

    def test_context_flags_report_observed_presence(self):
        agents_only = os.path.join(self.home, 'a')
        both = os.path.join(self.home, 'b')
        claude_only = os.path.join(self.home, 'c', 'sub')
        neither = os.path.join(self.home, 'd')
        self.write('a/AGENTS.md', 'x')
        self.write('b/AGENTS.md', 'x')
        self.write('b/.claude/CLAUDE.md', 'x')
        self.write('c/CLAUDE.local.md', 'x')  # ancestor of the cwd
        os.makedirs(claude_only)
        os.makedirs(neither)
        roots = [agents_only, both, claude_only, neither]
        contexts = [inventory.git_context(p) for p in roots]
        flags = {c['session_cwd']: (c['claude_md_family_present'], c['agents_md_present'])
                 for c in self.scan(roots, contexts)['contexts']}
        self.assertEqual(flags[agents_only], (False, True))
        self.assertEqual(flags[both], (True, True))
        self.assertEqual(flags[claude_only], (True, False))
        self.assertEqual(flags[neither], (False, False))

    def test_user_and_managed_claude_md_do_not_count_as_claude_family_in_scope(self):
        managed = os.path.join(self.home, 'managed')
        self.write('.claude/CLAUDE.md', 'user memory')
        self.write('managed/CLAUDE.md', 'managed memory')
        self.write('repo/AGENTS.md', 'x')
        root = os.path.join(self.home, 'repo')
        result = self.scan([root], [inventory.git_context(root)], managed)
        self.assertEqual(result['contexts'][0]['claude_md_family_present'], False)
        self.assertEqual(result['contexts'][0]['agents_md_present'], True)

    def test_instruction_files_setting_observed_from_user_and_managed_only(self):
        managed = os.path.join(self.home, 'managed')
        def setting(value):
            return {'pluginConfigs': {'agents-md@builtin': {'options': {'instructionFiles': value}}}}
        self.write('.claude/settings.json', setting('claude-md-and-agents-md'))
        self.write('managed/managed-settings.json', setting('managed-only'))
        self.write('repo/.claude/settings.json', setting('claude-md'))
        self.write('repo/.claude/settings.local.json', setting('claude-md'))
        root = os.path.join(self.home, 'repo')
        result = self.scan([root], [inventory.git_context(root)], managed)
        observed = {(o['scope'], o['value']) for o in result['agents_md_setting_observed']}
        self.assertEqual(observed, {('user', 'claude-md-and-agents-md'), ('managed', 'managed-only')})
        self.assertTrue(all(o['basis'] == 'observed' for o in result['agents_md_setting_observed']))

    def test_no_setting_and_bad_setting_shapes_are_ignored(self):
        self.write('.claude/settings.json', {'pluginConfigs': {'agents-md@builtin': {'options': {'instructionFiles': ['x']}}}})
        self.assertEqual(self.scan()['agents_md_setting_observed'], [])
        self.write('.claude/settings.json', {'pluginConfigs': 'nope'})
        self.assertEqual(self.scan()['agents_md_setting_observed'], [])

    def test_limitations_state_what_is_not_observable(self):
        text = ' '.join(self.scan()['limitations'])
        for phrase in ('AGENTS.md', 'version', 'feature flag', 'effective'):
            self.assertIn(phrase, text)

    def test_agents_md_is_not_counted_as_claude_md(self):
        root = self.write('repo/AGENTS.md', 'See `missing/file.py` and more').rsplit('/', 1)[0]
        self.assertEqual(collect.collect_projects([root]), {})
        self.write('repo/CLAUDE.md', 'short')
        entry = collect.collect_projects([root])['~/repo']
        self.assertEqual(entry['claude_md_lines'], 1)
        self.assertEqual(entry['claude_md_dead_refs'], [])

    def test_absent_flags_are_unknown_when_collection_is_incomplete(self):
        root = os.path.join(self.home, 'repo')
        self.write('repo/CLAUDE.md', 'x')
        os.makedirs(os.path.join(self.home, 'other'))
        contexts = [inventory.git_context(root), inventory.git_context(os.path.join(self.home, 'other'))]
        with mock.patch.object(inventory, 'MAX_FILES', 1):
            found, missing = self.scan([root], contexts)['contexts']
        self.assertIs(found['claude_md_family_present'], True)
        self.assertIsNone(found['agents_md_present'])
        self.assertIsNone(missing['claude_md_family_present'])

    def omissions(self, result):
        return {(os.path.relpath(o['source'], self.home), o['reason'])
                for o in result['sources'] if o.get('reason') and o['scope'] in ('user', 'managed')}

    def test_unreadable_managed_drop_in_directory_is_recorded_not_fatal(self):
        managed = os.path.join(self.home, 'managed')
        self.write('managed/CLAUDE.md', 'x')
        with mock.patch.object(inventory.os, 'listdir', side_effect=PermissionError):
            result = self.scan(managed_dir=managed)
        self.assertIn(('managed/managed-settings.d', 'list_failed'), self.omissions(result))

    def test_managed_drop_ins_skip_dotfiles_and_record_file_limit(self):
        managed = os.path.join(self.home, 'managed')
        value = {'pluginConfigs': {'agents-md@builtin': {'options': {'instructionFiles': 'claude-md'}}}}
        self.write('managed/managed-settings.d/.hidden.json', value)
        for n in range(3):
            self.write(f'managed/managed-settings.d/{n}.json', value)
        with mock.patch.object(inventory, 'MANAGED_MAX_FILES', 2):
            result = self.scan(managed_dir=managed)
        self.assertEqual(len(result['agents_md_setting_observed']), 2)
        self.assertIn(('managed/managed-settings.d', 'file_limit'), self.omissions(result))

    def test_skipped_settings_files_are_recorded_without_contents(self):
        managed = os.path.join(self.home, 'managed')
        self.write('.claude/settings.json', '{"secret": "SEKRET" ' + ' ' * 40000 + '}')
        self.write('managed/managed-settings.json', '{not json SEKRET')
        target = self.write('elsewhere.json', {})
        os.makedirs(os.path.join(managed, 'managed-settings.d'))
        os.symlink(target, os.path.join(managed, 'managed-settings.d', 'link.json'))
        result = self.scan(managed_dir=managed)
        self.assertEqual(result['agents_md_setting_observed'], [])
        self.assertEqual(self.omissions(result), {
            ('.claude/settings.json', 'byte_limit'), ('managed/managed-settings.json', 'invalid_settings'),
            ('managed/managed-settings.d/link.json', 'symlink_not_followed')})
        self.assertNotIn('SEKRET', str(result))

    def test_unknown_instruction_files_value_is_recorded_as_unrecognized(self):
        self.write('.claude/settings.json', {'pluginConfigs': {'agents-md@builtin': {
            'options': {'instructionFiles': 'SEKRET-value'}}}})
        (obs,) = self.scan()['agents_md_setting_observed']
        self.assertEqual(obs['value'], 'unrecognized')
        self.assertNotIn('SEKRET', str(obs))

    def flags(self, result, cwd):
        (context,) = [c for c in result['contexts'] if c['session_cwd'] == cwd]
        return context['claude_md_family_present'], context['agents_md_present']

    def test_flags_unknown_when_cwd_sits_under_a_symlinked_ancestor(self):
        real = os.path.join(self.home, 'real')
        os.makedirs(os.path.join(real, 'repo'))
        os.symlink(real, os.path.join(self.home, 'link'))
        cwd = os.path.join(self.home, 'link', 'repo')
        result = self.scan([cwd], [inventory.git_context(cwd)])
        self.assertEqual(self.flags(result, cwd), (None, None))

    def test_flags_unknown_for_a_symlinked_project_root_with_instruction_files(self):
        self.write('real/CLAUDE.md', 'x')
        self.write('real/AGENTS.md', 'x')
        os.symlink(os.path.join(self.home, 'real'), os.path.join(self.home, 'link'))
        cwd = os.path.join(self.home, 'link')
        result = self.scan([cwd], [inventory.git_context(cwd)])
        self.assertEqual(self.flags(result, cwd), (None, None))

    def test_unrelated_symlink_does_not_blur_flags(self):
        self.write('repo/CLAUDE.md', 'x')
        os.symlink(self.write('elsewhere/f.txt', 'x'), os.path.join(self.home, 'repo', 'link'))
        cwd = os.path.join(self.home, 'repo')
        self.assertEqual(self.flags(self.scan([cwd], [inventory.git_context(cwd)]), cwd), (True, False))

    def test_directory_read_failure_makes_absent_flags_unknown(self):
        cwd = os.path.join(self.home, 'repo')
        os.makedirs(os.path.join(cwd, 'sub'))
        self.write('repo/CLAUDE.md', 'x')
        real_walk = os.walk
        def walk(base, **kw):
            kw['onerror'](OSError())
            return real_walk(base, **kw)
        with mock.patch.object(inventory.os, 'walk', walk):
            result = self.scan([cwd], [inventory.git_context(cwd)])
        self.assertEqual(self.flags(result, cwd), (True, None))

    def test_settings_omissions_do_not_make_instruction_flags_unknown(self):
        managed = os.path.join(self.home, 'managed')
        for n in range(3):
            self.write(f'managed/managed-settings.d/{n}.json', {})
        cwd = os.path.join(self.home, 'repo')
        os.makedirs(cwd)
        with mock.patch.object(inventory, 'MANAGED_MAX_FILES', 1):
            result = self.scan([cwd], [inventory.git_context(cwd)], managed)
        self.assertTrue(any(s.get('reason') == 'file_limit' for s in result['sources']))
        self.assertEqual(self.flags(result, cwd), (False, False))
