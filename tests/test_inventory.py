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
