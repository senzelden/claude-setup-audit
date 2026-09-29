"""Deeper configuration checks: rule shapes, hook handler validation, cross-layer conflicts.

Fake homes only; never the real ~/.claude.
"""
import unittest
from test_collect import FakeHome, collect


class RuleShapes(unittest.TestCase):
    def test_documented_shapes_are_flagged(self):
        cases = {
            'Bash(git * main)': {'wildcard-before-subcommand'},
            'Bash(git -C * status *)': {'wildcard-before-subcommand'},
            'Bash(* --version)': {'wildcard-program'},
            'Bash(* --help *)': {'wildcard-program'},
            'Bash(ls*)': {'star-joined-to-program'},
            'Bash(/usr/bin/ls*)': {'star-joined-to-program'},
            'Bash(git:* push)': {'colon-star-literal'},
            'Bash(command:rm *)': {'ignored-primary-field'},
            'Read(file_path : ~/.ssh/id_rsa)': {'ignored-primary-field'},
            'WebFetch(url:https://x.test/*)': {'ignored-primary-field'},
            'mcp__github__create_issue(repo:x)': {'mcp-rule-with-parentheses'},
        }
        for rule, expected in cases.items():
            with self.subTest(rule=rule):
                self.assertEqual(collect.rule_shape_flags(rule), expected)

    def test_valid_patterns_are_not_flagged(self):
        for rule in ('Bash', 'Bash(*)', 'Bash(git *)', 'Bash(git:*)', 'Bash(git log *)', 'Bash(git commit *)',
                     'Bash(git log * main)', 'Bash(npm run test:*)', 'Bash(ls *)', 'Bash(ls:*)',
                     'Bash(npm run build)', 'Bash(python3 -m pytest *)', 'Bash(cat ./src/*)', 'Bash(./scripts/*)',
                     'Bash(git checkout feature-*)', 'Bash(git checkout feat*)', 'Bash(timeout:*)',
                     'Bash(run_in_background:true)', 'Agent(model:*)', 'Read(./.env)', 'Read(//etc/**)',
                     'Edit(src/**)', 'WebFetch(domain:example.com)', 'mcp__github__get_*', 'mcp__*'):
            with self.subTest(rule=rule):
                self.assertEqual(collect.rule_shape_flags(rule), set())

    def test_lists_keep_only_their_relevant_flags_capped_and_redacted(self):
        perms = {'allow': ['Bash(git * main)', 'Bash(git:* push)', 'Bash(npm run *)', 1],
                 'deny': ['Bash(git * main)', 'Bash(git:* push)', 'Bash(command:rm *)'],
                 'ask': ['Bash(ls*)', 'mcp__github__create_issue(repo:x)']}
        self.assertEqual(collect.rule_shape_issues(perms), {
            'allow': {'colon-star-literal': ['Bash(git:* push)'],
                      'wildcard-before-subcommand': ['Bash(git * main)']},
            'deny': {'colon-star-literal': ['Bash(git:* push)'],
                     'ignored-primary-field': ['Bash(command:rm *)']},
            'ask': {'mcp-rule-with-parentheses': ['mcp__github__create_issue(repo:x)']}})
        many = {'allow': [f'Bash(tool{i} * main)' for i in range(8)]}
        self.assertEqual(len(collect.rule_shape_issues(many)['allow']['wildcard-before-subcommand']), 6)
        stored = collect.rule_shape_issues({'allow': ['Bash(sk-abcdefghijklmnopqrstuv * main)']})
        self.assertEqual(stored['allow']['wildcard-before-subcommand'], ['Bash([REDACTED] * main)'])
        self.assertEqual(collect.rule_shape_issues({'allow': ['Bash(git status)']}), {})


class RuleShapesInSummary(FakeHome):
    def test_summary_carries_rule_shape_issues(self):
        flagged = self.write('.claude/settings.json', {'permissions': {'allow': ['Bash(ls*)'],
                                                                         'deny': ['Bash(git:* push)']}})
        clean = self.write('p/.claude/settings.json', {'permissions': {'allow': ['Bash(git status)']}})
        self.assertEqual(collect.summarize_settings(flagged)['permissions']['rule_shape_issues'],
                         {'allow': {'star-joined-to-program': ['Bash(ls*)']},
                          'deny': {'colon-star-literal': ['Bash(git:* push)']}})
        self.assertEqual(collect.summarize_settings(clean)['permissions']['rule_shape_issues'], {})
