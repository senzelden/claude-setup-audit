"""Deeper configuration checks: rule shapes, hook handler validation, cross-layer conflicts.

Fake homes only; never the real ~/.claude.
"""
import unittest
from test_collect import FakeHome, collect
import config_checks


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


def hook_issues(event, matcher=None, **handler):
    handler.setdefault('type', 'command')
    handler.setdefault('command', 'true')
    return config_checks.handler_issues(event, matcher, handler)[0]


class HookHandlerChecks(unittest.TestCase):
    def test_every_documented_event_is_known_without_a_matcher(self):
        for event in config_checks.HOOK_EVENTS:
            with self.subTest(event=event):
                self.assertEqual(hook_issues(event), [])
        self.assertEqual(config_checks.TOOL_EVENTS, {'PreToolUse', 'PostToolUse', 'PostToolUseFailure',
                                                     'PermissionRequest', 'PermissionDenied'})

    def test_documented_problems_are_flagged(self):
        cases = [
            (('pretooluse', 'Bash'), ['unknown_event']),
            (('Stop', 'Bash'), ['matcher_ignored']),
            (('UserPromptSubmit', '.*'), ['matcher_ignored']),
            (('PreToolUse', '*.py'), ['invalid_regex']),
            (('PreToolUse', 'Edit|Write)'), ['invalid_regex']),
            (('PreToolUse', '[Edit'), ['invalid_regex']),
            (('PreToolUse', 'mcp__memory'), ['mcp_server_only_matcher']),
            (('PreToolUse', 'Bash|mcp__brave-search'), ['mcp_server_only_matcher']),
            (('StopFailure', 'rate_limit, overloaded'), ['narrow_event_regex_path']),
            (('PreToolUse', ['Bash']), ['matcher_not_string']),
        ]
        for (event, matcher), expected in cases:
            with self.subTest(event=event, matcher=matcher):
                self.assertEqual(hook_issues(event, matcher), expected)

    def test_valid_matchers_are_not_flagged(self):
        for event, matcher in (
                ('PreToolUse', 'Edit|Write'), ('PreToolUse', 'Edit, Write'), ('PreToolUse', '^Notebook'),
                ('PreToolUse', '^Edit$'), ('PreToolUse', 'mcp__memory__.*'), ('PreToolUse', 'mcp__.*__write.*'),
                ('PreToolUse', 'mcp__memory__create_entities'), ('SubagentStart', 'code-reviewer'),
                ('SubagentStart', '^my-plugin:reviewer$'), ('PreModelSwitch', '.*opus.*'),
                ('Notification', 'permission_prompt'), ('SessionStart', 'mcp__memory'),
                ('StopFailure', 'rate_limit|overloaded'), ('FileChanged', '.envrc|.env'),
                ('FileChanged', r'^\.env'), ('PreToolUse', '(?<tool>Bash)'), ('PreToolUse', r'\p{L}+'),
                ('Stop', '*'), ('Stop', ''), ('Stop', None),
                ('FileChanged', '*.local'), ('FileChanged', 'my-config'),
                ('PreToolUse', 'a{99999999999}')):
            with self.subTest(event=event, matcher=matcher):
                self.assertEqual(hook_issues(event, matcher), [])

    def test_if_on_non_tool_events_never_runs(self):
        self.assertEqual(hook_issues('Stop', **{'if': 'Bash(git *)'}), ['if_never_runs'])
        self.assertEqual(hook_issues('PermissionDenied', 'Bash', **{'if': 'Bash(git *)'}), [])

    def test_handler_fields(self):
        check = config_checks.handler_issues
        full = {'type': 'command', 'command': 'x', 'args': [], 'async': True, 'asyncRewake': False,
                'shell': 'bash', 'timeout': 5, 'statusMessage': 's', 'once': True, 'if': 'Bash(x)'}
        self.assertEqual(check('PreToolUse', 'Bash', full), ([], []))
        self.assertEqual(check('PreToolUse', 'Bash', {'type': 'command', 'command': 'x', 'url': 'u'}),
                         (['unknown_fields'], ['url']))
        self.assertEqual(check('PreToolUse', 'Bash', {'type': 'http', 'url': 'u', 'async': True}),
                         (['unknown_fields'], ['async']))
        self.assertEqual(check('Stop', None, {'type': 'prompt', 'prompt': 'p', 'model': 'm'}), ([], []))
        self.assertEqual(check('Stop', None, {'type': 'script', 'command': 'x'}), (['unknown_type'], []))
        self.assertEqual(check('Stop', None, {'command': 'x'}), ([], []))
        self.assertEqual(check('Stop', 'Bash', {'type': 'command', 'command': 'x', 'colour': 'r'}),
                         (['matcher_ignored', 'unknown_fields'], ['colour']))

    def test_non_string_type_is_an_unknown_type(self):
        self.assertEqual(config_checks.handler_issues('Stop', None, {'type': ['command']}),
                         (['unknown_type'], []))

    def test_fingerprint(self):
        fp = config_checks.handler_fingerprint
        same = {fp('PreToolUse', None, {'command': 'a', 'type': 'command'}),
                fp('PreToolUse', '*', {'type': 'command', 'command': 'a'}),
                fp('PreToolUse', '', {'command': 'a'})}
        self.assertEqual(len(same), 1)
        self.assertRegex(same.pop(), r'^[0-9a-f]{16}$')
        self.assertNotEqual(fp('PreToolUse', 'Bash', {'command': 'a', 'timeout': 5}),
                            fp('PreToolUse', 'Bash', {'command': 'a'}))
        self.assertNotEqual(fp('PostToolUse', 'Bash', {'command': 'a'}), fp('PreToolUse', 'Bash', {'command': 'a'}))


class HookFieldsInSummary(FakeHome):
    def test_handler_entries_carry_checks(self):
        path = self.write('.claude/settings.json', {'hooks': {
            'Stop': [{'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': 'x', 'colour': 'r'}]}],
            'PreToolUse': [{'matcher': '[', 'hooks': [{'type': 'command', 'command': 'ok.sh'}]}],
            'SessionStart': [{'hooks': [{'type': 'command', 'command': '${CLAUDE_PLUGIN_ROOT}/s.sh'}]}]}})
        handlers = {h['event']: h for h in collect.summarize_settings(path)['hook_handlers']}
        self.assertEqual(handlers['Stop']['issues'], ['matcher_ignored', 'unknown_fields'])
        self.assertEqual(handlers['Stop']['unknown_fields'], ['colour'])
        self.assertEqual(handlers['PreToolUse']['issues'], ['invalid_regex'])
        self.assertNotIn('issues', handlers['SessionStart'])
        self.assertNotIn('unknown_fields', handlers['SessionStart'])
        self.assertTrue(handlers['SessionStart']['plugin_relative'])
        self.assertNotIn('plugin_relative', handlers['Stop'])
        self.assertRegex(handlers['Stop']['fingerprint'], r'^[0-9a-f]{16}$')

    def test_unhashable_handler_type_does_not_abort_the_summary(self):
        path = self.write('.claude/settings.json', {'hooks': {
            'Stop': [{'hooks': [{'type': ['command'], 'command': 'x'}]}]}})
        handlers = collect.summarize_settings(path)['hook_handlers']
        self.assertEqual(handlers[0]['issues'], ['unknown_type'])
