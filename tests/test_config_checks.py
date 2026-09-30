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


def sfile(layer, path, allow=(), ask=(), deny=(), handlers=()):
    return {'layer': layer, 'path': path, 'handlers': list(handlers), 'enabled_plugins': {},
            'permissions': {'allow': list(allow), 'ask': list(ask), 'deny': list(deny)}}


def stack(name, *files, plugins=()):
    return {'name': name, 'settings': list(files), 'plugins': list(plugins)}


USER, MANAGED, PROJECT = '~/.claude/settings.json', '/etc/claude-code/managed-settings.json', '~/app/.claude/settings.json'


class RuleCoverage(unittest.TestCase):
    def test_covering_pairs(self):
        for by, allow, match in (
                ('Bash(git push *)', 'Bash(git push *)', 'exact'), ('Bash(ls *)', 'Bash(ls:*)', 'exact'),
                ('Bash', 'Bash', 'exact'), ('Bash(*)', 'Bash(npm test)', 'tool'), ('Bash', 'Bash(npm test)', 'tool'),
                ('Read', 'Read(./src/**)', 'tool'), ('mcp__*', 'mcp__github__get_issue', 'tool'),
                ('*', 'WebSearch', 'tool'), ('Bash(git *)', 'Bash(git log *)', 'prefix'),
                ('Bash(git *)', 'Bash(git)', 'prefix'), ('Bash(git *)', 'Bash(git log*)', 'prefix'),
                ('Bash(git*)', 'Bash(gitk)', 'prefix'), ('Bash(git:*)', 'Bash(git status)', 'prefix'),
                ('Bash (x)', 'Bash (x)', 'exact'), ('Bash', 'Bash (x)', 'tool'),
                ('Bash(command:rm *)', 'Bash(command:rm *)', 'exact'), ('Read(/src/**)', 'Read(/src/**)', 'exact')):
            with self.subTest(by=by, allow=allow):
                self.assertEqual(config_checks.rule_covers(by, allow), match)

    def test_non_covering_pairs(self):
        for by, allow in (
                ('Bash(git *)', 'Bash(gitk)'), ('Bash(git *)', 'Bash(git*)'), ('Bash(git *)', 'Bash(* --version)'),
                ('Bash(git push --force *)', 'Bash(git push *)'), ('Bash(rm *)', 'Bash'),
                ('Bash(timeout:*)', 'Bash(timeout 5 ls)'), ('Read(./src/**)', 'Read(./src/a.py)'),
                ('Bash(git * main)', 'Bash(git merge main)'), ('mcp__github__*', 'mcp__gitlab__get'),
                ('Bash(git push *)', 'mcp__github__push(x)'), ('mcp__*', 'mcp__github__create(x)'),
                ('Bash(git:* push)', 'Bash(git push)'), (None, 'Bash'), ('Bash(', 'Bash'),
                ('Bash(timeout:*)', 'Bash(timeout *)'), ('Bash (x)', 'Bash'), ('Read(!sample.env)', 'Read(!sample.env)'),
                ('Bash(command:rm *)', 'Bash(command:rm x)')):
            with self.subTest(by=by, allow=allow):
                self.assertIsNone(config_checks.rule_covers(by, allow))


class PermissionOverlaps(unittest.TestCase):
    def overlaps(self, *stacks):
        return config_checks.permission_overlaps(list(stacks), collect.redact)

    def test_deny_or_ask_in_any_layer_shadows_allow_and_is_reported_once(self):
        user = sfile('user', USER, allow=['Bash(git push *)', 'Bash(git log *)'])
        managed = sfile('managed', MANAGED, deny=['Bash(git push *)'])
        found, omitted = self.overlaps(stack('global', managed, user),
                                       stack('~/app', managed, user, sfile('project', PROJECT, ask=['Bash(git *)'])))
        self.assertEqual(omitted, 0)
        self.assertEqual(found, [
            {'stack': 'global', 'allow': {'layer': 'user', 'path': USER, 'rule': 'Bash(git push *)'},
             'by': {'list': 'deny', 'layer': 'managed', 'path': MANAGED, 'rule': 'Bash(git push *)'}, 'match': 'exact'},
            {'stack': '~/app', 'allow': {'layer': 'user', 'path': USER, 'rule': 'Bash(git log *)'},
             'by': {'list': 'ask', 'layer': 'project', 'path': PROJECT, 'rule': 'Bash(git *)'}, 'match': 'prefix'}])

    def test_deny_is_preferred_over_ask_and_same_file_counts(self):
        found, _ = self.overlaps(stack('global', sfile('user', USER, allow=['Bash(git push *)'],
                                                       ask=['Bash(git *)'], deny=['Bash(git push *)'])))
        self.assertEqual([(o['by']['list'], o['match']) for o in found], [('deny', 'exact')])

    def test_other_projects_are_never_paired(self):
        self.assertEqual(self.overlaps(stack('~/a', sfile('project', '~/a/.claude/settings.json', allow=['Bash(x)'])),
                                       stack('~/b', sfile('project', '~/b/.claude/settings.json', deny=['Bash(x)']))),
                         ([], 0))

    def test_cap_and_redaction(self):
        found, omitted = self.overlaps(stack('global', sfile('user', USER, allow=[f'Bash(t{i})' for i in range(35)],
                                                             deny=['Bash'])))
        self.assertEqual((len(found), omitted), (30, 5))
        secret = 'Bash(sk-abcdefghijklmnopqrstuv *)'
        found, _ = self.overlaps(stack('global', sfile('user', USER, allow=[secret], deny=[secret])))
        self.assertEqual(found[0]['allow']['rule'], 'Bash([REDACTED] *)')
        self.assertEqual(found[0]['by']['rule'], 'Bash([REDACTED] *)')

    def test_single_slash_paths_anchor_per_file(self):
        self.assertIsNone(config_checks.rule_covers('Read(/src/**)', 'Read(/src/**)', same_file=False))
        self.assertEqual(config_checks.rule_covers('Read(//etc/**)', 'Read(//etc/**)', same_file=False), 'exact')


class PermissionOverlapEdges(unittest.TestCase):
    def overlaps(self, *stacks):
        return config_checks.permission_overlaps(list(stacks), collect.redact)

    def test_odd_rule_spellings_and_lists_do_not_crash(self):
        found, _ = self.overlaps(stack('g', sfile('user', USER, allow=['Bash', 'Bash(ls)', 7, None]),
                                       sfile('project', PROJECT, deny=['Bash (ls)', 5, None])))
        self.assertEqual([o['match'] for o in found], ['exact'])
        odd = {'layer': 'user', 'path': USER, 'handlers': [], 'enabled_plugins': {},
               'permissions': {'allow': None, 'deny': 'Bash', 'ask': [None]}}
        self.assertEqual(self.overlaps(stack('g', odd, {**odd, 'permissions': None})), ([], 0))

    def test_single_slash_rule_in_different_files_is_not_reported(self):
        user = sfile('user', USER, allow=['Read(/src/**)'])
        proj = sfile('project', PROJECT, deny=['Read(/src/**)'])
        self.assertEqual(self.overlaps(stack('~/app', user, proj)), ([], 0))
        both = sfile('user', USER, allow=['Read(/src/**)'], deny=['Read(/src/**)'])
        self.assertEqual(len(self.overlaps(stack('g', both))[0]), 1)

    def test_negation_in_the_denying_file_blocks_exact_claims(self):
        deny = sfile('project', PROJECT, deny=['Read(*.env)', 'Read(!sample.env)'])
        allow = sfile('user', USER, allow=['Read(*.env)'])
        self.assertEqual(self.overlaps(stack('~/app', deny, allow)), ([], 0))
        plain = sfile('project', PROJECT, deny=['Read(*.env)'])
        self.assertEqual(len(self.overlaps(stack('~/app', plain, allow))[0]), 1)


def entry(event, matcher, **handler):
    handler.setdefault('type', 'command')
    return collect.hook_handler_entry(event, matcher, handler)


class HookDuplicates(unittest.TestCase):
    def dups(self, *stacks):
        return config_checks.hook_duplicates(list(stacks), collect.redact)

    def test_effects_follow_the_docs(self):
        lint = entry('PreToolUse', 'Bash', command='lint.sh CANARY-cmd-7f3a')
        found, omitted = self.dups(stack('~/app', sfile('user', USER, handlers=[lint]),
                                         sfile('project', PROJECT, handlers=[lint])))
        self.assertEqual(omitted, 0)
        self.assertEqual(found, [{'stack': '~/app', 'event': 'PreToolUse', 'matcher': 'Bash', 'type': 'command',
                                  'fingerprint': lint['fingerprint'], 'effect': 'deduplicated',
                                  'sources': [{'layer': 'user', 'path': USER, 'plugin': None},
                                              {'layer': 'project', 'path': PROJECT, 'plugin': None}]}])
        self.assertNotIn('CANARY-cmd-7f3a', str(found))
        plugin = {'plugin': 'demo@m', 'path': '~/.claude/plugins/c/hooks/hooks.json', 'handlers': [lint]}
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[lint]), plugins=[plugin]))
        self.assertEqual(found[0]['effect'], 'separate_copies')
        self.assertEqual(found[0]['sources'][1], {'layer': 'plugin', 'path': plugin['path'], 'plugin': 'demo@m'})
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[lint, lint])))
        self.assertEqual(found[0]['effect'], 'same_file')

    def test_identity(self):
        local = '~/.claude/settings.local.json'
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[entry('Stop', None, command='x')]),
                                   sfile('local', local, handlers=[entry('Stop', '*', command='x')])))
        self.assertEqual(found[0]['matcher'], '*')
        for a, b in ((entry('PreToolUse', 'Bash', command='x'), entry('PreToolUse', 'Bash|Edit', command='x')),
                     (entry('PreToolUse', 'Bash', command='x', timeout=5), entry('PreToolUse', 'Bash', command='x'))):
            self.assertEqual(self.dups(stack('global', sfile('user', USER, handlers=[a]),
                                             sfile('local', local, handlers=[b]))), ([], 0))

    def test_plugin_root_commands_group_only_within_their_plugin(self):
        start = entry('SessionStart', None, command='${CLAUDE_PLUGIN_ROOT}/hooks/start.sh')
        plugins = [{'plugin': 'a@m', 'path': 'pa', 'handlers': [start]},
                   {'plugin': 'b@m', 'path': 'pb', 'handlers': [start]}]
        self.assertEqual(self.dups(stack('global', plugins=plugins)), ([], 0))

    def test_reported_once_and_capped(self):
        lint = entry('PreToolUse', 'Bash', command='lint.sh')
        g = stack('global', sfile('managed', MANAGED, handlers=[lint]), sfile('user', USER, handlers=[lint]))
        a = stack('~/app', sfile('managed', MANAGED, handlers=[lint]), sfile('user', USER, handlers=[lint]),
                  sfile('project', PROJECT))
        found, _ = self.dups(g, a)
        self.assertEqual([d['stack'] for d in found], ['global'])
        files = [sfile('user', f'f{i}', handlers=[entry('PreToolUse', 'Bash', command=f'c{j}') for j in range(25)])
                 for i in range(2)]
        self.assertEqual([len(x) if isinstance(x, list) else x for x in self.dups(stack('global', *files))], [20, 5])
        found, _ = self.dups(stack('global', *[sfile('user', f'f{i}', handlers=[lint]) for i in range(12)]))
        self.assertEqual(len(found[0]['sources']), 10)

    def test_list_matcher_is_stored_as_json_not_a_python_repr(self):
        h = entry('PreToolUse', ['Edit', 'Bash'], command='x')
        found, _ = self.dups(stack('global', sfile('user', USER, handlers=[h]),
                                   sfile('project', PROJECT, handlers=[h])))
        self.assertEqual(found[0]['matcher'], '["Bash","Edit"]')

    def test_malformed_shapes_do_not_crash(self):
        lint = entry('Stop', None, command='x')
        odd = {'layer': 'user', 'path': USER, 'handlers': None}
        junk = sfile('project', PROJECT, handlers=['nope', None, {'event': 'Stop'}, lint, lint])
        found, _ = self.dups({'name': 'g', 'settings': [odd, 'x', junk], 'plugins': [None, {'handlers': 3}]})
        self.assertEqual([d['effect'] for d in found], ['same_file'])
        self.assertEqual(self.dups({'name': 'g', 'settings': None, 'plugins': None}), ([], 0))

    def test_conflicts_section_shape(self):
        section = config_checks.conflicts([stack('global', sfile('user', USER))], collect.redact)
        self.assertEqual(section, {'stacks': 1, 'hook_duplicates': [], 'hook_duplicates_omitted': 0,
                                   'permission_overlaps': [], 'permission_overlaps_omitted': 0})
