"""Plugin runtime footprint: ledger-attributed rules, markers, state files, permission-deciding hooks,
injection vs the output cap, suspicious timeouts, spawned sessions. Fake homes only; nothing executes."""
import contextlib
import io
import json
import os
import re
import sys
import time
import unittest
from unittest import mock

from test_collect import FakeHome, collect
from test_harness import attachment, install
from test_privacy import PatchedHome, args
import config_checks
import extensions
import harness
import plugin_footprint
import prune_permissions

NOW = 1789473600


def stamp(offset=0):
    return collect.datetime.fromtimestamp(time.time() + offset, collect.timezone.utc).isoformat()


def ledger(home_test, by_path, sub='proj1', name='untool_applied.json'):
    return home_test.write(f'.tokeneconomizer/{sub}/{name}', {'by_path': by_path, 'kept': {}})


class LedgerRules(FakeHome):
    def project_settings(self, deny=('WebFetch', 'Bash(rm:*)'), allow=()):
        return self.write('code/app/.claude/settings.local.json',
                          {'permissions': {'deny': list(deny), 'allow': list(allow)}})

    def test_rules_listed_by_the_ledger_are_attributed_to_the_file(self):
        path = self.project_settings()
        ledger(self, {os.path.realpath(path): ['WebFetch', 'WebSearch']})
        summary = collect.summarize_settings(path)
        self.assertEqual(summary['plugin_written_rules'], [
            {'plugin': 'TokenEconomizer', 'list': 'deny', 'rules': ['WebFetch'], 'rule_count': 1, 'ledger_only': 1}])

    def test_a_rule_the_user_added_themselves_is_not_attributed(self):
        path = self.project_settings(deny=['WebFetch', 'Bash(rm:*)'])
        ledger(self, {os.path.realpath(path): ['WebFetch']})
        (entry,) = collect.summarize_settings(path)['plugin_written_rules']
        self.assertNotIn('Bash(rm:*)', entry['rules'])

    def test_a_file_the_ledger_does_not_list_has_no_attribution(self):
        path = self.project_settings()
        other = self.write('code/other/.claude/settings.local.json', {'permissions': {'deny': ['WebFetch']}})
        ledger(self, {os.path.realpath(other): ['WebFetch']})
        self.assertNotIn('plugin_written_rules', collect.summarize_settings(path))

    def test_symlinked_settings_path_maps_through_realpath(self):
        real = self.project_settings()
        link = os.path.join(self.home, 'code', 'link.json')
        os.symlink(real, link)
        ledger(self, {os.path.realpath(real): ['WebFetch']})
        self.assertEqual(collect.summarize_settings(link)['plugin_written_rules'][0]['rules'], ['WebFetch'])

    def test_older_ledger_shape(self):
        path = self.project_settings()
        self.write('.tokeneconomizer/old/untool_applied.json', {'tools': ['WebFetch'], 'path': os.path.realpath(path)})
        self.assertEqual(collect.summarize_settings(path)['plugin_written_rules'][0]['rules'], ['WebFetch'])

    def test_symlinked_ledger_file_and_directory_are_not_read(self):
        path = self.project_settings()
        real = self.write('elsewhere/untool_applied.json', {'by_path': {os.path.realpath(path): ['WebFetch']}})
        os.makedirs(os.path.join(self.home, '.tokeneconomizer', 'a'))
        os.symlink(real, os.path.join(self.home, '.tokeneconomizer', 'a', 'untool_applied.json'))
        os.symlink(os.path.dirname(real), os.path.join(self.home, '.tokeneconomizer', 'b'))
        self.assertNotIn('plugin_written_rules', collect.summarize_settings(path))

    def test_depth_size_and_fifo_bounds(self):
        path = self.project_settings()
        deep = '/'.join(['d'] * (plugin_footprint.LEDGER_DEPTH + 1))
        self.write(f'.tokeneconomizer/{deep}/untool_applied.json', {'by_path': {os.path.realpath(path): ['WebFetch']}})
        big = {'by_path': {os.path.realpath(path): ['WebFetch']}, 'pad': 'x' * plugin_footprint.LEDGER_BYTES}
        self.write('.tokeneconomizer/big/untool_applied.json', big)
        # valid JSON followed by padding past the bound: the truncated read still parses, so only the length check refuses it
        self.write('.tokeneconomizer/pad/untool_applied.json',
                   json.dumps({'by_path': {os.path.realpath(path): ['WebFetch']}}) + ' ' * plugin_footprint.LEDGER_BYTES)
        os.makedirs(os.path.join(self.home, '.tokeneconomizer', 'fifo'))
        fifo = os.path.join(self.home, '.tokeneconomizer', 'fifo', 'untool_applied.json')
        os.mkfifo(fifo)
        self.assertIsNone(plugin_footprint._read_regular(fifo, 10))  # opened without blocking, refused
        result = plugin_footprint.read_ledger(self.home)  # a FIFO must not stall this call
        self.assertEqual((result['by_path'], result['status']), ({}, 'partial'))
        self.assertEqual((result['files'], result['unreadable']), (0, 2))  # both oversized files; the FIFO is not listed

    def test_deeply_nested_json_is_unreadable_not_a_crash(self):
        path = self.project_settings()
        self.write('.tokeneconomizer/deep/untool_applied.json', '[' * 100000)
        self.write('.tokeneconomizer/ok/untool_applied.json', {'by_path': {os.path.realpath(path): ['WebFetch']}})
        result = plugin_footprint.read_ledger(self.home)
        self.assertEqual((result['files'], result['unreadable'], result['status']), (1, 1, 'partial'))
        self.assertEqual(collect.summarize_settings(path)['plugin_written_rules'][0]['rules'], ['WebFetch'])

    def test_nul_and_relative_keys_are_skipped_and_counted(self):
        path = self.project_settings()
        ledger(self, {'/a/b\u0000c': ['WebFetch'], 'relative/settings.json': ['WebFetch'],
                      os.path.realpath(path): ['WebFetch']})
        result = plugin_footprint.read_ledger(self.home)
        self.assertEqual((result['unreadable'], result['status'], list(result['by_path'])),
                         (2, 'partial', [os.path.realpath(path)]))
        snap_source = collect.summarize_settings(path)
        self.assertEqual(snap_source['plugin_written_rules'][0]['rules'], ['WebFetch'])

    def test_file_count_is_capped(self):
        for i in range(plugin_footprint.LEDGER_FILES + 5):
            self.write(f'.tokeneconomizer/p{i:03d}/untool_applied.json', {'by_path': {}})
        result = plugin_footprint.read_ledger(self.home)
        self.assertEqual((result['files'], result['status']), (plugin_footprint.LEDGER_FILES, 'partial'))

    def test_no_ledger_is_absent(self):
        self.assertEqual(plugin_footprint.read_ledger(self.home)['status'], 'absent')


class Markers(FakeHome):
    def test_quartermaster_key_is_a_marker_only_when_enabled(self):
        for value, expected in ((True, ['quartermaster.autoApprovePermissions']), (False, None), ('yes', None)):
            with self.subTest(value=value):
                path = self.write('s.json', {'quartermaster': {'autoApprovePermissions': value}})
                self.assertEqual(collect.summarize_settings(path).get('plugin_markers'), expected)

    def test_unrelated_settings_have_no_marker(self):
        self.assertNotIn('plugin_markers', collect.summarize_settings(self.write('s.json', {'model': 'opus'})))


class StateFiles(FakeHome):
    def test_known_state_files_are_present_booleans_without_reading_contents(self):
        self.write('code/app/.claude/ralph-loop.local.md', 'SENTINEL-CONTENT')
        self.write('code/app/.claude/hookify.block-rm.local.md', 'SENTINEL-CONTENT')
        self.write('code/app/.claude/auto-memory/config.json', 'SENTINEL-CONTENT')
        self.write('code/app/.claude/autoharness/state.json', 'SENTINEL-CONTENT')
        self.write('code/app/.claude/settings.json', {})
        self.write('code/plain/.claude/settings.json', {})
        projects = collect.collect_projects([os.path.join(self.home, 'code')])
        self.assertEqual(projects['~/code/app']['plugin_state'],
                         {'ralph-loop': True, 'hookify': True, 'auto-memory': True, 'autoharness': True})
        self.assertNotIn('plugin_state', projects['~/code/plain'])
        self.assertNotIn('SENTINEL', json.dumps(projects))

    def test_global_claude_hud_directory(self):
        os.makedirs(os.path.join(self.claude, 'plugins', 'claude-hud'))
        self.assertEqual(collect.collect_global()['plugin_state'], {'claude-hud': True})
        os.rmdir(os.path.join(self.claude, 'plugins', 'claude-hud'))
        self.assertNotIn('plugin_state', collect.collect_global())

    def test_project_names_are_not_reported_at_global_scope_and_vice_versa(self):
        self.write('.claude/ralph-loop.local.md', 'x')
        self.assertEqual(plugin_footprint.state_files(self.claude, 'global'), {})


DECIDER = '#!/bin/sh\necho \'{"hookSpecificOutput":{"permissionDecision":"allow"}}\'\n'


class HookEffects(FakeHome):
    def effects(self, event, command='"${CLAUDE_PLUGIN_ROOT}/hooks/h.sh"', files=None, **handler):
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1')
        for rel, text in (files or {}).items():
            self.write(os.path.relpath(os.path.join(root, rel), self.home), text)
        return plugin_footprint.hook_effects(event, dict({'type': 'command', 'command': command}, **handler), root)

    def test_permission_request_hook_decides_by_event(self):
        out = self.effects('PermissionRequest', files={'hooks/h.sh': 'echo hi'})
        self.assertEqual((out['decides_permissions'], out['decision_basis']), (True, 'permission_request_event'))

    def test_pretooluse_script_with_allow_or_deny_is_flagged_with_its_file(self):
        for word in ('allow', 'deny'):
            with self.subTest(word=word):
                out = self.effects('PreToolUse', files={'hooks/h.sh': DECIDER.replace('allow', word)})
                self.assertEqual((out['decides_permissions'], out['decision_basis'], out['decision_file']),
                                 (True, 'static_scan', os.path.join('hooks', 'h.sh')))

    def test_python_and_js_spellings(self):
        for text in ('print(json.dumps({"permissionDecision": "deny"}))', "const r = { permissionDecision: 'allow' }",
                     'echo "{\\"permissionDecision\\": \\"allow\\"}"'):
            with self.subTest(text=text):
                self.assertTrue(self.effects('PreToolUse', files={'hooks/h.sh': text}).get('decides_permissions'))

    def test_exit_code_two_and_legacy_decision_block_are_decisions(self):
        for text in ('exit 2', 'sys.exit(2)', 'process.exit(2)', 'os._exit(2)', '{"decision": "block"}',
                     'out["decision"] = "approve"'):
            with self.subTest(text=text):
                out = self.effects('PreToolUse', files={'hooks/h.sh': text})
                self.assertEqual((out.get('decides_permissions'), out.get('decision_basis')), (True, 'static_scan'))

    def test_other_exit_codes_and_prose_are_not(self):
        for text in ('exit 0', 'exit 20', 'sys.exit(1)', 'echo a 2>&1', 'myexit 2', '# exit 2', 'indecision block'):
            with self.subTest(text=text):
                self.assertEqual(self.effects('PreToolUse', files={'hooks/h.sh': text}), {})

    def test_relative_script_after_cd_to_the_plugin_root_is_resolved(self):
        out = self.effects('PreToolUse', command='cd "$CLAUDE_PLUGIN_ROOT" && node hooks/g.js',
                           files={'hooks/g.js': 'process.exit(2)'})
        self.assertEqual((out['decides_permissions'], out['decision_file']), (True, os.path.join('hooks', 'g.js')))

    def test_relative_script_without_the_cd_is_not_resolved_against_the_root(self):
        out = self.effects('PreToolUse', command='node hooks/g.js', files={'hooks/g.js': 'process.exit(2)'})
        self.assertEqual(out, {'scan_gap': 'no_local_script'})

    def test_command_without_a_local_script_is_a_gap_unless_the_text_matched(self):
        self.assertEqual(self.effects('PreToolUse', command='npx -y some-guard hook'), {'scan_gap': 'no_local_script'})
        self.assertEqual(self.effects('PreToolUse', command='echo ok; exit 2')['decision_basis'], 'static_scan')
        self.assertNotIn('scan_gap', self.effects('PreToolUse', command='echo ok; exit 2'))

    def test_ask_reason_comments_and_other_keys_do_not_match(self):
        for text in ('{"permissionDecision": "ask"}', '{"permissionDecisionReason": "allow all"}',
                     '# permissionDecision: allow', '// permissionDecision: deny', 'permissionDecisions allow'):
            with self.subTest(text=text):
                self.assertEqual(self.effects('PreToolUse', files={'hooks/h.sh': text}), {})

    def test_updated_input_marks_rewrite(self):
        out = self.effects('PreToolUse', files={'hooks/h.sh': 'out = {"updatedInput": {"command": c}}'})
        self.assertEqual(out, {'rewrites_input': True, 'decision_basis': 'static_scan',
                               'decision_file': os.path.join('hooks', 'h.sh')})

    def test_inline_command_text_is_scanned_without_a_file(self):
        out = self.effects('PreToolUse', command='''echo '{"permissionDecision":"deny"}' ''')
        self.assertEqual((out.get('decides_permissions'), 'decision_file' in out), (True, False))

    def test_other_events_are_not_scanned(self):
        self.assertEqual(self.effects('PostToolUse', files={'hooks/h.sh': DECIDER}), {})
        self.assertEqual(self.effects('SessionStart', files={'hooks/h.sh': DECIDER}), {})
        for event in ('PostToolUse', 'SessionStart', 'UserPromptSubmit'):
            self.assertEqual(self.effects(event, files={'hooks/h.sh': '{"updatedInput": {}}'}), {})

    def test_script_outside_the_plugin_root_is_never_read(self):
        outside = self.write('outside/h.sh', DECIDER)
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1')
        os.makedirs(root)
        self.assertTrue(os.path.isfile(os.path.join(root, '..', '..', '..', '..', '..', '..', 'outside', 'h.sh')))
        out = plugin_footprint.hook_effects('PreToolUse', {'type': 'command', 'command': f'{root}/../../../../../../outside/h.sh'}, root)
        self.assertEqual(out, {'scan_gap': 'script_unresolved'})  # named by the command, refused, not read

    def test_symlink_inside_root_pointing_outside_is_not_read(self):
        outside = self.write('outside/h.sh', DECIDER)
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1')
        os.makedirs(os.path.join(root, 'hooks'))
        os.symlink(outside, os.path.join(root, 'hooks', 'h.sh'))
        out = plugin_footprint.hook_effects('PreToolUse', {'type': 'command', 'command': f'{root}/hooks/h.sh'}, root)
        self.assertEqual(out, {'scan_gap': 'script_unresolved'})

    def test_fifo_script_does_not_stall(self):
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1')
        os.makedirs(os.path.join(root, 'hooks'))
        os.mkfifo(os.path.join(root, 'hooks', 'h.sh'))
        out = plugin_footprint.hook_effects('PreToolUse', {'type': 'command', 'command': f'{root}/hooks/h.sh'}, root)
        self.assertEqual(out, {'scan_gap': 'script_unresolved'})

    def test_missing_script_is_a_gap_not_a_clean_bill(self):
        self.assertEqual(self.effects('PreToolUse'), {'scan_gap': 'script_unresolved'})

    def test_non_command_pretooluse_handler_has_no_gap(self):
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1')
        self.assertEqual(plugin_footprint.hook_effects('PreToolUse', {'type': 'http', 'url': 'https://x'}, root), {})

    def test_script_over_the_read_bound_is_truncated_and_labelled(self):
        text = 'x' * plugin_footprint.SCAN_BYTES + '\n' + DECIDER
        self.assertEqual(self.effects('PreToolUse', files={'hooks/h.sh': text}), {'scan_gap': 'script_truncated'})

    def test_non_command_handlers_are_not_scanned(self):
        root = os.path.join(self.claude, 'plugins', 'cache', 'm', 'p', '1')
        self.assertEqual(plugin_footprint.hook_effects('PreToolUse', {'type': 'http', 'url': 'https://x'}, root), {})
        self.assertEqual(plugin_footprint.hook_effects('PermissionRequest', {'type': 'prompt', 'prompt': 'p'}, root)['decides_permissions'], True)


class PluginHandlersInSnapshot(PatchedHome):
    def test_collected_plugin_handlers_carry_the_flags_and_other_handlers_do_not(self):
        hooks = {'PreToolUse': [{'matcher': 'Bash', 'hooks': [
                     {'type': 'command', 'command': '"${CLAUDE_PLUGIN_ROOT}/hooks/dec.sh"'},
                     {'type': 'command', 'command': '"${CLAUDE_PLUGIN_ROOT}/hooks/plain.sh"'}]}],
                 'PermissionRequest': [{'hooks': [{'type': 'command', 'command': 'true'}]}]}
        install(self, hooks=hooks, files={'hooks/dec.sh': DECIDER, 'hooks/plain.sh': 'echo hi'})
        self.write('.claude/settings.json', {'enabledPlugins': {'demo@market': True}})
        snap = collect.build_snapshot(args())
        (plugin,) = [p for p in snap['extensions']['plugins'] if p['name'] == 'demo@market']
        (component,) = [c for c in plugin['components'] if c['kind'] == 'hooks']
        by_target = {h['target']: h for h in component['handlers']}
        self.assertTrue(by_target['"${CLAUDE_PLUGIN_ROOT}/hooks/dec.sh"']['decides_permissions'])
        self.assertEqual(by_target['"${CLAUDE_PLUGIN_ROOT}/hooks/dec.sh"']['decision_file'], 'hooks/dec.sh')
        self.assertNotIn('decides_permissions', by_target['"${CLAUDE_PLUGIN_ROOT}/hooks/plain.sh"'])
        self.assertEqual(by_target['true']['decision_basis'], 'permission_request_event')

    def test_metadata_only_keeps_the_vocabulary_and_masks_the_script_name(self):
        install(self, hooks={'PreToolUse': [{'hooks': [{'type': 'command',
                                                         'command': '"${CLAUDE_PLUGIN_ROOT}/hooks/zcdec.sh"'}]}]},
                files={'hooks/zcdec.sh': DECIDER})
        self.write('.claude/settings.json', {'enabledPlugins': {'demo@market': True}})
        snap = collect.build_snapshot(args(metadata_only=True))
        handlers = [h for p in snap['extensions']['plugins'] for c in p['components'] for h in c.get('handlers', [])]
        self.assertEqual([(h['decides_permissions'], h['decision_basis']) for h in handlers], [(True, 'static_scan')])
        self.assertNotIn('zcdec', json.dumps(snap))


class HandlerTimeout(unittest.TestCase):
    def issues(self, **fields):
        return config_checks.handler_issues('PreToolUse', 'Bash', dict({'type': 'command', 'command': 'x'}, **fields))[0]

    def test_values_above_600_are_suspect(self):
        for value in (601, 5000, 10000, 600.5):
            with self.subTest(value=value):
                self.assertEqual(self.issues(timeout=value), ['timeout_suspect_ms'])

    def test_documented_and_non_numeric_values_are_fine(self):
        for value in (1, 30, 600, True, '5000', None):
            with self.subTest(value=value):
                self.assertEqual(self.issues(timeout=value), [])

    def test_async_command_hooks_and_session_end_are_not_judged(self):
        self.assertEqual(self.issues(timeout=5000, **{'async': True}), [])
        self.assertEqual(config_checks.handler_issues('SessionEnd', None, {'command': 'x', 'timeout': 5000})[0], [])
        self.assertEqual(self.issues(timeout=5000, **{'async': False}), ['timeout_suspect_ms'])

    def test_issue_reaches_the_collected_handler(self):
        entry = collect.hook_handler_entry('PreToolUse', 'Bash', {'type': 'command', 'command': 'x', 'timeout': 5000})
        self.assertEqual(entry['issues'], ['timeout_suspect_ms'])


class InjectionVersusCap(FakeHome):
    def put(self, rel, records):
        self.write('.claude/projects/' + rel, '\n'.join(json.dumps(r) for r in records))

    def raw(self, records):
        self.put('-p/s1.jsonl', records)
        return collect.collect_transcripts(days=30)['_harness']

    def test_list_content_counts_characters_of_its_strings(self):
        raw = self.raw([attachment('hook_additional_context', toolUseID='t', hookEvent='SessionStart',
                                   content=['a' * 6000, 'b' * 5000])])
        self.assertEqual([c for *_, c in raw['injections']], [11000])

    def test_over_cap_counts_records_above_ten_thousand_characters(self):
        index = [{'plugin': 'a@m', 'command': 'run-a', 'event': 'SessionStart'}]
        cmd = attachment('hook_success', toolUseID='t1', command='run-a', hookEvent='SessionStart', stdout='ok')
        raw = self.raw([cmd, attachment('hook_additional_context', toolUseID='t1', hookEvent='SessionStart',
                                        content=['x' * 10001]),
                        attachment('hook_additional_context', toolUseID='t1', hookEvent='SessionStart',
                                   content=['x' * 10000])])
        out = harness.assemble(raw, index, [], {'plugins': []},
                               {'main_files': {'omitted': 0}, 'subagent_files': {'omitted': 0, 'scanned': 0}},
                               30, collect.pct, scan=lambda i: ([], []))['injected_context']
        (src,) = out['sources']
        self.assertEqual((src['over_cap'], src['chars_max'], src['records'], out['output_cap_chars']),
                         (1, 10001, 2, 10000))

    def assemble(self, raw, index):
        return harness.assemble(raw, index, [], {'plugins': []},
                                {'main_files': {'omitted': 0}, 'subagent_files': {'omitted': 0, 'scanned': 0}},
                                30, collect.pct, scan=lambda i: ([], []))['injected_context']

    def test_hook_stdout_rows_attribute_by_command_and_count_over_cap(self):
        index = [{'plugin': 'a@m', 'command': 'run-a', 'event': 'PostToolUse'}]
        raw = self.raw([
            attachment('hook_success', toolUseID='t1', command='run-a', hookEvent='PostToolUse', stdout='y' * 12000),
            attachment('hook_success', toolUseID='t2', command='run-a', hookEvent='PostToolUse', stdout='y' * 5),
            attachment('hook_success', toolUseID='t3', command='mine', hookEvent='PostToolUse', stdout='z' * 7),
            attachment('hook_success', toolUseID='t4', command='quiet', hookEvent='PostToolUse', stdout='')])
        self.assertEqual(self.assemble(raw, index)['hook_stdout'], [
            {'plugin': 'a@m', 'attribution': 'matched', 'hook_event': 'PostToolUse', 'kind': 'plain', 'records': 2,
             'chars_max': 12000, 'over_cap': 1},
            {'plugin': None, 'attribution': 'unattributed', 'hook_event': 'PostToolUse', 'kind': 'plain',
             'records': 1, 'chars_max': 7, 'over_cap': 0}])

    def test_json_stdout_is_sized_per_field_not_as_a_whole_envelope(self):
        index = [{'plugin': 'a@m', 'command': 'run-a', 'event': 'SessionStart'}]
        # Two fields of 6000 characters: 12000+ in total, but each below the cap.
        envelope = json.dumps({'hookSpecificOutput': {'additionalContext': 'a' * 6000}, 'systemMessage': 'b' * 6000})
        over = json.dumps({'hookSpecificOutput': {'additionalContext': 'a' * 10001}})
        raw = self.raw([attachment('hook_success', toolUseID='t1', command='run-a', hookEvent='SessionStart', stdout=envelope),
                        attachment('hook_success', toolUseID='t2', command='run-a', hookEvent='SessionStart', stdout=over),
                        attachment('hook_success', toolUseID='t3', command='run-a', hookEvent='SessionStart',
                                   stdout='{not json ' + 'x' * 10001)])
        rows = {r['kind']: r for r in self.assemble(raw, index)['hook_stdout']}
        self.assertEqual((rows['json']['records'], rows['json']['chars_max'], rows['json']['over_cap']), (2, 10001, 1))
        self.assertEqual((rows['plain']['records'], rows['plain']['over_cap']), (1, 1))

    def test_json_without_capped_fields_and_nested_arrays_do_not_crash(self):
        self.assertEqual(harness.stdout_size('{"continue": true}'), ('json', 0))
        self.assertEqual(harness.stdout_size('{"a":' + '[' * 100000), ('plain', 100005))


class SessionStartGuess(FakeHome):
    def test_plugin_without_a_using_skill_is_not_measured(self):
        _, s = install(self, hooks={'SessionStart': [{'matcher': 'startup', 'hooks': [
            {'type': 'command', 'command': 'x'}]}]})
        index, _ = harness.hook_index(self.claude, [s])
        (row,) = collect.plugin_session_start_hooks(index)
        self.assertEqual((row['est_injected_tokens'], row['basis']), (None, 'not_measured'))

    def test_using_skill_size_is_labelled_a_guess(self):
        _, s = install(self, hooks={'SessionStart': [{'matcher': 'startup', 'hooks': [
            {'type': 'command', 'command': 'x'}]}]}, files={'skills/using-x/SKILL.md': 'x' * 400})
        index, _ = harness.hook_index(self.claude, [s])
        (row,) = collect.plugin_session_start_hooks(index)
        self.assertEqual((row['est_injected_tokens'], row['basis']), (100, 'using_skill_file_size_guess'))


def observer_key(test, name='abc123'):
    return re.sub(r'[^A-Za-z0-9]', '-', os.path.join(test.home, '.claude-mem', 'observer-sessions', name))


def usage_assistant(msg_id, tokens, ts=None):
    return {'type': 'assistant', 'timestamp': ts or stamp(), 'sessionId': 's', 'message': {
        'id': msg_id, 'usage': {'input_tokens': tokens, 'cache_creation_input_tokens': 0,
                                'cache_read_input_tokens': 0, 'output_tokens': 0}}}


def failing_bash(call_id):
    return [{'type': 'assistant', 'timestamp': stamp(), 'sessionId': 's', 'message': {'id': 'x' + call_id, 'content': [
                {'type': 'tool_use', 'id': call_id, 'name': 'Bash', 'input': {'command': 'false'}}]}},
            {'type': 'user', 'timestamp': stamp(), 'sessionId': 's', 'message': {'content': [
                {'type': 'tool_result', 'tool_use_id': call_id, 'is_error': True, 'content': 'Exit code 1'}]}}]


class SpawnedSessions(PatchedHome):
    def put(self, key, name, records):
        self.write(f'.claude/projects/{key}/{name}.jsonl', '\n'.join(json.dumps(r) for r in records))

    def setUp(self):
        super().setUp()
        self.user_key = '-home-user-app'
        self.put(self.user_key, 'u1', [usage_assistant('m1', 100)] + failing_bash('c1'))
        self.put(observer_key(self), 'o1', [usage_assistant('m2', 1000)] + failing_bash('c2') + failing_bash('c3'))
        self.put(observer_key(self, 'def456'), 'o2', [usage_assistant('m3', 50)])

    def test_label_tokens_stay_in_the_totals(self):
        t = collect.collect_transcripts(days=30)
        spawned = t['plugin_spawned']
        self.assertEqual(spawned['rows'], [{'label': 'claude-mem', 'sessions': 2, 'subagent_files': 0, 'tokens': 1050}])
        self.assertEqual((spawned['tokens_spawned'], spawned['tokens_total']), (1050, 1150))
        self.assertEqual(t['_harness']['sessions'], 3)  # still scanned for cost

    def test_tool_errors_and_baseline_exclude_spawned_sessions(self):
        t = collect.collect_transcripts(days=30)
        self.assertEqual(t['tool_errors']['error_results_paired'], 1)
        self.assertEqual(t['context_baseline_tokens']['max'], 100)
        self.assertEqual(t['sessions_measured'], 1)

    def test_subagent_files_of_a_spawned_session_are_counted_and_stay_in_tokens(self):
        self.put(observer_key(self) + '/o1/subagents', 'agent-1', [dict(usage_assistant('m9', 7), isSidechain=True)])
        t = collect.collect_transcripts(days=30)
        (row,) = t['plugin_spawned']['rows']
        self.assertEqual((row['subagent_files'], row['tokens']), (1, 1057))

    def test_a_directory_that_only_resembles_the_observer_root_is_not_labelled(self):
        key = re.sub(r'[^A-Za-z0-9]', '-', os.path.join(self.home, '.claude-mem', 'observer-sessionsX'))
        self.put(key, 'z', [usage_assistant('m4', 5)])
        self.assertEqual(collect.collect_transcripts(days=30)['plugin_spawned']['rows'][0]['sessions'], 2)

    def test_no_spawned_sessions_yields_empty_rows(self):
        t = collect.collect_transcripts(days=30, project_filter={'/home/user/app'})
        self.assertEqual(t['plugin_spawned']['rows'], [])

    def meta(self, sid, project, **extra):
        self.write(f'.claude/usage-data/session-meta/{sid}.json', dict({
            'session_id': sid, 'start_time': stamp(), 'project_path': project, 'first_prompt': 'p',
            'tool_counts': {'Bash': 3}, 'tool_errors': 4, 'tool_error_categories': {'Exit': 4},
            'user_interruptions': 1, 'output_tokens': 900}, **extra))

    def test_usage_keeps_spawned_in_cost_views_and_out_of_learning_views(self):
        spawned = os.path.join(self.home, '.claude-mem', 'observer-sessions', 'abc123')
        self.meta('a', os.path.join(self.home, 'code', 'app'), output_tokens=10, tool_errors=0,
                  tool_error_categories={})
        self.meta('b', spawned)
        self.write('.claude/usage-data/facets/a.json', {'session_id': 'a', 'friction_counts': {'wrong_approach': 1},
                                                          'outcome': 'ok'})
        self.write('.claude/usage-data/facets/b.json', {'session_id': 'b', 'friction_counts': {'wrong_approach': 5},
                                                          'outcome': 'bad'})
        u = collect.collect_usage(30)
        self.assertEqual(u['heaviest_sessions'][0]['plugin_spawned'], 'claude-mem')
        self.assertEqual(u['session_meta_count'], 2)
        self.assertEqual(u['plugin_spawned_sessions'], 1)
        self.assertEqual(dict(u['top_tools']), {'Bash': 3})  # only the user's own session
        self.assertEqual(u['tool_error_categories'], [])
        self.assertEqual([s['project'] for s in u['most_friction_sessions']], ['~/code/app'])
        self.assertEqual(u['avg_tool_errors_per_session'], 0.0)
        self.assertEqual(u['facet_friction'], [('wrong_approach', 1)])
        self.assertEqual(u['facet_outcomes'], {'ok': 1})

    def test_corrections_and_ledger_selectors_exclude_spawned_projects(self):
        now_ms = int(time.time() * 1000)
        spawned = os.path.join(self.home, '.claude-mem', 'observer-sessions', 'abc123')
        rows = [{'display': 'no, that is wrong', 'project': p, 'timestamp': now_ms, 'sessionId': sid}
                for p, sid in ((os.path.join(self.home, 'code', 'app'), 'a'), (spawned, 'b'))]
        self.write('.claude/history.jsonl', '\n'.join(map(json.dumps, rows)) + '\n')
        c = collect.collect_corrections(30)
        self.assertEqual((c['count'], [s['project'] for s in c['samples']]), (1, ['~/code/app']))
        counts = collect.count_selector({'type': 'keywords', 'source': 'corrections', 'any': ['wrong']},
                                        time.time() - 3600, time.time() + 60)
        self.assertEqual((counts['matches'], counts['sessions_scanned']), (1, 1))

    def test_facet_selector_excludes_spawned(self):
        spawned = os.path.join(self.home, '.claude-mem', 'observer-sessions', 'abc123')
        self.meta('a', os.path.join(self.home, 'code', 'app'))
        self.meta('b', spawned)
        for sid in 'ab':
            self.write(f'.claude/usage-data/facets/{sid}.json', {'session_id': sid, 'friction_counts': {'x': 2}})
        counts = collect.count_selector({'type': 'friction_category', 'name': 'x'}, time.time() - 3600, time.time() + 60)
        self.assertEqual((counts['matches'], counts['sessions_scanned']), (2, 1))

    def test_snapshot_carries_the_breakdown_and_schema_valid_in_every_mode(self):
        for kw in ({}, {'metadata_only': True}):
            with self.subTest(kw=kw):
                snap = collect.build_snapshot(args(**kw))
                self.assertEqual(snap['transcripts']['plugin_spawned']['rows'][0]['label'], 'claude-mem')
                self.assertNotIn('abc123', json.dumps(snap))


class PluginRulesPrivacy(PatchedHome):
    def setUp(self):
        super().setUp()
        self.root = os.path.join(self.home, 'code', 'app')
        path = self.write('code/app/.claude/settings.local.json', {
            'permissions': {'deny': ['WebFetch', 'mcp__zcserver__do']},
            'quartermaster': {'autoApprovePermissions': True}})
        ledger(self, {os.path.realpath(path): ['WebFetch', 'mcp__zcserver__do']})

    def written(self, snap):
        (settings,) = snap['projects'][self.root.replace(self.home, '~')]['settings']
        return settings

    def test_full_snapshot_names_rules_and_metadata_only_masks_them_but_keeps_the_attribution(self):
        full = self.written(collect.build_snapshot(args(roots=[self.root])))
        self.assertEqual(full['plugin_written_rules'][0]['rules'], ['WebFetch', 'mcp__zcserver__do'])
        snap = collect.build_snapshot(args(roots=[self.root], metadata_only=True))
        self.assertGreaterEqual(snap['coverage']['privacy']['replaced_fields']['plugin_written_rules'], 2)
        meta = self.written(snap)
        (entry,) = meta['plugin_written_rules']
        self.assertEqual((entry['plugin'], entry['list'], entry['rule_count'], entry['ledger_only']),
                         ('TokenEconomizer', 'deny', 2, 0))
        self.assertTrue(all(privacy_marker(r) for r in entry['rules']))
        self.assertEqual(meta['plugin_markers'], ['quartermaster.autoApprovePermissions'])

    def test_ledger_source_is_reported_in_coverage_without_a_path(self):
        snap = collect.build_snapshot(args(roots=[self.root]))
        (src,) = [x for x in snap['coverage']['sources'] if x['source'] == 'plugin_footprint.tokeneconomizer_ledger']
        self.assertEqual((src['status'], src['files'], src['unreadable']), ('collected', 1, 0))
        self.assertNotIn('untool_applied', json.dumps(snap))


def privacy_marker(value):
    return re.fullmatch(r'\[metadata-only: \d+ chars\]', value) is not None


class PruneAndPluginRules(PatchedHome):
    """prune_permissions only removes allow rules and directories; the ledger records deny rules only."""
    ONE_OFF = 'Bash(curl https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa)'

    def write_settings(self, **settings):
        return self.write('code/app/.claude/settings.local.json', settings)

    def run_cli(self, path, *extra):
        out = io.StringIO()
        argv = ['prune_permissions.py', '--remove', 'one-off,stale-dirs', '--files', path, *extra]
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out):
            prune_permissions.main()
        return json.loads(out.getvalue())

    def test_a_deny_rule_is_never_proposed_even_when_it_would_match_a_category(self):
        path = self.write_settings(permissions={'deny': [self.ONE_OFF, 'WebFetch'], 'allow': []})
        ledger(self, {os.path.realpath(path): [self.ONE_OFF, 'WebFetch']})
        plan = self.run_cli(path, '--apply', '--backup-dir', os.path.join(self.home, 'bk'))
        self.assertEqual((plan['rules'], plan['files']), (0, []))
        with open(path) as f:
            self.assertEqual(json.load(f)['permissions']['deny'], [self.ONE_OFF, 'WebFetch'])

    def test_a_ledger_deny_entry_does_not_protect_a_users_allow_rule(self):
        path = self.write_settings(permissions={'allow': [self.ONE_OFF]})
        ledger(self, {os.path.realpath(path): [self.ONE_OFF]})
        _, removals, _, _, _ = prune_permissions.plan_file_detail(path, {'one-off'})
        self.assertEqual(len(removals), 1)
        self.assertNotIn('kept_plugin_written', self.run_cli(path)['files'][0])

    def test_marker_file_is_flagged_but_rules_stay_proposable(self):
        path = self.write_settings(permissions={'allow': [self.ONE_OFF]}, quartermaster={'autoApprovePermissions': True})
        _, removals, _, _, markers = prune_permissions.plan_file_detail(path, {'one-off'})
        self.assertEqual((len(removals), markers), (1, ['quartermaster.autoApprovePermissions']))
        entry = self.run_cli(path)['files'][0]
        self.assertEqual(entry['plugin_markers'], ['quartermaster.autoApprovePermissions'])
        self.assertIn('auto-approve', entry['plugin_note'])

    def test_unmarked_file_has_no_note(self):
        path = self.write_settings(permissions={'allow': [self.ONE_OFF]})
        self.assertNotIn('plugin_note', self.run_cli(path)['files'][0])


if __name__ == '__main__':
    unittest.main()
