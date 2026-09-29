"""Harness overhead: hook index, attribution, static scan, assembly. Fake homes only."""
import json
import os
import time
import unittest
from test_collect import FakeHome, collect
import harness


def install(t, name='demo', market='market', version='1', hooks=None, files=None, enabled=True, manifest=None):
    root = os.path.join(t.claude, 'plugins', 'cache', market, name, version)
    reg_path = os.path.join(t.claude, 'plugins', 'installed_plugins.json')
    reg = {'version': 2, 'plugins': {}}
    if os.path.exists(reg_path):
        with open(reg_path) as f:
            reg = json.load(f)
    reg['plugins'][f'{name}@{market}'] = [{'scope': 'user', 'installPath': root, 'version': version}]
    t.write('.claude/plugins/installed_plugins.json', reg)
    t.write(os.path.relpath(os.path.join(root, '.claude-plugin', 'plugin.json'), t.home),
            manifest or {'name': name})
    if hooks is not None:
        t.write(os.path.relpath(os.path.join(root, 'hooks', 'hooks.json'), t.home), {'hooks': hooks})
    for rel, text in (files or {}).items():
        t.write(os.path.relpath(os.path.join(root, rel), t.home), text)
    return root, {'path': 'settings.json', 'enabled_plugins': {f'{name}@{market}': enabled}}


def session_start(command):
    return {'SessionStart': [{'matcher': 'startup', 'hooks': [{'type': 'command', 'command': command}]}]}


class HookIndex(FakeHome):
    def test_registry_install_path_wins_over_newer_cache_copy(self):
        root, s = install(self, hooks=session_start('"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" start'),
                          files={'skills/using-demo/SKILL.md': 'x' * 400})
        stale = os.path.join(self.claude, 'plugins/cache/market/demo/2/hooks/hooks.json')
        self.write(os.path.relpath(stale, self.home), {'hooks': session_start('stale')})
        future = time.time() + 1000
        os.utime(stale, (future, future))
        index, reasons = harness.hook_index(self.claude, [s])
        self.assertEqual([e['command'] for e in index], ['"${CLAUDE_PLUGIN_ROOT}/hooks/run.sh" start'])
        self.assertEqual(index[0]['root'], root)
        self.assertEqual(reasons, [])
        found = collect.plugin_session_start_hooks(index)
        self.assertEqual(found, [{'plugin': 'demo@market', 'version': '1', 'matchers': ['startup'],
                                  'est_injected_tokens': 100, 'basis': 'file_size_estimate'}])

    def test_disabled_plugin_and_inline_manifest_hooks(self):
        install(self, name='off', hooks=session_start('a'), enabled=False)
        _, s = install(self, name='inline', manifest={'name': 'inline', 'hooks': {'hooks': session_start('b')}})
        index, _ = harness.hook_index(self.claude, [s, {'enabled_plugins': {'off@market': False}}])
        self.assertEqual([(e['plugin'], e['command']) for e in index], [('inline@market', 'b')])

    def test_root_outside_plugin_storage_is_incomplete(self):
        self.write('.claude/plugins/installed_plugins.json', {'version': 2, 'plugins': {
            'ext@market': [{'scope': 'user', 'installPath': '/elsewhere', 'version': '1'}]}})
        index, reasons = harness.hook_index(self.claude, [{'enabled_plugins': {'ext@market': True}}])
        self.assertEqual((index, reasons), ([], ['plugin_root_unreadable']))

    def test_match_command(self):
        index = [{'plugin': 'a@m', 'command': 'run'}, {'plugin': 'b@m', 'command': 'run'},
                 {'plugin': 'c@m', 'command': 'only-c'}]
        self.assertEqual(harness.match_command(index, 'only-c'), ('c@m', 'matched'))
        self.assertEqual(harness.match_command(index, 'run'), (None, 'ambiguous'))
        self.assertEqual(harness.match_command(index, None), (None, 'unattributed'))

    def test_near_miss_command_is_unattributed(self):
        index = [{'plugin': 'c@m', 'command': '"${CLAUDE_PLUGIN_ROOT}/x.sh" start'}]
        self.assertEqual(harness.match_command(index, '${CLAUDE_PLUGIN_ROOT}/x.sh start'), (None, 'unattributed'))


class StaticScan(FakeHome):
    def scan(self, hooks, files):
        _, s = install(self, hooks=hooks, files=files)
        index, _ = harness.hook_index(self.claude, [s])
        return harness.scan_hooks(index)

    def stop(self, command):
        return {'Stop': [{'hooks': [{'type': 'command', 'command': command}]}]}

    def test_each_pattern_in_a_referenced_script(self):
        script = '#!/bin/sh\n# claude -p "commented out"\necho hi\nclaude -p "reflect" > out\n'
        py = 'import os\nfrom claude_agent_sdk import query\n'
        js = "import x from '@anthropic-ai/claude-agent-sdk'\nconst c = new Anthropic()\n"
        found, reasons = self.scan(
            {'Stop': [{'hooks': [{'type': 'command', 'command': 'bash "${CLAUDE_PLUGIN_ROOT}/hooks/r.sh"'},
                                 {'type': 'command', 'command': 'python3 ${CLAUDE_PLUGIN_ROOT}/hooks/r.py'},
                                 {'type': 'command', 'command': 'node $CLAUDE_PLUGIN_ROOT/hooks/r.mjs'}]}]},
            {'hooks/r.sh': script, 'hooks/r.py': py, 'hooks/r.mjs': js})
        self.assertEqual(reasons, [])
        self.assertEqual([(f['file'], f['line'], f['pattern']) for f in found], [
            ('hooks/r.mjs', 1, 'agent_sdk_js'), ('hooks/r.mjs', 2, 'anthropic_client'),
            ('hooks/r.py', 2, 'agent_sdk_py'), ('hooks/r.sh', 4, 'claude_print')])
        self.assertTrue(all(f['plugin'] == 'demo@market' and f['hook_event'] == 'Stop' for f in found))

    def test_pattern_in_the_command_itself(self):
        found, _ = self.scan(self.stop('claude --print "summarize"'), {})
        self.assertEqual([(f['file'], f['line'], f['pattern']) for f in found],
                         [('hooks/hooks.json', None, 'claude_print')])

    def test_similar_words_do_not_match(self):
        found, _ = self.scan(self.stop('claude-setup -p x; myclaude --print'), {})
        self.assertEqual(found, [])

    def test_symlink_escape_missing_and_truncation(self):
        outside = self.write('outside.sh', 'claude -p x\n')
        root, s = install(self, hooks=self.stop('sh ${CLAUDE_PLUGIN_ROOT}/hooks/link.sh; '
                                                 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/../../../../outside.sh; '
                                                 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/missing.sh; '
                                                 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/big.sh'),
                          files={'hooks/big.sh': 'x\n' * 40000 + 'claude -p late\n'})
        os.symlink(outside, os.path.join(root, 'hooks', 'link.sh'))
        index, _ = harness.hook_index(self.claude, [s])
        found, reasons = harness.scan_hooks(index)
        self.assertEqual(found, [])
        self.assertEqual(reasons, ['script_truncated', 'script_unresolved'])

    def test_same_script_under_two_events_sorts_by_event(self):
        cmd = 'sh ${CLAUDE_PLUGIN_ROOT}/hooks/r.sh'
        found, _ = self.scan(
            {'Stop': [{'hooks': [{'type': 'command', 'command': cmd}]}],
             'SessionStart': [{'hooks': [{'type': 'command', 'command': cmd}]}]},
            {'hooks/r.sh': 'claude -p x\n'})
        self.assertEqual([(f['hook_event'], f['file'], f['line'], f['pattern']) for f in found],
                         [('SessionStart', 'hooks/r.sh', 1, 'claude_print'),
                          ('Stop', 'hooks/r.sh', 1, 'claude_print')])
