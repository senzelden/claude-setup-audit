"""Harness overhead: hook index, attribution, static scan, assembly. Fake homes only."""
import json
import os
from pathlib import Path
import time
import unittest
import unittest.mock
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


def now_iso(offset=0):
    return collect.datetime.fromtimestamp(time.time() + offset, collect.timezone.utc).isoformat()


def attachment(kind, **fields):
    return {'type': 'attachment', 'timestamp': now_iso(), 'attachment': dict(type=kind, **fields)}


def assistant(msg_id, tokens, sidechain=False, entrypoint='cli'):
    return {'type': 'assistant', 'timestamp': now_iso(), 'isSidechain': sidechain, 'entrypoint': entrypoint,
            'message': {'id': msg_id, 'usage': {'input_tokens': tokens, 'cache_creation_input_tokens': 0,
                                                'cache_read_input_tokens': 0, 'output_tokens': 0}}}


class TranscriptSignals(FakeHome):
    def put(self, rel, records, extra=''):
        self.write('.claude/projects/' + rel, '\n'.join(json.dumps(r) for r in records) + extra)

    def test_attachments_entrypoints_and_tokens(self):
        self.put('-p/s1.jsonl', [
            attachment('hook_success', toolUseID='t1', command='run', hookEvent='SessionStart'),
            attachment('hook_additional_context', toolUseID='t1', hookEvent='SessionStart', content='x' * 40),
            attachment('skill_listing', isInitial=True, skillCount=12, content='y' * 100),
            attachment('skill_listing', isInitial=False, skillCount=99, content='z'),
            assistant('m1', 10, entrypoint='sdk-py'), assistant('m2', 5, sidechain=True)])
        self.put('-p/s1/subagents/a.jsonl', [assistant('s1', 7), assistant('s2', 3)])
        old = attachment('hook_additional_context', toolUseID='t9', hookEvent='SessionStart', content='old')
        old['timestamp'] = now_iso(-40 * 86400)
        self.put('-p/s2.jsonl', [old])
        h = collect.collect_transcripts(days=30)['_harness']
        main = os.path.join(self.claude, 'projects', '-p', 's1.jsonl')
        self.assertEqual(h['sessions'], 1)
        self.assertEqual(h['injections'], [(main, 'SessionStart', 't1', 40)])
        self.assertEqual(h['commands'], {(main, 't1'): 'run'})
        self.assertEqual([(c, n) for _, c, n in h['listings']], [(12, 100)])
        self.assertEqual(dict(h['entrypoints']), {'sdk-py': 1})
        self.assertEqual(h['main_tokens'], {('-p', 's1'): 10})
        self.assertEqual(h['sub_tokens'], {('-p', 's1'): 10})

    def test_duplicate_message_ids_counted_once(self):
        self.put('-p/s1.jsonl', [assistant('m1', 10), assistant('m1', 10)])
        self.put('-p/s1/subagents/a.jsonl', [assistant('s1', 7), assistant('s1', 7)])
        h = collect.collect_transcripts(days=30)['_harness']
        self.assertEqual((h['main_tokens'], h['sub_tokens']), ({('-p', 's1'): 10}, {('-p', 's1'): 7}))

    def test_bad_skill_listing_fields_are_ignored(self):
        self.put('-p/s1.jsonl', [attachment('skill_listing', isInitial=True, skillCount='12', content='y'),
                                 attachment('skill_listing', isInitial=True, skillCount=3, content=None)])
        self.assertEqual([(c, n) for _, c, n in collect.collect_transcripts(days=30)['_harness']['listings']],
                         [(3, 0)])

    def test_malformed_lines_and_non_string_content(self):
        self.put('-p/s1.jsonl', [attachment('hook_additional_context', toolUseID=None, hookEvent='Stop',
                                            content={'k': 'v'}), [1, 2]], extra='\n{not json')
        h = collect.collect_transcripts(days=30)['_harness']
        self.assertEqual(h['malformed'], 2)
        self.assertEqual(h['injections'][0][1:], ('Stop', None, len('{"k":"v"}')))
        self.assertEqual(dict(h['entrypoints']), {})

    def test_missing_or_null_injection_content_is_not_observed(self):
        self.put('-p/s1.jsonl', [attachment('hook_additional_context', toolUseID='t1', hookEvent='Stop'),
                                 attachment('hook_additional_context', toolUseID='t2', hookEvent='Stop',
                                            content=None)])
        self.assertEqual(collect.collect_transcripts(days=30)['_harness']['injections'], [])

    def test_non_string_entrypoint_counts_as_other(self):
        self.put('-p/s1.jsonl', [assistant('m1', 1, entrypoint=7)])
        self.put('-p/s2.jsonl', [assistant('m2', 1, entrypoint=None)])
        self.assertEqual(dict(collect.collect_transcripts(days=30)['_harness']['entrypoints']), {'other': 1})


def cover(main_omitted=0, sub_omitted=0, sub_scanned=0):
    return {'main_files': {'omitted': main_omitted}, 'subagent_files': {'omitted': sub_omitted, 'scanned': sub_scanned}}


def raw_signals(**over):
    raw = {'sessions': 0, 'injections': [], 'commands': {}, 'listings': [], 'entrypoints': {},
           'main_tokens': {}, 'sub_tokens': {}, 'malformed': 0}
    raw.update(over)
    return raw


class Assemble(unittest.TestCase):
    index = [{'plugin': 'a@m', 'command': 'run-a', 'event': 'SessionStart'},
             {'plugin': 'b@m', 'command': 'dup', 'event': 'SessionStart'},
             {'plugin': 'c@m', 'command': 'dup', 'event': 'SessionStart'}]

    def build(self, raw, coverage=None, inventory=None, reasons=()):
        return harness.assemble(raw, self.index, list(reasons), inventory or {'plugins': []},
                                coverage or cover(), 30, collect.pct, scan=lambda index: ([], []))

    def test_startup_and_compact_sum_to_one_session(self):
        raw = raw_signals(sessions=1, injections=[('s1', 'SessionStart', 't1', 3000), ('s1', 'SessionStart', 't2', 1000)],
                          commands={('s1', 't1'): 'run-a', ('s1', 't2'): 'run-a'})
        src = self.build(raw)['injected_context']['sources']
        self.assertEqual(src, [{'plugin': 'a@m', 'attribution': 'matched', 'hook_event': 'SessionStart',
                                'sessions': 1, 'records': 2, 'chars_per_session_median': 4000,
                                'chars_per_session_p90': 4000, 'est_tokens_per_session_median': 1000}])

    def test_unpaired_injection_is_unattributed_and_ambiguous_is_kept_apart(self):
        raw = raw_signals(sessions=2, injections=[('s1', 'Stop', None, 10), ('s2', 'SessionStart', 't', 20)],
                          commands={('s2', 't'): 'dup'})
        rows = {(r['attribution'], r['hook_event']): r for r in self.build(raw)['injected_context']['sources']}
        self.assertEqual(set(rows), {('unattributed', 'Stop'), ('ambiguous', 'SessionStart')})
        self.assertIsNone(rows[('ambiguous', 'SessionStart')]['plugin'])
        self.assertEqual(self.build(raw)['injected_context']['sessions_with_injection'], 2)

    def test_skill_listing_series_and_per_plugin_skills(self):
        raw = raw_signals(listings=[(2000.0, 79, 29782), (1000.0, 12, 5837), (1500.0, 90, 20000)])
        inv = {'plugins': [{'name': 'a@m', 'components': [{'kind': 'skills'}, {'kind': 'skills'}, {'kind': 'agents'}]},
                           {'name': 'b@m', 'components': [{'kind': 'hooks'}]}]}
        series = self.build(raw, inventory=inv)['skill_listing_series']
        self.assertEqual(series['sessions'], 3)
        self.assertEqual(series['first'], {'date': '1970-01-01', 'skill_count': 12, 'chars': 5837})
        self.assertEqual(series['last']['skill_count'], 79)
        self.assertEqual(series['max'], {'skill_count': 90, 'chars': 20000})
        self.assertEqual(series['per_plugin_skills'], [{'plugin': 'a@m', 'skills': 2}])

    def test_no_listings_is_null_and_not_observed(self):
        out = self.build(raw_signals())
        self.assertIsNone(out['skill_listing_series'])
        self.assertEqual(out['incomplete_reasons'], ['not_observed'])
        self.assertTrue(out['complete'])

    def test_subagent_spend_and_entrypoints(self):
        raw = raw_signals(entrypoints={'cli': 2, 'sdk-py': 1, 'weird': 1},
                          main_tokens={('p', 's1'): 100, ('p', 's2'): 300}, sub_tokens={('p', 's1'): 50})
        spend = self.build(raw, coverage=cover(sub_scanned=4))['subagent_spend']
        self.assertEqual(spend, {'subagent_files_scanned': 4, 'sessions_with_subagents': 1,
                                 'subagent_tokens_per_session_median': 50, 'main_tokens_per_session_median': 200,
                                 'entrypoints': {'cli': 2, 'sdk-py': 1, 'sdk-cli': 0, 'other': 1}})

    def test_caps_malformed_and_index_reasons_make_it_incomplete(self):
        out = self.build(raw_signals(malformed=1, listings=[(1.0, 1, 1)]),
                         coverage=cover(main_omitted=1, sub_omitted=2), reasons=['plugin_root_unreadable'])
        self.assertFalse(out['complete'])
        self.assertEqual(out['incomplete_reasons'], ['main_file_cap', 'malformed_records',
                                                     'plugin_root_unreadable', 'subagent_file_cap'])


class EndToEnd(FakeHome):
    def test_snapshot_has_valid_private_harness_section(self):
        secret = 'sk-ant-api03-' + 'A' * 40
        _, s = install(self, hooks=session_start(f'echo {secret}'), files={'hooks/x.sh': f'TOKEN={secret}\n'})
        self.write('.claude/settings.json', {'enabledPlugins': s['enabled_plugins']})
        self.write('.claude/projects/-p/s1.jsonl', '\n'.join(json.dumps(r) for r in [
            attachment('hook_success', toolUseID='t1', command=f'echo {secret}', hookEvent='SessionStart'),
            attachment('hook_additional_context', toolUseID='t1', hookEvent='SessionStart', content=secret),
            attachment('skill_listing', isInitial=True, skillCount=2, content=secret)]))
        out = os.path.join(self.home, 'snap.json')
        with unittest.mock.patch('sys.argv', ['collect.py', '--claude-dir', self.claude, '--out', out]), \
                unittest.mock.patch.object(collect, '_write_snapshot',
                                           lambda path, text: Path(path).write_text(text)):
            collect.main()
        text = Path(out).read_text()
        self.assertNotIn(secret, text)
        self.assertNotIn('echo', json.dumps(json.loads(text)['harness_overhead']))
        section = json.loads(text)['harness_overhead']
        self.assertEqual(section['injected_context']['sources'][0]['plugin'], 'demo@market')
        self.assertEqual(section['skill_listing_series']['last']['skill_count'], 2)
        sources = {c['source']: c for c in json.loads(text)['coverage']['sources']}
        self.assertIn('harness_overhead', sources)
