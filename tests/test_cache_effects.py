"""Cache effect table, helper output, estimate and tool-search detection. Fake homes only."""
import contextlib
import io
import json
import os
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_collect import FakeHome, SCRIPTS, collect  # noqa: F401  (puts scripts/ on sys.path)
import apply_ops
import cache_effects as ce
import prune_permissions

NOW = 1789473600  # 2026-09-15 12:00 UTC
REFERENCE = Path(SCRIPTS).parent / 'references' / 'cache-effects.md'


def stamp(offset=0):
    return collect.datetime.fromtimestamp(NOW + offset, collect.timezone.utc).isoformat()


class Table(unittest.TestCase):
    def test_every_allowlisted_sandbox_key_has_a_table_row(self):
        for key in apply_ops.SANDBOX_KEYS:
            row = ce.effect_for('setting', key)
            self.assertIn(row['family'], ce.ROWS, key)
            self.assertNotEqual(row['family'], 'file.other', key)
            self.assertIn(row['effect'], ce.EFFECTS, key)

    def test_rows_are_well_formed_and_documented(self):
        doc = REFERENCE.read_text()
        for family, (effect, source, note) in ce.ROWS.items():
            self.assertIn(effect, ce.EFFECTS, family)
            self.assertTrue(source and note, family)
            self.assertIn(f'`{family}`', doc, f'{family} missing from references/cache-effects.md')
        for effect in ce.EFFECTS:
            self.assertIn(f'`{effect}`', doc)

    def test_unknown_inputs_fail_honest(self):
        for kind, key in (('setting', 'someFutureKey'), ('setting', 'sandbox_not'), ('setting', None),
                          ('file', 'notes.txt'), ('rule-deny', ''), ('bogus', 'x')):
            self.assertEqual(ce.effect_for(kind, key)['effect'], 'unknown', (kind, key))

    def test_permission_rules(self):
        for kind in ('allow', 'ask'):
            for rule in ('Bash', 'Bash(*)', 'Bash(rm *)', 'mcp__*'):
                self.assertEqual(ce.effect_for(f'rule-{kind}', rule)['effect'], 'keeps', (kind, rule))
        self.assertEqual(ce.effect_for('rule-deny', 'Bash(rm *)')['effect'], 'keeps')
        self.assertEqual(ce.effect_for('rule-deny', 'Read(./.env)')['effect'], 'keeps')
        for rule in ('Bash', 'WebFetch', 'Bash(*)', '*', 'mcp__*', 'mcp__github'):
            self.assertEqual(ce.effect_for('rule-deny', rule)['effect'],
                             'invalidates_without_tool_search', rule)

    def test_bare_name_deny_label_follows_tool_search_state(self):
        seen = ce.effect_for('rule-deny', 'Bash', True)['label']
        none = ce.effect_for('rule-deny', 'Bash', False)['label']
        both = ce.effect_for('rule-deny', 'Bash', None)['label']
        self.assertEqual(seen, 'keeps the cache (tool search observed)')
        self.assertEqual(none, 'invalidates (no tool search observed)')
        self.assertIn('keeps the cache', both)
        self.assertIn('invalidates', both)
        self.assertNotIn('observed)', both)

    def test_read_once_keys_and_files_apply_next_session(self):
        for key in ('model', 'effortLevel', 'modelSettings'):
            self.assertEqual(ce.effect_for('setting', key)['effect'], 'applies_next_session', key)
        for name in ('/h/CLAUDE.md', 'CLAUDE.md', '/h/p/CLAUDE.local.md', '/h/.claude/projects/x/memory/MEMORY.md'):
            self.assertEqual(ce.effect_for('file', name)['effect'], 'applies_next_session', name)
        self.assertEqual(ce.effect_for('file', '/h/p/.mcp.json')['effect'], 'applies_next_session')
        self.assertEqual(ce.effect_for('setting', 'enabledMcpjsonServers')['effect'], 'applies_next_session')

    def test_not_covered_families_are_unknown_not_guessed(self):
        for key in ('hooks', 'hooks.PreToolUse', 'env', 'env.FOO', 'sandbox.enabled', 'promptCacheTtl',
                    'permissions.additionalDirectories', 'enabledPlugins'):
            self.assertEqual(ce.effect_for('setting', key)['effect'], 'unknown', key)


class Estimate(unittest.TestCase):
    def test_write_instead_of_read_price(self):
        e = ce.estimate_reread(100000, '5m')
        self.assertTrue(e['estimate'])
        self.assertEqual((e['write_multiplier'], e['read_multiplier']), (1.25, 0.1))
        self.assertEqual(e['extra_cost_base_input_tokens'], round(100000 * (1.25 - 0.1)))
        self.assertEqual(ce.estimate_reread(100000, '1h')['write_multiplier'], 2.0)

    def test_model_read_multiplier_and_no_prices(self):
        self.assertEqual(ce.estimate_reread(1000, '5m', 'claude-opus-5-5')['read_multiplier'], 0.05)
        self.assertEqual(ce.estimate_reread(1000, '5m', 'claude-fable-5.1')['read_multiplier'], 0.025)
        e = ce.estimate_reread(1000, '5m', 'claude-haiku-4-5')
        self.assertEqual(e['read_multiplier'], 0.1)
        self.assertNotIn('$', json.dumps(e))
        self.assertIn('Estimate', e['note'])

    def test_bad_input_is_none(self):
        for bad in (None, -1, True, 1.5, 'x'):
            self.assertIsNone(ce.estimate_reread(bad), bad)
        self.assertIsNone(ce.estimate_reread(10, '2h'))


class Signals(FakeHome):
    def test_load_signals(self):
        snap = self.write('s.json', {'transcripts': {'tool_search_observed': True,
                                                     'cache': {'context_tokens': {'median': 1234.6}}}})
        self.assertEqual(ce.load_signals(snap), (True, 1235))
        self.assertEqual(ce.load_signals(self.write('t.json', {'transcripts': {}})), (None, None))
        self.assertEqual(ce.load_signals(self.write('u.json', '{')), (None, None))
        self.assertEqual(ce.load_signals(os.path.join(self.home, 'missing')), (None, None))
        self.assertEqual(ce.load_signals(None), (None, None))


class ApplyOpsOutput(FakeHome):
    FILE = '~/p/.claude/settings.local.json'

    def ops(self, expect_file=None, paths=(('sandbox.enabled', True), ('sandbox.network.allowedDomains', ['a.example']))):
        t = {'file': self.FILE, 'ops': [{'op': 'set', 'path': p, 'value': v, 'expect': {'absent': True}}
                                        for p, v in paths]}
        if expect_file:
            t['expect_file'] = expect_file
        return json.dumps({'version': 1, 'targets': [t]}).encode()

    def test_plan_and_apply_state_the_effect_per_op(self):
        path = self.write('p/.claude/settings.local.json', {})
        plan = apply_ops.run(self.ops())
        rows = plan['targets'][0]['ops']
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row['cache_effect'], ce.effect_for('setting', row['path']))
        self.assertIn('never', plan['cache_effects_note'])
        digest = plan['targets'][0]['file_sha256']
        backups = os.path.join(self.home, 'backups')
        done = apply_ops.run(self.ops(digest), apply=True, backup_dir=backups)
        self.assertTrue(done['ok'], done)
        self.assertTrue(all('cache_effect' in r for r in done['targets'][0]['ops']))
        self.assertIn('sandbox', json.loads(Path(path).read_text()))

    def test_nothing_gates_on_the_effect(self):
        hostile = {'effect': 'invalidates_next_request', 'label': 'x', 'family': 'f', 'source': 's', 'note': 'n'}
        self.write('p/.claude/settings.local.json', {})
        with mock.patch.object(ce, 'effect_for', return_value=hostile):
            plan = apply_ops.run(self.ops())
            done = apply_ops.run(self.ops(plan['targets'][0]['file_sha256']), apply=True,
                                 backup_dir=os.path.join(self.home, 'backups'))
        self.assertTrue(plan['ok'] and done['ok'], done)
        self.assertEqual(done['targets'][0]['status'], 'applied')
        self.assertEqual(done['targets'][0]['ops'][0]['cache_effect']['effect'], 'invalidates_next_request')

    def test_estimate_appears_only_with_context_and_a_possibly_invalidating_effect(self):
        snap = self.write('s.json', {'transcripts': {'cache': {'context_tokens': {'median': 50000}}}})
        self.write('p/.claude/settings.local.json', {})
        self.assertNotIn('cache_estimate', apply_ops.run(self.ops(), snapshot=snap))  # sandbox: unknown
        hostile = {'effect': 'invalidates_next_request', 'label': 'x', 'family': 'f', 'source': 's', 'note': 'n'}
        with mock.patch.object(ce, 'effect_for', return_value=hostile):
            self.assertTrue(apply_ops.run(self.ops(), snapshot=snap)['cache_estimate']['estimate'])
            self.assertNotIn('cache_estimate', apply_ops.run(self.ops()))


class PruneOutput(FakeHome):
    def run_prune(self, *extra, rules=('Bash(curl:*)',), dirs=()):
        target = self.write('p/.claude/settings.json',
                            {'permissions': {'allow': list(rules), 'additionalDirectories': list(dirs)}})
        argv = ['prune_permissions.py', '--remove', 'network-wildcard,stale-dirs', '--files', target, *extra]
        out = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out):
            prune_permissions.main()
        return json.loads(out.getvalue()), target

    def test_each_removal_states_its_effect(self):
        result, _ = self.run_prune(dirs=['/nonexistent-dir-for-test'])
        entry = result['files'][0]
        self.assertEqual(entry['remove_rules'][0]['cache_effect']['effect'], 'keeps')
        self.assertEqual(entry['remove_dirs_cache_effect']['effect'], 'unknown')
        self.assertIn('never', result['cache_effects_note'])

    def test_apply_is_not_gated_by_the_effect(self):
        hostile = {'effect': 'invalidates_next_request', 'label': 'x', 'family': 'f', 'source': 's', 'note': 'n'}
        with mock.patch.object(ce, 'effect_for', return_value=hostile):
            result, target = self.run_prune('--apply', '--backup-dir', os.path.join(self.home, 'b'))
        self.assertTrue(result['applied'])
        self.assertNotIn('Bash(curl:*)', json.loads(Path(target).read_text())['permissions']['allow'])
        self.assertNotIn('apply_error', result['files'][0])


class ToolSearchObserved(FakeHome):
    def scan(self):
        with mock.patch.object(collect.time, 'time', return_value=NOW):
            return collect.collect_transcripts(1)

    def session(self, rel, records):
        self.write(f'.claude/projects/{rel}', '\n'.join(map(json.dumps, records)))

    @staticmethod
    def delta(offset=0, kind='deferred_tools_delta'):
        return {'type': 'attachment', 'timestamp': stamp(offset), 'attachment': {'type': kind, 'addedNames': ['x']}}

    @staticmethod
    def reply(msg_id, usage, offset=0):
        return {'type': 'assistant', 'timestamp': stamp(offset),
                'message': {'id': msg_id, 'model': 'claude-opus-5-5', 'usage': usage}}

    def test_true_when_a_main_thread_delta_is_in_the_window(self):
        self.session('-a/s1.jsonl', [self.delta()])
        self.assertIs(self.scan()['tool_search_observed'], True)

    def test_false_without_delta_other_attachments_subagents_or_old_records(self):
        self.session('-a/s1.jsonl', [self.delta(kind='skill_listing'), self.delta(offset=-10 * 86400)])
        self.session('-a/s1/subagents/ag.jsonl', [self.delta()])
        self.assertIs(self.scan()['tool_search_observed'], False)

    def test_false_on_empty_home(self):
        self.assertIs(self.scan()['tool_search_observed'], False)

    def test_context_tokens_median_over_deduplicated_main_responses(self):
        def usage(i, w, r):
            return {'input_tokens': i, 'cache_creation_input_tokens': w, 'cache_read_input_tokens': r}
        self.session('-a/s1.jsonl', [self.reply('m1', usage(1, 99, 0)), self.reply('m2', usage(1, 0, 299)),
                                     self.reply('m2', usage(1, 0, 299)), self.reply('m3', usage(1, 0, 999))])
        ctx = self.scan()['cache']['context_tokens']
        self.assertEqual((ctx['median'], ctx['responses']), (300, 3))


class SnapshotContract(unittest.TestCase):
    def test_schema_types_the_field(self):
        schema = json.loads((Path(SCRIPTS).parent / 'references' / 'snapshot.schema.json').read_text())
        self.assertEqual(schema['properties']['transcripts']['properties']['tool_search_observed'],
                         {'type': 'boolean'})

    def test_coverage_labels_the_field_observed_undocumented(self):
        text = (Path(SCRIPTS).parent / 'references' / 'coverage.md').read_text()
        match = re.search(r'Tool search \(`transcripts\.tool_search_observed`;[^)]*\)', text)
        self.assertTrue(match and 'observed, undocumented' in match.group(0))


if __name__ == '__main__':
    unittest.main()
