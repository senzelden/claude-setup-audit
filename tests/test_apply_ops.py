"""apply_ops: allowlisted structured settings operations. Fake homes only; never the real ~/.claude."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

from test_collect import FakeHome, SCRIPTS  # noqa: F401  (puts scripts/ on sys.path)
import apply_ops
import ledger


def op(path, value=None, expect=None, kind='set'):
    o = {'op': kind, 'path': path, 'expect': expect if expect is not None else {'absent': True}}
    if kind == 'set':
        o['value'] = value
    return o


def sha(path):
    return 'sha256:' + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def reason(fn, *args):
    try:
        fn(*args)
    except apply_ops.OpsError as exc:
        return exc.reason
    return None


class Values(unittest.TestCase):
    def test_bool_keys_accept_only_booleans(self):
        self.assertEqual(apply_ops.validate_value('sandbox.enabled', True, 'local'), [])
        for bad in (1, 'true', None, [True]):
            self.assertEqual(reason(apply_ops.validate_value, 'sandbox.enabled', bad, 'local'), 'invalid_value')

    def test_lists_need_non_empty_strings(self):
        for good in ([], ['~/.npm']):
            self.assertEqual(apply_ops.validate_value('sandbox.network.allowedDomains', good, 'project'), [])
        for bad in ('github.com', [''], [1], {'a': 'b'}):
            self.assertEqual(reason(apply_ops.validate_value, 'sandbox.network.allowedDomains', bad, 'project'),
                             'invalid_value')

    def test_port_bounds_and_bool(self):
        self.assertEqual(apply_ops.validate_value('sandbox.network.httpProxyPort', 8080, 'user'), [])
        for bad in (0, 65536, True, 80.0, '8080'):
            self.assertEqual(reason(apply_ops.validate_value, 'sandbox.network.httpProxyPort', bad, 'user'),
                             'invalid_value')

    def test_ignore_violations_shape(self):
        self.assertEqual(apply_ops.validate_value('sandbox.ignoreViolations', {'npm': ['/x']}, 'local'), [])
        for bad in ({'npm': '/x'}, {'': ['/x']}, ['npm']):
            self.assertEqual(reason(apply_ops.validate_value, 'sandbox.ignoreViolations', bad, 'local'), 'invalid_value')

    def test_wildcard_write_entry_warns_but_read_does_not(self):
        self.assertEqual(apply_ops.validate_value('sandbox.filesystem.allowWrite', ['~/build/**', '~/c*'], 'user'),
                         ['wildcard_ignored_on_linux'])
        self.assertEqual(apply_ops.validate_value('sandbox.filesystem.allowWrite', ['~/build/**'], 'user'), [])
        self.assertEqual(apply_ops.validate_value('sandbox.filesystem.denyRead', ['~/secrets/*'], 'user'), [])

    def test_credential_entries(self):
        files, env = 'sandbox.credentials.files', 'sandbox.credentials.envVars'
        self.assertEqual(apply_ops.validate_value(files, [{'path': '~/.aws/credentials', 'mode': 'deny'}], 'project'), [])
        self.assertEqual(apply_ops.validate_value(
            files, [{'path': '~/.config/gh/hosts.yml', 'mode': 'mask', 'extract': 'oauth_token: (\\S+)',
                     'maskDuplicates': True, 'injectHosts': ['api.github.com']}], 'user'), [])
        self.assertEqual(reason(apply_ops.validate_value, files, [{'path': '~/x', 'mode': 'mask'}], 'local'),
                         'scope_not_honored')
        for bad in ([{'path': '~/x', 'mode': 'deny', 'extract': 'a(b)'}],   # mask field on deny
                    [{'path': '~/x', 'mode': 'hide'}],
                    [{'path': '~/x', 'mode': 'mask', 'colour': 'red'}],
                    [{'path': '~/x', 'mode': 'mask', 'maskClaims': ['sub']}],  # maskClaims needs decode
                    [{'mode': 'deny'}], {'path': '~/x', 'mode': 'deny'}):
            self.assertEqual(reason(apply_ops.validate_value, files, bad, 'user'), 'invalid_value', bad)
        for bad in ([{'name': 'TOKEN', 'mode': 'mask', 'maskDuplicates': True}],
                    [{'name': 'TOKEN', 'mode': 'mask', 'extract': 'x(y)', 'decode': 'jwt'}],
                    [{'name': 'TOKEN', 'mode': 'mask', 'decode': 'jwt', 'onExtractNoMatch': 'deny'}]):
            self.assertEqual(reason(apply_ops.validate_value, env, bad, 'user'), 'invalid_value', bad)
        self.assertEqual(apply_ops.validate_value(env, [{'name': 'AWS_SECRET_ACCESS_KEY', 'mode': 'deny'}], 'local'), [])

    def test_key_classes(self):
        self.assertEqual(reason(apply_ops.check_key, 'permissions.allow', 'user'), 'not_allowlisted')
        self.assertEqual(reason(apply_ops.check_key, 'sandbox.bwrapPath', 'user'), 'excluded_key')
        self.assertEqual(reason(apply_ops.check_key, 'sandbox.ripgrep', 'user'), 'excluded_key')
        self.assertEqual(reason(apply_ops.check_key, 'sandbox', 'user'), 'not_a_leaf')
        self.assertEqual(reason(apply_ops.check_key, 'sandbox.network', 'user'), 'not_a_leaf')
        self.assertEqual(reason(apply_ops.check_key, 'sandbox.netwrok.allowedDomains', 'user'), 'unknown_key')

    def test_scope_rules(self):
        for key in ('sandbox.network.strictAllowlist', 'sandbox.filesystem.disabled', 'sandbox.allowAppleEvents'):
            self.assertEqual(reason(apply_ops.check_key, key, 'local'), 'scope_not_honored')
            self.assertEqual(reason(apply_ops.check_key, key, 'project'), 'scope_not_honored')
            self.assertEqual(apply_ops.check_key(key, 'user'), 'bool')
            self.assertEqual(apply_ops.check_key(key, None), 'bool')  # remove skips the scope check

    def test_tables_are_disjoint_dated_and_sandbox_only(self):
        self.assertEqual(apply_ops.DOCS_FETCHED, '2026-09-29')
        self.assertFalse(set(apply_ops.SANDBOX_KEYS) & set(apply_ops.EXCLUDED_KEYS))
        kinds = {'bool', 'str_list', 'path_list', 'port', 'str_to_str_list', 'credential_files', 'credential_env'}
        for key, (kind, scopes) in apply_ops.SANDBOX_KEYS.items():
            self.assertTrue(key.startswith('sandbox.'), key)
            self.assertIn(kind, kinds)
            self.assertTrue(scopes <= apply_ops.ANY and scopes)
        self.assertEqual(len(apply_ops.SANDBOX_KEYS), 25)
        self.assertEqual(len(apply_ops.EXCLUDED_KEYS), 9)


class OpsFile(unittest.TestCase):
    def good(self):
        return {'version': 1, 'targets': [{'file': '/x/.claude/settings.json', 'ops': [op('sandbox.enabled', True)]}]}

    def load(self, doc):
        return reason(apply_ops.load_ops, json.dumps(doc).encode())

    def test_valid_file_loads(self):
        targets = apply_ops.load_ops(json.dumps(self.good()).encode())
        self.assertEqual(targets[0]['ops'][0]['path'], 'sandbox.enabled')
        doc = self.good()
        doc['targets'][0]['expect_file'] = 'absent'
        self.assertIsNone(self.load(doc))
        doc['targets'][0]['expect_file'] = 'sha256:' + 'a' * 64
        self.assertIsNone(self.load(doc))

    def test_structural_errors_refuse_the_whole_file(self):
        def mutate(fn):
            doc = self.good()
            fn(doc)
            return doc
        t = lambda d: d['targets'][0]  # noqa: E731
        o = lambda d: d['targets'][0]['ops'][0]  # noqa: E731
        cases = [
            mutate(lambda d: d.update(version=2)),
            mutate(lambda d: d.update(extra=1)),
            mutate(lambda d: t(d).update(extra=1)),
            mutate(lambda d: o(d).pop('expect')),
            mutate(lambda d: o(d).pop('value')),
            mutate(lambda d: o(d).update(op='append')),
            mutate(lambda d: o(d).update(op='remove')),                                   # remove with value
            mutate(lambda d: (o(d).update(op='remove'), o(d).pop('value'))),             # remove + absent
            mutate(lambda d: o(d).update(expect={'absent': True, 'value': 1})),
            mutate(lambda d: o(d).update(expect={'sha256': 'XYZ'})),
            mutate(lambda d: o(d).update(expect={'absent': False})),
            mutate(lambda d: t(d).update(expect_file='md5:abc')),
            mutate(lambda d: o(d).update(path='sandbox..enabled')),
            mutate(lambda d: o(d).update(path=['sandbox', 'enabled'])),
            mutate(lambda d: t(d).update(ops=[])),
            mutate(lambda d: t(d).update(ops=[op('sandbox.enabled', True)] * 51)),
            mutate(lambda d: d.update(targets=[])),
            mutate(lambda d: t(d).update(file=7)),
        ]
        for doc in cases:
            self.assertEqual(self.load(doc), 'invalid_ops_file', doc)
        for raw in (None, b'\xff\xfe', b'{"version": 1, "version": 1, "targets": []}', b'[1]',
                    b' ' * (1024 * 1024 + 1),
                    b'{"version": 1, "targets": [], "x": ' + b'9' * 5000 + b'}'):
            self.assertEqual(reason(apply_ops.load_ops, raw), 'invalid_ops_file', raw[:40] if raw else raw)

    def test_duplicate_path_and_target(self):
        doc = self.good()
        doc['targets'][0]['ops'].append(op('sandbox.enabled', False, {'value': True}))
        self.assertEqual(self.load(doc), 'duplicate_path')
        doc = self.good()
        doc['targets'].append(self.good()['targets'][0])
        self.assertEqual(self.load(doc), 'duplicate_target')


class Targets(FakeHome):
    def test_classification(self):
        self.assertEqual(apply_ops.resolve_target(os.path.join(self.claude, 'settings.json'))[1], 'user')
        self.assertEqual(apply_ops.resolve_target('~/.claude/settings.json'),
                         (os.path.join(self.claude, 'settings.json'), 'user'))
        self.assertEqual(apply_ops.resolve_target('~/.claude/settings.local.json')[1], 'local')
        self.assertEqual(apply_ops.resolve_target('~/p/.claude/settings.json')[1], 'project')
        self.assertEqual(apply_ops.resolve_target('~/p/.claude/settings.local.json')[1], 'local')

    def test_refusals_happen_before_reading(self):
        cases = {'p/.claude/settings.json': 'relative_path',
                 '/etc/claude-code/managed-settings.json': 'managed_refused',
                 os.path.join(self.home, 'p/.claude/managed-settings.json'): 'managed_refused',
                 os.path.join(self.home, 'p/managed-settings.d/10.json'): 'managed_refused',
                 os.path.join(self.home, 'p/settings.json'): 'target_not_settings',
                 '~/p/.claude/hooks.json': 'target_not_settings',
                 '~/p/claude/settings.json': 'target_not_settings'}
        with mock.patch.object(apply_ops.safe_write, 'open_no_symlink') as opened:
            for file, why in cases.items():
                self.assertEqual(apply_ops.plan_target({'file': file, 'ops': [op('sandbox.enabled', True)]})['reason'],
                                 why, file)
        opened.assert_not_called()

    def test_symlinked_claude_dir_is_refused(self):
        real = os.path.join(self.home, 'real')
        os.makedirs(real)
        os.makedirs(os.path.join(self.home, 'p'))
        os.symlink(real, os.path.join(self.home, 'p', '.claude'))
        self.assertEqual(reason(apply_ops.resolve_target, '~/p/.claude/settings.local.json'), 'symlink')


class Planning(FakeHome):
    FILE = '~/p/.claude/settings.local.json'

    def settings(self, content, rel='p/.claude/settings.local.json'):
        return self.write(rel, content if isinstance(content, str) else apply_ops.dump(content))

    def plan(self, *ops, file=None):
        return apply_ops.plan_target({'file': file or self.FILE, 'ops': list(ops)})

    def test_set_keeps_key_order_and_appends_new_keys(self):
        self.settings({'model': 'x', 'sandbox': {'enabled': False}, 'z': 1})
        p = self.plan(op('sandbox.enabled', True, {'value': False}),
                      op('sandbox.network.allowedDomains', ['github.com']))
        self.assertEqual((p['status'], p['kind'], p['exists']), ('planned', 'local', True))
        self.assertEqual(list(p['_new']), ['model', 'sandbox', 'z'])
        self.assertEqual(list(p['_new']['sandbox']), ['enabled', 'network'])
        row = p['ops'][0]
        self.assertEqual((row['status'], row['before'], row['after'], row['before_sha256']),
                         ('planned', False, True, ledger.fingerprint(False)))
        self.assertEqual(p['file_sha256'],
                         sha(os.path.join(self.home, 'p/.claude/settings.local.json')))

    def test_unchanged_when_value_already_set(self):
        self.settings({'sandbox': {'enabled': True}})
        p = self.plan(op('sandbox.enabled', True, {'value': True}))
        self.assertEqual((p['status'], p['ops'][0]['status']), ('unchanged', 'unchanged'))

    def test_precondition_by_sha256(self):
        self.settings({'sandbox': {'excludedCommands': ['docker *']}})
        p = self.plan(op('sandbox.excludedCommands', None, {'sha256': ledger.fingerprint(['docker *'])}, kind='remove'))
        self.assertEqual(p['status'], 'planned')
        self.assertEqual(p['_new'], {})

    def test_precondition_mismatch_reports_current_hash(self):
        self.settings({'sandbox': {'enabled': False}})
        p = self.plan(op('sandbox.enabled', False, {'value': True}))
        row = p['ops'][0]
        self.assertEqual((row['status'], row['reason'], row['current_sha256']),
                         ('rejected', 'precondition_mismatch', ledger.fingerprint(False)))
        self.assertEqual((p['status'], p['reason']), ('rejected', 'op_rejected'))

    def test_remove_prunes_emptied_ancestors_and_round_trips(self):
        original = {'a': 1, 'sandbox': {'enabled': True}}
        self.settings(original)
        p = self.plan(op('sandbox.network.allowedDomains', ['github.com']))
        self.settings(p['_new'])
        back = self.plan(op('sandbox.network.allowedDomains', None, {'value': ['github.com']}, kind='remove'))
        self.assertEqual(back['_new'], original)
        self.assertEqual(list(back['_new']), ['a', 'sandbox'])

    def test_remove_of_absent_key_is_rejected(self):
        self.settings({'sandbox': {}})
        p = self.plan(op('sandbox.enabled', None, {'value': True}, kind='remove'))
        self.assertEqual(p['ops'][0]['reason'], 'absent')

    def test_type_conflict(self):
        self.settings({'sandbox': True})
        self.assertEqual(self.plan(op('sandbox.enabled', True))['ops'][0]['reason'], 'type_conflict')

    def test_non_allowlisted_and_invalid_values_reject_the_target(self):
        self.settings({})
        for o, why in ((op('permissions.defaultMode', 'plan'), 'not_allowlisted'),
                       (op('sandbox.enabled', 'yes'), 'invalid_value'),
                       (op('sandbox.network.strictAllowlist', True), 'scope_not_honored')):
            p = self.plan(o)
            self.assertEqual((p['status'], p['ops'][0]['reason']), ('rejected', why))

    def test_symlinked_target_is_refused_and_untouched(self):
        other = self.write('elsewhere.json', '{"sandbox": {}}')
        os.makedirs(os.path.join(self.home, 'p', '.claude'))
        os.symlink(other, os.path.join(self.home, 'p', '.claude', 'settings.local.json'))
        p = self.plan(op('sandbox.enabled', True))
        self.assertEqual((p['status'], p['reason']), ('rejected', 'symlink'))
        self.assertEqual(Path(other).read_text(), '{"sandbox": {}}')

    def test_invalid_json_duplicate_keys_and_non_objects(self):
        for text in ('{', '{"sandbox": {}, "sandbox": {}}', '[]', '{"a": NaN}'):
            self.settings(text)
            self.assertEqual(self.plan(op('sandbox.enabled', True))['reason'], 'invalid_json', text)

    def test_too_large(self):
        self.settings('{"a": "' + 'x' * apply_ops.MAX_TARGET_BYTES + '"}')
        self.assertEqual(self.plan(op('sandbox.enabled', True))['reason'], 'too_large')

    def test_missing_file_is_planned_only_for_absent_sets(self):
        os.makedirs(os.path.join(self.home, 'p', '.claude'))
        p = self.plan(op('sandbox.enabled', True))
        self.assertEqual((p['status'], p['exists'], p['file_sha256'], p['_identity']), ('planned', False, 'absent', None))
        self.assertEqual(self.plan(op('sandbox.enabled', None, {'value': True}, kind='remove'))['ops'][0]['reason'], 'absent')
        self.assertEqual(self.plan(op('sandbox.enabled', True, {'value': False}))['ops'][0]['reason'], 'precondition_mismatch')
        self.assertEqual(self.plan(op('sandbox.enabled', True), file='~/q/.claude/settings.json')['reason'],
                         'no_parent_directory')

    def test_reformat_flag(self):
        self.settings(json.dumps({'sandbox': {}}, indent=4) + '\n')
        self.assertTrue(self.plan(op('sandbox.enabled', True))['reformat'])
        self.settings({'sandbox': {}})
        self.assertFalse(self.plan(op('sandbox.enabled', True))['reformat'])

    def test_project_file_warns_shared_and_wildcards_are_reported(self):
        self.settings({}, rel='p/.claude/settings.json')
        p = self.plan(op('sandbox.filesystem.allowWrite', ['~/c*']), file='~/p/.claude/settings.json')
        self.assertIn({'path': None, 'warning': 'shared_project_file'}, p['warnings'])
        self.assertIn({'path': 'sandbox.filesystem.allowWrite', 'warning': 'wildcard_ignored_on_linux'}, p['warnings'])

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'needs mkfifo')
    def test_fifo_target_is_refused_without_blocking(self):
        os.makedirs(os.path.join(self.home, 'p', '.claude'))
        os.mkfifo(os.path.join(self.home, 'p', '.claude', 'settings.local.json'))
        p = self.plan(op('sandbox.enabled', True))
        self.assertEqual((p['status'], p['reason']), ('rejected', 'unreadable'))

    def test_dry_run_planning_writes_nothing(self):
        path = self.settings({'sandbox': {'enabled': False}})
        before = (sorted(os.listdir(os.path.dirname(path))), Path(path).read_bytes(), os.stat(path).st_mtime_ns)
        self.plan(op('sandbox.enabled', True, {'value': False}))
        self.assertEqual(before, (sorted(os.listdir(os.path.dirname(path))), Path(path).read_bytes(),
                                  os.stat(path).st_mtime_ns))
