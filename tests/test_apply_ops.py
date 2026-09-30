"""apply_ops: allowlisted structured settings operations. Fake homes only; never the real ~/.claude."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
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

    def test_oversized_integer_literal_is_invalid_json(self):
        self.settings('{"a": ' + '9' * 5000 + '}')
        self.assertEqual(self.plan(op('sandbox.enabled', True))['reason'], 'invalid_json')

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
        box = []
        worker = threading.Thread(target=lambda: box.append(self.plan(op('sandbox.enabled', True))), daemon=True)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive(), 'planning blocked on the FIFO')
        self.assertEqual((box[0]['status'], box[0]['reason']), ('rejected', 'unreadable'))

    def test_dry_run_planning_writes_nothing(self):
        path = self.settings({'sandbox': {'enabled': False}})
        before = (sorted(os.listdir(os.path.dirname(path))), Path(path).read_bytes(), os.stat(path).st_mtime_ns)
        self.plan(op('sandbox.enabled', True, {'value': False}))
        self.assertEqual(before, (sorted(os.listdir(os.path.dirname(path))), Path(path).read_bytes(),
                                  os.stat(path).st_mtime_ns))


class Apply(FakeHome):
    FILE = '~/p/.claude/settings.local.json'

    def setUp(self):
        super().setUp()
        self.path = os.path.join(self.home, 'p', '.claude', 'settings.local.json')
        self.backups = os.path.join(self.home, 'backups')
        os.makedirs(self.backups, mode=0o700)

    def seed(self, doc=None, text=None):
        self.write('p/.claude/settings.local.json',
                   text if text is not None else apply_ops.dump(doc or {'sandbox': {'enabled': False}}))
        return Path(self.path).read_bytes()

    def plan(self, *ops, file=None):
        return apply_ops.plan_target({'file': file or self.FILE,
                                      'ops': list(ops) or [op('sandbox.enabled', True, {'value': False})]})

    def listing(self):
        return sorted(os.listdir(self.backups))

    def test_apply_backs_up_writes_and_verifies(self):
        original = self.seed({'model': 'x', 'sandbox': {'enabled': False}})
        p = self.plan()
        apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['verified'], p['created']), ('applied', True, False))
        self.assertEqual(json.loads(Path(self.path).read_text()), {'model': 'x', 'sandbox': {'enabled': True}})
        backup = os.path.join(self.backups, os.path.basename(p['backup']))
        self.assertEqual(Path(backup).read_bytes(), original)
        self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
        self.assertEqual(os.listdir(os.path.dirname(self.path)), ['settings.local.json'])  # no temp left

    def test_stale_expect_file_writes_nothing(self):
        original = self.seed()
        p = self.plan()
        apply_ops.apply_target(p, 'sha256:' + '0' * 64, self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'changed_since_plan'))
        self.assertEqual(Path(self.path).read_bytes(), original)
        self.assertEqual(self.listing(), [])

    def test_file_changed_after_plan_is_blocked(self):
        self.seed()
        p = self.plan()
        Path(self.path).write_text('{"sandbox": {"enabled": null}}\n')
        st = os.stat(self.path)
        os.utime(self.path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'changed_since_plan'))
        self.assertEqual(Path(self.path).read_text(), '{"sandbox": {"enabled": null}}\n')
        self.assertEqual(self.listing(), [])

    def test_target_swapped_for_symlink_is_blocked(self):
        self.seed()
        p = self.plan()
        sentinel = self.write('sentinel.json', '{"keep": true}')
        os.unlink(self.path)
        os.symlink(sentinel, self.path)
        apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'symlink'))
        self.assertEqual(Path(sentinel).read_text(), '{"keep": true}')
        self.assertEqual(self.listing(), [])

    def test_backup_failure_leaves_target_untouched(self):
        original = self.seed()
        p = self.plan()
        with mock.patch.object(apply_ops.safe_write, 'backup_from_fd', side_effect=OSError('disk full')):
            apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'backup_failed'))
        self.assertEqual(Path(self.path).read_bytes(), original)

    def test_write_failure_keeps_backup(self):
        original = self.seed()
        p = self.plan()
        with mock.patch.object(apply_ops.safe_write, 'atomic_write', side_effect=OSError('read-only')):
            apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'write_failed'))
        self.assertEqual(Path(self.path).read_bytes(), original)
        self.assertEqual(len(self.listing()), 1)

    def test_verify_mismatch_is_reported(self):
        original = self.seed()
        p = self.plan()

        def diverge(target, text, prefix, encoding):
            Path(target).write_text('{"sandbox": {"enabled": true}, "other": 1}\n')
        with mock.patch.object(apply_ops.safe_write, 'atomic_write', side_effect=diverge):
            apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['reason'], p['verified']), ('verify_failed', 'verify_failed', False))
        self.assertEqual(Path(self.backups, os.path.basename(p['backup'])).read_bytes(), original)

    def test_verify_reread_error_is_reported_and_keeps_backup(self):
        original = self.seed()
        p = self.plan()
        with mock.patch.object(apply_ops, '_read', side_effect=OSError('gone')):
            apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['verified']), ('verify_failed', False))
        self.assertEqual(Path(self.backups, os.path.basename(p['backup'])).read_bytes(), original)

    def test_target_deleted_after_plan_is_blocked_without_backup(self):
        self.seed()
        p = self.plan()
        os.unlink(self.path)
        apply_ops.apply_target(p, p['file_sha256'], self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'changed_since_plan'))
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.listing(), [])

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'needs mkfifo')
    def test_target_swapped_for_fifo_after_plan_does_not_hang(self):
        self.seed()
        p = self.plan()
        os.unlink(self.path)
        os.mkfifo(self.path)
        worker = threading.Thread(target=lambda: apply_ops.apply_target(p, p['file_sha256'], self.backups),
                                  daemon=True)
        worker.start()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive(), 'apply blocked on the FIFO')
        self.assertEqual((p['status'], p['reason']), ('blocked', 'changed_since_plan'))
        self.assertEqual(self.listing(), [])

    def test_failed_exclusive_create_leaves_no_file(self):
        os.makedirs(os.path.dirname(self.path))
        p = self.plan(op('sandbox.enabled', True))
        with mock.patch.object(apply_ops.os, 'fsync', side_effect=OSError('disk full')):
            apply_ops.apply_target(p, 'absent', self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'write_failed'))
        self.assertFalse(os.path.exists(self.path))

    def test_missing_file_is_created_exclusively(self):
        os.makedirs(os.path.dirname(self.path))
        p = self.plan(op('sandbox.enabled', True))
        apply_ops.apply_target(p, 'absent', self.backups)
        self.assertEqual((p['status'], p['created'], p['backup']), ('applied', True, None))
        self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o600)
        self.assertEqual(json.loads(Path(self.path).read_text()), {'sandbox': {'enabled': True}})

    def test_exclusive_creation_loses_to_a_file_created_after_planning(self):
        os.makedirs(os.path.dirname(self.path))
        p = self.plan(op('sandbox.enabled', True))
        Path(self.path).write_text('{}\n')
        apply_ops.apply_target(p, 'absent', self.backups)
        self.assertEqual((p['status'], p['reason']), ('blocked', 'changed_since_plan'))
        self.assertEqual(Path(self.path).read_text(), '{}\n')

    def test_backups_are_distinct_and_leave_existing_files_alone(self):
        outside = self.write('outside.txt', 'untouched')
        os.symlink(outside, os.path.join(self.backups, 'trap.bak'))
        Path(self.backups, 'keep.bak').write_text('old backup')
        other = self.write('q/.claude/settings.local.json', apply_ops.dump({'sandbox': {'enabled': False}}))
        self.seed()
        made = []
        for file in (self.FILE, '~/q/.claude/settings.local.json', self.FILE):
            ops = ([op('sandbox.enabled', False, {'value': True})] if len(made) == 2 else [])
            p = self.plan(*ops, file=file)
            before = Path(apply_ops.expand(file)).read_bytes()   # third pass: same target again, same second
            with mock.patch.object(apply_ops.safe_write.time, 'time', return_value=1_700_000_000):
                apply_ops.apply_target(p, p['file_sha256'], self.backups)
            self.assertEqual(p['status'], 'applied')
            backup = os.path.join(self.backups, os.path.basename(p['backup']))
            self.assertEqual(Path(backup).read_bytes(), before)
            made.append(p['backup'])
        self.assertEqual(len(set(made)), 3)
        self.assertEqual(Path(outside).read_text(), 'untouched')
        self.assertEqual(Path(self.backups, 'keep.bak').read_text(), 'old backup')
        self.assertEqual(json.loads(Path(other).read_text()), {'sandbox': {'enabled': True}})


class Run(FakeHome):
    def setUp(self):
        super().setUp()
        self.a = self.write('a/.claude/settings.local.json', apply_ops.dump({'sandbox': {'enabled': False}}))
        self.b = self.write('b/.claude/settings.local.json', apply_ops.dump({}))
        self.backups = os.path.join(self.home, 'backups')

    def ops(self, *targets):
        return json.dumps({'version': 1, 'targets': list(targets)}).encode()

    def target(self, file, *ops, expect_file=None):
        t = {'file': file, 'ops': list(ops)}
        if expect_file:
            t['expect_file'] = expect_file
        return t

    def test_one_rejected_target_blocks_all_writes(self):
        before = (Path(self.a).read_bytes(), Path(self.b).read_bytes())
        out = apply_ops.run(self.ops(
            self.target('~/a/.claude/settings.local.json', op('sandbox.enabled', True, {'value': False}), expect_file=sha(self.a)),
            self.target('~/b/.claude/settings.local.json', op('permissions.defaultMode', 'plan'), expect_file=sha(self.b))),
            apply=True, backup_dir=self.backups)
        self.assertEqual([t['status'] for t in out['targets']], ['blocked', 'rejected'])
        self.assertEqual(out['targets'][0]['reason'], 'not_applied_other_target_failed')
        self.assertFalse(out['ok'])
        self.assertEqual((Path(self.a).read_bytes(), Path(self.b).read_bytes()), before)
        self.assertFalse(os.path.exists(self.backups))

    def test_apply_requires_expect_file(self):
        before = Path(self.a).read_bytes()
        out = apply_ops.run(self.ops(self.target('~/a/.claude/settings.local.json',
                                                 op('sandbox.enabled', True, {'value': False}))),
                            apply=True, backup_dir=self.backups)
        self.assertEqual(out['targets'][0]['reason'], 'expect_file_missing')
        self.assertEqual(Path(self.a).read_bytes(), before)

    def test_same_file_spelled_twice_is_a_duplicate_target(self):
        out = apply_ops.run(self.ops(self.target('~/a/.claude/settings.local.json', op('sandbox.enabled', True, {'value': False})),
                                     self.target(self.a, op('sandbox.failIfUnavailable', True))))
        self.assertEqual((out['error'], out['ok'], out['targets']), ('duplicate_target', False, []))

    def test_symlinked_backup_dir_is_refused(self):
        real = os.path.join(self.home, 'real-backups')
        os.makedirs(real)
        os.symlink(real, self.backups)
        before = Path(self.a).read_bytes()
        out = apply_ops.run(self.ops(self.target('~/a/.claude/settings.local.json',
                                                 op('sandbox.enabled', True, {'value': False}), expect_file=sha(self.a))),
                            apply=True, backup_dir=self.backups)
        self.assertEqual((out['error'], out['targets'][0]['reason']), ('backup_dir_symlink', 'backup_dir_symlink'))
        self.assertEqual(Path(self.a).read_bytes(), before)
        self.assertEqual(os.listdir(real), [])

    def test_backup_dir_is_created_private(self):
        out = apply_ops.run(self.ops(self.target('~/a/.claude/settings.local.json',
                                                 op('sandbox.enabled', True, {'value': False}), expect_file=sha(self.a))),
                            apply=True, backup_dir=self.backups)
        self.assertTrue(out['ok'])
        self.assertEqual(stat.S_IMODE(os.stat(self.backups).st_mode), 0o700)

    def test_invalid_ops_file(self):
        self.assertEqual(apply_ops.run(b'{'), {'applied': False, 'ok': False, 'docs_fetched': '2026-09-29',
                                               'targets': [], 'error': 'invalid_ops_file'})

    def test_output_is_sanitized_and_has_no_internal_fields(self):
        canary = 'ghp_' + 'a' * 36
        out = apply_ops.run(self.ops(self.target('~/.claude/settings.json', op(
            'sandbox.credentials.envVars', [{'name': 'GH_TOKEN', 'mode': 'mask', 'extract': canary + '(x)'}]))))
        text = json.dumps(out)
        self.assertTrue(out['ok'], text)
        self.assertNotIn(canary, text)
        self.assertIn('[REDACTED]', text)
        self.assertFalse([k for t in out['targets'] for k in t if k.startswith('_')])


class Cli(FakeHome):
    SCRIPT = os.path.join(SCRIPTS, 'apply_ops.py')

    def call(self, *args):
        env = {**os.environ, 'HOME': self.home, 'CLAUDE_CONFIG_DIR': self.claude}
        r = subprocess.run([sys.executable, self.SCRIPT, *args], capture_output=True, text=True, env=env)
        return r.returncode, (json.loads(r.stdout) if r.stdout.strip() else None), r.stderr

    def ops_file(self, targets):
        return self.write('ops.json', json.dumps({'version': 1, 'targets': targets}))

    def test_dry_run_then_apply_then_stale_apply(self):
        path = self.write('.claude/settings.json', apply_ops.dump({'theme': 'dark'}))
        target = {'file': '~/.claude/settings.json', 'ops': [op('sandbox.enabled', True), op('sandbox.failIfUnavailable', True)]}
        code, out, _ = self.call('--ops', self.ops_file([target]))
        self.assertEqual((code, out['applied'], out['targets'][0]['status']), (0, False, 'planned'))
        self.assertEqual(json.loads(Path(path).read_text()), {'theme': 'dark'})   # dry run wrote nothing
        target['expect_file'] = out['targets'][0]['file_sha256']
        ops = self.ops_file([target])
        backups = os.path.join(self.home, 'b')
        code, out, _ = self.call('--ops', ops, '--apply', '--backup-dir', backups)
        self.assertEqual((code, out['targets'][0]['status'], out['targets'][0]['verified']), (0, 'applied', True))
        self.assertTrue(out['targets'][0]['backup'].startswith('~/b/'))
        code, out, _ = self.call('--ops', ops, '--apply', '--backup-dir', backups)
        self.assertEqual((code, out['targets'][0]['reason']), (1, 'op_rejected'))  # preconditions no longer hold
        same = {'file': '~/.claude/settings.json', 'ops': [op('sandbox.enabled', True, {'value': True})]}
        code, out, _ = self.call('--ops', self.ops_file([same]))
        self.assertEqual((code, out['targets'][0]['status']), (0, 'unchanged'))

    def test_file_changed_after_dry_run_is_changed_since_plan(self):
        path = self.write('.claude/settings.json', apply_ops.dump({'sandbox': {'enabled': False}}))
        target = {'file': '~/.claude/settings.json', 'ops': [op('sandbox.enabled', True, {'value': False})]}
        code, out, _ = self.call('--ops', self.ops_file([target]))
        self.assertEqual((code, out['targets'][0]['status']), (0, 'planned'))
        target['expect_file'] = out['targets'][0]['file_sha256']
        ops = self.ops_file([target])
        self.write('.claude/settings.json', apply_ops.dump({'sandbox': {'enabled': False}, 'theme': 'dark'}))
        modified = Path(path).read_bytes()
        backups = os.path.join(self.home, 'b')
        code, out, _ = self.call('--ops', ops, '--apply', '--backup-dir', backups)
        self.assertEqual((code, out['targets'][0]['status'], out['targets'][0]['reason']),
                         (1, 'blocked', 'changed_since_plan'))
        self.assertEqual(Path(path).read_bytes(), modified)
        self.assertEqual(os.listdir(backups) if os.path.isdir(backups) else [], [])

    def test_usage_errors_exit_2(self):
        ops = self.ops_file([{'file': '~/.claude/settings.json', 'ops': [op('sandbox.enabled', True)]}])
        self.assertEqual(self.call('--ops', ops, '--apply')[0], 2)
        self.assertEqual(self.call()[0], 2)

    def test_rejections_exit_1_with_json(self):
        code, out, _ = self.call('--ops', self.ops_file([{'file': '~/.claude/settings.json',
                                                          'ops': [op('sandbox.bwrapPath', '/usr/bin/bwrap')]}]))
        self.assertEqual((code, out['targets'][0]['ops'][0]['reason']), (1, 'excluded_key'))
        code, out, _ = self.call('--ops', os.path.join(self.home, 'missing.json'))
        self.assertEqual((code, out['error']), (1, 'invalid_ops_file'))


class Docs(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), '..')
    SKILL = os.path.join(ROOT, 'plugins', 'setup-audit', 'skills', 'setup-audit')

    def read(self, *parts):
        with open(os.path.join(*parts), encoding='utf-8') as f:
            return f.read()

    def test_reference_matches_constants(self):
        ref = self.read(self.SKILL, 'references', 'apply-ops.md')
        rows = {line.split('`')[1] for line in ref.splitlines() if line.startswith('| `sandbox')}
        self.assertEqual(rows, set(apply_ops.SANDBOX_KEYS) | set(apply_ops.EXCLUDED_KEYS))
        for text in (*apply_ops.REASONS, 'fetched 2026-09-29', *apply_ops.DOCS_SOURCES, 'expect_file',
                     'file_sha256', 'wildcard_ignored_on_linux', 'shared_project_file'):
            self.assertIn(text, ref)

    def test_skill_requires_the_helper_for_sandbox_changes(self):
        skill = self.read(self.SKILL, 'SKILL.md')
        item = skill.split('7. **Sandbox.**', 1)[1].split('8. **Record', 1)[0]
        for text in ('apply_ops.py --ops', '--apply --backup-dir', 'references/apply-ops.md', 'file_sha256',
                     'Never replace a refused or failed op with Write/Edit'):
            self.assertIn(text, item)
        preamble = skill.split('## Step 5', 1)[1].split('1. **Back up first**', 1)[0]
        self.assertIn('successful `apply_ops.py` dry run', preamble)
        frontmatter = skill.split('\n---', 1)[0]  # the file starts with '---'; the first '\n---' closes it
        allowed = frontmatter.split('allowed-tools:', 1)[1].split('\n', 1)[0]
        self.assertIn('collect.py', allowed)
        self.assertNotIn('apply_ops', allowed)

    def test_checklist_points_sandbox_fixes_at_the_helper(self):
        checklist = self.read(self.SKILL, 'references', 'checklist.md')
        section = checklist.split('**SEC-sandbox**', 1)[1].split('- **SEC-hooks**', 1)[0]
        self.assertIn('apply_ops.py', section)
