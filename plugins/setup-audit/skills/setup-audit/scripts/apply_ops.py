#!/usr/bin/env python3
"""Plan (default) or apply structured settings operations at allowlisted sandbox keys.

Dry run by default: validates the ops file, reads each target without following symlinks, checks
each op's precondition and prints a JSON plan including each target's file_sha256. With --apply
--backup-dir DIR it re-plans, requires every target's expect_file to equal that hash, backs the
file up through the planned descriptor, writes atomically and verifies by re-reading. Only keys
in SANDBOX_KEYS are accepted. Format, allowlist and reasons: references/apply-ops.md.

Usage:
  apply_ops.py --ops ops.json                                                  # plan
  apply_ops.py --ops ops.json --apply --backup-dir ~/.claude/backups/setup-audit-<ts>
"""
import argparse
import copy
import hashlib
import json
import os
import re
import stat
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect  # noqa: E402  (HOME, CLAUDE, managed_directory, sanitize)
import ledger  # noqa: E402  (fingerprint: one canonical-JSON hash across helpers)
import report_state  # noqa: E402  (load_json: rejects duplicate keys and non-finite numbers)
import safe_write  # noqa: E402

# Keys, types and scopes from the raw settings reference, fetched 2026-09-29.
DOCS_FETCHED = '2026-09-29'
DOCS_SOURCES = ('https://code.claude.com/docs/en/settings-reference.md',
                'https://code.claude.com/docs/en/sandboxing.md',
                'https://code.claude.com/docs/en/settings.md')
ANY = frozenset({'user', 'project', 'local'})
USER = frozenset({'user'})  # the docs' "User or managed"; managed files are never targets
SANDBOX_KEYS = {
    'sandbox.enabled': ('bool', ANY),
    'sandbox.failIfUnavailable': ('bool', ANY),
    'sandbox.autoAllowBashIfSandboxed': ('bool', ANY),
    'sandbox.allowUnsandboxedCommands': ('bool', ANY),
    'sandbox.excludedCommands': ('str_list', ANY),
    'sandbox.enableWeakerNestedSandbox': ('bool', ANY),
    'sandbox.enableWeakerNetworkIsolation': ('bool', ANY),
    'sandbox.allowAppleEvents': ('bool', USER),
    'sandbox.ignoreViolations': ('str_to_str_list', ANY),
    'sandbox.filesystem.allowWrite': ('path_list', ANY),
    'sandbox.filesystem.denyWrite': ('path_list', ANY),
    'sandbox.filesystem.denyRead': ('str_list', ANY),
    'sandbox.filesystem.allowRead': ('str_list', ANY),
    'sandbox.filesystem.disabled': ('bool', USER),
    'sandbox.network.allowUnixSockets': ('str_list', ANY),
    'sandbox.network.allowAllUnixSockets': ('bool', ANY),
    'sandbox.network.allowLocalBinding': ('bool', ANY),
    'sandbox.network.allowMachLookup': ('str_list', ANY),
    'sandbox.network.allowedDomains': ('str_list', ANY),
    'sandbox.network.deniedDomains': ('str_list', ANY),
    'sandbox.network.strictAllowlist': ('bool', USER),
    'sandbox.network.httpProxyPort': ('port', ANY),
    'sandbox.network.socksProxyPort': ('port', ANY),
    'sandbox.credentials.files': ('credential_files', ANY),   # mask entries: user only
    'sandbox.credentials.envVars': ('credential_env', ANY),   # mask entries: user only
}
EXCLUDED_KEYS = {
    'sandbox.bwrapPath': 'managed settings only',
    'sandbox.socatPath': 'managed settings only',
    'sandbox.filesystem.allowManagedReadPathsOnly': 'managed settings only',
    'sandbox.network.allowManagedDomainsOnly': 'managed settings only',
    'sandbox.ripgrep': 'points the sandbox at an executable',
    'sandbox.network.tlsTerminate': 'names CA certificate and key files',
    'sandbox.credentials.allowPlaintextInject': 'credential proxy tuning, not in this version',
    'sandbox.credentials.awsPairs': 'credential proxy tuning, not in this version',
    'sandbox.credentials.sigv4': 'credential proxy tuning, not in this version',
}
PARENTS = frozenset({'sandbox', 'sandbox.filesystem', 'sandbox.network', 'sandbox.credentials'})
REASONS = (
    'invalid_ops_file', 'duplicate_path', 'duplicate_target',
    'relative_path', 'managed_refused', 'target_not_settings', 'symlink', 'unreadable', 'too_large',
    'invalid_json', 'no_parent_directory',
    'not_allowlisted', 'unknown_key', 'excluded_key', 'not_a_leaf', 'scope_not_honored', 'invalid_value',
    'precondition_mismatch', 'absent', 'type_conflict', 'op_rejected',
    'expect_file_missing', 'not_applied_other_target_failed', 'changed_since_plan', 'backup_failed',
    'write_failed', 'verify_failed', 'backup_dir_symlink', 'backup_dir_unusable',
)
MAX_OPS_BYTES = 1024 * 1024
MAX_TARGET_BYTES = 8 * 1024 * 1024
MAX_TARGETS, MAX_OPS = 20, 50
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
FILE_SHA_RE = re.compile(r'sha256:[0-9a-f]{64}\Z')
PATH_RE = re.compile(r'[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)*\Z')
FILE_MASK_FIELDS = frozenset({'extract', 'onExtractNoMatch', 'decode', 'maskClaims', 'maskDuplicates',
                              'injectHosts'})
ENV_MASK_FIELDS = FILE_MASK_FIELDS - {'maskDuplicates'}


class OpsError(ValueError):
    """A refusal with a constant reason from REASONS; never carries file or value content."""

    def __init__(self, reason):
        assert reason in REASONS, reason
        super().__init__(reason)
        self.reason = reason


def _str_list(v):
    return isinstance(v, list) and all(isinstance(x, str) and x for x in v)


def check_key(path, scope):
    if path in SANDBOX_KEYS:
        kind, scopes = SANDBOX_KEYS[path]
        if scope is not None and scope not in scopes:
            raise OpsError('scope_not_honored')
        return kind
    if path in EXCLUDED_KEYS:
        raise OpsError('excluded_key')
    if path in PARENTS:
        raise OpsError('not_a_leaf')
    if path.startswith('sandbox.'):
        raise OpsError('unknown_key')
    raise OpsError('not_allowlisted')


def _mask_field_ok(name, v):
    if name == 'extract':
        return isinstance(v, str) and bool(v)
    if name == 'onExtractNoMatch':
        return v in ('warn', 'deny', 'error')
    if name == 'decode':
        return v == 'jwt'
    if name == 'maskClaims':
        return _str_list(v) and bool(v)
    if name == 'maskDuplicates':
        return isinstance(v, bool)
    return _str_list(v)  # injectHosts


def _credential_entries(value, ident, mask_fields, scope):
    if not isinstance(value, list):
        raise OpsError('invalid_value')
    for e in value:
        if not (isinstance(e, dict) and isinstance(e.get(ident), str) and e[ident]
                and e.get('mode') in ('deny', 'mask')):
            raise OpsError('invalid_value')
        extra = set(e) - {ident, 'mode'}
        if (e['mode'] == 'deny' and extra) or extra - mask_fields \
                or not all(_mask_field_ok(k, e[k]) for k in extra) \
                or ('maskClaims' in e and 'decode' not in e):
            raise OpsError('invalid_value')
        if ident == 'name' and 'decode' in e and ('extract' in e or e.get('onExtractNoMatch', 'warn') != 'warn'):
            raise OpsError('invalid_value')
        if e['mode'] == 'mask' and scope != 'user':
            raise OpsError('scope_not_honored')


def validate_value(path, value, scope):
    kind = check_key(path, scope)
    if kind == 'credential_files':
        _credential_entries(value, 'path', FILE_MASK_FIELDS, scope)
    elif kind == 'credential_env':
        _credential_entries(value, 'name', ENV_MASK_FIELDS, scope)
    elif kind == 'bool':
        ok = isinstance(value, bool)
    elif kind in ('str_list', 'path_list'):
        ok = _str_list(value)
    elif kind == 'port':
        ok = type(value) is int and 1 <= value <= 65535
    else:  # str_to_str_list
        ok = isinstance(value, dict) and all(k and _str_list(v) for k, v in value.items())
    if kind not in ('credential_files', 'credential_env') and not ok:
        raise OpsError('invalid_value')
    warnings = set()
    if kind == 'path_list':
        for entry in value:
            stem = entry[:-3] if entry.endswith('/**') else entry
            if any(c in stem for c in '*?['):
                warnings.add('wildcard_ignored_on_linux')
    return sorted(warnings)


def _valid_op(o):
    if not isinstance(o, dict) or o.get('op') not in ('set', 'remove'):
        return False
    fields = {'op', 'path', 'expect'} | ({'value'} if o['op'] == 'set' else set())
    if set(o) != fields or not isinstance(o['path'], str) or not PATH_RE.match(o['path']):
        return False
    e = o['expect']
    if not isinstance(e, dict) or len(e) != 1:
        return False
    (k, v), = e.items()
    if k == 'absent':
        return v is True and o['op'] == 'set'
    if k == 'sha256':
        return isinstance(v, str) and bool(SHA_RE.match(v))
    return k == 'value'


def load_ops(raw):
    """Parse and structurally validate an ops file; returns its targets."""
    if raw is None or len(raw) > MAX_OPS_BYTES:
        raise OpsError('invalid_ops_file')
    try:
        doc = report_state.load_json(raw.decode('utf-8'))
    except (report_state.ReportError, UnicodeDecodeError, RecursionError, ValueError):
        raise OpsError('invalid_ops_file') from None
    if not (isinstance(doc, dict) and set(doc) == {'version', 'targets'} and type(doc['version']) is int
            and doc['version'] == 1 and isinstance(doc['targets'], list) and 1 <= len(doc['targets']) <= MAX_TARGETS):
        raise OpsError('invalid_ops_file')
    files = set()
    for t in doc['targets']:
        if not (isinstance(t, dict) and {'file', 'ops'} <= set(t) <= {'file', 'ops', 'expect_file'}
                and isinstance(t['file'], str) and t['file'] and isinstance(t['ops'], list)
                and 1 <= len(t['ops']) <= MAX_OPS and all(_valid_op(o) for o in t['ops'])):
            raise OpsError('invalid_ops_file')
        if 'expect_file' in t and not (t['expect_file'] == 'absent' or (
                isinstance(t['expect_file'], str) and FILE_SHA_RE.match(t['expect_file']))):
            raise OpsError('invalid_ops_file')
        paths = [o['path'] for o in t['ops']]
        if len(set(paths)) != len(paths):
            raise OpsError('duplicate_path')
        if t['file'] in files:
            raise OpsError('duplicate_target')
        files.add(t['file'])
    return doc['targets']


_MISSING = object()


def dump(doc):
    return json.dumps(doc, indent=2, ensure_ascii=False) + '\n'


def tilde(path):
    return ledger.tilde(path, collect.HOME)


def expand(path):
    if path.startswith('~/'):
        return os.path.normpath(os.path.join(collect.HOME, path[2:]))
    if not os.path.isabs(path):
        raise OpsError('relative_path')
    return os.path.normpath(path)


def resolve_target(file):
    path = expand(file)
    name, parent = os.path.basename(path), os.path.dirname(path)
    managed = collect.managed_directory()
    if (managed and (path == managed or path.startswith(managed + os.sep))) \
            or name == 'managed-settings.json' or 'managed-settings.d' in path.split(os.sep):
        raise OpsError('managed_refused')
    claude = os.path.normpath(collect.CLAUDE)
    if path == os.path.join(claude, 'settings.json'):
        scope = 'user'
    elif name == 'settings.local.json' and (parent == claude or os.path.basename(parent) == '.claude'):
        scope = 'local'
    elif name == 'settings.json' and os.path.basename(parent) == '.claude':
        scope = 'project'
    else:
        raise OpsError('target_not_settings')
    if os.path.islink(parent):
        raise OpsError('symlink')
    return path, scope


def _get(doc, parts):
    node = doc
    for part in parts:
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _holds(expect, current):
    (k, v), = expect.items()
    if k == 'absent':
        return current is _MISSING
    if current is _MISSING:
        return False
    return ledger.fingerprint(current) == (v if k == 'sha256' else ledger.fingerprint(v))


def _set(doc, parts, value):
    node = doc
    for part in parts[:-1]:
        node = node.setdefault(part, {})
        if not isinstance(node, dict):
            raise OpsError('type_conflict')
    node[parts[-1]] = value


def _remove(doc, parts):
    chain = [doc]
    for part in parts[:-1]:
        chain.append(chain[-1][part])
    del chain[-1][parts[-1]]
    for depth in range(len(parts) - 1, 0, -1):  # prune ancestors this removal emptied
        if chain[depth]:
            break
        del chain[depth - 1][parts[depth - 1]]


def plan_ops(doc, ops, scope):
    new, rows, warnings = copy.deepcopy(doc), [], []
    for o in ops:
        parts = o['path'].split('.')
        row = {'op': o['op'], 'path': o['path'], 'status': 'planned', 'reason': '',
               'before': None, 'before_sha256': None, 'after': o.get('value')}
        rows.append(row)
        try:
            if o['op'] == 'set':
                warnings += [{'path': o['path'], 'warning': w} for w in validate_value(o['path'], o['value'], scope)]
            else:
                check_key(o['path'], None)
            current = _get(new, parts)
            if current is not _MISSING:
                row.update(before=current, before_sha256=ledger.fingerprint(current))
            if o['op'] == 'remove' and current is _MISSING:
                raise OpsError('absent')
            if not _holds(o['expect'], current):
                row['current_sha256'] = row['before_sha256']
                raise OpsError('precondition_mismatch')
            if o['op'] == 'set':
                if current is not _MISSING and ledger.fingerprint(current) == ledger.fingerprint(o['value']):
                    row['status'] = 'unchanged'
                    continue
                _set(new, parts, copy.deepcopy(o['value']))
            else:
                _remove(new, parts)
        except OpsError as exc:
            row.update(status='rejected', reason=exc.reason)
    return new, rows, warnings


def _parse(raw):
    try:
        doc = report_state.load_json(raw.decode('utf-8'))
    except (report_state.ReportError, UnicodeDecodeError, RecursionError, ValueError):
        raise OpsError('invalid_json') from None
    if not isinstance(doc, dict):
        raise OpsError('invalid_json')
    return doc


def _read(path):
    """(raw bytes, identity) through one no-follow descriptor; (None, None) when missing."""
    try:
        pre = os.lstat(path)  # refuse before open(): opening a FIFO would block
    except FileNotFoundError:
        return None, None
    except OSError:
        raise OpsError('unreadable') from None
    if stat.S_ISLNK(pre.st_mode):
        raise OpsError('symlink')
    if not stat.S_ISREG(pre.st_mode):
        raise OpsError('unreadable')
    try:
        fd, st = safe_write.open_no_symlink(path)
    except FileNotFoundError:
        return None, None
    except safe_write.SymlinkRefused:
        raise OpsError('symlink') from None
    except OSError:
        raise OpsError('unreadable') from None
    try:
        if not stat.S_ISREG(st.st_mode):
            raise OpsError('unreadable')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(MAX_TARGET_BYTES + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_TARGET_BYTES:
        raise OpsError('too_large')
    return raw, safe_write.identity_of(st)


def plan_target(target):
    p = {'file': target['file'], 'kind': None, 'exists': None, 'file_sha256': None, 'reformat': False,
         'status': 'rejected', 'reason': '', 'warnings': [], 'backup': None, 'created': False,
         'verified': None, 'ops': [], '_path': None, '_identity': None, '_new': None, '_text': None}
    try:
        path, scope = resolve_target(target['file'])
        p.update(file=tilde(path), kind=scope, _path=path)
        raw, identity = _read(path)
        if raw is None and not os.path.isdir(os.path.dirname(path)):
            raise OpsError('no_parent_directory')
        doc = {} if raw is None else _parse(raw)
        p.update(exists=raw is not None, _identity=identity,
                 file_sha256='absent' if raw is None else 'sha256:' + hashlib.sha256(raw).hexdigest(),
                 reformat=raw is not None and raw != dump(doc).encode('utf-8'))
        new, rows, warnings = plan_ops(doc, target['ops'], scope)
        p.update(ops=rows, warnings=([{'path': None, 'warning': 'shared_project_file'}] if scope == 'project' else [])
                 + warnings)
        if any(r['status'] == 'rejected' for r in rows):
            raise OpsError('op_rejected')
        changed = any(r['status'] == 'planned' for r in rows)
        p.update(status='planned' if changed else 'unchanged', _new=new, _text=dump(new) if changed else None)
    except OpsError as exc:
        p.update(status='rejected', reason=exc.reason)
    except RecursionError:  # loads, but too deeply nested to copy, dump or fingerprint
        p.update(status='rejected', reason='invalid_json')
    return p


def _block(p, why, status='blocked'):
    assert why in REASONS, why
    p.update(status=status, reason=why)


def _create(path, text):
    """Exclusive creation: never replaces a file that appeared after planning."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(text.encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.unlink(path)  # created exclusively above, so it is ours to remove
        except OSError:
            pass
        raise
    finally:
        os.close(fd)


def apply_target(p, expect_file, backup_dir):
    assert p['status'] == 'planned', p['status']
    path = p['_path']
    if expect_file != p['file_sha256']:
        return _block(p, 'changed_since_plan')
    if p['_identity'] is None:
        try:
            _create(path, p['_text'])
        except FileExistsError:
            return _block(p, 'changed_since_plan')
        except OSError:
            return _block(p, 'write_failed')
        p['created'] = True
    else:
        try:
            pre = os.lstat(path)  # refuse before open(): opening a FIFO would block
        except OSError:
            return _block(p, 'changed_since_plan')
        if stat.S_ISLNK(pre.st_mode):
            return _block(p, 'symlink')
        if not stat.S_ISREG(pre.st_mode):
            return _block(p, 'changed_since_plan')
        try:
            fd, st = safe_write.open_no_symlink(path)
        except safe_write.SymlinkRefused:
            return _block(p, 'symlink')
        except OSError:
            return _block(p, 'changed_since_plan')
        try:
            if safe_write.identity_of(st) != p['_identity']:
                return _block(p, 'changed_since_plan')
            try:
                backup = safe_write.backup_from_fd(fd, path, backup_dir, collect.HOME)
            except OSError:
                return _block(p, 'backup_failed')
        finally:
            os.close(fd)
        p['backup'] = tilde(backup)
        try:
            safe_write.atomic_write(path, p['_text'], prefix='.apply_ops.', encoding='utf-8')
        except OSError:
            return _block(p, 'write_failed')
    try:
        raw, _ = _read(path)
        ok = raw is not None and ledger.fingerprint(_parse(raw)) == ledger.fingerprint(p['_new'])
    except (OpsError, OSError):
        ok = False
    p['verified'] = ok
    if ok:
        p.update(status='applied', reason='')
    else:
        _block(p, 'verify_failed', status='verify_failed')


OK_STATUSES = ('planned', 'unchanged', 'applied')


def _public(p):
    row = {k: v for k, v in p.items() if not k.startswith('_')}
    row['ops'] = [dict(r, before=collect.sanitize(r['before']), after=collect.sanitize(r['after']))
                  for r in p['ops']]
    return row


def _prepare_backup_dir(backup_dir):
    path = os.path.abspath(expand(backup_dir) if backup_dir.startswith('~/') else backup_dir)
    if os.path.islink(path):
        raise OpsError('backup_dir_symlink')
    try:
        if not os.path.isdir(path):
            os.makedirs(path, mode=0o700)
            os.chmod(path, 0o700)  # makedirs mode is subject to umask
    except OSError:
        raise OpsError('backup_dir_unusable') from None
    return path


def run(raw, apply=False, backup_dir=None):
    result = {'applied': apply, 'ok': False, 'docs_fetched': DOCS_FETCHED, 'targets': [], 'error': None}
    try:
        targets = load_ops(raw)
    except OpsError as exc:
        result['error'] = exc.reason
        return result
    plans = [plan_target(t) for t in targets]
    resolved = [p['_path'] for p in plans if p['_path']]
    if len(set(resolved)) != len(resolved):
        result['error'] = 'duplicate_target'
        return result
    if apply:
        failed = any(p['status'] not in ('planned', 'unchanged') for p in plans)
        missing = any('expect_file' not in t for t in targets)
        if failed or missing:
            for p, t in zip(plans, targets):
                if p['status'] in ('planned', 'unchanged'):
                    _block(p, 'expect_file_missing' if 'expect_file' not in t else 'not_applied_other_target_failed')
        elif any(p['status'] == 'planned' and t['expect_file'] != p['file_sha256'] for p, t in zip(plans, targets)):
            for p, t in zip(plans, targets):
                if p['status'] in ('planned', 'unchanged'):
                    stale = p['status'] == 'planned' and t['expect_file'] != p['file_sha256']
                    _block(p, 'changed_since_plan' if stale else 'not_applied_other_target_failed')
        else:
            try:
                directory = _prepare_backup_dir(backup_dir) if any(p['status'] == 'planned' for p in plans) else None
            except OpsError as exc:
                result['error'] = exc.reason
                for p in plans:
                    if p['status'] == 'planned':
                        _block(p, exc.reason)
            else:
                for p, t in zip(plans, targets):
                    if p['status'] == 'planned':
                        apply_target(p, t['expect_file'], directory)
    result['targets'] = [_public(p) for p in plans]
    result['ok'] = result['error'] is None and all(p['status'] in OK_STATUSES for p in plans)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--ops', required=True, help='ops file (JSON, see references/apply-ops.md)')
    ap.add_argument('--apply', action='store_true', help='write the planned changes (default: dry run)')
    ap.add_argument('--backup-dir', help='directory for private backups (required with --apply)')
    ap.add_argument('--claude-dir', help='Claude Code config directory (default: $CLAUDE_CONFIG_DIR, else ~/.claude)')
    a = ap.parse_args(argv)
    if a.apply and not a.backup_dir:
        ap.error('--apply requires --backup-dir')
    if a.claude_dir:
        collect.CLAUDE = os.path.abspath(os.path.expanduser(a.claude_dir))
    try:
        fd, _ = safe_write.open_no_symlink(a.ops)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(MAX_OPS_BYTES + 1)
    except (OSError, safe_write.SymlinkRefused):
        raw = None
    result = run(raw, a.apply, a.backup_dir)
    print(json.dumps(result, indent=1, ensure_ascii=False))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
