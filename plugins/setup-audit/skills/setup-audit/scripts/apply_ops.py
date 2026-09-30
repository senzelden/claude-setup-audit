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
