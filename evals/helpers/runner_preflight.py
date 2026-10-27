#!/usr/bin/env python3
"""Credential-free OS probes; never invokes Claude or certifies an eval runner."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'
MARKER = 'preflight-command-ran'


def probe(name, argv, root, expected_stdout=MARKER):
    # Do not inherit credentials, shell startup hooks, proxies or loader settings.
    env = {'PATH': SYSTEM_PATH, 'HOME': str(root), 'TMPDIR': str(root), 'LC_ALL': 'C'}
    result = {'name': name, 'command': argv}
    try:
        run = subprocess.run(argv, cwd=root, env=env, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=10, check=False)
        result.update(returncode=run.returncode, stdout=run.stdout[:2048],
                      stderr=run.stderr[:2048],
                      passed=run.returncode == 0 and run.stdout.strip() == expected_stdout)
    except subprocess.TimeoutExpired:
        result.update(passed=False, error='timeout')
    except OSError as exc:
        result.update(passed=False, error=type(exc).__name__)
    return result


def linux_probes(root):
    unshare = shutil.which('unshare', path=SYSTEM_PATH)
    if not unshare:
        return [{'name': 'unshare_available', 'passed': False, 'error': 'missing'}]
    return [
        probe('setgroups_before_mapping', [unshare, '-U', '/bin/sh', '-c',
              f'printf deny > /proc/self/setgroups && printf {MARKER}'], root),
        probe('mapped_user_namespace_control', [unshare, '-Ur', '/bin/sh', '-c',
              f'printf {MARKER}'], root),
    ]


def macos_probes(root):
    # This small test policy is NOT the CLI's generated eval policy.
    allowed = root / 'allowed'
    allowed.mkdir()
    target = allowed / 'marker'
    denied = root / 'denied-marker'
    profile = ('(version 1)(deny default)(allow process*)(allow file-read*)'
               '(allow sysctl-read)(allow file-write* (subpath '
               + json.dumps(str(allowed)) + '))')
    prefix = ['/usr/bin/sandbox-exec', '-p', profile, '/bin/sh', '-c']
    positive = probe('seatbelt_allowed_write', prefix + [
        f'printf {MARKER} > "$1" && printf {MARKER}', 'preflight', str(target)], root)
    positive['artifact_verified'] = target.is_file() and target.read_text() == MARKER
    positive['passed'] = positive['passed'] and positive['artifact_verified']
    negative = probe('seatbelt_denied_write', prefix + [
        f'printf {MARKER}; if (printf blocked > "$1"); then exit 1; else exit 0; fi',
        'preflight', str(denied)], root)
    negative['artifact_absent'] = not denied.exists()
    negative['passed'] = negative['passed'] and negative['artifact_absent']
    return [positive, negative]


def collect(execution_context):
    system = platform.system()
    with tempfile.TemporaryDirectory(prefix='runner-preflight-') as temp:
        root = Path(temp).resolve()
        if system == 'Linux':
            probes = linux_probes(root)
        elif system == 'Darwin':
            probes = macos_probes(root)
        else:
            probes = []
    return {
        'schema_version': 1,
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'execution_context': execution_context,
        'system': system, 'release': platform.release(), 'machine': platform.machine(),
        'effective_uid': os.geteuid() if hasattr(os, 'geteuid') else None,
        'probes': probes,
        'prerequisite_checks_passed': bool(probes) and all(p['passed'] for p in probes),
        'eval_runner_verified': False,
        'coverage': 'partial OS prerequisites only; no CLI, model, proxy or eval policy execution',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execution-context', required=True,
                        help='Operator label, e.g. codex-sandbox, host-shell, github-hosted')
    args = parser.parse_args()
    result = collect(args.execution_context)
    print(json.dumps(result, indent=2))
    return 0 if result['prerequisite_checks_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
