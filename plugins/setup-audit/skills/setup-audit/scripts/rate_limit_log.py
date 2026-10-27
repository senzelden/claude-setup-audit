#!/usr/bin/env python3
"""Opt-in status-line logger for subscription rate limits. Stdlib only.

Reads the status-line JSON from stdin, appends the rate-limit windows to a guarded JSON Lines file
when they changed or the last entry is over 30 minutes old, and prints one short line (or the output of a wrapped command). The log holds
numbers and timestamps only. It never breaks the status line: any problem is swallowed, exit 0.
"""
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

import drift_log

VERSION = 1
WINDOWS = ('five_hour', 'seven_day', 'spend_limit')
PERIODS = ('daily', 'weekly', 'monthly')
ROTATE_BYTES = 2_000_000
STDIN_LIMIT = 1_000_000
TAIL_BYTES = 4096
COMMAND_TIMEOUT = 3
HEARTBEAT_SECONDS = 1800  # re-log unchanged values so a light-usage window's last value stays fresh


def _number(v):
    return type(v) in (int, float) and math.isfinite(v)


def extract(status):
    """Valid rate-limit windows only: finite used_percentage and resets_at; period for spend_limit."""
    limits = status.get('rate_limits') if isinstance(status, dict) else None
    if not isinstance(limits, dict):
        return {}
    windows = {}
    for kind in WINDOWS:
        w = limits.get(kind)
        if not isinstance(w, dict) or not _number(w.get('used_percentage')) or not _number(w.get('resets_at')):
            continue
        entry = {'used_percentage': w['used_percentage'], 'resets_at': w['resets_at']}
        if kind == 'spend_limit' and w.get('period') in PERIODS:
            entry['period'] = w['period']
        windows[kind] = entry
    return windows


def changed(last, windows):
    old = last.get('windows') if isinstance(last, dict) else None
    if not isinstance(old, dict):
        return bool(windows)
    if set(old) != set(windows):
        return True
    for kind, w in windows.items():
        o = old[kind]
        if not isinstance(o, dict) or not _number(o.get('used_percentage')) or o.get('resets_at') != w['resets_at']:
            return True
        if math.floor(o['used_percentage']) != math.floor(w['used_percentage']):
            return True
    return False


def heartbeat_due(last, now):
    """True when the last logged entry is older than HEARTBEAT_SECONDS (or its time is unreadable)."""
    try:
        at = datetime.strptime(last['at'], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (KeyError, TypeError, ValueError):
        return True
    return now - at > HEARTBEAT_SECONDS


def last_entry(path):
    """Last complete, valid line from the final 4 KB of the log, or None."""
    try:
        with open(path, 'rb') as f:
            size = f.seek(0, os.SEEK_END)
            f.seek(max(0, size - TAIL_BYTES))
            tail = f.read()
    except OSError:
        return None
    for raw in reversed(tail.split(b'\n')[:-1]):
        try:
            obj = json.loads(raw)
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get('version') == VERSION and isinstance(obj.get('windows'), dict):
            return obj
    return None


def render(windows, now):
    parts = []
    for kind, label in (('five_hour', '5h'), ('seven_day', '7d'), ('spend_limit', 'spend')):
        if kind in windows:
            parts.append('%s %d%%' % (label, math.floor(windows[kind]['used_percentage'])))
    if not parts:
        return ''
    line = ' · '.join(parts)
    if 'seven_day' in windows:
        try:
            line += ' (resets %s)' % time.strftime('%a %H:%M', time.localtime(windows['seven_day']['resets_at']))
        except (OverflowError, OSError, ValueError):
            pass
    return line


def _config_dir():
    return os.path.expanduser(os.environ.get('CLAUDE_CONFIG_DIR') or '~/.claude')


def _allowed_dirs(audits):
    dirs = {os.path.realpath(tempfile.gettempdir()), os.path.realpath(audits)}
    if os.environ.get('TMPDIR'):
        dirs.add(os.path.realpath(os.environ['TMPDIR']))
    return dirs


def _log(path, windows, now, audits):
    allowed = _allowed_dirs(audits)
    path = drift_log.check_path(path, allowed)
    if not windows:
        return  # absent until the first API response in every session: never log an empty entry
    last = last_entry(path)
    if not changed(last, windows) and not heartbeat_due(last, now):
        return
    try:
        if os.path.getsize(path) >= ROTATE_BYTES:
            os.replace(path, path + '.1')
    except OSError:
        pass
    at = datetime.fromtimestamp(now, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    drift_log.append(path, {'version': VERSION, 'at': at, 'windows': windows}, allowed, audits)


def _read_stdin(stdin):
    if stdin is None:
        stdin = sys.stdin
    if isinstance(stdin, (bytes, bytearray)):
        return bytes(stdin)[:STDIN_LIMIT]
    stream = getattr(stdin, 'buffer', stdin)
    data = stream.read(STDIN_LIMIT)
    return data.encode() if isinstance(data, str) else data


def _parse_args(argv):
    """(log or None, command list); None when the arguments are invalid."""
    command = []
    if '--' in argv:
        i = argv.index('--')
        argv, command = argv[:i], argv[i + 1:]
    log = None
    if argv[:1] == ['--log'] and len(argv) == 2:
        log = argv[1]
    elif argv:
        return None
    return log, command


def main(argv=None, stdin=None, now=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parsed = _parse_args(argv)
    if parsed is None:
        print('usage: rate_limit_log.py [--log PATH] [-- COMMAND ...]', file=sys.stderr)
        return 2
    log, command = parsed
    raw, windows, valid = b'', {}, False
    try:
        raw = _read_stdin(stdin)
        status = json.loads(raw)
        valid = isinstance(status, dict)
        windows = extract(status)
    except Exception:
        windows, valid = {}, False
    now = time.time() if now is None else now
    try:
        audits = os.path.join(_config_dir(), 'audits')
        if valid:
            _log(log or os.path.join(audits, 'rate-limits.jsonl'), windows, now, audits)
    except Exception:
        pass
    try:
        if command:
            try:
                done = subprocess.run(command, input=raw, capture_output=True, timeout=COMMAND_TIMEOUT)
                if done.returncode == 0:
                    # Pass the command's bytes through unchanged (ANSI colours, any encoding).
                    out = getattr(sys.stdout, 'buffer', None)
                    if out is None:
                        sys.stdout.write(done.stdout.decode(errors='replace'))
                    else:
                        sys.stdout.flush()
                        out.write(done.stdout)
                        out.flush()
                    return 0
            except Exception:
                pass
        line = render(windows, now)
        if line:
            print(line)
    except Exception:
        pass
    return 0


if __name__ == '__main__':
    sys.exit(main())
