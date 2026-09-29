"""Drift log: a guarded, append-only JSON Lines file with a tolerant reader. Stdlib only.

Entries hold counts, sizes, ratios, paths, dates and fingerprints, never rule or prompt text.
"""
import json
import os

VERSION = 1
SIGNALS = ('claude_md', 'cache_hit_ratio', 'broad_permissions', 'skill_listing_chars', 'injected_tokens')


class DriftLogError(ValueError):
    pass


def check_path(path, allowed_dirs):
    """Absolute log path, or DriftLogError when it is outside allowed_dirs or a symlink."""
    path = os.path.abspath(os.path.expanduser(path))
    real_dir = os.path.realpath(os.path.dirname(path))
    if not any(real_dir == d or real_dir.startswith(d + os.sep) for d in allowed_dirs):
        raise DriftLogError('drift log must be under a system temp directory or the audits directory')
    if os.path.islink(path):
        raise DriftLogError('drift log refuses to write through a symlink')
    return path


def append(path, entry, allowed_dirs, audits_dir):
    """Append one entry as a single line; create the file 0600 (and the audits dir 0700)."""
    path = check_path(path, allowed_dirs)
    directory = os.path.dirname(path)
    line = json.dumps(entry, separators=(',', ':'), allow_nan=False) + '\n'
    try:
        if not os.path.isdir(directory):
            if os.path.abspath(directory) != os.path.abspath(audits_dir):
                raise DriftLogError('drift log directory does not exist')
            os.makedirs(directory, mode=0o700)
            os.chmod(directory, 0o700)  # makedirs mode is subject to umask
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            size = os.fstat(fd).st_size
            if size and os.pread(fd, 1, size - 1) != b'\n':
                line = '\n' + line  # isolate an interrupted earlier line
            data = line.encode()
            if os.write(fd, data) != len(data):
                raise DriftLogError('drift log cannot be written')
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        raise DriftLogError('drift log cannot be written') from None


def read(path):
    """(entries, malformed); a missing log is empty. Partial, non-object or other-version lines are malformed."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return [], 0
    except OSError:
        raise DriftLogError('drift log cannot be read') from None
    entries, malformed = [], 0
    for raw in data.splitlines(keepends=True):
        if not raw.strip():
            continue
        if not raw.endswith(b'\n'):
            malformed += 1
            continue
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError):
            malformed += 1
            continue
        if isinstance(obj, dict) and obj.get('version') == VERSION and isinstance(obj.get('signals'), dict):
            entries.append(obj)
        else:
            malformed += 1
    return entries, malformed


def _num(v):
    return v if type(v) in (int, float) else None


def _last_value(name, signal):
    """Scalar for one signal; anything not a plain number becomes None."""
    if name == 'claude_md':
        return max((v['lines'] for v in signal.values()
                    if isinstance(v, dict) and type(v.get('lines')) is int), default=None)
    if name == 'broad_permissions':
        return _num(signal.get('count'))
    return _num(signal.get('value'))


def summarize(entries, malformed, display_path):
    """Per-signal last value, crossing count and dates, for the collector's drift_signals."""
    signals = {}
    for name in SIGNALS:
        seen = [e for e in entries if isinstance(e['signals'].get(name), dict)]
        dates = [e.get('at') for e in entries for c in (e.get('crossings') if isinstance(e.get('crossings'), list) else [])
                 if isinstance(c, dict) and c.get('signal') == name]
        if not seen and not dates:
            continue
        dated = sorted(d for d in dates if isinstance(d, str))
        signals[name] = {'last_value': _last_value(name, seen[-1]['signals'][name]) if seen else None,
                         'crossings': len(dates),
                         'first_crossing_at': dated[0] if dated else None,
                         'last_crossing_at': dated[-1] if dated else None,
                         'scopes': sorted({e['scope'] for e in seen if isinstance(e.get('scope'), str)})}
    ats = sorted(e['at'] for e in entries if isinstance(e.get('at'), str))
    return {'status': 'collected', 'path': display_path, 'entries': len(entries), 'malformed': malformed,
            'first_at': ats[0] if ats else None, 'last_at': ats[-1] if ats else None, 'signals': signals}
