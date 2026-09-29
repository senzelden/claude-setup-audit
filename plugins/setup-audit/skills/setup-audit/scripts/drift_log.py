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
    if not os.path.isdir(directory):
        if os.path.abspath(directory) != os.path.abspath(audits_dir):
            raise DriftLogError('drift log directory does not exist')
        os.makedirs(directory, mode=0o700)
        os.chmod(directory, 0o700)  # makedirs mode is subject to umask
    line = json.dumps(entry, separators=(',', ':'), allow_nan=False) + '\n'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b'\n':
            line = '\n' + line  # isolate an interrupted earlier line
        os.write(fd, line.encode())
        os.fsync(fd)
    finally:
        os.close(fd)


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
        except ValueError:
            malformed += 1
            continue
        if isinstance(obj, dict) and obj.get('version') == VERSION and isinstance(obj.get('signals'), dict):
            entries.append(obj)
        else:
            malformed += 1
    return entries, malformed
