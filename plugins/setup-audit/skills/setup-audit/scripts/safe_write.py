#!/usr/bin/env python3
"""Symlink-refusing reads, identity checks, atomic writes and private backups (stdlib only).

Shared by prune_permissions.py and ledger.py; behaviour moved unchanged from prune_permissions.py.
"""
import errno
import os
import shutil
import tempfile
import time


class SymlinkRefused(Exception):
    """The settings path is (or became) a symlink and --allow-symlinks wasn't given."""


class ChangedSincePlan(Exception):
    """The file's identity at apply time doesn't match what was read during planning."""


def open_no_symlink(path, allow_symlinks=False):
    """Open path for reading; raises SymlinkRefused if it is a symlink and that's not allowed."""
    flags = os.O_RDONLY
    if not allow_symlinks and hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as e:
        if getattr(e, "errno", None) == errno.ELOOP:
            raise SymlinkRefused(path) from e
        raise
    try:
        return fd, os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise


def identity_of(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def atomic_write(target, text, prefix=".prune_permissions."):
    """Write text to path without ever leaving it truncated or partially written.

    The caller supplies the target used for identity verification. Never resolve a symlink here:
    resolving the original settings path again could select a different, unverified target.
    """
    dirpath = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=dirpath)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(tmp, os.stat(target).st_mode)
        except OSError:
            pass
        os.replace(tmp, target)
    except BaseException:
        # tmp is only still at its own path if we didn't reach os.replace above.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    # Persist the directory entry too, so a crash right after replace can't leave it unrecorded.
    # tmp is gone (renamed onto target) by this point, so a failure here doesn't touch the cleanup
    # above. Best-effort: not every filesystem supports fsync on a directory fd, and the write
    # already succeeded, so a failure here must not be mistaken for the write itself failing.
    try:
        dir_fd = os.open(dirpath, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except OSError:
        pass



def backup_from_fd(fd, path, backup_dir, home):
    """Copy the open file into backup_dir under an exclusive, private (0600), unique name.

    mkstemp uses exclusive creation and mode 0600: repeated backups cannot overwrite recovery
    data or follow a pre-existing backup symlink, even in the same second. A partial backup is
    removed and the error re-raised, so a failed backup always blocks the edit.
    """
    os.makedirs(backup_dir, exist_ok=True)
    prefix = path.replace(home, "").strip(os.sep).replace(os.sep, "__")
    backup_fd, backup = tempfile.mkstemp(prefix=prefix + f".{int(time.time())}.",
                                         suffix=".bak", dir=backup_dir)
    try:
        with os.fdopen(backup_fd, "wb") as dst, os.fdopen(fd, "rb", closefd=False) as src:
            shutil.copyfileobj(src, dst)
            dst.flush()
            os.fsync(dst.fileno())
    except BaseException:
        try:
            os.unlink(backup)
        except OSError:
            pass
        raise
    return backup
