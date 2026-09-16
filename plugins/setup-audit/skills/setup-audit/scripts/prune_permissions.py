#!/usr/bin/env python3
"""Plan (default) or apply removal of permission allow rules and stale directories.

Dry-run by default: prints a JSON plan and changes nothing. With --apply, backs up every file it
touches into --backup-dir first, rewrites only the selected categories, and validates the JSON.
Backups use exclusively created unique names, are readable/writable only by their owner, and
are flushed and fsynced before settings are edited. A failed backup is removed and blocks editing;
a completed backup is retained if the subsequent settings write fails.

Writes are atomic (temp file + fsync + os.replace, so a crash or full disk mid-write can't leave
settings.json truncated) and refuse to follow a symlink by default (pass --allow-symlinks to
override; the symlink itself is preserved and its target is rewritten, not the link node). Each
file's identity (device, inode, size, mtime) is captured via the file descriptor used to plan it,
and re-checked through a freshly opened descriptor right before the backup and write; a file that
changed, or was swapped for a symlink, in between is skipped rather than overwritten. The final
rename is still by path, since POSIX rename has no fd-scoped form -- that narrow window is the one
part this can't close.

Categories (pass with --remove, comma-separated):
  risky flags from collect.py: wildcard-all, sudo, rm-recursive, network-wildcard, git-destructive,
    gh-api, interpreter-wildcard, package-install, docker, read-outside-project,
    secret-literal-in-rule, secret-via-env-file, file-append-wildcard
  one-off        exact commands with arguments, PIDs, /tmp paths or URLs (old single approvals)
  stale-dirs     additionalDirectories entries that no longer exist, plus /tmp

Usage:
  prune_permissions.py --remove sudo,secret-via-env-file,stale-dirs            # plan
  prune_permissions.py --remove one-off --apply --backup-dir ~/.claude/backups/x
  prune_permissions.py --remove one-off --files path/to/settings.json           # limit files
"""
import argparse
import errno
import json
import os
import re
import shutil
import sys
import tempfile
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect  # noqa: E402  (shares the risk classification with the collector)

KEEP_REUSABLE = re.compile(r"(localhost|127\.0\.0\.1):\d+|lsof -i:\d+")


class SymlinkRefused(Exception):
    """The settings path is (or became) a symlink and --allow-symlinks wasn't given."""


class ChangedSincePlan(Exception):
    """The file's identity at apply time doesn't match what was read during planning."""


def is_one_off(rule):
    if re.search(r"[: ]\*\)$|\*\*\)$", rule):  # generic prefix or glob rule: keep
        return False
    # Short read-only localhost checks (health endpoints, lsof on a port) are reusable.
    if len(rule) <= 80 and KEEP_REUSABLE.search(rule) and not re.search(r"-X (POST|PUT|DELETE)|/tmp/", rule):
        return False
    return len(rule) > 60 or "/tmp/" in rule or "http" in rule or "/home/" in rule or bool(re.search(r"\b\d{4,}\b", rule))


def settings_files(snapshot):
    files = [os.path.join(collect.CLAUDE, n) for n in ("settings.json", "settings.local.json")]
    if snapshot:
        for entry in json.load(open(snapshot))["projects"].values():
            files += [os.path.expanduser(s["path"]) for s in entry.get("settings", [])]
    else:
        for root in collect.discover_projects():
            files += [os.path.join(root, ".claude", n) for n in ("settings.json", "settings.local.json")]
    return [f for f in dict.fromkeys(files) if os.path.exists(f)]


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


def atomic_write(target, text):
    """Write text to path without ever leaving it truncated or partially written.

    The caller supplies the target used for identity verification. Never resolve a symlink here:
    resolving the original settings path again could select a different, unverified target.
    """
    dirpath = os.path.dirname(target) or "."
    fd, tmp = tempfile.mkstemp(prefix=".prune_permissions.", dir=dirpath)
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


def plan_file(path, remove, allow_symlinks=False):
    fd, st = open_no_symlink(path, allow_symlinks)
    with os.fdopen(fd) as f:
        data = json.load(f)
    identity = identity_of(st)
    perms = data.get("permissions") or {}
    removals = []
    for rule in perms.get("allow") or []:
        reasons = [name for name, rx in collect.RISKY_RULES if name in remove and rx.search(rule)]
        if "one-off" in remove and not reasons and is_one_off(rule):
            reasons = ["one-off"]
        if reasons:
            removals.append({"rule": collect.redact(rule)[:160], "reasons": reasons, "_raw": rule})
    dirs = []
    if "stale-dirs" in remove:
        dirs = [d for d in perms.get("additionalDirectories") or []
                if d.rstrip("/") == "/tmp" or not os.path.isdir(os.path.expanduser(d))]
    return data, removals, dirs, identity


def apply_file(path, data, removals, dirs, identity, backup_dir, allow_symlinks=False):
    """Re-validate the file is unchanged and not a symlink, back it up, then atomically rewrite it.

    Raises SymlinkRefused or ChangedSincePlan instead of writing when that check fails; the caller
    decides how to report it. Returns the backup path on success.

    The identity check and the backup both go through the same file descriptor opened here, so a
    retarget of the original symlink cannot redirect the backup or write. Resolve that symlink
    once before opening and checking the target, and retain that target for the write.
    Replacement of the resolved target or its parent directories can still race the final
    path-based os.replace(); this does not provide protection against every filesystem race.
    """
    target = os.path.realpath(path) if allow_symlinks else path
    fd, st = open_no_symlink(target)
    try:
        if identity_of(st) != identity:
            raise ChangedSincePlan(path)
        os.makedirs(backup_dir, exist_ok=True)
        prefix = path.replace(collect.HOME, "").strip(os.sep).replace(os.sep, "__")
        # mkstemp uses exclusive creation and mode 0600: repeated applies cannot overwrite
        # recovery data or follow a pre-existing backup symlink, even in the same second.
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
    finally:
        os.close(fd)
    raw = {r["_raw"] for r in removals}
    perms = data["permissions"]
    perms["allow"] = [r for r in perms.get("allow", []) if r not in raw]
    if dirs:
        perms["additionalDirectories"] = [d for d in perms["additionalDirectories"] if d not in dirs]
    text = json.dumps(data, indent=2) + "\n"
    json.loads(text)
    atomic_write(target, text)
    return backup


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remove", required=True, help="comma-separated categories")
    ap.add_argument("--files", nargs="*", help="settings files (default: user + discovered projects)")
    ap.add_argument("--snapshot", help="use the project list from a collect.py snapshot")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--backup-dir")
    ap.add_argument("--allow-symlinks", action="store_true",
                    help="operate on a settings path even if it is a symlink (refused by default)")
    a = ap.parse_args()
    remove = {c.strip() for c in a.remove.split(",") if c.strip()}
    known = {name for name, _ in collect.RISKY_RULES} | {"one-off", "stale-dirs"}
    if remove - known:
        ap.error(f"unknown categories: {sorted(remove - known)}")
    if a.apply and not a.backup_dir:
        ap.error("--apply requires --backup-dir")

    plan, total, skipped = [], 0, []
    for path in a.files or settings_files(a.snapshot):
        try:
            data, removals, dirs, identity = plan_file(path, remove, a.allow_symlinks)
        except (OSError, ValueError, SymlinkRefused) as e:  # unreadable (sandbox, permissions), symlink, bad JSON
            skipped.append({"file": path.replace(collect.HOME, "~"), "error": type(e).__name__})
            continue
        if not removals and not dirs:
            continue
        total += len(removals)
        plan.append({"file": path.replace(collect.HOME, "~"),
                     "remove_rules": [{k: v for k, v in r.items() if k != "_raw"} for r in removals],
                     "remove_dirs": dirs})
        if a.apply:
            try:
                backup = apply_file(path, data, removals, dirs, identity,
                                    os.path.expanduser(a.backup_dir), a.allow_symlinks)
            except (SymlinkRefused, ChangedSincePlan) as e:
                plan[-1]["apply_error"] = type(e).__name__
                continue
            plan[-1]["backup"] = backup.replace(collect.HOME, "~")
    print(json.dumps({"applied": a.apply, "rules": total, "files": plan, "skipped": skipped}, indent=1))


if __name__ == "__main__":
    main()
