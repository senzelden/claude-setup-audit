#!/usr/bin/env python3
"""Plan (default) or apply removal of permission allow rules and stale directories.

Dry-run by default: prints a JSON plan and changes nothing. With --apply, backs up every file it
touches into --backup-dir first, rewrites only the selected categories, and validates the JSON.

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
import json
import os
import re
import shutil
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect  # noqa: E402  (shares the risk classification with the collector)

KEEP_REUSABLE = re.compile(r"(localhost|127\.0\.0\.1):\d+|lsof -i:\d+")


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


def plan_file(path, remove):
    with open(path) as f:
        data = json.load(f)
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
    return data, removals, dirs


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--remove", required=True, help="comma-separated categories")
    ap.add_argument("--files", nargs="*", help="settings files (default: user + discovered projects)")
    ap.add_argument("--snapshot", help="use the project list from a collect.py snapshot")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--backup-dir")
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
            data, removals, dirs = plan_file(path, remove)
        except (OSError, ValueError) as e:  # unreadable (sandbox, permissions) or invalid JSON
            skipped.append({"file": path.replace(collect.HOME, "~"), "error": type(e).__name__})
            continue
        if not removals and not dirs:
            continue
        total += len(removals)
        plan.append({"file": path.replace(collect.HOME, "~"),
                     "remove_rules": [{k: v for k, v in r.items() if k != "_raw"} for r in removals],
                     "remove_dirs": dirs})
        if a.apply:
            backup_dir = os.path.expanduser(a.backup_dir)
            os.makedirs(backup_dir, exist_ok=True)
            backup = os.path.join(backup_dir, path.replace(collect.HOME, "").strip(os.sep).replace(os.sep, "__")
                                  + f".{int(time.time())}.bak")
            shutil.copy2(path, backup)
            raw = {r["_raw"] for r in removals}
            perms = data["permissions"]
            perms["allow"] = [r for r in perms.get("allow", []) if r not in raw]
            if dirs:
                perms["additionalDirectories"] = [d for d in perms["additionalDirectories"] if d not in dirs]
            text = json.dumps(data, indent=2) + "\n"
            json.loads(text)
            with open(path, "w") as f:
                f.write(text)
            plan[-1]["backup"] = backup.replace(collect.HOME, "~")
    print(json.dumps({"applied": a.apply, "rules": total, "files": plan, "skipped": skipped}, indent=1))


if __name__ == "__main__":
    main()
