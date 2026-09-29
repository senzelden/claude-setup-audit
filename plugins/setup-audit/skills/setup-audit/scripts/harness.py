"""Harness overhead: plugin hook index, command attribution, static hook scan, assembly.

Reads the plugin registry and hook files only; never runs a hook. Raw command strings stay in
memory for matching and are never part of the returned snapshot section.
"""
import json
import os

MAX_HOOK_FILE = 1024 * 1024


def _json(path):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            data = json.loads(f.read(MAX_HOOK_FILE + 1)[:MAX_HOOK_FILE])
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _entries(plugin, version, root, source, data):
    hooks = data.get('hooks', data) if isinstance(data, dict) else None
    out = []
    if not isinstance(hooks, dict):
        return out
    for event, groups in hooks.items():
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, dict):
                continue
            for h in group.get('hooks', []) if isinstance(group.get('hooks'), list) else []:
                if isinstance(h, dict) and isinstance(h.get('command'), str):
                    out.append(dict(plugin=plugin, version=version, root=root, event=event,
                                    matcher=group.get('matcher'), command=h['command'], source=source))
    return out


def hook_index(claude, settings):
    """Hook commands of enabled plugins, resolved through the registry installPath."""
    enabled = {k for s in settings for k, v in (s.get('enabled_plugins') or {}).items() if v is True}
    registry = (_json(os.path.join(claude, 'plugins', 'installed_plugins.json')) or {}).get('plugins')
    storage = os.path.realpath(os.path.join(claude, 'plugins'))
    index, reasons = [], set()
    for name in sorted(enabled):
        rows = registry.get(name) if isinstance(registry, dict) else None
        for row in rows if isinstance(rows, list) else []:
            root = row.get('installPath') if isinstance(row, dict) else None
            if (not isinstance(root, str) or not os.path.isabs(root)
                    or not os.path.realpath(root).startswith(storage + os.sep) or not os.path.isdir(root)):
                reasons.add('plugin_root_unreadable')
                continue
            version = str(row.get('version', 'unknown'))
            manifest_path = os.path.join(root, '.claude-plugin', 'plugin.json')
            inline = (_json(manifest_path) or {}).get('hooks')
            if isinstance(inline, dict):
                index += _entries(name, version, root, manifest_path, inline)
            hooks_path = os.path.join(root, 'hooks', 'hooks.json')
            if os.path.isfile(hooks_path) and not os.path.islink(hooks_path):
                index += _entries(name, version, root, hooks_path, _json(hooks_path) or {})
    return index, sorted(reasons)


def match_command(index, command):
    """Exact string match only; a near miss is unattributed, never guessed."""
    if not isinstance(command, str):
        return None, 'unattributed'
    plugins = {e['plugin'] for e in index if e['command'] == command}
    if len(plugins) == 1:
        return plugins.pop(), 'matched'
    return None, ('ambiguous' if plugins else 'unattributed')
