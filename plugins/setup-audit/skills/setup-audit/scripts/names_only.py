#!/usr/bin/env python3
"""Names-only view of Claude Code settings and MCP config files, for when collect.py cannot run.

Prints JSON per file: key paths, value types, array lengths, env/headers key names and permission
rule strings (redacted with privacy.redact). Values of any other key are never printed; a string
is reported as a type only. ~/.claude.json goes through config_names (names, counts, labels).
Nothing is executed, followed through a symlink, or written. Needs only config_names, inventory
and privacy, so it still works when collect.py fails.

Status per file: ok, missing, not_json, symlink_refused, too_large, unreadable.
--metadata-only replaces each permission rule with the collector's length marker (privacy.marker).
Every string of the final output, keys included, passes privacy.redact once more before printing.
"""
import argparse
import json
import os
import sys
import config_names
import inventory
import privacy

HOME = os.path.expanduser('~')
MAX_BYTES = 1024 * 1024
MAX_DEPTH = 8          # nesting levels walked; deeper values are reported as a type only
MAX_KEYS = 400         # distinct key paths kept per file
MAX_NAMES = 200        # env/header key names kept per path
MAX_RULES = 200        # permission rule strings kept per list
MAX_ELEMENTS = 50      # array elements walked per array
TEXT_CAP = 200         # characters kept of any name or rule
MAX_PLUGINS = 50
MAX_USER_PROJECTS = 100
MAX_MANAGED_FILES = 100
# Mappings whose keys are names of secrets: only the keys are printed.
NAME_ONLY = frozenset({'env', 'headers'})
RULE_LISTS = frozenset({'permissions.allow', 'permissions.deny', 'permissions.ask',
                        'permissions.additionalDirectories'})
STATUSES = ('ok', 'missing', 'not_json', 'symlink_refused', 'too_large', 'unreadable')


def managed_directory():
    if sys.platform == 'darwin':
        return '/Library/Application Support/ClaudeCode'
    return '/etc/claude-code' if sys.platform.startswith('linux') else None


def text(value):
    """A name or rule, redacted and capped."""
    return privacy.redact(str(value))[:TEXT_CAP]


def key_names(mapping):
    """Sorted, redacted key names of a mapping; values are not looked at."""
    return sorted({text(k) for k in mapping if isinstance(k, str)})[:MAX_NAMES]


def kind_of(value):
    if isinstance(value, dict):
        return 'object'
    if isinstance(value, list):
        return 'array'
    if isinstance(value, bool):
        return 'boolean'
    if value is None:
        return 'null'
    return 'number' if isinstance(value, (int, float)) else 'string'


def scrub(obj):
    """privacy.redact over every string of a JSON-shaped value, keys included (collect.sanitize's
    backstop): server facts and name lists are copied through and never passed through text()."""
    if isinstance(obj, str):
        return privacy.redact(obj)
    if isinstance(obj, dict):
        return {scrub(k): scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(v) for v in obj]
    return obj


class Walk:
    def __init__(self, metadata_only=False):
        self.keys, self.names, self.rules, self.truncated = {}, {}, {}, False
        self.metadata_only = metadata_only

    def note(self, path, value):
        row = self.keys.get(path)
        if row is None:
            if len(self.keys) >= MAX_KEYS:
                self.truncated = True
                return
            row = self.keys[path] = {'path': path, 'types': set(), 'count': 0, 'max_length': None}
        row['types'].add(kind_of(value))
        row['count'] += 1
        if isinstance(value, (dict, list)):
            row['max_length'] = max(row['max_length'] or 0, len(value))

    def visit(self, value, path, depth):
        self.note(path, value)
        if path in RULE_LISTS and isinstance(value, list):
            rules = self.rules.setdefault(path, [])
            for item in value:
                if isinstance(item, str) and len(rules) < MAX_RULES:
                    rules.append(privacy.marker(item) if self.metadata_only else text(item))
                elif isinstance(item, str):
                    self.truncated = True
            return
        if depth >= MAX_DEPTH:
            self.truncated = self.truncated or bool(value) and isinstance(value, (dict, list))
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:MAX_KEYS]:
                label = text(key)
                child_path = f'{path}.{label}' if path else label
                if key in NAME_ONLY and isinstance(child, dict):
                    self.note(child_path, child)
                    names = self.names.setdefault(child_path, set())
                    names.update(key_names(child))
                    continue
                self.visit(child, child_path, depth + 1)
            if len(value) > MAX_KEYS:
                self.truncated = True
        elif isinstance(value, list):
            for child in value[:MAX_ELEMENTS]:
                self.visit(child, path + '[]', depth + 1)
            if len(value) > MAX_ELEMENTS:
                self.truncated = True

    def result(self):
        rows = [dict(r, types=sorted(r['types'])) for r in self.keys.values()]
        out = {'keys': sorted(rows, key=lambda r: r['path']), 'truncated': self.truncated}
        if self.names:
            out['names'] = {p: sorted(n)[:MAX_NAMES] for p, n in sorted(self.names.items())}
        if self.rules:
            out['rules'] = dict(sorted(self.rules.items()))
        return out


def load(path):
    """(parsed object or None, status, reason). Symlinks are never followed; reads are bounded."""
    raw, info = inventory.read_text(path, MAX_BYTES)
    if raw is None:
        reason = info.get('reason')
        if info['status'] == 'absent':
            return None, 'missing', None
        if reason == 'symlink_not_followed':
            return None, 'symlink_refused', reason
        return None, 'unreadable', reason
    if info.get('truncated'):
        return None, 'too_large', 'byte_limit'
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return None, 'not_json', 'invalid_json'
    if not isinstance(data, dict):
        return None, 'not_json', 'not_an_object'
    return data, 'ok', None


def file_entry(path, scope, kind, mcp=None, metadata_only=False):
    """One file's names-only entry. ``mcp``: None, 'wrapped' (mcpServers key) or 'bare' (plugin shape)."""
    data, status, reason = load(path)
    entry = {'path': path, 'scope': scope, 'kind': kind, 'status': status}
    if reason:
        entry['reason'] = reason
    if data is None:
        return entry
    walk = Walk(metadata_only)
    try:
        walk.visit(data, '', 0)
    except RecursionError:  # unreachable under MAX_DEPTH; kept so a bug never aborts the fallback
        entry.update(status='not_json', reason='too_deep')
        return entry
    entry.update(walk.result())
    if mcp:
        servers = config_names.server_map(data, bare=mcp == 'bare')
        if servers is not None:
            entry['servers'] = {text(n): f for n, f in servers.items()}
    return entry


def user_state_entry(home):
    """(entry, raw project roots): ~/.claude.json through config_names, server facts and per-project
    server-name lists only. The raw roots are for discovery and are never printed as such."""
    view = config_names.user_mcp_state(home)
    status = view['source'].get('status')
    mapped = {'collected': 'ok', 'absent': 'missing'}.get(status)
    reason = view['source'].get('reason')
    if mapped is None:
        mapped = ('symlink_refused' if reason == 'symlink_not_followed' else 'not_json'
                  if reason == 'invalid_json_object' else 'too_large' if view['source'].get('truncated')
                  else 'unreadable')
    entry = {'path': view['path'], 'scope': 'user', 'kind': 'user_state', 'status': mapped}
    if mapped == 'ok':
        entry['servers'] = {text(n): f for n, f in (view.get('mcpServers') or {}).items()}
        entry['projects'] = {text(root): {k: (v if not isinstance(v, dict) else {text(n): f for n, f in v.items()})
                                          for k, v in row.items()} for root, row in sorted(view['projects'].items())}
    elif reason:
        entry['reason'] = reason
    return entry, (sorted(view['projects']) if mapped == 'ok' else [])


def plugin_entries(claude_dir, metadata_only=False):
    """Default <installPath>/.mcp.json of registered plugin installs inside the plugin cache."""
    data, status, _ = load(os.path.join(claude_dir, 'plugins', 'installed_plugins.json'))
    registry = data.get('plugins') if status == 'ok' else None
    if not isinstance(registry, dict):
        return []
    cache = os.path.realpath(os.path.join(claude_dir, 'plugins'))
    entries, seen = [], set()
    for name in sorted(registry):
        for row in registry[name] if isinstance(registry[name], list) else []:
            root = row.get('installPath') if isinstance(row, dict) else None
            if (not isinstance(root, str) or not os.path.isabs(root) or root in seen
                    or not os.path.realpath(root).startswith(cache + os.sep) or len(seen) >= MAX_PLUGINS):
                continue
            seen.add(root)
            entries.append(file_entry(os.path.join(root, '.mcp.json'), 'plugin', 'mcp', 'bare', metadata_only))
    return entries


def run(home=None, claude_dir=None, roots=(), managed_dir=None, user_projects=False, metadata_only=False):
    home = HOME if home is None else home
    claude_dir = claude_dir or os.environ.get('CLAUDE_CONFIG_DIR') or os.path.join(home, '.claude')

    def entry(path, scope, kind, mcp=None):
        return file_entry(path, scope, kind, mcp, metadata_only)

    files = [entry(os.path.join(claude_dir, n), 'user', 'settings') for n in ('settings.json', 'settings.local.json')]
    state, listed_roots = user_state_entry(home)
    files.append(state)
    roots = list(roots)
    omitted = 0
    if user_projects and state['status'] == 'ok':
        # Project roots Claude Code recorded in ~/.claude.json (names only), standing in for the
        # collector's discovery under scope=all. Missing directories are skipped; a root that the
        # name cap or redaction would change (longer than TEXT_CAP, or secret-shaped) is not read
        # and is counted as omitted, like roots beyond MAX_USER_PROJECTS.
        unusable = [r for r in listed_roots if text(r) != r]
        listed = [r for r in listed_roots if text(r) == r and os.path.isabs(r) and os.path.isdir(r)
                  and r not in roots]
        omitted = len(unusable) + max(0, len(listed) - MAX_USER_PROJECTS)
        roots += listed[:MAX_USER_PROJECTS]
    for root in roots:
        for rel in ('settings.json', 'settings.local.json'):
            files.append(entry(os.path.join(root, '.claude', rel), 'project', 'settings'))
        files.append(entry(os.path.join(root, '.mcp.json'), 'project', 'mcp', 'wrapped'))
    if managed_dir:
        files.append(entry(os.path.join(managed_dir, 'managed-settings.json'), 'managed', 'settings'))
        directory = os.path.join(managed_dir, 'managed-settings.d')
        try:
            names = sorted(n for n in os.listdir(directory) if n.endswith('.json') and not n.startswith('.'))
        except OSError:
            names = []
        files += [entry(os.path.join(directory, n), 'managed', 'settings') for n in names[:MAX_MANAGED_FILES]]
        files.append(entry(os.path.join(managed_dir, 'managed-mcp.json'), 'managed', 'mcp', 'wrapped'))
    files += plugin_entries(claude_dir, metadata_only)
    not_assessed = ('no project roots were given: project settings and .mcp.json files were not read'
                    if not roots else 'projects not in project_roots, worktree main-checkout local '
                    'settings, .envrc and transcripts were not read')
    if user_projects and state['status'] != 'ok':
        not_assessed = ('~/.claude.json, the source of --from-user-projects, could not be read (status %s), '
                        'so no project roots were discovered from it; ' % state['status']) + not_assessed
    return scrub({'names_only_version': 1,
                  'note': 'Names, types, counts and labels only; no env, header, OAuth or argument value is printed.',
                  'privacy': 'metadata-only' if metadata_only else 'full',
                  'project_roots': roots, 'user_projects_omitted': omitted,
                  'not_assessed': not_assessed,
                  'files': files})


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--claude-dir', help='Claude Code config directory (default: $CLAUDE_CONFIG_DIR, else ~/.claude)')
    ap.add_argument('--project', action='append', default=[], help='project root to include (repeatable)')
    ap.add_argument('--roots', nargs='*', default=[], help='more project roots')
    ap.add_argument('--from-user-projects', action='store_true',
                    help='also include the project roots listed in ~/.claude.json (scope=all stand-in)')
    ap.add_argument('--metadata-only', action='store_true',
                    help='replace permission rule strings with length markers (privacy=metadata-only)')
    a = ap.parse_args()
    roots = [os.path.abspath(os.path.expanduser(r)) for r in [*a.project, *a.roots]]
    claude = os.path.abspath(os.path.expanduser(a.claude_dir)) if a.claude_dir else None
    json.dump(run(claude_dir=claude, roots=roots, managed_dir=managed_directory(),
              user_projects=a.from_user_projects, metadata_only=a.metadata_only), sys.stdout, indent=1,
              allow_nan=False)
    print()


if __name__ == '__main__':
    main()
