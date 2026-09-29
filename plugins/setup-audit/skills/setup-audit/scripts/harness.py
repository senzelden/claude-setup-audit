"""Harness overhead: plugin hook index, command attribution, static hook scan, assembly.

Reads the plugin registry and hook files only; never runs a hook. Raw command strings stay in
memory for matching and are never part of the returned snapshot section.
"""
import json
import os
import re
import shlex
from collections import defaultdict
from datetime import datetime, timezone

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


MAX_SCRIPT = 64 * 1024
# Word boundaries exclude names such as claude-setup or myclaude.
PATTERNS = (
    ('claude_print', re.compile(r'(?<![\w.-])claude(?![\w.-])[^\n|;&]*?\s(?:-p|--print)(?![\w-])')),
    ('agent_sdk_py', re.compile(r'\bclaude_agent_sdk\b')),
    ('agent_sdk_js', re.compile(r'@anthropic-ai/claude-agent-sdk')),
    ('anthropic_client', re.compile(r'anthropic\.Anthropic\(|new Anthropic\(|api\.anthropic\.com')),
)
ROOT_VARS = ('${CLAUDE_PLUGIN_ROOT}', '$CLAUDE_PLUGIN_ROOT')


def _matches(text):
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(('#', '//')):
            continue
        for pattern_id, rx in PATTERNS:
            if rx.search(line):
                yield number, pattern_id


def _script_paths(command, root):
    expanded = command
    for var in ROOT_VARS:
        expanded = expanded.replace(var, root)
    try:
        tokens = shlex.split(expanded, comments=False)
    except ValueError:
        tokens = expanded.split()
    for token in tokens:
        for part in token.split(';'):
            if part.startswith(root + os.sep) or part.startswith(root + '/..'):
                yield part


def scan_hooks(index):
    """Flag hook commands and plugin-local scripts that invoke a model. Never runs anything."""
    found, reasons = set(), set()
    for e in index:
        root = e['root']
        for _, pattern_id in _matches(e['command']):
            found.add((e['plugin'], e['event'], os.path.relpath(e['source'], root), None, pattern_id))
        for raw in _script_paths(e['command'], root):
            path = os.path.abspath(raw)
            real_root = os.path.realpath(root)
            if (not path.startswith(os.path.abspath(root) + os.sep) or os.path.islink(path)
                    or not os.path.realpath(path).startswith(real_root + os.sep) or not os.path.isfile(path)):
                reasons.add('script_unresolved')
                continue
            try:
                with open(path, encoding='utf-8', errors='replace') as f:
                    text = f.read(MAX_SCRIPT + 1)
            except OSError:
                reasons.add('script_unresolved')
                continue
            if len(text) > MAX_SCRIPT:
                reasons.add('script_truncated')
                text = text[:MAX_SCRIPT]
            for line, pattern_id in _matches(text):
                found.add((e['plugin'], e['event'], os.path.relpath(path, root), line, pattern_id))
    rows = sorted(found, key=lambda r: (r[0], r[2], r[3] or 0, r[4], r[1]))
    return [dict(plugin=p, hook_event=ev, file=f, line=ln, pattern=pid) for p, ev, f, ln, pid in rows], sorted(reasons)


ENTRYPOINTS = ('cli', 'sdk-py', 'sdk-cli')


def _int(value):
    return None if value is None else int(round(value))


def _day(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime('%Y-%m-%d')


def assemble(raw, index, index_reasons, extension_inventory, transcript_coverage, window_days, pct, scan=None):
    """Build the harness_overhead snapshot section from in-memory transcript signals."""
    reasons = set(index_reasons)
    if transcript_coverage['main_files'].get('omitted'):
        reasons.add('main_file_cap')
    if transcript_coverage['subagent_files'].get('omitted'):
        reasons.add('subagent_file_cap')
    if raw['malformed']:
        reasons.add('malformed_records')

    per_session = defaultdict(lambda: defaultdict(int))  # source key -> session path -> chars
    records = defaultdict(int)
    for path, event, tool_id, chars in raw['injections']:
        plugin, attribution = match_command(index, raw['commands'].get((path, tool_id)) if tool_id else None)
        key = (plugin, attribution, event)
        per_session[key][path] += chars
        records[key] += 1
    sources = []
    for (plugin, attribution, event), sessions in per_session.items():
        values = list(sessions.values())
        median = pct(values, 0.5)
        sources.append(dict(plugin=plugin, attribution=attribution, hook_event=event, sessions=len(values),
                            records=records[(plugin, attribution, event)],
                            chars_per_session_median=_int(median), chars_per_session_p90=_int(pct(values, 0.9)),
                            est_tokens_per_session_median=_int(median / 4)))
    sources.sort(key=lambda s: (-s['sessions'], s['plugin'] or '', s['attribution'], s['hook_event']))

    listings = sorted(raw['listings'])
    per_plugin = [dict(plugin=p['name'], skills=n) for p in extension_inventory.get('plugins', [])
                  if (n := sum(1 for c in p.get('components', []) if c.get('kind') == 'skills'))]
    if listings:
        first, last = listings[0], listings[-1]
        top = max(listings, key=lambda x: (x[1], x[2]))
        series = dict(sessions=len(listings),
                      first=dict(date=_day(first[0]), skill_count=first[1], chars=first[2]),
                      last=dict(date=_day(last[0]), skill_count=last[1], chars=last[2]),
                      max=dict(skill_count=top[1], chars=top[2]), per_plugin_skills=per_plugin)
    else:
        series = None
        reasons.add('not_observed')

    entry = {k: 0 for k in ENTRYPOINTS + ('other',)}
    for name, count in raw['entrypoints'].items():
        entry[name if name in ENTRYPOINTS else 'other'] += count
    sub = [v for v in raw['sub_tokens'].values() if v]
    spend = dict(subagent_files_scanned=transcript_coverage['subagent_files'].get('scanned', 0),
                 sessions_with_subagents=len(sub),
                 subagent_tokens_per_session_median=_int(pct(sub, 0.5)),
                 main_tokens_per_session_median=_int(pct([v for v in raw['main_tokens'].values() if v], 0.5)),
                 entrypoints=entry)

    spawning, scan_reasons = (scan or scan_hooks)(index)
    reasons.update(scan_reasons)
    return dict(window_days=window_days, sessions_scanned=raw['sessions'],
                # not_observed is reported but is not a collection gap.
                complete=not (reasons - {'not_observed'}),
                incomplete_reasons=sorted(reasons),
                injected_context=dict(sessions_with_injection=len({p for p, *_ in raw['injections']}),
                                      sources=sources),
                skill_listing_series=series, subagent_spend=spend, model_spawning_hooks=spawning)
