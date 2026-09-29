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
    """(object, None) when readable; (None, 'absent') or (None, 'unreadable') otherwise.

    Unreadable covers OS errors, invalid JSON, a non-object and a file above MAX_HOOK_FILE.
    """
    if not os.path.lexists(path):
        return None, 'absent'
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read(MAX_HOOK_FILE + 1)
        data = None if len(text) > MAX_HOOK_FILE else json.loads(text)
    except (OSError, ValueError):
        data = None
    return (data, None) if isinstance(data, dict) else (None, 'unreadable')


def _inside(path, root):
    """Contained in root lexically and after resolving links, and not itself a symlink."""
    path = os.path.abspath(path)
    return (path.startswith(os.path.abspath(root) + os.sep) and not os.path.islink(path)
            and os.path.realpath(path).startswith(os.path.realpath(root) + os.sep))


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


def _hook_file(name, version, root, path):
    """Entries of one hooks file, or 'hook_file_unreadable' when it cannot be trusted or read."""
    if not _inside(path, root):
        return [], 'hook_file_unreadable'
    data, _ = _json(path)
    if data is None:
        return [], 'hook_file_unreadable'
    return _entries(name, version, root, path, data), None


def hook_index(claude, settings):
    """Hook commands of enabled plugins, resolved through the registry installPath."""
    enabled = {k for s in settings for k, v in (s.get('enabled_plugins') or {}).items() if v is True}
    registry, _ = _json(os.path.join(claude, 'plugins', 'installed_plugins.json'))
    registry = registry.get('plugins') if registry else None
    storage = os.path.realpath(os.path.join(claude, 'plugins'))
    index, reasons = [], set()
    for name in sorted(enabled):
        rows = registry.get(name) if isinstance(registry, dict) else None
        if not isinstance(rows, list) or not rows:
            reasons.add('plugin_registry_unreadable')
            continue
        for row in rows:
            root = row.get('installPath') if isinstance(row, dict) else None
            if (not isinstance(root, str) or not os.path.isabs(root)
                    or not os.path.realpath(root).startswith(storage + os.sep) or not os.path.isdir(root)):
                reasons.add('plugin_root_unreadable')
                continue
            version = str(row.get('version', 'unknown'))
            manifest_path = os.path.join(root, '.claude-plugin', 'plugin.json')
            default = os.path.join(root, 'hooks', 'hooks.json')
            manifest, why = _json(manifest_path)
            if why == 'unreadable':  # a missing manifest is normal
                reasons.add('manifest_unreadable')
            declared = (manifest or {}).get('hooks')
            # Manifest hooks: an inline object, a path string, or a list of either.
            for item in declared if isinstance(declared, list) else [declared]:
                if isinstance(item, dict):
                    index += _entries(name, version, root, manifest_path, item)
                elif isinstance(item, str):
                    path = os.path.abspath(os.path.join(root, item))
                    if path == os.path.abspath(default):
                        continue  # the default file is indexed below, once
                    entries, reason = _hook_file(name, version, root, path)
                    index += entries
                    reasons.update([reason] if reason else [])
            if os.path.lexists(default):
                entries, reason = _hook_file(name, version, root, default)
                index += entries
                reasons.update([reason] if reason else [])
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
# Word boundaries exclude names such as claude-setup or myclaude; a backtick-quoted `claude` is prose.
PATTERNS = (
    ('claude_print', re.compile(r'(?<![\w.`-])claude(?![\w.-])[^\n|;&]*?\s(?:-p|--print)(?![\w-])')),
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


def _attribute(index, raw, path, event, tool_id):
    """Exact toolUseID pairing first; otherwise the same file's hooks of that event that printed.

    SessionStart injections carry the event name as toolUseID (observed 2026-09-29), so they never
    pair. The fallback keeps only candidates that match a plugin hook; user and project hooks drop
    out. One plugin left is matched, several (or an ambiguous command) are ambiguous. Never guesses.
    """
    command = raw['commands'].get((path, tool_id)) if tool_id else None
    if command is not None:
        return match_command(index, command)
    results = [match_command(index, c) for c in sorted(raw.get('event_commands', {}).get((path, event), ()))]
    results = [r for r in results if r[1] != 'unattributed']
    plugins = {p for p, _ in results}
    if any(a == 'ambiguous' for _, a in results) or len(plugins) > 1:
        return None, 'ambiguous'
    if plugins:
        return plugins.pop(), 'matched'
    return None, 'unattributed'


def _per_plugin_skills(extension_inventory):
    """Skill counts of enabled plugins (any settings observation is True), max across registry rows."""
    counts = {}
    for p in extension_inventory.get('plugins', []):
        if not any(o.get('value') is True for o in p.get('enablement_observations') or []):
            continue
        n = sum(1 for c in p.get('components', []) if c.get('kind') == 'skills')
        counts[p['name']] = max(counts.get(p['name'], 0), n)
    return [dict(plugin=name, skills=n) for name, n in counts.items() if n]


def assemble(raw, index, index_reasons, extension_inventory, transcript_coverage, window_days, pct, scan=None,
             transcripts_read=True):
    """Build the harness_overhead snapshot section from in-memory transcript signals.

    transcripts_read is False for global scope, which reads no transcripts: only the static
    signals (hook index and scan) are then meaningful.
    """
    reasons = set(index_reasons)
    if not transcripts_read:
        reasons.add('transcripts_not_read')
    if transcript_coverage['main_files'].get('omitted'):
        reasons.add('main_file_cap')
    if transcript_coverage['subagent_files'].get('omitted'):
        reasons.add('subagent_file_cap')
    if raw['malformed']:
        reasons.add('malformed_records')

    per_session = defaultdict(lambda: defaultdict(int))  # source key -> session path -> chars
    records = defaultdict(int)
    for path, event, tool_id, chars in raw['injections']:
        plugin, attribution = _attribute(index, raw, path, event, tool_id)
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

    # SDK sessions list different skills than interactive ones; mixing them breaks the series.
    # No or unknown entrypoint counts as non-SDK.
    is_sdk = lambda p: raw.get('file_entrypoints', {}).get(p, '').startswith('sdk-')  # noqa: E731
    listings = sorted(x for x in raw['listings'] if not is_sdk(x[3]))
    sdk_excluded = sum(1 for x in raw['listings'] if is_sdk(x[3]))
    per_plugin = _per_plugin_skills(extension_inventory)
    if listings:
        first, last = listings[0], listings[-1]
        top = max(listings, key=lambda x: (x[1], x[2]))
        series = dict(sessions=len(listings),
                      first=dict(date=_day(first[0]), skill_count=first[1], chars=first[2]),
                      last=dict(date=_day(last[0]), skill_count=last[1], chars=last[2]),
                      max=dict(skill_count=top[1], chars=top[2]), sdk_sessions_excluded=sdk_excluded,
                      per_plugin_skills=per_plugin)
    else:
        series = None
        reasons.add('not_observed')

    entry = {k: 0 for k in ENTRYPOINTS + ('other',)}
    for name, count in raw['entrypoints'].items():
        entry[name if name in ENTRYPOINTS else 'other'] += count
    sub = [v for v in raw['sub_tokens'].values() if v]
    # Main tokens of the same sessions that spawned subagents, so the two medians compare like sessions.
    paired = [m for k, v in raw['sub_tokens'].items() if v and (m := raw['main_tokens'].get(k))]
    spend = dict(subagent_files_scanned=transcript_coverage['subagent_files'].get('scanned', 0),
                 sessions_with_subagents=len(sub),
                 subagent_tokens_per_session_median=_int(pct(sub, 0.5)),
                 main_tokens_per_session_median=_int(pct([v for v in raw['main_tokens'].values() if v], 0.5)),
                 main_tokens_median_in_subagent_sessions=_int(pct(paired, 0.5)),
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
