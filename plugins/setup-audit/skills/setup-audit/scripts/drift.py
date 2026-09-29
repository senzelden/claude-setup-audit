#!/usr/bin/env python3
"""Opt-in, model-free drift check: collect, derive five signals, compare, append one log line.

Silent unless a threshold is crossed. Never installs a hook or schedule; see references/drift.md.
"""
import hashlib
import drift_log

SIGNALS = drift_log.SIGNALS
META_KEYS = ('scope', 'project', 'window_days')


def fingerprint(path, flag, rule):
    return hashlib.sha256(f'{path}\0{flag}\0{rule}'.encode()).hexdigest()[:16]


def derive(snap, global_claude_md):
    """(signals, fingerprint -> settings path) from a collected snapshot. Rule text is not kept."""
    glob_ = snap.get('global') or {}
    projects = snap.get('projects') or {}
    claude_md = {}
    g = glob_.get('claude_md')
    if isinstance(g, dict):
        claude_md[global_claude_md] = {'lines': g.get('lines'), 'est_tokens': g.get('est_tokens')}
    for path, entry in sorted(projects.items()):
        if 'claude_md_lines' in entry and not entry.get('is_worktree_copy'):
            claude_md[path.rstrip('/') + '/CLAUDE.md'] = {'lines': entry['claude_md_lines'],
                                                         'est_tokens': entry.get('claude_md_tokens')}
    fps = {}
    for s in list(glob_.get('settings') or []) + [s for p in projects.values() for s in p.get('settings') or []]:
        for flag, rules in sorted(((s.get('permissions') or {}).get('risky') or {}).items()):
            for rule in rules:
                fps[fingerprint(s.get('path'), flag, rule)] = s.get('path')
    ratio = ((snap.get('transcripts') or {}).get('cache') or {}).get('hit_ratio')
    transcripts_complete = all(c.get('status') == 'collected' for c in (snap.get('coverage') or {}).get('sources', [])
                               if str(c.get('source', '')).startswith('transcripts.'))
    h = snap.get('harness_overhead') or {}
    series = h.get('skill_listing_series')
    sources = (h.get('injected_context') or {}).get('sources') or []
    top = sources[0] if sources else None
    signals = {
        'claude_md': claude_md or None,
        'cache_hit_ratio': None if ratio is None else {'value': ratio, 'complete': transcripts_complete},
        'broad_permissions': {'count': len(fps), 'fingerprints': sorted(fps)},
        'skill_listing_chars': None if not series else {'value': series['last']['chars'],
                                                        'complete': bool(h.get('complete'))},
        'injected_tokens': None if not top else {'value': top['est_tokens_per_session_median'],
                                                 'plugin': top['plugin'], 'hook_event': top['hook_event'],
                                                 'complete': bool(h.get('complete'))},
    }
    return signals, fps


def comparable(entries, meta, name):
    """The signal from the most recent entry with the same scope, project and window, if not null."""
    for e in reversed(entries):
        if all(e.get(k) == meta[k] for k in META_KEYS) and (e.get('signals') or {}).get(name) is not None:
            return e['signals'][name]
    return None


def compare(signals, fingerprint_paths, entries, meta, thresholds):
    crossings = []
    for path, v in sorted((signals['claude_md'] or {}).items()):
        if type(v.get('lines')) is int and v['lines'] > thresholds['claude_md_max_lines']:
            crossings.append({'signal': 'claude_md', 'kind': 'above_max', 'path': path, 'value': v['lines'],
                              'threshold': thresholds['claude_md_max_lines']})
    cache = signals['cache_hit_ratio']
    if cache and cache['value'] < thresholds['cache_hit_min']:
        crossings.append({'signal': 'cache_hit_ratio', 'kind': 'below_min', 'value': cache['value'],
                          'threshold': thresholds['cache_hit_min']})
    previous = comparable(entries, meta, 'broad_permissions')
    if previous is not None:
        new = sorted(set(signals['broad_permissions']['fingerprints']) - set(previous.get('fingerprints') or []))
        if new:
            crossings.append({'signal': 'broad_permissions', 'kind': 'new', 'fingerprints': new,
                              'paths': sorted({fingerprint_paths[f] for f in new if fingerprint_paths.get(f)})})
    for name in ('skill_listing_chars', 'injected_tokens'):
        current, previous = signals[name], comparable(entries, meta, name)
        if not current or not previous:
            continue
        if name == 'injected_tokens' and (current['plugin'], current['hook_event']) != (
                previous.get('plugin'), previous.get('hook_event')):
            continue
        before = previous.get('value')
        if type(before) not in (int, float) or before <= 0:
            continue
        fraction = (current['value'] - before) / before
        if fraction >= thresholds['growth_min']:
            crossings.append({'signal': name, 'kind': 'growth', 'value': current['value'], 'previous': before,
                              'fraction': round(fraction, 3), 'threshold': thresholds['growth_min']})
    return crossings
