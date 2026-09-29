#!/usr/bin/env python3
"""Opt-in, model-free drift check: collect, derive five signals, compare, append one log line.

Silent unless a threshold is crossed. Never installs a hook or schedule; see references/drift.md.
"""
import argparse
import hashlib
import os
import sys
from datetime import datetime, timezone
import collect
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
                                                 'attribution': top['attribution'],
                                                 'complete': bool(h.get('complete'))},
    }
    return signals, fps


def comparable(entries, meta, name, valid=None):
    """The signal from the most recent entry with the same scope, project and window, if a dict."""
    for e in reversed(entries):
        signals = e.get('signals')
        if all(e.get(k) == meta[k] for k in META_KEYS) and isinstance(signals, dict) \
                and isinstance(signals.get(name), dict) and (valid is None or valid(signals[name])):
            return signals[name]
    return None


def _number(x):
    return type(x) in (int, float)


def _identity(v):
    return v.get('plugin'), v.get('hook_event'), v.get('attribution')


def growth_anchor(entries, meta, name, current):
    """The reference value for growth and its `at`: the value at the last growth crossing of this
    signal, or else the earliest comparable run. For injected_tokens the walk stops at a run whose
    plugin, hook event or attribution differs (older entries lack attribution), so a change of the
    top source starts a new baseline. Only values above 0 can be a reference."""
    anchor = (None, None)
    for e in reversed(entries):
        signals = e.get('signals')
        if not all(e.get(k) == meta[k] for k in META_KEYS) or not isinstance(signals, dict) \
                or not isinstance(signals.get(name), dict):
            continue
        value = signals[name]
        if name == 'injected_tokens' and ('attribution' not in value or _identity(value) != _identity(current)):
            break
        if _number(value.get('value')) and value['value'] > 0:
            anchor = (value['value'], e.get('at'))
        crossings = e.get('crossings')
        if isinstance(crossings, list) and any(isinstance(c, dict) and c.get('signal') == name
                                               and c.get('kind') == 'growth' for c in crossings):
            break
    return anchor


def compare(signals, fingerprint_paths, entries, meta, thresholds):
    crossings = []
    for path, v in sorted((signals['claude_md'] or {}).items()):
        if type(v.get('lines')) is int and v['lines'] > thresholds['claude_md_max_lines']:
            crossings.append({'signal': 'claude_md', 'kind': 'above_max', 'path': path, 'value': v['lines'],
                              'threshold': thresholds['claude_md_max_lines']})
    cache = signals['cache_hit_ratio']
    if cache and _number(cache.get('value')) and cache['value'] < thresholds['cache_hit_min']:
        crossings.append({'signal': 'cache_hit_ratio', 'kind': 'below_min', 'value': cache['value'],
                          'threshold': thresholds['cache_hit_min']})
    previous = comparable(entries, meta, 'broad_permissions',
                          valid=lambda v: isinstance(v.get('fingerprints'), list))
    if previous is not None:
        before_fps = {f for f in previous['fingerprints'] if isinstance(f, str)}
        new = sorted(set(signals['broad_permissions']['fingerprints']) - before_fps)
        if new:
            crossings.append({'signal': 'broad_permissions', 'kind': 'new', 'fingerprints': new,
                              'paths': sorted({fingerprint_paths[f] for f in new if fingerprint_paths.get(f)})})
    for name in ('skill_listing_chars', 'injected_tokens'):
        current = signals[name]
        if not current or not _number(current.get('value')):
            continue
        before, since = growth_anchor(entries, meta, name, current)
        if before is None:
            continue
        fraction = (current['value'] - before) / before
        if fraction >= thresholds['growth_min']:
            crossings.append({'signal': name, 'kind': 'growth', 'value': current['value'], 'previous': before,
                              'since': since, 'fraction': round(fraction, 3), 'threshold': thresholds['growth_min']})
    return crossings


def summary_line(crossings, log_display):
    parts = []
    for c in crossings:
        if c['kind'] == 'above_max':
            parts.append(f"{c['path']} {c['value']} lines > {c['threshold']}")
        elif c['kind'] == 'below_min':
            parts.append(f"cache_hit_ratio {c['value']} < {c['threshold']}")
        elif c['kind'] == 'new':
            parts.append('new broad permission in ' + ', '.join(c['paths'] or ['an unknown settings file']))
        else:
            since = f" since {c['since'][:10]}" if isinstance(c.get('since'), str) else ''
            parts.append(f"{c['signal']} +{round(c['fraction'] * 100)}%{since} ({c['value']})")
    head = f'setup-audit drift: {len(crossings)} crossed ('
    prefix = '); log '
    # Keep the suffix by shortening the path itself (its tail identifies the file), leaving room for some detail.
    path_room = max(300 - len(head) - len(prefix) - 60, 3)
    if len(log_display) > path_room:
        log_display = '...' + log_display[len(log_display) - (path_room - 3):]
    tail = prefix + log_display
    middle = '; '.join(parts)
    room = 300 - len(head) - len(tail)
    if len(middle) > room:
        middle = middle[:max(room - 3, 0)] + '...'
    line = _one_line(head + middle + tail)
    return line if len(line) <= 300 else line[:297] + '...'


def _one_line(text):
    return text.replace('\r', '?').replace('\n', '?')


def home_relative(p, home):
    """p with a leading home directory shown as ~ (whole path components only)."""
    if p == home or p.startswith(home + os.sep):
        p = '~' + p[len(home):]
    return _one_line(p)


def _fraction(text, low, high, name):
    value = float(text)
    if not low < value <= high:
        raise argparse.ArgumentTypeError(f'{name} must be in ({low}, {high}]')
    return value


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    collect.add_collection_args(ap)
    ap.add_argument('--log', help='drift log (default: <claude dir>/audits/drift.jsonl)')
    ap.add_argument('--claude-md-max-lines', type=int, default=200)
    ap.add_argument('--cache-hit-min', type=lambda t: _fraction(t, 0, 1, '--cache-hit-min'), default=0.9)
    ap.add_argument('--growth-min', type=lambda t: _fraction(t, 0, 100, '--growth-min'), default=0.25)
    a = ap.parse_args(argv)
    if a.claude_md_max_lines < 1:
        ap.error('--claude-md-max-lines must be positive')
    collect.apply_collection_args(ap, a)
    audits = os.path.join(collect.CLAUDE, 'audits')
    allowed = collect._out_allowed_dirs()
    try:
        path = drift_log.check_path(a.log or os.path.join(audits, 'drift.jsonl'), allowed)
        entries, _ = drift_log.read(path)
    except drift_log.DriftLogError as e:
        print(f'setup-audit drift: {e}', file=sys.stderr)
        return 1
    try:
        snap = collect.build_snapshot(a)
    except Exception as e:  # never echo data from the failure
        print(f'setup-audit drift: collection failed ({type(e).__name__})', file=sys.stderr)
        return 1

    def display(p):
        return home_relative(p, collect.HOME)

    meta = {'scope': a.scope,
            'project': display(os.path.abspath(os.path.expanduser(a.project))) if a.project else None,
            'window_days': a.days}
    signals, fps = derive(snap, display(os.path.join(collect.CLAUDE, 'CLAUDE.md')))
    crossings = compare(signals, fps, entries, meta, {'claude_md_max_lines': a.claude_md_max_lines,
                                                      'cache_hit_min': a.cache_hit_min, 'growth_min': a.growth_min})
    entry = {'version': drift_log.VERSION, 'at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
             **meta, 'signals': signals, 'crossings': crossings}
    try:
        drift_log.append(path, entry, allowed, audits)
    except drift_log.DriftLogError as e:
        print(f'setup-audit drift: {e}', file=sys.stderr)
        return 1
    if crossings:
        print(summary_line(crossings, display(path)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
