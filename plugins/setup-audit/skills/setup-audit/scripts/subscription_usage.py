#!/usr/bin/env python3
"""Analysis of the opt-in rate-limit log (see rate_limit_log.py). Stdlib only, deterministic.

Findings are measured from the log, which only sees plan usage while Claude Code runs on this
machine: unused headroom is an upper bound. Thresholds are recommendations, not documented limits.
"""
import json
import math
import statistics
from datetime import datetime, timezone

import rate_limit_log

STALE_HOURS = {'five_hour': 1, 'seven_day': 24, 'spend_limit': 24}
MAX_RESETS_AT = 10 ** 11  # larger values are millisecond-shaped
EARLY_MIN_PREVIOUS_PCT = 10
EARLY_MIN_DROP = 10
BASIS_LOG = ('measured from the opt-in rate-limit log; it only records while Claude Code runs here, '
             'so unused headroom is an upper bound (usage on claude.ai or other devices also counts)')
BASIS_RESETS = ('inferred from the log; early resets are undocumented, and an account or plan switch '
                'or a log shared by several accounts looks the same')


def _num(v):
    return type(v) in (int, float) and math.isfinite(v)


def _epoch(at):
    try:
        return datetime.strptime(at, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _read_one(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        return [], 0
    except OSError:
        return [], 1
    entries, malformed = [], 0
    for raw in data.splitlines(keepends=True):
        if not raw.strip():
            continue
        if not raw.endswith(b'\n'):
            malformed += 1
            continue
        try:
            obj = json.loads(raw)
        except (ValueError, RecursionError):
            malformed += 1
            continue
        if not (isinstance(obj, dict) and obj.get('version') == rate_limit_log.VERSION
                and isinstance(obj.get('windows'), dict) and _epoch(obj.get('at')) is not None):
            malformed += 1
            continue
        windows = {}
        for kind in rate_limit_log.WINDOWS:
            w = obj['windows'].get(kind)
            if w is None:
                continue
            if (isinstance(w, dict) and _num(w.get('used_percentage')) and _num(w.get('resets_at'))
                    and 0 < w['resets_at'] <= MAX_RESETS_AT):
                windows[kind] = w
            else:
                malformed += 1
        if windows:
            entries.append({**obj, 'windows': windows})
    return entries, malformed


def read_log(path):
    """(entries sorted by time, malformed); reads path + '.1' then path; missing files are empty."""
    entries, malformed = [], 0
    for p in (path + '.1', path):
        e, m = _read_one(p)
        entries += e
        malformed += m
    entries.sort(key=lambda e: _epoch(e['at']))
    return entries, malformed


def _observations(entries):
    """Per kind: de-duplicated (at_epoch, pct, resets_at) tuples sorted by time."""
    obs = {}
    for e in entries:
        t = _epoch(e.get('at'))
        for kind, w in (e.get('windows') or {}).items():
            if t is not None and isinstance(w, dict):
                obs.setdefault(kind, set()).add((t, w['used_percentage'], w['resets_at']))
    return {k: sorted(v) for k, v in obs.items()}


def _dist(values):
    if not values:
        return None
    return {'min': round(min(values), 1), 'median': round(statistics.median(values), 1),
            'max': round(max(values), 1)}


def analyze_windows(entries, now):
    """Per window kind present: counts, peak and unused distributions; `now` is epoch seconds."""
    result = {}
    for kind, obs in _observations(entries).items():
        groups = {}
        for o in obs:
            groups.setdefault(o[2], []).append(o)
        closed = stale = reached_85 = reached_100 = 0
        peaks, unused, leads, open_last = [], [], [], []
        for resets_at, group in groups.items():
            if resets_at >= now:
                open_last.append(group[-1])
                continue
            closed += 1
            peak = max(o[1] for o in group)
            reached_85 += peak >= 85
            reached_100 += peak >= 100
            lead = resets_at - group[-1][0]
            if lead > STALE_HOURS[kind] * 3600:
                stale += 1
                continue
            peaks.append(peak)
            unused.append(max(0, 100 - group[-1][1]))
            leads.append(lead / 3600)
        current = None
        if open_last:
            last = max(open_last)
            current = {'used_percentage': last[1], 'resets_at': last[2]}
        result[kind] = {
            'windows': len(groups), 'closed': closed, 'stale_excluded': stale,
            'peak_used_pct': _dist(peaks), 'unused_at_close_pct': _dist(unused),
            'median_lead_hours': round(statistics.median(leads), 1) if leads else None,
            'reached_85': reached_85, 'reached_100': reached_100, 'current': current,
        }
    return result


def early_resets(entries):
    """Events where a later resets_at appears before the previous window's reset and usage dropped."""
    events = []
    for kind, obs in _observations(entries).items():
        for prev, new in zip(obs, obs[1:]):
            if (new[2] > prev[2] and new[0] < prev[2] and prev[1] >= EARLY_MIN_PREVIOUS_PCT
                    and prev[1] - new[1] >= EARLY_MIN_DROP):
                events.append({
                    'window': kind,
                    'at': datetime.fromtimestamp(new[0], timezone.utc).strftime('%Y-%m-%d'),
                    'previous_pct': prev[1], 'new_pct': new[1],
                    'previous_resets_at': prev[2], 'new_resets_at': new[2],
                })
    return events
