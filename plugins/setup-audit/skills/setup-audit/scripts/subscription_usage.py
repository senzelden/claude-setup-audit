#!/usr/bin/env python3
"""Analysis of the opt-in rate-limit log (see rate_limit_log.py). Stdlib only, deterministic.

Findings are measured from the log, which only sees plan usage while Claude Code runs on this
machine: unused headroom is an upper bound. Thresholds are recommendations, not documented limits.
"""
import json
import math
import re
import statistics
from datetime import datetime, timezone

import rate_limit_log

STALE_HOURS = {'five_hour': 1, 'seven_day': 24, 'spend_limit': 24}
MAX_RESETS_AT = 10 ** 11  # larger values are millisecond-shaped
EARLY_MIN_PREVIOUS_PCT = 10
EARLY_MIN_DROP = 10
EARLY_SKEW_SECONDS = 60  # an entry this close to the previous reset may be clock skew, not an early reset
BASIS_LOG = ('measured from the opt-in rate-limit log; unused at close is 100 minus the window\'s peak '
             'logged value; the log only records while Claude Code runs here, so unused headroom is an '
             'upper bound (usage on claude.ai or other devices also counts)')
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
            unused.append(max(0, 100 - peak))  # a later, lower value (a duplicate or stale writer) never adds
            leads.append(lead / 3600)
        current = None
        if open_last:
            last = max(open_last)
            current = {'used_percentage': last[1], 'resets_at': last[2]}
        result[kind] = {
            'windows': len(groups), 'closed': closed, 'stale_excluded': stale, 'counted': closed - stale,
            'peak_used_pct': _dist(peaks), 'unused_at_close_pct': _dist(unused),
            'median_lead_hours': round(statistics.median(leads), 1) if leads else None,
            'reached_85': reached_85, 'reached_100': reached_100, 'current': current,
        }
    return result


def early_resets(entries):
    """Events where a later resets_at appears before the previous window's reset and usage dropped.

    One event per (window, new resets_at), the first: sessions writing old and new values in turn
    repeat the transition. The entry must precede the previous reset by more than EARLY_SKEW_SECONDS.
    """
    events, seen = [], set()
    for kind, obs in _observations(entries).items():
        for prev, new in zip(obs, obs[1:]):
            if (new[2] > prev[2] and new[0] < prev[2] - EARLY_SKEW_SECONDS
                    and prev[1] >= EARLY_MIN_PREVIOUS_PCT and prev[1] - new[1] >= EARLY_MIN_DROP
                    and (kind, new[2]) not in seen):
                seen.add((kind, new[2]))
                events.append({
                    'window': kind,
                    'at': datetime.fromtimestamp(new[0], timezone.utc).strftime('%Y-%m-%d'),
                    'previous_pct': prev[1], 'new_pct': new[1],
                    'previous_resets_at': prev[2], 'new_resets_at': new[2],
                })
    return events


# --- transcript evidence: documented limit messages, model families, extra-usage settings ---------
# Message texts: errors.md "Usage limits" and interactive-mode.md "Wait for a usage limit to reset",
# fetched 2026-10-26. The record wrapper of a limit message is unverified (coverage.md), so matching
# is anchored at the start of the text of a synthetic/API-error assistant record or a system record:
# quoted strings in ordinary assistant text, user text or tool results never count.
LIMIT_KINDS = ('session', 'weekly', 'opus', 'sonnet', 'warning_85', 'auto_continue_wait', 'spend_limit',
               'credits_required_1m', 'fable_consent_unanswered')
_A = "['\u2019]"  # straight or curly apostrophe
_LIMIT_PATTERNS = tuple((kind, re.compile(rx)) for kind, rx in (
    ('session', f'You{_A}ve hit your session limit'),
    ('weekly', f'You{_A}ve hit your weekly limit'),
    ('opus', f'You{_A}ve hit your Opus limit'),
    ('sonnet', f'You{_A}ve hit your Sonnet limit'),
    ('warning_85', f'You{_A}ve used \\d+(?:\\.\\d+)?% of your'),
    ('auto_continue_wait', 'Usage limit reached \u00b7 continuing automatically'),
    ('spend_limit', f'You{_A}ve hit your (?:monthly spend limit|individual spend limit|org{_A}s monthly spend limit'
                    f'|channel{_A}s monthly spend limit|team{_A}s shared budget|individual usage limit)'),
    ('credits_required_1m', 'Usage credits required for 1M context'),
    ('fable_consent_unanswered', 'Fable\\b[^\\n]*the prompt to confirm went unanswered'),
))
API_ERROR_PREFIX = 'API Error: '
EXTRA_USAGE_KINDS = ('spend_limit', 'credits_required_1m', 'fable_consent_unanswered')
EXTRA_USAGE_KEYS = ('autoContinueAtUsageLimit', 'fastMode', 'fastModePerSessionOptIn')  # settings-reference
NOT_OBSERVABLE = ['plan tier', 'usage-credit balance and limit', 'available limit resets']
FAMILIES = ('opus', 'sonnet', 'haiku', 'fable', 'other')
BASIS_LIMITS = ('documented limit-message text (errors, interactive-mode; fetched 2026-10-26) at the start of '
                'a synthetic or API-error assistant record or a system record; the wrapper is observed, '
                'undocumented and unverified for limit messages, so other wrappers are missed (an under-count). '
                'In-window records of the user\'s own sessions (main and subagent files; plugin-spawned '
                'sessions excluded), deduplicated by project, sessionId and record uuid. Only the kind, '
                'session and UTC date are read; the text is never stored.')
BASIS_MODEL_MIX = ('requests per model family from the api-request counters of transcripts.request_params '
                   '(observed, undocumented; full counters, not the capped rows); family by substring of the '
                   'model id. Session and weekly limits are shared across models, Opus and Sonnet limits '
                   'apply per family (errors, fetched 2026-10-26).')


def classify_limit_text(text):
    """Documented limit-message kind when `text` starts with a documented prefix, else None."""
    if not isinstance(text, str):
        return None
    text = text.lstrip()
    if text.startswith(API_ERROR_PREFIX):
        text = text[len(API_ERROR_PREFIX):]
    for kind, rx in _LIMIT_PATTERNS:
        if rx.match(text):
            return kind
    return None


def is_limit_record(record):
    """A record whose text may be a limit message: synthetic or API-error assistant, or system."""
    kind = record.get('type')
    if kind == 'system':
        return True
    if kind != 'assistant':
        return False
    if record.get('isApiErrorMessage') is True:
        return True
    msg = record.get('message')
    return isinstance(msg, dict) and msg.get('model') == '<synthetic>'


def record_texts(record):
    """Text strings of a record: top-level `content` and `message.content` (a string or text blocks)."""
    msg = record.get('message') if isinstance(record.get('message'), dict) else {}
    for content in (record.get('content'), msg.get('content')):
        if isinstance(content, str):
            yield content
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get('type') == 'text' and isinstance(block.get('text'), str):
                    yield block['text']


def record_limit_kinds(record):
    """Sorted documented kinds found in one record (empty unless is_limit_record)."""
    if not is_limit_record(record):
        return []
    return sorted({k for k in map(classify_limit_text, record_texts(record)) if k is not None},
                  key=LIMIT_KINDS.index)


def model_family(model):
    if not isinstance(model, str):
        return 'other'
    low = model.lower()
    return next((f for f in FAMILIES[:-1] if f in low), 'other')


def limit_events(hits):
    """hits: (kind, session key, UTC date, is_subagent) tuples -> snapshot `limit_events`."""
    out = {}
    for kind in LIMIT_KINDS:
        rows = [h for h in hits if h[0] == kind]
        if rows:
            dates = sorted(h[2] for h in rows)
            out[kind] = {'count': len(rows), 'sessions': len({h[1] for h in rows}), 'first_date': dates[0],
                         'last_date': dates[-1], 'subagent_count': sum(1 for h in rows if h[3])}
    out['basis'] = BASIS_LIMITS
    return out


def model_mix(model_counters):
    """{'main'|'agent': Counter(model -> requests)} -> requests and share per family (share null at 0)."""
    out = {}
    for cls in ('main', 'agent'):
        fam = dict.fromkeys(FAMILIES, 0)
        for model, n in model_counters.get(cls, {}).items():
            fam[model_family(model)] += n
        total = sum(fam.values())
        out[cls] = {f: {'requests': n, 'share': round(n / total, 3) if total else None} for f, n in fam.items()}
    out['basis'] = BASIS_MODEL_MIX
    return out


def extra_usage(settings_summaries, events):
    """Documented extra-usage keys in collected settings (value, or "invalid" when not boolean),
    named `setting`: a field called `key` holding a long camelCase name trips contextual redaction.
    spend/credit message counts from `limit_events`, and what is not observable locally."""
    rows = []
    for s in settings_summaries:
        other = s.get('other') if isinstance(s.get('other'), dict) else {}
        for key in EXTRA_USAGE_KEYS:
            if key in other:
                value = other[key]
                rows.append({'path': s.get('path'), 'setting': key, 'value': value if isinstance(value, bool) else 'invalid'})
    return {'settings': rows,
            'messages': {k: events.get(k, {}).get('count', 0) for k in EXTRA_USAGE_KINDS},
            'not_observable': list(NOT_OBSERVABLE)}
