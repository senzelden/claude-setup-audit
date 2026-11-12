"""Outcome metrics for report-only ledger entries: a fixed catalog computed from snapshot fields.

Each metric is read from fields the collector already writes, by one fixed rule, so two audits
produce comparable values and the model never supplies a value. Names, labels, sources and the
finding checks each metric may measure are documented in references/ledger.md. Stdlib only.
"""
import math
from datetime import datetime, timezone

# kind 'window': the value covers the snapshot's window_days ending at collection time.
# kind 'point': the value is the state at collection time (window from == to).
CATALOG = {
    'context_baseline_tokens_median': dict(
        basis='measured', unit='tokens', source='transcripts.context_baseline_tokens.median', kind='window'),
    'cache_write_share': dict(
        basis='measured', unit='ratio', source='transcripts.cache.write_tokens', kind='window'),
    'allow_rule_count': dict(
        basis='measured', unit='rules', source='settings.permissions.allow_count', kind='point'),
    'risky_allow_rule_count': dict(
        basis='measured', unit='rules', source='settings.permissions.risky', kind='point'),
}

# Finding checks eligible for an outcome entry, and the metrics a fix for each can plausibly move
# (reasons per check: references/ledger.md, "Outcome metrics"). The fix itself may come from
# apply_ops.py, prune_permissions.py or a backed-up Edit in SKILL.md's apply flow.
CONTEXT, CACHE = ('context_baseline_tokens_median',), ('cache_write_share',)
CHECKS = {
    'SEC-risky-allow': ('risky_allow_rule_count', 'allow_rule_count'),
    'SEC-secret-literal': ('risky_allow_rule_count', 'allow_rule_count'),
    'SEC-secret-env': ('risky_allow_rule_count', 'allow_rule_count'),
    'COST-baseline': CONTEXT,
    'COST-claude-md-size': CONTEXT,
    'COST-mcp-unused': CONTEXT,
    'COST-skill-listing': CONTEXT,
    'COST-startup-hooks': CONTEXT,
    'COST-harness-overhead': CONTEXT,
    'COST-cache-health': CACHE,
}
FAMILIES = ('SEC-', 'COST-')
RISKY_CAP = 6  # collect.analyze_permissions keeps at most 6 rules per risky flag and file
LABELS = ('basis', 'unit', 'source')


def catalog_row(selector):
    """The catalog row a metric selector names with its exact labels, else None."""
    if not isinstance(selector, dict) or selector.get('type') != 'metric':
        return None
    row = CATALOG.get(selector.get('name'))
    if row is None or set(selector) != {'type', 'name', *LABELS}:
        return None
    return row if all(selector[k] == row[k] for k in LABELS) else None


def selector_for(name):
    row = CATALOG[name]
    return dict(type='metric', name=name, **{k: row[k] for k in LABELS})


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def collected_at(snapshot):
    """Collection time (epoch seconds) from `generated_utc`, or None. The legacy `generated` field is
    local wall time without an offset, so it cannot be compared with a ledger's UTC `applied_at`."""
    text = snapshot.get('generated_utc') if isinstance(snapshot, dict) else None
    try:
        return datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).timestamp()
    except (TypeError, ValueError):
        return None


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def _family_complete(snapshot, family):
    sources = (snapshot.get('coverage') or {}).get('sources')
    rows = [s for s in sources if isinstance(s, dict) and str(s.get('source', '')).startswith(family + '.')] \
        if isinstance(sources, list) else []
    return bool(rows) and all(s.get('status') == 'collected' and not s.get('omitted') for s in rows)


def _settings(snapshot):
    """Every user and project settings summary, once per path (managed files are never edited)."""
    found = list((snapshot.get('global') or {}).get('settings') or [])
    for entry in (snapshot.get('projects') or {}).values():
        found.extend(entry.get('settings') or [])
    seen = {}
    for item in found:
        seen.setdefault(item['path'], item)
    return list(seen.values())


def _value(name, snapshot):
    """(value, complete) for one catalog metric; raises on malformed snapshot shapes."""
    transcripts = snapshot.get('transcripts') or {}
    if name == 'context_baseline_tokens_median':
        value = (transcripts.get('context_baseline_tokens') or {}).get('median')
        return value, _family_complete(snapshot, 'transcripts')
    if name == 'cache_write_share':
        cache = transcripts.get('cache') or {}
        read, write = cache.get('read_tokens'), cache.get('write_tokens')
        ok = type(read) is int and type(write) is int and read >= 0 and write >= 0
        value = round(write / (read + write), 3) if ok and read + write else None
        return value, _family_complete(snapshot, 'transcripts')
    settings = _settings(snapshot)
    if name == 'allow_rule_count':
        counts = [(s.get('permissions') or {}).get('allow_count') for s in settings]
        complete = all(type(c) is int and c >= 0 for c in counts)
        return (sum(counts) if complete else None), complete
    rules, capped = set(), False
    for s in settings:
        for flagged in ((s.get('permissions') or {}).get('risky') or {}).values():
            if not isinstance(flagged, list):
                raise TypeError('risky rules must be a list')
            capped = capped or len(flagged) >= RISKY_CAP
            rules.update((s['path'], rule) for rule in flagged)
    # Metadata-only snapshots replace rule text with a length marker, so distinct rules can merge.
    masked = ((snapshot.get('coverage') or {}).get('privacy') or {}).get('mode') == 'metadata-only'
    return len(rules), not (capped or masked)


def compute(selector, snapshot):
    """{from, to, value, complete} for a catalog metric selector, or None when the selector is not a
    catalog metric or the snapshot has no usable collection time or window. Never raises."""
    row = catalog_row(selector)
    at = collected_at(snapshot)
    if row is None or at is None:
        return None
    try:
        days = snapshot['window_days']
        if type(days) is not int or days < 1:
            return None
        start = at if row['kind'] == 'point' else at - days * 86400
        value, complete = _value(selector['name'], snapshot)
        return {'from': iso(start), 'to': iso(at), 'value': value if _finite(value) else None,
                'complete': bool(complete)}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError, OSError):
        return None
