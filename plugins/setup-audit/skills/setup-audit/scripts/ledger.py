#!/usr/bin/env python3
"""Per-item learning ledger: strict format, verdicts, and the next-id/record/remove CLI.

The ledger is the plugin's own file. It holds counts, hashes, paths and ids, never prompt text
or configuration values. Every path is explicit; nothing is searched for. Stdlib only.
"""
import argparse
import copy
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import report_state  # noqa: E402
import safe_write  # noqa: E402

VERSION = 1
MECHANISMS = ('memory', 'rule', 'hook', 'skill', 'setting')
LADDER = ('memory', 'rule', 'hook', 'skill')
STATES = ('active', 'removed', 'superseded')
SOURCES = ('corrections', 'friction_details')
KINDS = ('markdown_block', 'hook_script', 'json_array_append', 'json_set')
SCOPES = ('global', 'project', 'all')
ID_RE = re.compile(r'L-\d{8}-\d{1,4}\Z')
INDEX_RE = re.compile(r'(0|[1-9][0-9]*)\Z')
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')
MIN_SESSIONS, MIN_BASELINE, QUIET_DAYS = 5, 3, 30
ENTRY_FIELDS = {'id', 'applied_at', 'run', 'finding_id', 'pattern', 'mechanism', 'state',
                'supersedes', 'selector', 'scope', 'baseline', 'edits', 'observations'}
COUNT_FIELDS = {'from', 'to', 'matches', 'sessions_matched', 'sessions_scanned', 'complete'}
METRIC_FIELDS = {'from', 'to', 'value', 'complete'}
OBSERVATION_EXTRA = {'run', 'verdict', 'reason'}


class LedgerError(report_state.ReportError):
    """Constant-text validation failure; `input` names the file role, never its content."""

    def __init__(self, message, input='ledger', line=None):
        super().__init__(message, input=input, line=line)


def require(condition, message, input='ledger'):
    if not condition:
        raise LedgerError(message, input=input)


def empty():
    return {'version': VERSION, 'entries': []}


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def epoch(text):
    try:
        return report_state.timestamp(text).timestamp()
    except (report_state.ReportError, ValueError, TypeError, AttributeError):
        raise LedgerError('invalid timestamp') from None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def fingerprint(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def selector_hash(selector):
    return fingerprint(selector)


def _text(value, limit):
    return isinstance(value, str) and 0 < len(value.strip()) and len(value) <= limit


def _count(value):
    return type(value) is int and value >= 0


def validate_selector(selector):
    require(isinstance(selector, dict), 'invalid selector')
    kind = selector.get('type')
    if kind == 'keywords':
        require(set(selector) == {'type', 'source', 'any'}, 'invalid selector fields')
        require(selector['source'] in SOURCES, 'invalid selector source')
        words = selector['any']
        require(isinstance(words, list) and 1 <= len(words) <= 5, 'selector needs 1 to 5 keywords')
        require(all(_text(w, 40) for w in words), 'keywords must be 1 to 40 characters')
    elif kind == 'friction_category':
        require(set(selector) == {'type', 'name'} and _text(selector['name'], 60), 'invalid selector fields')
    elif kind == 'metric':
        require(set(selector) == {'type', 'name', 'basis', 'unit', 'source'}, 'invalid selector fields')
        require(all(_text(selector[k], 120) for k in ('name', 'basis', 'unit', 'source')), 'invalid selector fields')
    else:
        raise LedgerError('invalid selector type')


def validate_counts(counts, metric, extra=frozenset()):
    require(isinstance(counts, dict), 'invalid counts')
    require(set(counts) == (METRIC_FIELDS if metric else COUNT_FIELDS) | set(extra), 'invalid count fields')
    epoch(counts['from'])
    epoch(counts['to'])
    require(type(counts['complete']) is bool, 'invalid completeness flag')
    if metric:
        require(counts['value'] is None or report_state.finite(counts['value']), 'invalid metric value')
    else:
        require(all(_count(counts[k]) for k in ('matches', 'sessions_matched', 'sessions_scanned')),
                'counts must be non-negative integers')
        require(counts['sessions_matched'] <= counts['sessions_scanned'], 'matched sessions exceed scanned')
        require(counts['sessions_matched'] <= counts['matches'], 'matched sessions exceed matches')


def validate_edit(edit):
    require(isinstance(edit, dict) and edit.get('kind') in KINDS, 'invalid edit kind')
    fields = {'file', 'kind', 'sha256', 'backup'} | ({'pointer'} if edit['kind'].startswith('json_') else set())
    require(set(edit) == fields, 'invalid edit fields')
    require(_text(edit['file'], 4096), 'invalid edit file')
    require(edit['backup'] is None or _text(edit['backup'], 4096), 'invalid edit backup')
    require(isinstance(edit['sha256'], str) and SHA_RE.match(edit['sha256']), 'invalid edit fingerprint')
    if 'pointer' in edit:
        require(isinstance(edit['pointer'], str) and edit['pointer'].startswith('/'), 'invalid JSON pointer')


def validate_scope(scope):
    require(isinstance(scope, dict) and set(scope) == {'scope', 'project', 'window_days'}, 'invalid scope')
    require(scope['scope'] in SCOPES, 'invalid scope')
    require(scope['project'] is None or _text(scope['project'], 4096), 'invalid scope project')
    require(type(scope['window_days']) is int and scope['window_days'] > 0, 'invalid window')


def validate_entry(item):
    require(isinstance(item, dict) and set(item) == ENTRY_FIELDS, 'invalid entry fields')
    require(isinstance(item['id'], str) and ID_RE.match(item['id']), 'invalid entry id')
    epoch(item['applied_at'])
    require(_text(item['run'], 120), 'invalid run')
    require(_text(item['finding_id'], 200), 'invalid finding id')
    require(_text(item['pattern'], 200), 'invalid pattern')
    require(item['mechanism'] in MECHANISMS, 'invalid mechanism')
    require(item['state'] in STATES, 'invalid state')
    require(item['supersedes'] is None or (isinstance(item['supersedes'], str) and ID_RE.match(item['supersedes'])),
            'invalid supersedes')
    validate_selector(item['selector'])
    validate_scope(item['scope'])
    metric = item['selector']['type'] == 'metric'
    validate_counts(item['baseline'], metric)
    require(isinstance(item['edits'], list) and item['edits'], 'entry needs edits')
    for edit in item['edits']:
        validate_edit(edit)
    require(isinstance(item['observations'], list), 'invalid observations')
    for obs in item['observations']:
        validate_counts(obs, metric, OBSERVATION_EXTRA)
        require(_text(obs['run'], 120) and obs['verdict'] in report_state.LEDGER_VERDICTS
                and _text(obs['reason'], 60), 'invalid observation')


def validate(book):
    require(isinstance(book, dict) and set(book) == {'version', 'entries'}, 'invalid ledger fields')
    require(book['version'] == VERSION, 'unsupported ledger version')
    require(isinstance(book['entries'], list), 'invalid ledger entries')
    seen = set()
    for item in book['entries']:
        validate_entry(item)
        require(item['id'] not in seen, 'duplicate entry id')
        seen.add(item['id'])
    return book


def loads(text, input='ledger'):
    try:
        return validate(report_state.load_json(text))
    except LedgerError as exc:
        exc.input = input
        raise
    except report_state.ReportError as exc:
        raise LedgerError(exc.message, input=input, line=exc.line) from None
    except (ValueError, RecursionError):
        raise LedgerError('invalid JSON', input=input) from None


def load(path):
    require(not os.path.islink(path), 'ledger must not be a symlink')
    if not os.path.exists(path):
        return empty()
    try:
        with open(path, encoding='utf-8') as stream:
            text = stream.read(8 * 1024 * 1024 + 1)
    except (UnicodeDecodeError, OSError):
        raise LedgerError('ledger cannot be read') from None
    require(len(text) <= 8 * 1024 * 1024, 'ledger too large')
    return loads(text)


def dump(book, path):
    validate(book)
    require(not os.path.islink(path), 'ledger must not be a symlink')
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    text = json.dumps(book, indent=2, ensure_ascii=True, allow_nan=False) + '\n'
    safe_write.atomic_write(path, text, prefix='.ledger.')
    os.chmod(path, 0o600)


def next_id(book, day):
    stem = 'L-%s-' % day.strftime('%Y%m%d')
    used = [int(e['id'][len(stem):]) for e in book['entries'] if e['id'].startswith(stem)]
    return stem + str(max(used, default=0) + 1)


def _rate(counts):
    return counts['sessions_matched'] / counts['sessions_scanned']


def verdict(entry, current, scope, previous):
    """Classify one entry for this run. `current` carries `selector_sha`; `previous` is the latest
    observation from another run (or None). Returns (verdict, reason code)."""
    if (current is None or scope != entry['scope']
            or current.get('selector_sha') != selector_hash(entry['selector'])):
        return 'unknown', 'incomparable'
    base = entry['baseline']
    if not (base['complete'] and current['complete']):
        return 'unknown', 'incomplete'
    if entry['selector']['type'] == 'metric':
        if epoch(current['from']) < epoch(entry['applied_at']):
            return 'too_early', 'window_overlaps_fix'
        if base['value'] is None or current['value'] is None:
            return 'unknown', 'incomparable'
        if current['value'] <= 0.5 * base['value']:
            return 'dropped', 'rate_at_or_below_half'
        return 'not_dropped', 'rate_above_half'
    if base['sessions_scanned'] == 0:
        return 'unknown', 'no_baseline'
    if base['sessions_matched'] < MIN_BASELINE:
        return 'too_early', 'weak_baseline'
    if current['sessions_scanned'] < MIN_SESSIONS:
        return 'too_early', 'few_sessions'
    days = (epoch(current['to']) - epoch(entry['applied_at'])) / 86400
    if (current['matches'] == 0 and previous is not None and previous.get('matches') == 0
            and previous['verdict'] not in ('unknown', 'too_early') and days >= QUIET_DAYS):
        return 'quiet', 'quiet'
    if _rate(current) <= 0.5 * _rate(base):
        return 'dropped', 'rate_at_or_below_half'
    return 'not_dropped', 'rate_above_half'


def next_rung(entry):
    if entry['mechanism'] not in LADDER[:-1]:
        return None
    return LADDER[LADDER.index(entry['mechanism']) + 1]


def proposal(entry, verdict_now, previous):
    if verdict_now == 'quiet' and entry['mechanism'] in ('memory', 'rule'):
        return 'retire'
    if (verdict_now == 'not_dropped' and previous is not None and previous['verdict'] == 'not_dropped'
            and next_rung(entry) is not None):
        return 'escalate'
    return None


SPEC_FIELDS = {'id', 'finding_id', 'pattern', 'mechanism', 'selector', 'edits'}
LABELS = {'ledger': 'ledger', 'snapshot': 'snapshot', 'report': 'current report',
          'spec': 'entry spec', 'edited file': 'edited file', 'backup': 'backup'}


def begin_marker(entry_id):
    return '<!-- setup-audit:begin %s -->' % entry_id


def end_marker(entry_id):
    return '<!-- setup-audit:end %s -->' % entry_id


def hook_marker(entry_id):
    return '# setup-audit: %s' % entry_id


def find_block(text, entry_id):
    lines = text.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.strip() == begin_marker(entry_id)]
    ends = [i for i, line in enumerate(lines) if line.strip() == end_marker(entry_id)]
    if not begins and not ends:
        return None
    require(len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0], 'markers are ambiguous',
            input='edited file')
    return begins[0], ends[0]


def block_hash(text, entry_id):
    span = find_block(text, entry_id)
    require(span is not None, 'markers not found', input='edited file')
    lines = text.splitlines(keepends=True)
    return hashlib.sha256(''.join(lines[span[0] + 1:span[1]]).encode()).hexdigest()


def pointer_parts(pointer):
    require(isinstance(pointer, str) and pointer.startswith('/'), 'invalid JSON pointer', input='spec')
    return [p.replace('~1', '/').replace('~0', '~') for p in pointer[1:].split('/')]


def pointer_text(parts):
    return '/' + '/'.join(p.replace('~', '~0').replace('/', '~1') for p in parts)


def resolve(doc, parts):
    node = doc
    for part in parts:
        if isinstance(node, list):
            require(INDEX_RE.match(part) and int(part) < len(node), 'JSON pointer not found', input='edited file')
            node = node[int(part)]
        else:
            require(isinstance(node, dict) and part in node, 'JSON pointer not found', input='edited file')
            node = node[part]
    return node


def read_text(path, input='edited file'):
    require(not os.path.islink(path), 'symlinks are refused', input=input)
    try:
        with open(path, 'rb') as stream:
            data = stream.read(8 * 1024 * 1024 + 1)
    except OSError:
        raise LedgerError('cannot be read', input=input) from None
    require(len(data) <= 8 * 1024 * 1024, 'file too large', input=input)
    return data


def read_json(path, input='edited file'):
    try:
        return report_state.load_json(read_text(path, input).decode('utf-8'))
    except (report_state.ReportError, UnicodeDecodeError, RecursionError) as exc:
        raise LedgerError('invalid JSON', input=input, line=getattr(exc, 'line', None)) from None


def tilde(path, home):
    return '~' + path[len(home):] if path == home or path.startswith(home + os.sep) else path


def fingerprint_edit(entry_id, edit, home):
    require(isinstance(edit, dict) and edit.get('kind') in KINDS, 'invalid edit kind', input='spec')
    json_kind = edit['kind'].startswith('json_')
    require(set(edit) == {'file', 'kind', 'backup'} | ({'pointer'} if json_kind else set()),
            'invalid edit fields', input='spec')
    require(_text(edit['file'], 4096), 'invalid edit file', input='spec')
    require(edit['backup'] is None or _text(edit['backup'], 4096), 'invalid edit backup', input='spec')
    path = os.path.abspath(os.path.expanduser(edit['file']))
    if edit['backup'] is not None:
        require(os.path.exists(os.path.expanduser(edit['backup'])), 'backup not found', input='backup')
    out = dict(file=tilde(path, home), kind=edit['kind'],
               backup=None if edit['backup'] is None else tilde(os.path.abspath(os.path.expanduser(edit['backup'])), home))
    if edit['kind'] == 'markdown_block':
        out['sha256'] = block_hash(read_text(path).decode('utf-8', 'replace'), entry_id)
    elif edit['kind'] == 'hook_script':
        data = read_text(path)
        marks = [line.strip() == hook_marker(entry_id) for line in data.decode('utf-8', 'replace').splitlines()]
        require(sum(marks) == 1 and any(marks[:5]), 'hook marker not found or ambiguous', input='edited file')
        out['sha256'] = hashlib.sha256(data).hexdigest()
    else:
        parts = pointer_parts(edit['pointer'])
        doc = read_json(path)
        if edit['kind'] == 'json_array_append':
            require(INDEX_RE.match(parts[-1]), 'pointer must name the appended element', input='spec')
        value = resolve(doc, parts)
        if edit['kind'] == 'json_array_append':
            require(isinstance(resolve(doc, parts[:-1]), list), 'pointer parent must be an array',
                    input='edited file')
            parts = parts[:-1]
        out['pointer'] = pointer_text(parts)
        out['sha256'] = fingerprint(value)
    return out


def snapshot_scope(snapshot):
    require(isinstance(snapshot, dict) and isinstance(snapshot.get('collection_scope'), dict),
            'snapshot scope is missing', input='snapshot')
    cs = snapshot['collection_scope']
    try:
        scope = dict(scope=cs['requested'], project=cs.get('project'), window_days=snapshot['window_days'])
        validate_scope(scope)
        require((scope['scope'] == 'project') == (scope['project'] is not None), 'invalid scope')
    except (KeyError, LedgerError):
        raise LedgerError('snapshot scope is missing', input='snapshot') from None
    if scope['scope'] == 'all':
        return scope, None
    if scope['scope'] == 'global':
        return scope, set()
    return scope, {os.path.abspath(os.path.expanduser(scope['project']))}


def metric_baseline(selector, report, start, end):
    metrics = report.get('metrics', {})
    require(isinstance(metrics, dict), 'invalid metrics', input='report')
    metric = metrics.get(selector['name'])
    labels = all(isinstance(metric, dict) and metric.get(k) == selector[k] for k in ('basis', 'unit', 'source'))
    value = metric.get('value') if labels else None
    complete = False
    if labels:
        coverage = report.get('coverage', {})
        sources = coverage.get('sources', []) if isinstance(coverage, dict) else None
        require(isinstance(sources, list) and all(isinstance(s, dict) and isinstance(s.get('source'), str)
                                                  for s in sources), 'invalid coverage', input='report')
        complete = bool(report_state.metric_coverage(report, metric))
    return {'from': iso(start), 'to': iso(end),
            'value': value if report_state.finite(value) else None, 'complete': complete}


def record(book, spec, snapshot, report, run, now):
    import collect  # lazy: collect imports ledger lazily too
    book = copy.deepcopy(validate(book))
    require(isinstance(spec, dict) and SPEC_FIELDS <= set(spec) <= SPEC_FIELDS | {'supersedes'},
            'invalid spec fields', input='spec')
    try:
        report_state.validate_report(report)
    except report_state.ReportError as exc:
        raise LedgerError(exc.message, input='report', line=exc.line) from None
    require(isinstance(report, dict) and isinstance(report.get('findings', []), list)
            and all(isinstance(f, dict) for f in report.get('findings', [])), 'invalid findings', input='report')
    require(isinstance(spec['id'], str) and ID_RE.match(spec['id']), 'invalid entry id', input='spec')
    ids = {e['id']: e for e in book['entries']}
    require(spec['id'] not in ids, 'entry id already used', input='spec')
    findings = {f.get('id') for f in report.get('findings', []) if isinstance(f.get('id'), str)}
    require(isinstance(spec['finding_id'], str) and spec['finding_id'] in findings,
            'finding not in current report', input='spec')
    supersedes = spec.get('supersedes')
    if supersedes is not None:
        require(isinstance(supersedes, str) and supersedes in ids and ids[supersedes]['state'] == 'active',
                'superseded entry not active', input='spec')
    require(_text(spec['pattern'], 200), 'invalid pattern', input='spec')
    try:
        validate_selector(spec['selector'])
    except LedgerError as exc:
        exc.input = 'spec'
        raise
    require(spec['mechanism'] in MECHANISMS, 'invalid mechanism', input='spec')
    require(isinstance(spec['edits'], list) and spec['edits'], 'entry needs edits', input='spec')
    selector = copy.deepcopy(spec['selector'])
    if selector['type'] == 'keywords':
        selector['any'] = [collect.redact(w) for w in selector['any']]
    scope, project_filter = snapshot_scope(snapshot)
    start = now - scope['window_days'] * 86400
    if selector['type'] == 'metric':
        baseline = metric_baseline(selector, report, start, now)
    else:
        baseline = collect.count_selector(selector, start, now, project_filter)
        baseline.update({'from': iso(start), 'to': iso(now)})
    entry = dict(id=spec['id'], applied_at=iso(now), run=run, finding_id=spec['finding_id'],
                 pattern=collect.redact(spec['pattern'])[:200], mechanism=spec['mechanism'], state='active',
                 supersedes=supersedes, selector=selector, scope=scope, baseline=baseline,
                 edits=[fingerprint_edit(spec['id'], e, collect.HOME) for e in spec['edits']], observations=[])
    if supersedes is not None:
        ids[supersedes]['state'] = 'superseded'
    book['entries'].append(entry)
    return validate(book)


ORDER = {'json_array_append': 0, 'json_set': 0, 'markdown_block': 1, 'hook_script': 2}
_MISSING = object()
_MAX_READ = 8 * 1024 * 1024


def _row(entry, index, status, reason='', identity=None):
    # `edit` is the index into the entry's edits; _identity is the file identity at plan time and is
    # internal: apply_removal and the CLI strip it before rows leave this module.
    edit = entry['edits'][index]
    return dict(entry=entry['id'], edit=index, file=edit['file'], kind=edit['kind'], status=status,
                reason=reason, _identity=identity)


def _previous_value(edit):
    """Value at the pointer before the edit, or _MISSING. Raises LedgerError when unreadable."""
    if edit['backup'] is None:
        return _MISSING
    backup = os.path.expanduser(edit['backup'])
    require(os.path.isfile(backup), 'backup not found', input='backup')
    try:
        return resolve(read_json(backup, 'backup'), pointer_parts(edit['pointer']))
    except LedgerError as exc:
        if exc.message == 'JSON pointer not found':
            return _MISSING
        raise


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _strings(value)


def _still_registered(entry, script):
    """True when a settings file of the entry still mentions the hook script's path, ignoring the
    elements this entry's own json_array_append edits would remove. Fails closed on unreadable files."""
    names = {script, os.path.abspath(os.path.expanduser(script))}
    for edit in entry['edits']:
        if not edit['kind'].startswith('json_'):
            continue
        path = os.path.expanduser(edit['file'])
        if not os.path.lexists(path):
            continue
        try:
            doc = read_json(path)
            for other in entry['edits']:
                if other['kind'] == 'json_array_append' and other['file'] == edit['file']:
                    try:
                        array = resolve(doc, pointer_parts(other['pointer']))
                    except LedgerError:
                        continue
                    hits = [i for i, x in enumerate(array) if fingerprint(x) == other['sha256']] \
                        if isinstance(array, list) else []
                    if len(hits) == 1:
                        del array[hits[0]]
        except LedgerError:
            return True
        if any(name in text for text in _strings(doc) for name in names):
            return True
    return False


def plan_edit(entry, index):
    edit = entry['edits'][index]
    path = os.path.expanduser(edit['file'])
    if os.path.islink(path):
        return _row(entry, index, 'blocked', 'symlink')
    if not os.path.exists(path):
        return _row(entry, index, 'absent', 'file_missing')
    try:
        identity = safe_write.identity_of(os.stat(path))
    except OSError:
        return _row(entry, index, 'blocked', 'unreadable')
    kind = edit['kind']

    def row(status, reason=''):
        return _row(entry, index, status, reason, identity)

    try:
        if kind == 'hook_script':
            if not any(e['kind'] == 'json_array_append' for e in entry['edits']):
                return row('blocked', 'registration_unrecorded')
            same = hashlib.sha256(read_text(path)).hexdigest() == edit['sha256']
            if same and _still_registered(entry, edit['file']):
                return row('blocked', 'registration_remains')
            return row('removable' if same else 'modified', '' if same else 'hash_mismatch')
        if kind == 'markdown_block':
            text = read_text(path).decode('utf-8', 'replace')
            try:
                span = find_block(text, entry['id'])
            except LedgerError:
                return row('modified', 'markers_ambiguous')
            if span is None:
                return row('absent', 'markers_missing')
            same = block_hash(text, entry['id']) == edit['sha256']
            return row('removable' if same else 'modified', '' if same else 'hash_mismatch')
        doc = read_json(path)
        try:
            node = resolve(doc, pointer_parts(edit['pointer']))
        except LedgerError:
            return row('absent', 'pointer_missing')
        if kind == 'json_array_append':
            if not isinstance(node, list):
                return row('modified', 'not_an_array')
            found = sum(fingerprint(x) == edit['sha256'] for x in node)
            if found > 1:
                return row('modified', 'ambiguous_duplicate')
            return row('removable' if found else 'absent', '' if found else 'value_missing')
        if fingerprint(node) != edit['sha256']:
            return row('modified', 'hash_mismatch')
        try:
            _previous_value(edit)
        except LedgerError:
            return row('blocked', 'backup_missing')
        return row('removable')
    except LedgerError:
        return row('blocked', 'unreadable')


def plan_removal(book, entry_ids):
    index = {e['id']: e for e in book['entries']}
    rows = []
    for entry_id in entry_ids:
        require(entry_id in index, 'entry not found')
        entry = index[entry_id]
        order = sorted(range(len(entry['edits'])), key=lambda i: ORDER[entry['edits'][i]['kind']])
        rows.extend(plan_edit(entry, i) for i in order)
    return rows


def _strip_block(text, entry_id):
    span = find_block(text, entry_id)
    if span is None:  # a second edit of the same entry in this file: already stripped
        return text
    lines = text.splitlines(keepends=True)
    return ''.join(lines[:span[0]] + lines[span[1] + 1:])


def _remove_json(doc, edit):
    parts = pointer_parts(edit['pointer'])
    if edit['kind'] == 'json_array_append':
        array = resolve(doc, parts)
        hits = [i for i, item in enumerate(array) if fingerprint(item) == edit['sha256']]
        require(len(hits) <= 1, 'ambiguous duplicate', input='edited file')
        if hits:
            del array[hits[0]]
        return
    parent = resolve(doc, parts[:-1])
    key = int(parts[-1]) if isinstance(parent, list) else parts[-1]
    previous = _previous_value(edit)
    if previous is _MISSING:
        del parent[key]
    else:
        parent[key] = previous


def _edit_for(book, row):
    """The (entry, edit index) a plan row names, looked up by entry id and edit index."""
    entry = next((e for e in book['entries'] if e['id'] == row.get('entry')), None)
    index = row.get('edit')
    require(entry is not None and type(index) is int and 0 <= index < len(entry['edits']), 'unknown plan row')
    return entry, index


def _restored(entry, index, doc_after):
    """True when a json_set edit was undone in the re-read document."""
    edit = entry['edits'][index]
    previous = _previous_value(edit)
    try:
        node = resolve(doc_after, pointer_parts(edit['pointer']))
    except LedgerError:
        return previous is _MISSING
    return previous is not _MISSING and fingerprint(node) == fingerprint(previous)


def _verified(entry, index):
    edit = entry['edits'][index]
    try:
        if edit['kind'] == 'json_set':
            return _restored(entry, index, read_json(os.path.expanduser(edit['file'])))
        return plan_edit(entry, index)['status'] == 'absent'
    except LedgerError:
        return False


def _block(group, reason):
    for r in group:
        r.update(status='blocked', reason=reason)


def _apply_file(book, group, path, backup_dir, home):
    """Back up and rewrite one file for its removable rows; mark each row removed or blocked."""
    planned = [_edit_for(book, r) for r in group]
    if any(plan_edit(e, i)['status'] != 'removable' for e, i in planned):
        return _block(group, 'changed_since_plan')
    kinds = {r['kind'] for r in group}
    json_kinds = kinds <= {'json_array_append', 'json_set'}
    if not json_kinds and len(kinds) != 1:
        return _block(group, 'mixed_edits')
    try:
        fd, st = safe_write.open_no_symlink(path)
    except safe_write.SymlinkRefused:
        return _block(group, 'symlink')
    except OSError:
        return _block(group, 'unreadable')
    try:
        if any(safe_write.identity_of(st) != r.get('_identity') for r in group):
            return _block(group, 'changed_since_plan')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            before = stream.read(_MAX_READ + 1)
        if len(before) > _MAX_READ:
            return _block(group, 'unreadable')
        os.lseek(fd, 0, os.SEEK_SET)
        try:
            backup = safe_write.backup_from_fd(fd, path, backup_dir, home)
        except OSError:
            return _block(group, 'backup_failed')
    finally:
        os.close(fd)
    try:
        if kinds == {'hook_script'}:
            new_text = None
        elif kinds == {'markdown_block'}:
            new_text = before.decode('utf-8')
            for r in group:
                new_text = _strip_block(new_text, r['entry'])
        else:
            doc = report_state.load_json(before.decode('utf-8'))
            for entry, index in planned:
                _remove_json(doc, entry['edits'][index])
            new_text = json.dumps(doc, indent=2, ensure_ascii=False) + '\n'
            json.loads(new_text)
    except (LedgerError, report_state.ReportError, UnicodeDecodeError, ValueError, RecursionError,
            KeyError, TypeError, IndexError):
        return _block(group, 'changed_since_plan')
    if new_text is None and any(_still_registered(e, e['edits'][i]['file']) for e, i in planned):
        return _block(group, 'registration_remains')
    try:
        if new_text is None:
            os.unlink(path)
        else:
            safe_write.atomic_write(path, new_text, prefix='.ledger.', encoding='utf-8')
    except OSError:
        return _block(group, 'write_failed')
    for r, (entry, index) in zip(group, planned):
        done = _verified(entry, index)
        r.update(backup=backup, status='removed' if done else 'blocked', reason='' if done else 'verify_failed')


def apply_removal(book, rows, backup_dir, home):
    book = copy.deepcopy(book)
    rows = [dict(r) for r in rows]
    for r in rows:
        _edit_for(book, r)
    by_file = {}
    for row in rows:
        if row['status'] == 'removable':
            by_file.setdefault(os.path.abspath(os.path.expanduser(row['file'])), []).append(row)
    for path, group in by_file.items():
        if {r['kind'] for r in group} == {'hook_script'}:
            # Deleting a hook script whose registration is still in place would break every tool call.
            registrations = [r for r in rows if r['kind'] == 'json_array_append'
                             and r['entry'] in {g['entry'] for g in group}]
            if any(r['status'] not in ('removed', 'absent') for r in registrations):
                _block(group, 'registration_remains')
                continue
        _apply_file(book, group, path, backup_dir, home)
    for row in rows:
        row.pop('_identity', None)
    for entry in book['entries']:
        mine = [r for r in rows if r['entry'] == entry['id']]
        if mine and all(r['status'] in ('removed', 'absent') for r in mine):
            entry['state'] = 'removed'
    return validate(book), rows


def fail(parser, exc):
    what = LABELS.get(getattr(exc, 'input', None), 'input')
    where = ' (line %d)' % exc.line if getattr(exc, 'line', None) else ''
    detail = exc.message if isinstance(exc, report_state.ReportError) else 'cannot be read or written'
    parser.exit(1, 'Ledger update failed. The %s%s: %s. Nothing was changed.\n' % (what, where, detail))


def read_input(path, input):
    try:
        data = report_state.load_json(read_text(path, input).decode('utf-8'))
    except report_state.ReportError as exc:
        raise LedgerError(exc.message, input=input, line=exc.line) from None
    except (UnicodeDecodeError, RecursionError):
        raise LedgerError('invalid text encoding or nesting', input=input) from None
    require(isinstance(data, dict), 'expected a JSON object', input=input)
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('next-id', help='print the next free entry id for today')
    p.add_argument('--ledger', required=True)
    p = sub.add_parser('record', help='append an entry for an applied, verified learning fix')
    for flag in ('--ledger', '--snapshot', '--report', '--spec'):
        p.add_argument(flag, required=True)
    p.add_argument('--claude-dir', help='Claude Code config directory (default: $CLAUDE_CONFIG_DIR, else ~/.claude)')
    p = sub.add_parser('remove', help='remove recorded edits (dry run unless --apply)')
    p.add_argument('--ledger', required=True)
    which = p.add_mutually_exclusive_group(required=True)
    which.add_argument('--entry', action='append')
    which.add_argument('--all', action='store_true')
    p.add_argument('--apply', action='store_true')
    p.add_argument('--backup-dir')
    args = parser.parse_args(argv)
    if args.command == 'remove' and args.apply and not args.backup_dir:
        fail(parser, LedgerError('--apply requires --backup-dir', input='input'))
    try:
        book = load(args.ledger)
        if args.command == 'remove':
            ids = list(dict.fromkeys(args.entry)) if args.entry else [
                e['id'] for e in book['entries'] if e['state'] != 'removed']
            rows = plan_removal(book, ids)
            if args.apply:
                try:
                    book, rows = apply_removal(book, rows, os.path.abspath(os.path.expanduser(args.backup_dir)),
                                               os.path.expanduser('~'))
                    dump(book, args.ledger)
                except (report_state.ReportError, OSError, ValueError, TypeError, KeyError):
                    parser.exit(1, 'Ledger update failed after files were changed. Backups are in the backup '
                                   'directory; the ledger was not updated.\n')
            for row in rows:
                row.pop('_identity', None)
            print(json.dumps(rows, indent=2))
            if any(r['status'] == 'blocked' for r in rows):
                sys.exit(2)
            return
        if args.command == 'next-id':
            print(next_id(book, datetime.now(timezone.utc).date()))
            return
        import collect
        if args.claude_dir:
            collect.CLAUDE = os.path.abspath(os.path.expanduser(args.claude_dir))
        snapshot = read_input(args.snapshot, 'snapshot')
        report = read_input(args.report, 'report')
        spec = read_input(args.spec, 'spec')
        book = record(book, spec, snapshot, report, Path(args.report).stem, time.time())
        dump(book, args.ledger)
        entry = book['entries'][-1]
        print(json.dumps({'recorded': entry['id'], 'baseline': entry['baseline']}, indent=2))
    except report_state.ReportError as exc:
        fail(parser, exc)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        fail(parser, LedgerError('cannot be processed', input=getattr(exc, 'input', None) or 'ledger'))


if __name__ == '__main__':
    main()
