#!/usr/bin/env python3
"""Per-item learning ledger: strict format, verdicts, and the next-id/record/remove CLI.

The ledger is the plugin's own file. It holds counts, hashes, paths and ids, never prompt text
or configuration values. Every path is explicit; nothing is searched for. Stdlib only.
"""
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

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


def load(path):
    require(not os.path.islink(path), 'ledger must not be a symlink')
    if not os.path.exists(path):
        return empty()
    with open(path, encoding='utf-8') as stream:
        text = stream.read(8 * 1024 * 1024 + 1)
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
