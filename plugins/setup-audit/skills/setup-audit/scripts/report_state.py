"""Audit validation, conservative history comparison, and decision expiry (stdlib only)."""
import copy
from datetime import date, datetime, timezone
import hashlib
import json
import math
import re

HISTORY = {'new', 'open', 'regressed', 'resolved', 'suppressed'}
ACTIONS = {'proposed', 'approved', 'applied', 'partial', 'failed', 'skipped', 'declined'}
COVERAGE = {'collected', 'absent', 'partial', 'unavailable', 'not_checked'}
BASIS = {'measured', 'estimated', 'unknown'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def iso_date(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', value), 'expected ISO date')
    return date.fromisoformat(value)


def timestamp(value):
    require(isinstance(value, str), 'expected timestamp')
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    # Legacy date-only and naive timestamps use UTC for deterministic comparisons.
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def load_json(text):
    return json.loads(text, object_pairs_hook=unique_pairs,
                      parse_constant=lambda _: require(False, 'non-finite JSON number'))


def validate_report(report, strict=False):
    try:
        json.dumps(report, allow_nan=False)
        return _validate_report(report, strict)
    except (TypeError, KeyError, AttributeError) as exc:
        raise ValueError('invalid report field shape') from exc


def _validate_report(report, strict=False):
    require(isinstance(report, dict) and type(report.get('version')) is int and report['version'] == 1,
            'expected version 1 report')
    if strict:
        for key in ('generated', 'profile', 'coverage', 'summary', 'findings', 'metrics', 'applied'):
            require(key in report, 'missing required report field: ' + key)
    if 'generated' in report:
        timestamp(report['generated'])
    for key in ('summary', 'claude_code_version'):
        if key in report:
            require(isinstance(report[key], str), key + ' must be text')
    for key in ('profile', 'metrics', 'coverage', 'checks'):
        if key in report:
            require(isinstance(report[key], dict), key + ' must be an object')
    profile = report.get('profile', {})
    if strict:
        require(profile.get('scope') in ('global', 'project', 'all'), 'profile scope required')
    if 'scope' in profile:
        require(profile['scope'] in ('global', 'project', 'all'), 'invalid scope')
    for key, values in (('depth', {'quick', 'full'}), ('mode', {'audit', 'propose', 'apply'})):
        if key in profile:
            require(profile[key] in values, 'invalid profile ' + key)
    if 'window_days' in report:
        require(type(report['window_days']) is int and report['window_days'] > 0, 'invalid window_days')
    coverage = report.get('coverage', {})
    if 'requested_scope' in coverage:
        require(coverage['requested_scope'] == profile.get('scope'), 'coverage scope mismatch')
    for key in ('projects_collected', 'limitations'):
        if key in coverage:
            require(isinstance(coverage[key], list) and all(isinstance(x, str) for x in coverage[key]),
                    'invalid coverage ' + key)
    if 'sources' in coverage:
        require(isinstance(coverage['sources'], list), 'coverage sources must be an array')
        for src in coverage['sources']:
            require(isinstance(src, dict) and isinstance(src.get('source'), str) and src.get('status') in COVERAGE,
                    'invalid coverage source')
            for key in ('eligible', 'scanned', 'omitted', 'unknown_date', 'bytes_read', 'file_bytes', 'directories_scanned'):
                if key in src:
                    require(type(src[key]) is int and src[key] >= 0, 'invalid coverage count')
    for value in report.get('checks', {}).values():
        require(value in ('complete', 'partial', 'not_checked'), 'invalid check status')
    for metric in report.get('metrics', {}).values():
        if isinstance(metric, dict):
            require('value' in metric, 'metric value required')
            require(metric.get('basis', 'unknown') in BASIS, 'invalid metric basis')
            if strict:
                require(all(isinstance(metric.get(k), str) for k in ('unit', 'basis', 'source')), 'metric labels required')
            value = metric['value']
            require(value is None or finite(value), 'metric value must be finite or null')
        else:
            require(not strict and (metric is None or finite(metric)), 'legacy metric must be finite or null')
    seen = set()
    for key in ('findings', 'applied'):
        require(isinstance(report.get(key, []), list), key + ' must be an array')
        for item in report.get(key, []):
            require(isinstance(item, dict), key + ' entry must be an object')
            if strict or 'id' in item:
                require(isinstance(item.get('id'), str) and bool(item['id']), 'entry id required')
            if key == 'findings':
                if 'id' in item:
                    require(item['id'] not in seen, 'duplicate finding id')
                    seen.add(item['id'])
                require(finite(item.get('score', 0)), 'finding score must be finite')
                if strict:
                    require(isinstance(item.get('title'), str) and bool(item['title']), 'finding title required')
                    require('evidence' in item and 'status' in item, 'finding evidence and status required')
                if 'status' in item:
                    require(item['status'] in HISTORY, 'invalid finding history status')
                if 'action_status' in item:
                    require(item['action_status'] in ACTIONS, 'invalid action status')
                if 'evidence' in item:
                    require(isinstance(item['evidence'], (str, list, dict)), 'invalid finding evidence')
                if 'fix' in item:
                    require(isinstance(item['fix'], (str, dict)), 'invalid finding fix')
                for field in ('title', 'check', 'why', 'area'):
                    if field in item:
                        require(isinstance(item[field], str), 'finding text field required')
                if 'severity' in item:
                    require(item['severity'] in ('critical', 'high', 'medium', 'low', 'info'), 'invalid severity')
            else:
                if strict:
                    require('status' in item, 'applied status required')
                if 'status' in item:
                    require(item['status'] in ACTIONS, 'invalid applied status')
                for field in ('files', 'backups'):
                    if field in item:
                        require(isinstance(item[field], list) and all(isinstance(x, str) for x in item[field]),
                                'action file paths must be arrays of text')
    if 'trend' in report:
        trend = report['trend']
        require(isinstance(trend, dict) and type(trend.get('comparable')) is bool,
                'invalid trend metadata')
        require(isinstance(trend.get('reason'), str) and isinstance(trend.get('metrics'), dict),
                'invalid trend detail')
        require(isinstance(trend.get('findings'), dict), 'invalid trend findings')
        for ids in trend['findings'].values():
            require(isinstance(ids, list) and all(isinstance(x, str) for x in ids), 'invalid trend IDs')
        for metric in trend['metrics'].values():
            require(isinstance(metric, dict) and type(metric.get('comparable')) is bool, 'invalid trend metric')
            if metric['comparable']:
                require(all(finite(metric.get(k)) for k in ('previous', 'current', 'delta')), 'invalid trend values')
                require(isinstance(metric.get('unit'), str) and metric.get('basis') in BASIS, 'invalid trend labels')
                require(math.isclose(metric['delta'], metric['current'] - metric['previous']), 'inconsistent trend delta')
    if strict:
        require(all(item['id'] in seen for item in report['applied']), 'action refers to missing finding')
    return report


def yaml_scalar(text):
    """The supported decisions YAML subset is a flat list of scalar maps; no tags/aliases."""
    text = text.strip()
    if text.startswith('"'):
        decoder = json.JSONDecoder()
        value, end = decoder.raw_decode(text)
        require(isinstance(value, str) and (not text[end:].strip() or text[end:].lstrip().startswith('#')),
                'invalid quoted decision scalar')
        return value
    if text.startswith("'"):
        match = re.fullmatch(r"'((?:[^']|'')*)'\s*(?:#.*)?", text)
        require(match is not None, 'invalid quoted decision scalar')
        return match[1].replace("''", "'")
    text = re.split(r'\s+#', text, maxsplit=1)[0].rstrip()
    require(bool(text) and text[0] not in '!&*[{>|' and ': ' not in text and text not in ('null', '~'),
            'unsupported decision YAML; use quoted scalars')
    return text


def parse_decisions(text):
    if not text.strip():
        return []
    if text.lstrip().startswith('['):
        rows = load_json(text)
    else:
        rows, row = [], None
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'(- |  )([a-z_]+):\s*(.*)', line)
            require(match is not None, 'unsupported decisions YAML; use flat scalar entries')
            if match[1] == '- ':
                row = {}
                rows.append(row)
            require(row is not None and match[2] not in row, 'duplicate or misplaced decision field')
            row[match[2]] = yaml_scalar(match[3])
    require(isinstance(rows, list), 'decisions must be an array')
    seen = set()
    for row in rows:
        require(isinstance(row, dict) and set(row) <= {'id', 'reason', 'settled', 'review_after', 'evidence_hash'},
                'invalid decision fields')
        require(all(isinstance(row.get(k), str) and row[k].strip() for k in ('id', 'reason', 'settled', 'review_after')),
                'decision fields required')
        require(row['id'] not in seen, 'duplicate decision id')
        seen.add(row['id'])
        require(iso_date(row['settled']) <= iso_date(row['review_after']), 'decision dates reversed')
        if 'evidence_hash' in row:
            require(re.fullmatch('[a-f0-9]{64}', row['evidence_hash']) is not None, 'invalid evidence hash')
    return rows


def evidence_hash(finding):
    require('evidence' in finding, 'evidence required for fingerprint')
    encoded = json.dumps(finding['evidence'], sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()


def comparable(current, previous):
    if previous is None:
        return False, 'No previous report supplied.'
    try:
        if timestamp(current['generated']) <= timestamp(previous['generated']):
            return False, 'Previous report is not older than the current report.'
        for key in ('scope', 'focus'):
            if key not in current['profile'] or current['profile'][key] != previous['profile'].get(key):
                return False, 'Requested scopes or focus differ or are missing.'
        if current['window_days'] != previous['window_days']:
            return False, 'Measurement windows differ.'
        for report in (current, previous):
            if not isinstance(report['coverage']['projects_collected'], list):
                return False, 'Project coverage is missing.'
        if sorted(current['coverage']['projects_collected']) != sorted(previous['coverage']['projects_collected']):
            return False, 'Collected projects differ.'
    except (KeyError, TypeError, ValueError):
        return False, 'Comparison metadata is incomplete.'
    return True, 'Scope, focus, projects and measurement window match.'


def metric_coverage(report, metric):
    prefix = metric.get('source', '').split('.')[0]
    sources = [s for s in report.get('coverage', {}).get('sources', [])
               if s['source'] == prefix or s['source'].startswith(prefix + '.')]
    return bool(sources) and all(s['status'] == 'collected' and not s.get('omitted') for s in sources)


def finalize(current, previous=None, decisions=(), as_of=None):
    validate_report(current, strict=True)
    if previous is not None:
        validate_report(previous)
    # Also validate caller-supplied decisions, not just the CLI parser path.
    decisions = parse_decisions(json.dumps(list(decisions)))
    day = iso_date(as_of) if as_of else timestamp(current['generated']).date()
    out = copy.deepcopy(current)
    out['findings'] = [f for f in out['findings'] if not f.get('comparison_generated')]
    same, reason = comparable(current, previous)
    prior = {f['id']: f for f in (previous or {}).get('findings', []) if 'id' in f}
    trend = dict(comparable=same, reason=reason, previous_generated=(previous or {}).get('generated'),
                 findings={'new': [], 'open': [], 'regressed': [], 'resolved': [], 'not_rechecked': []}, metrics={})
    decision_index = {d['id']: d for d in decisions}
    for finding in out['findings']:
        old = prior.get(finding['id']) if same else None
        status = 'regressed' if old and old.get('status') == 'resolved' else 'open' if old else 'new'
        finding['status'] = status
        finding.pop('decision', None)
        finding['evidence_hash'] = evidence_hash(finding)
        trend['findings'][status].append(finding['id'])
        decision = decision_index.get(finding['id']) or decision_index.get(finding.get('check'))
        if decision:
            baseline = decision.get('evidence_hash')
            if baseline is None and old and iso_date(decision['settled']) <= timestamp(previous['generated']).date():
                old_decision = old.get('decision')
                if isinstance(old_decision, dict):
                    if all(old_decision.get(k) == decision.get(k) for k in ('id', 'reason', 'settled', 'review_after')):
                        baseline = old_decision.get('evidence_hash')
                elif 'evidence' in old:
                    baseline = evidence_hash(old)
            reason = ('not_yet_settled' if day < iso_date(decision['settled']) else
                      'review_due' if day >= iso_date(decision['review_after']) else
                      'evidence_unverified' if baseline is None else
                      'evidence_changed' if baseline != finding['evidence_hash'] else 'suppressed')
            finding['decision'] = dict(decision, result=reason)
            if baseline is not None:
                finding['decision']['evidence_hash'] = baseline
            if reason == 'suppressed':
                finding['status'] = 'suppressed'
    present = {f['id'] for f in out['findings']}
    for id_, old in sorted(prior.items()):
        if id_ in present:
            continue
        check = old.get('check')
        enough = isinstance(old.get('title'), str) and 'evidence' in old
        if same and enough and (old.get('status') == 'resolved' or
                                check and current.get('checks', {}).get(check) == 'complete'):
            resolved = copy.deepcopy(old)
            resolved.update(status='resolved', comparison_generated=True)
            resolved.pop('action_status', None)
            resolved.pop('decision', None)
            out['findings'].append(resolved)
            if old.get('status') != 'resolved':
                trend['findings']['resolved'].append(id_)
        else:
            trend['findings']['not_rechecked'].append(id_)
    for key, metric in current['metrics'].items():
        old = (previous or {}).get('metrics', {}).get(key)
        result = dict(comparable=False, reason='Comparable labeled values and complete source coverage required.')
        if same and isinstance(metric, dict) and isinstance(old, dict) and all(
                metric.get(k) == old.get(k) and metric.get(k) is not None for k in ('basis', 'unit', 'source')) and metric.get('basis') != 'unknown' and finite(metric['value']) and finite(old.get('value')) and metric_coverage(current, metric) and metric_coverage(previous, old):
            result = dict(comparable=True, previous=old['value'], current=metric['value'],
                          delta=metric['value'] - old['value'], unit=metric['unit'], basis=metric['basis'])
        trend['metrics'][key] = result
    out['trend'] = trend
    validate_report(out, strict=True)
    return out
