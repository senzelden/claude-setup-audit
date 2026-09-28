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
LEDGER_VERDICTS = ('unknown', 'too_early', 'quiet', 'dropped', 'not_dropped')


class ReportError(ValueError):
    """Validation failure with a constant message; never built from input values.

    `input` names the failing input ('report', 'previous', 'decisions', 'as_of', or 'output' when
    the result cannot be written) and `line` is set only when the parser already knows it.
    """

    def __init__(self, message, input=None, line=None):
        super().__init__(message)
        self.message, self.input, self.line = message, input, line


def require(condition, message):
    if not condition:
        raise ReportError(message)


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def iso_date(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}', value), 'expected ISO date')
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise ReportError('expected ISO date') from None


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
    try:
        return json.loads(text, object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: require(False, 'non-finite JSON number'))
    except json.JSONDecodeError as exc:
        # lineno/colno are positions; exc.msg can quote the document, so it is not used.
        raise ReportError('invalid JSON at column %d' % exc.colno, line=exc.lineno) from None


def validate_report(report, strict=False):
    try:
        json.dumps(report, allow_nan=False)
        return _validate_report(report, strict)
    except ReportError:
        raise
    except (TypeError, KeyError, AttributeError) as exc:
        raise ReportError('invalid report field shape') from exc
    except ValueError as exc:  # e.g. a malformed date; its text can quote the value
        raise ReportError('invalid report field value') from exc


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
                if 'ledger_entry' in item:
                    require(isinstance(item['ledger_entry'], str), 'invalid ledger entry reference')
    if 'trend' in report:
        trend = report['trend']
        require(isinstance(trend, dict) and type(trend.get('comparable')) is bool,
                'invalid trend metadata')
        require(isinstance(trend.get('reason'), str) and isinstance(trend.get('metrics'), dict),
                'invalid trend detail')
        require(isinstance(trend.get('findings'), dict), 'invalid trend findings')
        for ids in trend['findings'].values():
            require(isinstance(ids, list) and all(isinstance(x, str) for x in ids), 'invalid trend IDs')
        if 'ignored' in trend:
            ignored = trend['ignored']
            require(isinstance(ignored, dict) and all(
                isinstance(v, list) and all(isinstance(x, str) for x in v) for v in ignored.values()),
                'invalid trend ignored')
        if 'ledger' in trend:
            rows = trend['ledger']
            require(isinstance(rows, list), 'invalid trend ledger')
            for row in rows:
                require(isinstance(row, dict) and isinstance(row.get('entry'), str)
                        and row.get('verdict') in LEDGER_VERDICTS and isinstance(row.get('reason'), str)
                        and row.get('proposal') in (None, 'escalate', 'retire')
                        and (row.get('next_mechanism') is None or isinstance(row['next_mechanism'], str)),
                        'invalid trend ledger')
                require(all(row.get(k) is None or (type(row[k]) is int and row[k] >= 0)
                            for k in ('matches', 'sessions_matched', 'sessions_scanned'))
                        and (row.get('value') is None or finite(row['value'])), 'invalid trend ledger')
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
    require(not text or text[0] not in '>|',
            'block scalars (> or |) are not supported; quote the value as a single string')
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
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            try:
                match = re.fullmatch(r'(- |  )([a-z_]+):\s*(.*)', line)
                require(match is not None, 'unsupported decisions YAML; use flat scalar entries')
                if match[1] == '- ':
                    row = {}
                    rows.append(row)
                require(row is not None and match[2] not in row, 'duplicate or misplaced decision field')
                row[match[2]] = yaml_scalar(match[3])
            except ReportError as exc:
                exc.line = number
                raise
            except ValueError:  # e.g. a malformed quoted scalar; keep the message constant
                raise ReportError('invalid quoted decision scalar', line=number) from None
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
        if current['profile'].get('clarity', 'off') != previous['profile'].get('clarity', 'off'):
            return False, 'Instruction clarity profiles differ.'
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


def _fits(**fragment):
    try:
        validate_report(dict(version=1, **fragment))
        return True
    except ValueError:
        return False


def _keep_entries(name, mapping, kept, fits, note):
    """Copy the mapping entries one by one, dropping (and noting) those that fail `fits`."""
    for key, value in mapping.items():
        if fits(key, value):
            kept[key] = value
        else:
            note(name + '.' + key)


def lenient_previous(previous):
    """Return (usable copy, ignored) for an earlier report; only version 1 and finding ids matter.

    Every other field that fails validation is dropped from the copy. A finding status outside
    the history enum keeps the id but loses the status, so it is never treated as resolved.
    `ignored` holds finding ids, metric names and field paths only, never values.
    """
    require(isinstance(previous, dict) and type(previous.get('version')) is int and previous['version'] == 1,
            'expected version 1 report')
    ignored = dict(finding_statuses=[], metrics=[], fields=[])
    note = ignored['fields'].append
    out = {'version': 1}
    special = ('version', 'profile', 'coverage', 'checks', 'metrics', 'findings', 'applied')
    for key, value in previous.items():
        if key not in special:
            if _fits(**{key: value}):
                out[key] = value
            else:
                note(key)
    if 'generated' not in out and 'generated' not in ignored['fields']:
        note('generated')
    if 'profile' in previous:
        if isinstance(previous['profile'], dict):
            out['profile'] = {}
            _keep_entries('profile', previous['profile'], out['profile'],
                          lambda k, v: _fits(profile=dict(out['profile'], **{k: v})), note)
        else:
            note('profile')
    if 'coverage' in previous:
        coverage = previous['coverage']
        if isinstance(coverage, dict):
            out['coverage'] = {}
            context = dict(profile=out['profile']) if 'profile' in out else {}
            for key, value in coverage.items():
                if key == 'sources' and isinstance(value, list):
                    out['coverage'][key] = []
                    for index, source in enumerate(value):
                        if _fits(coverage=dict(sources=[source])):
                            out['coverage'][key].append(source)
                        else:
                            note('coverage.sources[%d]' % index)
                elif _fits(coverage=dict(out['coverage'], **{key: value}), **context):
                    out['coverage'][key] = value
                else:
                    note('coverage.' + key)
        else:
            note('coverage')
    if 'checks' in previous:
        if isinstance(previous['checks'], dict):
            out['checks'] = {}
            _keep_entries('checks', previous['checks'], out['checks'],
                          lambda k, v: _fits(checks={k: v}), note)
        else:
            note('checks')
    if 'metrics' in previous:
        if isinstance(previous['metrics'], dict):
            out['metrics'] = {}
            for name, metric in previous['metrics'].items():
                if _fits(metrics={name: metric}):
                    out['metrics'][name] = metric
                else:
                    ignored['metrics'].append(name)
        else:
            note('metrics')
    if 'findings' in previous:
        if isinstance(previous['findings'], list):
            out['findings'], seen = [], set()
            for index, item in enumerate(previous['findings']):
                ident = item.get('id') if isinstance(item, dict) else None
                if not (isinstance(ident, str) and ident) or ident in seen:
                    note('findings[%d]' % index)
                    continue
                seen.add(ident)
                kept = {'id': ident}
                for key, value in item.items():
                    if key == 'id' or _fits(findings=[{'id': ident, key: value}]):
                        kept[key] = value
                    elif key == 'status':
                        ignored['finding_statuses'].append(ident)
                    else:
                        note('findings[%s].%s' % (ident, key))
                out['findings'].append(kept)
        else:
            note('findings')
    if 'applied' in previous:
        if isinstance(previous['applied'], list):
            out['applied'] = []
            for index, item in enumerate(previous['applied']):
                if not isinstance(item, dict):
                    note('applied[%d]' % index)
                    continue
                kept = {}
                for key, value in item.items():
                    if _fits(applied=[{key: value}]):
                        kept[key] = value
                    else:
                        note('applied[%d].%s' % (index, key))
                out['applied'].append(kept)
        else:
            note('applied')
    return out, ignored


def finalize(current, previous=None, decisions=(), as_of=None):
    try:
        validate_report(current, strict=True)
    except ReportError as exc:
        exc.input = 'report'
        raise
    ignored = dict(finding_statuses=[], metrics=[], fields=[])
    if previous is not None:
        try:
            previous, ignored = lenient_previous(previous)
            validate_report(previous)
        except ReportError as exc:
            exc.input = 'previous'
            raise
    # Also validate caller-supplied decisions, not just the CLI parser path.
    try:
        decisions = parse_decisions(json.dumps(list(decisions)))
    except ReportError as exc:
        exc.input, exc.line = 'decisions', None
        raise
    try:
        day = iso_date(as_of) if as_of else timestamp(current['generated']).date()
    except ReportError as exc:
        exc.input = 'as_of'
        raise
    out = copy.deepcopy(current)
    out['findings'] = [f for f in out['findings'] if not f.get('comparison_generated')]
    same, reason = comparable(current, previous)
    # A dropped previous coverage source may have been incomplete, so no metric may be compared.
    lost_coverage = any(f == 'coverage' or f.startswith('coverage.sources') for f in ignored['fields'])
    prior = {f['id']: f for f in (previous or {}).get('findings', []) if 'id' in f}
    trend = dict(comparable=same, reason=reason, previous_generated=(previous or {}).get('generated'),
                 findings={'new': [], 'open': [], 'regressed': [], 'resolved': [], 'not_rechecked': []}, metrics={},
                 ignored=ignored)
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
        if same and enough and id_ not in ignored['finding_statuses'] and (
                old.get('status') == 'resolved' or check and current.get('checks', {}).get(check) == 'complete'):
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
                metric.get(k) == old.get(k) and metric.get(k) is not None for k in ('basis', 'unit', 'source')) and metric.get('basis') != 'unknown' and finite(metric['value']) and finite(old.get('value')) and metric_coverage(current, metric) and not lost_coverage and metric_coverage(previous, old):
            delta = metric['value'] - old['value']
            if finite(delta):
                result = dict(comparable=True, previous=old['value'], current=metric['value'],
                              delta=delta, unit=metric['unit'], basis=metric['basis'])
        trend['metrics'][key] = result
    out['trend'] = trend
    validate_report(out, strict=True)
    return out
