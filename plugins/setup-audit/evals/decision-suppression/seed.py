"""Synthetic report inputs with dates relative to scaffold time; no user data."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path


def seed(root, today=None):
    today = today or datetime.now(timezone.utc).date()
    day = lambda offset: (today + timedelta(days=offset)).isoformat()
    findings = [dict(id='SEC-' + name, check='SEC-' + name, title=name.capitalize(),
                     evidence=[dict(source='fixture/' + name, detail='Bash(curl:*)')],
                     status='new', action_status='proposed')
                for name in ('unchanged', 'prior', 'changed', 'expired', 'unverified')]
    current = dict(version=1, generated=day(0), window_days=30,
                   profile=dict(scope='global', focus='security', depth='quick', mode='audit'),
                   coverage=dict(requested_scope='global', projects_collected=[]),
                   summary='Synthetic decision review',
                   findings=findings, metrics={}, applied=[])
    previous = copy.deepcopy(current)
    previous['generated'] = day(-1)
    previous['findings'] = previous['findings'][:-1]
    decisions = []
    for finding in previous['findings'] + [findings[-1]]:
        decision = dict(id=finding['id'], reason='Deliberate fixture exception: ' + finding['id'],
                        settled=day(-2), review_after=day(7))
        if finding['id'] not in ('SEC-prior', 'SEC-unverified'):
            canonical = json.dumps(finding['evidence'], sort_keys=True, ensure_ascii=True,
                                   separators=(',', ':')).encode()
            decision['evidence_hash'] = hashlib.sha256(canonical).hexdigest()
        if finding['id'] == 'SEC-expired':
            decision['review_after'] = day(0)  # Inclusive expiry boundary.
        decisions.append(decision)
    findings[2]['evidence'][0]['detail'] = 'Bash(wget:*)'
    for name, data in [('current', current), ('previous', previous), ('decisions', decisions)]:
        (root / 'inputs' / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')


if __name__ == '__main__':
    seed(Path.cwd())
