#!/usr/bin/env python3
"""Render an audit JSON report as private, self-contained HTML (stdlib only).

All report content is inert text. This is not a secret redactor or a trend validator.
Version 1 reports without the additive presentation fields remain readable.
"""
import argparse
import html
import json
import math
import os
from pathlib import Path
import tempfile
import report_state


def escape(value):
    return html.escape(str(value), quote=True)


def display(value):
    """Render arbitrary JSON as text without interpreting Markdown, URLs or HTML."""
    if value is None:
        return '<span class="muted">Not reported</span>'
    if isinstance(value, dict):
        if not value:
            return '<span class="muted">None reported</span>'
        return '<dl>' + ''.join(
            f'<dt>{escape(label(k))}</dt><dd>{display(v)}</dd>' for k, v in value.items()
        ) + '</dl>'
    if isinstance(value, list):
        if not value:
            return '<span class="muted">None reported</span>'
        return '<ul>' + ''.join(f'<li>{display(v)}</li>' for v in value) + '</ul>'
    return '<span class="text">' + escape(value) + '</span>'


def validate(report):
    report_state.validate_report(report)


def label(value):
    return str(value).replace('_', ' ').capitalize()


def disclosure(title, value):
    return f'<details><summary>{escape(title)}</summary>{display(value)}</details>'


def paragraph(value, css=''):
    return f'<div class="{css}">{display(value)}</div>'


STYLE = """
:root { color-scheme: light; font: 17px/1.6 system-ui, sans-serif; color: #243348; background: #f4f6f9; }
* { box-sizing: border-box; } body { max-width: 960px; margin: auto; padding: 3rem 1.2rem; }
h1,h2,h3 { line-height: 1.25; color: #16263b; } h1 { font-size: 2.4rem; margin: .3rem 0 1rem; }
h2 { font-size: 1.5rem; margin-top: 2.2rem; } h3 { font-size: 1.2rem; margin: .6rem 0 1rem; }
article,.overview { background: white; border: 1px solid #d5dde7; border-radius: 12px; padding: 1.5rem; margin: 1rem 0; }
.overview { border-top: 4px solid #276957; } .lead { font-size: 1.15rem; }
.eyebrow,.muted { color: #526174; } .eyebrow { font-size: .85rem; letter-spacing: .08em; text-transform: uppercase; }
.badge { display: inline-block; background: #eef2f6; padding: .15rem .6rem; border-radius: 5px; font-size: .85rem; margin: 0 .4rem .3rem 0; }
.high { background: #fde9e7; color: #8c2923; } .medium { background: #fff0d2; color: #77500b; }
.next { border-left: 3px solid #276957; padding-left: 1rem; margin: 1rem 0; }
.grid { display: grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap: 1rem; }
.grid article { margin: 0; } .number { font-size: 1.8rem; font-weight: 700; }
details { margin-top: 1rem; border-top: 1px solid #dde3eb; padding-top: .7rem; }
summary { cursor: pointer; color: #285b86; font-weight: 600; } dt { font-weight: 650; } dd { margin: 0 0 .7rem 1rem; }
.text { white-space: pre-wrap; overflow-wrap: anywhere; } a { color: #285b86; } li { margin-bottom: .4rem; }
nav { margin: 1.2rem 0; } .privacy { margin-top: 2rem; font-size: .85rem; color: #526174; }
@media(max-width: 550px) { body { padding: 1.3rem .8rem; } h1 { font-size: 1.9rem; } article { padding: 1rem; } }
@media print { body { max-width: none; padding: 0; background: white; } article { break-inside: avoid; } }
"""


ACTION_LABELS = {
    'proposed': 'Awaiting your approval', 'approved': 'Approved; not yet completed',
    'applied': 'Change applied', 'partial': 'Partly completed', 'failed': 'Change failed',
    'skipped': 'Skipped', 'declined': 'Declined',
}


def render(report):
    validate(report)
    findings = report.get('findings', [])
    ranked = sorted((f for f in findings if f.get('type') != 'parked' and
                     f.get('status') not in ('resolved', 'suppressed')),
                    key=lambda f: -f.get('score', 0))
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\'">',
             '<title>Claude Code setup audit</title><style>', STYLE, '</style></head><body>',
             '<header><div class="eyebrow">Claude Code · Setup review</div><h1>Your setup audit</h1>']
    if report.get('example') is True:
        parts.append('<p class="badge">Example report · fictional data</p>')
    if report.get('generated'):
        parts.append(paragraph(report['generated'], 'muted'))
    parts.append('</header><nav aria-label="Report sections"><a href="#findings">Findings</a> · '
                 '<a href="#metrics">Key numbers</a> · <a href="#coverage">What was checked</a></nav>')
    parts.append('<section class="overview"><h2>At a glance</h2>')
    parts.append(paragraph(report.get('summary', 'This audit has no written summary. Review the findings and coverage below.'), 'lead'))
    noun = 'finding' if len(ranked) == 1 else 'findings'
    parts.append(f'<p>{len(ranked)} {noun} to review. Each shows whether a change is awaiting approval or has been attempted.</p></section>')

    def finding_section(ident, title, items, numbered=False):
        if not items and not numbered:
            return
        parts.append(f'<section id="{ident}"><h2>{title}</h2>')
        if not items:
            parts.append('<p>No findings reported. Check the coverage below before drawing conclusions.</p>')
        for index, finding in enumerate(items, 1):
            prefix = f'{index}. ' if numbered else ''
            parts.append('<article>')
            severity = finding.get('severity')
            if severity:
                css = severity if severity in ('high', 'medium', 'low') else ''
                parts.append(f'<span class="badge {css}">{escape(label(severity))} priority</span>')
            state = finding.get('action_status')
            parts.append(f'<span class="badge">{escape(ACTION_LABELS.get(state, label(state) if state else "Action status not recorded"))}</span>')
            parts.append(f'<h3>{prefix}{escape(finding.get("title", finding.get("id", "Untitled finding")))}</h3>')
            if finding.get('why'):
                parts.append(paragraph(finding['why']))
            fix = finding.get('fix')
            if fix:
                parts.append('<div class="next"><strong>What to do</strong>')
                if isinstance(fix, dict):
                    parts.append(paragraph(fix.get('summary') or fix.get('steps') or
                                           'Review the exact change in the supporting details below.'))
                else:
                    parts.append(paragraph(fix))
                parts.append('</div>')
            if finding.get('effort'):
                parts.append('<p class="muted">Estimated effort: ' + escape(finding['effort']) + '</p>')
            if finding.get('evidence'):
                parts.append('<strong>What we found</strong>' + display(finding['evidence']))
            technical = {k: v for k, v in finding.items() if k not in ('title', 'why', 'effort', 'evidence')}
            parts.append(disclosure('Supporting details and exact change', technical))
            parts.append('</article>')
        parts.append('</section>')

    finding_section('findings', 'Findings, in priority order', ranked, True)
    finding_section('parked', 'Lower-value changes to consider later', [f for f in findings if f.get('type') == 'parked'
                    and f.get('status') not in ('resolved', 'suppressed')])
    for status, title in (('resolved', 'Resolved findings'), ('suppressed', 'Accepted exceptions')):
        finding_section(status, title, [f for f in findings if f.get('status') == status])

    if report.get('applied'):
        parts.append('<section id="actions"><h2>Changes made and attempted</h2>')
        titles = {str(f.get('id')): f.get('title', f.get('id')) for f in findings}
        for action in report['applied']:
            parts.append('<article><h3>' + escape(titles.get(str(action.get('id')), 'Recorded action')) + '</h3>')
            state = action.get('status', 'unknown')
            parts.append(paragraph(ACTION_LABELS.get(state, label(state))))
            if action.get('verification'):
                parts.append('<strong>Verification</strong>' + display(action['verification']))
            parts.append(disclosure('Files, backups and recovery details', action) + '</article>')
        parts.append('</section>')
    metrics = report.get('metrics')
    if metrics:
        parts.append('<section id="metrics"><h2>Key numbers</h2><div class="grid">')
        if isinstance(metrics, dict):
            for key, metric in metrics.items():
                item = metric if isinstance(metric, dict) and 'value' in metric else {'value': metric}
                parts.append('<article><strong>' + escape(item.get('label', label(key))) + '</strong>')
                value = item['value']
                if type(value) in (int, float):
                    value = format(value, ',')
                parts.append(paragraph(value, 'number'))
                parts.append(paragraph(item.get('unit', ''), 'muted'))
                basis = item.get('basis', 'unknown')
                parts.append(paragraph({'measured': 'Measured from recorded data', 'estimated': 'Estimate',
                                        'unknown': 'Measurement method not recorded'}.get(basis, label(basis)), 'muted'))
                if item.get('explanation'):
                    parts.append(paragraph(item['explanation']))
                parts.append(disclosure('How this number was obtained', metric) + '</article>')
        else:
            parts.append(display(metrics))
        parts.append('</div></section>')
    if report.get('trend'):
        trend = report['trend']
        parts.append('<section id="trend"><h2>Since the previous audit</h2>')
        parts.append(paragraph(trend.get('reason', 'Comparison details are unavailable.')))
        for name, metric in trend.get('metrics', {}).items():
            if metric.get('comparable'):
                parts.append(paragraph(f"{label(name)}: {metric['previous']} → {metric['current']} {metric['unit']} "
                                       f"(change: {metric['delta']:+g}; {metric['basis']})."))
        if trend.get('findings', {}).get('not_rechecked'):
            parts.append(paragraph('Some earlier findings were not rechecked; they are not counted as resolved.'))
        parts.append(disclosure('Comparison evidence', trend))
        parts.append('</section>')
    parts.append('<section id="coverage"><h2>What was checked</h2>')
    coverage = report.get('coverage')
    if coverage is None:
        parts.append('<p>Not reported. Requested scope does not establish collection completeness.</p>')
    else:
        if isinstance(coverage, dict):
            if coverage.get('summary'):
                parts.append(paragraph(coverage['summary']))
            if coverage.get('projects_collected'):
                parts.append('<strong>Projects included</strong>' + display(coverage['projects_collected']))
            if coverage.get('limitations'):
                parts.append('<strong>Limits to this review</strong>' + display(coverage['limitations']))
        parts.append(disclosure('Collection details', coverage))
    if report.get('caveats'):
        parts.append('<h3>Not checked or uncertain</h3>' + display(report['caveats']))
    parts.append(disclosure('Audit settings', {k: report.get(k) for k in ('claude_code_version', 'profile')}))
    parts.append('</section>')
    if report.get('new_features'):
        parts.append('<section><h2>New features worth trying</h2>' + display(report['new_features']) + '</section>')
    parts.append('<p class="privacy">Private report — review before sharing. Paths and evidence may contain sensitive information.</p></body></html>\n')
    return ''.join(parts)


def write_report(source):
    source = Path(source)
    if source.suffix.lower() != '.json':
        raise ValueError('input must have a .json extension')
    with source.open(encoding='utf-8') as stream:
        report = report_state.load_json(stream.read())
    output = render(report)
    target = source.with_suffix('.html')
    # A private temporary file plus replacement avoids following an existing output symlink,
    # leaves old output intact on failure, and preserves mode 0600 even under a permissive umask.
    fd, temporary = tempfile.mkstemp(prefix='.audit-', suffix='.html', dir=target.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(output)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('audit_json', help='audit JSON; writes the sibling .html file')
    args = parser.parse_args()
    try:
        target = write_report(args.audit_json)
    except (OSError, ValueError, RecursionError):
        # JSON decoder exceptions can contain private input; do not echo them.
        parser.exit(1, 'Could not render report: check input JSON, version, finding scores and file permissions.\n')
    print(target)


if __name__ == '__main__':
    main()
