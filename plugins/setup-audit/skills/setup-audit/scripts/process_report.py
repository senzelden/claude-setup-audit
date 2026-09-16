#!/usr/bin/env python3
"""Validate a report; optionally finalize history/decisions in place before HTML rendering.

Only the explicitly named current report is written with --finalize. Previous reports and
flat-scalar decisions YAML/JSON are read-only. No configuration is changed.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile
import report_state


def read(path):
    with open(path, encoding='utf-8') as stream:
        text = stream.read(8 * 1024 * 1024 + 1)
    if len(text) > 8 * 1024 * 1024:
        raise ValueError('input too large')
    return text


def write(path, report):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('current report must not be a symlink')
    text = json.dumps(report, indent=2, ensure_ascii=True, allow_nan=False) + '\n'
    fd, temporary = tempfile.mkstemp(prefix='.audit-state-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    parser.add_argument('--previous')
    parser.add_argument('--decisions')
    parser.add_argument('--as-of', help='ISO date; defaults to current report date')
    parser.add_argument('--finalize', action='store_true', help='replace current report with validated history and trends')
    args = parser.parse_args()
    try:
        current = report_state.load_json(read(args.report))
        previous = report_state.load_json(read(args.previous)) if args.previous else None
        decisions = report_state.parse_decisions(read(args.decisions)) if args.decisions else []
        result = report_state.finalize(current, previous, decisions, args.as_of)
        if args.finalize:
            if args.previous and os.path.realpath(args.previous) == os.path.realpath(args.report):
                raise ValueError('current and previous reports must differ')
            write(args.report, result)
    except (OSError, ValueError, TypeError, KeyError, RecursionError):
        parser.exit(1, 'Report validation failed. Check version, required fields, unique IDs, finite metrics, dates and flat-scalar decisions syntax. No report was finalized.\n')
    print('Report finalized.' if args.finalize else 'Report and comparison inputs are valid.')


if __name__ == '__main__':
    main()
