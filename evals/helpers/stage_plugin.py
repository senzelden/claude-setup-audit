#!/usr/bin/env python3
"""Stage the plugin plus the repo-level eval suite for `claude plugin eval`.

`claude plugin eval` only looks for cases inside the plugin directory, but the shipped plugin
must not contain them. This copies both into a fresh directory; it never runs Claude.
"""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
PLUGIN_REL = Path('plugins/setup-audit')


def reject_symlinks(root):
    for dirpath, dirnames, filenames in os.walk(root):
        for name in dirnames + filenames:
            if (Path(dirpath) / name).is_symlink():
                raise SystemExit(f'refusing symlink: {Path(dirpath) / name}')


def stage(repo, out=None):
    repo = Path(repo)
    plugin, evals = repo / PLUGIN_REL, repo / 'evals'
    for source in (plugin, evals):
        if not source.is_dir():
            raise SystemExit(f'missing directory: {source}')
        reject_symlinks(source)
    if out is None:
        target = Path(tempfile.mkdtemp(prefix='setup-audit-eval-'))
    else:
        target = Path(out)
        if target.exists():
            raise SystemExit(f'--out already exists: {target}')
    shutil.copytree(plugin, target, dirs_exist_ok=True)
    shutil.copytree(evals, target / 'evals',
                    ignore=shutil.ignore_patterns('results', '__pycache__'))
    return target.resolve()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', help='staging directory to create (must not exist)')
    args = parser.parse_args(argv)
    staged = stage(REPO, args.out)
    quoted = shlex.quote(str(staged))
    print(f'staged: {staged}')
    print(f'run:    claude plugin eval {quoted} <your flags>  (paid; see evals/README.md)')
    print(f'results land in: {staged}/evals/results/')
    print(f'bring back: cp -r {quoted}/evals/results/. {shlex.quote(str(REPO / "evals/results"))}/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
