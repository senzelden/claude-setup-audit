"""Bounded, read-only instruction inventory. Discovered content is never executed.

Only fixed inventory locations are opened; imports and symlinks are recorded, not followed.
This describes candidate sources, not the running session's effective context.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess

MAX_BYTES = 32768
MAX_FILES = 200
MAX_DIRS = 500
SKIP = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build', 'vendor', 'target'}
FRONTMATTER_KEYS = {'name', 'description', 'when_to_use', 'paths', 'allowed-tools', 'disallowed-tools',
                    'disable-model-invocation', 'user-invocable', 'context', 'agent', 'model', 'hooks'}


def source(path, scope, status, **kw):
    return dict(source=str(path), scope=scope, status=status, **kw)


def read_text(path, limit=MAX_BYTES):
    """Return bounded text and collection metadata, without following file symlinks."""
    path = Path(path)
    info = {}
    try:
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            return None, dict(status='not_checked', reason='symlink_not_followed')
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode):
                return None, dict(status='unavailable', reason='not_regular_file')
            raw = stream.read(limit + 1)
        truncated = len(raw) > limit
        info.update(status='partial' if truncated else 'collected', bytes_read=min(len(raw), limit),
                    file_bytes=st.st_size, truncated=truncated)
        return raw[:limit].decode('utf-8'), info
    except FileNotFoundError:
        return None, dict(status='absent')
    except (OSError, UnicodeError):
        return None, dict(status='unavailable', reason='read_failed')


def frontmatter(text):
    """Extract selected YAML fields as text, not a YAML evaluator or an effective value parser."""
    if not text.startswith('---\n'):
        return {}, 'absent'
    end = re.search(r'^---\s*$', text[4:], re.M)
    if end is None:
        return {}, 'incomplete'
    block = text[4:4 + end.start()]
    result, key = {}, None
    for line in block.splitlines():
        match = re.match(r'^([\w-]+):\s*(.*)$', line)
        if match:
            key = match[1] if match[1] in FRONTMATTER_KEYS else None
            if key:
                result[key] = match[2]
        elif key and (line.startswith((' ', '\t')) or not line.strip()):
            result[key] += '\n' + line
        else:
            key = None
    return result, 'selected_text_only'


def git_context(cwd):
    result = dict(session_cwd=os.path.abspath(cwd), worktree_root=None, main_checkout=None)
    try:
        proc = subprocess.run(['git', '-C', cwd, 'rev-parse', '--path-format=absolute',
                               '--show-toplevel', '--git-common-dir'], capture_output=True,
                              text=True, timeout=5)
        lines = proc.stdout.splitlines()
        if proc.returncode == 0 and len(lines) == 2:
            result['worktree_root'] = lines[0]
            if lines[1].endswith(os.sep + '.git'):
                result['main_checkout'] = os.path.dirname(lines[1])
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def collect_instructions(home, claude, roots, contexts, managed_dir, redact, summarize_settings=None):
    entries, sources, seen = [], [], set()
    exhausted = False

    def add(path, scope, kind, relation):
        nonlocal exhausted
        path = os.path.abspath(path)
        if path in seen:
            return
        seen.add(path)
        if len(entries) >= MAX_FILES:
            exhausted = True
            return
        text, info = read_text(path)
        if info['status'] == 'absent':
            return
        entry = source(path, scope, **info, kind=kind, relation=relation, active_state='unknown')
        if text is not None:
            fm, parse = frontmatter(text)
            entry.update(frontmatter={k: redact(v) for k, v in fm.items()}, frontmatter_status=parse,
                         excerpt=redact(text), excerpt_start_line=1,
                         estimated_tokens=len(text) // 4, estimate_basis='collected_chars/4')
            # Import candidates are evidence only. Do not read arbitrary paths in source text.
            entry['imports_followed'] = False
        entries.append(entry)

    def walk(base, scope, only_rules=False):
        visited = 0
        info = source(base, scope, 'collected', directories_scanned=0)
        if os.path.islink(base):
            sources.append(source(base, scope, 'not_checked', reason='symlink_not_followed'))
            return
        if not os.path.isdir(base):
            sources.append(source(base, scope, 'absent' if not os.path.lexists(base) else 'unavailable'))
            return
        def error(_):
            info.update(status='partial', reason='directory_read_failed')
        for directory, dirs, files in os.walk(base, followlinks=False, onerror=error):
            visited += 1
            if visited > MAX_DIRS or exhausted:
                info.update(status='partial', reason='scan_limit')
                break
            kept = []
            for name in sorted(dirs):
                path = os.path.join(directory, name)
                if name in SKIP:
                    continue
                if os.path.islink(path):
                    sources.append(source(path, scope, 'not_checked', reason='symlink_not_followed'))
                else:
                    kept.append(name)
            dirs[:] = kept
            for name in sorted(files):
                path = os.path.join(directory, name)
                parts = Path(path).parts
                if only_rules or ('.claude' in parts and 'rules' in parts[parts.index('.claude') + 1:]):
                    if name.endswith('.md'):
                        add(path, scope, 'rule', 'conditional_or_directory')
                elif name in ('CLAUDE.md', 'CLAUDE.local.md'):
                    add(path, scope, 'instruction', 'directory')
                elif name == 'SKILL.md' and 'skills' in parts:
                    add(path, scope, 'skill', 'on_invocation')
        info['directories_scanned'] = min(visited, MAX_DIRS)
        sources.append(info)

    add(os.path.join(claude, 'CLAUDE.md'), 'user', 'instruction', 'user')
    walk(os.path.join(claude, 'rules'), 'user', True)
    walk(os.path.join(claude, 'skills'), 'user')
    if managed_dir:
        add(os.path.join(managed_dir, 'CLAUDE.md'), 'managed', 'instruction', 'managed')
    for root in sorted(set(roots)):
        walk(root, 'project')
    for context in contexts:
        # Ancestor instruction files influence this cwd. Do not scan sibling repositories.
        for parent in Path(context['session_cwd']).parents:
            for rel in ('CLAUDE.md', 'CLAUDE.local.md', '.claude/CLAUDE.md'):
                add(parent / rel, 'ancestor', 'instruction', context['session_cwd'])
    settings = []
    if summarize_settings:
        candidates = set()
        for context in contexts:
            for name in ('settings.json', 'settings.local.json'):
                candidates.add(os.path.join(context['session_cwd'], '.claude', name))
            if context['main_checkout']:
                candidates.add(os.path.join(context['main_checkout'], '.claude', 'settings.local.json'))
        for path in sorted(candidates):
            text, info = read_text(path)
            if text is not None and not info.get('truncated'):
                try:
                    data = json.loads(text)
                    if not isinstance(data, dict):
                        raise ValueError()
                    settings.append(summarize_settings(path, data=data))
                except (ValueError, TypeError, AttributeError, KeyError):
                    info.update(status='unavailable', reason='invalid_settings')
            sources.append(source(path, 'session_settings_candidate', **info))
    if exhausted:
        sources.append(source('instruction files', 'all_collected_scopes', 'partial', reason='file_limit'))
    sources.extend(source(e['source'], e['scope'], e['status'], kind=e['kind']) for e in entries)
    return dict(entries=entries, sources=sources, contexts=contexts, settings_candidates=settings,
                limitations=['Imports, symlink targets, runtime exclusions and actual loading are unverified.',
                             'Project walks skip build/dependency directories and stop at 500 directories or 200 files.'])
