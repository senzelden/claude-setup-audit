"""Plugin runtime footprint: what plugins do outside their own files. Read-only, stdlib only.

Two kinds of signal. Generic ones need no plugin table: hook handlers that decide permissions or
rewrite tool input, injected-context size, suspicious hook timeouts. A small dated table of ROBUST
fingerprints (a file or key a plugin writes under a documented name) attributes the rest. Nothing
here executes a plugin, a hook or a script; scripts are read as bounded text.

Fingerprints below come from docs/research/2026-10-25-plugin-side-effects.md (survey of plugin
sources, 2026-10-25). Anything weaker than a named file or key is deliberately not here.
Hook semantics: docs page `hooks`, fetched 2026-10-25 (PreToolUse
`permissionDecision` and `updatedInput`, PermissionRequest decision control, 10,000-character
output cap, `timeout` in seconds).
"""
import glob
import json
import os
import re
import shlex
import stat

import harness

FINGERPRINTS_DATED = '2026-10-25'

# --- TokenEconomizer ledger ------------------------------------------------------------------
# microsoft/TokenEconomizer denylist.py:170-200 records every bare-name permissions.deny rule it
# wrote in `<home>/**/untool_applied.json`: {"by_path": {"<realpath of settings file>": [rule, ...]},
# "kept": {...}} (older: {"tools": [...], "path": "..."}). The tool honours $TOKENECONOMIZER_HOME;
# environment values are not collected, so only the default directory is read.
LEDGER_PLUGIN = 'TokenEconomizer'
LEDGER_DIR = '.tokeneconomizer'
LEDGER_FILE = 'untool_applied.json'
LEDGER_DEPTH, LEDGER_FILES, LEDGER_BYTES, LEDGER_RULES = 4, 50, 256 * 1024, 200
RULE_CAP = 120

# --- quartermaster marker ----------------------------------------------------------------------
# Eigenwise/eigenwise-toolshed lib/permission-allowlist.js:12,68-83: opt-in automatic allow
# appends in settings.local.json, switched on by this top-level key. Its rules are not attributable.
MARKERS = (('quartermaster.autoApprovePermissions', 'quartermaster', 'autoApprovePermissions'),)

# --- known state files (presence only; contents are never read) ----------------------------------
# name -> (scope, relative path or glob under the project's .claude/ directory, or under ~/.claude/).
STATE_FILES = (
    ('ralph-loop', 'project', 'ralph-loop.local.md'),
    ('hookify', 'project', 'hookify.*.local.md'),
    ('auto-memory', 'project', os.path.join('auto-memory', 'config.json')),
    ('autoharness', 'project', 'autoharness'),
    ('claude-hud', 'global', os.path.join('plugins', 'claude-hud')),
)

# --- spawned sessions --------------------------------------------------------------------------
# claude-mem (thedotmack/claude-mem src/shared/paths.ts:26,70) runs observer Claude sessions with
# the working directory `~/.claude-mem/observer-sessions/<id>`. Transcripts and history record the
# working directory, so the label is observable. Env-var and flag fingerprints (remember's
# REMEMBER_NESTED_SUMMARIZER, autoharness `claude -p --fork-session`) leave no trace in the files
# the collector reads, so they are not attributed (references/coverage.md).
SPAWN_DIRS = (('claude-mem', os.path.join('.claude-mem', 'observer-sessions')),)


def _read_regular(path, limit):
    """Bytes of a regular, non-symlink file up to limit+1, or None; a FIFO must not stall the read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as f:
            if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                return None
            return f.read(limit + 1)
    except OSError:
        return None


def _ledger_files(base):
    """Ledger files under base: bounded depth and count, symlinks never followed. (paths, truncated)."""
    found, truncated = [], False
    stack = [(base, 0)]
    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue
        for e in entries:
            try:
                if e.is_symlink():
                    continue
                if e.is_dir(follow_symlinks=False):
                    if depth + 1 <= LEDGER_DEPTH:
                        stack.append((e.path, depth + 1))
                    else:
                        truncated = True
                elif e.name == LEDGER_FILE and e.is_file(follow_symlinks=False):
                    if len(found) >= LEDGER_FILES:
                        truncated = True
                    else:
                        found.append(e.path)
            except OSError:
                continue
    return sorted(found), truncated


def _rules(value):
    """Rule strings of a ledger list value; anything else is dropped."""
    if not isinstance(value, list):
        return []
    return [r[:RULE_CAP] for r in value if isinstance(r, str) and r][:LEDGER_RULES]


def read_ledger(home):
    """Rules TokenEconomizer says it wrote, keyed by realpath of the settings file.

    {'status': 'absent' | 'collected' | 'partial', 'files': n, 'unreadable': n, 'by_path': {path: [rules]}}.
    Names of tools only; no other ledger field is read.
    """
    base = os.path.join(home, LEDGER_DIR)
    out = {'status': 'absent', 'files': 0, 'unreadable': 0, 'by_path': {}}
    if not os.path.isdir(base) or os.path.islink(base):
        return out
    paths, truncated = _ledger_files(base)
    out['status'] = 'partial' if truncated else 'collected'
    for path in paths:
        raw = _read_regular(path, LEDGER_BYTES)
        try:
            data = json.loads(raw) if raw is not None and len(raw) <= LEDGER_BYTES else None
        except (ValueError, RecursionError):  # deeply nested arrays raise RecursionError
            data = None
        if not isinstance(data, dict):
            out['unreadable'] += 1
            continue
        out['files'] += 1
        pairs = []
        if isinstance(data.get('by_path'), dict):
            pairs = [(k, _rules(v)) for k, v in data['by_path'].items() if isinstance(k, str)]
        elif isinstance(data.get('path'), str):
            pairs = [(data['path'], _rules(data.get('tools')))]
        for key, rules in pairs:
            if '\0' in key or not os.path.isabs(key):  # realpath raises on NUL; a relative key names no file
                out['unreadable'] += 1
                out['status'] = 'partial'
                continue
            have = out['by_path'].setdefault(os.path.realpath(key), [])
            have.extend(r for r in rules if r not in have)
    if out['unreadable']:
        out['status'] = 'partial'
    return out


def written_rules(ledger, settings_path, deny):
    """plugin_written_rules entries for one settings file: [{plugin, list, rules, rule_count, ledger_only}].

    `rules` are the ledger rules present in the file's deny list; `ledger_only` counts the ledger's
    rules the file no longer holds (the user removed them). Empty when the ledger does not list the file.
    """
    listed = ledger['by_path'].get(os.path.realpath(settings_path))
    if listed is None:
        return []
    present = [r for r in listed if r in set(deny)]
    return [{'plugin': LEDGER_PLUGIN, 'list': 'deny', 'rules': present, 'rule_count': len(present),
             'ledger_only': len(listed) - len(present)}]


def markers(raw):
    """Plugin marker keys present in a settings object (key paths from the table, never values)."""
    found = []
    for name, top, key in MARKERS:
        block = raw.get(top) if isinstance(raw, dict) else None
        if isinstance(block, dict) and block.get(key) is True:
            found.append(name)
    return found


def state_files(directory, scope):
    """{name: True} for known plugin state files present in a `.claude` directory; presence only."""
    found = {}
    for name, where, rel in STATE_FILES:
        if where != scope:
            continue
        present = (bool(glob.glob(os.path.join(glob.escape(directory), rel))) if '*' in rel
                   else os.path.lexists(os.path.join(directory, rel)))
        if present:
            found[name] = True
    return found


def spawn_label(path, home):
    """Label of a plugin-spawned session from its working directory (or project path), else None."""
    if not isinstance(path, str) or not path:
        return None
    path = os.path.normpath(os.path.expanduser(path)) if path.startswith('~') else os.path.normpath(path)
    for label, rel in SPAWN_DIRS:
        root = os.path.join(os.path.normpath(home), rel)
        if path == root or path.startswith(root + os.sep):
            return label
    return None


def spawn_label_for_key(key, home):
    """Same, for a dash-encoded transcript directory name (non-alphanumerics become `-`)."""
    for label, rel in SPAWN_DIRS:
        prefix = re.sub(r'[^A-Za-z0-9]', '-', os.path.join(os.path.normpath(home), rel))
        if key == prefix or key.startswith(prefix + '-'):
            return label
    return None


# --- hook handlers that decide permissions or rewrite input ------------------------------------
SCAN_BYTES = 64 * 1024
# Heuristic text patterns. `permissionDecision` followed by quotes, colon or escaped quotes, then
# allow|deny (a `permissionDecisionReason` key does not match); `updatedInput` as a word.
DECISION_RE = re.compile(r'permissionDecision[\\"\'\s:=]{1,12}(allow|deny)\b')
# Other documented ways a PreToolUse hook decides (hooks.md, fetched 2026-10-25): the deprecated top-level
# `"decision": "approve"|"block"` and exit code 2, which blocks the tool call ("Exit code 2 behavior per event").
LEGACY_DECISION_RE = re.compile(r'(?<![A-Za-z])decision[\\"\'\s:=\]]{1,12}(approve|block)\b')
EXIT_TWO_RE = re.compile(r'(?<![A-Za-z0-9])_?exit\s*\(?\s*2(?![\d>])')
CD_ROOT_RE = re.compile(r'\bcd\s+["\']?\$\{?CLAUDE_PLUGIN_ROOT\}?["\']?\s*(?:&&|;)')
SCRIPT_SUFFIXES = ('.sh', '.bash', '.js', '.mjs', '.cjs', '.ts', '.py', '.rb', '.pl')
REWRITE_RE = re.compile(r'\bupdatedInput\b')
SCAN_EVENTS = ('PreToolUse', 'PermissionRequest')


def _scan_text(text):
    decides = rewrites = False
    for line in text.splitlines():
        if line.lstrip().startswith(('#', '//')):
            continue
        decides = (decides or DECISION_RE.search(line) is not None or LEGACY_DECISION_RE.search(line) is not None
                   or EXIT_TWO_RE.search(line) is not None)
        rewrites = rewrites or REWRITE_RE.search(line) is not None
    return decides, rewrites


def _relative_scripts(command, root):
    """Script paths written relative to the plugin root, only after `cd "$CLAUDE_PLUGIN_ROOT" &&` (or `;`)."""
    expanded = command
    for var in harness.ROOT_VARS:
        expanded = expanded.replace(var, '%ROOT%')
    if not CD_ROOT_RE.search(expanded.replace('%ROOT%', '$CLAUDE_PLUGIN_ROOT')):
        return []
    try:
        tokens = shlex.split(expanded.replace('%ROOT%', root))
    except ValueError:
        return []
    return [os.path.join(root, t) for t in tokens
            if t and not t.startswith(('-', '/')) and t.lower().endswith(SCRIPT_SUFFIXES)]


def hook_effects(event, handler, root):
    """Heuristic effect flags of one plugin hook handler; never runs it.

    Returns a dict with `decides_permissions`, `rewrites_input` (only when true), `decision_basis`
    ('permission_request_event' | 'static_scan'), `decision_file` (plugin-relative script that matched)
    and `scan_gap` ('script_unresolved' |
    'script_truncated') when a script the command names could not be read in full. A PermissionRequest
    handler decides by definition; for PreToolUse the command line and the plugin-local scripts it
    names are scanned for `permissionDecision` allow/deny and `updatedInput`. Files outside the plugin
    root, symlinks and non-regular files are never read; sourced or nested scripts are not followed.
    """
    out = {}
    if event not in SCAN_EVENTS or not isinstance(handler, dict) or not root:
        return out
    if event == 'PermissionRequest':
        out.update(decides_permissions=True, decision_basis='permission_request_event')
    if handler.get('type', 'command') != 'command' or not isinstance(handler.get('command'), str):
        return out
    command = handler['command']
    texts, gap = [(None, command)], None
    candidates = list(harness._script_paths(command, root))
    candidates += _relative_scripts(command, root)
    for raw in candidates:
        path = os.path.abspath(raw)
        if not harness._inside(path, root) or not os.path.isfile(path):
            gap = gap or 'script_unresolved'
            continue
        data = _read_regular(path, SCAN_BYTES)
        if data is None:
            gap = gap or 'script_unresolved'
            continue
        if len(data) > SCAN_BYTES:
            gap = 'script_truncated'
        texts.append((os.path.relpath(path, root), data[:SCAN_BYTES].decode('utf-8', errors='replace')))
    decides = rewrites = False
    evidence = None  # the first plugin-relative file whose text matched
    for name, text in texts:
        d, r = _scan_text(text)
        if (d or r) and evidence is None:
            evidence = name
        decides, rewrites = decides or d, rewrites or r
    if decides and event == 'PreToolUse':
        out.update(decides_permissions=True, decision_basis='static_scan')
    if rewrites:
        out['rewrites_input'] = True
        out.setdefault('decision_basis', 'static_scan')
    if evidence and ('decision_basis' in out or rewrites):
        out['decision_file'] = evidence
    if not candidates and not decides and not rewrites:
        gap = 'no_local_script'  # e.g. `npx -y pkg hook`: nothing of this hook's logic was readable
    if gap:
        out['scan_gap'] = gap
    return out
