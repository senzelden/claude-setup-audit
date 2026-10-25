#!/usr/bin/env python3
"""Failure loops: a turn that keeps repeating the same failing cycle. Detected after the fact.

A turn is the main-thread span from one real user prompt to the next (tool results, sidechain
records and system or meta records do not start one). Within a turn two loops are detected:

- repeat_error: one normalized Bash command whose tool_result is an error, REPEAT_ERROR_MIN or more
  times (permission denials and user rejections are not failures);
- edit_test: an Edit/Write/MultiEdit on one file followed by a failing test-like Bash command,
  EDIT_TEST_MIN or more times on the same file. A passing test run resets only the files edited since
  the previous test run; a denied, interrupted or background-launched run changes nothing.
  Only Edit/Write/MultiEdit are tracked: NotebookEdit and edits made through Bash (sed -i, heredocs)
  are invisible, and an edit whose own result is an error does not count.

Only counts, a command head (first token, strict identifier pattern) and the project key leave this
module; normalized commands and file paths are held in memory for one turn and never stored.
Inspired by TokenEconomizer's turn-duration redirect (microsoft/TokenEconomizer), but nothing here
intervenes at runtime. The transcript record shapes are observed, undocumented. Stdlib only.
"""
import hashlib
import re
from collections import Counter

REPEAT_ERROR_MIN = 3   # same failing command in one turn
EDIT_TEST_MIN = 3      # failing test runs after edits of the same file in one turn
KINDS = ('repeat_error', 'edit_test')
EDIT_TOOLS = ('Edit', 'Write', 'MultiEdit')
# Command heads leave the tracker only from this fixed list (test runners and common tools); anything
# else, including project, script and tool names, is `other`.
HEAD_ALLOW = frozenset('''
    pytest vitest jest go cargo python python3 py npm pnpm yarn npx bun bunx deno node make just mix rspec phpunit tox nox
    dotnet uv uvx pip pip3 rustc git gh docker kubectl bash sh zsh curl wget mkdir rm cp mv ls cat grep rg find sed awk jq
    tsc eslint prettier ruff mypy black flake8 pyright gradle mvn ant ruby bundle rake php composer java javac gcc clang
    cmake sudo timeout cd echo test head tail diff tar unzip chmod'''.split())
TOKEN_FIELDS = ('input_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens', 'output_tokens')
# Text that begins a record Claude Code writes as a "user" record without the user typing it.
NOT_A_PROMPT = ('<local-command', '<task-notification', '<system-reminder', '<command-message>',
                '[Request interrupted', 'Caveat:')

_LEADING = re.compile(r'\A\s*(?:(?:cd\s+\S+|[A-Za-z_][A-Za-z0-9_]*=\S*)\s*(?:&&|;)?\s*)+')
_TRAILING = re.compile(r'(?:\s*2>&1|\s*>\s*/dev/null|\s*\|\s*(?:tail|head|tee|grep|less|wc|cat)\b[^|;&]*)+\s*\Z')
_SPACE = re.compile(r'\s+')


def normalize_command(command):
    """Comparison key of a Bash command: drops a leading cd/VAR=value prefix and trailing output
    plumbing (2>&1, redirects to /dev/null, pipes into tail/head/tee/grep/...), collapses whitespace.
    Arguments otherwise stay: a different test selector is a different command."""
    text = command if isinstance(command, str) else ''
    text = _LEADING.sub('', text, count=1)
    text = _TRAILING.sub('', text)
    return _SPACE.sub(' ', text).strip()


def command_head(normalized, test_re):
    """The test runner (or else the first token) when it is on HEAD_ALLOW, else `other`."""
    match = test_re.search(normalized)
    token = (match.group(1) if match else (normalized.split(' ', 1)[0] if normalized else ''))
    token = token.split(' ', 1)[0]
    return token if token in HEAD_ALLOW else 'other'


def real_prompt(record):
    """True for a user record the person typed: main thread, not meta, no tool result inside."""
    if record.get('type') != 'user' or record.get('isSidechain') or record.get('isMeta'):
        return False
    if record.get('isCompactSummary') or record.get('isVisibleInTranscriptOnly') or 'toolUseResult' in record:
        return False
    msg = record.get('message')
    content = msg.get('content') if isinstance(msg, dict) else record.get('content')
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        if any(isinstance(b, dict) and b.get('type') == 'tool_result' for b in content):
            return False
        text = ''.join(b.get('text', '') for b in content
                       if isinstance(b, dict) and b.get('type') == 'text' and isinstance(b.get('text'), str))
        if not text.strip():
            return False
    else:
        return False
    return bool(text.strip()) and not text.lstrip().startswith(NOT_A_PROMPT)


def _text(content):
    if isinstance(content, list):
        content = ' '.join(b['text'] for b in content if isinstance(b, dict) and isinstance(b.get('text'), str))
    return content if isinstance(content, str) else ''


def _interrupted(item, record):
    """A result of an interrupted run or a background launch notice (observed, undocumented shapes)."""
    summary = record.get('toolUseResult') if isinstance(record, dict) else None
    if isinstance(summary, dict) and (summary.get('interrupted') is True or summary.get('backgroundTaskId')):
        return True
    return _text(item.get('content')).lstrip().startswith(('[Request interrupted', 'Command running in background'))


def _usage_total(usage):
    return sum(v for k in TOKEN_FIELDS if type(v := usage.get(k)) is int)


class LoopTracker:
    """Feed the in-window records of one main-thread transcript file in order; read `.turns` after
    `finish()`. Each finished turn is a dict: tokens, kinds (repeats per kind, only looping kinds)
    and heads (one head per looping command or file)."""

    def __init__(self, is_denial, test_re):
        self.is_denial, self.test_re = is_denial, test_re
        self.turns = []
        self.seen_tools, self.seen_msgs = set(), set()
        self._open = None

    def _begin(self):
        self._close()
        self._open = {'tokens': 0, 'calls': {}, 'edits': {}, 'fails': Counter(), 'cycles': Counter(), 'pending': set(),
                      'heads': {}}

    def _close(self):
        turn, self._open = self._open, None
        if turn is None:
            return
        kinds, heads = {}, []
        repeats = [n for n in turn['fails'].values() if n >= REPEAT_ERROR_MIN]
        if repeats:
            kinds['repeat_error'] = max(repeats)
            heads += [turn['heads'][('cmd', c)] for c, n in turn['fails'].items() if n >= REPEAT_ERROR_MIN]
        cycles = [n for n in turn['cycles'].values() if n >= EDIT_TEST_MIN]
        if cycles:
            kinds['edit_test'] = max(cycles)
            heads += [turn['heads'][('file', f)] for f, n in turn['cycles'].items() if n >= EDIT_TEST_MIN]
        self.turns.append({'tokens': turn['tokens'], 'kinds': kinds, 'heads': sorted(heads)})

    def finish(self):
        self._close()

    def feed(self, record):
        if real_prompt(record):
            self._begin()
            return
        turn = self._open
        if turn is None or record.get('isSidechain'):
            return
        msg = record.get('message') if isinstance(record.get('message'), dict) else {}
        if record.get('type') == 'assistant':
            usage = msg.get('usage')
            mid = msg.get('id') if isinstance(msg.get('id'), str) else None  # a list/dict id is unhashable
            if isinstance(usage, dict) and (mid is None or mid not in self.seen_msgs):
                self.seen_msgs.add(mid)
                turn['tokens'] += _usage_total(usage)
        items = msg.get('content')
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                if item.get('type') == 'tool_use':
                    self._call(turn, item)
                elif item.get('type') == 'tool_result':
                    self._result(turn, item, record)

    def _call(self, turn, item):
        tid, name, args = item.get('id'), item.get('name'), item.get('input')
        args = args if isinstance(args, dict) else {}
        if isinstance(tid, str) and tid:
            if tid in self.seen_tools:
                return
            self.seen_tools.add(tid)
        if name in EDIT_TOOLS and isinstance(tid, str) and isinstance(args.get('file_path'), str) and args['file_path']:
            turn['edits'][tid] = args['file_path']  # pending only once its own result is not an error
        elif name == 'Bash' and isinstance(tid, str) and isinstance(args.get('command'), str):
            norm = normalize_command(args['command'])
            if norm:
                # The comparison key is a digest: long commands never merge, and no text is kept.
                key = hashlib.sha256(norm.encode('utf-8', 'replace')).hexdigest()
                turn['calls'][tid] = (key, bool(self.test_re.search(norm)), command_head(norm, self.test_re),
                                      args.get('run_in_background') is True)

    def _result(self, turn, item, record=None):
        tid = item.get('tool_use_id')
        if not isinstance(tid, str):
            return
        path = turn['edits'].pop(tid, None)
        if path is not None:
            if item.get('is_error') is not True:
                turn['pending'].add(path)
            return
        call = turn['calls'].pop(tid, None)
        if call is None:
            return
        key, is_test, head, background = call
        error = item.get('is_error') is True
        if error and self.is_denial(item.get('content')):
            return  # a permission answer says nothing about the command
        if _interrupted(item, record) or (background and not error):
            return  # no verdict: neither a failure nor a pass
        if error:
            turn['fails'][key] += 1
            turn['heads'][('cmd', key)] = head
        if not is_test:
            return
        failed = error
        for path in turn['pending']:
            if failed:
                turn['cycles'][path] += 1
                turn['heads'][('file', path)] = head
            else:
                turn['cycles'].pop(path, None)
        turn['pending'] = set()


def summarize(per_session):
    """Aggregate [(project_key, [turn, ...]), ...] into the snapshot block (counts only)."""
    out = {'turns_scanned': 0, 'turns_with_loop': 0, 'sessions_scanned': 0, 'sessions_with_loop': 0,
           'by_kind': {k: 0 for k in KINDS}, 'max_repeats': {k: 0 for k in KINDS},
           'tokens_scanned': 0, 'tokens_in_loop_turns': 0}
    projects, heads = {}, Counter()
    for key, turns in per_session:
        if not turns:
            continue
        out['sessions_scanned'] += 1
        row = projects.setdefault(key, {'turns': 0, 'loop_turns': 0, 'tokens': 0})
        looped = False
        for t in turns:
            out['turns_scanned'] += 1
            out['tokens_scanned'] += t['tokens']
            row['turns'] += 1
            if not t['kinds']:
                continue
            looped = True
            out['turns_with_loop'] += 1
            out['tokens_in_loop_turns'] += t['tokens']
            row['loop_turns'] += 1
            row['tokens'] += t['tokens']
            for kind, repeats in t['kinds'].items():
                out['by_kind'][kind] += 1
                out['max_repeats'][kind] = max(out['max_repeats'][kind], repeats)
            heads.update(t['heads'])
        out['sessions_with_loop'] += looped
    out['by_project'] = {k: v for k, v in sorted(projects.items()) if v['loop_turns']}
    out['command_heads'] = dict(sorted(heads.items(), key=lambda kv: (-kv[1], kv[0]))[:HEAD_LIMIT])
    out['thresholds'] = {'repeat_error_min': REPEAT_ERROR_MIN, 'edit_test_min': EDIT_TEST_MIN}
    out['basis'] = ('Main-thread turns from a real user prompt to the next; observed, undocumented record shapes. '
                    'Tokens are the turn\'s main-thread assistant usage (input, cache and output, once per message id); '
                    'subagent work inside a turn is not attributed. Plugin-spawned sessions are excluded. '
                    'This block is built from the bounded transcript scan (most recent files first); the ledger '
                    'failure_loops selector scans every main transcript in the window, so do not compare the two. '
                    'Command text and file paths are not stored.')
    return out


HEAD_LIMIT = 15
