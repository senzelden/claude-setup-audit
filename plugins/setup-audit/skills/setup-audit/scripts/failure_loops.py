#!/usr/bin/env python3
"""Failure loops: a turn that keeps repeating the same failing cycle. Detected after the fact.

A turn is the main-thread span from one real user prompt to the next (tool results, sidechain
records and system or meta records do not start one). Within a turn two loops are detected:

- repeat_error: one normalized Bash command whose tool_result is an error, REPEAT_ERROR_MIN or more
  times (permission denials and user rejections are not failures);
- edit_test: an Edit/Write/MultiEdit on one file followed by a failing test-like Bash command,
  EDIT_TEST_MIN or more times on the same file, with no passing test run in between.

Only counts, a command head (first token, strict identifier pattern) and the project key leave this
module; normalized commands and file paths are held in memory for one turn and never stored.
Inspired by TokenEconomizer's turn-duration redirect (microsoft/TokenEconomizer), but nothing here
intervenes at runtime. The transcript record shapes are observed, undocumented. Stdlib only.
"""
import re
from collections import Counter

REPEAT_ERROR_MIN = 3   # same failing command in one turn
EDIT_TEST_MIN = 3      # failing test runs after edits of the same file in one turn
KINDS = ('repeat_error', 'edit_test')
EDIT_TOOLS = ('Edit', 'Write', 'MultiEdit')
COMMAND_CAP = 500      # characters of a normalized command that distinguish it
HEAD_RE = re.compile(r'[a-z][a-z0-9_+-]{0,23}(?:\.\d{1,3}){0,2}\Z')  # no path, no file extension
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
    return _SPACE.sub(' ', text).strip()[:COMMAND_CAP]


def command_head(normalized, test_re):
    """First token (or test runner) when it matches a strict identifier pattern, else `other`."""
    match = test_re.search(normalized)
    token = (match.group(1) if match else (normalized.split(' ', 1)[0] if normalized else ''))
    token = token.split(' ', 1)[0]
    return token if HEAD_RE.match(token) else 'other'


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
        self._open = {'tokens': 0, 'calls': {}, 'fails': Counter(), 'cycles': Counter(), 'pending': set(),
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
            if isinstance(usage, dict) and (msg.get('id') is None or msg['id'] not in self.seen_msgs):
                self.seen_msgs.add(msg.get('id'))
                turn['tokens'] += _usage_total(usage)
        items = msg.get('content')
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                if item.get('type') == 'tool_use':
                    self._call(turn, item)
                elif item.get('type') == 'tool_result':
                    self._result(turn, item)

    def _call(self, turn, item):
        tid, name, args = item.get('id'), item.get('name'), item.get('input')
        args = args if isinstance(args, dict) else {}
        if isinstance(tid, str) and tid:
            if tid in self.seen_tools:
                return
            self.seen_tools.add(tid)
        if name in EDIT_TOOLS and isinstance(args.get('file_path'), str) and args['file_path']:
            turn['pending'].add(args['file_path'])
        elif name == 'Bash' and isinstance(tid, str) and isinstance(args.get('command'), str):
            norm = normalize_command(args['command'])
            if norm:
                turn['calls'][tid] = (norm, bool(self.test_re.search(norm)))

    def _result(self, turn, item):
        call = turn['calls'].pop(item.get('tool_use_id'), None)
        if call is None:
            return
        norm, is_test = call
        failed = item.get('is_error') is True and not self.is_denial(item.get('content'))
        head = command_head(norm, self.test_re)
        if failed:
            turn['fails'][norm] += 1
            turn['heads'][('cmd', norm)] = head
        if not is_test:
            return
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
                    'Command text and file paths are not stored.')
    return out


HEAD_LIMIT = 15
