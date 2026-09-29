"""Static configuration checks: hook handler validation and fingerprints, cross-layer conflicts.

Pure functions over settings JSON and collector summaries. Stdlib only; never runs a hook.
Documentation baseline: https://code.claude.com/docs/en/hooks.md and
https://code.claude.com/docs/en/permissions.md, both fetched 2026-09-29.
"""
import hashlib
import json
import re
import warnings

DOCS_FETCHED = '2026-09-29'
DEFAULT, NARROW = 'default', 'narrow'
# hooks.md (fetched 2026-09-29), "Hook lifecycle" event table and "Matcher patterns":
# event -> (what the matcher filters, exact-match character set). (None, None) = "no matcher
# support"; there "If you add a `matcher` field to an event without matcher support, it is
# silently ignored." FileChanged and StopFailure use the narrower exact set (letters, digits, _, |).
HOOK_EVENTS = {
    'PreToolUse': ('tool name', DEFAULT),
    'PostToolUse': ('tool name', DEFAULT),
    'PostToolUseFailure': ('tool name', DEFAULT),
    'PermissionRequest': ('tool name', DEFAULT),
    'PermissionDenied': ('tool name', DEFAULT),
    'SessionStart': ('how the session started', DEFAULT),
    'Setup': ('which CLI flag triggered setup', DEFAULT),
    'SessionEnd': ('why the session ended', DEFAULT),
    'Notification': ('notification type', DEFAULT),
    'SubagentStart': ('agent type', DEFAULT),
    'SubagentStop': ('agent type', DEFAULT),
    'PreCompact': ('what triggered compaction', DEFAULT),
    'PostCompact': ('what triggered compaction', DEFAULT),
    'PreModelSwitch': ('model name', DEFAULT),
    'PostModelSwitch': ('model name', DEFAULT),
    'ConfigChange': ('configuration source', DEFAULT),
    'DirectoryAdded': ('how the directory was added', DEFAULT),
    'FileChanged': ('literal filenames to watch', NARROW),
    'StopFailure': ('error type', NARROW),
    'InstructionsLoaded': ('load reason', DEFAULT),
    'UserPromptExpansion': ('command name', DEFAULT),
    'Elicitation': ('MCP server name', DEFAULT),
    'ElicitationResult': ('MCP server name', DEFAULT),
    'CwdChanged': (None, None),
    'UserPromptSubmit': (None, None),
    'PostToolBatch': (None, None),
    'Stop': (None, None),
    'TeammateIdle': (None, None),
    'TaskCreated': (None, None),
    'TaskCompleted': (None, None),
    'WorktreeCreate': (None, None),
    'WorktreeRemove': (None, None),
    'MessageDisplay': (None, None),
}
TOOL_EVENTS = frozenset(e for e, (filters, _) in HOOK_EVENTS.items() if filters == 'tool name')
# hooks.md "Hook handler fields" (fetched 2026-09-29).
COMMON_FIELDS = frozenset({'type', 'if', 'timeout', 'statusMessage', 'once'})
TYPE_FIELDS = {
    'command': frozenset({'command', 'args', 'async', 'asyncRewake', 'shell'}),
    'http': frozenset({'url', 'headers', 'allowedEnvVars'}),
    'mcp_tool': frozenset({'server', 'tool', 'input'}),
    'prompt': frozenset({'prompt', 'model'}),
    'agent': frozenset({'prompt', 'model'}),
}
EXACT = {DEFAULT: re.compile(r'[A-Za-z0-9_\- ,|]*'), NARROW: re.compile(r'[A-Za-z0-9_|]*')}
# Constructs JavaScript accepts (or reads differently) where Python's re errors: not judged.
JS_DIVERGENT = re.compile(r'\(\?<(?![=!])|\\(?:[ceghijklmopqyzCEFGHIJKLMOPQRTVXY]|u(?![0-9A-Fa-f]{4})'
                          r'|x(?![0-9A-Fa-f]{2})|[UN1-9])')


def normalize_matcher(matcher):
    """Omitted, "" and "*" all match everything (hooks.md "Matcher patterns")."""
    return '*' if matcher is None or matcher in ('', '*') else matcher


def handler_fingerprint(event, matcher, handler):
    """First 16 hex of SHA-256 over event, normalized matcher and the whole handler (type defaulted)."""
    body = dict(handler)
    body.setdefault('type', 'command')
    text = json.dumps([event, normalize_matcher(matcher), body], sort_keys=True,
                      separators=(',', ':'), ensure_ascii=False, default=str)
    return hashlib.sha256(text.encode('utf-8', 'surrogatepass')).hexdigest()[:16]


def _matcher_issues(event, spec, matcher):
    if matcher is None or matcher in ('', '*'):
        return []
    if not isinstance(matcher, str):
        return ['matcher_not_string']
    filters, charset = spec
    if filters is None:
        return ['matcher_ignored']
    if EXACT[charset].fullmatch(matcher):
        parts = [p.strip() for p in re.split(r'[|,]' if charset == DEFAULT else r'\|', matcher)]
        if event in TOOL_EVENTS and any(p.startswith('mcp__') and '__' not in p[5:] for p in parts):
            return ['mcp_server_only_matcher']
        return []
    if event == 'FileChanged':
        return []  # the watch list reads segments as literal filenames (hooks.md "FileChanged")
    issues = []
    if charset == NARROW and EXACT[DEFAULT].fullmatch(matcher):
        issues.append('narrow_event_regex_path')
    if not JS_DIVERGENT.search(matcher):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                re.compile(matcher)
        except re.error:
            issues.append('invalid_regex')
    return issues


def handler_issues(event, matcher, handler):
    """(issues, unknown_fields) for one handler; see references/checklist.md HYG-hook-config."""
    spec = HOOK_EVENTS.get(event)
    issues = ['unknown_event'] if spec is None else _matcher_issues(event, spec, matcher)
    if spec is not None and 'if' in handler and event not in TOOL_EVENTS:
        issues.append('if_never_runs')
    kind = handler.get('type', 'command')
    unknown = []
    if kind not in TYPE_FIELDS:
        issues.append('unknown_type')
    else:
        unknown = sorted(str(k) for k in handler if k not in COMMON_FIELDS | TYPE_FIELDS[kind])[:10]
        if unknown:
            issues.append('unknown_fields')
    return issues, unknown
