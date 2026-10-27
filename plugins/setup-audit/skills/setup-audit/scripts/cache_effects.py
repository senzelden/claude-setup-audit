#!/usr/bin/env python3
"""Cache effect of a configuration change, from the Claude Code docs. Inform only.

Every row traces to a sentence in the raw docs fetched 2026-10-25:
  prompt-caching  docs page `prompt-caching`
  settings        docs page `settings` ("When edits take effect")
  permissions     docs page `permissions`
Anything not covered is `unknown`; this module never guesses. Nothing here gates a change:
callers print the effect next to each op and apply it regardless.

Effects:
  keeps                          the cached prefix is untouched
  invalidates_next_request       the next request re-reads the whole conversation uncached
  invalidates_without_tool_search  bare-name or tool-name-glob deny: keeps the cache while tool
                                 search is active (default on supported models), invalidates
                                 when it is off or unavailable; adding and removing alike
  applies_next_session           the edit does not reach the running session (key read once at
                                 start; MCP config until restart; CLAUDE.md until /clear,
                                 /compact or restart); the running cache is not touched
  unknown                        the docs do not say

Usage:
  cache_effects.py effect KIND KEY [--snapshot S]   # KIND: setting | rule-allow | rule-ask | rule-deny | file
  cache_effects.py estimate --snapshot S [--model M] [--ttl 5m|1h]
  cache_effects.py table
"""
import argparse
import json
import re
import sys

sys.dont_write_bytecode = True

DOCS_FETCHED = '2026-10-25'
PC = 'prompt-caching'
ST = 'settings'
PM = 'permissions'

EFFECTS = ('keeps', 'invalidates_next_request', 'invalidates_without_tool_search',
           'applies_next_session', 'unknown')

# family -> (effect, source, note). Sources name the page and section; the sentence each row
# rests on is in `note` (paraphrase) so a reader can find it.
ROWS = {
    'permission.allow_or_ask_rule': (
        'keeps', f'{PC} "Denying an entire tool"',
        'all allow and ask rules do not change which tools Claude sees; Claude Code checks them '
        'when Claude attempts a call'),
    'permission.deny_scoped_rule': (
        'keeps', f'{PC} "Denying an entire tool"; {PM}',
        'a scoped deny such as Bash(rm *) leaves the tool available and is checked at call time'),
    'permission.mcp_parenthesized_rule': (
        'unknown', f'{PM} "Match by input parameter"',
        'Claude Code skips any mcp__ rule with parentheses when it loads a settings file, so the '
        'rule has no effect and no cache effect; only --disallowedTools takes one'),
    'permission.deny_bare_tool_rule': (
        'invalidates_without_tool_search', f'{PC} "Denying an entire tool"; {PM}',
        'a bare tool name, the Bash(*) form or a tool-name glob like "*" or "mcp__*" removes the '
        'tool; with tool search active the definitions do not change and the prefix survives, '
        'otherwise the next request invalidates the cache, and so does removing the rule later'),
    'permission.mode_default': (
        'keeps', f'{PC} "Changing permission mode"',
        'permission mode does not change the system prompt or tool definitions (exception: '
        'plan mode with the opusplan model setting is a model switch)'),
    'permission.additional_directories': (
        'unknown', f'{ST} "When edits take effect"',
        'permission edits reload mid-session, but the prompt-caching page does not say whether '
        'directory entries touch the cached prefix'),
    'settings.model': (
        'applies_next_session', f'{ST} "When edits take effect"',
        'model is read once at session start; /model switches mid-session and invalidates the '
        'cache because each model has its own cache (prompt-caching "Switching models")'),
    'settings.effort': (
        'applies_next_session', f'{ST} "When edits take effect"',
        'effortLevel and modelSettings are read once at session start; /effort changes mid-session '
        '(prompt-caching "Changing effort level": keeps on Opus 5.5, Sonnet 5.5, Haiku 5.5, '
        'Fable 5.1 with an API key or subscription, invalidates on most other models)'),
    'settings.output_style': (
        'keeps', f'{PC} "Changing output style"',
        'a mid-session style switch is delivered as a conversation message'),
    'settings.sandbox': (
        'unknown', f'{ST} "When edits take effect"',
        'settings reload mid-session, but the prompt-caching page says nothing about sandbox keys'),
    'settings.hooks': (
        'unknown', f'{ST} "When edits take effect"',
        'hooks in settings files reload mid-session; the prompt-caching sentence that hooks never '
        'invalidate covers plugin hooks, not settings-file hooks'),
    'settings.env': (
        'unknown', f'{ST} "When edits take effect"',
        'the page lists no env behaviour; some variables are read once at start, which the docs '
        'do not enumerate'),
    'settings.prompt_cache_ttl': (
        'unknown', f'{PC} "Cache lifetime"',
        'the page names promptCacheTtl and subagentPromptCacheTtl but does not say when an edit '
        'applies to a running session'),
    'settings.enabled_plugins': (
        'unknown', f'{PC} "Enabling or disabling a plugin"',
        'depends on the plugin: its skills, commands, agents, hooks, monitors and themes keep the '
        'cache; plugin MCP servers follow the MCP rules; an LSP tool is added by code '
        'intelligence plugins'),
    'mcp.config': (
        'applies_next_session', f'{PC} "Connecting or removing an MCP server"',
        'editing MCP config does not by itself change the cache; the new config takes effect '
        'only after a restart (disabling a server in /mcp mid-session is a different action)'),
    'memory.claude_md': (
        'applies_next_session', f'{PC} "Editing CLAUDE.md mid-session"',
        'project-root and user-level CLAUDE.md are read once at start; editing keeps the cache '
        'but does not apply until /clear, /compact or restart'),
    'memory.auto_memory': (
        'applies_next_session', f'{PC} "How the cache is organized"',
        'the project context layer (CLAUDE.md, auto memory, unscoped rules) changes when the '
        'session starts or after /clear or /compact'),
    'file.other': (
        'unknown', PC, 'no sentence covers this file or key'),
}

# When an applies_next_session edit reaches the session. "restart": read once at session start
# (settings "When edits take effect"; MCP config, prompt-caching "Connecting or removing an MCP
# server"). "clear": project context layer, reloaded on /clear, /compact or restart (prompt-caching
# "Editing CLAUDE.md mid-session" and the layer table).
APPLIES_AT = {
    'settings.model': 'restart', 'settings.effort': 'restart', 'mcp.config': 'restart',
    'memory.claude_md': 'clear', 'memory.auto_memory': 'clear',
}
APPLIES_LABEL = {
    'restart': 'applies at the next session start (restart); keeps the running cache',
    'clear': 'applies after /clear, /compact or restart; keeps the running cache',
}

SANDBOX_PREFIX = 'sandbox.'
_BARE_TOOL = re.compile(r'^[A-Za-z_*?][\w.\-*?]*$')
_ALL_FORM = re.compile(r'^[A-Za-z_*?][\w.\-*?]*\(\*\)$')


def _row(family):
    effect, source, note = ROWS[family]
    row = {'effect': effect, 'family': family, 'source': source, 'note': note,
           'docs_fetched': DOCS_FETCHED}
    if family in APPLIES_AT:
        row['applies_at'] = APPLIES_AT[family]
    return row


def classify_rule(kind, rule):
    """kind: allow | ask | deny. A deny that names a tool (bare, Tool(*), or glob) removes it."""
    if isinstance(rule, str) and rule.strip().startswith('mcp__') and '(' in rule:
        return _row('permission.mcp_parenthesized_rule')
    if kind in ('allow', 'ask'):
        return _row('permission.allow_or_ask_rule')
    if not isinstance(rule, str) or not rule.strip():
        return _row('file.other')
    rule = rule.strip()
    if _ALL_FORM.match(rule) and rule.split('(')[0] not in ('Bash', 'PowerShell'):
        row = _row('permission.deny_bare_tool_rule')
        row['note'] += ('; the docs state that Tool(*) equals the bare name only for Bash and '
                        'PowerShell, so this classification is conservative')
        return row
    if _BARE_TOOL.match(rule) or _ALL_FORM.match(rule):
        return _row('permission.deny_bare_tool_rule')
    return _row('permission.deny_scoped_rule')


def classify_setting(key):
    """Settings-file key by dotted path."""
    if not isinstance(key, str):
        return _row('file.other')
    if key.startswith(SANDBOX_PREFIX) or key == 'sandbox':
        return _row('settings.sandbox')
    if key == 'model':
        return _row('settings.model')
    if key in ('effortLevel', 'modelSettings'):
        return _row('settings.effort')
    if key == 'outputStyle':
        return _row('settings.output_style')
    if key in ('permissions.defaultMode', 'defaultMode'):
        return _row('permission.mode_default')
    if key == 'permissions.additionalDirectories':
        return _row('permission.additional_directories')
    if key == 'hooks' or key.startswith('hooks.'):
        return _row('settings.hooks')
    if key == 'env' or key.startswith('env.'):
        return _row('settings.env')
    if key in ('promptCacheTtl', 'subagentPromptCacheTtl'):
        return _row('settings.prompt_cache_ttl')
    if key == 'enabledPlugins' or key.startswith('enabledPlugins.'):
        return _row('settings.enabled_plugins')
    if key in ('mcpServers', 'enabledMcpjsonServers', 'disabledMcpjsonServers', 'enableAllProjectMcpServers'):
        return _row('mcp.config')
    return _row('file.other')


def classify_file(name):
    """Instruction and memory files by basename or path fragment."""
    n = (name or '').replace('\\', '/')
    base = n.rsplit('/', 1)[-1]
    if base in ('CLAUDE.md', 'CLAUDE.local.md'):
        return _row('memory.claude_md')
    if base == 'MEMORY.md' or '/memory/' in n:
        return _row('memory.auto_memory')
    if base in ('.mcp.json', '.claude.json'):  # names an edited file from a transcript; never opened
        return _row('mcp.config')
    return _row('file.other')


def with_tool_search(row, tool_search=None):
    """Resolve invalidates_without_tool_search against the observed tool-search state.

    tool_search True: observed in the window; False: not observed; None: not known. Observation
    of deferred-tool records is evidence, not proof of the live session's state (observed,
    undocumented), so the label says "observed".
    """
    row = dict(row)
    if row['effect'] != 'invalidates_without_tool_search':
        row['label'] = row['effect'].replace('_', ' ')
        return row
    if tool_search is True:
        row['label'] = 'keeps the cache (tool search observed)'
    elif tool_search is False:
        row['label'] = ('may invalidate: no tool-search records seen in the window; tool search is '
                        'on by default on supported models')
    else:
        row['label'] = ('keeps the cache if tool search is active, invalidates if it is off '
                        '(not known from this run)')
    row['tool_search_observed'] = tool_search
    return row


LABELS = {
    'keeps': 'keeps the cache',
    'invalidates_next_request': 'invalidates the cache on the next request',
    'unknown': 'cache effect not documented',
}


def label_row(row, tool_search=None):
    row = with_tool_search(row, tool_search)
    if row['effect'] == 'applies_next_session':
        row['label'] = APPLIES_LABEL[row['applies_at']]
    elif row['effect'] in LABELS:
        row['label'] = LABELS[row['effect']]
    return row


def effect_for(kind, key, tool_search=None):
    """kind: setting | rule-allow | rule-ask | rule-deny | file."""
    if kind.startswith('rule-'):
        row = classify_rule(kind[5:], key)
    elif kind == 'setting':
        row = classify_setting(key)
    elif kind == 'file':
        row = classify_file(key)
    else:
        row = _row('file.other')
    return label_row(row, tool_search)


def load_signals(snapshot_path):
    """Signals from a snapshot as a dict; never raises (malformed input gives all None).

    tool_search: transcripts.tool_search_observed (bool or None); context_tokens: median cached
    context; ttl: '1h' when the majority of cache writes were 1-hour, else '5m' (None when no
    writes are known); model: top main-thread model of transcripts.request_params.
    """
    out = {'tool_search': None, 'context_tokens': None, 'ttl': None, 'model': None}
    if not snapshot_path:
        return out
    try:
        with open(snapshot_path) as f:
            t = json.load(f).get('transcripts')
        t = t if isinstance(t, dict) else {}
        obs = t.get('tool_search_observed')
        out['tool_search'] = obs if isinstance(obs, bool) else None
        cache = t.get('cache') if isinstance(t.get('cache'), dict) else {}
        ctx = (cache.get('context_tokens') or {}).get('median')
        if isinstance(ctx, (int, float)) and not isinstance(ctx, bool) and ctx >= 0:
            out['context_tokens'] = round(ctx)
        share = cache.get('write_1h_share')
        if isinstance(share, (int, float)) and not isinstance(share, bool):
            out['ttl'] = '1h' if share > 0.5 else '5m'
        rows = ((t.get('request_params') or {}).get('main') or {}).get('by_model')
        top = rows[0][0] if isinstance(rows, list) and rows and isinstance(rows[0], list) and rows[0] else None
        out['model'] = top if isinstance(top, str) else None
    except (OSError, ValueError, AttributeError, TypeError, IndexError, RecursionError):
        pass
    return out


def estimate_from(signals):
    """Estimate from load_signals output, or None without a context size."""
    if signals.get('context_tokens') is None:
        return None
    return estimate_reread(signals['context_tokens'], signals.get('ttl') or '5m', signals.get('model'))


# Multipliers on base input price, from references/checklist.md (prompt caching docs, fetched
# 2026-10-24): writes 1.25x (5-minute TTL) or 2x (1-hour); reads 0.1x, 0.05x on Opus 5.5 and
# Sonnet 5.5, 0.025x on Fable 5.1. No absolute prices are stored here.
WRITE_MULT = {'5m': 1.25, '1h': 2.0}
READ_MULT_BY_MODEL = (('opus-5-5', 0.05), ('sonnet-5-5', 0.05), ('fable-5-1', 0.025))
READ_MULT_DEFAULT = 0.1


def estimate_reread(context_tokens, ttl='5m', model=None):
    """Estimate of one full uncached re-read, in base-input-token equivalents. Not spend."""
    if (not isinstance(context_tokens, int) or isinstance(context_tokens, bool)
            or context_tokens < 0 or ttl not in WRITE_MULT):
        return None
    norm = (model or '').lower().replace('.', '-')
    read = next((m for frag, m in READ_MULT_BY_MODEL if frag in norm), READ_MULT_DEFAULT)
    write = WRITE_MULT[ttl]
    return {
        'estimate': True,
        'context_tokens': context_tokens,
        'ttl': ttl,
        'write_multiplier': write,
        'read_multiplier': read,
        'model_basis': 'matched' if any(f in norm for f, _ in READ_MULT_BY_MODEL) else 'default 0.1x read',
        'reread_cost_base_input_tokens': round(context_tokens * write),
        'normal_read_cost_base_input_tokens': round(context_tokens * read),
        'extra_cost_base_input_tokens': round(context_tokens * (write - read)),
        'note': ('Estimate, not measured spend: one full re-read costs about the cached context '
                 'at the cache-write multiplier instead of the read multiplier (checklist, '
                 'prompt caching docs fetched 2026-10-24). Units are base-input-token '
                 'equivalents; multiply by your model price. Output and the new message are '
                 'excluded.'),
    }


INFORM_ONLY = ('Cache effects are information only: apply never holds, refuses or delays a '
               'change because of them.')


def needs_estimate(row):
    return row['effect'] == 'invalidates_next_request' or (
        row['effect'] == 'invalidates_without_tool_search' and row.get('tool_search_observed') is not True)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('effect')
    e.add_argument('kind', choices=('setting', 'rule-allow', 'rule-ask', 'rule-deny', 'file'))
    e.add_argument('key')
    e.add_argument('--snapshot')
    s = sub.add_parser('estimate')
    s.add_argument('--snapshot')
    s.add_argument('--context-tokens', type=int)
    s.add_argument('--model')
    s.add_argument('--ttl', choices=sorted(WRITE_MULT), help='default: majority TTL of the snapshot, else 5m')
    sub.add_parser('table')
    a = ap.parse_args(argv)
    if a.cmd == 'table':
        print(json.dumps({'docs_fetched': DOCS_FETCHED, 'note': INFORM_ONLY,
                          'rows': {k: _row(k) for k in ROWS}}, indent=1))
        return 0
    sig = load_signals(a.snapshot)
    if a.cmd == 'effect':
        print(json.dumps(effect_for(a.kind, a.key, sig['tool_search']), indent=1))
        return 0
    ctx = a.context_tokens if a.context_tokens is not None else sig['context_tokens']
    est = estimate_reread(ctx, a.ttl or sig['ttl'] or '5m', a.model or sig['model'])
    print(json.dumps({'estimate': est, 'note': INFORM_ONLY}, indent=1))
    return 0 if est else 1


if __name__ == '__main__':
    sys.exit(main())
