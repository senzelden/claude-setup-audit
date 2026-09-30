"""Privacy helpers: contextual secret detection (both modes) and metadata-only masking. Stdlib only."""
import math
import re
from collections import Counter

CONTEXT_TOKEN = '[REDACTED:context]'
CONTEXT_MIN_LEN, CONTEXT_MAX_LEN, PASSWORD_MIN_LEN, ENTROPY_MIN = 16, 512, 6, 3.5
PASSWORD_WORDS = {'password', 'passwd', 'pwd', 'passphrase', 'pass'}
SECRET_WORDS = {'key', 'secret', 'token', 'auth', 'credential', 'credentials', 'creds', 'signature',
                'sig', 'cookie', 'session', 'pat', 'apikey'}
QUALIFIERS = {'id', 'ids', 'name', 'names', 'file', 'path', 'dir', 'url', 'uri', 'env', 'var', 'type',
              'kind', 'format', 'count', 'len', 'length', 'size', 'max', 'min', 'limit', 'ttl', 'sha',
              'hash', 'digest', 'commit', 'rev', 'checksum', 'fingerprint', 'etag', 'hint', 'header',
              'field', 'prefix', 'mode', 'source', 'ref', 'version', 'expiry', 'expires', 'public',
              'provider', 'method', 'storage', 'primary', 'foreign', 'sort', 'partition'}
VALUE_CHARS = r'A-Za-z0-9+/_.~=-'
CONTEXT_RE = re.compile(
    r'(?<![\w.-])(?:(?P<flag>--?[A-Za-z][\w.-]{0,63})(?:\s+|=)'
    r'|(?P<label>[A-Za-z][\w.-]{0,63})["\']?\s*[:=]\s*)'
    rf'["\']?(?P<value>[{VALUE_CHARS}]{{{PASSWORD_MIN_LEN},{CONTEXT_MAX_LEN}}})(?![:{VALUE_CHARS}])')
VALUE_RE = re.compile(rf'[{VALUE_CHARS}]+')
UUID_RE = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')
SNAKE_RE = re.compile(r'[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\Z')
FILE_END_RE = re.compile(r'\.[a-z]{1,5}\Z')


def shannon(s):
    """Shannon entropy in bits per character; the empty string gives 0.0."""
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values()) if n else 0.0


def label_segments(label):
    """camelCase split, then `[_.-]+` split, lowercased, leading dashes stripped, empties dropped."""
    spaced = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', label.lstrip('-'))
    return [s for s in re.split(r'[_.\-]+', spaced.lower()) if s]


def _is_password_word(segment):
    return segment in PASSWORD_WORDS or segment.endswith(('password', 'passwd'))


def _label_class(label):
    segments = label_segments(label)
    if any(s in QUALIFIERS for s in segments):
        return None
    if label == 'pass':  # bare lowercase label (not a flag): English prose such as "one pass: ..."
        return None
    words = [s for s in segments if not s.isdigit()]
    if words and _is_password_word(words[-1]):
        return 'password'
    if any(s in SECRET_WORDS or s.endswith(('key', 'secret', 'token')) for s in segments):
        return 'secret'
    return None


def _excluded(value):
    # The next flag, a reference (`$FOO`, `<set>`, `{{X}}`, `(cmd)`, `_x`; JSON values can hold
    # these, text candidates cannot), a path, or a SCREAMING_SNAKE name.
    return (value.startswith(('-', '_', '$', '<', '{', '(', '/', '~', '.')) or FILE_END_RE.search(value) is not None
            or SNAKE_RE.match(value) is not None)


def _word_like(value):
    parts = [p for p in re.split(r'[-_.]', value) if p]
    return (all(p.isdigit() or (p.isalpha() and p.islower()) for p in parts)
            and sum(p.isalpha() and len(p) >= 3 for p in parts) >= 2)


def contextual_secret(label, value):
    """True when `value` next to `label` looks like a literal secret (spec: contextual detector)."""
    kind = _label_class(label)
    if kind is None or _excluded(value):
        return False
    if kind == 'password':
        return len(value) >= PASSWORD_MIN_LEN
    if (not CONTEXT_MIN_LEN <= len(value) <= CONTEXT_MAX_LEN or not VALUE_RE.fullmatch(value)
            or UUID_RE.match(value) or _word_like(value)):
        return False
    has_digit = any(c.isdigit() for c in value)
    mixed_case = any(c.islower() for c in value) and any(c.isupper() for c in value)
    return (has_digit or mixed_case) and shannon(value) >= ENTROPY_MIN


def contextual_redact(text):
    """Replace the value of each labelled literal secret with CONTEXT_TOKEN, keeping the label.

    A candidate that is not a secret consumes only its label, so a label inside its value
    (`-e AWS_SECRET_ACCESS_KEY=...`) is examined next."""
    out, pos = [], 0
    while (m := CONTEXT_RE.search(text, pos)) is not None:
        if contextual_secret(m.group('flag') or m.group('label'), m.group('value')):
            out.append(text[pos:m.start('value')] + CONTEXT_TOKEN)
            pos = m.end()
        else:
            out.append(text[pos:m.start('value')])
            pos = m.start('value')
    return ''.join(out) + text[pos:]


def contextual_search(text):
    return contextual_redact(text) != text


MARKER_FORMAT = '[metadata-only: N chars]'
MARKER_RE = re.compile(r'\[metadata-only: \d+ chars\]\Z')
FRONTMATTER_KEEP = frozenset({'name', 'model', 'context', 'agent', 'disable-model-invocation',
                              'user-invocable', 'paths'})


def marker(s):
    return f'[metadata-only: {len(s)} chars]'


def mask_value(v, counter, family):
    if not isinstance(v, str) or MARKER_RE.match(v):
        return v
    counter[family] += 1
    return marker(v)


def mask_leaves(obj, counter, family):
    if isinstance(obj, str):
        return mask_value(obj, counter, family)
    if isinstance(obj, dict):
        return {k: mask_leaves(v, counter, family) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_leaves(v, counter, family) for v in obj]
    return obj


def _mask_list(lst, counter, family):
    if isinstance(lst, list):
        lst[:] = [mask_value(v, counter, family) for v in lst]


def mask_handler(h, counter):
    if isinstance(h, dict) and 'target' in h:
        h['target'] = mask_value(h['target'], counter, 'hook_targets')


def mask_settings(s, counter):
    _mask_list(s.get('hook_commands'), counter, 'hook_commands')
    for h in s.get('hook_handlers') or []:
        mask_handler(h, counter)
    _mask_list(s.get('missing_hook_scripts'), counter, 'missing_hook_scripts')
    for key, family in (('sandbox', 'sandbox'), ('model_settings', 'model_settings')):
        if key in s:
            s[key] = mask_leaves(s[key], counter, family)
    other = s.get('other') or {}
    if 'statusLine' in other:
        other['statusLine'] = mask_leaves(other['statusLine'], counter, 'status_line')
    perms = s.get('permissions') or {}
    _mask_list(perms.get('deny'), counter, 'permission_deny')
    for rules in (perms.get('risky') or {}).values():
        _mask_list(rules, counter, 'permission_risky')
    for flags in (perms.get('rule_shape_issues') or {}).values():
        for rules in flags.values() if isinstance(flags, dict) else ():
            _mask_list(rules, counter, 'rule_shape_issues')


def mask_conflicts(conflicts, counter):
    for overlap in (conflicts or {}).get('permission_overlaps') or []:
        for side in ('allow', 'by'):
            if isinstance(overlap.get(side), dict) and 'rule' in overlap[side]:
                overlap[side]['rule'] = mask_value(overlap[side]['rule'], counter, 'permission_overlaps')


def mask_frontmatter(fm, counter):
    if isinstance(fm, dict):
        for k in fm:
            if k not in FRONTMATTER_KEEP:
                fm[k] = mask_leaves(fm[k], counter, 'frontmatter')


def _entry(e, counter):
    if 'excerpt' in e:
        e['excerpt'] = mask_value(e['excerpt'], counter, 'excerpts')
    mask_frontmatter(e.get('frontmatter'), counter)
    for h in e.get('handlers') or []:
        mask_handler(h, counter)


def mask_snapshot(snap):
    counter = Counter()
    g, ms, ins = snap.get('global') or {}, snap.get('managed_settings') or {}, snap.get('instructions') or {}
    summaries = list(g.get('settings') or []) + list(ms.get('settings') or [])
    for p in (snap.get('projects') or {}).values():
        summaries += p.get('settings') or []
    summaries += ins.get('settings_candidates') or []
    for s in summaries:
        if isinstance(s, dict):
            mask_settings(s, counter)
    mask_conflicts(snap.get('config_conflicts'), counter)
    if 'last_update' in g:
        g['last_update'] = mask_leaves(g['last_update'], counter, 'last_update')
    usage = snap.get('usage') or {}
    for key in ('heaviest_sessions', 'most_friction_sessions'):
        for sess in usage.get(key) or []:
            if 'first_prompt' in sess:
                sess['first_prompt'] = mask_value(sess['first_prompt'], counter, 'first_prompt')
    _mask_list(usage.get('facet_friction_details'), counter, 'facet_friction_details')
    for sample in (snap.get('corrections') or {}).get('samples') or []:
        if 'text' in sample:
            sample['text'] = mask_value(sample['text'], counter, 'correction_samples')
    for proj in ((snap.get('memory') or {}).get('by_project') or {}).values():
        for e in proj.get('entries') or []:
            if 'description' in e:
                e['description'] = mask_value(e['description'], counter, 'memory_descriptions')
    for e in ins.get('entries') or []:
        _entry(e, counter)
    for plugin in (snap.get('extensions') or {}).get('plugins') or []:
        for comp in plugin.get('components') or []:
            _entry(comp, counter)
    mask_unclassified(snap, counter)
    return dict(counter)


def leaves(obj, path=()):
    """Yield (path, value) for every non-container leaf; list indices are ints."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leaves(v, path + (i,))
    else:
        yield path, obj


def is_kept(path):
    return any(path_matches(path, pat) for pat in KEPT_STRING_FIELDS)


def mask_unclassified(snap, counter):
    """Fail closed: mask every string leaf that is neither a marker nor a kept field (dict keys stay)."""
    for path, v in list(leaves(snap)):
        if isinstance(v, str) and not MARKER_RE.match(v) and not is_kept(path):
            parent = snap
            for p in path[:-1]:
                parent = parent[p]
            if parent[path[-1]] is v:  # a shared object may already have been masked
                parent[path[-1]] = mask_value(v, counter, 'unclassified')


def path_matches(path, pattern):
    """'*' matches one key or index; '**' (last element only) matches any remainder."""
    if '**' in pattern[:-1]:
        raise ValueError("'**' is only valid as the last pattern element")
    for i, pat in enumerate(pattern):
        if pat == '**':
            return True
        if i >= len(path):
            return False
        if pat == '*':
            continue
        if isinstance(path[i], int) or path[i] != pat:
            return False
    return len(path) == len(pattern)


SETTINGS_PREFIXES = (('global', 'settings', '*'), ('managed_settings', 'settings', '*'),
                     ('projects', '*', 'settings', '*'), ('instructions', 'settings_candidates', '*'))
MCP_POLICY_LISTS = ('enabledMcpjsonServers', 'disabledMcpjsonServers')
MCP_POLICY_KEYS = MCP_POLICY_LISTS + ('enableAllProjectMcpServers', 'allowManagedMcpServersOnly',
                                       'disableClaudeAiConnectors', 'allowedMcpServers', 'deniedMcpServers')
MCP_POLICY_KEEP = (  # collect.mcp_policy: names, or the string "invalid" in place of a list, flag or dict
    *(('mcp_policy', k) for k in MCP_POLICY_KEYS),
    *(('mcp_policy', k, '*') for k in MCP_POLICY_LISTS),
    *(('mcp_policy', k, 'server_names', '*') for k in ('allowedMcpServers', 'deniedMcpServers')))
HANDLER_KEEP = (('fingerprint',), ('event',), ('matcher',), ('type',), ('server',), ('tool',), ('target_origin',),
                ('header_keys', '*'), ('allowed_env_vars', '*'), ('issues', '*'), ('unknown_fields', '*'))
SETTINGS_KEEP = (('path',), ('scope',), ('keys', '*'), ('model',), ('env_keys', '*'), ('hooks', '*', '*'),
                 ('permissions', 'default_mode'), ('permissions', 'additional_dirs', '*'),
                 ('permissions', 'missing_additional_dirs', '*'), ('other', 'outputStyle'),
                 ('other', 'autoUpdates')) + tuple(('hook_handlers', '*') + h for h in HANDLER_KEEP)
ENTRY_KEEP = tuple((k,) for k in ('source', 'scope', 'status', 'kind', 'relation', 'active_state',
                                  'reason', 'frontmatter_status', 'estimate_basis')) \
    + tuple(('frontmatter', k) for k in FRONTMATTER_KEEP)
SUBTREES = (('collection_scope', '**'), ('readiness', '**'), ('harness_overhead', '**'), ('coverage', '**'),
            ('ledger_signals', '**'), ('drift_signals', '**'), ('skill_listing', '**'),
            ('managed_settings', 'sources', '**'), ('instructions', 'sources', '**'),
            ('instructions', 'contexts', '**'), ('instructions', 'agents_md_setting_observed', '**'),
            ('extensions', 'sources', '**'), ('global', 'plugin_session_start_hooks', '**'),
            ('memory', 'similar_across_projects', '**'))
CONFLICT_KEEP = (
    *(('config_conflicts', 'hook_duplicates', '*', k) for k in ('stack', 'event', 'matcher', 'type', 'fingerprint',
                                                                'effect')),
    *(('config_conflicts', 'hook_duplicates', '*', 'sources', '*', k) for k in ('layer', 'path', 'plugin')),
    *(('config_conflicts', 'permission_overlaps', '*') + k for k in (('stack',), ('match',), ('by', 'list'),
                                                                      ('allow', 'layer'), ('allow', 'path'),
                                                                      ('by', 'layer'), ('by', 'path'))))
MCP_ID_FIELDS = ('transport_class', 'endpoint_locality', 'file_git_status', 'tool_prefix', 'plugin')
MCP_ID_LISTS = ('config_notes', 'url_variable_references', 'env_literal_keys', 'headers_literal_keys',
                'oauth_keys', 'oauth_scopes')
SWEEP_KEEP = (  # string fields added by plans 2A and 2B (classified 2026-09-30)
    *CONFLICT_KEEP,
    *(('extensions', 'mcp_servers', '*', k) for k in MCP_ID_FIELDS),
    *(('extensions', 'mcp_servers', '*', k, '*') for k in MCP_ID_LISTS),
    *(('extensions', 'mcp_servers', '*', 'policy_observations', '*', k) for k in ('source', 'kind')),
    *(('extensions', 'mcp_project_state', '*', k) for k in ('project', 'source')),
    *(('extensions', 'mcp_project_state', '*', k, '*') for k in (
          'enabledMcpServers', 'disabledMcpServers', 'enabledMcpjsonServers', 'disabledMcpjsonServers')),
    ('extensions', 'mcp_name_collisions', '*', 'name'), ('extensions', 'mcp_name_collisions', '*', 'project'),
    ('extensions', 'mcp_name_collisions', '*', 'scopes', '*'),
    ('transcripts', 'tool_errors', 'by_tool', '*', 'tool'),
    ('transcripts', 'tool_errors', 'by_mcp_server', '*', 'server'),
    ('transcripts', 'tool_errors', 'by_mcp_server', '*', 'top_error_tools', '*', '*'))
SINGLE = (('generated',), ('previous_audits', '*'), ('managed_settings', 'effective_policy'),
          ('global', 'version'), ('global', 'doctor'),
          *(('global', k, '*') for k in ('skills', 'agents', 'commands', 'mcp_user', 'installed_plugins')),
          *(('projects', '*', k, '*') for k in ('claude_md_dead_refs', 'mcp_servers', 'skills', 'agents',
                                                'commands', 'hooks', 'git')),
          ('memory', 'by_project', '*', 'entries', '*', 'file'),
          *(('usage', k) for k in ('coverage_note', 'window_note', 'stats_scope_note', 'facets_scope_note',
                                   'latest_insights_report')),
          ('usage', 'daily_token_totals_recent', '*', 'date'),
          *(('usage', k, '*', '*') for k in ('top_tools', 'tool_error_categories', 'sessions_per_project',
                                             'facet_friction')),
          *(('usage', s, '*', k) for s in ('heaviest_sessions', 'most_friction_sessions') for k in ('project', 'start')),
          ('corrections', 'by_project', '*', '*'), ('corrections', 'samples', '*', 'project'),
          *(('transcripts', k) for k in ('coverage_note', 'window_note', 'quantile_method', 'mcp_count_note',
                                         'mcp_configured_but_unused_note')),
          *(('transcripts', k, '*', '*') for k in ('context_baseline_by_project_median', 'mcp_calls_by_server')),
          ('transcripts', 'mcp_configured_but_unused', '*'),
          ('transcripts', 'tool_errors', 'categories_basis'), ('transcripts', 'tool_errors', 'scope_note'),
          ('instructions', 'limitations', '*'), ('extensions', 'limitations', '*'),
          *(('extensions', 'mcp_servers', '*', k) for k in ('source', 'scope', 'status', 'name', 'project',
                'active_state', 'representation', 'transport', 'executable', 'package_version_evidence',
                'endpoint_origin', 'endpoint_detail', 'reason')),
          *(('extensions', 'mcp_servers', '*', k, '*') for k in ('env_keys', 'headers_keys',
                'env_variable_references', 'headers_variable_references', 'credential_mechanisms')),
          *(('extensions', 'plugins', '*', k) for k in ('name', 'scope', 'project', 'version', 'active_state',
                                                        'source', 'status', 'reason')),
          ('extensions', 'plugins', '*', 'manifest_keys', '*'),
          ('extensions', 'plugins', '*', 'enablement_observations', '*', 'source'))
KEPT_STRING_FIELDS = (SUBTREES + SWEEP_KEEP + SINGLE
    + tuple(p + s for p in SETTINGS_PREFIXES for s in SETTINGS_KEEP + MCP_POLICY_KEEP)
    + tuple(p + s for p in (('instructions', 'entries', '*'), ('extensions', 'plugins', '*', 'components', '*'))
            for s in ENTRY_KEEP)
    + tuple(('extensions', 'plugins', '*', 'components', '*', 'handlers', '*') + h for h in HANDLER_KEEP))
