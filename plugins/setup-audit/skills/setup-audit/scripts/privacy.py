"""Privacy helpers: contextual secret detection (both modes) and metadata-only masking. Stdlib only."""
import hmac
import math
import os
import posixpath
import re
import secrets
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
    for written in s.get('plugin_written_rules') or []:
        _mask_list(written.get('rules'), counter, 'plugin_written_rules')
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
                ('on_failure',), ('background',), ('decision_basis',), ('scan_gap',), ('header_keys', '*'), ('allowed_env_vars', '*'), ('issues', '*'), ('unknown_fields', '*'))
SETTINGS_KEEP = (('path',), ('scope',), ('keys', '*'),
                 # plugin_markers: key paths from plugin_footprint.MARKERS; the rule names are masked (mask_settings)
                 ('plugin_markers', '*'), ('plugin_written_rules', '*', 'plugin'), ('plugin_written_rules', '*', 'list'), ('shape_issues', '*'), ('model',), ('env_keys', '*'), ('hooks', '*', '*'),
                 ('permissions', 'default_mode'), ('permissions', 'additional_dirs', '*'),
                 ('permissions', 'missing_additional_dirs', '*'), ('other', 'outputStyle'),
                 ('other', 'autoUpdates'),  # scope_ignored_keys / ignored_env_keys: table vocabulary and env names (0.11.0)
                 ('scope_ignored_keys', '*', 'key'), ('scope_ignored_keys', '*', 'scope'),
                 ('ignored_env_keys', '*', 'name'), ('ignored_env_keys', '*', 'reason')) + tuple(('hook_handlers', '*') + h for h in HANDLER_KEEP)
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
SUBAGENT_KEEP = (  # transcripts.subagent_models / request_params: names and fixed vocabularies (0.11.0)
    *(('transcripts', 'subagent_models', 'rows', '*', k) for k in ('agent_type', 'requested_model', 'actual_model')),
    ('transcripts', 'subagent_models', 'basis'), ('transcripts', 'request_params', 'basis'),
    *(('transcripts', 'request_params', c, k, '*', '*')
      for c in ('main', 'sdk', 'agent', 'other') for k in ('by_model', 'by_effort', 'by_thinking')))
FOOTPRINT_KEEP = (  # plugin_footprint.py: table labels, fixed vocabulary and notes (0.12.0)
    ('transcripts', 'plugin_spawned', 'basis'), ('transcripts', 'plugin_spawned', 'rows', '*', 'label'),
    ('usage', 'heaviest_sessions', '*', 'plugin_spawned'),
    ('transcripts', 'failure_loops', 'basis'))  # counts, a command-head vocabulary (dict keys) and project-keyed maps
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
          # Mod API vocabulary (event and call names matching a strict identifier pattern); module path is masked.
          *(('extensions', 'plugins', '*', 'components', '*', 'mod', k) for k in ('reason',)),
          *(('extensions', 'plugins', '*', 'components', '*', 'mod', k, '*') for k in ('events', 'calls')),
          ('extensions', 'plugins', '*', 'enablement_observations', '*', 'source'))
KEPT_STRING_FIELDS = (SUBTREES + SWEEP_KEEP + SUBAGENT_KEEP + FOOTPRINT_KEEP + SINGLE
    + tuple(p + s for p in SETTINGS_PREFIXES for s in SETTINGS_KEEP + MCP_POLICY_KEEP)
    + tuple(p + s for p in (('instructions', 'entries', '*'), ('extensions', 'plugins', '*', 'components', '*'))
            for s in ENTRY_KEEP)
    + tuple(('extensions', 'plugins', '*', 'components', '*', 'handlers', '*') + h for h in HANDLER_KEEP))


# --- --hash-paths -------------------------------------------------------------------------------
# Path-like kept strings become `h:<12 hex>` = HMAC-SHA256(salt, normalized value) truncated to 48 bits.
# Whole values are hashed (no per-component or extension-preserving hashing): a component hash would
# still reveal depth and common basenames, and the joins that matter go through the same function.
# Not hashed: fixed vocabulary (event names, model ids, setting keys, scopes, enum values), plugin, skill,
# agent and MCP server names, and free text (hook commands, rule text), which --metadata-only masks and
# which in full mode only has known home and project prefixes replaced (scrub_known_paths).
TAG_RE = re.compile(r'h:[0-9a-f]{12}\Z')
SALT_MIN_BYTES = 16
SALT_READ_LIMIT = 1 << 20


class SaltError(ValueError):
    """The salt file is missing, unreadable, empty or too short."""


def resolve_salt(path):
    """(salt bytes, 'per_run' | 'file'). A salt file must already exist; this never creates one."""
    if path is None:
        return secrets.token_bytes(32), 'per_run'
    path = os.path.abspath(os.path.expanduser(path))
    try:
        with open(path, 'rb') as f:
            raw = f.read(SALT_READ_LIMIT)
    except OSError as exc:
        raise SaltError(f'cannot read salt file {path}: {exc.strerror or type(exc).__name__}; '
                        'create it yourself (collect.py never writes it)') from None
    salt = raw.strip()
    if not salt:
        raise SaltError(f'salt file {path} is empty')
    if len(salt) < SALT_MIN_BYTES:
        raise SaltError(f'salt file {path} holds fewer than {SALT_MIN_BYTES} bytes of salt')
    return salt, 'file'


class PathHasher:
    """Callable str -> tag. Equal normalized inputs give equal tags; `~/x` and `<home>/x` are equal."""

    def __init__(self, salt, home):
        self.salt, self.home = salt, home.rstrip('/') if home else ''

    def normalize(self, value):
        if value == '~' or value.startswith('~/'):
            value = self.home + value[1:]
        return posixpath.normpath(value) if '/' in value else value

    def __call__(self, value):
        if TAG_RE.match(value):
            return value
        digest = hmac.new(self.salt, self.normalize(value).encode('utf-8', 'surrogatepass'), 'sha256')
        return 'h:' + digest.hexdigest()[:12]


def path_like(value):
    return '/' in value or '\\' in value or value.startswith('~')


_SETTINGS = tuple(p for p in SETTINGS_PREFIXES)
_PROJECT_STRINGS = (
    ('collection_scope', 'project'), ('coverage', 'projects_collected', '*'),
    ('usage', 'heaviest_sessions', '*', 'project'), ('usage', 'most_friction_sessions', '*', 'project'),
    ('usage', 'sessions_per_project', '*', '*'), ('corrections', 'by_project', '*', '*'),
    ('corrections', 'samples', '*', 'project'),
    ('extensions', 'mcp_servers', '*', 'project'), ('extensions', 'mcp_name_collisions', '*', 'project'),
    ('extensions', 'mcp_project_state', '*', 'project'), ('extensions', 'plugins', '*', 'project'),
    *(('instructions', 'contexts', '*', k) for k in ('session_cwd', 'worktree_root', 'main_checkout')))
_FILE_SOURCES = (  # a file path, or fixed vocabulary such as `user`: hashed only when path-like
    *(p + ('path',) for p in _SETTINGS),
    ('config_conflicts', 'hook_duplicates', '*', 'sources', '*', 'path'),
    ('config_conflicts', 'permission_overlaps', '*', 'allow', 'path'),
    ('config_conflicts', 'permission_overlaps', '*', 'by', 'path'),
    ('instructions', 'entries', '*', 'source'), ('instructions', 'sources', '*', 'source'),
    ('managed_settings', 'sources', '*', 'source'), ('extensions', 'sources', '*', 'source'),
    ('coverage', 'sources', '*', 'source'),
    ('extensions', 'mcp_servers', '*', 'source'), ('extensions', 'mcp_project_state', '*', 'source'),
    ('extensions', 'mcp_servers', '*', 'policy_observations', '*', 'source'),
    ('extensions', 'plugins', '*', 'enablement_observations', '*', 'source'),
    ('drift_signals', 'path'), ('usage', 'latest_insights_report'), ('previous_audits', '*'))
# One row per family: `leaves` are hashed whenever they hold a string; `maybe` only when the string is path-like
# (the field also carries fixed vocabulary); `keys` are dict containers whose keys are hashed.
PATH_FAMILIES = {
    'project_roots': {
        'doc': 'project root directories: projects/readiness keys, session and correction project paths, '
               'coverage.projects_collected, collection_scope.project, session and worktree roots',
        'leaves': _PROJECT_STRINGS,
        'maybe': (('config_conflicts', 'hook_duplicates', '*', 'stack'),
                  ('config_conflicts', 'permission_overlaps', '*', 'stack')),
        'keys': (('projects',), ('readiness',))},
    'transcript_keys': {
        'doc': 'transcript directory keys (dash-encoded project paths): memory and per-project transcript maps, '
               'the project of each memory.similar_across_projects pair (same tag as that project root)',
        'leaves': (('transcripts', 'context_baseline_by_project_median', '*', '*'),
                   ('memory', 'similar_across_projects', '*', 'a_project'),
                   ('memory', 'similar_across_projects', '*', 'b_project')),
        'keys': (('memory', 'by_project'), ('transcripts', 'env_error_hits_by_project'),
                 ('transcripts', 'test_run_seconds_by_project'), ('transcripts', 'failure_loops', 'by_project'))},
    'config_files': {
        'doc': 'settings, instruction, managed and MCP config file paths, previous audit file names, the '
               'drift log path and the /insights report path',
        'leaves': (), 'maybe': _FILE_SOURCES},
    'plugin_paths': {
        'doc': 'plugin install roots, plugin component files, declared mod modules and hook scripts that decide permissions',
        'leaves': (('extensions', 'plugins', '*', 'components', '*', 'mod', 'module'),
                   ('extensions', 'plugins', '*', 'components', '*', 'handlers', '*', 'decision_file')), 'maybe': (('extensions', 'plugins', '*', 'source'),
                                ('extensions', 'plugins', '*', 'components', '*', 'source'))},
    'referenced_files': {
        'doc': 'file and directory names taken from repos and configs: CLAUDE.md dead references, missing hook '
               'scripts, additional directories, memory file names, `paths:` frontmatter, SDK call-site file names, MCP executables',
        'leaves': (*(('projects', '*', 'claude_md_dead_refs', '*'),),
                   *(p + ('missing_hook_scripts', '*') for p in _SETTINGS),
                   *(p + ('permissions', k, '*') for p in _SETTINGS for k in ('additional_dirs', 'missing_additional_dirs')),
                   ('memory', 'by_project', '*', 'entries', '*', 'file'),
                   # rules/skill `paths:` frontmatter names repo files (kept raw, often multi-line)
                   *(p + ('frontmatter', 'paths') + t
                     for p in (('instructions', 'entries', '*'), ('extensions', 'plugins', '*', 'components', '*'))
                     for t in ((), ('*',))),
                   ('readiness', '*', 'env', 'undeclared', '*', 'files', '*'),
                   ('memory', 'similar_across_projects', '*', 'a'), ('memory', 'similar_across_projects', '*', 'b'),
                   ('memory', 'similar_across_projects', '*', 'a_file'),
                   ('memory', 'similar_across_projects', '*', 'b_file'),
                   ('readiness', '*', 'app_caching', 'uncached_files', '*'),
                   ('readiness', '*', 'app_caching', 'possible_cache_breakers', '*', '*')),
        'maybe': (('extensions', 'mcp_servers', '*', 'executable'),)},
}

# Counters that are not path patterns (recorded beside the families in hashed_path_families).
EXTRA_COUNTERS = {
    'other_paths': 'path-like kept strings and dict keys that no family names, hashed after the families so a '
                   'new field fails closed; URLs, `name/N` basis strings and whitespace-containing prose are exempt',
    'free_text_scrubbed': 'strings and dict keys in which a known home, config or project directory (or its '
                          'dash-encoded form) was replaced by its tag',
}
BASIS_RE = re.compile(r'[A-Za-z_]+/\d+\Z')
FIXED_SLASH_VOCAB = frozenset()  # exact kept strings with a slash that are vocabulary, not paths


def stray_path(value):
    """A kept, whitespace-free, path-like string that is not a tag, URL or basis string."""
    return (path_like(value) and not TAG_RE.match(value) and not MARKER_RE.match(value) and '://' not in value
            and not BASIS_RE.match(value) and not any(c.isspace() for c in value)
            and value not in FIXED_SLASH_VOCAB)


def _transcript_key(root):
    return re.sub(r'[^A-Za-z0-9]', '-', root)


def path_needles(home, extra_dirs, roots):
    """Absolute and dash-encoded directories whose occurrences inside any string are replaced."""
    found = set()
    for d in [home, *extra_dirs, *roots]:
        if not d or not isinstance(d, str):
            continue
        found.update((d, _transcript_key(d)))
        if home and d.startswith(home.rstrip('/') + '/'):
            found.add('~' + d[len(home.rstrip('/')):])
    return sorted(n for n in found if len(n) >= 4 and n.strip('/-') != '')


def scrub_known_paths(snap, hasher, needles, dirs=()):
    """Replace every occurrence of a known home or project directory in any string leaf or dict key."""
    needles = sorted((n for n in needles if len(n) >= 4 and n.strip('/-') != ''), key=len, reverse=True)
    if not needles:
        return 0
    # A path needle ends at a path boundary, so `/h/u/code/app2` is not tagged as inside `/h/u/code/app`;
    # dash-encoded needles stay unbounded (their continuation is also dash-separated: fail closed).
    alts = [re.escape(n) + ('' if '/' not in n and '-' in n else r'(?![\w-]|\.[\w-])') for n in needles]
    rx = re.compile('|'.join(alts))
    count = [0]
    encoded = {_transcript_key(d): d for d in dirs}

    def sub(text):
        if TAG_RE.match(text) or MARKER_RE.match(text):
            return text
        new = rx.sub(lambda m: hasher(encoded.get(m.group(0), m.group(0))), text)
        count[0] += new != text
        return new

    def walk(o):
        if isinstance(o, str):
            return sub(o)
        if isinstance(o, dict):
            return {sub(k) if isinstance(k, str) else k: walk(v) for k, v in o.items()}
        if isinstance(o, (list, tuple)):  # the collector still holds tuples (Counter.most_common)
            return [walk(v) for v in o]
        return o

    for key in list(snap):
        snap[key] = walk(snap[key])
    return count[0]


def hash_paths(snap, hasher, roots, extra_dirs=()):
    """Hash the path families in place, then scrub known directories out of everything else.

    Returns {family: count of hashed values and keys, ...} for every family (zero included)."""
    counts = Counter({f: 0 for f in (*PATH_FAMILIES, *EXTRA_COUNTERS)})
    cs = snap.get('collection_scope')
    if isinstance(cs, dict) and isinstance(cs.get('project'), str) and cs.get('requested') == 'project' and roots:
        cs['project'] = roots[0]  # the resolved root, so it joins with the `projects` keys
    for pair in (snap.get('memory') or {}).get('similar_across_projects', ()):
        if isinstance(pair, dict) and 'shared' in pair:  # name-derived words: keep only how many
            pair['shared_count'] = len(pair['shared'])
            pair['shared'] = []
    rows = [(f, pat, maybe) for f, spec in PATH_FAMILIES.items()
            for maybe, pats in ((False, spec.get('leaves', ())), (True, spec.get('maybe', ())))
            for pat in pats]
    key_rows = [(f, pat) for f, spec in PATH_FAMILIES.items() for pat in spec.get('keys', ())]
    encoded = {_transcript_key(r): r for r in roots}

    def leaf(path, v):
        for family, pat, maybe in rows:
            if path_matches(path, pat) and not MARKER_RE.match(v) and (not maybe or path_like(v)):
                counts[family] += 1
                return hasher(encoded.get(v, v) if family == 'transcript_keys' else v)
        return v

    def walk(o, path):
        if isinstance(o, str):
            return leaf(path, o)
        if isinstance(o, (list, tuple)):
            return [walk(v, path + (i,)) for i, v in enumerate(o)]
        if not isinstance(o, dict):
            return o
        fam = next((f for f, pat in key_rows if path_matches(path, pat)), None)
        out = {}
        for k, v in o.items():
            new = walk(v, path + (k,))
            if fam and isinstance(k, str) and not MARKER_RE.match(k):
                counts[fam] += 1
                k = hasher(encoded[k]) if fam == 'transcript_keys' and k in encoded else hasher(k)
            out[k] = new
        return out

    for key in list(snap):
        snap[key] = walk(snap[key], (key,))
    dirs = [d for d in (hasher.home, *extra_dirs, *roots) if d and isinstance(d, str)]
    counts['free_text_scrubbed'] = scrub_known_paths(snap, hasher, path_needles(hasher.home, extra_dirs, roots), dirs)
    counts['other_paths'] = _hash_strays(snap, hasher)
    return dict(counts)


def _hash_strays(snap, hasher):
    """Fail closed: hash path-like kept strings (and any path-like dict key) that no family claimed."""
    n = [0]

    def walk(o, path):
        if isinstance(o, str):
            if is_kept(path) and stray_path(o):
                n[0] += 1
                return hasher(o)
            return o
        if isinstance(o, (list, tuple)):
            return [walk(v, path + (i,)) for i, v in enumerate(o)]
        if not isinstance(o, dict):
            return o
        out = {}
        for k, v in o.items():
            if isinstance(k, str) and stray_path(k):
                n[0] += 1
                new_k = hasher(k)
            else:
                new_k = k
            out[new_k] = walk(v, path + (k,))
        return out

    for key in list(snap):
        snap[key] = walk(snap[key], (key,))
    return n[0]
