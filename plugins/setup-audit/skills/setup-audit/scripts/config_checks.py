"""Static configuration checks: hook handler validation and fingerprints, cross-layer conflicts.

Pure functions over settings JSON and collector summaries. Stdlib only; never runs a hook.
Documentation baseline: https://code.claude.com/docs/en/hooks.md and
https://code.claude.com/docs/en/permissions.md, both fetched 2026-09-29, re-verified 2026-09-30.
"""
import hashlib
import json
import re
import warnings

DEFAULT, NARROW = 'default', 'narrow'
# hooks.md (fetched 2026-09-29, re-verified 2026-09-30), "Hook lifecycle" event table and "Matcher patterns":
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
# hooks.md "Hook handler fields" (fetched 2026-09-29, re-verified 2026-10-24: onFailure, 2.1.295+).
COMMON_FIELDS = frozenset({'type', 'if', 'timeout', 'statusMessage', 'once'})
TYPE_FIELDS = {
    'command': frozenset({'command', 'args', 'async', 'asyncRewake', 'shell', 'onFailure'}),
    'http': frozenset({'url', 'headers', 'allowedEnvVars', 'onFailure'}),
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
        except (OverflowError, RecursionError):
            pass  # JavaScript accepts large quantifiers and deep nesting; not judged
    return issues


def handler_issues(event, matcher, handler):
    """(issues, unknown_fields) for one handler; see references/checklist.md HYG-hook-config."""
    spec = HOOK_EVENTS.get(event)
    issues = ['unknown_event'] if spec is None else _matcher_issues(event, spec, matcher)
    if spec is not None and 'if' in handler and event not in TOOL_EVENTS:
        issues.append('if_never_runs')
    kind = handler.get('type', 'command')
    unknown = []
    if not isinstance(kind, str) or kind not in TYPE_FIELDS:
        issues.append('unknown_type')
    else:
        unknown = sorted(str(k) for k in handler if k not in COMMON_FIELDS | TYPE_FIELDS[kind])[:10]
        if unknown:
            issues.append('unknown_fields')
        if 'onFailure' in TYPE_FIELDS[kind] and 'onFailure' in handler:
            if on_failure(handler) is None:
                issues.append('invalid_on_failure')
            elif on_failure(handler) == 'block' and (event in ON_FAILURE_NO_EFFECT or background(handler)):
                issues.append('on_failure_no_effect')
    return issues, unknown


# hooks.md "Block the action when a hook fails" (fetched 2026-10-24): onFailure has no effect here.
ON_FAILURE_NO_EFFECT = frozenset({'Stop', 'SubagentStop', 'TaskCompleted', 'TeammateIdle'})


def background(handler):
    """True for a command hook that runs in the background (async or asyncRewake)."""
    return handler.get('type', 'command') == 'command' and (handler.get('async') is True
                                                             or handler.get('asyncRewake') is True)


def on_failure(handler):
    """The documented onFailure value of a command/http handler, else None (hooks.md)."""
    value = handler.get('onFailure')
    return value if value in ('continue', 'block') else None


MAX_OVERLAPS, MAX_DUPLICATES, MAX_SOURCES = 30, 20, 10
# hooks.md "Bash" tool_input table (fetched 2026-09-29, re-verified 2026-09-30): the only documented fields.
BASH_PARAMS = ('command', 'description', 'timeout', 'run_in_background')
RULE_RE = re.compile(r'([^()]+?)(?:\((.*)\))?', re.S)
BASH_RULE_RE = re.compile(r'Bash\((.*)\)', re.S)
PARAM_RE = re.compile(r'(%s)\s*:' % '|'.join(BASH_PARAMS))


def bash_spec_body(spec):
    """(body, colon_prefix) of a Bash specifier; colon_prefix: a trailing `:*` (prefix form) was stripped."""
    body = spec.strip()
    if body.endswith(':*'):
        return body[:-2], True
    return body, False


def bash_rule_body(rule):
    """bash_spec_body of a `Bash(...)` rule, else None; shared with collect.rule_shape_flags."""
    m = BASH_RULE_RE.fullmatch(rule.strip()) if isinstance(rule, str) else None
    return bash_spec_body(m.group(1)) if m else None


def _parse(rule):
    """(tool, normalized specifier or None, is_bash_param_rule, raw specifier); None if unparseable.

    permissions.md: `Bash(*)` is equivalent to `Bash`; a trailing `:*` equals a trailing ` *`.
    """
    m = RULE_RE.fullmatch(rule.strip()) if isinstance(rule, str) else None
    if not m:
        return None
    tool, raw = m.group(1).strip(), m.group(2)
    spec, param = raw, False
    if tool == 'Bash' and raw is not None:
        body, colon = bash_spec_body(raw)
        param = bool(PARAM_RE.match(body + ':*' if colon else body))
        if colon and ':*' not in body:
            spec = body + ' *'
        else:
            spec = None if body == '*' else body + (':*' if colon else '')
    return tool, spec, param, raw


def rule_covers(by, allow, same_file=True):
    """'exact' | 'tool' | 'prefix' when every call `allow` matches is provably matched by `by`.

    Conservative: path globs and mid-rule wildcards are never compared, and a deny shaped like a
    Bash input-parameter rule (`Bash(timeout:*)`) is ambiguous, so only its raw text matches.
    Non-Bash specifiers are equal-text only, and not even then when `!` (gitignore negation
    denies nothing) or, across settings files, a leading single `/` (anchors at each file's own
    directory, permissions.md fetched 2026-09-29, re-verified 2026-09-30) makes equal text mean different things.
    """
    b, a = _parse(by), _parse(allow)
    if not b or not a:
        return None
    (btool, bspec, bparam, braw), (atool, aspec, _, araw) = b, a
    if atool.startswith('mcp__') and aspec is not None:
        return None  # "it skips any `mcp__` rule that has parentheses"
    if bparam:
        return 'exact' if (btool, braw) == (atool, araw) else None
    if (btool, bspec) == (atool, aspec):
        if btool != 'Bash' and bspec is not None and (
                bspec.startswith('!') or (bspec.startswith('/') and not bspec.startswith('//') and not same_file)):
            return None
        return 'exact'
    if bspec is None:
        if btool == atool:
            return 'tool'
        if btool.count('*') == 1 and btool.endswith('*') and atool.startswith(btool[:-1]):
            return 'tool'
        return None
    if btool != atool or atool != 'Bash' or aspec is None:
        return None
    if bspec.count('*') != 1 or not bspec.endswith('*'):
        return None
    spaced = bspec.endswith(' *')
    prefix = bspec[:-2] if spaced else bspec[:-1]
    literal = aspec.split('*', 1)[0]
    if spaced:  # `git *` matches `git` and `git ...`, not `gitk`
        good = literal.startswith(prefix + ' ') or ('*' not in aspec and literal == prefix)
    else:
        good = literal.startswith(prefix)
    return 'prefix' if good else None


def _rules(files, lst):
    """Rule strings of one list across settings files, tolerating missing lists and odd entries."""
    for f in files:
        perms = f.get('permissions')
        rules = perms.get(lst) if isinstance(perms, dict) else None
        yield f, [r for r in rules if isinstance(r, str)] if isinstance(rules, list) else []


def _negates(f, tool):
    """True when this file's deny/ask lists hold a `Tool(!...)` gitignore negation for `tool`."""
    for lst in ('deny', 'ask'):
        for _, rules in _rules([f], lst):
            for r in rules:
                p = _parse(r)
                if p and p[0] == tool and p[3] is not None and p[3].startswith('!'):
                    return True
    return False


def permission_overlaps(stacks, redact, cap=MAX_OVERLAPS):
    """Allow rules a deny or ask rule in the same stack always matches first; each pair reported once.

    permissions.md: "Rules are evaluated in order: deny, then ask, then allow", across all scopes.
    """
    seen, found = set(), []
    for stack in stacks:
        files = stack['settings']
        candidates = [(lst, f, rule) for lst in ('deny', 'ask') for f, rules in _rules(files, lst)
                      for rule in rules]
        for f, allows in _rules(files, 'allow'):
            for allow in allows:
                atool = (_parse(allow) or (None,))[0]
                for lst, by_file, by in candidates:
                    match = rule_covers(by, allow, same_file=by_file['path'] == f['path'])
                    if match == 'exact' and atool != 'Bash' and _negates(by_file, atool):
                        match = None  # a `!` carve-out in that file may cancel the equal rule
                    if match:
                        break
                else:
                    continue
                key = (f['path'], allow, by_file['path'], lst, by)
                if key in seen:
                    continue
                seen.add(key)
                found.append({'stack': stack['name'],
                              'allow': {'layer': f['layer'], 'path': f['path'], 'rule': redact(allow)[:160]},
                              'by': {'list': lst, 'layer': by_file['layer'], 'path': by_file['path'],
                                     'rule': redact(by)[:160]},
                              'match': match})
    return found[:cap], max(0, len(found) - cap)


def _matcher_text(matcher):
    """Display form of a normalized matcher; list matchers become sorted compact JSON."""
    matcher = normalize_matcher(matcher)
    if isinstance(matcher, list):
        return json.dumps(sorted(matcher, key=str), separators=(',', ':'), ensure_ascii=False, default=str)
    return str(matcher)


def _hook_members(stack):
    """(layer, path, plugin, handler) for every well-formed handler entry in a stack."""
    def dicts(items):
        return [x for x in items if isinstance(x, dict)] if isinstance(items, list) else []
    members = []
    for f in dicts(stack.get('settings')):
        members += [(f.get('layer'), f.get('path'), None, h) for h in dicts(f.get('handlers'))]
    for p in dicts(stack.get('plugins')):
        members += [('plugin', p.get('path'), p.get('plugin'), h) for h in dicts(p.get('handlers'))]
    return [m for m in members if isinstance(m[3].get('fingerprint'), str)]


def hook_duplicates(stacks, redact, cap=MAX_DUPLICATES):
    """Identical handlers in more than one place within a stack; each group reported once.

    hooks.md: "If you define the same handler in more than one settings file, it runs once. A
    plugin's or skill's copy of the same handler stays separate." Handlers that reference
    CLAUDE_PLUGIN_* expand per plugin, so they group only within their own plugin.
    """
    seen, found = set(), []
    for stack in stacks:
        groups = {}
        for member in _hook_members(stack):
            h = member[3]
            key = (h['fingerprint'], member[2] if h.get('plugin_relative') else None)
            groups.setdefault(key, []).append(member)
        for key, group in groups.items():
            if len(group) < 2:
                continue
            ids = tuple(sorted((str(layer), str(path), str(plugin or '')) for layer, path, plugin, _ in group))
            if (key, ids) in seen:
                continue
            seen.add((key, ids))
            paths = {path for _, path, _, _ in group}
            effect = ('same_file' if len(paths) == 1 else
                      'separate_copies' if any(layer == 'plugin' for layer, *_ in group) else 'deduplicated')
            first = group[0][3]
            found.append({'stack': stack.get('name'), 'event': redact(str(first.get('event')))[:200],
                          'matcher': redact(_matcher_text(first.get('matcher')))[:200],
                          'type': redact(str(first.get('type')))[:200], 'fingerprint': key[0], 'effect': effect,
                          'sources': [{'layer': layer, 'path': path, 'plugin': plugin}
                                      for layer, path, plugin, _ in group][:MAX_SOURCES]})
    return found[:cap], max(0, len(found) - cap)


def conflicts(stacks, redact):
    """The snapshot's config_conflicts section."""
    hooks, hooks_omitted = hook_duplicates(stacks, redact)
    perms, perms_omitted = permission_overlaps(stacks, redact)
    return {'stacks': len(stacks), 'hook_duplicates': hooks, 'hook_duplicates_omitted': hooks_omitted,
            'permission_overlaps': perms, 'permission_overlaps_omitted': perms_omitted}


# settings-reference.md (https://code.claude.com/docs/en/settings-reference.md, fetched 2026-10-24), the
# key table's Scope column and each key's `* **Scope**:` line; every key whose scope is not `Any file`.
# Scope vocabulary: user_or_managed = "User or managed", managed = "Managed", global_config = "Global
# config" (lives in ~/.claude.json: "Claude Code ignores them anywhere else"), user_local_managed =
# "User, local, or managed", user = "User". A key not in this table is never judged.
SETTINGS_SCOPES = {
    # user_or_managed
    'modelPicker': 'user_or_managed',
    'autoMode': 'user_or_managed',
    'autoMode.classifyAllShell': 'user_or_managed',
    'skipAutoPermissionPrompt': 'user_or_managed',
    'sandbox.filesystem.disabled': 'user_or_managed',
    'sandbox.allowAppleEvents': 'user_or_managed',
    'sandbox.allowNestedUserNamespaces': 'user_or_managed',
    'sandbox.ripgrep': 'user_or_managed',
    'sandbox.credentials.allowPlaintextInject': 'user_or_managed',
    'sandbox.credentials.awsPairs': 'user_or_managed',
    'sandbox.credentials.sigv4': 'user_or_managed',
    'sandbox.network.strictAllowlist': 'user_or_managed',
    'sandbox.network.tlsTerminate': 'user_or_managed',
    'askUserQuestionTimeout': 'user_or_managed',
    'autoContinueAtUsageLimit': 'user_or_managed',
    'axScreenReader': 'user_or_managed',
    'bashEditDiffEnabled': 'user_or_managed',
    'dialogExpiry': 'user_or_managed',
    'footerLinksRegexes': 'user_or_managed',
    'spellcheck': 'user_or_managed',
    'vimInsertModeRemaps': 'user_or_managed',
    'pluginConfigs': 'user_or_managed',
    'prependPlugins': 'user_or_managed',
    'appendPlugins': 'user_or_managed',
    'processWrapper': 'user_or_managed',
    'sshConfigs': 'user_or_managed',
    'sshHostCommands': 'user_or_managed',
    'forceLoginGatewayUrl': 'user_or_managed',
    'desktopSessionCleanupPeriodDays': 'user_or_managed',
    'feedbackDrafts': 'user_or_managed',
    # managed
    'availableModelsMatch': 'managed',
    'deniedModels': 'managed',
    'modelPricing': 'managed',
    'allowManagedPermissionRulesOnly': 'managed',
    'sandbox.filesystem.allowManagedReadPathsOnly': 'managed',
    'sandbox.bwrapPath': 'managed',
    'sandbox.socatPath': 'managed',
    'sandbox.network.allowManagedDomainsOnly': 'managed',
    'claudeMd': 'managed',
    'allowManagedHooksOnly': 'managed',
    'allowedChannelPlugins': 'managed',
    'blockedMarketplaces': 'managed',
    'channelsEnabled': 'managed',
    'disableCommandPluginSources': 'managed',
    'pluginSuggestionMarketplaces': 'managed',
    'pluginTrustMessage': 'managed',
    'strictKnownMarketplaces': 'managed',
    'strictPluginOnlyCustomization': 'managed',
    'strictPluginOnlyCustomization.skills': 'managed',
    'strictPluginOnlyCustomization.agents': 'managed',
    'strictPluginOnlyCustomization.hooks': 'managed',
    'strictPluginOnlyCustomization.mcp': 'managed',
    'allowAllClaudeAiMcps': 'managed',
    'allowClaudeInChromeWithManagedMcp': 'managed',
    'allowManagedMcpServersOnly': 'managed',
    'managedMcpServers': 'managed',
    'disableDesktopLocalSessions': 'managed',
    'sshHostAllowlist': 'managed',
    'allowedProviders': 'managed',
    'gatewayInternalNetworks': 'managed',
    'requiredMaximumVersion': 'managed',
    'requiredMinimumVersion': 'managed',
    'browserExternalPageTools': 'managed',
    'disableBrowserExternalNavigation': 'managed',
    'disableMobileSimulatorTools': 'managed',
    'disableSideloadFlags': 'managed',
    'forceRemoteSettingsRefresh': 'managed',
    'managedSourcesBehavior': 'managed',
    'parentSettingsBehavior': 'managed',
    'policyHelper': 'managed',
    'policyHelper.path': 'managed',
    'policyHelper.timeoutMs': 'managed',
    'policyHelper.refreshIntervalMs': 'managed',
    'wslInheritsWindowsSettings': 'managed',
    # global_config
    'autoConnectIde': 'global_config',
    'autoInstallIdeExtension': 'global_config',
    'claudeInChromeDefaultEnabled': 'global_config',
    'copyFullResponse': 'global_config',
    'copyOnSelect': 'global_config',
    'defaultToAgentsView': 'global_config',
    'diffTool': 'global_config',
    'externalEditorContext': 'global_config',
    'leftArrowOpensAgents': 'global_config',
    'permissionExplainerEnabled': 'global_config',
    'prStatusFooterEnabled': 'global_config',
    'teammateDefaultModel': 'global_config',
    # user_local_managed
    'useAutoModeDuringPlan': 'user_local_managed',
    'skipDangerousModePermissionPrompt': 'user_local_managed',
    'syncClaudeAiSkills': 'user_local_managed',
    'syncClaudeAiPlugins': 'user_local_managed',
    # user
    'worktree.location': 'user',
}
# Settings layers that ignore a key of each scope class. A managed file is never judged: this check
# is about what a repository (or a stray user file) can't set, and the managed layer is the admin's.
SCOPE_IGNORED_IN = {
    'user_or_managed': frozenset({'project', 'local'}),
    'managed': frozenset({'user', 'project', 'local'}),
    'global_config': frozenset({'user', 'project', 'local'}),
    'user_local_managed': frozenset({'project'}),
    'user': frozenset({'project', 'local'}),
}
# settings-reference.md "Variables Claude Code ignores in `env`" and env-vars.md (fetched 2026-10-24).
# Reasons: project_local = dropped from project and local settings; every_file = dropped from every
# settings file; telemetry_unless_off = dropped from project and local settings unless the value turns
# telemetry off (`none` for the exporter selectors, an off value for three content variables; values
# aren't collected, so only the name is judged); ignored_if_1 = CLAUDE_CODE_ENABLE_CFC=1 and OTEL_LOG_MANAGED_SETTINGS=1
# (2.1.274+) are ignored in project and local settings (env-vars.md), other values apply.
ENV_PROJECT_LOCAL = frozenset({
    'CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_TMPDIR', 'HOME', 'TMPDIR', 'TMP', 'TEMP',
    'SystemRoot', 'ComSpec', 'ProgramData', 'LOCALAPPDATA', 'PATHEXT', 'PSModulePath',
    'OTEL_LOG_RAW_API_BODIES', 'ENABLE_BETA_TRACING_DETAILED', 'BETA_TRACING_ENDPOINT',
    'CLAUDE_CODE_ENABLE_TELEMETRY', 'CLAUDE_CODE_ENHANCED_TELEMETRY_BETA', 'ENABLE_ENHANCED_TELEMETRY_BETA',
    'OTEL_LOG_ASSISTANT_RESPONSES', 'OTEL_EXPORTER_PROMETHEUS_HOST', 'OTEL_EXPORTER_PROMETHEUS_PORT',
    'CLAUDE_CODE_PROCESS_WRAPPER', 'CLAUDE_CODE_SYNC_SKILLS', 'CLAUDE_CODE_SYNC_PLUGINS',
    'CLAUDE_CODE_PLUGIN_CACHE_DIR', 'CLAUDE_CODE_PLUGIN_SEED_DIR', 'CLAUDE_CODE_USER_DIALOG_TIMEOUT_MS',
    'CLAUDE_CODE_DISABLE_ATTACHMENTS', 'CLAUDE_CODE_DISABLE_FILE_MENTIONS'})
ENV_PROJECT_LOCAL_PREFIXES = ('XDG_', 'CLAUDE_AX_', 'ProgramFiles')  # the XDG_* family, CLAUDE_AX_*, the ProgramFiles family
ENV_OTLP = re.compile(r'OTEL_EXPORTER_OTLP_(?:[A-Z]+_)*(?:ENDPOINT|HEADERS|PROTOCOL|CERTIFICATE|CLIENT_KEY|INSECURE)')
# env-vars.md: a value in project or local settings doesn't turn these on (CFC: ignores `1`).
ENV_IGNORED_IF_1 = frozenset({'CLAUDE_CODE_ENABLE_CFC', 'OTEL_LOG_MANAGED_SETTINGS'})
ENV_TELEMETRY_UNLESS_OFF = frozenset({'OTEL_LOGS_EXPORTER', 'OTEL_METRICS_EXPORTER', 'OTEL_TRACES_EXPORTER',
                                      'OTEL_LOG_USER_PROMPTS', 'OTEL_LOG_TOOL_CONTENT', 'OTEL_LOG_TOOL_DETAILS'})
ENV_EVERY_FILE = frozenset({
    'CLAUDE_CODE_REMOTE', 'CLAUDE_CODE_ACCOUNT_UUID', 'CLAUDE_CODE_MESSAGING_SOCKET', 'CLAUDE_CODE_MESSAGING_TOKEN',
    'CLAUDE_CODE_PROJECT_DIR_NAME', 'CLAUDE_CODE_RESTRICTED', 'CLAUDE_CODE_DISABLE_POWERSHELL_CMD_RM_DENY',
    'CLAUDE_CODE_DISABLE_DANGEROUS_RM_TIMEOUT', 'CLAUDE_CODE_DISABLE_SUBSTITUTION_RM_PROMPT',
    'CLAUDE_CODE_DISABLE_INLINE_SHELL_RM_PROMPT', 'CLAUDE_CODE_DISABLE_MOUNTED_DRIVE_RM_PROMPT',
    'CLAUDE_CODE_WARN_DISK_FREE_GIB', 'CLAUDE_CODE_WARN_MEMORY_FREE_GIB'})


def _env_reason(name, layer):
    """Why a settings file of this layer ignores env var `name`, else None."""
    if name in ENV_EVERY_FILE:
        return 'every_file' if layer != 'managed' else None
    if layer not in ('project', 'local'):
        return None
    if name in ENV_TELEMETRY_UNLESS_OFF:
        return 'telemetry_unless_off'
    if name in ENV_IGNORED_IF_1:
        return 'ignored_if_1'
    if name in ENV_PROJECT_LOCAL or name.startswith(ENV_PROJECT_LOCAL_PREFIXES) or ENV_OTLP.fullmatch(name):
        return 'project_local'
    return None


def _present(data, path):
    """True when the dotted key path holds a value other than null (null removes a key)."""
    node = data
    for part in path.split('.'):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return node is not None


def scope_ignored(layer, data):
    """(scope_ignored_keys, ignored_env_keys) for one settings file; see references/checklist.md HYG-scope-ignored.

    `layer` is user, project, local or managed. Keys are matched at their documented (nested) path; a nested
    key is left out when its parent is already reported. Names and table vocabulary only, never values.
    """
    if not isinstance(data, dict):
        return [], []
    keys = []
    for key in sorted(SETTINGS_SCOPES):
        klass = SETTINGS_SCOPES[key]
        parent = key.rpartition('.')[0]
        if layer in SCOPE_IGNORED_IN[klass] and _present(data, key) and not (
                parent in SETTINGS_SCOPES and layer in SCOPE_IGNORED_IN[SETTINGS_SCOPES[parent]]
                and _present(data, parent)):
            keys.append({'key': key, 'scope': klass})
    env = data.get('env')
    names = sorted(n for n in env if isinstance(n, str)) if isinstance(env, dict) else []
    return keys, [{'name': n, 'reason': r} for n in names for r in [_env_reason(n, layer)] if r]
