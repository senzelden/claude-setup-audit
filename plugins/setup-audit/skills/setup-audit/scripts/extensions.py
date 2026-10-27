"""Bounded MCP/plugin provenance. Never connects, installs, or runs discovered components."""
import os
from pathlib import Path
import re
import config_names
import inventory
import plugin_footprint

MAX_ENTRIES = 100
MAX_PLUGINS = 50
NAME_CAP = 120
OBS_LIMIT = 20

# mcp.md, fetched 2026-09-29: reserved built-in names ("including"; not exhaustive), remote types
# (streamable-http is an alias of http), and the tool-name normalization for plugin servers.
RESERVED_NAMES = frozenset({'workspace', 'claude-in-chrome', 'computer-use', 'Claude Preview', 'Claude Browser'})
REMOTE_TYPES = frozenset({'http', 'streamable-http', 'sse', 'ws'})


def tool_prefix(name, plugin=None):
    """Server segment of mcp__<segment>__<tool>: chars outside [A-Za-z0-9_-] become '_'."""
    norm = lambda s: re.sub(r'[^A-Za-z0-9_-]', '_', s)  # noqa: E731
    return f'plugin_{norm(plugin)}_{norm(name)}' if plugin else norm(name)


def json_object(path, scope, sources):
    data, info = inventory.read_json_object(path)
    sources.append(inventory.source(path, scope, **info))
    return data


def mcp_summary(name, facts, path, scope, redact, project=None, plugin=None):
    """One server row from config_names.server_facts (None: the config was not an object)."""
    item = inventory.source(path, scope, 'collected', name=redact(name), project=project,
                            active_state='unknown', representation='selected_fields')
    if facts is None:
        return dict(item, status='unavailable', reason='invalid_server')
    item['transport'] = facts['transport']
    # Arguments and URL paths may hold unlabeled credentials; config_names reduces them to counts and labels.
    item['executable'] = redact(facts['executable']) if facts['executable'] is not None else 'unknown_or_complex'
    item['argument_count'] = facts['argument_count']
    item['package_version_evidence'] = facts['package_version_evidence']
    if facts['endpoint_origin'] is not None:
        item['endpoint_origin'] = facts['endpoint_origin']
        item['endpoint_detail'] = 'path, query, fragment, port and userinfo omitted'
    # Only the presence of an oauth or headersHelper key is reported, never its content.
    mechanisms = [key + '_configured' for key in facts['configured_mechanisms']]
    item['credential_mechanisms'] = mechanisms or ['not_observed_in_selected_fields']
    declared, has_url = facts['declared_type'], facts['has_url']
    notes = []
    if declared is None and has_url:
        notes.append('url_without_type')
    if declared == 'sdk':
        notes.append('sdk_type_skipped')
    if declared == 'sse':
        notes.append('sse_deprecated')
    if name in RESERVED_NAMES:
        notes.append('reserved_name')
    if declared in REMOTE_TYPES and facts['url_is_empty']:
        notes.append('empty_url_placeholder')
    item['config_notes'] = notes
    item['transport_class'] = ('skipped' if declared == 'sdk' or (declared is None and has_url) else
                               'remote' if declared in REMOTE_TYPES else
                               'local_process' if declared in (None, 'stdio') else 'unknown')
    url = facts['url_facts']
    if url is not None:
        item['endpoint_locality'] = url['endpoint_locality']
        item['url_has_userinfo'], item['url_has_query'] = url['url_has_userinfo'], url['url_has_query']
        item['plaintext_transport'] = url['plaintext_transport']
    item['tool_prefix'] = tool_prefix(redact(name), redact(plugin) if plugin else None)[:NAME_CAP]
    if plugin:
        item['plugin'] = redact(plugin)[:NAME_CAP]
    return item


def mcp_observations(servers, layers, display):
    """Per-source observations for each collected server; never an effective state.

    layers: (user|project|managed, project display path or None, settings summary). A project layer
    applies to servers of that project, or to servers without a project (then its source names it).
    Past OBS_LIMIT, managed-policy observations are kept first, then the rest in collection order.
    """
    for s in servers:
        if s.get('status') != 'collected':
            continue
        project = display(s['project']) if s.get('project') else None
        obs = []  # (is_managed, observation)
        for layer, where, summary in layers:
            if layer == 'project' and project is not None and where != project:
                continue
            managed = layer == 'managed'
            src = summary.get('path', '?')
            policy = summary.get('mcp_policy') or {}

            def add(kind, value, src=src, managed=managed):
                obs.append((managed, dict(source=src, kind=kind, value=value)))

            if s['scope'] == 'project':
                for key, kind in (('enabledMcpjsonServers', 'approval_enabled'),
                                  ('disabledMcpjsonServers', 'approval_rejected')):
                    if isinstance(policy.get(key), list) and s['name'] in policy[key]:
                        add(kind, True)
                if isinstance(policy.get('enableAllProjectMcpServers'), bool):
                    add('approval_enable_all', policy['enableAllProjectMcpServers'])
            for key, kind in (('allowedMcpServers', 'policy_allowed_by_name'),
                              ('deniedMcpServers', 'policy_denied_by_name')):
                shape = policy.get(key)
                if isinstance(shape, dict) and s['name'] in shape.get('server_names', []):
                    add(kind, True)
            rules = summary.get('mcp_permission_rules') or {}
            for kind in ('allow', 'ask', 'deny'):
                counts = rules.get(kind) or {}
                if counts.get(s.get('tool_prefix')):
                    add(f'permission_{kind}', counts[s['tool_prefix']])
                if counts.get('*'):
                    add(f'permission_{kind}_any_server', counts['*'])
        keep = sorted(sorted(range(len(obs)), key=lambda i: (not obs[i][0], i))[:OBS_LIMIT])
        s['policy_observations'] = [obs[i][1] for i in keep]
        if len(obs) > OBS_LIMIT:
            s['policy_observations_omitted'] = len(obs) - OBS_LIMIT


def collect_extensions(home, claude, roots, contexts, managed_dir, managed_sources, settings, redact, hook_summary,
                       git_status=None):
    sources, servers, plugins = [], [], []

    def servers_from(data, path, scope, project=None, key='mcpServers', bare=False, plugin=None):
        add_servers(config_names.server_map(data, key, bare), path, scope, project, plugin)

    def add_servers(values, path, scope, project=None, plugin=None):
        """values: {name: config_names.server_facts} or None for a server map that is not an object."""
        if values is None:
            sources.append(inventory.source(path, scope, 'unavailable', reason='invalid_server_map'))
            return
        remaining = max(0, MAX_ENTRIES - len(servers))
        names = sorted(values)
        if len(names) > remaining:
            sources.append(inventory.source(path, scope, 'partial', reason='server_limit', omitted=len(names)-remaining))
        servers.extend(mcp_summary(n, values[n], path, scope, redact, project, plugin) for n in names[:remaining])

    project_paths = sorted(set(roots) | {c['session_cwd'] for c in contexts})
    for root in project_paths:
        path = os.path.join(root, '.mcp.json')
        before = len(servers)
        servers_from(json_object(path, 'project', sources), path, 'project', root)
        if git_status and len(servers) > before:
            state = git_status(root, '.mcp.json')
            for server in servers[before:]:
                server['file_git_status'] = state
    if managed_dir:
        path = os.path.join(managed_dir, 'managed-mcp.json')
        servers_from(json_object(path, 'managed', sources), path, 'managed')
    for src in managed_sources:
        path = src['source']
        if src['status'] == 'collected' and path.endswith('.json'):
            servers_from(json_object(path, 'managed', sources), path, 'managed', key='managedMcpServers')

    registry_path = os.path.join(claude, 'plugins', 'installed_plugins.json')
    registry_data = json_object(registry_path, 'plugin_registry', sources)
    registry_read = sources[-1]['status'] == 'collected'
    registry = registry_data.get('plugins')
    registry_valid = registry_read and isinstance(registry, dict)
    if registry_read and not isinstance(registry, dict):
        sources.append(inventory.source(registry_path, 'plugin_registry', 'unavailable', reason='unknown_registry_shape'))
    if not isinstance(registry, dict):
        registry = {}
    if any(not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows)
           for rows in registry.values()):
        sources.append(inventory.source(registry_path, 'plugin_registry', 'partial', reason='unknown_registry_shape'))
    records = [(name, row) for name in sorted(registry) if isinstance(registry[name], list)
               for row in registry[name] if isinstance(row, dict)]
    selected = []
    for name, row in records:
        scope = row.get('scope')
        project = row.get('projectPath') if isinstance(row.get('projectPath'), str) else None
        if scope in ('project', 'local') and project not in project_paths:
            continue
        if scope not in ('user', 'project', 'local', 'managed'):
            sources.append(inventory.source(registry_path, 'plugin_registry', 'not_checked', reason='unknown_install_scope'))
            continue
        selected.append((name, row))
    if registry_valid:
        sources.append(inventory.source(registry_path + '#selected-installs', 'plugin_registry',
                                        'partial' if len(selected) > MAX_PLUGINS else 'collected',
                                        eligible=len(selected), scanned=min(len(selected), MAX_PLUGINS),
                                        omitted=max(0, len(selected)-MAX_PLUGINS)))
    for name, row in selected[:MAX_PLUGINS]:
        plugin = dict(name=redact(name), scope=row.get('scope'), project=project,
                      version=redact(str(row.get('version', 'unknown'))), active_state='unknown',
                      enablement_observations=[dict(source=s['path'], value=s['enabled_plugins'][name])
                                               for s in settings if isinstance(s.get('enabled_plugins'), dict)
                                               and name in s['enabled_plugins']], components=[])
        plugins.append(plugin)
        root = row.get('installPath')
        cache = os.path.realpath(os.path.join(claude, 'plugins'))
        if not isinstance(root, str) or not os.path.isabs(root) or not os.path.realpath(root).startswith(cache + os.sep):
            plugin.update(status='not_checked', reason='install_path_outside_plugin_storage')
            continue
        plugin.update(source=root, status='collected')
        manifest_path = os.path.join(root, '.claude-plugin', 'plugin.json')
        manifest = json_object(manifest_path, 'plugin', sources)
        plugin['manifest_keys'] = sorted(manifest)
        plugin_name = (manifest['name'] if isinstance(manifest.get('name'), str) and manifest['name']
                       else name.split('@')[0])
        for kind, default in (('hooks', 'hooks/hooks.json'), ('mcpServers', '.mcp.json'),
                              ('skills', 'skills'), ('agents', 'agents'), ('commands', 'commands')):
            field = manifest.get(kind)
            paths = [default] if kind not in ('agents', 'commands') or field is None else []
            inline = []
            for value in field if isinstance(field, list) else [field]:
                if isinstance(value, str):
                    paths.append(value)
                elif isinstance(value, dict):
                    inline.append(value)
            for data in inline:
                if kind == 'mcpServers':
                    servers_from(data, manifest_path, 'plugin', plugin['project'], bare=True, plugin=plugin_name)
                elif kind == 'hooks':
                    add_hooks(plugin, data, manifest_path, hook_summary, root)
            if len(set(paths)) > MAX_ENTRIES:
                sources.append(inventory.source(manifest_path, 'plugin', 'partial', reason='component_path_limit',
                                                omitted=len(set(paths))-MAX_ENTRIES))
            for rel in sorted(set(paths))[:MAX_ENTRIES]:
                path = os.path.abspath(os.path.join(root, rel))
                if not path.startswith(os.path.abspath(root) + os.sep) or not os.path.realpath(path).startswith(os.path.realpath(root) + os.sep):
                    sources.append(inventory.source(manifest_path, 'plugin', 'not_checked', reason='external_component_path'))
                    continue
                if kind in ('hooks', 'mcpServers'):
                    data = json_object(path, 'plugin', sources)
                    if kind == 'mcpServers':
                        servers_from(data, path, 'plugin', plugin['project'], bare=True, plugin=plugin_name)
                    else:
                        add_hooks(plugin, data, path, hook_summary, root)
                else:
                    component_files(plugin, path, kind, sources, redact)
    sources.extend(inventory.source(s['source'], s['scope'], s['status'], name=s['name']) for s in servers)
    sources.extend(inventory.source(p.get('source', registry_path), 'plugin', p['status']) for p in plugins)
    return dict(mcp_servers=servers, plugins=plugins, sources=sources,
                limitations=['Effective activation, runtime overrides and remote connectors remain unknown; approvals, server policy and permission rules are per-source observations, not effective state.',
                             'Registry-selected installs only; no newest-cache guess. External component paths are not followed.',
                             'Selected fields omit argument values, URL paths and credentials. Package pinning is a syntax signal.'])


def add_hooks(plugin, data, path, hook_summary, root=None):
    # A hooks file that lists JS `modules` has no event table of its own; its modules are not read.
    hooks = data.get('hooks', {} if isinstance(data, dict) and 'modules' in data else data)
    if not isinstance(hooks, dict):
        plugin['components'].append(dict(source=path, kind='hooks', status='unavailable'))
        return
    try:
        handlers = [dict(hook_summary(ev, group.get('matcher'), h), **plugin_footprint.hook_effects(ev, h, root))
                    for ev, groups in hooks.items() for group in groups for h in group.get('hooks', [])]
        component = dict(source=path, kind='hooks', handlers=handlers[:MAX_ENTRIES],
                         status='partial' if len(handlers) > MAX_ENTRIES else 'collected')
        plugin['components'].append(component)
    except (TypeError, AttributeError, KeyError):
        plugin['components'].append(dict(source=path, kind='hooks', status='unavailable'))


def component_files(plugin, base, kind, sources, redact):
    paths = []
    if os.path.isdir(base) and not os.path.islink(base):
        def error(_):
            sources.append(inventory.source(base, 'plugin', 'partial', reason='directory_read_failed'))
        for i, (directory, dirs, files) in enumerate(os.walk(base, followlinks=False, onerror=error)):
            dirs[:] = sorted(d for d in dirs if d not in inventory.SKIP and not os.path.islink(os.path.join(directory, d)))
            if i >= 100 or len(paths) >= 100:
                sources.append(inventory.source(base, 'plugin', 'partial', reason='component_scan_limit'))
                break
            wanted = (lambda f: f == 'SKILL.md') if kind == 'skills' else (lambda f: f.endswith('.md'))
            paths.extend(os.path.join(directory, f) for f in sorted(files) if wanted(f))
    else:
        paths = [base]
    if len(paths) > 100:
        sources.append(inventory.source(base, 'plugin', 'partial', reason='component_file_limit', omitted=len(paths)-100))
    for path in paths[:100]:
        text, info = inventory.read_text(path)
        sources.append(inventory.source(path, 'plugin', **info))
        if text is None:
            continue
        fields, status = inventory.frontmatter(text)
        plugin['components'].append(dict(source=path, kind=kind, **info,
                                         frontmatter={k: redact(v) for k, v in fields.items()},
                                         frontmatter_status=status, excerpt=redact(text)))
