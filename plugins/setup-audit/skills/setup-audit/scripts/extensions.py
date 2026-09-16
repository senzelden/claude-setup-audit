"""Bounded MCP/plugin provenance. Never connects, installs, or runs discovered components."""
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import inventory

MAX_ENTRIES = 100
MAX_PLUGINS = 50


def json_object(path, scope, sources):
    text, info = inventory.read_text(path, 1024 * 1024)
    data = {}
    if text is not None and not info.get('truncated'):
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ValueError()
        except ValueError:
            data = {}
            info.update(status='unavailable', reason='invalid_json_object')
    sources.append(inventory.source(path, scope, **info))
    return data


def mcp_summary(name, config, path, scope, redact, project=None):
    item = inventory.source(path, scope, 'collected', name=redact(name), project=project,
                            active_state='unknown', representation='selected_fields')
    if not isinstance(config, dict):
        return dict(item, status='unavailable', reason='invalid_server')
    command = config.get('command')
    item['transport'] = config.get('type', 'stdio') if isinstance(config.get('type', 'stdio'), str) else 'unknown'
    # Arguments and URL paths may hold unlabeled credentials; do not serialize them.
    item['executable'] = (redact(command) if isinstance(command, str) and
                          re.fullmatch(r'[\w./${}-]+', command) else 'unknown_or_complex')
    args = config.get('args', [])
    item['argument_count'] = len(args) if isinstance(args, list) else None
    item['package_version_evidence'] = 'unknown'
    if isinstance(command, str) and os.path.basename(command) in ('npx', 'uvx') and isinstance(args, list):
        packages = [a for a in args if isinstance(a, str) and not a.startswith('-')]
        if packages:
            candidate = packages[0]
            item['package_version_evidence'] = ('exact_version_shape' if re.fullmatch(
                r'(?:@[\w.-]+/)?[\w.-]+(?:@|==)\d+\.\d+\.\d+(?:-[\w.-]+)?', candidate) else 'no_exact_version_observed')
    url = config.get('url')
    if isinstance(url, str):
        try:
            parts = urlsplit(url)
            item['endpoint_origin'] = (f'{parts.scheme}://{parts.hostname}' if parts.scheme in ('http', 'https', 'ws', 'wss')
                                       and parts.hostname else 'dynamic_or_unknown')
        except ValueError:
            item['endpoint_origin'] = 'invalid_url'
        item['endpoint_detail'] = 'path, query, fragment, port and userinfo omitted'
    mechanisms = []
    for key in ('env', 'headers'):
        values = config.get(key)
        item[key + '_keys'] = sorted(values) if isinstance(values, dict) else []
        if isinstance(values, dict) and values:
            refs = sorted({m.group(1) for v in values.values() if isinstance(v, str)
                           for m in re.finditer(r'\$\{([A-Za-z_][A-Za-z_0-9]*)(?::-[^}]*)?\}', v)})
            item[key + '_variable_references'] = refs
            mechanisms.append(key + ('_references_or_literals' if refs else '_configured_values_omitted'))
    for key in ('oauth', 'headersHelper'):
        if key in config:
            mechanisms.append(key + '_configured')
    item['credential_mechanisms'] = mechanisms or ['not_observed_in_selected_fields']
    return item


def collect_extensions(home, claude, roots, contexts, managed_dir, managed_sources, settings, redact, hook_summary):
    sources, servers, plugins = [], [], []

    def servers_from(data, path, scope, project=None, key='mcpServers', bare=False):
        values = data.get(key, data if bare else {})
        if not isinstance(values, dict):
            sources.append(inventory.source(path, scope, 'unavailable', reason='invalid_server_map'))
            return
        remaining = max(0, MAX_ENTRIES - len(servers))
        names = sorted(values)
        if len(names) > remaining:
            sources.append(inventory.source(path, scope, 'partial', reason='server_limit', omitted=len(names)-remaining))
        servers.extend(mcp_summary(n, values[n], path, scope, redact, project) for n in names[:remaining])

    user_path = os.path.join(home, '.claude.json')
    user = json_object(user_path, 'user', sources)
    servers_from(user, user_path, 'user')
    project_paths = sorted(set(roots) | {c['session_cwd'] for c in contexts})
    local = user.get('projects', {})
    for root in project_paths:
        if isinstance(local, dict) and isinstance(local.get(root), dict):
            servers_from(local[root], user_path, 'local', root)
        path = os.path.join(root, '.mcp.json')
        servers_from(json_object(path, 'project', sources), path, 'project', root)
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
        project = row.get('projectPath')
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
        plugin = dict(name=redact(name), scope=row.get('scope'), project=row.get('projectPath'),
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
                    servers_from(data, manifest_path, 'plugin', plugin['project'], bare=True)
                elif kind == 'hooks':
                    add_hooks(plugin, data, manifest_path, hook_summary)
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
                        servers_from(data, path, 'plugin', plugin['project'], bare=True)
                    else:
                        add_hooks(plugin, data, path, hook_summary)
                else:
                    component_files(plugin, path, kind, sources, redact)
    sources.extend(inventory.source(s['source'], s['scope'], s['status'], name=s['name']) for s in servers)
    sources.extend(inventory.source(p.get('source', registry_path), 'plugin', p['status']) for p in plugins)
    return dict(mcp_servers=servers, plugins=plugins, sources=sources,
                limitations=['Activation, approval, runtime overrides, remote connectors and server policy remain unknown.',
                             'Registry-selected installs only; no newest-cache guess. External component paths are not followed.',
                             'Selected fields omit argument values, URL paths and credentials. Package pinning is a syntax signal.'])


def add_hooks(plugin, data, path, hook_summary):
    hooks = data.get('hooks', data)
    if not isinstance(hooks, dict):
        plugin['components'].append(dict(source=path, kind='hooks', status='unavailable'))
        return
    try:
        handlers = [hook_summary(ev, group.get('matcher'), h) for ev, groups in hooks.items()
                    for group in groups for h in group.get('hooks', [])]
        plugin['components'].append(dict(source=path, kind='hooks', handlers=handlers[:MAX_ENTRIES],
                                         status='partial' if len(handlers) > MAX_ENTRIES else 'collected'))
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
            paths.extend(os.path.join(directory, f) for f in sorted(files) if f.endswith('.md'))
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
