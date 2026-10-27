"""Bounded plugin provenance (MCP config files are not read). Never connects, installs, or runs discovered components."""
import os
from pathlib import Path
import inventory
import plugin_footprint

MAX_ENTRIES = 100
MAX_PLUGINS = 50
NAME_CAP = 120


def json_object(path, scope, sources):
    data, info = inventory.read_json_object(path)
    sources.append(inventory.source(path, scope, **info))
    return data


def collect_extensions(home, claude, roots, contexts, settings, redact, hook_summary):
    sources, plugins = [], []
    project_paths = sorted(set(roots) | {c['session_cwd'] for c in contexts})

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
        for kind, default in (('hooks', 'hooks/hooks.json'), ('skills', 'skills'), ('agents', 'agents'), ('commands', 'commands')):
            field = manifest.get(kind)
            paths = [default] if kind not in ('agents', 'commands') or field is None else []
            inline = []
            for value in field if isinstance(field, list) else [field]:
                if isinstance(value, str):
                    paths.append(value)
                elif isinstance(value, dict):
                    inline.append(value)
            for data in inline:
                if kind == 'hooks':
                    add_hooks(plugin, data, manifest_path, hook_summary, root)
            if len(set(paths)) > MAX_ENTRIES:
                sources.append(inventory.source(manifest_path, 'plugin', 'partial', reason='component_path_limit',
                                                omitted=len(set(paths))-MAX_ENTRIES))
            for rel in sorted(set(paths))[:MAX_ENTRIES]:
                path = os.path.abspath(os.path.join(root, rel))
                if not path.startswith(os.path.abspath(root) + os.sep) or not os.path.realpath(path).startswith(os.path.realpath(root) + os.sep):
                    sources.append(inventory.source(manifest_path, 'plugin', 'not_checked', reason='external_component_path'))
                    continue
                if kind == 'hooks':
                    add_hooks(plugin, json_object(path, 'plugin', sources), path, hook_summary, root)
                else:
                    component_files(plugin, path, kind, sources, redact)
    sources.extend(inventory.source(p.get('source', registry_path), 'plugin', p['status']) for p in plugins)
    return dict(plugins=plugins, sources=sources,
                limitations=['Effective activation, runtime overrides and remote connectors remain unknown.',
                             'MCP config files are not read, so there is no MCP server inventory; the user reviews servers with `claude mcp list`.',
                             'Registry-selected installs only; no newest-cache guess. External component paths are not followed.'])


def add_hooks(plugin, data, path, hook_summary, root=None):
    # JS hook `modules` are not read; any events beside them still are, and the component says partial.
    modules = isinstance(data, dict) and 'modules' in data
    hooks = data.get('hooks', {k: v for k, v in data.items() if k != 'modules'} if modules else data)
    if not isinstance(hooks, dict):
        plugin['components'].append(dict(source=path, kind='hooks', status='unavailable'))
        return
    try:
        handlers = [dict(hook_summary(ev, group.get('matcher'), h), **plugin_footprint.hook_effects(ev, h, root))
                    for ev, groups in hooks.items() for group in groups for h in group.get('hooks', [])]
        component = dict(source=path, kind='hooks', handlers=handlers[:MAX_ENTRIES],
                         status='partial' if modules or len(handlers) > MAX_ENTRIES else 'collected')
        if modules:
            component['reason'] = 'js_modules_not_scanned'
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
