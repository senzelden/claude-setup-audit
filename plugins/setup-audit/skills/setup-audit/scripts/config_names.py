"""Names-only reads of credential-bearing configuration.

Reads credential-bearing config sources and returns names, counts and booleans only; never
returns, logs or stores a value. "Names" here also covers fixed classification labels (transport,
URL origin and locality, package version shape) and the executable name an MCP server runs.

Values from these sources are interpreted only here (tests/test_config_names.py enforces it):
- MCP server configs: ``env`` and ``headers`` mappings, ``url``, ``args`` and ``oauth``, wherever
  the config comes from (~/.claude.json user and local-project scope, .mcp.json, managed and
  plugin MCP files).
- settings ``env`` and http hook ``headers``.
- a repository's .envrc.

Files: ~/.claude.json (MCP servers and the per-project state lists extensions.py reports) and
.envrc are also opened and read only here. .mcp.json, managed and plugin MCP files and settings
files are opened by their existing loaders, which hand the parsed objects to this module.

A value is looked at only transiently, inside this module, to decide something about it (literal
or ${VAR} reference, URL origin and locality, version shape); only the derived names leave.
"""
import ipaddress
import json
import os
import re
from urllib.parse import urlsplit
import inventory

# ${VAR} or ${VAR:-default}, the MCP config expansion syntax (mcp.md, fetched 2026-09-29).
VAR_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z_0-9]*)(?::-[^}]*)?\}')
# ~/.claude.json projects[<root>] keys extensions.py reports (server names only).
PROJECT_STATE_LISTS = ('enabledMcpjsonServers', 'disabledMcpjsonServers', 'disabledMcpServers', 'enabledMcpServers')
ENVRC_LIMIT = 200_000


def mapping_names(mapping):
    """Names in an env/headers mapping; None when it is not a mapping.

    literal_keys: names whose value is a non-empty string without a ${VAR} reference.
    variable_references: the VAR names referenced from string values.
    """
    if not isinstance(mapping, dict):
        return None
    return {'keys': sorted(mapping),
            'literal_keys': sorted(k for k, v in mapping.items() if isinstance(v, str) and v and not VAR_RE.search(v)),
            'variable_references': sorted({m.group(1) for v in mapping.values() if isinstance(v, str)
                                           for m in VAR_RE.finditer(v)})}


def settings_env_names(settings):
    """Sorted names declared in a settings object's env mapping (values never read)."""
    env = settings.get('env') if isinstance(settings, dict) else None
    return sorted(n for n in env if isinstance(n, str)) if isinstance(env, dict) else []


def hook_header_names(handler):
    """Sorted header names of an http hook handler."""
    names = mapping_names(handler.get('headers'))
    return names['keys'] if names else []


def hook_handler_view(handler):
    """Copy of a hook handler with ``headers`` replaced by its sorted header names, for fingerprinting.

    Every other field is kept as is; a non-mapping ``headers`` value becomes an empty name list.
    """
    view = dict(handler)
    if 'headers' in view:
        view['headers'] = hook_header_names(handler)
    return view


def split_url(url):
    """urlsplit with the WHATWG rule that '\\' equals '/' in special schemes (http, https, ws, wss)."""
    if url.split(':', 1)[0].lower() in ('http', 'https', 'ws', 'wss'):
        url = url.replace('\\', '/')
    return urlsplit(url)


def url_origin(url):
    """scheme://host for http/https/ws/wss URLs with a host; else 'dynamic_or_unknown' ('invalid_url' on ValueError)."""
    try:
        parts = split_url(url)
    except ValueError:
        return 'invalid_url'
    return (f'{parts.scheme}://{parts.hostname}' if parts.scheme in ('http', 'https', 'ws', 'wss')
            and parts.hostname else 'dynamic_or_unknown')


def endpoint_locality(url):
    """Locality from the URL text alone; never resolves names."""
    if '${' in url:
        return 'dynamic'
    try:
        host = split_url(url).hostname
    except ValueError:
        return 'invalid'
    if not host:
        return 'invalid'
    if host == 'localhost':
        return 'loopback'
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return 'named_host'
    if ip.is_loopback:
        return 'loopback'
    if ip.is_private or ip.is_link_local:
        return 'private_address'
    return 'public_address'


def _url_facts(url):
    locality = endpoint_locality(url)
    try:
        parts = split_url(url)
        scheme, userinfo, query = parts.scheme, '@' in parts.netloc, bool(parts.query)
    except ValueError:
        scheme, userinfo, query = '', False, False
    return {'endpoint_locality': locality, 'url_has_userinfo': userinfo, 'url_has_query': query,
            'plaintext_transport': scheme in ('http', 'ws') and locality != 'loopback',
            'url_variable_names': sorted({m.group(1) for m in VAR_RE.finditer(url)})}


def server_facts(config):
    """Value-free view of one MCP server config, everything extensions.mcp_summary reports; None if not a dict.

    Arguments, URL paths/queries/userinfo and env/header/oauth values may hold unlabeled credentials;
    they are reduced here to counts, labels and names.
    """
    if not isinstance(config, dict):
        return None
    transport = config.get('type', 'stdio')
    declared = config.get('type')
    command = config.get('command')
    args = config.get('args', [])
    evidence = 'unknown'
    if isinstance(command, str) and os.path.basename(command) in ('npx', 'uvx') and isinstance(args, list):
        packages = [a for a in args if isinstance(a, str) and not a.startswith('-')]
        if packages:
            evidence = ('exact_version_shape' if re.fullmatch(
                r'(?:@[\w.-]+/)?[\w.-]+(?:@|==)\d+\.\d+\.\d+(?:-[\w.-]+)?', packages[0]) else 'no_exact_version_observed')
    url = config.get('url')
    oauth = config.get('oauth')
    scopes = oauth.get('scopes') if isinstance(oauth, dict) else None
    facts = {
        'transport': transport if isinstance(transport, str) else 'unknown',
        'declared_type': declared if declared is None or isinstance(declared, str) else '<invalid>',
        'executable': command if isinstance(command, str) and re.fullmatch(r'[\w./${}-]+', command) else None,
        'argument_count': len(args) if isinstance(args, list) else None,
        'package_version_evidence': evidence,
        'has_url': 'url' in config,
        'url_is_empty': url == '',
        'endpoint_origin': url_origin(url) if isinstance(url, str) else None,
        'url_facts': _url_facts(url) if isinstance(url, str) and url else None,
        'env_names': mapping_names(config.get('env')),
        'headers_names': mapping_names(config.get('headers')),
        'configured_mechanisms': [k for k in ('oauth', 'headersHelper') if k in config],
        'oauth': ({'keys': [k for k in oauth if isinstance(k, str)],
                   'scopes': [t[:64] for t in scopes.split()] if isinstance(scopes, str) else None}
                  if isinstance(oauth, dict) else None),
    }
    return facts


def server_map(data, key='mcpServers', bare=False):
    """{name: server_facts} for a server map inside a config object; None when the map is not a dict.

    bare: the object itself is the map when ``key`` is absent (plugin .mcp.json shape).
    """
    values = data.get(key, data if bare else {})
    if not isinstance(values, dict):
        return None
    return {name: server_facts(config) for name, config in values.items()}


def user_mcp_state(home):
    """Load ~/.claude.json once and return a value-free view of it.

    {'path', 'source' (collection metadata, as extensions.json_object records it),
     'mcpServers': {name: server_facts} (None if not a dict; absent if not configured),
     'projects': {root: {'mcpServers': ..., <PROJECT_STATE_LISTS present as lists: their string
                         server names>, 'hasTrustDialogAccepted': bool or None}}}.
    Missing, oversized or invalid files give an empty view, mirroring extensions.json_object.
    """
    path = os.path.join(home, '.claude.json')
    data, info = inventory.read_json_object(path)
    view = {'path': path, 'source': inventory.source(path, 'user', **info), 'projects': {}}
    if 'mcpServers' in data:
        view['mcpServers'] = server_map(data)
    projects = data.get('projects', {})
    for root, entry in (projects.items() if isinstance(projects, dict) else ()):
        if not isinstance(entry, dict):
            continue
        row = {k: [x for x in entry[k] if isinstance(x, str)] for k in PROJECT_STATE_LISTS
               if isinstance(entry.get(k), list)}
        trust = entry.get('hasTrustDialogAccepted')
        row['hasTrustDialogAccepted'] = trust if isinstance(trust, bool) else None
        if 'mcpServers' in entry:
            row['mcpServers'] = server_map(entry)
        view['projects'][root] = row
    return view


def user_mcp_server_names(home):
    """Sorted user-scope MCP server names from ~/.claude.json, read whole (collect.py's mcp_user field)."""
    try:
        with open(os.path.join(home, '.claude.json')) as f:
            data = json.load(f)
    except Exception:
        return []
    servers = data.get('mcpServers', {}) if isinstance(data, dict) else {}
    return sorted(servers) if isinstance(servers, dict) else []


def envrc_names(root):
    """Names and facts from <root>/.envrc; None when it is absent or empty.

    declared_names: exported or assigned variables plus use_pass* targets.
    pointer_lines: secret-manager lookups (use_pass, pass show, op read, sops, vault).
    literal_secret_names: KEY/TOKEN/SECRET/PASSWORD-like names exported with a literal of 12+ characters.
    """
    try:
        with open(os.path.join(root, '.envrc'), errors='replace') as f:
            text = f.read(ENVRC_LIMIT)
    except OSError:
        return None
    if not text:
        return None
    declared = set(re.findall(r"^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)=", text, re.M))
    # Not anchored: several use_pass calls may share a line (`use_pass A x; use_pass B y`).
    declared |= set(re.findall(r"\buse_pass\w*\s+([A-Z][A-Z0-9_]*)", text))
    literal = re.findall(r"^\s*export\s+(\w*(?:KEY|TOKEN|SECRET|PASSWORD)\w*)=['\"]?(?![$`'\"])[^\s'\"]{12,}", text, re.M)
    return {'declared_names': sorted(declared),
            'pointer_lines': len(re.findall(r"use_pass|pass show|op read|sops |vault ", text)),
            'literal_secret_names': sorted(set(literal))}
