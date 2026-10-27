"""Value-free MCP and hook facts, .envrc presence and documented env names.

This module never opens ~/.claude.json and never reads .envrc contents; it also never reads,
returns or stores an env, headers or oauth value or the names inside those mappings. What it offers:
- ``server_facts`` / ``server_map``: transport, executable name, URL origin and locality labels,
  package version shape and which of ``oauth``/``headersHelper`` keys are present on an MCP server
  config that another loader (.mcp.json, managed or plugin MCP files) already parsed.
- ``hook_handler_view``: a hook handler without its ``headers`` and ``allowedEnvVars`` fields, for
  fingerprinting.
- ``envrc_present``: whether <root>/.envrc exists, by stat only.
- ``documented_env_set``: which names from a fixed, caller-supplied vocabulary are keys of a settings
  object's ``env`` mapping (no other name and no value leaves).
"""
import ipaddress
import os
import re
from urllib.parse import urlsplit

HANDLER_CREDENTIAL_FIELDS = ('headers', 'allowedEnvVars')


def documented_env_set(settings, names):
    """Sorted names from ``names`` that are keys of ``settings['env']``; no other key or any value is read."""
    if not isinstance(settings, dict) or not isinstance(settings.get('env'), dict):
        return []
    env = settings['env']
    return sorted(n for n in names if n in env)


def hook_handler_view(handler):
    """Copy of a hook handler without its ``headers`` and ``allowedEnvVars`` fields, for fingerprinting."""
    return {k: v for k, v in handler.items() if k not in HANDLER_CREDENTIAL_FIELDS}


def envrc_present(root):
    """True when <root>/.envrc exists as a file (stat only; the file is never opened)."""
    try:
        return os.path.isfile(os.path.join(root, '.envrc'))
    except OSError:
        return False


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
            'plaintext_transport': scheme in ('http', 'ws') and locality != 'loopback'}


def server_facts(config):
    """Value-free view of one MCP server config, everything extensions.mcp_summary reports; None if not a dict.

    Arguments and URL paths/queries/userinfo may hold unlabeled credentials; they are reduced here
    to counts and labels. The env, headers and oauth fields are not read; only the presence of the
    oauth and headersHelper keys is reported.
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
        'configured_mechanisms': [k for k in ('oauth', 'headersHelper') if k in config],
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
