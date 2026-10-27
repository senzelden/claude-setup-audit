"""Value-free hook facts, .envrc presence and documented env names.

This module never opens ~/.claude.json and never reads .envrc contents; it also never reads,
returns or stores an env, headers or oauth value. MCP config files are not read by the audit at all. What it offers:
- ``url_origin``: scheme://host of a hook handler URL (path, query, userinfo and port dropped).
- ``hook_handler_view``: a hook handler without its ``headers`` and ``allowedEnvVars`` fields, for
  fingerprinting.
- ``envrc_present``: whether <root>/.envrc exists, by stat only.
- ``documented_env_set``: which names from a fixed, caller-supplied vocabulary are keys of a settings
  object's ``env`` mapping (no other name and no value leaves).
"""
import glob
import os
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


ENV_STORE_FILES = ('mise.toml', '.mise.toml', '.devcontainer/devcontainer.json', '.devcontainer.json')


def env_store_files(root):
    """Names of files that may hold environment values (mise [env], devcontainer containerEnv or
    remoteEnv, compose environment). Existence only: a directory listing and stat, never opened."""
    found = []
    try:
        found = [n for n in ENV_STORE_FILES if os.path.isfile(os.path.join(root, n))]
        found += sorted(os.path.basename(p) for p in glob.glob(os.path.join(glob.escape(root), '*compose*.y*ml'))
                        if os.path.isfile(p))
    except OSError:
        pass
    return found


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
