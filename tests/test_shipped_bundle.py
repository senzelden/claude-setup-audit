import ast
import re
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/setup-audit'
ICON = PLUGIN / '.claude-plugin/icon.png'

# Plugin directory rules (claude.com/docs/plugins/pre-submission-checklist, fetched 2026-10-27):
# a bundled image referenced from the plugin is held for a reviewer, and a credential source
# named next to a network destination reads as "uses a credential from the user's machine". The
# scanner matches per file: on 0.13.1 and 0.13.2 it flagged exactly the files CREDENTIAL_SOURCE and
# URL both match (plugin.json through its `direnv` keyword). These guards keep each shipped file
# clear of both patterns.
IMAGE_OR_FONT_PATH = re.compile(r'\.(png|jpe?g|gif|webp|woff2?|ttf|otf|ico)\b', re.I)
CREDENTIAL_SOURCE = re.compile(
    r'\.claude\.json|\.envrc|\.credentials\.json|\bdirenv\b'
    r'|\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)[A-Z0-9_]*\b|\b[A-Z0-9_]+_KEY\b')
URL = re.compile(r'https?://')
# Added in 0.11.0, the first version the directory held: telemetry export and gateway names (an
# endpoint plus its auth headers) and mod API calls written as an environment read beside a network
# send. Kept out of shipped files from 0.14.1.
EXPORT_VOCABULARY = re.compile(r'OTEL_|BETA_TRACING|GatewayUrl|\benv\.get\b|\bhttp\.fetch\b')
# Also added in 0.11.0: --hash-salt-file read a key (the HMAC salt) from a user file. Gone from 0.14.2.
# The sandbox credential proxy forwards a credential to chosen hosts. apply_ops wrote its entries and
# collect recorded whether it was set; from 0.14.4 neither does (apply_ops refuses the whole subtree).
CREDENTIAL_PROXY = re.compile(r'sandbox\.credentials\.(?:files|envVars)|sandbox_credentials|injectHosts'
                              r'|maskClaims|maskDuplicates|onExtractNoMatch|credential_files|credential_env'
                              r'|allowPlaintextInject|awsPairs|sigv4')
SALT_FILE = re.compile(r'salt[ _-]file|hash-salt|hash_salt', re.I)

# Also added in 0.11.0: HYG-scope-ignored, whose tables named credential-adjacent settings and env
# variables. Gone from 0.14.3.
SCOPE_IGNORED = re.compile(r'scope[_-]ignored|ignored_env_keys|SETTINGS_SCOPES|ENV_EVERY_FILE')

# Also added in 0.11.0: SEC-mods and the mods inventory, which read a plugin's JS hook modules and
# the managed guard options. Gone from 0.14.3.
MODS_FEATURE = re.compile(r'SEC-mods|mods_policy|allowManagedModsOnly|allowModsToOverrideDenyRules'
                          r'|cc-plugin-sec-default|scan_mod|MOD_EVENT|MOD_CALL'
                          r'|components\[\]\.mod\b|settings\[\]\.mods\b')
# Helper-command settings run a user-supplied command whose output is a credential; the never-open
# rule describes them by family. Gone from shipped text in 0.14.3.
HELPER_COMMAND_KEYS = re.compile(r'apiKeyHelper|awsAuthRefresh|awsCredentialExport|otelHeadersHelper|gcpAuthRefresh')

# Also added in 0.11.0: the MCP inventory, which opened project .mcp.json, managed-mcp.json,
# managed managedMcpServers and installed plugins' MCP files, where servers keep env and headers
# credentials (rule MCP_FORWARDS_CREDENTIAL_ENV). Gone from 0.14.5; the audit tells the user to
# review MCP servers themselves.
MCP_INVENTORY = re.compile(r'servers_from|server_facts|server_map|mcp_observations|credential_mechanisms'
                           r'|managedMcpServers|SEC-mcp-exposure')
MCP_FILE_NAMES = ('.mcp.json', 'managed-mcp.json')


# Stdlib modules that can open a connection (or load one by name); urllib.parse only parses URLs.
NETWORK_MODULES = ('socket', 'socketserver', 'ssl', 'http', 'urllib.request', 'urllib.error', 'ftplib',
                   'smtplib', 'imaplib', 'poplib', 'nntplib', 'telnetlib', 'xmlrpc', 'asyncio',
                   'webbrowser', 'importlib')


def imported_modules(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module == 'urllib':
                yield from ('urllib.' + a.name for a in node.names)
            else:
                yield node.module
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == '__import__'
              and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            yield node.args[0].value


def network_module(name):
    return any(name == m or name.startswith(m + '.') for m in NETWORK_MODULES)


def shipped_text_files():
    for path in sorted(PLUGIN.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path != ICON:
            yield path, path.read_text(encoding='utf-8')


class ShippedBundleTests(unittest.TestCase):
    def test_no_evals_in_plugin(self):
        self.assertFalse((PLUGIN / 'evals').exists())
        self.assertTrue((ROOT / 'evals/README.md').is_file())

    def test_listing_icon_at_default_path(self):
        # The directory picks up .claude-plugin/icon.png without a manifest field: square PNG,
        # 512 to 2048 px, under 2 MB.
        data = ICON.read_bytes()
        self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
        width, height = struct.unpack('>II', data[16:24])
        self.assertEqual(width, height)
        self.assertTrue(512 <= width <= 2048, width)
        self.assertLess(len(data), 2 * 1024 * 1024)

    def test_no_shipped_file_refers_to_an_image_or_font(self):
        for path, text in shipped_text_files():
            self.assertIsNone(IMAGE_OR_FONT_PATH.search(text), path.relative_to(ROOT))

    def test_no_shipped_file_pairs_a_credential_source_with_a_url(self):
        # Docs are cited by page name (docs-map.md holds the base URL) wherever a file names a
        # credential-bearing file or variable.
        for path, text in shipped_text_files():
            source, url = CREDENTIAL_SOURCE.search(text), URL.search(text)
            self.assertFalse(source and url, '%s: %s with %s' % (
                path.relative_to(ROOT), source and source.group(), url and url.group()))

    def test_no_shipped_file_names_telemetry_export_or_mod_credential_calls(self):
        for path, text in shipped_text_files():
            match = EXPORT_VOCABULARY.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))

    def test_no_shipped_file_configures_the_credential_proxy(self):
        for path, text in shipped_text_files():
            match = CREDENTIAL_PROXY.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))

    def test_no_shipped_script_makes_network_requests(self):
        # 0.14.4: fetch_doc.py was the only sender; docs now come through Claude's own web tools.
        for path, text in shipped_text_files():
            self.assertNotIn('fetch_doc', text, path.relative_to(ROOT))
            if path.suffix == '.py':
                found = sorted(m for m in imported_modules(ast.parse(text)) if network_module(m))
                self.assertEqual(found, [], path.relative_to(ROOT))

    def test_network_module_check_catches_the_stdlib_senders(self):
        tree = ast.parse('import os, socket\nimport urllib.parse, urllib.request\nfrom http import client\n'
                         'from asyncio import open_connection\nimport importlib\n__import__("ssl")\n'
                         'from urllib.parse import urlsplit\nimport xmlrpc.client\n')
        self.assertEqual(sorted(m for m in imported_modules(tree) if network_module(m)),
                         ['asyncio', 'http', 'importlib', 'socket', 'ssl', 'urllib.request', 'xmlrpc.client'])

    def test_no_shipped_file_offers_a_salt_file(self):
        for path, text in shipped_text_files():
            match = SALT_FILE.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))

    def test_no_shipped_file_offers_scope_ignored_settings(self):
        for path, text in shipped_text_files():
            match = SCOPE_IGNORED.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))
        sys.path.insert(0, str(PLUGIN / 'skills/setup-audit/scripts'))
        try:
            import config_checks
        finally:
            sys.path.pop(0)
        self.assertFalse(hasattr(config_checks, 'scope_ignored'))

    def test_no_shipped_file_offers_the_mods_inventory(self):
        for path, text in shipped_text_files():
            match = MODS_FEATURE.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))
        sys.path.insert(0, str(PLUGIN / 'skills/setup-audit/scripts'))
        try:
            import collect
            import extensions
        finally:
            sys.path.pop(0)
        self.assertFalse(hasattr(collect, 'mods_policy'))
        self.assertFalse(hasattr(extensions, 'scan_mod'))

    def test_no_shipped_file_names_a_helper_command_setting(self):
        for path, text in shipped_text_files():
            match = HELPER_COMMAND_KEYS.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))

    def test_no_shipped_file_offers_the_mcp_inventory(self):
        for path, text in shipped_text_files():
            match = MCP_INVENTORY.search(text)
            self.assertIsNone(match, '%s: %s' % (path.relative_to(ROOT), match and match.group()))

    def test_no_shipped_script_names_an_mcp_config_file(self):
        for path, text in shipped_text_files():
            if path.suffix != '.py':
                continue
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    for name in MCP_FILE_NAMES:
                        self.assertNotIn(name, node.value, '%s: %s' % (path.relative_to(ROOT), name))


class RiskyRulePatterns(unittest.TestCase):
    # collect.py builds these two patterns from named command lists (a regex that inlines download
    # and interpreter commands reads to the scan as download-and-run); the regexes are unchanged.
    def test_patterns_unchanged(self):
        sys.path.insert(0, str(PLUGIN / 'skills/setup-audit/scripts'))
        import collect
        patterns = dict((flag, rx.pattern) for flag, rx in collect.RISKY_RULES if hasattr(rx, 'pattern'))
        self.assertEqual(patterns['network-wildcard'],
                         r"Bash\((curl|wget|nc|ssh|scp|rsync)[ :]\*?\*?\)|Bash\((curl|wget)[: ]\*")
        self.assertEqual(patterns['interpreter-wildcard'],
                         r"Bash\((python3?|node|bash|sh|npx|uv run|\.venv/bin/python)[ :]*(-[ce]\s*['\"]?\s*)?\*")


if __name__ == '__main__':
    unittest.main()
