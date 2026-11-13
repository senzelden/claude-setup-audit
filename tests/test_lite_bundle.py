import datetime
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LITE = ROOT / 'plugins/setup-audit-lite'

# Plugin directory rules for the Markdown-only edition (non-Verified orgs: no scripts, no tool
# grants beyond read-only, no image or font references, no credential source next to a URL).
ALLOWED_EXTENSIONS = {'.md', '.txt', '.json', '.yaml', '.yml', '.png', '.jpg', '.jpeg', '.gif',
                      '.webp'}
MAX_TEXT_BYTES = 256 * 1024
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}
TEXT_EXTENSIONS = {'.md', '.txt', '.json', '.yaml', '.yml'}
ALLOWED_TOOLS = {'Read', 'Grep', 'Glob', 'LS'}
FORBIDDEN_NAMES = {'package.json', 'package-lock.json', 'pyproject.toml', 'poetry.lock', 'uv.lock',
                   'pnpm-lock.yaml', 'yarn.lock', 'pnpm-workspace.yaml', 'Pipfile', 'Pipfile.lock'}
# Config files that start local servers or processes.
LOCAL_SERVER_NAMES = {'.mcp.json', '.lsp.json', 'monitors.json'}
FORBIDDEN_DIRS = {'hooks', 'bin', 'workflows', 'scripts', 'monitors'}
# LSP servers and monitors run local processes, like hooks and MCP servers (plugins-reference).
FORBIDDEN_MANIFEST_KEYS = {'icon', 'hooks', 'mcpServers', 'mods', 'modules', 'lspServers', 'monitors'}
UTF8_BOM = b'\xef\xbb\xbf'
IMAGE_OR_FONT_PATH = re.compile(r'\.(png|jpe?g|gif|webp|svg|avif|bmp|ico|woff2?|ttf|otf|eot)\b', re.I)
# Uppercase credential-name words; each has its own red-proof sample (test_each_credential_word).
CREDENTIAL_WORDS = ('TOKEN', 'SECRET', 'PASSWORD', 'PASSWD', 'API_KEY')


def credential_source_regex(words=CREDENTIAL_WORDS, key_suffix=True):
    return re.compile(
        r'(?i:\.claude\.json|\.envrc|\.credentials\.json|\bdirenv\b)'
        r'|\b[A-Z0-9_]*(?:' + '|'.join(words) + r')[A-Z0-9_]*\b'
        + (r'|\b[A-Z0-9_]+_KEY\b' if key_suffix else ''))


CREDENTIAL_SOURCE = credential_source_regex()
URL = re.compile(r'https?://')


def normalise(text):
    """Text as Claude Code's YAML loader sees it: no byte-order mark, LF line endings."""
    return text.lstrip('\ufeff').replace('\r\n', '\n').replace('\r', '\n')


def frontmatter(text):
    """Top-level keys mapped to their inline value plus any indented or '- ' continuation lines;
    None when there is no frontmatter block (CRLF and a BOM are normalised first)."""
    match = re.match(r'---\n(.*?)\n---(\n|$)', normalise(text), re.S)
    if not match:
        return None
    fields = {}
    key = None
    for line in match.group(1).splitlines():
        if line.startswith((' ', '\t', '- ')) and key is not None:
            fields[key] += ' ' + line.strip()
            continue
        name, sep, value = line.partition(':')
        if sep:
            key = name.strip()
            fields[key] = value.strip()
    return fields


def tool_tokens(value):
    """Tool names in an allowed-tools value: inline, flow list or block list."""
    cleaned = re.sub(r'(^|\s)- ', ' ', value)
    cleaned = re.sub(r'[\[\],"\']', ' ', cleaned)
    return cleaned.split()


def bundle_problems(root):
    """One message per violated constraint for the plugin at root."""
    root = Path(root)
    problems = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        for name in list(dirnames) + filenames:
            path = here / name
            rel = path.relative_to(root)
            if os.path.islink(path):
                problems.append('symlink: %s' % rel)
        for name in dirnames:
            if name in FORBIDDEN_DIRS and not os.path.islink(here / name):
                problems.append('forbidden directory: %s' % (here / name).relative_to(root))
        for name in filenames:
            path = here / name
            rel = path.relative_to(root)
            if os.path.islink(path):
                continue
            ext = path.suffix.lower()
            if name in FORBIDDEN_NAMES or re.match(r'requirements.*\.txt$', name):
                problems.append('package-manager config: %s' % rel)
            if name in LOCAL_SERVER_NAMES:
                problems.append('local server config: %s' % rel)
            if ext not in ALLOWED_EXTENSIONS:
                problems.append('disallowed file type: %s' % rel)
            if ext not in IMAGE_EXTENSIONS and path.stat().st_size > MAX_TEXT_BYTES:
                problems.append('larger than 256 KiB: %s' % rel)
            with open(path, 'rb') as handle:
                head = handle.read(5)
                if head.startswith(UTF8_BOM):
                    head = head[len(UTF8_BOM):]
                if head.startswith(b'#!'):
                    problems.append('starts with #!: %s' % rel)
            if ext not in TEXT_EXTENSIONS:
                continue
            text = path.read_text(encoding='utf-8')
            if IMAGE_OR_FONT_PATH.search(text):
                problems.append('refers to an image or font path: %s' % rel)
            source, url = CREDENTIAL_SOURCE.search(text), URL.search(text)
            if source and url:
                problems.append('credential source %r paired with URL in %s' % (source.group(), rel))
            if name == 'plugin.json' and rel.parent.name == '.claude-plugin':
                try:
                    manifest = json.loads(text)
                except ValueError:
                    problems.append('invalid JSON: %s' % rel)
                else:
                    keys = set(manifest)
                    experimental = manifest.get('experimental')
                    if isinstance(experimental, dict):
                        keys |= set(experimental) & {'monitors'}
                    for key in sorted(FORBIDDEN_MANIFEST_KEYS & keys):
                        problems.append('manifest key %s: %s' % (key, rel))
            if ext == '.md':
                fields = frontmatter(text)
                if fields is None:
                    if normalise(text).startswith('---'):
                        # Claude Code may still load a block the guard can't parse; fail closed.
                        problems.append('unparseable frontmatter: %s' % rel)
                    elif name == 'SKILL.md':
                        problems.append('missing frontmatter: %s' % rel)
                    continue
                if 'hooks' in fields:
                    problems.append('frontmatter hooks key in %s' % rel)
                tools = fields.get('allowed-tools', '')
                for tool in tool_tokens(tools):
                    if tool not in ALLOWED_TOOLS:
                        problems.append('allowed-tools entry %r not allowed in %s' % (tool, rel))
                for bad in ('${', '//', '://'):
                    if bad in tools:
                        problems.append('allowed-tools contains %s in %s' % (bad, rel))
    return problems


class LiteBundleTests(unittest.TestCase):
    def test_bundle_passes(self):
        self.assertEqual(bundle_problems(LITE), [])

    def test_allowed_tools_exact(self):
        fields = frontmatter((LITE / 'skills/setup-audit-lite/SKILL.md').read_text(encoding='utf-8'))
        tools = set(tool_tokens(fields['allowed-tools']))
        self.assertTrue(tools)
        self.assertLessEqual(tools, ALLOWED_TOOLS)
        self.assertEqual(fields['name'], 'setup-audit-lite')

    def test_manifest_fields(self):
        manifest = json.loads((LITE / '.claude-plugin/plugin.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['name'], 'setup-audit-lite')
        self.assertEqual(manifest['version'], '0.1.0')
        self.assertFalse({'icon', 'hooks', 'mcpServers'} & set(manifest))

    def test_listed_in_marketplace(self):
        market = json.loads((ROOT / '.claude-plugin/marketplace.json').read_text(encoding='utf-8'))
        entries = {p['name']: p for p in market['plugins']}
        names = [p['name'] for p in market['plugins']]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(entries['setup-audit-lite']['source'], './plugins/setup-audit-lite')
        # The entry as on main when lite was added (hard-coded so a fresh checkout needs no git).
        self.assertEqual(entries['setup-audit'], {
            'name': 'setup-audit',
            'source': './plugins/setup-audit',
            'description': 'Audit Claude Code configuration and usage against current docs, generate '
                           'readable reports, and apply approved fixes with backups and verification.'})


class RedProofTests(unittest.TestCase):
    def violate(self, mutate):
        tmp = tempfile.TemporaryDirectory(prefix='lite-redproof-')
        self.addCleanup(tmp.cleanup)
        copy = Path(tmp.name) / 'lite'
        shutil.copytree(LITE, copy, symlinks=True)
        mutate(copy)
        return bundle_problems(copy)

    def assertNamed(self, problems, fragment):
        self.assertTrue(any(fragment in p for p in problems), (fragment, problems))

    def test_script_file(self):
        def mutate(root):
            (root / 'scripts').mkdir()
            (root / 'scripts/x.py').write_text('print(1)\n')
        problems = self.violate(mutate)
        self.assertNamed(problems, 'scripts/x.py')
        self.assertNamed(problems, 'forbidden directory')

    def test_shebang(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text('#!/bin/sh\n'))
        self.assertNamed(problems, 'starts with #!: notes.md')

    def test_shebang_after_bom(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_bytes(UTF8_BOM + b'#!/bin/sh\n'))
        self.assertNamed(problems, 'starts with #!: notes.md')

    def test_lsp_and_monitor_files(self):
        def mutate(root):
            (root / '.lsp.json').write_text('{}\n')
            (root / 'monitors').mkdir()
            (root / 'monitors/monitors.json').write_text('[]\n')
        problems = self.violate(mutate)
        self.assertNamed(problems, 'local server config: .lsp.json')
        self.assertNamed(problems, 'forbidden directory: monitors')
        self.assertNamed(problems, 'local server config: monitors/monitors.json')

    def test_lsp_and_monitor_manifest_keys(self):
        for patch in ({'lspServers': {}}, {'monitors': []}, {'experimental': {'monitors': []}}):
            with self.subTest(patch=patch):
                def mutate(root, patch=patch):
                    path = root / '.claude-plugin/plugin.json'
                    data = json.loads(path.read_text(encoding='utf-8'))
                    data.update(patch)
                    path.write_text(json.dumps(data))
                key = 'lspServers' if 'lspServers' in patch else 'monitors'
                self.assertNamed(self.violate(mutate), 'manifest key %s' % key)

    def test_crlf_and_bom_frontmatter_checked(self):
        for label, encode in (('crlf', lambda s: s.replace('\n', '\r\n').encode()),
                              ('bom', lambda s: UTF8_BOM + s.encode()),
                              ('bom and crlf', lambda s: UTF8_BOM + s.replace('\n', '\r\n').encode())):
            with self.subTest(form=label):
                def mutate(root, encode=encode):
                    (root / 'commands').mkdir()
                    (root / 'commands/x.md').write_bytes(encode('---\nallowed-tools: Bash\n---\nbody\n'))
                self.assertNamed(self.violate(mutate),
                                 "allowed-tools entry 'Bash' not allowed in commands/x.md")

    def test_unparseable_frontmatter(self):
        def mutate(root):
            (root / 'notes.md').write_text('---\nallowed-tools: Bash\nno closing fence\n')
        self.assertNamed(self.violate(mutate), 'unparseable frontmatter: notes.md')

    def skill_with_tools(self, tools):
        def mutate(root):
            path = root / 'skills/setup-audit-lite/SKILL.md'
            text = path.read_text(encoding='utf-8')
            path.write_text(re.sub(r'allowed-tools:.*', 'allowed-tools: ' + tools, text))
        return self.violate(mutate)

    def test_bash_grant(self):
        self.assertNamed(self.skill_with_tools('Read Bash(ls *)'), "'Bash(ls'")

    def test_skill_dir_variable_grant(self):
        problems = self.skill_with_tools('Read(${CLAUDE_SKILL_DIR}/x)')
        self.assertNamed(problems, 'allowed-tools')
        self.assertNamed(problems, 'contains ${')

    def test_hooks_json(self):
        def mutate(root):
            (root / 'hooks').mkdir()
            (root / 'hooks/hooks.json').write_text('{"hooks": {}}\n')
        self.assertIn('forbidden directory: hooks', self.violate(mutate))

    def test_bin_dir(self):
        self.assertNamed(self.violate(lambda r: (r / 'bin').mkdir()), 'forbidden directory: bin')

    def test_package_json(self):
        problems = self.violate(lambda r: (r / 'package.json').write_text('{}\n'))
        self.assertNamed(problems, 'package-manager config: package.json')

    def test_symlink(self):
        problems = self.violate(lambda r: os.symlink('README.md', r / 'link.md'))
        self.assertNamed(problems, 'symlink: link.md')

    def test_credential_source_with_url(self):
        for sample in ('.claude.json', '.envrc', '.credentials.json', 'direnv', 'DIRENV', '.ENVRC',
                       'GITHUB_TOKEN', 'MY_SECRET', 'DB_PASSWORD', 'DB_PASSWD', 'X_API_KEY',
                       'API_KEYS_FILE', 'SIGNING_KEY'):
            with self.subTest(sample=sample):
                problems = self.violate(lambda r: (r / 'notes.md').write_text(
                    'Never open %s. See https://example.invalid\n' % sample))
                self.assertNamed(problems, 'paired with URL in notes.md')

    def test_each_credential_word(self):
        # Each word's sample is caught only through that word: dropping the word from the pattern
        # lets its sample through, so every branch is red-provable on its own.
        samples = {'TOKEN': 'GITHUB_TOKEN', 'SECRET': 'MY_SECRET', 'PASSWORD': 'DB_PASSWORD',
                   'PASSWD': 'DB_PASSWD', 'API_KEY': 'API_KEYS_FILE'}
        self.assertEqual(set(samples), set(CREDENTIAL_WORDS))
        for word, sample in samples.items():
            with self.subTest(word=word):
                self.assertTrue(CREDENTIAL_SOURCE.search(sample))
                without = credential_source_regex(tuple(w for w in CREDENTIAL_WORDS if w != word))
                self.assertIsNone(without.search(sample))
        self.assertTrue(CREDENTIAL_SOURCE.search('SIGNING_KEY'))
        self.assertIsNone(credential_source_regex(key_suffix=False).search('SIGNING_KEY'))

    def test_lowercase_key_word_is_not_a_credential_name(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text(
            'The key idea. See https://example.invalid\n'))
        self.assertEqual(problems, [])

    def test_credential_source_without_url_is_fine(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text('Never open .envrc.\n'))
        self.assertEqual(problems, [])

    def test_image_reference(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text('![x](icon.png)\n'))
        self.assertNamed(problems, 'image or font path: notes.md')

    def test_directory_symlink(self):
        problems = self.violate(lambda r: os.symlink('skills', r / 'linkdir'))
        self.assertNamed(problems, 'symlink: linkdir')

    def test_oversized_text_file(self):
        problems = self.violate(lambda r: (r / 'big.md').write_text('x' * (300 * 1024)))
        self.assertNamed(problems, 'larger than 256 KiB: big.md')

    def test_ico_file_not_allowed(self):
        problems = self.violate(lambda r: (r / 'a.ico').write_bytes(b'\x00\x00\x01\x00'))
        self.assertNamed(problems, 'disallowed file type: a.ico')

    def test_image_reference_extensions(self):
        for ext in ('png', 'svg', 'avif', 'bmp', 'eot', 'ico', 'woff2'):
            with self.subTest(ext=ext):
                problems = self.violate(lambda r: (r / 'notes.md').write_text('see x.%s\n' % ext))
                self.assertNamed(problems, 'image or font path: notes.md')

    def test_frontmatter_allowed_tools_forms(self):
        forms = {
            'block list': 'allowed-tools:\n  - Read\n  - Bash\n',
            'flow list': 'allowed-tools: [Read, Bash]\n',
            'quoted flow list': 'allowed-tools: ["Read", "Bash"]\n',
            'unindented block list': 'allowed-tools:\n- Read\n- Bash\n',
        }
        for label, line in forms.items():
            with self.subTest(form=label):
                def mutate(root, line=line):
                    path = root / 'skills/setup-audit-lite/SKILL.md'
                    text = path.read_text(encoding='utf-8')
                    path.write_text(re.sub(r'allowed-tools:.*\n', line, text, count=1))
                self.assertNamed(self.violate(mutate), "allowed-tools entry 'Bash' not allowed")

    def test_frontmatter_hooks_key(self):
        def mutate(root):
            path = root / 'skills/setup-audit-lite/SKILL.md'
            text = path.read_text(encoding='utf-8')
            path.write_text(text.replace('---\n\n', 'hooks:\n  PreToolUse:\n    - x\n---\n\n', 1))
        self.assertNamed(self.violate(mutate), 'frontmatter hooks key')

    def test_allowed_tools_checked_in_any_markdown(self):
        def mutate(root):
            (root / 'commands').mkdir()
            (root / 'commands/x.md').write_text('---\nallowed-tools: Bash\n---\nbody\n')
        self.assertNamed(self.violate(mutate), "allowed-tools entry 'Bash' not allowed in commands/x.md")

    def test_manifest_keys(self):
        def mutate(root):
            path = root / '.claude-plugin/plugin.json'
            data = json.loads(path.read_text(encoding='utf-8'))
            data['icon'] = 'x'
            data['mcpServers'] = {}
            path.write_text(json.dumps(data))
        problems = self.violate(mutate)
        self.assertNamed(problems, 'manifest key icon')
        self.assertNamed(problems, 'manifest key mcpServers')


REFS = LITE / 'skills/setup-audit-lite/references'
FULL_CHECKLIST = ROOT / 'plugins/setup-audit/skills/setup-audit/references/checklist.md'
CHECK_ID = re.compile(r'(SEC|COST|LRN|RDY|HYG)-[a-z0-9-]+')
LITE_ONLY_IDS = {'HYG-lite-clutter-skills', 'HYG-lite-clutter-hooks', 'HYG-lite-clutter-overlap'}
SNAPSHOT_MAX_AGE_DAYS = 120
SNAPSHOT_ENTRY = re.compile(r'^- `(?P<key>[a-z0-9-]+)` — (?P<quote>.+) — page `(?P<page>[a-z0-9-]+)`$')
# Statuses in stale-strings.md that mark a string as still fine to see in a page.
NOT_STALE_STATUSES = {'old style, still valid', 'current again'}
READ_VERB = re.compile(r'(?i)\b(read|grep|open)\b')
MCP_OR_GLOBAL_CONFIG_FILE = re.compile(r'\.mcp\.json|\.claude\.json')
NEGATION = re.compile(r'(?i)\b(never|not)\b')
# Patterns of the allowlist reading rules in reading-rules.md, copied verbatim (a test asserts each
# appears there). They must stay within syntax that Python re and ripgrep share: no lookaround and
# no backreferences (test_documented_patterns_portable).
# Settings files are never Read; Claude sees only lines that match one of these whole-line shapes.
# Keys are lowercase or camelCase settings names from the docs, never a helper or credential name
# (test_allowlisted_keys_are_settings_names); env variable names are uppercase by convention.
SCALAR_KEYS = ('model|fallbackModel|effortLevel|maxEffortLevel|cleanupPeriodDays|alwaysThinkingEnabled|'
               'disableAllHooks|allowManagedHooksOnly|allowManagedPermissionRulesOnly|'
               'allowManagedDomainsOnly|allowManagedReadPathsOnly|enableAllProjectMcpServers|'
               'enableArtifact|disableClaudeAiConnectors|isolatePeerMachines|remoteControlAtStartup|'
               'crossSessionInbound|useAutoModeDuringPlan|syncClaudeAiSkills|syncClaudeAiPlugins|'
               'requiredMinimumVersion|spinnerTipsEnabled|promptCacheTtl|subagentPromptCacheTtl|'
               'idleCompaction|skipDangerousModePermissionPrompt|defaultMode|'
               'disableBypassPermissionsMode|disableAutoMode|denyInsteadOfPrompting|'
               'blockReadsOutsideWorkingDirectories|blockWritesOutsideWorkingDirectories|enabled|'
               'failIfUnavailable|autoAllowBashIfSandboxed|allowUnsandboxedCommands|'
               'enableWeakerNestedSandbox|enableWeakerNetworkIsolation|allowNestedUserNamespaces|'
               'allowAppleEvents|allowLocalBinding|allowAllUnixSockets|strictAllowlist|httpProxyPort|'
               'socksProxyPort|disabled')
SCALAR_VALUE = r'("[^"\\]*"|true|false|null|-?\d+(\.\d+)?)'
SCALAR_SETTING = r'^\s*"(' + SCALAR_KEYS + r')"\s*:\s*' + SCALAR_VALUE + r',?\s*$'
OPENER = r'^\s*"[A-Za-z][A-Za-z0-9_.-]*"\s*:\s*[\[{]\s*$'
BOOLEAN_FLAG = r'^\s*"[A-Za-z0-9_.@/-]+"\s*:\s*(true|false|null),?\s*$'
RULE_LINE = (r'^\s*"(Bash|PowerShell|Read|Edit|Write|MultiEdit|NotebookEdit|WebFetch|WebSearch|Glob|'
             r'Grep|LS|Agent|Task|Skill|mcp__[A-Za-z0-9_*-]+)(\([^"\\]*\))?",?\s*$')
HOOK_FIELD = r'^\s*"(type|matcher|event|timeout|async|onFailure)"\s*:\s*("[^"\\]*"|true|false|-?\d+),?\s*$'
HOOK_TARGET = r'^\s*"command"\s*:\s*"[^"\\]*",?\s*$'
# Webhook URLs with a path or query are credentials: only a bare scheme and host (and port) shows.
HOOK_URL = r'^\s*"url"\s*:\s*"https?://[A-Za-z0-9.-]+(:\d+)?",?\s*$'
# Array entries shaped like a path or a host name (sandbox and directory lists). There is no
# bare-word element pattern: it would show bare tokens in hook args. The host's last label is
# letters only, so dotted tokens (JWT-like) with digits in the last part don't match.
PATH_ELEMENT = r'^\s*"[~./][^"\\]*",?\s*$'
HOST_ELEMENT = r'^\s*"(\*\.)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}",?\s*$'
# A key and its value on different lines: a lone string line could then be a value, not a rule.
SPLIT_LINE = r'(^\s*:|:\s*$|"\s*:\s*/[/*])'
NON_EMPTY = '.'
# Secret shapes: best effort by known shapes (the allowlist is the guarantee for env, headers and
# helpers; these guard the free-text rule, command and URL lines).
_ANY_QUOTE = r"""(\\?["'])?"""  # an optional, possibly escaped, quote before a value
_SECRET_SHAPES = '|'.join([
    r"""bearer\s+[^\s$"'\\][^\s"'\\]{11,}""",
    r'\b[a-z0-9_]*(pass|token|secret|key)[a-z0-9_]*=' + _ANY_QUOTE + r"""[^\s$"'&;|)\\]""",
    r'\bAKIA[0-9A-Z]{16}\b', r'\bgithub_pat_[a-z0-9_]{20,}', r'\bglpat-[a-z0-9_-]{16,}',
    r'\bnpm_[a-z0-9]{30,}', r'\b(sk|ghp|gho|ghs|ghu|xox[abpr])[-_][a-z0-9_-]{16,}',
    r'://[^/\s:@]+:[^/\s@$][^/\s@]*@',
    r'x-api-key\s*:\s*' + _ANY_QUOTE + r"""[^\s$"'\\]""",
    r"""authorization\s*:\s*basic\s+[^\s$"'\\]""",
])
_STRING_BODY = r'([^"\\]|\\.)*'
SECRET_IN_RULE = (r'(?i)(Bash\(|PowerShell\(|"(command|url|args|[A-Za-z]*Helper)"\s*:).*('
                  + _SECRET_SHAPES + ')')
SECRET_IN_ELEMENT = (r'(?i)^\s*("' + _STRING_BODY + r'",\s*)*"' + _STRING_BODY + '(' + _SECRET_SHAPES
                     + ')' + _STRING_BODY + r'"(,\s*"' + _STRING_BODY + r'")*,?\s*$')
SECRET_IN_MANIFEST = r'(?i)(' + _SECRET_SHAPES + ')'
TOML_HEADER = r'^\[\[?[A-Za-z][^\]#]*\]\]?\s*$'
PY_STRICT = r'^\s*(strict|typeCheckingMode)\s*=\s*("[a-z]+"|true|false)\s*$'
TS_STRICT = r'^\s*"strict"\s*:\s*(true|false),?\s*$'
SCRIPT_LINE = (r'^\s*"(test|lint|check|format|typecheck|build|dev|start|ci|verify|setup|bootstrap|'
               r'prepare)(:[A-Za-z0-9_.:-]+)?"\s*:\s*"[^"\\]*",?\s*$')
MAKE_TARGET = (r'^(test|tests|check|lint|format|fmt|typecheck|build|dev|start|run|ci|verify|setup|'
               r'bootstrap|install|all)([-_.][A-Za-z0-9_.-]*)?:[^=]*$')
# Skills, agents and commands: agent frontmatter can define MCP servers inline (env, headers, URLs)
# and skills and agents can carry hooks with commands (sub-agents and skills pages). A count probe
# for them comes first; frontmatter is then shown only through single-line top-level keys.
INLINE_CONFIG_PROBE = r"""(^\s*|[{,]\s*)["']?(mcpServers|hooks)["']?\s*:"""
FRONTMATTER_KEYS = ('name|description|when_to_use|model|effort|tools|disallowedTools|allowed-tools|'
                    'disallowed-tools|permissionMode|paths|skills|memory|isolation|background|context|'
                    'agent|user-invocable|disable-model-invocation')
FRONTMATTER_KEY_LINE = r'^(' + FRONTMATTER_KEYS + r'):[^\n]*$'
FENCE_LINE = r'^---\s*$'
# Frontmatter keys in the skills and sub-agents tables (docs fetched 2026-11-12), hard-coded so a
# fresh checkout needs no docs. Keys that hold servers, hooks, free-form maps or prompts are not
# allowlisted.
DOC_FRONTMATTER_KEYS = {
    'name', 'description', 'when_to_use', 'argument-hint', 'arguments', 'disable-model-invocation',
    'user-invocable', 'allowed-tools', 'disallowed-tools', 'model', 'effort', 'context', 'agent',
    'background', 'hooks', 'paths', 'shell', 'metadata', 'license', 'compatibility', 'tools',
    'disallowedTools', 'permissionMode', 'maxTurns', 'autoCompactWindow', 'skills', 'mcpServers',
    'memory', 'omitClaudeMd', 'isolation', 'color', 'initialPrompt', 'experimental'}
NEVER_SHOWN_FRONTMATTER_KEYS = {'hooks', 'mcpServers', 'metadata', 'experimental', 'initialPrompt'}
DOCUMENTED_PATTERNS = (SCALAR_SETTING, OPENER, BOOLEAN_FLAG, RULE_LINE, HOOK_FIELD, HOOK_TARGET,
                       HOOK_URL, PATH_ELEMENT, HOST_ELEMENT,
                       SPLIT_LINE, SECRET_IN_RULE, SECRET_IN_ELEMENT, SECRET_IN_MANIFEST, TOML_HEADER,
                       PY_STRICT, TS_STRICT, SCRIPT_LINE, MAKE_TARGET, INLINE_CONFIG_PROBE,
                       FRONTMATTER_KEY_LINE, FENCE_LINE)
# Words that mark a helper or credential-bearing key; no allowlisted key may contain one.
CREDENTIAL_KEY_WORDS = re.compile(r'(?i)token|secret|password|key|header|credential|auth|helper|refresh|export')
SEED_SOURCES = ('trailofbits/claude-code-config', 'shanraisshan/claude-code-best-practice',
                'luongnv89/claude-howto', 'hesreallyhim/awesome-claude-code',
                'simonwillison.net/tags/claude-code', 'systima.ai/blog/claude-code-vs-opencode-token-overhead',
                'blakecrosley.com/guides/claude-code')


def checklist_ids(text):
    """(ids outside the Lite-only section, ids inside it), from backticked tokens."""
    outside, inside = set(), set()
    section = None
    for line in text.splitlines():
        if line.startswith('## '):
            section = line[3:].strip()
        for token in re.findall(r'`([^`]+)`', line):
            if CHECK_ID.fullmatch(token):
                (inside if section == 'Lite-only' else outside).add(token)
    return outside, inside


def unknown_ids(lite_text, full_text):
    """Lite ids (outside Lite-only) that the full checklist doesn't define."""
    full = {m.group() for m in CHECK_ID.finditer(full_text)}
    return sorted(checklist_ids(lite_text)[0] - full)


def snapshot_age_problem(text, today):
    """None when the first line is 'Snapshot date: YYYY-MM-DD' within the age limit."""
    first = text.splitlines()[0] if text else ''
    match = re.fullmatch(r'Snapshot date: (\d{4}-\d{2}-\d{2})', first)
    if not match:
        return 'first line is not "Snapshot date: YYYY-MM-DD": %r' % first
    age = (today - datetime.date.fromisoformat(match.group(1))).days
    if age < 0 or age > SNAPSHOT_MAX_AGE_DAYS:
        return 'snapshot is %d days old (limit %d): refresh it' % (age, SNAPSHOT_MAX_AGE_DAYS)
    return None


def snapshot_entries(text):
    return [m.groupdict() for m in map(SNAPSHOT_ENTRY.match, text.splitlines()) if m]


def stale_rows(text):
    """Rows of the `| string | status | since | replacement |` table, backticks stripped."""
    rows = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) != 4 or not cells[0].startswith('`'):
            continue
        rows.append({'string': cells[0].strip('`'), 'status': cells[1], 'since': cells[2],
                     'replacement': cells[3]})
    return rows


def stale_in_snapshot(stale_text, snapshot_text):
    """(string, claim key) pairs where a stale string appears in a snapshot quote."""
    hits = []
    for row in stale_rows(stale_text):
        if row['status'] in NOT_STALE_STATUSES:
            continue
        for entry in snapshot_entries(snapshot_text):
            if row['string'] in entry['quote']:
                hits.append((row['string'], entry['key']))
    return hits


def unsafe_mcp_line(line):
    """True when a line pairs read/grep/open with MCP config or ~/.claude.json and no negation comes
    before the first verb or before the first file name ("Read .mcp.json if it is not empty")."""
    verb, name = READ_VERB.search(line), MCP_OR_GLOBAL_CONFIG_FILE.search(line)
    if not (verb and name):
        return False
    negation = NEGATION.search(line)
    return not (negation and (negation.start() < verb.start() or negation.start() < name.start()))


def mcp_instruction_problems(root):
    """Lines that tell Claude to read, grep or open MCP config or ~/.claude.json."""
    problems = []
    for path in sorted(Path(root).rglob('*')):
        if path.suffix.lower() not in TEXT_EXTENSIONS or path.is_symlink() or not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            if unsafe_mcp_line(line):
                problems.append('%s:%d' % (path.relative_to(root), number))
    return problems


SETTINGS_PATTERNS = {'scalar': SCALAR_SETTING, 'opener': OPENER, 'boolean': BOOLEAN_FLAG,
                     'rule': RULE_LINE, 'hook_field': HOOK_FIELD, 'hook_target': HOOK_TARGET,
                     'hook_url': HOOK_URL, 'path': PATH_ELEMENT, 'host': HOST_ELEMENT}


def grep_shown(text, patterns=None, gate=True):
    """Lines of a settings file that content-mode Grep shows under the reading rules.

    Returns (reason, lines): reason is set when the file is reported "not read" as a whole. Counts
    (output_mode: count) never show lines, so only the content-mode patterns matter here. Lines are
    split on newline only, as ripgrep does, so a carriage return stays on the line.
    """
    p = dict(SETTINGS_PATTERNS, **(patterns or {}))
    lines = text.split('\n')

    def count(pattern):
        return sum(1 for line in lines if re.search(pattern, line))

    if count(NON_EMPTY) == 1:
        return 'compact JSON layout', []
    shown = [p['scalar'], p['opener'], p['boolean'], p['hook_field'], p['hook_url']]
    secret = count(SECRET_IN_RULE) + count(SECRET_IN_ELEMENT) > 0
    if not gate or not secret:
        shown.append(p['hook_target'])
        if not gate or not count(SPLIT_LINE):
            shown += [p['rule'], p['path'], p['host']]
    return None, [line for line in lines if any(re.search(pat, line) for pat in shown)]


def allowlisted_key_problems(patterns):
    """Keys in the settings and hook allowlists that aren't plain settings names."""
    problems = []
    for pattern in patterns:
        keys = re.match(r'\^\\s\*"\(([^)]*)\)"', pattern).group(1).split('|')
        for key in keys:
            if not re.fullmatch(r'[a-z][A-Za-z0-9]*', key):
                problems.append('not lowercase or camelCase: %s' % key)
            if CREDENTIAL_KEY_WORDS.search(key):
                problems.append('credential-bearing name: %s' % key)
    return problems


SECRET = 'SECRET' + 'VAL'  # marker for a value that must never be shown
# Settings layouts that carry a value Claude must not see, including every leak sample from the
# structure-scanner rounds. Fixture secrets are assembled at run time so they never look like real
# vendor keys.
LEAK_SAMPLES = {
    'env value line': '{\n  "env": {\n    "API_TOKEN": "%s",\n    "B": "x"\n  }\n}',
    'tight inline env': '{\n  "env": {"A": "%s"},\n  "model": "opus"\n}',
    'spaced inline env': '{\n  "env": { "A": "%s" },\n  "model": "opus"\n}',
    'inline env ending in an allowlisted pair': '{\n  "env": {"API_TOKEN": "%s"}, "model": "opus",\n'
                                                '  "x": 1\n}',
    'two pairs on one line': '{\n  "env": {\n    "effortLevel": "high", "API_TOKEN": "%s",\n'
                             '    "model": "opus", "API_KEY": "%s"\n  }\n}',
    'block opened after other text': '{\n  "permissions": {\n    "allow": []\n  }, "env": {\n'
                                     '    "A": "%s"\n  }\n}',
    'escaped env key, inline': '{\n  "\\u0065nv": {"A": "%s"},\n  "model": "opus"\n}',
    'escaped env key, pretty': '{\n  "\\u0065nv": {\n    "A": "%s"\n  }\n}',
    'escaped helper key': '{\n  "apiKey\\u0048elper": "echo %s",\n  "model": "opus"\n}',
    'escaped allowlisted key': '{\n  "\\u006dodel": "%s",\n  "x": 1\n}',
    'brace in a string hides an opening': '{\n  "env": {\n    "A": {"n": "}",\n    "m": 2\n    },\n'
                                          '    "B": "%s" }\n}',
    'object opened mid-line inside env': '{\n  "env": {\n    "A": {"n": 1,\n    "m": 2\n    },\n'
                                         '    "B": "%s" }\n}',
    'value block and empty block on one line': '{\n  "env": {"A": "%s"}, "headers": {},\n'
                                               '  "model": "opus"\n}',
    'nested object in env': '{\n  "env": {\n    "A": {\n      "B": "%s"\n    }\n  }\n}',
    'brace on next line': '{\n  "env":\n  {\n    "A": "%s"\n  }\n}',
    'helpers': '{\n  "apiKeyHelper": "echo %s",\n  "awsAuthRefresh": "%s",\n'
               '  "gcpAuthRefresh": "%s",\n  "awsCredentialExport": "%s",\n'
               '  "otelHeadersHelper": "%s",\n  "headersHelper": "%s",\n  "model": "opus"\n}',
    'hook headers': '{\n  "hooks": {\n    "PostToolUse": [\n      {\n        "type": "http",\n'
                    '        "headers": {\n          "Authorization": "Bearer %s",\n'
                    '          "X-Api-Key": "%s",\n          "authorization": "%s",\n'
                    '          "x-api-key": "%s"\n        }\n      }\n    ]\n  }\n}',
    'credential-named lowercase keys': '{\n  "token": "%s",\n  "apiKey": "%s",\n  "password": "%s",\n'
                                       '  "secret": "%s",\n  "authToken": "%s"\n}',
    'uppercase allowlisted name': '{\n  "env": {\n    "MODEL": "%s",\n    "ENABLED": "%s"\n  }\n}',
    'quote escaped in an allowlisted value': '{\n  "model": "x\\", \\"API_TOKEN\\": \\"%s",\n'
                                             '  "y": 1\n}',
    'trailing text after an allowlisted pair': '{\n  "model": "opus", // %s\n  "y": 1\n}',
    'crlf line endings': '{\r\n  "env": {\r\n    "API_TOKEN": "%s"\r\n  },\r\n  "model": "opus"\r\n}',
    'env after a hook command on one line': '{\n  "hooks": [\n    { "command": "run", "env": '
                                            '{"API_TOKEN": "%s"} }\n  ]\n}',
    'webhook url in a hook': '{\n  "hooks": {\n    "Stop": [\n      {\n        "type": "http",\n'
                             '        "url": "https://hooks.example.invalid/services/%s"\n      }\n'
                             '    ]\n  }\n}',
    'url with a query': '{\n  "hooks": [\n    {\n      "url": "https://h.example.invalid?k=%s"\n'
                        '    }\n  ]\n}',
    'bare token in hook args': '{\n  "hooks": [\n    {\n      "args": [\n        "--flag",\n'
                               '        "%s",\n        "ab%s"\n      ]\n    }\n  ]\n}',
    'dotted token in hook args': '{\n  "hooks": [\n    {\n      "args": [\n'
                                 '        "eyJhbGci.%s.Q2x9"\n      ]\n    }\n  ]\n}',
    'path value after a split key': '{\n  "env": {\n    "API_TOKEN":\n      "/%s"\n  }\n}',
    'path value after a block-commented key': '{\n  "env": {\n    "API_TOKEN": /* c */\n      "/%s"\n  }\n}',
    'host value after a line-commented key': '{\n  "env": {\n    "API_TOKEN": // c\n      "%s.example.com"\n  }\n}',
    'secret in a path element': '{\n  "sandbox": {\n    "allowWrite": [\n'
                                '      "./x?to' + 'ken=%s"\n    ]\n  }\n}',
    'minified': '{"env": {"A": "%s"}, "model": "opus", "permissions": {"allow": ["Bash(ls *)"]}}',
    'value on the line after its key': '{\n  "env": {\n    "API_TOKEN":\n      "Bash(%s)"\n  },\n'
                                       '  "permissions": {\n    "allow": [\n      "Read"\n    ]\n  }\n}',
    'colon on its own line': '{\n  "env": {\n    "API_TOKEN"\n    :\n    "Read(%s)"\n  }\n}',
    'secret in an allow rule': '{\n  "permissions": {\n    "allow": [\n'
                               '      "Bash(PG' + 'PASSWORD=hunter2%s psql -h db)",\n'
                               '      "Bash(ls *)"\n    ]\n  }\n}',
    'secret in a hook command': '{\n  "hooks": {\n    "Stop": [\n      {\n'
                                '        "command": "curl -H \'Authorization: Bear' + 'er abcdef%s123\' x",\n'
                                '        "type": "command"\n      }\n    ]\n  }\n}',
    'credentials in a hook url': '{\n  "hooks": {\n    "Stop": [\n      {\n        "type": "http",\n'
                                 '        "url": "https://deploy:' + 'pw%s@hooks.example.invalid/x"\n'
                                 '      }\n    ]\n  }\n}',
}


def leaks(patterns=None, gate=True):
    """Labels of leak samples whose secret marker reaches a shown line."""
    found = []
    for label, template in LEAK_SAMPLES.items():
        text = template.replace('%s', SECRET)
        _, shown = grep_shown(text, patterns, gate)
        if any(SECRET in line for line in shown):
            found.append(label)
    return found


def ref(name):
    return (REFS / name).read_text(encoding='utf-8')


def frontmatter_reading(text, probe=INLINE_CONFIG_PROBE, secret=SECRET_IN_MANIFEST,
                        keys=FRONTMATTER_KEY_LINE):
    """How lite sees a skill, agent or command file under reading-rules.md.

    Returns (reason, shown, whole_read_allowed). Lines split on newline only, as ripgrep does.
    """
    lines = text.split('\n')

    def count(pattern):
        return pattern is not None and sum(1 for line in lines if re.search(pattern, line))

    if count(probe):
        return 'inline MCP/hooks present, not read', [], False
    if count(secret):
        return 'not read: secret-shaped text', [], False
    fences = [i for i, line in enumerate(lines) if re.search(FENCE_LINE, line)]
    end = fences[1] if len(fences) > 1 and fences[0] == 0 else 0
    return None, [line for line in lines[:end] if re.search(keys, line)], True


# Agent, skill and command files whose inline config or secret-shaped text must never reach Claude.
FRONTMATTER_LEAK_SAMPLES = {
    'inline mcp env': '---\nname: a\nmcpServers:\n  db:\n    env:\n      DB_PASS: %s\n---\nbody\n',
    'inline mcp headers, flow style': '---\nname: a\nmcpServers: {db: {headers: {X: %s}}}\n---\n',
    'quoted mcp key': '---\nname: a\n"mcpServers":\n  x:\n    url: https://h.example.invalid/%s\n---\n',
    'indented mcp key': '---\nname: a\n  mcpServers:\n    x: %s\n---\n',
    'hook command': '---\nname: a\nhooks:\n  PreToolUse:\n    - hooks:\n        - type: command\n'
                    '          command: deploy --pw %s\n---\n',
    'flow mapping frontmatter': '---\n{name: a, hooks: {Stop: [{command: x %s}]}}\n---\n',
    'hooks in the body': '---\nname: a\n---\nExample:\nhooks:\n  Stop: x %s\n',
    'crlf inline mcp': '---\r\nname: a\r\nmcpServers:\r\n  db:\r\n    env: {T: %s}\r\n---\r\n',
    'secret-shaped text in tools': '---\nname: a\ntools: Bash(curl -H "Authorization: Bear' + 'er abcdef%s123")\n---\n',
    'secret-shaped text in the body': '---\nname: a\n---\nRun PG' + 'PASSWORD=x%s psql.\n',
}


def frontmatter_leaks(**kwargs):
    """Labels of samples whose secret marker is shown or sits in a file lite may Read whole."""
    found = []
    for label, template in FRONTMATTER_LEAK_SAMPLES.items():
        text = template.replace('%s', SECRET)
        _, shown, whole = frontmatter_reading(text, **kwargs)
        if any(SECRET in line for line in shown) or whole:
            found.append(label)
    return found


def frontmatter_key_problems(pattern):
    """Allowlisted frontmatter keys that the docs don't define or that may hold servers or hooks."""
    keys = re.match(r'\^\(([^)]*)\)', pattern).group(1).split('|')
    problems = ['not a documented frontmatter key: %s' % k for k in keys if k not in DOC_FRONTMATTER_KEYS]
    problems += ['key may hold servers, hooks or free text: %s' % k
                 for k in keys if k in NEVER_SHOWN_FRONTMATTER_KEYS]
    return problems


class LiteReferencesTests(unittest.TestCase):
    def test_lite_ids_subset_of_full(self):
        outside, _ = checklist_ids(ref('checklist.md'))
        self.assertGreater(len(outside), 10)
        self.assertEqual(unknown_ids(ref('checklist.md'), FULL_CHECKLIST.read_text(encoding='utf-8')), [])

    def test_checklist_sections(self):
        headings = re.findall(r'^## (.+)$', ref('checklist.md'), re.M)
        self.assertEqual(headings, ['Security (SEC-)', 'Cost & context (COST-)', 'Learning (LRN-)',
                                    'Agent readiness (RDY-)', 'Hygiene (HYG-)',
                                    'New features (adopt)', 'Lite-only'])

    def test_lite_only_ids_present(self):
        _, inside = checklist_ids(ref('checklist.md'))
        self.assertEqual(inside, LITE_ONLY_IDS)

    def test_checklist_claim_keys_in_snapshot(self):
        text = ref('checklist.md')
        cited = set()
        for group in re.findall(r'Claims?:\s+((?:`[a-z0-9-]+`(?:,\s+)?)+)', text):
            cited |= set(re.findall(r'`([a-z0-9-]+)`', group))
        keys = {e['key'] for e in snapshot_entries(ref('docs-snapshot.md'))}
        self.assertGreater(len(cited), 30)
        self.assertEqual(sorted(cited - keys), [])
        # Every check bullet names its claims (or says "Claims: none").
        for bullet in re.split(r'\n(?=- `)', text):
            match = re.match(r'- `([A-Z]+-[a-z0-9-]+)`', bullet)
            if match:
                self.assertRegex(bullet, r'Claims:\s+(`|none)', match.group(1))

    def test_snapshot_dated_and_fresh(self):
        self.assertIsNone(snapshot_age_problem(ref('docs-snapshot.md'), datetime.date.today()))

    def test_snapshot_entries_well_formed(self):
        text = ref('docs-snapshot.md')
        entries = snapshot_entries(text)
        self.assertGreaterEqual(len(entries), 20)
        keys = [e['key'] for e in entries]
        self.assertEqual(len(keys), len(set(keys)))
        bullet_lines = [l for l in text.splitlines() if l.startswith('- `')]
        self.assertEqual(len(bullet_lines), len(entries))

    def test_snapshot_has_no_stale_string_as_current(self):
        self.assertEqual(stale_in_snapshot(ref('stale-strings.md'), ref('docs-snapshot.md')), [])

    def test_stale_strings_table(self):
        rows = {r['string']: r for r in stale_rows(ref('stale-strings.md'))}
        for name in ('includeCoAuthoredBy', 'ignorePatterns', 'TaskOutput', 'taskOutputMaxChars',
                     'Write(', '/output-style'):
            self.assertIn(name, rows)
        self.assertEqual(rows['Bash(x:*)']['status'], 'old style, still valid')
        for row in rows.values():
            if row['status'] not in NOT_STALE_STATUSES:
                self.assertRegex(row['since'], r'^\d+\.\d+\.\d+$', row)

    def test_reading_rules_document_allowlist(self):
        text = ref('reading-rules.md')
        for pattern in DOCUMENTED_PATTERNS:
            self.assertIn('`%s`' % pattern, text)
        for phrase in ('output_mode: count', 'never opened with Read',
                       'not read: compact JSON layout — reformat to audit', 'uppercase', '-i'):
            self.assertIn(phrase, text)
        # The structure scanner is gone.
        for phrase in ('value block', 'depth 2 or deeper', 'offset'):
            self.assertNotIn(phrase, text)

    def test_documented_patterns_portable(self):
        # Grep runs ripgrep, Python runs these tests: keep to the shared syntax.
        text = ref('reading-rules.md')
        for token in ('(?=', '(?!', '(?<', '\\1'):
            self.assertNotIn(token, text)
        for pattern in DOCUMENTED_PATTERNS:
            re.compile(pattern)

    def test_allowlisted_keys_are_settings_names(self):
        self.assertEqual(allowlisted_key_problems((SCALAR_SETTING, HOOK_FIELD)), [])

    def test_no_secret_reaches_a_shown_line(self):
        self.assertEqual(leaks(), [])

    def test_secret_layouts_named_in_corpus(self):
        # Every layout the structure scanner missed stays in the corpus.
        for label in ('brace in a string hides an opening', 'block opened after other text',
                      'escaped env key, inline', 'tight inline env', 'helpers', 'minified'):
            self.assertIn(label, LEAK_SAMPLES)

    def test_safe_lines_shown(self):
        for line in ('  "model": "opus",', '    "defaultMode": "acceptEdits",', '    "enabled": true,',
                     '    "failIfUnavailable": false', '    "httpProxyPort": 8080,',
                     '  "permissions": {', '    "allow": [', '  "env": {', '    "PreToolUse": [',
                     '    "superpowers@claude-plugins-official": true',
                     '      "Bash(uv run pytest -q)",', '      "Read(./.env)"', '      "WebSearch",',
                     '      "mcp__github__get_issue",', '      "WebFetch(domain:example.invalid)"',
                     '            "type": "command",', '        "matcher": "Bash",',
                     '            "timeout": 30', '            "onFailure": "block",',
                     '            "command": "${CLAUDE_PLUGIN_ROOT}/guard.sh",',
                     '        "url": "https://hooks.example.invalid",',
                     '        "url": "http://localhost:8080"',
                     '      "~/old-project",', '      "./build"', '      "/tmp/scratch",',
                     '      "pypi.org",', '      "*.github.com"', '      "registry.npmjs.org",'):
            with self.subTest(line=line):
                reason, shown = grep_shown('{\n%s\n}' % line)
                self.assertIsNone(reason)
                self.assertEqual(shown, [line])

    def test_realistic_settings_stay_readable(self):
        text = """{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "model": "opus",
  "env": {
    "API_TOKEN": "%s"
  },
  "permissions": {
    "allow": ["Bash(uv run pytest *)", "Bash(awk '{print $1}' *)"],
    "deny": [
      "Read(./.env)",
      "Bash(git push --force *)"
    ],
    "defaultMode": "acceptEdits"
  },
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [
        {
          "type": "command",
          "command": "${CLAUDE_PLUGIN_ROOT}/guard.sh",
          "onFailure": "block",
          "timeout": 30
        }
      ]
    }],
    "SessionStart": [{ "hooks": [{ "type": "command", "command": "echo hi" }] }]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true
  },
  "enabledPlugins": {
    "superpowers@claude-plugins-official": true
  }
}""" % SECRET
        reason, shown = grep_shown(text)
        self.assertIsNone(reason)
        self.assertFalse([line for line in shown if SECRET in line])
        for fragment in ('"model": "opus"', '"env": {', '"Bash(git push --force *)"',
                         '"defaultMode"', '"matcher": "Bash"', '"onFailure": "block"',
                         'guard.sh', '"enabled": true', '"superpowers@'):
            self.assertTrue(any(fragment in line for line in shown), fragment)

    def test_secret_probe_hides_rules_and_commands(self):
        text = LEAK_SAMPLES['secret in an allow rule'].replace('%s', SECRET)
        _, shown = grep_shown(text)
        self.assertNotIn('      "Bash(ls *)"', shown)  # rule lines are only counted after a hit
        self.assertIn('    "allow": [', shown)

    def test_boolean_env_name_shows(self):
        # A boolean env entry's name shows through the true/false pattern; the doc says so.
        _, shown = grep_shown('{\n  "env": {\n    "FEATURE_FLAG": true,\n    "A": "x"\n  }\n}')
        self.assertEqual(shown, ['  "env": {', '    "FEATURE_FLAG": true,'])
        self.assertIn('a boolean env entry', ref('reading-rules.md'))

    def test_collision_names_listed(self):
        text = flat(ref('reading-rules.md'))
        self.assertIn('scalar allowlist plus the hook-field keys', text)
        self.assertIn('and the `command` and `url` keys', text)

    def test_no_secret_reaches_claude_from_frontmatter(self):
        self.assertEqual(frontmatter_leaks(), [])

    def test_frontmatter_keys_shown(self):
        text = ('---\nname: reviewer\ndescription: Reviews code\nmodel: haiku\ntools: Read, Grep\n'
                'color: blue\n  model: nested\n---\nmodel: in the body\n')
        reason, shown, whole = frontmatter_reading(text)
        self.assertEqual((reason, whole), (None, True))
        self.assertEqual(shown, ['name: reviewer', 'description: Reviews code', 'model: haiku',
                                 'tools: Read, Grep'])

    def test_multiline_description_is_partial(self):
        _, shown, _ = frontmatter_reading('---\nname: a\ndescription: >\n  long text\n---\n')
        self.assertEqual(shown, ['name: a', 'description: >'])
        self.assertIn('report that field "partial"', flat(ref('reading-rules.md')))

    def test_frontmatter_keys_documented(self):
        self.assertEqual(frontmatter_key_problems(FRONTMATTER_KEY_LINE), [])

    def test_inline_config_files_never_opened(self):
        never_opened = section(ref('reading-rules.md'), '## Never opened')
        self.assertTrue(any('mcpServers' in line and 'hooks' in line and NEGATION.search(line)
                            for line in never_opened.splitlines() if line.startswith('- ')))

    def test_minified_reported_not_read(self):
        reason, shown = grep_shown('{"model": "opus"}\n')
        self.assertEqual((reason, shown), ('compact JSON layout', []))

    def test_manifest_probe_samples(self):
        manifest = re.compile(SECRET_IN_MANIFEST)
        for line in ('    "pub": "NPM_' + 'TOKEN=x npm publish",',
                     'env = ["API_' + 'KEY=abc123"]',
                     '    "release": "twine upload -u u -p x https://u:' + 'pw9@pypi.example.invalid"'):
            with self.subTest(hit=line):
                self.assertTrue(manifest.search(line))
        for line in ('    "test": "pytest -q",', 'addopts = "-q"', 'key = "value"',
                     '    "deploy": "API_KEY=$API_KEY ./deploy.sh",'):
            with self.subTest(miss=line):
                self.assertFalse(manifest.search(line))
        header = re.compile(TOML_HEADER)
        for line in ('[tool.ruff]', '[[tool.uv.index]]', '[project.scripts]',
                     '[tool.pytest.ini_options]'):
            self.assertTrue(header.search(line), line)
        for line in ('["a",', '[1, 2]', '  [tool.x]', '"[x]"', '[tool.ruff] # SECRET',
                     '[tool.x] token = "y"'):
            self.assertFalse(header.search(line), line)
        for pattern, hits, misses in (
                (SCRIPT_LINE, ('    "test": "pytest -q",', '    "lint:fix": "eslint --fix ."'),
                 ('    "pub": "npm publish",', '    "test": "echo \\"x\\""', '"test": "a", "b": "c"')),
                (TS_STRICT, ('    "strict": true,',), ('    "strict": "yes"', '"strict": true, "x": 1')),
                (PY_STRICT, ('strict = true', 'typeCheckingMode = "strict"'),
                 ('strict = true # x', 'password = "x"')),
                (MAKE_TARGET, ('test:', 'build: deps', 'lint-fix: deps', 'setup:'),
                 ('TOKEN := x', 'x = y:z', 'Authorization: Bear' + 'er x', 'deploy: build',
                  'Token: abc'))):
            for line in hits:
                self.assertTrue(re.search(pattern, line), line)
            for line in misses:
                self.assertFalse(re.search(pattern, line), line)

    def test_secret_probe_samples(self):
        # Fixture secrets are assembled at run time so they never look like real vendor keys.
        rule, element = re.compile(SECRET_IN_RULE), re.compile(SECRET_IN_ELEMENT)
        hits = [
            '      "Bash(PG' + 'PASSWORD=hunter2 psql -h db)",',
            '      "Bash(aws s3 ls --key AK' + 'IA' + 'Q' * 16 + ')",',
            '      "Bash(gh api -H x github' + '_pat_' + 'a1' * 12 + ')",',
            '          "Authorization: Bear' + 'er abcdef123456",',
            '  "headersHelper": "echo \'Authorization: Bear' + 'er abc123def456ghi\'",',
            '      "Bash(curl -u x:y https://h?api_' + 'key=zz9)",',
            '      "Bash(npm publish --otp 1 --registry r gl' + 'pat-' + 'b2' * 10 + ')",',
            '      "Bash(PG' + "PASSWORD='hunter2' psql)\",",
            '          "--env=PG' + 'PASSWORD=\\"hunter2\\"",',
            '          "-H", "Authorization: Bear' + 'er abc123def456",',
            '            "url": "https://deploy:' + 'pw9@hooks.example.invalid/x",',
            '      "Bash(curl -H \\"X-Api-' + 'Key: abc\\" https://h)",',
            '          "-H", "Authorization: Ba' + 'sic dXNlcjpwYXNz"',
        ]
        misses = [
            '      "Bash(npm run test:*)",',
            '      "Bash(git commit:*)",',
            '      "Bash(uv run pytest -q)",',
            '            "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/check-token.sh",',
            '      "Bash(curl -H \\"Authorization: Bearer $ANTHROPIC_API_KEY\\" https://h)",',
            '      "Bash(SOME_TOKEN=${SOME_TOKEN_VALUE} make deploy)",',
            '    "GITHUB_TOKEN": "abc",',
            '    "model": "opus",',
            '      "Bash(SOME_TOKEN=\\"${SOME_TOKEN_VALUE}\\" make deploy)",',
            '      "Bash(git clone https://github.com/a/b)",',
            '      "Bash(psql postgres://app:$DB_PW@db/app)",',
            '          "-H", "Authorization: Bearer $X",',
        ]
        for line in hits:
            with self.subTest(hit=line):
                self.assertTrue(rule.search(line) or element.search(line))
        for line in misses:
            with self.subTest(miss=line):
                self.assertFalse(rule.search(line) or element.search(line))

    def test_reading_rules_forbid_mcp_and_claude_json(self):
        lines = ref('reading-rules.md').splitlines()
        for name in ('.mcp.json', '.claude.json', '.envrc', '.credentials.json'):
            self.assertTrue(any(name in l and NEGATION.search(l) for l in lines), name)
        self.assertEqual(mcp_instruction_problems(LITE), [])

    def test_sources_lists_seed_allowlist(self):
        text = ref('sources.md')
        for source in SEED_SOURCES:
            self.assertIn(source, text)
        self.assertIsNone(CREDENTIAL_SOURCE.search(text))

    def test_only_sources_has_urls_among_references(self):
        with_urls = sorted(p.name for p in REFS.glob('*.md') if URL.search(p.read_text(encoding='utf-8')))
        self.assertEqual(with_urls, ['sources.md'])


class ReferencesRedProofTests(unittest.TestCase):
    def test_made_up_id_fails_subset(self):
        text = ref('checklist.md').replace('## Cost & context (COST-)',
                                           '- `SEC-not-a-real-check` (high)\n\n## Cost & context (COST-)')
        self.assertEqual(unknown_ids(text, FULL_CHECKLIST.read_text(encoding='utf-8')),
                         ['SEC-not-a-real-check'])

    def test_old_snapshot_fails_freshness(self):
        text = re.sub(r'^Snapshot date: .*', 'Snapshot date: 2026-01-01', ref('docs-snapshot.md'))
        self.assertIsNotNone(snapshot_age_problem(text, datetime.date.today()))

    def test_stale_string_in_quote_detected(self):
        text = ref('docs-snapshot.md') + '- `x-claim` — set includeCoAuthoredBy to false — page `settings`\n'
        self.assertIn(('includeCoAuthoredBy', 'x-claim'), stale_in_snapshot(ref('stale-strings.md'), text))

    def test_widened_allowlist_leaks(self):
        # Each loosening of the documented rules lets a secret through, so the corpus test fails.
        mutations = {
            'any key name': {'scalar': r'^\s*"[A-Za-z_]+"\s*:\s*' + SCALAR_VALUE + r',?\s*$'},
            'start not anchored': {'scalar': SCALAR_SETTING.replace(r'^\s*', '', 1)},
            'value spans quotes': {'scalar': SCALAR_SETTING.replace(SCALAR_VALUE, '(".*")')},
            'opener with a value': {'opener': r'^\s*"[A-Za-z][A-Za-z0-9_.-]*"\s*:\s*[\[{]'},
            'command not anchored': {'hook_target': r'"(command|url)"\s*:\s*"[^"\\]*"'},
            'url with any path': {'hook_url': r'^\s*"url"\s*:\s*"[^"\\]*",?\s*$'},
            'element of any word': {'path': r'^\s*"[^"\\]*",?\s*$'},
            'host with a digit tail': {'host': r'^\s*"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+",?\s*$'},
        }
        for label, patterns in mutations.items():
            with self.subTest(mutation=label):
                self.assertNotEqual(leaks(patterns), [])

    def test_ungated_rules_leak(self):
        found = leaks(gate=False)
        for label in ('secret in an allow rule', 'secret in a hook command', 'secret in a path element',
                      'value on the line after its key', 'colon on its own line',
                      'path value after a split key', 'path value after a block-commented key',
                      'host value after a line-commented key'):
            self.assertIn(label, found)

    def test_frontmatter_without_probes_leaks(self):
        self.assertIn('inline mcp env', frontmatter_leaks(probe=None))
        self.assertIn('hooks in the body', frontmatter_leaks(probe=None))
        self.assertIn('secret-shaped text in tools', frontmatter_leaks(secret=None))
        narrow = INLINE_CONFIG_PROBE.replace(r'(^\s*|[{,]\s*)', '^')
        self.assertIn('flow mapping frontmatter', frontmatter_leaks(probe=narrow))
        self.assertIn('indented mcp key', frontmatter_leaks(probe=narrow))
        unquoted = INLINE_CONFIG_PROBE.replace("""["']?""", '')
        self.assertIn('quoted mcp key', frontmatter_leaks(probe=unquoted))

    def test_frontmatter_key_widened(self):
        widened = FRONTMATTER_KEY_LINE.replace('^(name|', '^(mcpServers|initialPrompt|bogus|name|')
        problems = frontmatter_key_problems(widened)
        self.assertIn('key may hold servers, hooks or free text: mcpServers', problems)
        self.assertIn('key may hold servers, hooks or free text: initialPrompt', problems)
        self.assertIn('not a documented frontmatter key: bogus', problems)

    def test_credential_key_in_allowlist_detected(self):
        widened = SCALAR_SETTING.replace('"(model|', '"(apiKeyHelper|API_TOKEN|model|')
        problems = allowlisted_key_problems((widened,))
        self.assertIn('credential-bearing name: apiKeyHelper', problems)
        self.assertIn('not lowercase or camelCase: API_TOKEN', problems)

    def test_mcp_read_instruction_detected(self):
        tmp = tempfile.TemporaryDirectory(prefix='lite-redproof-')
        self.addCleanup(tmp.cleanup)
        copy = Path(tmp.name) / 'lite'
        shutil.copytree(LITE, copy, symlinks=True)
        (copy / 'notes.md').write_text('Read .mcp.json to list servers.\nGrep ~/.claude.json for x.\n')
        problems = mcp_instruction_problems(copy)
        self.assertIn('notes.md:1', problems)
        self.assertIn('notes.md:2', problems)

    def test_negation_must_precede_verb_or_file(self):
        self.assertTrue(unsafe_mcp_line('Read .mcp.json if it is not empty.'))
        self.assertTrue(unsafe_mcp_line('Open `~/.claude.json`; it is not secret.'))
        self.assertFalse(unsafe_mcp_line('Never Read .mcp.json.'))
        self.assertFalse(unsafe_mcp_line('`.mcp.json` is never opened, Read or Grepped.'))


SKILL = LITE / 'skills/setup-audit-lite/SKILL.md'
FULL_PLUGIN_GLOB = '~/.claude/plugins/cache/*/setup-audit/*/.claude-plugin/plugin.json'
SNAPSHOT_FALLBACK_LINE = ('Official docs could not be fetched; this audit uses the bundled snapshot '
                          'from <date> and may be out of date.')
COMMUNITY_UNAVAILABLE_LINE = 'Community practice not gathered this run.'
# The four hard limits from the spec ("Applying changes"), never applied even with approval.
HARD_LIMITS = ('credentials and secret values', 'anything that loosens security',
               'adding hooks, MCP servers or plugins',
               'managed settings and files outside the chosen scope')
LOG_FIELDS = ('file', 'scope', 'focus', 'why', 'before', 'after', 'added', 'removed', 'backup',
              'measure', 'status')
LOG_STATUSES = ('applied', 'handed-over', 'rolled-back', 'kept')
# Files written for the workflow; they describe Claude's own tool use, so a Bash rule in them could
# read as an instruction (the references from Task 2 quote Bash rules as audit examples instead).
WORKFLOW_FILES = ('SKILL.md', 'references/report-format.md', 'references/applied-log.md')


def flat(text):
    """Text with line wrapping undone, so phrase checks don't depend on where a line breaks."""
    return ' '.join(text.split())


def skill_text():
    return SKILL.read_text(encoding='utf-8')


BACKUPS_DIR = '~/.claude/setup-audit-lite/backups/'
# One backup per log entry (never one shared per file and day), so restoring or removing one entry's
# backup can't touch another entry.
ENTRY_BACKUP = BACKUPS_DIR + '<YYYY-MM-DD>/<check-id>__<slug>'
SHARED_BACKUP = re.compile(r'backups/<YYYY-MM-DD>/<slug>')
COMMUNITY_RULE = 'community-only practice is never an appliable finding and never enters the apply list'
RESTORE_RULE = ('A full restore only when the reverse Edit can\'t apply and the file is otherwise '
                'unchanged')
NEVER_OPENED_CHECKIN = 'The check-in never Greps a file on the never-opened list'


def workflow_texts():
    """The texts the workflow rules span, keyed by short name."""
    return {'SKILL.md': skill_text(), 'report-format.md': ref('report-format.md'),
            'applied-log.md': ref('applied-log.md'), 'sources.md': ref('sources.md'),
            'reading-rules.md': ref('reading-rules.md')}


def section(text, heading):
    """Body of the Markdown section whose heading line starts with heading, up to the next heading
    of the same or a higher level; '' when absent."""
    level = len(heading) - len(heading.lstrip('#'))
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(heading):
            body = []
            for later in lines[i + 1:]:
                hashes = len(later) - len(later.lstrip('#'))
                if 0 < hashes <= level and later[hashes:hashes + 1] == ' ':
                    break
                body.append(later)
            return '\n'.join(body)
    return ''


def community_only_problems(texts):
    """R1: SKILL.md, report-format.md and sources.md all say community-only practices are never
    appliable findings; report-format.md keeps them to the comparison, marked "by hand"."""
    problems = ['%s lacks the community-only rule' % name
                for name in ('SKILL.md', 'report-format.md', 'sources.md')
                if COMMUNITY_RULE not in flat(texts[name])]
    if 'suggestion, by hand' not in texts['report-format.md']:
        problems.append('report-format.md template lacks the "by hand" community line')
    return problems


def backup_problems(texts):
    """R2: backups live under ~/.claude/setup-audit-lite/backups/, never next to the file, and the
    backups directory is on reading-rules.md's never-opened list."""
    problems = []
    for name in ('SKILL.md', 'applied-log.md'):
        if BACKUPS_DIR not in texts[name]:
            problems.append('%s does not name the backups directory' % name)
    for name, text in texts.items():
        if re.search(r'<file>\.bak-|\.bak-<', text):
            problems.append('%s puts a backup next to the file' % name)
    never_opened = section(texts['reading-rules.md'], '## Never opened')
    if not any(BACKUPS_DIR.rstrip('/') in line and NEGATION.search(line)
               for line in never_opened.splitlines() if line.startswith('- ')):
        problems.append('backups directory missing from the never-opened list')
    for name in ('SKILL.md', 'applied-log.md'):
        if 'its log and its backups directory' not in flat(texts[name]):
            problems.append('%s does not say lite adds its log and backups directory' % name)
    if '! rm <backup path>' not in texts['applied-log.md']:
        problems.append('applied-log.md does not offer removing the backup')
    for name in ('SKILL.md', 'applied-log.md'):
        text = texts[name]
        if ENTRY_BACKUP not in text:
            problems.append('%s does not use one backup per entry' % name)
        if SHARED_BACKUP.search(text):
            problems.append('%s shares a backup per file and day' % name)
        flattened = flat(text)
        if 'Glob for' not in flattened or 'existence only' not in flattened:
            problems.append('%s does not say how the backup existence check works' % name)
        if "entry's own backup" not in flattened:
            problems.append('%s lets rm reach beyond the entry\'s own backup' % name)
        if 'no later entry on the same file is still in place (any status but `rolled-back`)' not in flattened:
            problems.append('%s restores over later applied entries' % name)
    return problems


def never_opened_checkin_problems(texts):
    """R3: the check-in never Greps a never-opened file; presence then comes from a paste or the
    user, and the hand-over uses claude mcp remove or /mcp."""
    problems = []
    for name in ('SKILL.md', 'applied-log.md'):
        text = flat(texts[name])
        if NEVER_OPENED_CHECKIN not in text:
            problems.append('%s lacks the never-opened check-in rule' % name)
        if 'names-only `claude mcp list` paste' not in text:
            problems.append('%s lacks the names-only paste for presence' % name)
        if 'claude mcp remove <name>' not in text:
            problems.append('%s lacks the MCP removal hand-over' % name)
    return problems


def hard_limit_problems(skill):
    """The four hard limits are numbered items under the Hard limits heading itself."""
    body = section(skill, '### Hard limits')
    items = re.findall(r'^\d\. (.+)$', body, re.M)
    problems = []
    for number, limit in enumerate(HARD_LIMITS, 1):
        if not any(item.startswith(limit) for item in items[number - 1:number]):
            problems.append('hard limit %d missing under the heading: %s' % (number, limit))
    return problems


def restore_problems(texts):
    """F9: rollback prefers the reverse Edit; a full restore only when it can't apply and the file is
    otherwise unchanged."""
    problems = []
    for name in ('SKILL.md', 'applied-log.md'):
        text = flat(texts[name])
        if RESTORE_RULE not in text:
            problems.append('%s lacks the restore-only-if-unchanged rule' % name)
    if 'Prefer the reverse Edit' not in texts['applied-log.md']:
        problems.append('applied-log.md does not prefer the reverse Edit')
    return problems


SPEC = ROOT / 'docs/superpowers/specs/2026-11-12-setup-audit-lite-design.md'
CHECKLIST_BULLET = re.compile(r'^- `(?P<id>[A-Z]+-[a-z0-9-]+)`.*?(?=^- `|^## |\Z)', re.S | re.M)


def doc_texts():
    """Flattened texts the final-review rules span; 'checklist.md#<id>' is one check's bullet."""
    texts = {'SKILL.md': skill_text(), 'CHANGELOG.md': (LITE / 'CHANGELOG.md').read_text(encoding='utf-8'),
             'spec': SPEC.read_text(encoding='utf-8')}
    for name in ('reading-rules.md', 'applied-log.md', 'report-format.md', 'docs-snapshot.md',
                 'sources.md', 'checklist.md'):
        texts[name] = ref(name)
    for match in CHECKLIST_BULLET.finditer(texts['checklist.md']):
        texts['checklist.md#' + match.group('id')] = match.group()
    return {name: flat(text) for name, text in texts.items()}


FETCH_LABEL = '"not in fetched portion; snapshot <date>"'
PRESENT = 'every `added` pattern is found and every `removed` pattern counts 0'
REVERSED = 'every `removed` pattern is found and every `added` pattern counts 0'
# (rule, file, phrase): each phrase must be in that file (flattened); one per rule it pins.
REQUIRED_PHRASES = (
    ('C1 probe before frontmatter', 'reading-rules.md', '"inline MCP/hooks present, not read"'),
    ('C1 no whole Read with a hit', 'reading-rules.md', 'A file with either count above 0 is never Read whole.'),
    ('C1 Path A only with probes 0', 'SKILL.md', 'whose inline-config probe and secret probe both count 0'),
    ('C1 hit goes to Path B', 'SKILL.md', 'a skill, agent or command with inline `mcpServers` or `hooks`'),
    ('C1 model check via key Grep', 'checklist.md#COST-model-default', 'single-line key Grep'),
    ('C1 subagent check via key Grep', 'checklist.md#COST-subagents', 'single-line key Grep'),
    ('C1 skill listing via key Grep', 'checklist.md#COST-skill-listing', 'single-line key Grep'),
    ('C1 clutter via key Grep', 'checklist.md#HYG-lite-clutter-skills', 'single-line key Grep'),
    ('I1 added and removed fields', 'applied-log.md', 'Then these eleven fields, in this order:'),
    ('I1 presence rule (log)', 'applied-log.md', '"Still in place" means ' + PRESENT),
    ('I1 presence rule (skill)', 'SKILL.md', 'in place when ' + PRESENT),
    ('I1 reversal rule (log)', 'applied-log.md', 'with the roles swapped (reversed means ' + REVERSED),
    ('I1 reversal rule (skill)', 'SKILL.md', 'then every `removed` pattern is found again and every '
                                            '`added` pattern counts 0'),
    ('I1 core string, not line', 'applied-log.md', 'the core string of one changed line, not the whole line'),
    ('I1 distinctive patterns', 'applied-log.md', 'an `added` pattern counts 0 there before the change, '
                                                  'a `removed` pattern counts 1'),
    ('I2 marker list', 'reading-rules.md', 'with `output_mode: files_with_matches` for the marker '
                                           '`setup-audit-lite`'),
    ('I2 subtraction', 'reading-rules.md', 'the number of files in the first list that are not in the second'),
    ('I2 measure format', 'applied-log.md', '`sessions with "<phrase>" = 12 (setup-audit-lite sessions excluded)`'),
    ('I2 learning check', 'checklist.md#LRN-enforce', "lite's own sessions left out"),
    ('I2 effectiveness check', 'checklist.md#LRN-effectiveness', "lite's own sessions left out"),
    ('I3 label (skill)', 'SKILL.md', FETCH_LABEL),
    ('I3 label (report)', 'report-format.md', 'one of the four labels'),
    ('I3 label (snapshot)', 'docs-snapshot.md', FETCH_LABEL),
    ('I3 label (sources)', 'sources.md', FETCH_LABEL),
    ('I3 one section per call', 'SKILL.md', 'ask one section per call, naming its heading'),
    ('I3 changelog newer versions', 'SKILL.md', "ask only for the versions newer than the user's version"),
    ('I3 coverage line', 'report-format.md', 'Not in fetched portion:'),
    ('M1 unconfirmed quote not applied', 'SKILL.md', 'never on a "current docs, quote not confirmed" quote alone'),
    ('M1 applies-as value', 'report-format.md', '**by hand (quote not confirmed)**'),
    ('M2 output styles rule', 'reading-rules.md', 'Read whole, like instruction files'),
    ('M3 wrong types not run', 'checklist.md#HYG-settings-shape', 'not run: lite does not parse settings'),
    ('M4 hook script partial', 'checklist.md#HYG-missing-hook-script', '"Partial" for hooks whose command isn\'t shown: exec-form'),
    ('M4 hooks partial', 'checklist.md#SEC-hooks', 'makes the check "partial" for that hook'),
    ('M4 duplicates partial', 'checklist.md#HYG-hook-duplicates', 'exec-form `args`'),
    ('M4 clutter partial', 'checklist.md#HYG-lite-clutter-hooks', 'exec-form `args`'),
    ('M5 skip unparseable (skill)', 'SKILL.md', 'skip only those, say in one line how many were skipped'),
    ('M5 skip unparseable (log)', 'applied-log.md', 'Skip only those entries, say in one line how many were skipped'),
    ('M6 enabled plugins only', 'report-format.md', 'only for plugins shown as `true` under `enabledPlugins`'),
    ('M6 current version only', 'report-format.md', 'Older version folders and disabled plugins'),
    ('M7 spec rulings section', 'spec', '## Calls made during the build'),
    ('M7 spec marks superseded', 'spec', 'Superseded (see Calls made during the build)'),
    ('M8 changelog session logs', 'CHANGELOG.md', 'Session logs are counted with count-only Grep'),
)
# (rule, file, phrase): text a fix removed; it must not come back.
FORBIDDEN_PHRASES = (
    ('I1 incoherent anchor sentence', 'applied-log.md', 'the block holds only the changed line'),
    ('I1 whole after lines', 'applied-log.md', 'of each non-empty line of the `after` text'),
    ('I1 whole before lines', 'applied-log.md', 'count-only Grep of each `before` line'),
    ('I1 whole after lines (skill)', 'SKILL.md', 'count-only Grep of the `after` text'),
    ('I2 raw hit count', 'applied-log.md', 'log hits for'),
    ('I2 raw hit count (skill)', 'SKILL.md', 'count-only Grep over local session logs'),
    ('I2 raw hit count (checklist)', 'checklist.md', 'count-only Grep of session logs'),
    ('I3 three labels', 'report-format.md', 'three labels'),
    ('M5 whole log unparseable', 'SKILL.md', 'no check-ins this run'),
    ('M5 whole log unparseable (log)', 'applied-log.md', 'no check-ins this run'),
    ('M8 internal parked items', 'CHANGELOG.md', 'Parked minor items'),
    ('M8 session logs by Glob', 'CHANGELOG.md', 'and session logs. Existence checks by Glob only'),
)


def doc_rule_problems(texts):
    problems = ['%s: %s lacks %r' % (rule, name, phrase) for rule, name, phrase in REQUIRED_PHRASES
                if phrase not in texts.get(name, '')]
    problems += ['%s: %s contains %r' % (rule, name, phrase) for rule, name, phrase in FORBIDDEN_PHRASES
                 if phrase in texts.get(name, '')]
    return problems


def presence(file_text, added, removed):
    """The check-in rule: in place when every added pattern is found and every removed one isn't."""
    def found(pattern):
        return any(re.search(pattern, line) for line in file_text.split('\n'))
    return all(found(p) for p in added) and not any(found(p) for p in removed)


def example_entry():
    """before, after, added and removed from the example entry in applied-log.md."""
    text = ref('applied-log.md')
    blocks = re.findall(r'```text\n(.*?)\n  ```', text, re.S)
    before, after = ('\n'.join(l[2:] for l in b.splitlines()) for b in blocks[:2])
    lists = {}
    for field in ('added', 'removed'):
        body = re.search(r'^- `%s`:\n((?:  - `.*`\n)+)' % field, text, re.M).group(1)
        lists[field] = re.findall(r'  - `(.*)`', body)
    return before, after, lists['added'], lists['removed']


class SkillWorkflowRedProof(unittest.TestCase):
    """Each rule check fails when the documents are mutated to break that rule."""

    def test_community_rule_removed(self):
        for name in ('SKILL.md', 'report-format.md', 'sources.md'):
            with self.subTest(file=name):
                text = workflow_texts()[name]
                broken = re.sub(r'never(\s+)an(\s+)appliable', 'sometimes an appliable', text)
                texts = workflow_texts()
                texts[name] = broken
                self.assertTrue(community_only_problems(texts))

    def test_backup_next_to_file(self):
        texts = workflow_texts()
        texts['SKILL.md'] += '\nWrite `<file>.bak-<YYYY-MM-DD>`.\n'
        self.assertIn('SKILL.md puts a backup next to the file', backup_problems(texts))

    def test_shared_per_day_backup(self):
        texts = workflow_texts()
        for name in ('SKILL.md', 'applied-log.md'):
            texts[name] = texts[name].replace('<check-id>__<slug>', '<slug>')
        problems = backup_problems(texts)
        self.assertIn('SKILL.md shares a backup per file and day', problems)
        self.assertIn('applied-log.md does not use one backup per entry', problems)

    def test_restore_over_later_entries(self):
        texts = workflow_texts()
        texts['applied-log.md'] = re.sub(r'no(\s+)later(\s+)entry', 'some entry',
                                         texts['applied-log.md'])
        self.assertIn('applied-log.md restores over later applied entries', backup_problems(texts))

    def test_backups_dir_not_never_opened(self):
        texts = workflow_texts()
        texts['reading-rules.md'] = '\n'.join(
            l for l in texts['reading-rules.md'].splitlines() if BACKUPS_DIR not in l)
        self.assertIn('backups directory missing from the never-opened list', backup_problems(texts))

    def test_checkin_greps_never_opened(self):
        texts = workflow_texts()
        texts['applied-log.md'] = texts['applied-log.md'].replace('never Greps', 'Greps')
        self.assertIn('applied-log.md lacks the never-opened check-in rule',
                      never_opened_checkin_problems(texts))

    def test_hard_limit_outside_heading(self):
        skill = skill_text()
        body = section(skill, '### Hard limits')
        moved = skill.replace(body, body.replace('2. anything that loosens security', '2. loosening'))
        moved += '\n2. anything that loosens security\n'
        self.assertIn('hard limit 2 missing under the heading: anything that loosens security',
                      hard_limit_problems(moved))

    def test_doc_rules_removed(self):
        for rule, name, phrase in REQUIRED_PHRASES:
            with self.subTest(rule=rule):
                texts = doc_texts()
                texts[name] = texts[name].replace(phrase, '')
                self.assertIn('%s: %s lacks %r' % (rule, name, phrase), doc_rule_problems(texts))

    def test_doc_rules_reverted(self):
        for rule, name, phrase in FORBIDDEN_PHRASES:
            with self.subTest(rule=rule):
                texts = doc_texts()
                texts[name] += ' ' + phrase
                self.assertIn('%s: %s contains %r' % (rule, name, phrase), doc_rule_problems(texts))

    def test_whole_line_presence_misleads(self):
        # A change that removes a deny rule, with an anchor line in both blocks. The user later put
        # the rule back. The old check (every line of `after` found) still says "in place", because
        # `after` holds only the anchor; the added/removed rule sees the rule is back.
        after = '    "deny": [\n      "Read(./.env)"\n    ]'
        undone = '    "deny": [\n      "Read(./.env)",\n      "Bash(rm -rf *)"\n    ]'

        def old_rule(file_text):
            return all(re.search(re.escape(l.strip()), file_text) for l in after.splitlines() if l.strip())

        self.assertTrue(old_rule(undone))  # the false "still in place"
        removed = [r'"Bash\(rm -rf \*\)"']
        self.assertTrue(presence(after, [], removed))
        self.assertFalse(presence(undone, [], removed))
        # A core string survives a re-format that breaks a whole-line match.
        reformatted = '  "deny": ["Read(./.env)", "Bash(git push *)"]'
        self.assertTrue(presence(reformatted, [r'"Bash\(git push \*\)"'], []))
        self.assertFalse(re.search(re.escape('      "Bash(git push *)"'), reformatted))

    def test_restore_without_unchanged_check(self):
        texts = workflow_texts()
        texts['applied-log.md'] = re.sub(r'and(\s+)the(\s+)file(\s+)is(\s+)otherwise(\s+)unchanged',
                                         'whenever the user likes', texts['applied-log.md'])
        self.assertIn('applied-log.md lacks the restore-only-if-unchanged rule',
                      restore_problems(texts))


class SkillWorkflow(unittest.TestCase):
    def test_skill_cites_every_reference(self):
        text = skill_text()
        names = sorted(p.name for p in REFS.iterdir() if p.is_file())
        for name in ('report-format.md', 'applied-log.md'):
            self.assertIn(name, names)
        for name in names:
            self.assertIn(name, text)

    def test_skill_under_500_lines(self):
        self.assertLess(len(skill_text().splitlines()), 500)

    def test_hard_limits_listed(self):
        text = flat(skill_text())
        for limit in HARD_LIMITS:
            self.assertIn(limit, text)

    def test_snapshot_fallback_line(self):
        self.assertIn(SNAPSHOT_FALLBACK_LINE, flat(skill_text()))

    def test_community_unavailable_line(self):
        self.assertIn(COMMUNITY_UNAVAILABLE_LINE, flat(skill_text()))

    def test_mcp_paste_redaction(self):
        self.assertIn('remove tokens, URLs with keys and arguments before pasting', flat(skill_text()))
        report = flat(ref('report-format.md'))
        self.assertIn('never repeats values, URLs or arguments from a pasted', report)

    def test_rollback_never_forces(self):
        text = ref('applied-log.md')
        defined = re.findall(r'^- `([a-z-]+)`', text, re.M)
        for field in LOG_FIELDS:
            self.assertIn(field, defined)
        self.assertIn('~/.claude/setup-audit-lite/applied.md', text)
        self.assertRegex(flat(text), r'If the `after` text is no longer found, lite reports the '
                                     r'mismatch and hands over the manual reversal; it never '
                                     r'forces a write\.')

    def test_log_statuses(self):
        text = flat(ref('applied-log.md'))
        for status in LOG_STATUSES:
            self.assertIn('`%s`' % status, text)

    def test_full_plugin_detection(self):
        self.assertIn(FULL_PLUGIN_GLOB, skill_text())

    def test_no_curl_fallback(self):
        self.assertRegex(flat(skill_text()), r'(?i)never fall back to curl')
        for rel in WORKFLOW_FILES:
            with self.subTest(file=rel):
                text = (LITE / 'skills/setup-audit-lite' / rel).read_text(encoding='utf-8')
                self.assertNotIn('Bash(', text)
        self.assertEqual([p for p in bundle_problems(LITE) if 'allowed-tools' in p], [])

    def test_settings_never_edited(self):
        text = flat(skill_text())
        self.assertIn('Settings files are never Edited or Written', text)
        self.assertIn('paste-ready edit', text)
        self.assertIn('`handed-over`', flat(ref('applied-log.md')))

    def test_community_only_never_appliable(self):
        self.assertEqual(community_only_problems(workflow_texts()), [])

    def test_backups_outside_project(self):
        self.assertEqual(backup_problems(workflow_texts()), [])

    def test_checkin_never_greps_never_opened(self):
        self.assertEqual(never_opened_checkin_problems(workflow_texts()), [])

    def test_hard_limits_under_heading(self):
        self.assertEqual(hard_limit_problems(skill_text()), [])

    def test_restore_only_if_unchanged(self):
        self.assertEqual(restore_problems(workflow_texts()), [])

    def test_final_review_doc_rules(self):
        self.assertEqual(doc_rule_problems(doc_texts()), [])

    def test_example_entry_patterns_work(self):
        before, after, added, removed = example_entry()
        self.assertTrue(added and removed)
        self.assertTrue(presence(after, added, removed))
        self.assertFalse(presence(before, added, removed))
        # Reversal is the same test with the roles swapped.
        self.assertTrue(presence(before, removed, added))
        self.assertFalse(presence(after, removed, added))

    def test_workflow_files_have_no_urls(self):
        for rel in WORKFLOW_FILES:
            with self.subTest(file=rel):
                text = (LITE / 'skills/setup-audit-lite' / rel).read_text(encoding='utf-8')
                self.assertIsNone(URL.search(text))


if __name__ == '__main__':
    unittest.main()
