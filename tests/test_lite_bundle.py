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
                   'pnpm-lock.yaml', 'yarn.lock', 'pnpm-workspace.yaml', 'Pipfile', 'Pipfile.lock',
                   '.mcp.json'}
FORBIDDEN_DIRS = {'hooks', 'bin', 'workflows', 'scripts'}
FORBIDDEN_MANIFEST_KEYS = {'icon', 'hooks', 'mcpServers', 'mods', 'modules'}
IMAGE_OR_FONT_PATH = re.compile(r'\.(png|jpe?g|gif|webp|svg|avif|bmp|ico|woff2?|ttf|otf|eot)\b', re.I)
CREDENTIAL_SOURCE = re.compile(
    r'(?i:\.claude\.json|\.envrc|\.credentials\.json|\bdirenv\b)'
    r'|\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)[A-Z0-9_]*\b|\b[A-Z0-9_]+_KEY\b')
URL = re.compile(r'https?://')


def frontmatter(text):
    """Top-level keys mapped to their inline value plus any indented or '- ' continuation lines."""
    match = re.match(r'---\n(.*?)\n---\n', text, re.S)
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
            if ext not in ALLOWED_EXTENSIONS:
                problems.append('disallowed file type: %s' % rel)
            if ext not in IMAGE_EXTENSIONS and path.stat().st_size > MAX_TEXT_BYTES:
                problems.append('larger than 256 KiB: %s' % rel)
            with open(path, 'rb') as handle:
                if handle.read(2) == b'#!':
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
                    for key in sorted(FORBIDDEN_MANIFEST_KEYS & set(manifest)):
                        problems.append('manifest key %s: %s' % (key, rel))
            if ext == '.md':
                fields = frontmatter(text)
                if fields is None:
                    if name == 'SKILL.md':
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
                       'GITHUB_TOKEN', 'MY_SECRET', 'DB_PASSWORD', 'X_API_KEY', 'SIGNING_KEY'):
            with self.subTest(sample=sample):
                problems = self.violate(lambda r: (r / 'notes.md').write_text(
                    'Never open %s. See https://example.invalid\n' % sample))
                self.assertNamed(problems, 'paired with URL in notes.md')

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
SPLIT_LINE = r'(^\s*:|:\s*$)'
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
DOCUMENTED_PATTERNS = (SCALAR_SETTING, OPENER, BOOLEAN_FLAG, RULE_LINE, HOOK_FIELD, HOOK_TARGET,
                       HOOK_URL, PATH_ELEMENT, HOST_ELEMENT,
                       SPLIT_LINE, SECRET_IN_RULE, SECRET_IN_ELEMENT, SECRET_IN_MANIFEST, TOML_HEADER,
                       PY_STRICT, TS_STRICT, SCRIPT_LINE, MAKE_TARGET)
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
        text = ref('reading-rules.md')
        self.assertIn('scalar allowlist plus the hook-field keys', text)

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
                      'path value after a split key'):
            self.assertIn(label, found)

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


if __name__ == '__main__':
    unittest.main()
