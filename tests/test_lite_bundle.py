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
# Probes and structure patterns of the value-free algorithm in reading-rules.md, copied verbatim
# (a test asserts each appears there). They must stay within syntax that Python re and ripgrep
# share: no lookaround and no backreferences (test_documented_patterns_portable).
VALUE_KEY = r'"(env|headers)"'
# Both forms are anchored to the whole line: every line naming env/headers must be exactly one.
VALUE_OPEN_EOL = r'^\s*"(env|headers)"\s*:\s*\{\s*$'
VALUE_EMPTY = r'^\s*"(env|headers)"\s*:\s*\{\s*\},?\s*$'
HELPER = (r'"(apiKeyHelper|awsAuthRefresh|gcpAuthRefresh|awsCredentialExport|otelHeadersHelper|'
          r'headersHelper)"')
HEADERS_HELPER = r'"headersHelper"'
# Secret shapes: defence in depth, best effort by known shapes (the structural skip is the guarantee).
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
TOML_HEADER = r'^\[\[?[A-Za-z]'
ESCAPED_KEY = r'"[^"]*\\u[0-9A-Fa-f]{4}[^"]*"\s*:'
OPEN_BRACE_LINE = r'\{[^}]*$'
MAPPED_BRACE_OPEN = r'^\s*("[^"]*"\s*:\s*)?\{\s*$'
BLOCK_OPEN = r'^\s*("[^"]*"\s*:\s*)?[\[{]\s*$'
BLOCK_CLOSE = r'^\s*[\]}],?\s*$'
DOCUMENTED_PATTERNS = (VALUE_KEY, VALUE_OPEN_EOL, VALUE_EMPTY, HELPER, HEADERS_HELPER, SECRET_IN_RULE,
                       SECRET_IN_ELEMENT, SECRET_IN_MANIFEST, TOML_HEADER, ESCAPED_KEY,
                       OPEN_BRACE_LINE, MAPPED_BRACE_OPEN, BLOCK_OPEN, BLOCK_CLOSE)
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


def simulate_settings_read(text):
    """Run the reading-rules algorithm on a settings file's text, as Grep and Read would.

    Returns (reason, []) when the file is "not read", else (None, [line numbers read]).
    """
    lines = text.splitlines()

    def count(pattern):
        return sum(1 for line in lines if re.search(pattern, line))

    if count(VALUE_KEY) != count(VALUE_OPEN_EOL) + count(VALUE_EMPTY):
        return 'value on an opening line or split key', []
    if count(HEADERS_HELPER):
        return 'headers helper', []
    if count(SECRET_IN_RULE) + count(SECRET_IN_ELEMENT):
        return 'secret-shaped', []
    if count('.') == 1:
        return 'one non-empty line', []
    if count(ESCAPED_KEY):
        return 'unicode-escaped key name', []
    if count(OPEN_BRACE_LINE) != count(MAPPED_BRACE_OPEN):
        return 'object opened on a line with other text', []
    helper = count(HELPER) > 0
    stack, depth_of, in_value = [], {}, set()
    for number, line in enumerate(lines, 1):
        depth_of[number] = len(stack)
        if stack and stack[-1][1]:
            in_value.add(number)
        if re.search(BLOCK_OPEN, line):
            if stack and stack[-1][1]:
                return 'opening inside a value block', []
            stack.append((line.rstrip()[-1], bool(re.search(VALUE_OPEN_EOL, line))))
            if stack[-1][1]:
                in_value.add(number)
        elif re.search(BLOCK_CLOSE, line):
            if not stack or {'{': '}', '[': ']'}[stack[-1][0]] != line.strip().rstrip(',')[0]:
                return 'unpaired structure', []
            stack.pop()
    if stack:
        return 'unpaired structure', []
    read = [n for n in range(1, len(lines) + 1)
            if n not in in_value and (not helper or depth_of[n] >= 2)]
    return None, read


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

    def test_reading_rules_cover_inline_and_minified(self):
        text = ref('reading-rules.md')
        for pattern in DOCUMENTED_PATTERNS:
            self.assertIn('`%s`' % pattern, text)
        self.assertIn('output_mode: count', text)
        self.assertIn('one non-empty line', text)
        self.assertIn('not read', text)
        self.assertIn('depth 2 or deeper', text)
        self.assertIn('root object', text)

    def test_documented_patterns_portable(self):
        # Grep runs ripgrep, Python runs these tests: keep to the shared syntax.
        text = ref('reading-rules.md')
        for token in ('(?=', '(?!', '(?<', '\\1'):
            self.assertNotIn(token, text)
        for pattern in DOCUMENTED_PATTERNS:
            re.compile(pattern)

    def test_value_blocks_never_read(self):
        clean = '\n'.join(['{', '  "model": "opus",', '  "env": {', '    "A": "VALUE1",',
                           '    "B": "VALUE2"', '  },', '  "headers": {},', '  "permissions": {',
                           '    "allow": [', '      "Bash(uv run pytest -q)"', '    ]', '  }', '}'])
        reason, read = simulate_settings_read(clean)
        self.assertIsNone(reason)
        lines = clean.splitlines()
        self.assertFalse([n for n in read if 'VALUE' in lines[n - 1]])
        self.assertIn(10, read)  # the allow rule
        self.assertIn(2, read)   # a top-level scalar, no helper present
        layouts = {
            'tight inline': '{\n  "env": {"A": "VALUE"},\n  "model": "opus"\n}',
            'spaced inline': '{\n  "env": { "A": "VALUE" },\n  "model": "opus"\n}',
            'brace on next line': '{\n  "env":\n  {\n    "A": "VALUE"\n  }\n}',
            'key alone, colon on next line': '{\n  "env"\n  : {\n    "A": "VALUE"\n  }\n}',
            'nested object in env': '{\n  "env": {\n    "A": {\n      "B": "VALUE"\n    }\n  }\n}',
            'minified': '{"model": "opus", "permissions": {"allow": ["Bash(ls *)"]}}',
            'unpaired': '{\n  "permissions": {\n    "allow": []\n}',
            'headers helper': '{\n  "headersHelper": "/x.sh",\n  "model": "opus"\n}',
            'block opened after other text': ('{\n  "permissions": {\n    "allow": []\n  }, "env": {\n'
                                              '    "A": "VALUE"\n  }\n}'),
            'escaped env key, inline': '{\n  "\\u0065nv": {"A": "VALUE"},\n  "model": "opus"\n}',
            'escaped env key, pretty': '{\n  "\\u0065nv": {\n    "A": "VALUE"\n  }\n}',
            'escaped helper key': '{\n  "apiKey\\u0048elper": "echo VALUE",\n  "model": "opus"\n}',
            'object opened mid-line inside env': ('{\n  "env": {\n    "A": {"n": 1,\n    "m": 2\n'
                                                  '    },\n    "B": "VALUE" }\n}'),
            'value block and empty block on one line': ('{\n  "env": {"A": "VALUE"}, "headers": {},\n'
                                                        '  "model": "opus"\n}'),
        }
        for label, text in layouts.items():
            with self.subTest(layout=label):
                self.assertIsNotNone(simulate_settings_read(text)[0])

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
        for line in ('[tool.ruff]', '[[tool.uv.index]]', '[project.scripts]'):
            self.assertTrue(header.search(line), line)
        for line in ('["a",', '[1, 2]', '  [tool.x]', '"[x]"'):
            self.assertFalse(header.search(line), line)

    def test_realistic_settings_stay_readable(self):
        # The structure probes must not refuse an ordinary pretty-printed settings file.
        text = '''{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "model": "opus",
  "env": {
    "A": "VALUE1"
  },
  "permissions": {
    "allow": ["Bash(uv run pytest *)", "Bash(awk '{print $1}' *)"],
    "deny": [
      "Read(./.env)",
      "Bash(git push --force *)"
    ],
    "additionalDirectories": []
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "${CLAUDE_PLUGIN_ROOT}/guard.sh",
            "onFailure": "block",
            "timeout": 30
          }
        ]
      }
    ],
    "SessionStart": [{ "hooks": [{ "type": "command", "command": "echo hi" }] }]
  },
  "sandbox": {
    "enabled": true,
    "network": {
      "allowedDomains": ["pypi.org"]
    }
  },
  "enabledPlugins": {
    "superpowers@claude-plugins-official": true
  }
}'''
        reason, read = simulate_settings_read(text)
        self.assertIsNone(reason)
        lines = text.splitlines()
        self.assertFalse([n for n in read if 'VALUE' in lines[n - 1]])
        self.assertTrue(any('onFailure' in lines[n - 1] for n in read))

    def test_structure_probe_samples(self):
        escaped, open_line, mapped = (re.compile(ESCAPED_KEY), re.compile(OPEN_BRACE_LINE),
                                      re.compile(MAPPED_BRACE_OPEN))
        self.assertTrue(escaped.search('  "\\u0065nv": {"A": "x"}'))
        self.assertTrue(escaped.search('  "apiKey\\u0048elper": "echo x",'))
        self.assertFalse(escaped.search('  "env": {'))
        self.assertTrue(open_line.search('    "A": {"n": 1,'))
        self.assertFalse(mapped.search('    "A": {"n": 1,'))
        for line in ('{', '  "hooks": {', '      {'):
            self.assertTrue(open_line.search(line) and mapped.search(line), line)
        for line in ('"command": "${CLAUDE_PLUGIN_ROOT}/x.sh",', '"Bash(awk \'{print $1}\' *)",',
                     '[{ "hooks": [{ "type": "command" }] }]'):
            self.assertFalse(open_line.search(line), line)

    def test_helper_lines_skipped(self):
        text = '\n'.join(['{', '  "apiKeyHelper": "/opt/VALUE.sh",', '  "model": "opus",',
                          '  "permissions": {', '    "deny": [', '      "Read(./.env)"', '    ]',
                          '  }', '}'])
        reason, read = simulate_settings_read(text)
        self.assertIsNone(reason)
        self.assertNotIn(2, read)
        self.assertNotIn(3, read)  # every depth-1 line is skipped when a helper is present
        self.assertIn(6, read)

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
