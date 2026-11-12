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
                      '.webp', '.ico'}
TEXT_EXTENSIONS = {'.md', '.txt', '.json', '.yaml', '.yml'}
ALLOWED_TOOLS = {'Read', 'Grep', 'Glob', 'LS'}
FORBIDDEN_NAMES = {'package.json', 'package-lock.json', 'pyproject.toml', 'poetry.lock', 'uv.lock',
                   'pnpm-lock.yaml', 'yarn.lock', 'pnpm-workspace.yaml', 'Pipfile', 'Pipfile.lock',
                   '.mcp.json'}
FORBIDDEN_DIRS = {'hooks', 'bin', 'workflows', 'scripts'}
FORBIDDEN_MANIFEST_KEYS = {'icon', 'hooks', 'mcpServers', 'mods', 'modules'}
IMAGE_OR_FONT_PATH = re.compile(r'\.(png|jpe?g|gif|webp|woff2?|ttf|otf|ico)\b', re.I)
CREDENTIAL_SOURCE = re.compile(
    r'\.claude\.json|\.envrc|\.credentials\.json|\bdirenv\b'
    r'|\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)[A-Z0-9_]*\b|\b[A-Z0-9_]+_KEY\b')
URL = re.compile(r'https?://')


def frontmatter(text):
    match = re.match(r'---\n(.*?)\n---\n', text, re.S)
    if not match:
        return None
    fields = {}
    for line in match.group(1).splitlines():
        key, sep, value = line.partition(':')
        if sep and not line.startswith((' ', '\t')):
            fields[key.strip()] = value.strip()
    return fields


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
            if name == 'SKILL.md':
                fields = frontmatter(text)
                if fields is None:
                    problems.append('missing frontmatter: %s' % rel)
                    continue
                tools = fields.get('allowed-tools', '')
                for tool in tools.split():
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
        tools = set(fields['allowed-tools'].split())
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
        self.assertEqual(entries['setup-audit-lite']['source'], './plugins/setup-audit-lite')
        self.assertEqual(entries['setup-audit']['source'], './plugins/setup-audit')
        self.assertTrue(entries['setup-audit']['description'].startswith('Audit Claude Code configuration'))


class RedProofTests(unittest.TestCase):
    def violate(self, mutate):
        tmp = tempfile.mkdtemp(prefix='lite-redproof-')
        copy = Path(tmp) / 'lite'
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
        self.assertNamed(self.violate(mutate), 'hooks')

    def test_bin_dir(self):
        self.assertNamed(self.violate(lambda r: (r / 'bin').mkdir()), 'forbidden directory: bin')

    def test_package_json(self):
        problems = self.violate(lambda r: (r / 'package.json').write_text('{}\n'))
        self.assertNamed(problems, 'package-manager config: package.json')

    def test_symlink(self):
        problems = self.violate(lambda r: os.symlink('README.md', r / 'link.md'))
        self.assertNamed(problems, 'symlink: link.md')

    def test_credential_source_with_url(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text(
            'Never open .envrc. See https://example.invalid\n'))
        self.assertNamed(problems, 'paired with URL in notes.md')

    def test_credential_source_without_url_is_fine(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text('Never open .envrc.\n'))
        self.assertEqual(problems, [])

    def test_image_reference(self):
        problems = self.violate(lambda r: (r / 'notes.md').write_text('![x](icon.png)\n'))
        self.assertNamed(problems, 'image or font path: notes.md')

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


if __name__ == '__main__':
    unittest.main()
