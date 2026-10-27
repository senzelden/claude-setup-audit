"""Bundled docs fetch script. The network opener is always patched; nothing here hits the net."""
import ast
import contextlib
import io
import os
import re
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest import mock

SCRIPTS = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins', 'setup-audit',
                                       'skills', 'setup-audit', 'scripts'))
sys.path.insert(0, SCRIPTS)
import fetch_doc  # noqa: E402


class FakeResponse:
    def __init__(self, body, url='https://code.claude.com/docs/en/x.md'):
        self._body, self._url = body, url

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def run(*argv, response=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(fetch_doc, '_open', return_value=response) as opener:
        code = fetch_doc.main(list(argv))
    return code, out.getvalue(), err.getvalue(), opener


class FetchDoc(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='fetchdoc.')
        self.out = os.path.join(self.tmp, 'page.md')

    def test_valid_page_written(self):
        code, stdout, _, opener = run('en/settings-reference.md', self.out, response=FakeResponse(b'# hi\n'))
        self.assertEqual(code, 0)
        with open(self.out, 'rb') as f:
            self.assertEqual(f.read(), b'# hi\n')
        self.assertEqual(os.stat(self.out).st_mode & 0o777, 0o600)
        self.assertIn(f'wrote {self.out} (5 bytes)', stdout)
        req = opener.call_args[0][0]
        self.assertEqual(req.full_url, 'https://code.claude.com/docs/en/settings-reference.md')
        self.assertEqual(dict(req.header_items()), {'User-agent': 'setup-audit-fetch-doc'})
        self.assertIsNone(req.data)

    def test_llms_txt_accepted(self):
        code, *_ = run('llms.txt', self.out, response=FakeResponse(b'idx'))
        self.assertEqual(code, 0)

    def test_bad_pages_exit_2(self):
        for page in ('../x.md', 'https://evil/x.md', 'en/../../etc', 'en/x.txt', 'en/A.md', '/etc/passwd'):
            code, _, _, opener = run(page, self.out, response=FakeResponse(b'x'))
            self.assertEqual(code, 2, page)
            opener.assert_not_called()
        self.assertFalse(os.path.exists(self.out))

    def test_wrong_arg_count_exit_2(self):
        self.assertEqual(run('llms.txt', response=None)[0], 2)

    def only_allowed(self, allowed):
        return mock.patch.object(fetch_doc, '_allowed_dirs', return_value={os.path.realpath(allowed)})

    def test_out_outside_allowed_dirs_exit_2(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        outside = tempfile.mkdtemp(prefix='fetchdoc.outside.')
        dest = os.path.join(outside, 'page.md')
        with self.only_allowed(allowed):
            code, _, _, opener = run('llms.txt', dest, response=FakeResponse(b'x'))
        self.assertEqual(code, 2)
        opener.assert_not_called()
        self.assertFalse(os.path.exists(dest))

    def test_symlinked_parent_escape_exit_2(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        outside = tempfile.mkdtemp(prefix='fetchdoc.outside.')
        link = os.path.join(allowed, 'link')
        os.symlink(outside, link)
        for dest in (os.path.join(link, 'page.md'), os.path.join(link, 'new', 'page.md')):
            with self.only_allowed(allowed):
                code, _, _, opener = run('llms.txt', dest, response=FakeResponse(b'x'))
            self.assertEqual(code, 2, dest)
            opener.assert_not_called()
        self.assertEqual(os.listdir(outside), [])

    def test_missing_parents_created_inside_allowed_dir(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        dest = os.path.join(allowed, 'setup-audit-docs', 'en', 'page.md')
        with self.only_allowed(allowed):
            code, *_ = run('en/settings.md', dest, response=FakeResponse(b'# hi\n'))
        self.assertEqual(code, 0)
        with open(dest, 'rb') as f:
            self.assertEqual(f.read(), b'# hi\n')
        for d in (os.path.join(allowed, 'setup-audit-docs'), os.path.dirname(dest)):
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700, d)

    def test_missing_parent_outside_allowed_dir_not_created(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        outside = tempfile.mkdtemp(prefix='fetchdoc.outside.')
        dest = os.path.join(outside, 'new', 'page.md')
        with self.only_allowed(allowed):
            code, *_ = run('llms.txt', dest, response=FakeResponse(b'x'))
        self.assertEqual(code, 2)
        self.assertFalse(os.path.exists(os.path.join(outside, 'new')))

    def test_parent_not_created_when_fetch_fails(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        dest = os.path.join(allowed, 'new', 'page.md')
        with self.only_allowed(allowed):
            code, *_ = run('llms.txt', dest, response=FakeResponse(b'x', url='https://evil.example/x'))
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(allowed, 'new')))

    def test_redirect_to_other_host_exit_1_nothing_written(self):
        code, *_ = run('llms.txt', self.out, response=FakeResponse(b'x', url='https://evil.example/llms.txt'))
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out))

    def test_http_scheme_refused(self):
        code, *_ = run('llms.txt', self.out, response=FakeResponse(b'x', url='http://code.claude.com/docs/llms.txt'))
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out))

    def test_oversize_exit_1_nothing_written(self):
        code, *_ = run('llms.txt', self.out, response=FakeResponse(b'x' * (5 * 1024 * 1024 + 1)))
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out))

    def test_fetch_error_exit_1(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(fetch_doc, '_open', side_effect=OSError('down')):
            code = fetch_doc.main(['llms.txt', self.out])
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out))

    def test_symlink_not_followed(self):
        target = os.path.join(self.tmp, 'target')
        with open(target, 'w') as f:
            f.write('keep')
        os.symlink(target, self.out)
        code, *_ = run('llms.txt', self.out, response=FakeResponse(b'x'))
        self.assertEqual(code, 1)
        with open(target) as f:
            self.assertEqual(f.read(), 'keep')

    def test_claude_audits_dir_allowed(self):
        cfg = tempfile.mkdtemp(prefix='fetchdoc.cfg.')
        os.makedirs(os.path.join(cfg, 'audits'))
        dest = os.path.join(cfg, 'audits', 'p.md')
        with mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': cfg}), \
                mock.patch.object(fetch_doc.tempfile, 'gettempdir', return_value='/nonexistent-tmp'), \
                mock.patch.dict(os.environ, {'TMPDIR': '/nonexistent-tmp'}):
            code, *_ = run('llms.txt', dest, response=FakeResponse(b'x'))
        self.assertEqual(code, 0)


class SameHostRedirects(unittest.TestCase):
    """The redirect handler itself, not just the final-URL check in main()."""

    def redirect(self, newurl):
        handler = fetch_doc._SameHostOnly()
        req = urllib.request.Request('https://code.claude.com/docs/llms.txt')
        return handler.redirect_request(req, None, 301, 'Moved', {}, newurl)

    def test_off_host_https_refused(self):
        with self.assertRaises(urllib.error.URLError):
            self.redirect('https://evil.example/docs/llms.txt')

    def test_same_host_http_refused(self):
        with self.assertRaises(urllib.error.URLError):
            self.redirect('http://code.claude.com/docs/llms.txt')

    def test_same_host_https_allowed(self):
        new = self.redirect('https://code.claude.com/docs/en/overview.md')
        self.assertIsInstance(new, urllib.request.Request)
        self.assertEqual(new.full_url, 'https://code.claude.com/docs/en/overview.md')


class DocumentedInvocation(unittest.TestCase):
    """SKILL.md and the docs map run the script like every other bundled script, into $TMPDIR."""

    def test_every_fetch_doc_command_uses_skill_dir_and_tmpdir(self):
        skill = os.path.dirname(SCRIPTS)
        pattern = re.compile(r'python3 (\S+)/fetch_doc\.py (\S+) (\S+)')
        for name in ('SKILL.md', os.path.join('references', 'docs-map.md')):
            with open(os.path.join(skill, name)) as f:
                text = f.read()
            commands = pattern.findall(text)
            self.assertTrue(commands, name)
            self.assertEqual(len(commands), text.count('fetch_doc.py'), name)
            for script_dir, _page, out in commands:
                self.assertEqual(script_dir, '${CLAUDE_SKILL_DIR}/scripts', name)
                self.assertTrue(out.startswith('"$TMPDIR/setup-audit-docs/'), (name, out))


class Isolation(unittest.TestCase):
    """Static: the script stays a fixed-host download with no local reads and no code execution."""

    def setUp(self):
        with open(os.path.join(SCRIPTS, 'fetch_doc.py')) as f:
            self.tree = ast.parse(f.read())

    def test_script_is_isolated(self):
        allowed = {'os', 're', 'sys', 'tempfile', 'urllib.request', 'urllib.error', 'urllib.parse'}
        imported = set()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                imported |= {a.name for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                imported.add(node.module)
        self.assertLessEqual(imported, allowed)
        names = {n.id for n in ast.walk(self.tree) if isinstance(n, ast.Name)}
        self.assertFalse(names & {'open', 'exec', 'eval', 'compile', '__import__', 'subprocess'})
        attrs = [(n.value.id, n.attr) for n in ast.walk(self.tree)
                 if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)]
        self.assertNotIn(('os', 'system'), attrs)
        self.assertNotIn(('os', 'popen'), attrs)
        # exactly one file open, the O_NOFOLLOW write of OUT
        self.assertEqual(attrs.count(('os', 'open')), 1)
        self.assertNotIn(('os', 'getenv'), attrs)

    def test_fixed_host_only(self):
        src = ast.unparse(self.tree)
        self.assertIn('https://code.claude.com/docs/', src)
        self.assertEqual(src.count('http://') + src.count('https://'), src.count('https://code.claude.com'))


if __name__ == '__main__':
    unittest.main()
