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

    @contextlib.contextmanager
    def only_allowed(self, allowed):
        # Patch the configured spelling too: on macOS mkdtemp paths sit under /var -> /private/var.
        with mock.patch.object(fetch_doc, '_allowed_spellings', return_value={os.path.abspath(allowed)}), \
                mock.patch.object(fetch_doc, '_allowed_dirs', return_value={os.path.realpath(allowed)}):
            yield

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
        old_umask = os.umask(0o022)  # a mode-less mkdir would then yield 0755 and fail below
        try:
            with self.only_allowed(allowed):
                code, *_ = run('en/settings.md', dest, response=FakeResponse(b'# hi\n'))
        finally:
            os.umask(old_umask)
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

    def assert_refused_nothing_written(self, allowed, dest):
        with self.only_allowed(allowed):
            code, _, err, _ = run('llms.txt', dest, response=FakeResponse(b'x'))
        self.assertEqual(code, 1, err)
        self.assertIn('refused:', err)
        self.assertFalse(os.path.lexists(dest))
        return err

    def test_group_or_other_writable_parent_refused(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        shared = os.path.join(allowed, 'setup-audit-docs')
        os.mkdir(shared)
        os.chmod(shared, 0o777)
        self.assertIn('writable by group or others',
                      self.assert_refused_nothing_written(allowed, os.path.join(shared, 'p.md')))
        os.chmod(shared, 0o720)
        self.assert_refused_nothing_written(allowed, os.path.join(shared, 'p.md'))

    def test_parent_owned_by_other_user_refused(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        sub = os.path.join(allowed, 'setup-audit-docs')
        os.mkdir(sub, 0o700)
        with mock.patch.object(fetch_doc.os, 'getuid', return_value=os.getuid() + 1):
            err = self.assert_refused_nothing_written(allowed, os.path.join(sub, 'p.md'))
        self.assertIn('owned by another user', err)

    def test_symlinked_component_inside_allowed_dir_refused(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        real = os.path.join(allowed, 'real')
        os.mkdir(real, 0o700)
        os.symlink(real, os.path.join(allowed, 'link'))
        err = self.assert_refused_nothing_written(allowed, os.path.join(allowed, 'link', 'p.md'))
        self.assertIn('not a real directory', err)
        self.assertEqual(os.listdir(real), [])

    def test_symlink_back_to_allowed_dir_used_as_prefix_refused(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        os.symlink(allowed, os.path.join(allowed, 'loop'))
        err = self.assert_refused_nothing_written(allowed, os.path.join(allowed, 'loop', 'p.md'))
        self.assertIn('through a symlink', err)
        self.assertEqual(sorted(os.listdir(allowed)), ['loop'])

    def test_allowed_root_under_symlinked_ancestor_works(self):
        # macOS-style: $TMPDIR=/var/folders/... where /var -> /private/var.
        base = tempfile.mkdtemp(prefix='fetchdoc.mac.')
        real_tmp = os.path.join(base, 'private', 'var', 'folders', 'T')
        os.makedirs(real_tmp, 0o700)
        os.symlink(os.path.join(base, 'private', 'var'), os.path.join(base, 'var'))
        tmpdir = os.path.join(base, 'var', 'folders', 'T')
        env = {'TMPDIR': tmpdir, 'CLAUDE_CONFIG_DIR': os.path.join(base, 'nocfg')}
        dest = os.path.join(tmpdir, 'setup-audit-docs', 'p.md')
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(fetch_doc.tempfile, 'gettempdir', return_value='/nonexistent-tmp'):
            code, _, err, _ = run('llms.txt', dest, response=FakeResponse(b'mac'))
        self.assertEqual(code, 0, err)
        with open(os.path.join(real_tmp, 'setup-audit-docs', 'p.md'), 'rb') as f:
            self.assertEqual(f.read(), b'mac')

    def test_out_directly_in_allowed_root_written(self):
        allowed = tempfile.mkdtemp(prefix='fetchdoc.allowed.')
        os.chmod(allowed, 0o777)  # the allowed directory itself (like /tmp) is not checked
        dest = os.path.join(allowed, 'p.md')
        with self.only_allowed(allowed):
            code, *_ = run('llms.txt', dest, response=FakeResponse(b'x'))
        self.assertEqual(code, 0)

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
        # os.open only opens directories or the O_NOFOLLOW write of OUT; no file is read
        opens = [ast.unparse(n) for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute) and n.func.attr == 'open'
                 and isinstance(n.func.value, ast.Name) and n.func.value.id == 'os']
        writes = [c for c in opens if 'O_DIRECTORY' not in c]
        self.assertEqual(len(writes), 1, opens)
        for flag in ('O_WRONLY', 'O_CREAT', 'O_NOFOLLOW'):
            self.assertIn(flag, writes[0])
        self.assertNotIn(('os', 'getenv'), attrs)

    def test_fixed_host_only(self):
        src = ast.unparse(self.tree)
        self.assertIn('https://code.claude.com/docs/', src)
        self.assertEqual(src.count('http://') + src.count('https://'), src.count('https://code.claude.com'))


if __name__ == '__main__':
    unittest.main()
