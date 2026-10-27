#!/usr/bin/env python3
"""Download one Claude Code docs page (raw text) from the fixed host code.claude.com.

    fetch_doc.py PAGE OUT

PAGE is `llms.txt` or a docs page path such as `en/settings-reference.md`. The script makes one
HTTPS GET to https://code.claude.com/docs/<PAGE> and writes the response bytes to OUT. It sends no
user data (only a fixed User-Agent, no request body), reads no local file, imports no other plugin
module and executes nothing it downloads. OUT must sit under a system temp directory, $TMPDIR or
<Claude config dir>/audits; missing parent directories of OUT inside those are created (mode 0700).
Every directory between the allowed directory and OUT must be a real directory (no symlink) owned
by the current user and not group- or other-writable, otherwise nothing is written.
Exit 0 on success, 2 on bad arguments, 1 on fetch or write failure.
"""
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://code.claude.com/docs/"
HOST = "code.claude.com"
PAGE_RE = re.compile(r"^(llms\.txt|en/[a-z0-9][a-z0-9/-]*\.md)$")
MAX_BYTES = 5 * 1024 * 1024
TIMEOUT = 20


class _SameHostOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_docs_url(newurl):
            raise urllib.error.URLError(f"redirect away from {HOST} refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _is_docs_url(url):
    parts = urllib.parse.urlsplit(url)
    return parts.scheme == "https" and parts.hostname == HOST


def _open(request):
    return urllib.request.build_opener(_SameHostOnly).open(request, timeout=TIMEOUT)


def _allowed_dirs():
    config = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.join(os.path.expanduser("~"), ".claude")
    dirs = {os.path.realpath(tempfile.gettempdir()), os.path.realpath(os.path.join(config, "audits"))}
    if os.environ.get("TMPDIR"):
        dirs.add(os.path.realpath(os.environ["TMPDIR"]))
    return dirs


def _out_is_allowed(out):
    # realpath resolves symlinks in the existing part of the path, so a missing parent is judged
    # by where it would be created.
    parent = os.path.realpath(os.path.dirname(os.path.abspath(out)))
    return any(parent == d or parent.startswith(d + os.sep) for d in _allowed_dirs())


class _Refused(Exception):
    pass


def _allowed_root(parent):
    """Split PARENT into (prefix, remaining names) at the deepest prefix that is an allowed dir."""
    allowed = _allowed_dirs()
    names = []
    prefix = parent
    while True:
        real = os.path.realpath(prefix)
        if real in allowed:
            return prefix, real, list(reversed(names))
        head, name = os.path.split(prefix)
        if head == prefix:
            raise _Refused("OUT is not under an allowed directory")
        names.append(name)
        prefix = head


def _open_parent(out):
    """Return a descriptor for OUT's parent, walked and created one directory at a time.

    Each step opens the next directory relative to the previous descriptor with O_NOFOLLOW and
    checks the opened directory itself, so a path swapped by another user after a check is not the
    one written to.
    """
    prefix, real, names = _allowed_root(os.path.dirname(os.path.abspath(out)))
    fd = os.open(prefix, os.O_RDONLY | os.O_DIRECTORY)
    try:
        root, expected = os.fstat(fd), os.stat(real)
        if (root.st_dev, root.st_ino) != (expected.st_dev, expected.st_ino):
            raise _Refused(f"{prefix} changed while being opened")
        for name in names:
            try:
                os.mkdir(name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as exc:
                raise _Refused(f"{name}: not a real directory ({exc.strerror})") from None
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != os.getuid():
                raise _Refused(f"{name}: owned by another user")
            if info.st_mode & 0o022:
                raise _Refused(f"{name}: writable by group or others")
    except BaseException:
        os.close(fd)
        raise
    return fd


def main(argv):
    if len(argv) != 2 or not PAGE_RE.match(argv[0]):
        print("usage: fetch_doc.py PAGE OUT   (PAGE: llms.txt or en/<name>.md)", file=sys.stderr)
        return 2
    page, out = argv
    if not _out_is_allowed(out):
        print("OUT must be under a system temp directory, $TMPDIR or <Claude config dir>/audits",
              file=sys.stderr)
        return 2
    request = urllib.request.Request(BASE + page, headers={"User-Agent": "setup-audit-fetch-doc"})
    try:
        with _open(request) as response:
            if not _is_docs_url(response.geturl()):
                print(f"refused: final URL is not on {HOST}", file=sys.stderr)
                return 1
            body = response.read(MAX_BYTES + 1)
    except (urllib.error.URLError, OSError) as exc:
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 1
    if len(body) > MAX_BYTES:
        print(f"refused: response larger than {MAX_BYTES} bytes", file=sys.stderr)
        return 1
    try:
        parent_fd = _open_parent(out)
        try:
            fd = os.open(os.path.basename(out), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
    except _Refused as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"write failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
