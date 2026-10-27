#!/usr/bin/env python3
"""Download one Claude Code docs page (raw text) from the fixed host code.claude.com.

    fetch_doc.py PAGE OUT

PAGE is `llms.txt` or a docs page path such as `en/settings-reference.md`. The script makes one
HTTPS GET to https://code.claude.com/docs/<PAGE> and writes the response bytes to OUT. It sends no
user data (only a fixed User-Agent, no request body), reads no local file, imports no other plugin
module and executes nothing it downloads. OUT must sit under a system temp directory, $TMPDIR or
<Claude config dir>/audits; missing parent directories of OUT inside those are created (mode 0700).
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


def _make_parent(out):
    # os.makedirs applies its mode only to the last directory, so create each missing one here.
    missing = []
    parent = os.path.dirname(os.path.abspath(out))
    while not os.path.isdir(parent):
        missing.append(parent)
        parent = os.path.dirname(parent)
    for directory in reversed(missing):
        os.mkdir(directory, 0o700)


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
        _make_parent(out)
        if not _out_is_allowed(out):
            print("refused: OUT's parent left the allowed directories while being created",
                  file=sys.stderr)
            return 1
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
    except OSError as exc:
        print(f"write failed: {exc}", file=sys.stderr)
        return 1
    print(f"wrote {out} ({len(body)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
