"""Tool usage and MCP connection failures from main-thread transcripts (0.12.0). Stdlib only.

Reads `deferred_tools_delta` attachments (observed, undocumented; see references/coverage.md) and
assistant `tool_use` names. Names and counts only: the server `error` text is never read into the
result and an `errorCode` survives only when it matches a strict vocabulary pattern.
"""
import re
from collections import Counter

ROW_CAP = 40
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@\- ]{0,119}\Z")
CODE_RE = re.compile(r"[A-Z][A-Z0-9_]{1,39}\Z")
BASIS = ("Counts of main-thread sessions in the window (plugin-spawned sessions excluded). A tool is 'used' when an "
         "assistant tool_use carries its name. 'Listed' means a deferred_tools_delta attachment added, re-added or "
         "surfaced it (observed, undocumented record). Always-loaded built-in tools are not listed in transcripts, so "
         "their use is counted but their absence of use is not observable. A deferred tool costs about one listing "
         "line until used, so pruning unused ones saves little.")
FAILURE_BASIS = ("Sessions whose deferred_tools_delta attachments name the server in failedMcpServers or "
                 "pendingMcpServers (observed, undocumented). errorCode classes are counted per session; the error "
                 "text is never stored. Sessions without such records say nothing about connection health.")


def _name(value):
    return value if isinstance(value, str) and NAME_RE.match(value) else None


def _names(value):
    return {n for n in (_name(v) for v in value) if n} if isinstance(value, list) else set()


class Session:
    """Per-transcript-file facts, merged into Totals only for main-thread, non-spawned sessions."""

    def __init__(self):
        self.used, self.listed = set(), set()
        self.failed, self.pending = set(), set()
        self.codes = set()  # (server, code)
        self.deferred = False

    def record(self, record):
        if record.get("type") == "attachment":
            att = record.get("attachment")
            if isinstance(att, dict) and att.get("type") == "deferred_tools_delta":
                self.delta(att)
        elif record.get("type") == "assistant":
            content = (record.get("message") or {}).get("content", record.get("content", []))
            for item in content if isinstance(content, list) else []:
                if isinstance(item, dict) and item.get("type") == "tool_use":
                    name = _name(item.get("name"))
                    if name:
                        self.used.add(name)

    def delta(self, att):
        self.deferred = True
        for key in ("addedNames", "readdedNames", "surfacedNames"):
            self.listed |= _names(att.get(key))
        self.pending |= _names(att.get("pendingMcpServers"))
        failed = att.get("failedMcpServers")
        for entry in failed if isinstance(failed, list) else []:
            server = _name(entry.get("name")) if isinstance(entry, dict) else None
            if server is None:
                continue
            self.failed.add(server)
            code = entry.get("errorCode")
            self.codes.add((server, code if isinstance(code, str) and CODE_RE.match(code) else "other"))


class Totals:
    def __init__(self):
        self.sessions = self.with_deferred = 0
        self.used, self.listed = Counter(), Counter()
        self.failed, self.pending, self.codes = Counter(), Counter(), Counter()
        self.ever_used = set()

    def add(self, s):
        self.sessions += 1
        self.used.update(s.used)
        self.ever_used |= s.used
        if s.deferred:
            self.with_deferred += 1
            self.listed.update(s.listed)
            self.failed.update(s.failed)
            self.pending.update(s.pending)
            self.codes.update(s.codes)

    def usage(self):
        used = sorted(self.used.items(), key=lambda kv: (-kv[1], kv[0]))
        never = sorted(((n, c) for n, c in self.listed.items() if n not in self.ever_used),
                       key=lambda kv: (-kv[1], kv[0]))
        return {"sessions": self.sessions, "sessions_with_deferred_records": self.with_deferred,
                "used": [{"tool": n, "sessions": c} for n, c in used[:ROW_CAP]],
                "used_omitted": max(0, len(used) - ROW_CAP),
                "listed_never_called": [{"tool": n, "sessions_listed": c} for n, c in never[:ROW_CAP]],
                "listed_never_called_total": len(never),
                "listed_never_called_omitted": max(0, len(never) - ROW_CAP),
                "basis": BASIS}

    def failures(self, configured=None):
        """configured: set of configured MCP server names, or None when unknown."""
        servers = sorted(set(self.failed) | set(self.pending),
                         key=lambda n: (-self.failed[n], -self.pending[n], n))
        rows = [{"server": n, "sessions_failed": self.failed[n], "sessions_pending": self.pending[n],
                 "error_codes": [{"code": c, "sessions": k} for (srv, c), k in
                                 sorted(self.codes.items(), key=lambda kv: (-kv[1], kv[0][1])) if srv == n],
                 **({} if configured is None else {"configured": n in configured})}
                for n in servers[:ROW_CAP]]
        return {"sessions_observed": self.with_deferred, "servers": rows,
                "servers_omitted": max(0, len(servers) - ROW_CAP), "basis": FAILURE_BASIS}
