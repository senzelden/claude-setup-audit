"""Unit tests for the setup-audit collector and permission pruner. Stdlib only.

Run from the repo root:  python3 -m unittest discover -s tests -v
All tests use a temporary fake home, never the real ~/.claude.
"""
import json
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "plugins", "setup-audit", "skills", "setup-audit", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import collect  # noqa: E402
import prune_permissions  # noqa: E402


def flags(rule):
    return {name for name, rx in collect.RISKY_RULES if rx.search(rule)}


class FakeHome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        self.claude = os.path.join(self.home, ".claude")
        os.makedirs(os.path.join(self.claude, "projects"))
        self._saved = (collect.HOME, collect.CLAUDE)
        collect.HOME, collect.CLAUDE = self.home, self.claude

    def tearDown(self):
        collect.HOME, collect.CLAUDE = self._saved
        self.tmp.cleanup()

    def write(self, rel, content):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content if isinstance(content, str) else json.dumps(content))
        return path


class RiskClassification(unittest.TestCase):
    def test_broad_rules_are_flagged(self):
        self.assertIn("network-wildcard", flags("Bash(curl:*)"))
        self.assertIn("interpreter-wildcard", flags("Bash(python3:*)"))
        self.assertIn("sudo", flags("Bash(sudo apt install -y ffmpeg)"))
        self.assertIn("read-outside-project", flags("Read(//proc/**)"))

    def test_narrow_rules_are_not_flagged(self):
        self.assertEqual(flags("Bash(uv run pytest tests/test_ids.py)"), set())
        self.assertEqual(flags("Bash(git status)"), set())

    def test_literal_secret_vs_env_reference(self):
        self.assertIn("secret-literal-in-rule", flags("Bash(curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuv' x)"))
        env_ref = "Bash(curl -H \"Authorization: Token $(grep COURTLISTENER_TOKEN .env)\" x)"
        self.assertIn("secret-via-env-file", flags(env_ref))
        self.assertNotIn("secret-literal-in-rule", flags(env_ref))
        # Masking a .env file is not a secret leak.
        self.assertNotIn("secret-via-env-file", flags("Bash(sed 's/=.*/=<set>/' .env)"))

    def test_redaction_hides_values(self):
        out = collect.redact("api_key=sk-THISISASECRETVALUE123456")
        self.assertNotIn("THISISASECRETVALUE", out)


class OneOffRules(unittest.TestCase):
    def test_one_off_detection(self):
        self.assertTrue(prune_permissions.is_one_off("Bash(kill 94266)"))
        self.assertTrue(prune_permissions.is_one_off("Bash(tee /tmp/full-run.log)"))
        self.assertFalse(prune_permissions.is_one_off("Bash(uv run *)"))
        self.assertFalse(prune_permissions.is_one_off("Bash(curl -sf http://127.0.0.1:8000/healthz)"))


class DeadReferences(FakeHome):
    def test_only_real_dead_paths_are_reported(self):
        repo = os.path.join(self.home, "repo")
        os.makedirs(os.path.join(repo, "docs"))
        os.makedirs(os.path.join(repo, "src", "pkg"))
        open(os.path.join(repo, "docs", "exists.md"), "w").close()
        md = self.write("repo/CLAUDE.md", "\n".join([
            "See `docs/exists.md` and `docs/missing.md`.",   # one real, one dead
            "Ratio `D/A`, repo `owner/project`.",            # not paths
            "Template `docs/NN-name.md`, prefix `src/022`.", # placeholder, prefix
        ]))
        self.assertEqual(collect.dead_references(md, repo), ["docs/missing.md"])


class HookScripts(FakeHome):
    def test_missing_script_detected_and_project_dir_expanded(self):
        proj = os.path.join(self.home, "proj")
        self.write("proj/.claude/hooks/ok.sh", "#!/bin/sh\n")
        cmds = ["${CLAUDE_PROJECT_DIR}/.claude/hooks/ok.sh", "python3 ${CLAUDE_PROJECT_DIR}/.claude/hooks/gone.py",
                "${CLAUDE_PLUGIN_ROOT}/x.sh", "echo hi"]
        missing = collect.missing_hook_scripts(cmds, proj)
        self.assertEqual(len(missing), 1)
        self.assertIn("gone.py", missing[0])


class Transcripts(FakeHome):
    def test_baseline_and_mcp_counts(self):
        records = [
            {"type": "user", "cwd": "/x", "message": {"content": "hi"}},
            {"type": "assistant", "isSidechain": True, "message": {"usage": {"input_tokens": 1}}},
            {"type": "assistant", "message": {"usage": {"input_tokens": 10, "cache_creation_input_tokens": 20000,
                                                        "cache_read_input_tokens": 5000}},
             "content": [{"type": "tool_use", "name": "mcp__github__create_issue"}]},
            {"type": "assistant", "message": {"usage": {"input_tokens": 99999}}},
        ]
        for i in range(3):
            self.write(f".claude/projects/-p/s{i}.jsonl", "\n".join(json.dumps(r) for r in records))
        t = collect.collect_transcripts(days=30)
        self.assertEqual(t["sessions_measured"], 3)
        self.assertEqual(t["context_baseline_tokens"]["median"], 25010)  # first main-thread turn only
        self.assertEqual(dict(t["mcp_calls_by_server"]), {"github": 3})
        self.assertEqual(t["context_baseline_by_project_median"][0][0], "-p")


class ProjectDiscovery(FakeHome):
    def test_discovers_existing_cwds_and_skips_home(self):
        real = os.path.join(self.home, "work", "app")
        os.makedirs(real)
        self.write(".claude/projects/-a/s.jsonl", json.dumps({"type": "user", "cwd": real}))
        self.write(".claude/projects/-b/s.jsonl", json.dumps({"type": "user", "cwd": "/does/not/exist"}))
        self.write(".claude/projects/-c/s.jsonl", json.dumps({"type": "user", "cwd": self.home}))
        self.assertEqual(collect.discover_projects(), [real])


class PrunePlan(FakeHome):
    def test_plan_is_dry_and_selective(self):
        path = self.write("proj/.claude/settings.local.json", {"permissions": {
            "allow": ["Bash(sudo -n true)", "Bash(uv run *)", "Bash(kill 94266)"],
            "additionalDirectories": ["/nonexistent/dir"]}})
        def read():
            with open(path) as f:
                return f.read()

        before = read()
        _, removals, dirs = prune_permissions.plan_file(path, {"sudo", "stale-dirs"})
        self.assertEqual([r["_raw"] for r in removals], ["Bash(sudo -n true)"])
        self.assertEqual(dirs, ["/nonexistent/dir"])
        self.assertEqual(read(), before)


class EnvContract(FakeHome):
    def test_envrc_pointers_count_as_declarations(self):
        self.write("repo/.envrc", "use_pass ANTHROPIC_API_KEY api/anthropic; use_pass_optional HF_TOKEN api/hf\nexport LOG_LEVEL=info\n")
        self.write("repo/src/app.py", "import os\nkey = os.environ['ANTHROPIC_API_KEY']\nhf = os.getenv('HF_TOKEN')\n"
                                      "lvl = os.getenv('LOG_LEVEL')\nurl = os.environ['DATABASE_URL']\nh = os.getenv('HOME')\n"
                                      "cache = os.getenv('CACHE_DIR', '/tmp/c')\nregion = os.getenv('REGION')\n")
        self.write("repo/tests/browser/run.mjs", "const base = process.env.BASE\n")
        c = collect.env_contract(os.path.join(self.home, "repo"))
        self.assertEqual(c["declared_via"], [".envrc"])
        kinds = {u["name"]: u["kind"] for u in c["undeclared"]}  # HOME ignored; both use_pass calls on one line declared
        self.assertEqual(kinds, {"DATABASE_URL": "required", "REGION": "read", "CACHE_DIR": "optional", "BASE": "test-only"})
        self.assertEqual(c["undeclared"][0]["name"], "DATABASE_URL")

    def test_other_mechanisms_and_validation(self):
        self.write("repo/.env.example", "API_URL=\n")
        self.write("repo/mise.toml", "[tools]\nnode = '22'\n[env]\nFEATURE_X = '1'\n")
        self.write("repo/settings.py", "from pydantic_settings import BaseSettings\nclass S(BaseSettings):\n    redis_url: str\n")
        self.write("repo/web/env.ts", "import { z } from 'zod'\nconst s = z.object({})\nprocess.env.API_URL; process.env.FEATURE_X; process.env.REDIS_URL\n")
        c = collect.env_contract(os.path.join(self.home, "repo"))
        self.assertEqual(c["undeclared"], [])
        self.assertEqual(c["validation"], ["pydantic-settings", "zod"])

    def test_envrc_literal_secret_reports_names_only(self):
        self.write("repo/.envrc", "export OPENAI_API_KEY=sk-abcdefghijklmnopqrstu\nexport HF_TOKEN=$(pass show api/hf)\n")
        info = collect.envrc_info(os.path.join(self.home, "repo"))
        self.assertEqual(info["literal_secret_names"], ["OPENAI_API_KEY"])
        self.assertNotIn("sk-abc", json.dumps(info))


class ReadinessSignals(FakeHome):
    def test_setup_and_guardrails_detected(self):
        self.write("repo/Makefile", "setup:\n\tuv sync\ntest:\n\tuv run pytest\n")
        self.write("repo/.pre-commit-config.yaml", "repos: []\n")
        self.write("repo/pyproject.toml", "[tool.ruff]\nline-length = 100\n[tool.mypy]\nstrict = true\n")
        self.write("repo/docs/adr/0001-use-sqlite.md", "# ADR\n")
        r = collect.readiness(os.path.join(self.home, "repo"))
        self.assertEqual(r["setup_entrypoints"], ["make setup"])
        self.assertEqual(r["precommit"], [".pre-commit-config.yaml"])
        self.assertIn("ruff (pyproject)", r["formatter_config"])
        self.assertTrue(r["type_strictness"]["mypy_strict"])
        self.assertEqual(r["adr"], {"docs/adr": 1})


class TranscriptEvidence(FakeHome):
    def test_test_durations_and_env_errors(self):
        records = [
            {"type": "assistant", "timestamp": "2026-09-14T10:00:00.000Z", "message": {"content": [
                {"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "uv run pytest -q"}}]}},
            {"type": "user", "timestamp": "2026-09-14T10:00:42.500Z", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "KeyError: 'DATABASE_URL'"}]}},
        ]
        self.write(".claude/projects/-home-x-repo/s.jsonl", "\n".join(json.dumps(r) for r in records))
        t = collect.collect_transcripts(days=36500)
        self.assertEqual(t["test_run_seconds_by_project"]["-home-x-repo"]["median"], 42.5)
        self.assertEqual(t["env_error_hits_by_project"], {"-home-x-repo": 1})


class QuerySnapshot(FakeHome):
    def run_query(self, *args):
        import subprocess
        script = os.path.join(os.path.abspath(SCRIPTS), "query_snapshot.py")
        return subprocess.run([sys.executable, "-B", script, *args], capture_output=True, text=True)

    def test_select_keys_index_and_truncate(self):
        snap = self.write("snap.json", {"readiness": {"~/code/app": {"env": {"undeclared": [{"name": "A"}, {"name": "B"}]}}},
                                        "usage": {"big": "x" * 500}})
        self.assertIn("readiness", self.run_query(snap).stdout)
        self.assertEqual(json.loads(self.run_query(snap, "readiness", "--keys").stdout), ["~/code/app"])
        out = self.run_query(snap, "readiness", "~/code/app", "env", "undeclared", "1")
        self.assertEqual(json.loads(out.stdout), {"name": "B"})
        self.assertIn("truncated", self.run_query(snap, "usage", "--max-chars", "100").stdout)
        missing = self.run_query(snap, "readiness", "nope")
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("available", missing.stderr)


if __name__ == "__main__":
    unittest.main()
