"""Files inside an audited repo are untrusted: the collector must not follow symlinks out of the
repo, block on a FIFO, read without bound, or crash on an unexpected JSON shape. Stdlib only.
"""
import json
import os
import sys
import tempfile
import threading
import unittest

sys.dont_write_bytecode = True
SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "plugins", "setup-audit", "skills", "setup-audit", "scripts")
sys.path.insert(0, os.path.abspath(SCRIPTS))

import collect  # noqa: E402


def finishes(fn, timeout=5):
    """Run fn in a daemon thread; (finished, result). A blocked open/read never finishes."""
    box = {}
    t = threading.Thread(target=lambda: box.update(result=fn()), daemon=True)
    t.start()
    t.join(timeout)
    return not t.is_alive(), box.get("result")


class UntrustedRepoReads(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = os.path.realpath(self.tmp.name)
        self.repo = os.path.join(self.base, "repo")
        self.outside = os.path.join(self.base, "outside")
        os.makedirs(self.repo)
        os.makedirs(self.outside)

    def tearDown(self):
        self.tmp.cleanup()

    def put(self, path, text):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def mcp_servers(self):
        return next(iter(collect.collect_projects([self.repo]).values()), {}).get("mcp_servers")

    # .mcp.json in collect_projects
    def test_mcp_json_symlink_out_of_repo_is_not_followed(self):
        target = os.path.join(self.outside, "servers.json")
        self.put(target, json.dumps({"mcpServers": {"OUTSIDE_SERVER": {}}}))
        os.symlink(target, os.path.join(self.repo, ".mcp.json"))
        self.assertFalse(self.mcp_servers())

    def test_mcp_json_fifo_does_not_hang(self):
        os.mkfifo(os.path.join(self.repo, ".mcp.json"))
        done, servers = finishes(self.mcp_servers)
        self.assertTrue(done, "collect_projects blocked on a FIFO .mcp.json")
        self.assertFalse(servers)

    def test_mcp_servers_not_an_object_does_not_crash(self):
        self.put(os.path.join(self.repo, ".mcp.json"), json.dumps({"mcpServers": ["a", "b"]}))
        self.assertFalse(self.mcp_servers())

    def test_mcp_json_top_level_not_an_object_does_not_crash(self):
        self.put(os.path.join(self.repo, ".mcp.json"), json.dumps(["x"]))
        self.assertFalse(self.mcp_servers())

    def test_oversized_mcp_json_is_not_parsed(self):
        big = {"mcpServers": {"BIG": {}}, "pad": "x" * (collect.UNTRUSTED_JSON_LIMIT + 10)}
        self.put(os.path.join(self.repo, ".mcp.json"), json.dumps(big))
        self.assertFalse(self.mcp_servers())

    def test_regular_mcp_json_still_lists_servers(self):
        self.put(os.path.join(self.repo, ".mcp.json"), json.dumps({"mcpServers": {"b": {}, "a": {}}}))
        self.assertEqual(self.mcp_servers(), ["a", "b"])

    # _read in env_declarations / readiness
    def test_symlinked_mise_toml_is_not_read(self):
        target = os.path.join(self.outside, "mise.toml")
        self.put(target, "[env]\nOUTSIDE_NAME = \"x\"\n")
        os.symlink(target, os.path.join(self.repo, "mise.toml"))
        declared, sources = collect.env_declarations(self.repo)
        self.assertNotIn("OUTSIDE_NAME", declared)
        self.assertNotIn("mise.toml", sources)

    def test_file_under_symlinked_directory_is_not_read(self):
        self.put(os.path.join(self.outside, "dc", "devcontainer.json"),
                 json.dumps({"containerEnv": {"OUTSIDE_NAME": "x"}}))
        os.symlink(os.path.join(self.outside, "dc"), os.path.join(self.repo, ".devcontainer"))
        declared, _ = collect.env_declarations(self.repo)
        self.assertNotIn("OUTSIDE_NAME", declared)

    def test_fifo_compose_file_does_not_hang(self):
        os.mkfifo(os.path.join(self.repo, "docker-compose.yml"))
        done, result = finishes(lambda: collect.env_declarations(self.repo))
        self.assertTrue(done, "env_declarations blocked on a FIFO compose file")
        self.assertNotIn("docker-compose.yml", result[1])

    def test_regular_files_are_still_read(self):
        self.put(os.path.join(self.repo, "mise.toml"), "[env]\nMISE_NAME = \"x\"\n")
        self.put(os.path.join(self.repo, ".devcontainer", "devcontainer.json"),
                 json.dumps({"containerEnv": {"DC_NAME": "x"}}))
        self.put(os.path.join(self.repo, "compose.yaml"), "services:\n  a:\n    environment:\n      - COMPOSE_NAME=1\n")
        declared, sources = collect.env_declarations(self.repo)
        self.assertTrue({"MISE_NAME", "DC_NAME", "COMPOSE_NAME"} <= declared)
        self.assertIn("compose.yaml", sources)

    def test_read_is_bounded(self):
        self.put(os.path.join(self.repo, "pyproject.toml"), "x" * 300_000)
        self.assertEqual(len(collect._read(self.repo, "pyproject.toml")), 200_000)

    def test_readiness_ignores_symlinked_package_json(self):
        target = os.path.join(self.outside, "package.json")
        self.put(target, json.dumps({"scripts": {"test": "OUTSIDE_SCRIPT"}}))
        os.symlink(target, os.path.join(self.repo, "package.json"))
        done, _ = finishes(lambda: collect.readiness(self.repo))
        self.assertTrue(done)
        self.assertEqual(collect._read_json_object(self.repo, "package.json"), {})

    def test_readiness_fifo_package_json_does_not_hang(self):
        os.mkfifo(os.path.join(self.repo, "package.json"))
        done, _ = finishes(lambda: collect.readiness(self.repo))
        self.assertTrue(done, "readiness blocked on a FIFO package.json")


if __name__ == "__main__":
    unittest.main()
