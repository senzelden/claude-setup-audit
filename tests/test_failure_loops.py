"""Failure loops: repeated failing cycles inside one turn, from fake transcripts. Counts only."""
import json
import re
import unittest
from unittest import mock

from test_collect import FakeHome, collect  # also puts the plugin scripts directory on sys.path
from test_plugin_footprint import observer_key
import failure_loops
import ledger

NOW = 1789473600  # 2026-09-15 12:00 UTC
TEST_CMD = "uv run pytest -q tests/test_x.py"
_n = [0]


def stamp(offset=0):
    return collect.datetime.fromtimestamp(NOW - 600 + offset, collect.timezone.utc).isoformat()


def nid():
    _n[0] += 1
    return f"t{_n[0]}"


def prompt(text="please fix it", **extra):
    return {"type": "user", "timestamp": stamp(), "message": {"content": text}, **extra}


def call(name, args, tid=None, msg=None, usage=None):
    tid = tid or nid()
    message = {"id": msg or nid(), "content": [{"type": "tool_use", "id": tid, "name": name, "input": args}]}
    if usage is not None:
        message["usage"] = usage
    return {"type": "assistant", "timestamp": stamp(1), "message": message}, tid


def result(tid, text="ok", error=False):
    item = {"type": "tool_result", "tool_use_id": tid, "content": text}
    if error:
        item["is_error"] = True
    return {"type": "user", "timestamp": stamp(2), "toolUseResult": {}, "message": {"content": [item]}}


def run(cmd, fail, text="Exit code 1\nboom"):
    c, tid = call("Bash", {"command": cmd})
    return [c, result(tid, text if fail else "ok", error=fail)]


def edit(path, name="Edit"):
    return [call(name, {"file_path": path})[0]]


def cycle(path, fail=True, cmd=TEST_CMD):
    return edit(path) + run(cmd, fail)


class Base(FakeHome):
    def transcript(self, rel, records):
        self.write(f".claude/projects/{rel}", "\n".join(map(json.dumps, records)))

    def loops(self, rel_records):
        for i, (rel, records) in enumerate(rel_records.items()):
            self.transcript(rel, records)
        with mock.patch.object(collect.time, "time", return_value=NOW):
            return collect.collect_transcripts(1)["failure_loops"]

    def one(self, records, rel="-a/s.jsonl"):
        return self.loops({rel: records})


def flat(*parts):
    return [r for p in parts for r in p]


class RepeatError(Base):
    def test_three_identical_failures_in_one_turn_is_a_loop(self):
        t = self.one([prompt()] + flat(*[run("make build", True) for _ in range(3)]))
        self.assertEqual((t["turns_scanned"], t["turns_with_loop"]), (1, 1))
        self.assertEqual((t["by_kind"], t["max_repeats"]["repeat_error"]), ({"repeat_error": 1, "edit_test": 0}, 3))
        self.assertEqual(t["command_heads"], {"make": 1})

    def test_two_failures_are_below_the_threshold(self):
        t = self.one([prompt()] + flat(*[run("make build", True) for _ in range(failure_loops.REPEAT_ERROR_MIN - 1)]))
        self.assertEqual((t["turns_with_loop"], t["max_repeats"]["repeat_error"]), (0, 0))

    def test_output_plumbing_and_prefix_do_not_make_commands_differ(self):
        cmds = ["make build", "cd /x/y && make build 2>&1", "FOO=1 make build | tail -20", "make   build  > /dev/null"]
        t = self.one([prompt()] + flat(*[run(c, True) for c in cmds]))
        self.assertEqual(t["max_repeats"]["repeat_error"], 4)

    def test_different_arguments_are_different_commands(self):
        t = self.one([prompt()] + flat(*[run(f"make build T={i}x", True) for i in range(5)]))
        self.assertEqual(t["turns_with_loop"], 0)

    def test_denials_and_successes_are_not_failures(self):
        denied = lambda: run("make build", True, "Permission to use Bash with command x has been denied.")  # noqa: E731
        t = self.one([prompt()] + flat(denied(), denied(), denied(), run("make build", False)))
        self.assertEqual(t["turns_with_loop"], 0)

    def test_a_new_real_prompt_starts_a_new_turn(self):
        t = self.one([prompt()] + run("make build", True) + run("make build", True)
                     + [prompt("again")] + run("make build", True) + run("make build", True))
        self.assertEqual((t["turns_scanned"], t["turns_with_loop"]), (2, 0))

    def test_tool_results_meta_sidechain_and_system_records_do_not_start_turns(self):
        noise = [prompt("<system-reminder>x</system-reminder>"), prompt("meta", isMeta=True),
                 prompt("side", isSidechain=True), prompt("<local-command-stdout>x</local-command-stdout>"),
                 {"type": "user", "timestamp": stamp(), "message": {"content": [{"type": "text", "text": ""}]}}]
        runs = [run("make build", True) for _ in range(3)]
        bare = dict(result("zz"), message={"content": [{"type": "tool_result", "tool_use_id": "zz", "content": "x"},
                                                              {"type": "text", "text": "tool output followed by text"}]})
        bare.pop("toolUseResult")  # a tool result is recognised by its content alone
        marked = dict(prompt("plain text"), toolUseResult={})  # and by the record marker alone
        t = self.one([prompt()] + runs[0] + noise[:2] + runs[1] + noise[2:] + [bare, marked] + runs[2])
        self.assertEqual((t["turns_scanned"], t["turns_with_loop"]), (1, 1))

    def test_duplicate_records_count_once(self):
        c, tid = call("Bash", {"command": "make build"})
        r = result(tid, error=True)
        t = self.one([prompt(), c, r, c, r] + run("make build", True))
        self.assertEqual(t["turns_with_loop"], 0)


class EditTest(Base):
    def test_three_edit_then_failing_test_cycles_on_one_file(self):
        t = self.one([prompt()] + flat(*[cycle("/r/a.py") for _ in range(3)]))
        self.assertEqual((t["by_kind"]["edit_test"], t["max_repeats"]["edit_test"]), (1, 3))
        # the same test command also failed three times: both kinds, one looping turn
        self.assertEqual((t["turns_with_loop"], t["by_kind"]["repeat_error"]), (1, 1))
        self.assertEqual(t["command_heads"], {"pytest": 2})

    def test_edit_test_loop_with_varying_test_commands_is_still_a_loop(self):
        recs = flat(*[cycle("/r/a.py", cmd=f"pytest -k case{i}") for i in range(3)])
        t = self.one([prompt()] + recs)
        self.assertEqual((t["by_kind"]["edit_test"], t["by_kind"]["repeat_error"]), (1, 0))
        self.assertEqual(t["command_heads"], {"pytest": 1})

    def test_edits_of_different_files_do_not_add_up(self):
        t = self.one([prompt()] + flat(*[cycle(f"/r/f{i}.py", cmd=f"pytest -k c{i}") for i in range(4)]))
        self.assertEqual(t["turns_with_loop"], 0)

    def test_a_passing_test_run_resets_the_file(self):
        recs = cycle("/r/a.py", cmd="pytest -k a") + cycle("/r/a.py", cmd="pytest -k b") \
            + cycle("/r/a.py", False, "pytest -k c") + cycle("/r/a.py", cmd="pytest -k d") \
            + cycle("/r/a.py", cmd="pytest -k e")
        self.assertEqual(self.one([prompt()] + recs)["turns_with_loop"], 0)

    def test_failing_non_test_command_is_not_an_edit_test_cycle(self):
        recs = flat(*[edit("/r/a.py") + run(f"make lint{i}", True) for i in range(4)])
        self.assertEqual(self.one([prompt()] + recs)["by_kind"]["edit_test"], 0)

    def test_write_and_multiedit_count_as_edits(self):
        recs = [r for name in ("Write", "MultiEdit", "Edit") for r in edit("/r/a.py", name) + run("pytest -k z" + name, True)]
        self.assertEqual(self.one([prompt()] + recs)["by_kind"]["edit_test"], 1)


class Aggregation(Base):
    def looping(self):
        return [prompt()] + flat(*[run("npm test", True) for _ in range(3)])

    def test_tokens_dedup_by_message_id_and_count_only_loop_turns(self):
        u = {"input_tokens": 10, "cache_read_input_tokens": 90, "output_tokens": 5}
        c1, t1 = call("Bash", {"command": "npm test"}, msg="m1", usage=u)
        c1b, t1b = call("Bash", {"command": "npm test"}, msg="m1", usage=u)  # same response, second line
        c2, t2 = call("Bash", {"command": "npm test"}, msg="m2", usage=u)
        calm, _ = call("Read", {}, msg="m3", usage={"input_tokens": 1000})
        side = dict(calm, isSidechain=True)
        quiet = [prompt("q"), calm]
        t = self.one([prompt(), c1, result(t1, error=True), c1b, result(t1b, error=True), c2, result(t2, error=True),
                      side] + quiet)
        self.assertEqual((t["turns_scanned"], t["turns_with_loop"]), (2, 1))
        self.assertEqual(t["tokens_in_loop_turns"], 2 * 105)
        self.assertEqual(t["tokens_scanned"], 2 * 105 + 1000)

    def test_per_project_counts_and_head_vocabulary(self):
        t = self.loops({"-a/s.jsonl": self.looping(), "-a/s2.jsonl": self.looping() + [prompt("x")],
                        "-b/s.jsonl": [prompt()] + run("npm test", True)})
        self.assertEqual(t["by_project"], {"-a": {"turns": 3, "loop_turns": 2, "tokens": 0}})
        self.assertEqual((t["sessions_scanned"], t["sessions_with_loop"]), (3, 2))
        self.assertEqual(t["command_heads"], {"npm": 2})

    def test_odd_command_heads_collapse_to_other_and_text_is_not_stored(self):
        secret = "ZZ-Sentinel_9f3a2"
        recs = flat(*[run(f"./Scripts/{secret}.sh", True) for _ in range(3)]
                    + [edit(f"/r/{secret}.py") + run("pytest " + secret, True) for _ in range(3)])
        t = self.one([prompt()] + recs)
        self.assertEqual(t["command_heads"], {"other": 1, "pytest": 2})  # one per looping kind
        self.assertNotIn(secret, json.dumps(t))
        self.assertNotIn("/r/", json.dumps(t))

    def test_plugin_spawned_sessions_are_excluded(self):
        t = self.loops({"-a/s.jsonl": self.looping(), observer_key(self) + "/o1.jsonl": self.looping()})
        self.assertEqual((t["sessions_scanned"], t["turns_with_loop"]), (1, 1))

    def test_subagent_files_are_not_turns(self):
        t = self.loops({"-a/s/subagents/agent-1.jsonl": self.looping()})
        self.assertEqual(t["turns_scanned"], 0)

    def test_records_outside_the_window_are_not_scanned(self):
        old = [dict(r, timestamp=collect.datetime.fromtimestamp(NOW - 40 * 86400, collect.timezone.utc).isoformat())
               for r in self.looping()]
        self.assertEqual(self.one(old)["turns_scanned"], 0)

    def test_empty_home_has_a_zero_block(self):
        with mock.patch.object(collect.time, "time", return_value=NOW):
            t = collect.collect_transcripts(1)["failure_loops"]
        self.assertEqual((t["turns_scanned"], t["by_project"], t["command_heads"]), (0, {}, {}))


class LedgerSelector(Base):
    def selector(self, kind="any"):
        return {"type": "failure_loops", "kind": kind}

    def test_selector_validation(self):
        ledger.validate_selector(self.selector("edit_test"))
        for bad in ({"type": "failure_loops"}, self.selector("nope"), dict(self.selector(), extra=1)):
            with self.assertRaises(ledger.LedgerError):
                ledger.validate_selector(bad)

    def count(self, kind, **kw):
        with mock.patch.object(collect.time, "time", return_value=NOW):
            return collect.count_selector(self.selector(kind), NOW - 3600, NOW, kw.get("filter"))

    def plant(self):
        self.transcript("-a/loop.jsonl", [prompt()] + flat(*[cycle("/r/a.py", cmd=f"pytest -k c{i}") for i in range(3)])
                        + [prompt("ok")])
        self.transcript("-a/quiet.jsonl", [prompt()] + run("make build", False))
        self.transcript("-b/rep.jsonl", [prompt()] + flat(*[run("make build", True) for _ in range(4)]))
        self.transcript(observer_key(self) + "/o.jsonl", [prompt()] + flat(*[run("make build", True) for _ in range(4)]))

    def test_counts_looping_turns_and_sessions_by_kind(self):
        self.plant()
        any_ = self.count("any")
        self.assertEqual((any_["matches"], any_["sessions_matched"], any_["sessions_scanned"], any_["complete"]),
                         (2, 2, 3, True))
        self.assertEqual((self.count("edit_test")["matches"], self.count("repeat_error")["matches"]), (1, 1))

    def test_project_filter_and_bounds(self):
        self.plant()
        self.assertEqual(self.count("any", filter={"/a"})["sessions_scanned"], 2)
        self.assertEqual(self.count("any", filter=set())["sessions_scanned"], 0)
        with mock.patch.object(collect.time, "time", return_value=NOW):
            c = collect.count_selector(self.selector(), NOW + 1, NOW + 2, None)
        self.assertEqual(c["sessions_scanned"], 0)

    def test_unreadable_lines_mark_counts_incomplete(self):
        self.plant()
        self.write(".claude/projects/-c/bad.jsonl", "{not json\n")
        self.assertFalse(self.count("any")["complete"])


class Normalizer(unittest.TestCase):
    def test_head_is_a_strict_identifier(self):
        rx = collect.TEST_CMD_RE
        for text, want in (("npm run test", "npm"), ("python3 -m pytest x", "pytest"), ("./x/Bin.sh a", "other"),
                           ("deploy-prod.sh a", "other"), ("python3.12 x.py", "python3.12"), ("/usr/bin/make", "other"),
                           ("cargo test", "cargo"), ("go test ./...", "go"), ("", "other")):
            self.assertEqual(failure_loops.command_head(failure_loops.normalize_command(text), rx), want, text)


if __name__ == "__main__":
    unittest.main()
