# Development checks

Run from the repository root:

```sh
python3 -m unittest discover -s tests -v
git diff --check
```

The regression suite uses the Python standard library and temporary fake homes. It includes
CLI fixtures, hostile-input/redaction cases, mutation safeguards, snapshot contract checks and
report processing/rendering. It does not run paid model evaluations.

CI runs that suite on Linux and macOS with Python 3.11, 3.13 and 3.14. It additionally installs
`jsonschema==4.26.0` to independently validate the bundled snapshot schema and fixture outputs:

```sh
python3 tests/check_snapshot_schema.py -v
```

Install that dependency in a virtual environment for this optional local check. The plugin and
normal regression suite have no new runtime dependency. The schema check reuses the fake-home
collector fixture, exercises all scopes with/without the clarity pilot, and checks structural
regressions against both validators. Cross-field scope consistency is an additional runtime
invariant, beyond the JSON Schema.

A separate Linux CI job installs Claude Code **2.1.273**, disables automatic updates, and runs
these commands with a temporary home/config directory and no account credentials:

```sh
claude plugin validate . --strict
claude plugin validate plugins/setup-audit --strict
```

Keep the CLI pin explicit and update it after local verification. This job checks marketplace
and plugin manifests; it makes no model calls and does not test runtime audit behavior.
On the locally verified 2.1.273 build, direct skill-directory validation reports a missing
manifest despite broader support described in the CLI help/docs. Do not count that as skill
validation coverage; recheck when updating the pin.
Passing macOS CI does not establish complete macOS integration or Windows support.

Version-sensitive commands checked 2026-09-16 against the installed CLI help and official
[plugin validation reference](https://code.claude.com/docs/en/plugins-reference) and
[versioned native installation instructions](https://code.claude.com/docs/en/setup#install-a-specific-version).

Paid trigger/quality evaluations are separate; see
[evals/README.md](../plugins/setup-audit/evals/README.md).

The manually triggered `runner-preflight.yml` workflow checks Linux namespace and macOS
Seatbelt prerequisites without installing Claude or using model credentials. It is diagnostic,
separate from the normal validation gate, and cannot certify eval-runner compatibility. See
[unpaid runner preflight](../plugins/setup-audit/evals/README.md#unpaid-runner-preflight)
for local usage and coverage limits.
