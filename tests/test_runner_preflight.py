"""No model calls or host policy changes; subprocesses use temporary fake homes."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HELPER = (Path(__file__).resolve().parents[1]
          / 'plugins/setup-audit/evals/helpers/runner_preflight.py')
spec = importlib.util.spec_from_file_location('runner_preflight', HELPER)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)


class RunnerPreflight(unittest.TestCase):
    def test_subprocess_has_no_credentials_or_startup_environment(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
                'os.environ', {'ANTHROPIC_API_KEY': 'fake', 'BASH_ENV': '/bad',
                               'ENV': '/bad', 'LD_PRELOAD': '/bad'}):
            result = preflight.probe('environment', ['/bin/sh', '-c',
                'test -z "$ANTHROPIC_API_KEY$BASH_ENV$ENV$LD_PRELOAD" '
                '&& test "$HOME" = "$PWD" && printf preflight-command-ran'], Path(temp))
        self.assertTrue(result['passed'], result)

    def test_zero_exit_without_execution_marker_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            result = preflight.probe('empty', ['/bin/sh', '-c', ':'], Path(temp))
        self.assertFalse(result['passed'])

    def test_errors_and_timeouts_fail_closed(self):
        for error in (FileNotFoundError(), PermissionError(),
                      subprocess.TimeoutExpired(['probe'], 10)):
            with self.subTest(error=type(error).__name__), mock.patch.object(
                    preflight.subprocess, 'run', side_effect=error):
                result = preflight.probe('error', ['probe'], Path('/tmp'))
                self.assertFalse(result['passed'])

    def test_successful_prerequisites_never_certify_runner(self):
        with mock.patch.object(preflight.platform, 'system', return_value='Linux'), \
             mock.patch.object(preflight, 'linux_probes', return_value=[{'passed': True}]):
            result = preflight.collect('test-context')
        self.assertTrue(result['prerequisite_checks_passed'])
        self.assertFalse(result['eval_runner_verified'])
        self.assertEqual(result['execution_context'], 'test-context')

    def test_missing_unsupported_and_failed_probes_do_not_pass(self):
        for system, probes in [('Windows', []), ('Linux', []),
                               ('Linux', [{'passed': True}, {'passed': False}])]:
            with self.subTest(system=system, probes=probes), \
                 mock.patch.object(preflight.platform, 'system', return_value=system), \
                 mock.patch.object(preflight, 'linux_probes', return_value=probes):
                self.assertFalse(preflight.collect('test')['prerequisite_checks_passed'])
        with mock.patch.object(preflight.shutil, 'which', return_value=None):
            self.assertFalse(preflight.linux_probes(Path('/tmp'))[0]['passed'])

    def test_macos_denied_write_requires_shell_execution_and_absent_artifact(self):
        for startup_failed, write_escaped in [(True, False), (False, True), (False, False)]:
            with self.subTest(startup_failed=startup_failed, write_escaped=write_escaped), \
                 tempfile.TemporaryDirectory() as temp:
                root = Path(temp)

                def fake_probe(name, argv, directory):
                    if name == 'seatbelt_allowed_write':
                        (directory / 'allowed/marker').write_text(preflight.MARKER)
                        return {'passed': True}
                    if write_escaped:
                        (directory / 'denied-marker').write_text('blocked')
                    return {'passed': not startup_failed}

                with mock.patch.object(preflight, 'probe', side_effect=fake_probe):
                    checks = preflight.macos_probes(root)
                self.assertEqual(checks[1]['passed'], not startup_failed and not write_escaped)


if __name__ == '__main__':
    unittest.main()
