"""Rate-limit status-line logger. Temp dirs and a patched CLAUDE_CONFIG_DIR only."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'plugins', 'setup-audit',
                                                'skills', 'setup-audit', 'scripts')))
import rate_limit_log  # noqa: E402

FIVE = {'used_percentage': 23.5, 'resets_at': 1738425600}
SEVEN = {'used_percentage': 41.2, 'resets_at': 1738857600}


def status(**windows):
    return json.dumps({'model': {'display_name': 'x'}, 'rate_limits': windows}).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = os.path.join(self.tmp.name, 'cfg')
        os.makedirs(self.config)
        patcher = mock.patch.dict(os.environ, {'CLAUDE_CONFIG_DIR': self.config})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.log = os.path.join(self.tmp.name, 'rate-limits.jsonl')

    def run_main(self, data, argv=None, now=1738400000.0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = rate_limit_log.main(['--log', self.log] if argv is None else argv,
                                       stdin=io.BytesIO(data), now=now)
        return code, out.getvalue(), err.getvalue()

    def lines(self, path=None):
        p = Path(path or self.log)
        return p.read_text().splitlines() if p.exists() else []


class Logging(Base):
    def test_logs_and_prints(self):
        code, out, err = self.run_main(status(five_hour=FIVE, seven_day=SEVEN))
        self.assertEqual((code, err), (0, ''))
        self.assertIn('5h 23%', out)
        self.assertIn('7d 41%', out)
        (line,) = self.lines()
        entry = json.loads(line)
        self.assertEqual(entry['version'], 1)
        self.assertIsInstance(entry['at'], str)
        self.assertEqual(entry['windows'], {'five_hour': FIVE, 'seven_day': SEVEN})

    def test_unchanged_is_not_relogged(self):
        self.run_main(status(five_hour=FIVE))
        self.run_main(status(five_hour=FIVE))
        self.assertEqual(len(self.lines()), 1)
        self.run_main(status(five_hour={**FIVE, 'used_percentage': 23.9}))
        self.assertEqual(len(self.lines()), 1)
        self.run_main(status(five_hour={**FIVE, 'used_percentage': 24.0}))
        self.assertEqual(len(self.lines()), 2)
        self.run_main(status(five_hour={'used_percentage': 24.0, 'resets_at': 1738440000}))
        self.assertEqual(len(self.lines()), 3)
        self.run_main(status())
        self.assertEqual(len(self.lines()), 4)

    def test_bad_stdin_is_silent(self):
        bad = [b'', b'not json', b'[]']
        for value in ('null', '"x"', 'NaN', 'true'):
            bad.append(('{"rate_limits": %s}' % value).encode())
        bad.append(b'{"rate_limits": {"five_hour": {"used_percentage": NaN, "resets_at": 1}}}')
        bad.append(b'{"rate_limits": {"five_hour": {"used_percentage": true, "resets_at": 1}}}')
        bad.append(b'{"rate_limits": {"five_hour": {"used_percentage": 5, "resets_at": Infinity}}}')
        for data in bad:
            with self.subTest(data=data):
                code, out, err = self.run_main(data)
                self.assertEqual((code, out.strip(), err), (0, '', ''))
                self.assertFalse(os.path.exists(self.log))

    def test_unparseable_stdin_does_not_log_disappearance(self):
        self.run_main(status(five_hour=FIVE))
        self.run_main(b'not json')
        self.assertEqual(len(self.lines()), 1)

    def test_no_rate_limits_prints_nothing(self):
        code, out, _ = self.run_main(b'{"model": {"display_name": "x"}}')
        self.assertEqual((code, out), (0, ''))
        self.assertFalse(os.path.exists(self.log))

    def test_spend_limit_drops_usd(self):
        spend = {'used_percentage': 120, 'resets_at': 1740000000, 'used_usd': 12.0, 'limit_usd': 10.0,
                 'period': 'monthly'}
        self.run_main(status(spend_limit=spend))
        logged = json.loads(self.lines()[0])['windows']['spend_limit']
        self.assertEqual(set(logged), {'used_percentage', 'resets_at', 'period'})
        self.assertNotIn('usd', self.lines()[0])
        self.run_main(status(spend_limit={**spend, 'period': 'hourly'}))
        self.assertNotIn('period', rate_limit_log.extract({'rate_limits': {'spend_limit': {
            **spend, 'period': 'hourly'}}})['spend_limit'])
        self.assertNotIn('period', rate_limit_log.extract({'rate_limits': {'five_hour': {
            **FIVE, 'period': 'monthly'}}})['five_hour'])

    def test_unwritable_log_still_prints(self):
        target = os.path.join(self.tmp.name, 'target.jsonl')
        link = os.path.join(self.tmp.name, 'link.jsonl')
        os.symlink(target, link)
        for path in (link, '/usr/rate-limits.jsonl'):
            with self.subTest(path=path):
                code, out, err = self.run_main(status(five_hour=FIVE), argv=['--log', path])
                self.assertEqual((code, err), (0, ''))
                self.assertIn('5h', out)
        self.assertFalse(os.path.exists(target))

    def test_default_log_under_config_audits(self):
        self.run_main(status(five_hour=FIVE), argv=[])
        self.assertEqual(len(self.lines(os.path.join(self.config, 'audits', 'rate-limits.jsonl'))), 1)

    def test_rotation(self):
        old = b'x' * rate_limit_log.ROTATE_BYTES
        Path(self.log).write_bytes(old)
        self.run_main(status(five_hour=FIVE))
        self.assertEqual(Path(self.log + '.1').read_bytes(), old)
        self.assertEqual(len(self.lines()), 1)

    def test_last_entry_tolerates_junk(self):
        Path(self.log).write_text('{"version":1,"at":"a","windows":{}}\n{"version":1,"at":"b","wind')
        self.assertEqual(rate_limit_log.last_entry(self.log)['at'], 'a')
        self.assertIsNone(rate_limit_log.last_entry(self.log + '.missing'))


class Wrapping(Base):
    def test_wraps_command(self):
        data = status(five_hour=FIVE)
        cmd = ['--log', self.log, '--', sys.executable, '-c', "import sys; print('W'+str(len(sys.stdin.read())))"]
        code, out, _ = self.run_main(data, argv=cmd)
        self.assertEqual((code, out.strip()), (0, 'W%d' % len(data)))
        self.assertEqual(len(self.lines()), 1)

    def test_failing_command_prints_own_line(self):
        data = status(five_hour=FIVE)
        for cmd in ([sys.executable, '-c', 'import sys; sys.exit(1)'], ['/nonexistent/command']):
            with self.subTest(cmd=cmd):
                code, out, err = self.run_main(data, argv=['--log', self.log, '--'] + cmd)
                self.assertEqual((code, err), (0, ''))
                self.assertIn('5h 23%', out)

    def test_bad_args_exit_2(self):
        code, out, _ = self.run_main(status(five_hour=FIVE), argv=['--bogus'])
        self.assertEqual((code, out), (2, ''))


class Helpers(unittest.TestCase):
    def test_render(self):
        self.assertEqual(rate_limit_log.render({}, 0), '')
        self.assertTrue(rate_limit_log.render({'five_hour': FIVE, 'seven_day': SEVEN}, 0).startswith(
            '5h 23% · 7d 41% (resets '))


if __name__ == '__main__':
    unittest.main()
