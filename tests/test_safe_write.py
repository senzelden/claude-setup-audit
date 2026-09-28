"""Shared file-safety helpers: symlink refusal, atomic writes, private unique backups."""
import os
import stat
import tempfile
import unittest

from test_collect import SCRIPTS  # noqa: F401  (puts scripts/ on sys.path)
import safe_write


class SafeWrite(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = self.tmp.name
        self.path = os.path.join(self.home, "proj", "CLAUDE.md")
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("original\n")

    def test_backup_is_private_unique_and_complete(self):
        backups = os.path.join(self.home, "backups")
        made = []
        for _ in range(2):
            fd, _st = safe_write.open_no_symlink(self.path)
            try:
                made.append(safe_write.backup_from_fd(fd, self.path, backups, self.home))
            finally:
                os.close(fd)
        self.assertNotEqual(made[0], made[1])
        for backup in made:
            self.assertTrue(os.path.basename(backup).startswith("proj__CLAUDE.md."))
            self.assertEqual(stat.S_IMODE(os.stat(backup).st_mode), 0o600)
            with open(backup) as f:
                self.assertEqual(f.read(), "original\n")

    def test_symlink_is_refused(self):
        link = os.path.join(self.home, "link.md")
        os.symlink(self.path, link)
        with self.assertRaises(safe_write.SymlinkRefused):
            safe_write.open_no_symlink(link)

    def test_atomic_write_uses_prefix_and_replaces(self):
        safe_write.atomic_write(self.path, "new\n", prefix=".ledger.")
        with open(self.path) as f:
            self.assertEqual(f.read(), "new\n")
        self.assertEqual(sorted(os.listdir(os.path.dirname(self.path))), ["CLAUDE.md"])


if __name__ == "__main__":
    unittest.main()
