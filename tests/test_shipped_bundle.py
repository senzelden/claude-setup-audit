import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ShippedBundleTests(unittest.TestCase):
    def test_no_evals_in_plugin(self):
        self.assertFalse((ROOT / 'plugins/setup-audit/evals').exists())
        self.assertTrue((ROOT / 'evals/README.md').is_file())


if __name__ == '__main__':
    unittest.main()
