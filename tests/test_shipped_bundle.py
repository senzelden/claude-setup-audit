import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/setup-audit'


class ShippedBundleTests(unittest.TestCase):
    def test_no_evals_in_plugin(self):
        self.assertFalse((PLUGIN / 'evals').exists())
        self.assertTrue((ROOT / 'evals/README.md').is_file())

    def test_manifest_icon_points_at_shipped_png(self):
        # The plugin directory reads the listing icon from plugin.json `icon`.
        manifest = json.loads((PLUGIN / '.claude-plugin/plugin.json').read_text())
        icon = manifest.get('icon')
        self.assertIsInstance(icon, str)
        self.assertTrue(icon.startswith('./'), icon)
        path = (PLUGIN / icon).resolve()
        self.assertTrue(path.is_relative_to(PLUGIN.resolve()), icon)
        self.assertTrue(path.is_file(), icon)
        self.assertEqual(path.read_bytes()[:8], b'\x89PNG\r\n\x1a\n')


if __name__ == '__main__':
    unittest.main()
