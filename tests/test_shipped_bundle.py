import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/setup-audit'
ICON = PLUGIN / '.claude-plugin/icon.png'

# Plugin directory rules (claude.com/docs/plugins/pre-submission-checklist, fetched 2026-10-27):
# a bundled image referenced from the plugin is held for a reviewer, and a credential source
# named next to a network destination reads as "uses a credential from the user's machine". The
# scanner matches per file: on 0.13.1 it flagged exactly the seven files CREDENTIAL_SOURCE and URL
# both match. These guards keep each shipped file clear of both patterns.
IMAGE_OR_FONT_PATH = re.compile(r'\.(png|jpe?g|gif|webp|woff2?|ttf|otf|ico)\b', re.I)
CREDENTIAL_SOURCE = re.compile(
    r'\.claude\.json|\.envrc|\.credentials\.json'
    r'|\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY)[A-Z0-9_]*\b|\b[A-Z0-9_]+_KEY\b')
URL = re.compile(r'https?://')


def shipped_text_files():
    for path in sorted(PLUGIN.rglob('*')):
        if path.is_file() and '__pycache__' not in path.parts and path != ICON:
            yield path, path.read_text(encoding='utf-8')


class ShippedBundleTests(unittest.TestCase):
    def test_no_evals_in_plugin(self):
        self.assertFalse((PLUGIN / 'evals').exists())
        self.assertTrue((ROOT / 'evals/README.md').is_file())

    def test_listing_icon_at_default_path(self):
        # The directory picks up .claude-plugin/icon.png without a manifest field: square PNG,
        # 512 to 2048 px, under 2 MB.
        data = ICON.read_bytes()
        self.assertEqual(data[:8], b'\x89PNG\r\n\x1a\n')
        width, height = struct.unpack('>II', data[16:24])
        self.assertEqual(width, height)
        self.assertTrue(512 <= width <= 2048, width)
        self.assertLess(len(data), 2 * 1024 * 1024)

    def test_no_shipped_file_refers_to_an_image_or_font(self):
        for path, text in shipped_text_files():
            self.assertIsNone(IMAGE_OR_FONT_PATH.search(text), path.relative_to(ROOT))

    def test_no_shipped_file_pairs_a_credential_source_with_a_url(self):
        # Docs are cited by page name (docs-map.md holds the base URL) wherever a file names a
        # credential-bearing file or variable.
        for path, text in shipped_text_files():
            source, url = CREDENTIAL_SOURCE.search(text), URL.search(text)
            self.assertFalse(source and url, '%s: %s with %s' % (
                path.relative_to(ROOT), source and source.group(), url and url.group()))


if __name__ == '__main__':
    unittest.main()
