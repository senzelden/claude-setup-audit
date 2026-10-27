"""The subscription-usage checklist entries exist and carry their required wording."""
import re
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / 'plugins' / 'setup-audit' / 'skills' / 'setup-audit'
IDS = ('COST-subscription-headroom', 'COST-model-scoped-limits', 'COST-extra-usage',
       'COST-limit-resets')


class SubscriptionChecklist(unittest.TestCase):
    def setUp(self):
        self.text = (SKILL / 'references' / 'checklist.md').read_text(encoding='utf-8')

    def entry(self, check_id):
        m = re.search(r'- \*\*%s\*\*(.*?)(?=\n- \*\*[A-Z]+-|\n## )' % re.escape(check_id),
                      self.text, re.S)
        self.assertIsNotNone(m, check_id)
        return ' '.join(m.group(1).split())

    def test_every_id_is_defined(self):
        for check_id in IDS:
            self.assertTrue(self.entry(check_id).strip(), check_id)

    def test_entries_name_source_and_evidence_class(self):
        for check_id in IDS:
            body = self.entry(check_id)
            self.assertIn('`subscription.', body, check_id)
            self.assertTrue(re.search(r'measured|inferred|documented text', body), check_id)

    def test_headroom_wording(self):
        body = self.entry('COST-subscription-headroom')
        for needle in ('at most', 'reached_85', 'stale_excluded', 'recommendation',
                       'rate-limit-log.md', 'not observable locally',
                       'at least 3 counted (non-stale) closed weekly windows (`counted`)'):
            self.assertIn(needle, body)

    def test_resets_are_inferred_and_undocumented(self):
        body = self.entry('COST-limit-resets')
        self.assertIn('inferred', body)
        self.assertIn('undocumented', body)


if __name__ == '__main__':
    unittest.main()
