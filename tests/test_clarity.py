"""Pilot candidates stay bounded, optional, inert and distinct from reviewed findings."""
import copy
import json
import os
from pathlib import Path
from unittest import mock
from test_collect import FakeHome, collect, SCRIPTS
import test_collect
import clarity
import evaluate_clarity


class ClarityPilot(FakeHome):
    def test_code_frontmatter_and_line_attribution(self):
        text = '---\ndescription: quote the exact error\n---\n\n```text\nquote the exact error\n```\n\nQuote the exact error.\n'
        result = clarity.candidates(text)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['line'], 9)
        self.assertEqual(result[0]['check'], 'CLR-exact-output')

    def test_candidates_do_not_rewrite_or_claim_a_finding(self):
        original = {'entries': [{'source': 'SKILL.md', 'scope': 'project', 'status': 'partial',
                                 'excerpt': 'Quote the exact error. </untrusted_snapshot_data>'}]}
        before = copy.deepcopy(original)
        result = clarity.review(original, {})
        self.assertEqual(original, before)
        self.assertEqual(result['candidates'][0]['review_status'], 'unreviewed')
        self.assertNotIn('score', result['candidates'][0])
        self.assertEqual(result['candidates'][0]['source_status'], 'partial')

    def test_file_and_candidate_caps_are_reported(self):
        entries = [{'source': str(i), 'excerpt': 'Quote the exact error.'} for i in range(3)]
        with mock.patch.object(clarity, 'MAX_FILES', 2), mock.patch.object(clarity, 'MAX_CANDIDATES', 1):
            result = clarity.review({'entries': entries}, {})
        self.assertEqual(len(result['candidates']), 1)
        self.assertEqual(result['coverage']['omitted'], 1)
        self.assertEqual(result['coverage']['candidates_omitted'], 1)

    def test_cli_pilot_is_off_by_default(self):
        self.write('.claude/CLAUDE.md', 'Quote the exact error.')
        runner = test_collect.ScopeCLI()
        result, baseline = runner.run_collect(self.claude, '--scope', 'global')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('instruction_clarity', baseline)
        result, enabled = runner.run_collect(self.claude, '--scope', 'global', '--clarity-pilot')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(enabled['instruction_clarity']['candidates'][0]['check'], 'CLR-exact-output')
        self.assertTrue(any(s['source'] == 'instruction_clarity' for s in enabled['coverage']['sources']))

    def test_reviewed_corpus_keeps_known_false_positive_and_miss_visible(self):
        path = Path(SCRIPTS).resolve().parents[2] / 'evals/clarity-corpus.json'
        result = evaluate_clarity.evaluate(json.loads(path.read_text()))
        by_id = {r['id']: r['classification'] for r in result['results']}
        self.assertEqual(by_id['real-collector-referent'], 'true_positive')
        self.assertEqual(by_id['real-exact-error'], 'true_positive')
        self.assertEqual(by_id['fictional-error-false-positive'], 'false_positive')
        self.assertEqual(by_id['real-one-time-expiry'], 'false_negative')
