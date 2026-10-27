import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    'stage_plugin', Path(__file__).resolve().parents[1] / 'evals/helpers/stage_plugin.py')
stage_plugin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_plugin)


def make_repo(root):
    plugin = root / 'plugins/setup-audit'
    (plugin / '.claude-plugin').mkdir(parents=True)
    (plugin / '.claude-plugin/plugin.json').write_text('{}')
    (root / 'evals/case-a').mkdir(parents=True)
    (root / 'evals/case-a/case.yaml').write_text('x')
    (root / 'evals/results').mkdir()
    (root / 'evals/results/old.txt').write_text('old')
    return root


class StagePluginTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = make_repo(Path(self.tmp.name) / 'repo')

    def test_stages_plugin_with_evals_beneath_it(self):
        out = Path(self.tmp.name) / 'staged'
        staged = stage_plugin.stage(self.repo, out)
        self.assertTrue((staged / '.claude-plugin/plugin.json').is_file())
        self.assertTrue((staged / 'evals/case-a/case.yaml').is_file())
        self.assertFalse((staged / 'evals/results').exists())
        self.assertTrue((self.repo / 'evals/results/old.txt').exists())

    def test_default_target_is_fresh_temp_dir(self):
        staged = stage_plugin.stage(self.repo)
        self.addCleanup(__import__('shutil').rmtree, staged, True)
        self.assertTrue((staged / 'evals/case-a').is_dir())

    def test_symlink_refused(self):
        (self.repo / 'evals/link').symlink_to(self.repo / 'evals/case-a')
        with self.assertRaises(SystemExit):
            stage_plugin.stage(self.repo, Path(self.tmp.name) / 'staged')

    def test_existing_out_refused(self):
        out = Path(self.tmp.name) / 'there'
        out.mkdir()
        with self.assertRaises(SystemExit):
            stage_plugin.stage(self.repo, out)

    def test_real_repo_staged_helpers_resolve_scripts(self):
        out = Path(self.tmp.name) / 'real'
        staged = stage_plugin.stage(stage_plugin.REPO, out)
        self.assertTrue((staged / 'evals/helpers/check_quality.py').is_file())
        self.assertTrue((staged / 'skills/setup-audit/scripts').is_dir())
        self.assertTrue((staged / 'evals/cache-health/fixture.sh').is_file())
        self.assertTrue((staged / '.claude-plugin/plugin.json').is_file())


if __name__ == '__main__':
    unittest.main()
