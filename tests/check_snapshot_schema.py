"""CI-only independent JSON Schema checks; normal regression tests stay stdlib-only."""
import copy
import json
import unittest

from jsonschema import Draft202012Validator
import test_snapshot_contract as fixtures


class IndependentSchemaChecks(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SnapshotContract()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.schema = json.loads(fixtures.contract.SCHEMA_PATH.read_text())
        Draft202012Validator.check_schema(self.schema)
        self.validator = Draft202012Validator(self.schema)

    def test_collector_scopes_and_pilot_match_standard_schema(self):
        for scope in ('global', 'project', 'all'):
            for pilot in (False, True):
                with self.subTest(scope=scope, pilot=pilot):
                    self.validator.validate(self.fixture.snapshot(scope, pilot))

    def test_schema_rejects_structural_regressions(self):
        original = self.fixture.snapshot()
        cases = []
        for field in self.schema['required']:
            changed = copy.deepcopy(original)
            del changed[field]
            cases.append(changed)
        for version in (None, True, '1', 2):
            cases.append(dict(original, snapshot_version=version))
        cases.append(dict(original, projects=[]))
        for value in (-1, True, '0'):
            changed = copy.deepcopy(original)
            changed['coverage']['sources'][0]['omitted'] = value
            cases.append(changed)
        for changed in cases:
            self.assertFalse(self.validator.is_valid(changed))
            with self.assertRaises(fixtures.contract.SnapshotError):
                fixtures.contract.validate_snapshot(changed)

    def test_schema_keywords_are_supported_even_in_optional_branches(self):
        def visit(schema):
            self.assertFalse(set(schema) - fixtures.contract.KEYWORDS)
            for keyword in ('$defs', 'properties'):
                for child in schema.get(keyword, {}).values():
                    visit(child)
            for keyword in ('items', 'additionalProperties'):
                if isinstance(schema.get(keyword), dict):
                    visit(schema[keyword])
        visit(self.schema)


if __name__ == '__main__':
    unittest.main()
