"""Validate the bundled snapshot contract without runtime dependencies.

This is a deliberately limited evaluator for our schema, not a general JSON Schema engine.
Only the keywords used in snapshot.schema.json are supported; unknown keywords fail closed.
Errors never include instance values or dynamic object keys (which can contain secrets).
"""
import argparse
import json
import math
from pathlib import Path

VERSION = 1
SCHEMA_PATH = Path(__file__).resolve().parents[1] / 'references' / 'snapshot.schema.json'
KEYWORDS = {'$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'const',
            'enum', 'minimum', 'required', 'properties', 'additionalProperties', 'items'}


class SnapshotError(ValueError):
    pass


def _json_values(value):
    if value is None or type(value) in (str, bool, int):
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, list):
        for item in value:
            _json_values(item)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for item in value.values():
            _json_values(item)
        return
    raise SnapshotError('snapshot contains a non-JSON or non-finite value')


def _check(value, schema, root, path='$'):
    if set(schema) - KEYWORDS:
        raise SnapshotError('bundled schema uses an unsupported keyword')
    if '$ref' in schema:
        ref = schema['$ref']
        if not ref.startswith('#/$defs/') or ref[8:] not in root['$defs']:
            raise SnapshotError('bundled schema uses an unsupported reference')
        _check(value, root['$defs'][ref[8:]], root, path)
    types = {'object': isinstance(value, dict), 'array': isinstance(value, list),
             'string': isinstance(value, str), 'null': value is None,
             'integer': type(value) is int, 'boolean': type(value) is bool}
    expected = schema.get('type')
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(types.get(t, False) for t in allowed):
            raise SnapshotError(f'{path}: wrong type')
    if 'const' in schema and value != schema['const']:
        raise SnapshotError(f'{path}: unsupported constant/version')
    if 'enum' in schema and value not in schema['enum']:
        raise SnapshotError(f'{path}: unsupported value')
    if 'minimum' in schema and value < schema['minimum']:
        raise SnapshotError(f'{path}: below minimum')
    if isinstance(value, dict):
        if set(schema.get('required', [])) - value.keys():
            raise SnapshotError(f'{path}: missing required field')
        properties = schema.get('properties', {})
        for key, item in value.items():
            if key in properties:
                _check(item, properties[key], root, f'{path}.{key}')
            else:
                extra = schema.get('additionalProperties', True)
                if extra is False:
                    raise SnapshotError(f'{path}: unexpected field')
                if isinstance(extra, dict):
                    _check(item, extra, root, f'{path}.*')
    if isinstance(value, list) and 'items' in schema:
        for index, item in enumerate(value):
            _check(item, schema['items'], root, f'{path}[{index}]')


def validate_snapshot(snapshot, *, allow_legacy=False):
    """Return 'v1' or 'legacy'; legacy is readable but has no validated contract."""
    _json_values(snapshot)
    if not isinstance(snapshot, dict):
        raise SnapshotError('snapshot must be an object')
    if 'snapshot_version' not in snapshot and allow_legacy:
        return 'legacy'
    schema = json.loads(SCHEMA_PATH.read_text(encoding='utf-8'))
    _check(snapshot, schema, schema)
    scope = snapshot['collection_scope']
    coverage = snapshot['coverage']
    if scope['requested'] != coverage['requested_scope']:
        raise SnapshotError('collection_scope and coverage disagree')
    if scope['projects_collected'] != len(coverage['projects_collected']):
        raise SnapshotError('project count and coverage disagree')
    if scope['requested'] == 'global' and scope['projects_collected'] != 0:
        raise SnapshotError('global scope cannot collect projects')
    if scope['requested'] == 'project':
        if not scope['project'] or scope['projects_collected'] != 1:
            raise SnapshotError('project scope requires one named project')
    elif scope['project'] is not None:
        raise SnapshotError('project selector requires project scope')
    return 'v1'


def main():
    parser = argparse.ArgumentParser(description='Validate snapshot structure; never execute its contents.')
    parser.add_argument('snapshot')
    args = parser.parse_args()
    try:
        with open(args.snapshot, encoding='utf-8') as stream:
            validate_snapshot(json.load(stream))
    except (OSError, ValueError, RecursionError) as exc:
        parser.exit(1, f'invalid snapshot: {exc if isinstance(exc, SnapshotError) else "unreadable or invalid JSON"}\n')
    print('valid snapshot v1')


if __name__ == '__main__':
    main()
