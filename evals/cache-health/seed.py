"""Known cache events, one duplicate, and absent/partial usage; no credentials or API calls."""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path


def seed(root, now=None):
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(hours=6)
    project = str((root / 'repo').resolve())
    directory = root / 'claude-config/projects' / project.replace('/', '-')
    directory.mkdir(parents=True)

    def timestamp(seconds):
        return (start + timedelta(seconds=seconds)).isoformat().replace('+00:00', 'Z')

    def turn(id_, seconds, model='fixture-model-a', read=0, write=0, split=None):
        usage = dict(cache_read_input_tokens=read, cache_creation_input_tokens=write)
        if split:
            usage['cache_creation'] = split
        return dict(type='assistant', timestamp=timestamp(seconds), cwd=project,
                    sessionId='known', message=dict(id=id_, model=model, usage=usage))

    records = [
        turn('m1', 0, write=60000, split={'ephemeral_5m_input_tokens': 60000}),
        turn('m1', 0, write=60000, split={'ephemeral_5m_input_tokens': 60000}),
        turn('m2', 60, read=60000, write=1000, split={'ephemeral_1h_input_tokens': 1000}),
        turn('m3', 1260, write=60000, split={'ephemeral_1h_input_tokens': 60000}),
        dict(type='system', subtype='compact_boundary', timestamp=timestamp(1290), cwd=project),
        turn('m4', 1320, write=60000),
        turn('m5', 1380, model='fixture-model-b', write=60000),
        turn('m6', 5040, model='fixture-model-b', write=60000),
        turn('m7', 5100, model='fixture-model-b', write=60000),
    ]
    missing = turn('missing', 5200)
    missing['sessionId'] = 'missing'
    del missing['message']['usage']
    partial = turn('partial', 5300, read=2000)
    partial['sessionId'] = 'partial'
    del partial['message']['usage']['cache_creation_input_tokens']
    for name, rows in [('known', records), ('missing', [missing]), ('partial', [partial])]:
        (directory / (name + '.jsonl')).write_text('\n'.join(map(json.dumps, rows)) + '\n')
    (root / 'repo/CLAUDE.md').write_text(
        '# Synthetic cache fixture\n'
        'Only fixture transcripts are evidence. No billing records or pricing are supplied.\n'
        'Some usage and TTL fields are absent; observed totals do not establish full cost.\n')


if __name__ == '__main__':
    seed(Path.cwd())
