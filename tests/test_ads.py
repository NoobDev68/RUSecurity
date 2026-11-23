"""Тест сбора Alternate Data Streams."""

import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.core.sections import ads  # noqa: E402


def test_ads_streams_are_detected(tmp_path):
    target = tmp_path / 'file.txt'
    target.write_text('data', encoding='utf-8')
    with open(f'{target}:secret', 'w', encoding='utf-8') as handle:
        handle.write('hidden')
    found = dict(ads._streams(str(target)))
    assert 'secret' in {name.lower() for name in found}
    assert 'data' not in {name.lower() for name in found}
    target.unlink()
