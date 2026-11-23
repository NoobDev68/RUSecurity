"""Тесты delta-скана и сбора Alternate Data Streams."""

import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.core import delta  # noqa: E402
from rusecurity.core.sections import ads  # noqa: E402


def test_normalize_strips_volatile_parts():
    line = r'HKLM\...\Run: [X] => C:\x.exe [123456 2026-11-22] <4>'
    normalized = delta.normalize(line)
    assert normalized == r'HKLM\...\Run: [X] => C:\x.exe [ФАЙЛ] <N>'
    stamp = delta.normalize('2026-11-22 14:50:01 - 2026-11-01 10:00:00')
    assert stamp == '<ДАТА> <ВРЕМЯ> - <ДАТА> <ВРЕМЯ>'


def test_entries_skip_noisy_sections():
    text = '\n'.join([
        'Отчёт RUSecurity Версия: 2026-11-22',
        '==================== Процессы (Все) ====================',
        '(Microsoft Corporation) C:\\Windows\\explorer.exe',
        '==================== Службы (Все) ====================',
        'R2 Test; C:\\test.exe [100 2026-01-01]',
        '==================== Диски ====================',
        'Drive c: () (Fixed)',
    ])
    entries = delta.entries_from_text(text)
    keys = list(entries)
    assert any('R2 Test' in key for key in keys)
    assert not any('explorer.exe' in key for key in keys)
    assert not any('Drive c' in key for key in keys)
    assert not any('Отчёт RUSecurity' in key for key in keys)


def test_compare_new_and_gone():
    previous = {'a': 'line A', 'b': 'line B'}
    current = {'a': 'line A', 'c': 'line C'}
    new, gone = delta.compare(previous, current)
    assert new == ['line C']
    assert gone == ['line B']


def test_snapshot_roundtrip_and_prune(tmp_path):
    entries = {'key': 'value'}
    for _ in range(12):
        delta.save(tmp_path, entries)
    files = sorted((tmp_path / 'history').glob('scan-*.json'))
    assert len(files) == delta._KEEP_SNAPSHOTS
    loaded = delta.load_last(tmp_path)
    assert loaded == entries


def test_ads_streams_are_detected(tmp_path):
    target = tmp_path / 'file.txt'
    target.write_text('data', encoding='utf-8')
    with open(f'{target}:secret', 'w', encoding='utf-8') as handle:
        handle.write('hidden')
    found = dict(ads._streams(str(target)))
    assert 'secret' in {name.lower() for name in found}
    assert 'data' not in {name.lower() for name in found}
    target.unlink()
