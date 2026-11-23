"""Delta-скан: что появилось и что исчезло с прошлого сканирования."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

HISTORY_DIR = 'history'
_KEEP_SNAPSHOTS = 10

_EXCLUDED = (
    'процессы', 'диски', 'информация о памяти', 'ошибки журнала',
    'точки восстановления',
)

_VOLATILE = (
    (re.compile(r'\[\d{6,}\s+\d{4}-\d{2}-\d{2}\]'), '[ФАЙЛ]'),
    (re.compile(r'\b\d{4}-\d{2}-\d{2}\b'), '<ДАТА>'),
    (re.compile(r'\b\d{2}-\d{2}-\d{4}\b'), '<ДАТА>'),
    (re.compile(r'\b\d{2}:\d{2}:\d{2}\b'), '<ВРЕМЯ>'),
    (re.compile(r'<\d+>'), '<N>'),
)


def normalize(line: str) -> str:
    text = ' '.join(line.split())
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def entries_from_text(text: str) -> Dict[str, str]:
    """Нормализованная строка → исходная, без заголовков и служебных пометок."""
    result: Dict[str, str] = {}
    section = ''
    started = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith('='):
            started = True
            section = stripped.strip('= ').strip().lower()
            continue
        if not started:
            continue
        if any(section.startswith(name) for name in _EXCLUDED):
            continue
        if stripped.startswith('(') and stripped.endswith(')'):
            continue
        key = normalize(stripped)
        result.setdefault(key, stripped)
    return result


def _history_dir(reports_dir: Path) -> Path:
    return Path(reports_dir) / HISTORY_DIR


def load_last(reports_dir: Path) -> Optional[Dict[str, str]]:
    history = _history_dir(reports_dir)
    files = sorted(history.glob('scan-*.json'))
    if not files:
        return None
    try:
        data = json.loads(files[-1].read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None
    entries = data.get('entries')
    if isinstance(entries, dict):
        return {str(key): str(value) for key, value in entries.items()}
    return None


def save(reports_dir: Path, entries: Dict[str, str]) -> Path:
    history = _history_dir(reports_dir)
    history.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    target = history / f'scan-{stamp}.json'
    counter = 1
    while target.exists():
        target = history / f'scan-{stamp}_{counter}.json'
        counter += 1
    target.write_text(json.dumps({
        'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'entries': entries,
    }, ensure_ascii=False), encoding='utf-8')
    _prune(history)
    return target


def _prune(history: Path) -> None:
    files = sorted(history.glob('scan-*.json'))
    for old in files[:-_KEEP_SNAPSHOTS]:
        try:
            old.unlink()
        except OSError:
            continue


def compare(previous: Dict[str, str],
            current: Dict[str, str]) -> Tuple[List[str], List[str]]:
    new = [line for key, line in current.items() if key not in previous]
    gone = [line for key, line in previous.items() if key not in current]
    return new, gone
