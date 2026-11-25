"""Исключения: элементы, которые не нужно показывать при следующих сканах."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Iterable, List

from . import names


def normalize(text: str) -> str:
    """Схлопнуть пробелы, чтобы одинаковые строки совпадали."""
    return ' '.join(str(text).split())


def path(reports_dir: Path) -> Path:
    return Path(reports_dir) / names.EXCLUSIONS


def load(reports_dir: Path) -> List[str]:
    try:
        data = json.loads(path(reports_dir).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []
    items = data.get('items') if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    result: List[str] = []
    for item in items:
        text = normalize(item) if isinstance(item, str) else ''
        if text and text not in result:
            result.append(text)
    return result


def save(reports_dir: Path, items: Iterable[str]) -> List[str]:
    cleaned: List[str] = []
    seen = set()
    for item in items:
        text = normalize(item)
        key = text.casefold()
        if text and key not in seen:
            seen.add(key)
            cleaned.append(text)
    target = path(reports_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({'items': cleaned}, ensure_ascii=False, indent=2),
                      encoding='utf-8')
    return cleaned


def add(reports_dir: Path, texts: Iterable[str]) -> int:
    items = load(reports_dir)
    seen = {item.casefold() for item in items}
    added = 0
    for text in texts:
        normalized = normalize(text)
        key = normalized.casefold()
        if normalized and key not in seen:
            items.append(normalized)
            seen.add(key)
            added += 1
    if added:
        save(reports_dir, items)
    return added


def remove(reports_dir: Path, texts: Iterable[str]) -> int:
    items = load(reports_dir)
    removed = {normalize(text).casefold() for text in texts}
    remaining = [item for item in items if item.casefold() not in removed]
    if len(remaining) != len(items):
        save(reports_dir, remaining)
    return len(items) - len(remaining)


def clear(reports_dir: Path) -> None:
    save(reports_dir, [])


def contains(items: Iterable[str], text: str) -> bool:
    key = normalize(text).casefold()
    for item in items:
        item_key = item.casefold()
        if item_key == key:
            return True
        if any(ch in item for ch in '*?['):
            if fnmatch.fnmatchcase(key, item_key):
                return True
    return False
