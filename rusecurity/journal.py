"""Журнал действий RUSecurity: подробный лог в файле рядом с отчётами."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

_MAX_LINES = 4000


class Journal:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self, limit: int = _MAX_LINES) -> str:
        try:
            lines = self.path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            return ''
        return '\n'.join(lines[-limit:])

    def append(self, message: str) -> str:
        line = f'[{datetime.now():%d.%m.%Y %H:%M:%S}] {message}'
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open('a', encoding='utf-8', newline='') as handle:
                handle.write(line + '\n')
        except OSError:
            pass
        return line

    def clear(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass
