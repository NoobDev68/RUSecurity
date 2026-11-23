"""Модель отчёта: заголовки секций, накопление строк, запись файла."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

HEADING_WIDTH = 64
_ENCODING = 'utf-8'
_NEWLINE = '\r\n'


def heading(title: str) -> str:
    """Заголовок секции отчёта: '===== Title ====='."""
    base = f'{"=" * 20} {title} '
    return base + '=' * max(4, HEADING_WIDTH - len(base))


@dataclass
class Section:
    title: str
    lines: List[str] = field(default_factory=list)
    note: Optional[str] = None

    def render(self) -> List[str]:
        result = [heading(self.title)]
        if self.note:
            result.append(self.note)
        result.extend(self.lines)
        result.append('')
        return result


@dataclass
class Report:
    header: List[str] = field(default_factory=list)
    sections: List[Section] = field(default_factory=list)

    def add(self, title: str, lines: List[str], note: Optional[str] = None) -> Section:
        section = Section(title=title, lines=list(lines), note=note)
        self.sections.append(section)
        return section

    def render(self) -> str:
        lines: List[str] = list(self.header)
        for section in self.sections:
            lines.extend(section.render())
        return _NEWLINE.join(lines) + _NEWLINE

    def write(self, path: Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding=_ENCODING, newline='') as handle:
            handle.write(self.render())
        return path
