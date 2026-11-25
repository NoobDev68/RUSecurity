"""Имена файлов RUSecurity.

Отчёты, список исправлений и журнал лежат рядом с программой и названы
по-своему, чтобы не путаться с файлами других инструментов.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

REPORT = 'rusecurity-report.txt'
ADDITION = 'rusecurity-add.txt'
FIXLIST = 'rusecurity-fix.txt'
FIXLOG = 'rusecurity-log.txt'
JOURNAL = 'rusecurity-journal.txt'
EXCLUSIONS = 'rusecurity-exclusions.json'
DEEP = 'rusecurity-deep.json'
BACKUPS = 'Backups'

LEGACY_RUSECURITY_ADDITION = 'rusecurity-additional.txt'


def addition_candidates(report_path: Path) -> List[Path]:
    """Где искать дополнительный отчёт рядом с основным."""
    report_path = Path(report_path)
    candidates: List[Path] = []
    stem = report_path.stem
    if stem.endswith('-report'):
        candidates.append(report_path.with_name(stem[:-len('-report')] + '-add.txt'))
    candidates.append(report_path.with_name(ADDITION))
    candidates.append(report_path.with_name(LEGACY_RUSECURITY_ADDITION))
    return candidates
