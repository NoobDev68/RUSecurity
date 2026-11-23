"""Имена файлов RUSecurity.

Намеренно не совпадают с FRST (`FRST.txt`, `Addition.txt`, `fixlist.txt`), чтобы
отчёты приложения не путались с отчётами FRST. Анализатор при этом по-прежнему
принимает и «родные» имена FRST.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

REPORT = 'rusecurity-report.txt'
ADDITION = 'rusecurity-add.txt'
FIXLIST = 'rusecurity-fix.txt'
FIXLOG = 'rusecurity-log.txt'
JOURNAL = 'rusecurity-journal.txt'
BACKUPS = 'Backups'

LEGACY_ADDITION = 'Addition.txt'
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
    candidates.append(report_path.with_name(LEGACY_ADDITION))
    return candidates
