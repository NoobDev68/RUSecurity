"""Экспорт сводки проверки в Markdown и архива для поддержки."""

from __future__ import annotations

import zipfile
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Sequence

from . import names

_DIRECTIVES = (
    ('restore_point', 'Точка восстановления'),
    ('close_processes', 'Закрыть блокирующие процессы'),
    ('empty_temp', 'Очистить временные файлы'),
    ('browser_cache', 'Очистить кэш и куки браузеров'),
    ('reboot', 'Перезагрузка'),
)


def latest_backup(reports_dir: Path) -> Optional[Path]:
    """Самое свежее исправление с манифестом."""
    manifests = sorted(
        Path(reports_dir).glob(f'{names.BACKUPS}/*/manifest.json'),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return manifests[0].parent if manifests else None


def summary_markdown(*, created: datetime, duration: float, entries: int,
                     addition_entries: int = 0,
                     findings: Sequence[object] = (),
                     hidden: Sequence[object] = (),
                     directives: Optional[dict] = None,
                     report: Optional[Path] = None,
                     addition: Optional[Path] = None,
                     fixlog: Optional[Path] = None,
                     backup_dir: Optional[Path] = None) -> str:
    """Человекочитаемая сводка: что проверено, что найдено и где лежат файлы."""
    lines: List[str] = [
        '# RUSecurity — сводка проверки',
        '',
        f'Дата: {created.strftime("%d.%m.%Y %H:%M:%S")}',
        f'Время сканирования: {duration:.1f} с',
        f'Записей в отчёте: {entries}',
    ]
    if addition_entries:
        lines.append(f'Записей в дополнительном отчёте: {addition_entries}')
    lines.append(f'Найдено элементов: {len(findings)}')
    if hidden:
        lines.append(f'Скрыто исключениями: {len(hidden)}')
    if directives:
        enabled = [label for key, label in _DIRECTIVES if directives.get(key)]
        lines.append('Директивы: ' + (', '.join(enabled) if enabled else 'нет'))
    lines.extend(['', '## Найденное', ''])
    if not findings:
        lines.append('Подозрительных элементов не найдено.')
    else:
        category = None
        for finding in findings:
            if finding.category != category:
                category = finding.category
                lines.extend([f'### {category}', ''])
            mark = ' (вручную)' if getattr(finding, 'manual', False) else ''
            lines.append(f'- [{finding.kind_label}] {finding.text}{mark}')
    lines.extend(['', '## Файлы', ''])
    for label, value in (('Отчёт', report), ('Дополнительный отчёт', addition),
                         ('Журнал исправления', fixlog),
                         ('Последние бэкапы', backup_dir)):
        if value:
            lines.append(f'- {label}: {value}')
    if fixlog is not None and fixlog.is_file():
        done, total = _fixlog_summary(fixlog)
        lines.extend(['', '## Последнее исправление', ''])
        if total:
            lines.append(total)
        if done:
            lines.extend(f'- {line}' for line in done[:15])
            if len(done) > 15:
                lines.append(f'- … ещё {len(done) - 15}')
        elif not total:
            lines.append('Изменений в журнале нет.')
    lines.append('')
    return '\n'.join(lines)


def _fixlog_summary(path: Path) -> tuple:
    """Строки «[done]» и итог из журнала исправления."""
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return [], ''
    done = []
    total = ''
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith('Итог:'):
            total = line
        elif '[done]' in line:
            done.append(line.split('[done] ', 1)[-1])
    return done, total


def export_markdown(target: Path, text: str) -> Path:
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding='utf-8')
    return target


def export_zip(target: Path, reports_dir: Path, summary_text: str) -> Path:
    """ZIP со сводкой, отчётами и журналами — одним файлом для поддержки."""
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    reports_dir = Path(reports_dir)
    with zipfile.ZipFile(target, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('summary.md', summary_text)
        for name in (names.REPORT, names.ADDITION, names.JOURNAL,
                     names.FIXLOG, names.FIXLIST, names.DEEP):
            source = reports_dir / name
            if source.is_file():
                archive.write(source, arcname=name)
        backup = latest_backup(reports_dir)
        if backup is not None:
            manifest = backup / 'manifest.json'
            if manifest.is_file():
                archive.write(manifest, arcname=f'backup/{manifest.name}')
    return target
