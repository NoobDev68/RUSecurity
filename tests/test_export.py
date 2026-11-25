"""Тесты исключений и экспорта сводки."""

import sys
import zipfile
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity import exclusions, names, report_export  # noqa: E402


def _finding(text: str, category: str = 'Реестр') -> SimpleNamespace:
    return SimpleNamespace(text=text, category=category, kind_label='значения реестра',
                           manual=False)


def test_exclusions_add_remove_and_persist(tmp_path):
    assert exclusions.add(tmp_path, [' run  value ', 'run value']) == 1
    assert exclusions.load(tmp_path) == ['run value']
    assert exclusions.contains(exclusions.load(tmp_path), 'run   value')

    assert exclusions.remove(tmp_path, ['RUN VALUE']) == 1
    assert exclusions.load(tmp_path) == []


def test_exclusions_bad_json_is_empty(tmp_path):
    (tmp_path / names.EXCLUSIONS).write_text('{broken', encoding='utf-8')
    assert exclusions.load(tmp_path) == []


def test_exclusions_wildcard_matches(tmp_path):
    exclusions.add(tmp_path, ['*4pda*', 'DNS: *'])
    items = exclusions.load(tmp_path)
    assert exclusions.contains(items, 'Edge: Новости 4pda — http://4pda.ru')
    assert exclusions.contains(items, 'DNS: 8.8.8.8')
    assert not exclusions.contains(items, 'Входящее правило: pythonw.exe')


def test_summary_markdown_has_findings_and_hidden(tmp_path):
    report = tmp_path / names.REPORT
    report.write_text('x', encoding='utf-8')
    text = report_export.summary_markdown(
        created=datetime(2026, 11, 23, 22, 0, 0),
        duration=3.5,
        entries=42,
        addition_entries=7,
        findings=[_finding(r'HKLM\...\Run: [Bad] => C:\bad.exe')],
        hidden=[_finding('hidden')],
        directives={'restore_point': True, 'reboot': False},
        report=report,
    )
    assert 'RUSecurity — сводка проверки' in text
    assert 'Найдено элементов: 1' in text
    assert 'Скрыто исключениями: 1' in text
    assert 'Bad' in text
    assert 'Директивы: Точка восстановления' in text
    assert str(report) in text


def test_summary_includes_last_fix(tmp_path):
    log = tmp_path / names.FIXLOG
    log.write_text(
        'RUSecurity — журнал исправления 2026-11-23 22:00:00\n'
        '[22:00:01] [done] HKLM\\...\\Run: [Bad] => C:\\bad.exe — удалить значение\n'
        'Итог: изменено 1, ошибок 0, вручную 0\n',
        encoding='utf-8')
    text = report_export.summary_markdown(
        created=datetime(2026, 11, 23, 22, 0, 0), duration=1.0, entries=1,
        fixlog=log)
    assert '## Последнее исправление' in text
    assert 'Итог: изменено 1' in text
    assert 'HKLM\\...\\Run: [Bad]' in text


def test_export_zip_contains_summary_and_reports(tmp_path):
    reports = tmp_path / 'Reports'
    reports.mkdir()
    (reports / names.REPORT).write_text('report', encoding='utf-8')
    (reports / names.JOURNAL).write_text('journal', encoding='utf-8')
    backup = reports / names.BACKUPS / '20261123_220000'
    backup.mkdir(parents=True)
    (backup / 'manifest.json').write_text('{"items": []}', encoding='utf-8')

    target = report_export.export_zip(tmp_path / 'support.zip', reports, 'summary')
    with zipfile.ZipFile(target) as archive:
        names_in_zip = set(archive.namelist())
    assert {'summary.md', names.REPORT, names.JOURNAL,
            'backup/manifest.json'} <= names_in_zip
    assert names.ADDITION not in names_in_zip
