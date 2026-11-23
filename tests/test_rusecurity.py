"""Тесты RUSecurity: формат отчётов, анализатор, портативные пути."""

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity import analyzer, config, names  # noqa: E402
from rusecurity.core import textfmt  # noqa: E402
from rusecurity.core.model import Report, heading  # noqa: E402


def test_heading_has_title_and_equals():
    line = heading('Процессы (Все)')
    assert line.startswith('=') and line.endswith('=')
    assert 'Процессы (Все)' in line
    assert len(line) >= 64


def test_report_writes_crlf_without_bom(tmp_path):
    report = Report(header=['Первая строка', 'Вторая строка', ''])
    report.add('Службы (Все)', ['R2 Test; C:\\x.exe'])
    target = report.write(tmp_path / 'rusecurity-report.txt')

    raw = target.read_bytes()
    assert not raw.startswith(b'\xef\xbb\xbf')
    assert b'\r\n' in raw
    assert b'\r\r\n' not in raw

    text = raw.decode('utf-8')
    assert 'Первая строка\r\nВторая строка\r\n' in text
    assert 'R2 Test; C:\\x.exe' in text


def test_command_suffix_for_missing_file():
    assert textfmt.command_suffix(r'C:\no\such\app.exe') == ' (Нет файла)'


def test_resolve_command_file_with_quoted_path(tmp_path):
    exe = tmp_path / 'App.exe'
    exe.write_bytes(b'MZ')
    command = f'"{exe}" --silent'
    path, exists = textfmt.resolve_command_file(command)
    assert exists
    assert Path(path) == exe


def test_resolve_command_file_without_quotes(tmp_path):
    exe = tmp_path / 'Tool.exe'
    exe.write_bytes(b'MZ')
    command = f'{exe} -arg'
    path, exists = textfmt.resolve_command_file(command)
    assert exists
    assert Path(path) == exe


def _write_report(tmp_path: Path, body: str) -> Path:
    path = tmp_path / 'rusecurity-report.txt'
    path.write_text(
        'Результат сканирования\n'
        '==================== Реестр Windows (Все) ==================\n'
        f'{body}\n'
        '==================== Конец от rusecurity-report.txt ==================\n',
        encoding='utf-8')
    return path


def test_analyzer_flags_dead_run_entry(tmp_path):
    report = _write_report(tmp_path, r'HKLM\...\Run: [BadApp] => C:\no\file.exe (Нет файла)')
    result = analyzer.analyze(report)
    assert result.fix_count == 1
    assert 'BadApp' in result.text
    assert 'CreateRestorePoint:' in result.text


def test_analyzer_reports_no_findings_for_clean_report(tmp_path):
    report = _write_report(tmp_path, r'HKLM\...\Run: [Good] => C:\Windows\System32\notepad.exe '
                                r'[100 2024-01-01] (Microsoft Corporation)')
    result = analyzer.analyze(report)
    assert result.text == ''
    assert result.fix_count == 0


def test_save_fixlist(tmp_path):
    target = analyzer.save_fixlist('Start::\r\nEnd::\r\n', tmp_path / 'fixlist.txt')
    assert target.read_bytes() == b'Start::\r\nEnd::\r\n'


def test_findings_have_categories_and_manual_flag():
    text = (
        'Start::\nCloseProcesses:\nCreateRestorePoint:\n'
        '; ---- Services / Drivers ----\n'
        'S3 Bad; C:\\bad.sys\n'
        '; ---- Shortcuts ----\n'
        'Shortcut: C:\\Users\\u\\Desktop\\Bad.lnk -> C:\\bad.exe (Нет файла)\n'
        'GroupPolicy: Ограничение ? <==== ВНИМАНИЕ\n'
        'EmptyTemp:\nReboot:\nEnd::\n')
    items = analyzer.findings(text)
    assert [item.kind for item in items] == ['service', 'shortcut', 'manual']
    assert items[0].category == 'Службы и драйверы'
    assert items[1].category == 'Ярлыки'
    assert items[1].kind_label == 'ярлыки'
    assert items[2].manual is True
    assert items[0].manual is False


def test_directives_are_read_from_analysis():
    text = ('Start::\nCloseProcesses:\nCreateRestorePoint:\nEmptyTemp:\n'
            'C:\\Windows\\Temp\\bad.exe\nEnd::\n')
    assert analyzer.directives(text) == {'restore_point': True,
                                         'close_processes': True,
                                         'empty_temp': True, 'reboot': False}


def test_close_processes_not_recommended_without_files():
    text = ('Start::\nCloseProcesses:\n'
            'HKLM\\...\\Run: [Bad] => C:\\x.exe (Нет файла)\nEnd::\n')
    assert analyzer.directives(text)['close_processes'] is False


def test_close_processes_recommended_for_extension_folder():
    text = ('Start::\nCloseProcesses:\n'
            'CHR Extension: (Adware) - C:\\Users\\u\\AppData\\Local\\Google\\'
            'Chrome\\User Data\\Default\\Extensions\\abc\nEnd::\n')
    assert analyzer.directives(text)['close_processes'] is True


def test_scan_options_defaults():
    from rusecurity.core import scanner

    options = scanner.ScanOptions()
    assert options.addition_enabled()
    assert len(options.enabled_labels()) == (len(scanner.REPORT_OPTIONS)
                                            + len(scanner.ADDITION_OPTIONS))
    without_addition = options.with_addition(False)
    assert not without_addition.addition_enabled()
    assert without_addition.processes is True


def test_build_report_respects_options(monkeypatch):
    from rusecurity.core import scanner
    from rusecurity.core.context import ScanContext

    monkeypatch.setattr(scanner, 'report_header', lambda ctx, launcher: ['header', ''])
    monkeypatch.setattr(scanner.system, 'processes', lambda ctx: ['P: test'])

    def boom(*_args, **_kwargs):
        raise AssertionError('отключённый раздел не должен вызываться')

    monkeypatch.setattr(scanner.registry, 'collect', boom)
    options = scanner.ScanOptions(**{
        name: False for name, _label in scanner.REPORT_OPTIONS + scanner.ADDITION_OPTIONS})
    options.processes = True
    report = scanner.build_report(ScanContext(), 'launcher', options)
    assert [section.title for section in report.sections] == [
        'Процессы (Все)', 'Конец отчёта RUSecurity']
    assert report.sections[0].lines == ['P: test']


def test_build_addition_respects_options(monkeypatch):
    from rusecurity.core import scanner
    from rusecurity.core.context import ScanContext

    monkeypatch.setattr(scanner, 'addition_header', lambda ctx, launcher: ['header', ''])
    monkeypatch.setattr(scanner.ads, 'collect', lambda ctx: ['AlternateDataStreams: x'])

    def boom(*_args, **_kwargs):
        raise AssertionError('отключённый раздел не должен вызываться')

    monkeypatch.setattr(scanner.addition, 'accounts', boom)
    options = scanner.ScanOptions(**{
        name: False for name, _label in scanner.REPORT_OPTIONS + scanner.ADDITION_OPTIONS})
    options.ads = True
    report = scanner.build_addition(ScanContext(), 'launcher', options)
    assert [section.title for section in report.sections] == [
        'Alternate Data Streams', 'Конец дополнительного отчёта']


def test_analyze_filters_security_center_without_programs(tmp_path):
    from rusecurity.core import scanner

    report = tmp_path / names.REPORT
    report.write_text(
        '==================== Реестр Windows (Все) ====================\n'
        r'HKLM\...\Run: [Bad] => C:\no\file.exe (Нет файла)' '\n'
        '==================== Конец отчёта RUSecurity ====================\n',
        encoding='utf-8')
    addition = tmp_path / names.ADDITION
    addition.write_text(
        '==================== Центр безопасности ====================\n'
        'AV: Kaspersky (Disabled - Out of date) '
        '{70E35457-C7D9-669C-FEA5-55382EABDC78}\n'
        '==================== Конец дополнительного отчёта ====================\n',
        encoding='utf-8')
    plain = analyzer.analyze(report, addition)
    assert 'Центр безопасности' in {item.category for item in plain.findings}
    filtered = analyzer.analyze(report, addition,
                                options=scanner.ScanOptions(programs=False))
    categories = {item.category for item in filtered.findings}
    assert 'Центр безопасности' not in categories
    assert 'Реестр' in categories


def test_journal_appends_and_loads(tmp_path):
    from rusecurity.journal import Journal

    journal = Journal(tmp_path / 'Reports' / 'rusecurity-journal.txt')
    line = journal.append('Сканирование начато')
    assert line.startswith('[')
    assert 'Сканирование начато' in line
    assert 'Сканирование начато' in journal.load()
    journal.clear()
    assert journal.load() == ''


def test_config_defaults_are_portable():
    settings = config.load()
    reports = Path(settings['reports_dir'])
    assert reports.is_absolute()
    assert reports.parent == config.APP_DIR


def test_names_are_own():
    assert names.REPORT == 'rusecurity-report.txt'
    assert names.ADDITION == 'rusecurity-add.txt'
    assert names.FIXLIST == 'rusecurity-fix.txt'


def test_resolve_addition_prefers_own_names(tmp_path):
    report = tmp_path / names.REPORT
    report.write_text('отчёт', encoding='utf-8')
    own = tmp_path / names.ADDITION
    own.write_text('доп', encoding='utf-8')
    legacy = tmp_path / names.LEGACY_RUSECURITY_ADDITION
    legacy.write_text('старое имя', encoding='utf-8')
    assert analyzer.resolve_addition(report) == own


def test_resolve_addition_accepts_old_rusecurity_name(tmp_path):
    report = tmp_path / names.REPORT
    report.write_text('отчёт', encoding='utf-8')
    legacy = tmp_path / names.LEGACY_RUSECURITY_ADDITION
    legacy.write_text('доп', encoding='utf-8')
    assert analyzer.resolve_addition(report) == legacy
