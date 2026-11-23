"""Тесты новых разделов и карантина: SigCheck, BCD, ассоциации, восстановление."""

import json
import sys
import winreg
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity import analyzer, names  # noqa: E402
from rusecurity.core.sections import association, bcd, sigcheck  # noqa: E402
from rusecurity.fixer import Fixer  # noqa: E402
from rusecurity.fixer import restore as quarantine  # noqa: E402


def _make_test_key() -> str:
    path = r'Software\RusecurityScanRestore'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, 'TestValue', 0, winreg.REG_SZ, 'payload')
    winreg.CloseKey(key)
    return path


def _drop_test_key(path: str) -> None:
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except OSError:
        pass


def test_sigcheck_section_format():
    lines = sigcheck.collect()
    assert lines[0] == sigcheck.NOTE
    assert any(line.lower().endswith('winlogon.exe') for line in lines)
    detail = next(line for line in lines if line.startswith('[') and ' - [' in line)
    assert detail.count(' - ') >= 2
    assert len(detail.rsplit(' ', 1)[-1]) == 32


def test_association_command_safety():
    assert association._command_is_safe('"%1" %*')
    assert association._command_is_safe('"%1" /S')
    assert association._command_is_safe('regedit.exe "%1"')
    assert association._command_is_safe('C:\\Windows\\System32\\wscript.exe "%1" %*')
    assert not association._command_is_safe('C:\\Temp\\evil.exe "%1"')
    assert not association._command_is_safe('regedit.exe')


def test_bcd_section_returns_lines_or_note():
    lines = bcd.collect()
    assert lines
    assert isinstance(bcd.testsigning_enabled(), bool)


def test_manifest_and_file_restore(tmp_path):
    reports = tmp_path
    backup = reports / 'Backups' / '20260101_120000'
    victim = tmp_path / 'dropper.exe'
    victim.write_bytes(b'MZ')
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False)
    fixer.run(str(victim))
    manifest = backup / 'manifest.json'
    assert manifest.is_file()
    data = json.loads(manifest.read_text(encoding='utf-8'))
    assert data['items'] and data['items'][0]['kind'] == 'file'
    assert not victim.exists()

    entries = quarantine.load_entries(reports)
    assert len(entries) == 1
    results = quarantine.restore_many(entries, tmp_path / 'restore-log.txt')
    assert results[0][1] == 'done'
    assert victim.read_bytes() == b'MZ'


def test_quarantine_delete_selected_and_clear(tmp_path):
    reports = tmp_path
    backup = reports / 'Backups' / '20260101_150000'
    victims = [tmp_path / 'one.exe', tmp_path / 'two.exe']
    for victim in victims:
        victim.write_bytes(b'MZ')
    Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False).run(
        '\n'.join(str(victim) for victim in victims))
    entries = quarantine.load_entries(reports)
    assert len(entries) == 2

    results = quarantine.delete_entries([entries[0]])
    assert results[0][1] == 'done'
    assert not entries[0].stored.exists()
    assert entries[1].stored.exists()
    assert len(quarantine.load_entries(reports)) == 1

    deleted, failed = quarantine.clear_quarantine(reports)
    assert (deleted, failed) == (1, 0)
    assert quarantine.load_entries(reports) == []
    assert not (reports / 'Backups').exists()


def test_manifest_and_registry_restore(tmp_path):
    reports = tmp_path
    backup = reports / 'Backups' / '20260101_130000'
    subkey = _make_test_key()
    try:
        fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False)
        fixer.run(r'HKCU\...\RusecurityScanRestore: [TestValue] payload')
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        try:
            with pytest.raises(OSError):
                winreg.QueryValueEx(key, 'TestValue')
        finally:
            winreg.CloseKey(key)

        entries = quarantine.load_entries(reports)
        assert entries and entries[0].kind == 'reg'
        results = quarantine.restore_many(entries, tmp_path / 'restore-log.txt')
        assert results[0][1] == 'done', results[0][1]
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        try:
            assert winreg.QueryValueEx(key, 'TestValue')[0] == 'payload'
        finally:
            winreg.CloseKey(key)
    finally:
        _drop_test_key(subkey)


def test_take_ownership_on_own_key(tmp_path):
    import winreg
    from rusecurity.core import winapi

    subkey = r'Software\RusecurityScanOwnership'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_WRITE)
    winreg.CloseKey(key)
    try:
        assert winapi.take_registry_ownership(winreg.HKEY_CURRENT_USER, subkey) is True
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, subkey)
        except OSError:
            pass


def test_compose_fixlist_directives():
    text = analyzer.compose_fixlist([r'HKLM\...\Run: [Bad] => C:\x.exe'],
                                    restore_point=False, close_processes=True,
                                    empty_temp=True, reboot=True)
    lines = text.splitlines()
    assert lines[0] == 'Start::'
    assert r'HKLM\...\Run: [Bad] => C:\x.exe' in lines
    assert lines[-1] == 'End::'
    assert 'CreateRestorePoint:' not in lines
    assert lines.index('CloseProcesses:') < lines.index(r'HKLM\...\Run: [Bad] => C:\x.exe')
    assert lines.index(r'HKLM\...\Run: [Bad] => C:\x.exe') < lines.index('EmptyTemp:')
    assert lines.index('EmptyTemp:') < lines.index('Reboot:')


def test_cli_restore_returns_file(tmp_path, monkeypatch):
    from rusecurity import cli
    from rusecurity.fixer import elevate

    reports = tmp_path
    backup = reports / 'Backups' / '20260101_140000'
    victim = tmp_path / 'bad.exe'
    victim.write_bytes(b'MZ')
    Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False).run(str(victim))
    assert not victim.exists()
    monkeypatch.setattr(elevate, 'is_admin', lambda: True)
    code = cli.main(['restore', str(backup), '--yes'])
    assert code == 0
    assert victim.read_bytes() == b'MZ'


def test_ads_entry_reaches_fixlist(tmp_path):
    frst = tmp_path / 'rusecurity-report.txt'
    frst.write_text(
        '==================== Службы (Все) ====================\n'
        'R2 Test; C:\\test.exe\n'
        '==================== Конец отчёта ====================\n',
        encoding='utf-8')
    addition = tmp_path / names.ADDITION
    addition.write_text(
        '==================== Alternate Data Streams ====================\n'
        r'AlternateDataStreams: C:\Temp\file.txt:secret [5]' '\n'
        '==================== Конец дополнительного отчёта ====================\n',
        encoding='utf-8')
    result = analyzer.analyze(frst, addition)
    assert 'AlternateDataStreams: C:\\Temp\\file.txt:secret [5]' in result.text
    assert 'EmptyTemp:' not in result.text


def test_fixer_deletes_ads(tmp_path):
    target = tmp_path / 'file.txt'
    target.write_text('data', encoding='utf-8')
    with open(f'{target}:probe', 'w', encoding='utf-8') as handle:
        handle.write('hidden')
    fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt',
                  create_restore_point=False)
    report = fixer.run(f'AlternateDataStreams: {target}:probe [6]')
    assert report.changed == 1
    from rusecurity.core.sections import ads
    names = {name.lower() for name, _size in ads._streams(str(target))}
    assert 'probe' not in names
    target.unlink()


def _write_manifest(backup: Path, created: str, items: list) -> None:
    backup.mkdir(parents=True, exist_ok=True)
    payload = {'created': created,
               'items': [dict(item, id=index + 1)
                         for index, item in enumerate(items)]}
    (backup / 'manifest.json').write_text(json.dumps(payload, ensure_ascii=False),
                                          encoding='utf-8')


def test_load_runs_lists_fixes_newest_first(tmp_path):
    reports = tmp_path
    old = reports / 'Backups' / '20260101_100000'
    _write_manifest(old, '2026-01-01 10:00:00', [
        {'kind': 'reg', 'original': r'HKLM\SOFTWARE\Test', 'stored': 'reg/test.reg'},
    ])
    new = reports / 'Backups' / '20260102_110000'
    _write_manifest(new, '2026-01-02 11:00:00', [
        {'kind': 'file', 'original': str(tmp_path / 'a.exe'), 'stored': 'files/a.exe'},
        {'kind': 'file', 'original': str(tmp_path / 'b.exe'), 'stored': 'files/b.exe'},
        {'kind': 'hosts', 'original': 'C:\\Windows\\hosts', 'stored': 'files/hosts'},
    ])
    runs = quarantine.load_runs(reports)
    assert [run.created for run in runs] == ['2026-01-02 11:00:00',
                                             '2026-01-01 10:00:00']
    assert runs[0].kinds == {'file': 2, 'hosts': 1}
    assert runs[0].total == 3
    assert runs[1].total == 1
    entries = quarantine.run_entries(runs[0])
    assert len(entries) == 3
    assert {entry.kind for entry in entries} == {'file', 'hosts'}
    assert all(entry.manifest == runs[0].manifest for entry in entries)


def test_load_runs_skips_broken_and_empty_manifests(tmp_path):
    reports = tmp_path
    broken = reports / 'Backups' / 'bad'
    broken.mkdir(parents=True)
    (broken / 'manifest.json').write_text('{not json', encoding='utf-8')
    empty = reports / 'Backups' / 'empty'
    _write_manifest(empty, '2026-01-03 12:00:00', [])
    assert quarantine.load_runs(reports) == []


def test_run_entries_restore_file(tmp_path):
    reports = tmp_path
    backup = reports / 'Backups' / '20260101_120000'
    victim = tmp_path / 'dropper.exe'
    victim.write_bytes(b'MZ')
    Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False).run(str(victim))
    assert not victim.exists()
    run = quarantine.load_runs(reports)[0]
    entries = quarantine.run_entries(run)
    assert [entry.kind for entry in entries] == ['file']
    results = quarantine.restore_many(entries, backup / 'restore-log.txt')
    assert [status for _entry, status in results] == ['done']
    assert victim.read_bytes() == b'MZ'


def _read_dword(notation: str, name: str):
    hives = {'HKCU': winreg.HKEY_CURRENT_USER, 'HKLM': winreg.HKEY_LOCAL_MACHINE}
    hive, subkey = notation.split('\\', 1)
    handle = winreg.OpenKey(hives[hive], subkey)
    try:
        return winreg.QueryValueEx(handle, name)[0]
    except FileNotFoundError:
        return None
    finally:
        winreg.CloseKey(handle)


def test_reg_set_without_previous_value_is_rollback_ready(tmp_path):
    """`Reg: reg add` в новый ключ должен попадать в откат (kind reg_new)."""
    notation = r'HKCU\Software\RusecurityScanRestore\Policies'
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                         r'Software\RusecurityScanRestore\Policies')
    except OSError:
        pass
    backup = tmp_path / 'Backups' / '20260101_150000'
    Fixer(backup, tmp_path / 'fixlog.txt',
          create_restore_point=False).run(
        f'Reg: reg add "{notation}" /v "TestValue" /t REG_DWORD /d "1" /f')
    assert _read_dword(notation, 'TestValue') == 1
    entries = quarantine.load_entries(tmp_path)
    assert [entry.kind for entry in entries] == ['reg_new']
    results = quarantine.restore_many(entries, backup / 'restore-log.txt')
    assert [status for _entry, status in results] == ['done']
    assert _read_dword(notation, 'TestValue') is None
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                     r'Software\RusecurityScanRestore\Policies')
