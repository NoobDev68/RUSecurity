"""Тесты фиксера: разбор fixlist, нотация реестра, бэкапы, применение."""

import sys
import winreg
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.fixer import Fixer, parse_fixlist  # noqa: E402
from rusecurity.fixer import actions as act  # noqa: E402
from rusecurity.fixer import registry  # noqa: E402


def kinds(text):
    return [action.kind for action in parse_fixlist(text)]


def test_parse_directives():
    assert kinds('Start::\nEnd::\nCloseProcesses:\nSystemRestore: On\n'
                 'CreateRestorePoint:\nEmptyTemp:\nReboot:\nHosts:\n') == [
        act.NOOP, act.NOOP, act.CLOSE_PROCESSES, act.NOOP, act.RESTORE_POINT,
        act.EMPTY_TEMP, act.REBOOT, act.HOSTS]


def test_empty_temp_clears_only_temp_folders(tmp_path, monkeypatch):
    from rusecurity.fixer import execute

    folder = tmp_path / 'Temp'
    folder.mkdir()
    (folder / 'installer.tmp').write_text('x', encoding='utf-8')
    nested = folder / 'nested'
    nested.mkdir()
    (nested / 'inner.txt').write_text('y', encoding='utf-8')
    cookies = tmp_path / 'Cookies'
    cookies.mkdir()
    (cookies / 'cookies.db').write_text('z', encoding='utf-8')

    monkeypatch.setattr(execute, '_TEMP_DIRS', (str(folder),))
    report = execute.Fixer(tmp_path / 'backup', tmp_path / 'log.txt',
                           create_restore_point=False).run(
        'Start::\nEmptyTemp:\nEnd::\n')
    assert report.changed >= 1
    assert not (folder / 'installer.tmp').exists()
    assert not nested.exists()
    assert (cookies / 'cookies.db').exists()


def test_parse_registry_value_and_key():
    actions = parse_fixlist(
        r'HKLM\...\Run: [Bad] => C:\x.exe (Нет файла)' '\n'
        r'HKLM\...\Policies\Explorer: [DisableTaskMgr] 1 <==== ВНИМАНИЕ' '\n'
        r'HKU\S-1-5-21-1-2-3-4\...\MountPoints2: {abc} - E:\setup.exe' '\n'
        r'CustomCLSID: HKU\S-1-5-21-1-2-3-4_Classes\CLSID\{GUID}\InprocServer32 -> C:\x.dll')
    assert [a.kind for a in actions] == [
        act.REG_VALUE, act.REG_VALUE, act.REG_KEY, act.REG_KEY]
    assert actions[0].path == r'HKLM\...\Run'
    assert actions[0].name == 'Bad'
    assert actions[1].name == 'DisableTaskMgr'
    assert actions[2].path.endswith('{abc}')
    assert actions[3].path.endswith('_Classes\\CLSID\\{GUID}')


def test_parse_system_entries():
    actions = parse_fixlist(
        r'Task: {AAAA} - System32\Tasks\Bad Task => C:\bad.exe' '\n'
        r'S3 BadService; C:\bad.sys [1 2024-01-01]' '\n'
        r'U4 DeadSvc; отсутствует ImagePath' '\n'
        r'FirewallRules: [TCP Query User{1}] => (Allow) C:\bad.exe' '\n'
        r'AV: Kaspersky (Disabled) {D68DDC3A-831F-4FAE-9E44-DA132C1ACF46}')
    assert [a.kind for a in actions] == [
        act.TASK, act.SERVICE, act.SERVICE, act.FIREWALL, act.SECURITY_PROVIDER]
    assert actions[0].name == 'Bad Task'
    assert actions[1].name == 'BadService'
    assert actions[4].name == 'AV'
    assert actions[4].guid == '{D68DDC3A-831F-4FAE-9E44-DA132C1ACF46}'


def test_schedule_reboot_command(monkeypatch):
    from rusecurity.fixer import execute

    calls = []

    class Result:
        returncode = 0

    monkeypatch.setattr(execute, '_run',
                        lambda command, timeout=60: calls.append(command) or Result())
    assert execute.schedule_reboot(45) is True
    assert calls[0][:4] == ['shutdown', '/r', '/t', '45']


def test_parse_files_shortcuts_ads():
    actions = parse_fixlist(
        r'Shortcut: C:\Users\u\Desktop\Bad.lnk -> C:\bad.exe' '\n'
        r'ShortcutWithArgument: C:\Users\u\Desktop\Bad.lnk -> C:\bad.exe -> -x' '\n'
        r'CHR Extension: (Adware) - C:\Users\u\AppData\Local\Google\Chrome\User Data\Default\Extensions\abc [2024-01-01]' '\n'
        r'AlternateDataStreams: C:\ProgramData\Temp:9E00596C [392]' '\n'
        r'C:\Users\u\Desktop\dropper.exe')
    assert [a.kind for a in actions] == [
        act.SHORTCUT, act.SHORTCUT, act.EXTENSION, act.ADS, act.FILE]
    assert actions[2].path.endswith('\\abc')
    assert actions[2].browser == 'CHR'
    assert actions[3].path == r'C:\ProgramData\Temp'
    assert actions[3].name == '9E00596C'


def test_parse_reg_add_and_unknown():
    actions = parse_fixlist(
        'Reg: reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" '
        '/v "SmartScreenEnabled" /t REG_SZ /d "Warn" /f\n'
        'ContextMenuHandlers1: [x] -> {y} => C:\\x.dll\n'
        'GroupPolicy: Ограничение ? <==== ВНИМАНИЕ')
    assert actions[0].kind == act.REG_SET
    assert actions[0].name == 'SmartScreenEnabled'
    assert actions[0].reg_type == 'REG_SZ'
    assert actions[1].kind == act.MANUAL
    assert actions[2].kind == act.MANUAL


def test_parse_hidden_program_line():
    actions = parse_fixlist(
        r'Rus Test Adblock Shield (HKLM\...\RusSecurityTestHidden) '
        r'(Version: 1.0 - Rus Test) Hidden')
    assert actions[0].kind == act.REG_KEY
    assert actions[0].path == r'HKLM\...\RusSecurityTestHidden'

    actions = parse_fixlist(
        r'Foo (64-bit) (HKCU\...\Bar) (Version: 1.0 - Test) Hidden')
    assert actions[0].kind == act.REG_KEY
    assert actions[0].path == r'HKCU\...\Bar'


def test_notation_resolution():
    hive, sub = registry.split_notation(r'HKLM\...\Run')
    assert hive == 'HKLM'
    assert sub == r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    hive, sub = registry.split_notation(r'HKLM-x32\...\Run')
    assert hive == 'HKLM'
    assert sub == r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
    hive, sub = registry.split_notation(r'HKU\S-1-5-21-1\...\Run')
    assert hive == 'HKU'
    assert sub == r'S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run'
    hive, sub = registry.split_notation(r'HKCU\...\Run')
    assert hive == 'HKCU'
    assert sub == r'Software\Microsoft\Windows\CurrentVersion\Run'


def test_notation_dots_for_mountpoints2():
    path = r'Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\RusecurityTest'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
    winreg.CloseKey(key)
    try:
        hive, sub = registry.split_notation(r'HKCU\...\MountPoints2\RusecurityTest')
        assert (hive, sub) == ('HKCU', path)
    finally:
        _drop_test_key(path)


def test_notation_dots_for_uninstall():
    path = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\RusecurityHiddenTest'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
    winreg.CloseKey(key)
    try:
        hive, sub = registry.split_notation(r'HKCU\...\RusecurityHiddenTest')
        assert (hive, sub) == ('HKCU', path)
    finally:
        _drop_test_key(path)


def test_delete_value_missing_key_is_not_found():
    assert registry.delete_value(r'HKCU\...\RusecurityNoSuchKey', 'X') == 'not_found'


def _make_test_key() -> str:
    path = r'Software\RusecurityScanTest'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, 'TestValue', 0, winreg.REG_SZ, 'payload')
    winreg.CloseKey(key)
    return path


def _drop_test_key(path: str) -> None:
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_SET_VALUE)
    except OSError:
        return
    try:
        winreg.DeleteValue(key, 'TestValue')
    except OSError:
        pass
    finally:
        winreg.CloseKey(key)
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except OSError:
        pass


def test_registry_value_deleted_with_backup(tmp_path):
    subkey = _make_test_key()
    try:
        text = r'HKCU\...\RusecurityScanTest: [TestValue] payload'
        fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt',
                      create_restore_point=False)
        report = fixer.run(text)
        assert report.changed == 1
        assert not report.failed
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        try:
            with pytest.raises(OSError):
                winreg.QueryValueEx(key, 'TestValue')
        finally:
            winreg.CloseKey(key)
        assert list((tmp_path / 'backups' / 'reg').glob('*.reg'))
    finally:
        _drop_test_key(subkey)


def test_registry_value_under_current_version_deleted(tmp_path):
    path = r'Software\Microsoft\Windows\CurrentVersion\RusecurityFixerTest'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, 'TestValue', 0, winreg.REG_SZ, 'payload')
    winreg.CloseKey(key)
    try:
        fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt',
                      create_restore_point=False)
        report = fixer.run(r'HKCU\...\RusecurityFixerTest: [TestValue] payload')
        assert report.changed == 1
        assert not report.failed
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
        try:
            with pytest.raises(OSError):
                winreg.QueryValueEx(key, 'TestValue')
        finally:
            winreg.CloseKey(key)
    finally:
        _drop_test_key(path)


def test_hidden_program_key_deleted(tmp_path):
    path = r'Software\Microsoft\Windows\CurrentVersion\Uninstall\RusecurityHiddenTest'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE)
    winreg.CloseKey(key)
    try:
        fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt',
                      create_restore_point=False)
        report = fixer.run(
            r'Rus Test Adblock Shield (HKCU\...\RusecurityHiddenTest) '
            r'(Version: 1.0 - Rus Test) Hidden')
        assert report.changed == 1
        assert not report.failed
        assert not registry.exists(r'HKCU\...\RusecurityHiddenTest')
    finally:
        _drop_test_key(path)


def test_dry_run_changes_nothing(tmp_path):
    subkey = _make_test_key()
    try:
        text = r'HKCU\...\RusecurityScanTest: [TestValue] payload'
        fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt', dry_run=True)
        report = fixer.run(text)
        assert report.outcomes[0].status == 'planned'
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey)
        try:
            assert winreg.QueryValueEx(key, 'TestValue')[0] == 'payload'
        finally:
            winreg.CloseKey(key)
        assert not (tmp_path / 'backups').exists()
    finally:
        _drop_test_key(subkey)


def test_file_quarantined(tmp_path):
    victim = tmp_path / 'dropper.exe'
    victim.write_bytes(b'MZ')
    backup = tmp_path / 'backups'
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False)
    report = fixer.run(str(victim))
    assert report.changed == 1
    assert not victim.exists()
    quarantined = list((backup / 'files').rglob('dropper.exe'))
    assert quarantined and quarantined[0].read_bytes() == b'MZ'


def test_hosts_skips_when_nothing_suspicious(tmp_path):
    hosts = tmp_path / 'hosts'
    original = '0.0.0.0 example.com\n'
    hosts.write_text(original, encoding='utf-8')
    backup = tmp_path / 'backups'
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False,
                  hosts_path=hosts)
    report = fixer.run('Hosts:')
    assert report.changed == 0
    assert hosts.read_text(encoding='utf-8') == original
    assert not (backup / 'manifest.json').exists()


def test_hosts_created_when_missing(tmp_path):
    hosts = tmp_path / 'missing-hosts'
    fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt',
                  create_restore_point=False, hosts_path=hosts)
    report = fixer.run('Hosts:')
    assert report.changed == 1
    assert '127.0.0.1 localhost' in hosts.read_text(encoding='utf-8')


def test_hosts_removes_only_suspicious_and_restores(tmp_path):
    import json

    from rusecurity.fixer import restore as quarantine

    hosts = tmp_path / 'hosts'
    original = ('127.0.0.1 localhost\n'
                '0.0.0.0 google.com\n'
                '192.168.1.10 nas.local\n')
    hosts.write_text(original, encoding='utf-8')
    backup = tmp_path / 'Reports' / 'Backups' / 'run'
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False,
                  hosts_path=hosts)
    report = fixer.run('Hosts:')
    assert report.changed == 1
    text = hosts.read_text(encoding='utf-8')
    assert 'google.com' not in text
    assert 'nas.local' in text
    assert '127.0.0.1 localhost' in text
    manifest = json.loads((backup / 'manifest.json').read_text(encoding='utf-8'))
    assert manifest['items'][0]['kind'] == 'hosts'

    entries = quarantine.load_entries(tmp_path / 'Reports')
    assert [entry.kind for entry in entries] == ['hosts']
    results = quarantine.restore_many(entries, tmp_path / 'restore.log')
    assert results[0][1] == 'done'
    assert hosts.read_text(encoding='utf-8') == original


def test_close_processes_only_for_deleted_files(tmp_path, monkeypatch):
    import os
    from rusecurity.core import winapi

    victim = tmp_path / 'dropper.exe'
    victim.write_bytes(b'MZ')
    other = tmp_path / 'other.exe'
    other.write_bytes(b'MZ')
    processes = [
        winapi.ProcessInfo(pid=100, parent_pid=1, name='dropper.exe', path=''),
        winapi.ProcessInfo(pid=101, parent_pid=1, name='other.exe', path=''),
        winapi.ProcessInfo(pid=os.getpid(), parent_pid=1, name='python.exe', path=''),
    ]
    images = {100: str(victim), 101: str(other), os.getpid(): str(victim)}
    monkeypatch.setattr(winapi, 'list_processes', lambda: processes)
    monkeypatch.setattr(winapi, 'process_image_path', lambda pid: images.get(pid, ''))
    terminated = []
    monkeypatch.setattr(winapi, 'terminate_process',
                        lambda pid: terminated.append(pid) or True)

    fixer = Fixer(tmp_path / 'backups', tmp_path / 'fixlog.txt',
                  create_restore_point=False)
    report = fixer.run('CloseProcesses:\n' + str(victim))
    assert terminated == [100]
    assert report.changed == 1
    assert not victim.exists()
    log = (tmp_path / 'fixlog.txt').read_text(encoding='utf-8')
    assert 'закрыто процессов: 1' in log


def test_cli_apply_runs_fixer(tmp_path, monkeypatch):
    from rusecurity import cli
    from rusecurity.fixer import elevate

    subkey = _make_test_key()
    try:
        victim = tmp_path / 'bad.exe'
        victim.write_bytes(b'MZ')
        fixlist = tmp_path / 'fixlist.txt'
        fixlist.write_text(
            r'HKCU\...\RusecurityScanTest: [TestValue] payload' + '\n' + str(victim),
            encoding='utf-8')
        monkeypatch.setattr(elevate, 'is_admin', lambda: True)
        code = cli.main(['apply', str(fixlist), '--yes',
                         '--log', str(tmp_path / 'log.txt'),
                         '--backup-dir', str(tmp_path / 'backups'),
                         '--no-restore-point'])
        assert code == 0
        log = (tmp_path / 'log.txt').read_text(encoding='utf-8')
        assert 'изменено 2' in log
        assert not victim.exists()
    finally:
        _drop_test_key(subkey)
