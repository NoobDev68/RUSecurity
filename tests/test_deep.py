"""Тесты тщательного режима: риск-оценка, COM, ярлыки и слияние."""

import os
import sqlite3
import sys
import winreg
from pathlib import Path

import json

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity import analyzer, deep  # noqa: E402
from rusecurity.core import winapi  # noqa: E402
from rusecurity.core.context import ScanContext  # noqa: E402
from rusecurity.fixer import Fixer, actions as act  # noqa: E402
from rusecurity.fixer import parse_fixlist  # noqa: E402


def test_risk_scoring_finds_user_autostart():
    text = (r'HKLM\...\Run: [Bad] => C:\Users\u\AppData\Roaming\bad.exe '
            r'[123 2026-01-01] () [Файл не подписан]')
    items = deep.analyze_report(text)
    assert len(items) == 1
    assert items[0].category == 'Автозагрузка'
    assert items[0].recommended
    assert items[0].fix_line.startswith(r'HKLM\...\Run')


def test_risk_scoring_skips_signed_system_run():
    text = (r'HKLM\...\Run: [Good] => C:\Windows\System32\svchost.exe '
            r'[123 2026-01-01] (Microsoft Corporation)')
    assert deep.analyze_report(text) == []


def test_risk_scoring_flags_encoded_powershell():
    text = ('Task: {AAAA} - System32\\Tasks\\Bad => '
            'powershell -NoProfile -EncodedCommand AAAA '
            '[123 2026-01-01] (Microsoft Corporation)')
    items = deep.analyze_report(text)
    assert items
    assert 'подозрительная команда' in items[0].evidence


def test_risk_scoring_winlogon_active_setup_ifeo():
    text = '\n'.join([
        r'HKLM\...\Winlogon: [Shell] C:\Users\u\AppData\bad.exe '
        r'[123 2026-01-01] () [Файл не подписан]',
        r'HKLM\Software\Microsoft\Active Setup\Installed Components: '
        r'[{GUID}] -> C:\Users\u\AppData\bad.exe [123 2026-01-01] ()',
        r'IFEO\bad.exe: [Debugger] C:\Users\u\AppData\bad.exe '
        r'[123 2026-01-01] ()',
    ])
    items = deep.analyze_report(text)
    assert len(items) == 3
    assert all(not item.recommended for item in items)
    assert any(item.fix_line.startswith('CustomCLSID:') for item in items)
    assert any(item.fix_line.startswith('HKLM\\SOFTWARE\\Microsoft') for item in items)


def test_defender_exclusions_detected(monkeypatch):
    monkeypatch.setattr(deep.winapi, 'read_values',
                        lambda *args, **kwargs: {r'C:\Users\u\bad': 0})
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda *args, **kwargs: None)
    items = deep._defender()
    assert len(items) == 3
    assert all(item.fix_line.startswith('HKLM\\') for item in items)


def test_deep_file_roundtrip_and_report_match(tmp_path):
    report = tmp_path / 'rusecurity-report.txt'
    report.write_text('report', encoding='utf-8')
    other = tmp_path / 'other.txt'
    other.write_text('other', encoding='utf-8')
    item = deep.DeepItem('COM-перехват', 'HKCU\\...\\{X}', 'test',
                         'RegKey: HKCU\\Software\\Classes\\CLSID\\{X}',
                         act.REG_KEY, True)
    target = deep.save(tmp_path / 'rusecurity-deep.json', report, [item])
    loaded = deep.load(target, report)
    assert loaded == [item]
    assert deep.load(target, other) == []


def test_analyzer_merges_deep_fixlist(tmp_path):
    report = tmp_path / 'rusecurity-report.txt'
    report.write_text(
        'RUSecurity\n'
        '==================== Реестр Windows (Все) ====================\n'
        '==================== Конец отчёта RUSecurity ====================\n',
        encoding='utf-8')
    item = deep.DeepItem(
        'COM-перехват', 'HKCU\\Software\\Classes\\CLSID\\{X}', 'test',
        'RegKey: HKCU\\Software\\Classes\\CLSID\\{X}', act.REG_KEY, True)
    deep_path = deep.save(tmp_path / 'rusecurity-deep.json', report, [item])
    result = analyzer.analyze(report, deep_path=deep_path)
    assert 'RegKey: HKCU\\Software\\Classes\\CLSID\\{X}' in result.text
    assert result.fix_count == 1
    finding = result.findings[0]
    assert finding.fix.startswith('RegKey:')
    assert finding.manual is False


def test_deep_recommended_flag_reaches_finding(tmp_path):
    report = tmp_path / 'rusecurity-report.txt'
    report.write_text('RUSecurity\n', encoding='utf-8')
    item = deep.DeepItem('Сеть', 'Входящее правило: Legit', 'ev',
                         'FirewallRules: [Legit]', act.FIREWALL, False)
    deep_path = deep.save(tmp_path / 'rusecurity-deep.json', report, [item])
    result = analyzer.analyze(report, deep_path=deep_path)
    assert result.findings[0].recommended is False
    assert result.findings[0].manual is False


def test_genfix_findings_are_recommended_by_default():
    finding = analyzer.Finding('Реестр', 'text', act.REG_VALUE,
                               'значения реестра')
    assert finding.recommended is True


def test_deep_fixlist_inserted_before_reboot():
    text = 'Start::\nCreateRestorePoint:\nReboot:\nEnd::\n'
    merged = analyzer._merge_deep_fixlist(text, ['RegKey: HKCU\\Software\\X'])
    lines = merged.splitlines()
    assert lines.index('RegKey: HKCU\\Software\\X') < lines.index('Reboot:')


def test_parse_regkey_and_shortcut_clean():
    actions = parse_fixlist(
        'RegKey: HKCU\\Software\\Classes\\CLSID\\{X}\n'
        'ShortcutClean: C:\\Users\\u\\Desktop\\Chrome.lnk -> '
        'C:\\Program Files\\Chrome\\chrome.exe -> --profile-directory=Default')
    assert [a.kind for a in actions] == [act.REG_KEY, act.SHORTCUT_CLEAN]
    assert actions[0].path.endswith('{X}')
    assert actions[1].target.endswith('chrome.exe')
    assert actions[1].value == '--profile-directory=Default'


def test_parse_new_deep_actions():
    actions = parse_fixlist(
        'ProcessKill: 123|C:\\Users\\u\\AppData\\bad.exe\n'
        'BitsCancel: job-1\n'
        'WebData: CHR|C:\\Web Data|7|Bad engine\n'
        'ServiceQuote: HKLM\\SYSTEM\\CurrentControlSet\\Services\\X -> '
        '"C:\\Program Files\\X\\x.exe" -k')
    assert [a.kind for a in actions] == [
        act.PROCESS_KILL, act.BITS_CANCEL, act.WEB_DATA, act.SERVICE_QUOTE]
    assert actions[0].name == '123'
    assert actions[0].path.endswith('bad.exe')
    assert actions[2].browser == 'CHR'
    assert actions[2].name == '7'
    assert actions[3].value.startswith('"C:\\Program Files')


def test_new_actions_dry_run(tmp_path):
    from rusecurity.fixer import Fixer
    report = Fixer(tmp_path / 'backup', tmp_path / 'log.txt',
                   dry_run=True).run(
        'Start::\nProcessKill: 123|C:\\x.exe\nBitsCancel: job\nEnd::\n')
    assert len(report.outcomes) == 4
    assert report.outcomes[1].status == 'planned'
    assert report.outcomes[2].status == 'planned'


def test_service_quote_handler(tmp_path):
    from rusecurity.fixer import Fixer
    base = r'Software\RUSecurityTest\ServiceQuote'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base, 0,
                             winreg.KEY_SET_VALUE | winreg.KEY_READ)
    winreg.SetValueEx(key, 'ImagePath', 0, winreg.REG_EXPAND_SZ,
                      r'C:\Program Files\X\x.exe -k')
    winreg.CloseKey(key)
    try:
        line = (f'ServiceQuote: HKCU\\{base} -> '
                '"C:\\Program Files\\X\\x.exe" -k')
        report = Fixer(tmp_path / 'backup', tmp_path / 'log.txt',
                       create_restore_point=False).run(
            'Start::\n' + line + '\nEnd::\n')
        assert any(outcome.status == 'done' for outcome in report.outcomes)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base) as opened:
            assert winreg.QueryValueEx(opened, 'ImagePath')[0].startswith('"')
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base)


def test_extension_permissions(tmp_path, monkeypatch):
    profile = tmp_path / 'Default'
    extension = tmp_path / 'Ext'
    profile.mkdir()
    extension.mkdir()
    (profile / 'Preferences').write_text(json.dumps({
        'extensions': {'settings': {'abc': {
            'location': 4,
            'path': str(extension),
            'manifest': {'name': 'Bad extension',
                         'permissions': ['<all_urls>', 'webRequest']},
        }}},
    }), encoding='utf-8')
    monkeypatch.setattr(deep.browsers, 'chromium_profiles',
                        lambda: [(profile, 'CHR')])
    items = deep._extension_permissions()
    assert len(items) == 1
    assert items[0].fix_line.startswith('CHR Extension:')
    assert '<all_urls>' in items[0].evidence


def test_web_data_detection(tmp_path, monkeypatch):
    database = tmp_path / 'Web Data'
    connection = sqlite3.connect(database)
    connection.execute(
        'CREATE TABLE keywords (id INTEGER, short_name TEXT, keyword TEXT, '
        'url TEXT, prepopulate_id INTEGER)')
    connection.execute(
        "INSERT INTO keywords VALUES (1, 'Bad', 'bad', "
        "'http://ads.example/?q={searchTerms}', 0)")
    connection.execute(
        "INSERT INTO keywords VALUES (2, 'Google', 'google', "
        "'https://google.com/?q={searchTerms}', 1)")
    connection.commit()
    connection.close()
    monkeypatch.setattr(deep.browsers, 'chromium_profiles',
                        lambda: [(tmp_path, 'CHR')])
    items = deep._web_data()
    assert len(items) == 1
    assert 'Bad' in items[0].title
    assert items[0].fix_line.startswith('WebData: CHR|')


def test_web_data_handler(tmp_path, monkeypatch):
    from rusecurity.fixer import Fixer, browsers
    database = tmp_path / 'Web Data'
    connection = sqlite3.connect(database)
    connection.execute('CREATE TABLE keywords (id INTEGER, short_name TEXT, '
                       'keyword TEXT, url TEXT)')
    connection.execute("INSERT INTO keywords VALUES (1, 'Bad', 'bad', "
                       "'http://ads.example/?q={searchTerms}')")
    connection.commit()
    connection.close()
    monkeypatch.setattr(browsers, 'close', lambda _prefix: [])
    line = f'WebData: CHR|{database}|1|Bad'
    report = Fixer(tmp_path / 'backup', tmp_path / 'log.txt',
                   create_restore_point=False).run(
        'Start::\n' + line + '\nEnd::\n')
    assert any(outcome.status == 'done' for outcome in report.outcomes)
    connection = sqlite3.connect(database)
    try:
        assert connection.execute('SELECT COUNT(*) FROM keywords').fetchone()[0] == 0
    finally:
        connection.close()


def test_create_shortcut_roundtrip(tmp_path):
    target = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'notepad.exe'
    if not target.is_file():
        return
    link = tmp_path / 'test.lnk'
    assert winapi.create_shortcut(str(link), str(target), '--test')
    info = winapi.resolve_shortcut(str(link))
    assert info is not None
    assert Path(info.target) == target
    assert info.arguments == '--test'


def test_browser_policy_detected(monkeypatch):
    base = r'Software\RUSecurityTest\Policies\Chrome'
    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base, 0, winreg.KEY_WRITE)
    winreg.SetValueEx(key, 'HomepageLocation', 0, winreg.REG_SZ,
                      'http://ads.example')
    winreg.CloseKey(key)
    try:
        monkeypatch.setattr(deep, '_POLICY_PATHS',
                            ((winapi.HKCU, base, 'Test'),))
        items = deep._browser_policies()
        assert any('HomepageLocation' in item.title for item in items)
        assert any(item.fix_line.startswith('HKCU\\') for item in items)
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base)
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r'Software\RUSecurityTest\Policies')
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r'Software\RUSecurityTest')


def test_com_hijack_missing_file(tmp_path):
    guid = '{RUSECURITY-TEST-0000-0000-000000000001}'
    base = rf'Software\Classes\CLSID\{guid}'
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base, 0,
                            winreg.KEY_WRITE) as key:
        sub = winreg.CreateKeyEx(key, 'InprocServer32', 0, winreg.KEY_WRITE)
        winreg.SetValueEx(sub, '', 0, winreg.REG_SZ,
                          str(tmp_path / 'missing.dll'))
        winreg.CloseKey(sub)
    try:
        items = deep._com_hijacks(ScanContext())
        found = [item for item in items if guid in item.title]
        assert found
        assert found[0].recommended
        assert found[0].fix_line.startswith('RegKey:')
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                         base + r'\InprocServer32')
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, base)


def test_browser_shortcut_with_url(tmp_path):
    profile = tmp_path / 'profile'
    desktop = profile / 'Desktop'
    desktop.mkdir(parents=True)
    browser = tmp_path / 'chrome.exe'
    browser.write_bytes(b'MZ')
    link = desktop / 'Chrome.lnk'
    assert winapi.create_shortcut(str(link), str(browser), 'http://ads.example')
    ctx = ScanContext(sids=['S-1-5-21-test'], profiles={'S-1-5-21-test': str(profile)})
    items = deep._browser_shortcuts(ctx)
    found = [item for item in items if item.title.endswith('Chrome.lnk')]
    assert found
    assert found[0].fix_line.startswith('ShortcutClean:')
    assert 'ads.example' in found[0].evidence
    assert found[0].fix_line.rstrip().endswith('->')


def test_fixer_cleans_shortcut(tmp_path):
    browser = tmp_path / 'chrome.exe'
    browser.write_bytes(b'MZ')
    link = tmp_path / 'Chrome.lnk'
    assert winapi.create_shortcut(str(link), str(browser), 'http://ads.example')
    line = f'ShortcutClean: {link} -> {browser} -> '
    report = Fixer(tmp_path / 'backup', tmp_path / 'fixlog.txt',
                   create_restore_point=False).run(
        'Start::\n' + line + '\nEnd::\n')
    assert any(outcome.status == 'done' for outcome in report.outcomes)
    info = winapi.resolve_shortcut(str(link))
    assert info is not None
    assert info.arguments == ''
    assert (tmp_path / 'backup' / 'files').is_dir()


def test_payload_flags_missing_and_system(tmp_path):
    missing = tmp_path / 'missing.dll'
    path, flags, recommend = deep._payload_flags(str(missing))
    assert path == str(missing)
    assert 'файл отсутствует' in flags and recommend
    system = os.path.join(os.environ['SystemRoot'], 'System32', 'svchost.exe')
    if os.path.isfile(system):
        assert deep._payload_flags(system)[1] == []


def test_legacy_persistence_value_list(tmp_path, monkeypatch):
    binary = tmp_path / 'bad.exe'
    binary.write_bytes(b'MZ')
    monkeypatch.setattr(deep, '_LEGACY_VALUES', ())
    monkeypatch.setattr(deep, '_LEGACY_SUBKEYS', ())
    monkeypatch.setattr(deep, '_LEGACY_VALUE_LISTS',
                        ((deep._SESSION + r'\AppCertDlls', 'test'),))
    monkeypatch.setattr(deep.winapi, 'read_value', lambda *args, **kwargs: None)
    monkeypatch.setattr(deep.winapi, 'read_values',
                        lambda *args, **kwargs: {'Bad': str(binary)})
    monkeypatch.setattr(deep.winapi, 'enum_keys', lambda *args, **kwargs: [])
    items = deep._legacy_persistence()
    assert len(items) == 1
    item = items[0]
    assert item.kind == act.REG_VALUE
    assert item.fix_line.startswith(
        'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager'
        '\\AppCertDlls: [Bad]')
    assert 'нет подписи' in item.evidence
    action = parse_fixlist(item.fix_line)[0]
    assert action.kind == act.REG_VALUE
    assert action.name == 'Bad'


def test_legacy_bootexecute_default_skipped(monkeypatch):
    monkeypatch.setattr(deep, '_LEGACY_VALUE_LISTS', ())
    monkeypatch.setattr(deep, '_LEGACY_SUBKEYS', ())
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda root, key, name, *args: (
                            ['autocheck autochk *']
                            if name == 'BootExecute' else None))
    monkeypatch.setattr(deep.winapi, 'read_values', lambda *args, **kwargs: {})
    monkeypatch.setattr(deep.winapi, 'enum_keys', lambda *args, **kwargs: [])
    assert deep._legacy_persistence() == []


def test_lsa_packages(monkeypatch):
    monkeypatch.setattr(deep.winapi, 'enum_keys', lambda *args, **kwargs: [])
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda root, key, name, *args: (
                            ['baddll'] if name == 'Security Packages' else None))
    items = deep._lsa_extensions()
    assert len(items) == 1
    assert items[0].kind == act.MANUAL
    assert items[0].fix_line == ''
    assert 'DLL не найдена' in items[0].evidence


def test_lsa_system_package_skipped(monkeypatch):
    root = os.environ['SystemRoot']
    if not os.path.isfile(os.path.join(root, 'System32', 'scecli.dll')):
        return
    monkeypatch.setattr(deep.winapi, 'enum_keys', lambda *args, **kwargs: [])
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda root, key, name, *args: (
                            ['scecli'] if name == 'Security Packages' else None))
    assert deep._lsa_extensions() == []


def test_service_binary_outside_program_files(tmp_path, monkeypatch):
    binary = tmp_path / 'svc.exe'
    binary.write_bytes(b'MZ')
    monkeypatch.setattr(deep.winapi, 'enum_keys',
                        lambda *args, **kwargs: ['TestSvc'])
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda root, key, name, *args: (
                            f'"{binary}"' if name == 'ImagePath' else None))
    monkeypatch.setattr(deep, '_writable_dirs', lambda folders: set())
    items = deep._service_binaries()
    assert len(items) == 1
    assert items[0].kind == act.MANUAL
    assert 'нет подписи' in items[0].evidence
    monkeypatch.setattr(deep, '_writable_dirs',
                        lambda folders: {os.path.dirname(str(binary))})
    items = deep._service_binaries()
    assert 'папка доступна на запись' in items[0].evidence


def test_process_modules_temp_dll(tmp_path, monkeypatch):
    host = tmp_path / 'app.exe'
    host.write_bytes(b'MZ')
    nested = tmp_path / 'plugins'
    nested.mkdir()
    module = nested / 'bad.dll'
    module.write_bytes(b'MZ')
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'Pid': 4242, 'Process': 'app', 'Host': str(host),
         'Module': str(module)}])
    items = deep._process_modules()
    assert len(items) == 1
    assert items[0].kind == act.MANUAL
    assert 'нет подписи' in items[0].evidence
    assert str(module) in items[0].title


def test_firewall_rule_fixline(tmp_path, monkeypatch):
    program = tmp_path / 'bad.exe'
    program.write_bytes(b'MZ')
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'Name': 'BadRule', 'Display': 'Bad rule', 'Program': str(program)}])
    items = deep._firewall_rules()
    assert len(items) == 1
    assert items[0].fix_line == 'FirewallRules: [BadRule]'
    action = parse_fixlist(items[0].fix_line)[0]
    assert action.kind == act.FIREWALL
    assert action.name == 'BadRule'


def test_firewall_skips_system_program(monkeypatch):
    system = os.path.join(os.environ['SystemRoot'], 'System32', 'svchost.exe')
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'Name': 'Sys', 'Display': 'System', 'Program': 'System'},
        {'Name': 'Sys2', 'Display': 'system32', 'Program': system}])
    assert deep._firewall_rules() == []


def test_listening_ports_user_process(tmp_path, monkeypatch):
    program = tmp_path / 'srv.exe'
    program.write_bytes(b'MZ')
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'LocalPort': 8080, 'OwningProcess': 4321}])
    monkeypatch.setattr(deep.winapi, 'process_image_path',
                        lambda pid: str(program))
    items = deep._listening_ports()
    assert len(items) == 1
    assert '8080' in items[0].title
    assert items[0].kind == act.MANUAL


def test_routes_public_gateway(monkeypatch):
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'NextHop': '8.8.8.8', 'InterfaceAlias': 'WLAN', 'RouteMetric': 25},
        {'NextHop': '192.168.0.1', 'InterfaceAlias': 'Ethernet',
         'RouteMetric': 0}])
    items = deep._routes()
    assert len(items) == 1
    assert '8.8.8.8' in items[0].title
    assert 'WLAN' in items[0].evidence


def test_private_ip_ranges():
    assert deep._private_ip('10.1.2.3')
    assert deep._private_ip('172.16.0.1')
    assert deep._private_ip('192.168.1.1')
    assert deep._private_ip('169.254.10.1')
    assert deep._private_ip('100.64.0.1')
    assert not deep._private_ip('8.8.8.8')
    assert not deep._private_ip('203.0.113.5')
    assert deep._private_ip('::')


def test_static_dns_ignores_private_servers(monkeypatch):
    monkeypatch.setattr(deep.winapi, 'enum_keys', lambda *args, **kwargs: ['{X}'])
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda root, key, name, *args: (
                            '10.254.254.8' if name == 'NameServer' else None))
    assert deep._static_dns() == []


def test_static_dns_flags_public_server(monkeypatch):
    monkeypatch.setattr(deep.winapi, 'enum_keys', lambda *args, **kwargs: ['{X}'])
    monkeypatch.setattr(deep.winapi, 'read_value',
                        lambda root, key, name, *args: (
                            '8.8.8.8' if name == 'NameServer' else None))
    items = deep._static_dns()
    assert len(items) == 1
    assert items[0].title == 'DNS: 8.8.8.8'
    assert items[0].kind == act.MANUAL
    assert items[0].recommended is False


def test_duplicate_titles_keep_all_fix_lines():
    items = [
        deep.DeepItem('Сеть', 'Входящее правило: X', 'e',
                      'FirewallRules: [A]', act.FIREWALL, False),
        deep.DeepItem('Сеть', 'Входящее правило: X', 'e2',
                      'FirewallRules: [B]', act.FIREWALL, False),
    ]
    findings = analyzer._merge_deep_findings([], items)
    assert len(findings) == 1
    merged = analyzer._merge_deep_fixlist(
        'Start::\nEnd::\n', [item.fix_line for item in items])
    assert 'FirewallRules: [A]' in merged
    assert 'FirewallRules: [B]' in merged


def test_environment_override_system_var(monkeypatch):
    monkeypatch.setattr(deep.winapi, 'read_values',
                        lambda root, path, *args, **kwargs: (
                            {'ComSpec': r'C:\Users\u\cmd.exe'}
                            if root == winapi.HKCU else {}))
    items = deep._environment(ScanContext())
    assert len(items) == 1
    item = items[0]
    assert item.fix_line.startswith('HKCU\\Environment: [ComSpec]')
    assert item.kind == act.REG_VALUE
    assert item.recommended
    action = parse_fixlist(item.fix_line)[0]
    assert action.kind == act.REG_VALUE
    assert action.name == 'ComSpec'


def test_environment_ignores_ordinary_path(monkeypatch):
    monkeypatch.setattr(deep.winapi, 'read_values',
                        lambda root, path, *args, **kwargs: (
                            {'Path': r'C:\Tools;C:\Windows\System32'}
                            if root == winapi.HKCU else {}))
    assert deep._environment(ScanContext()) == []


def test_wmi_subscriptions_flags_suspicious(monkeypatch):
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'Class': 'CommandLineEventConsumer', 'Name': 'Updater',
         'Command': 'powershell.exe -NoProfile -EncodedCommand AAAA'}])
    items = deep._wmi_subscriptions()
    assert len(items) == 1
    assert items[0].kind == act.MANUAL
    assert 'подозрительная команда' in items[0].evidence
    assert 'Updater' in items[0].title


def test_wmi_subscriptions_skips_benign(monkeypatch):
    monkeypatch.setattr(deep, '_powershell_json', lambda *args, **kwargs: [
        {'Class': 'CommandLineEventConsumer', 'Name': 'LogRotate',
         'Command': r'C:\Windows\System32\wevtutil.exe cl Application'}])
    assert deep._wmi_subscriptions() == []
