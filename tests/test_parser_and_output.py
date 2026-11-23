"""Регрессионные тесты парсера, формата fixlist и выбора исправлений."""

import os
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))


# ===================================================================
# Parser
# ===================================================================

class TestParserSections:
    def test_russian_sections(self, tmp_path):
        from report_parser import parse_report

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==================== Реестр Windows (В белом списке) ===================\n'
            'HKLM\\...\\Run: [Bad] => C:\\bad.exe (Нет файла) <==== ВНИМАНИЕ\n'
            '==================== Запланированные задачи ===================\n'
            'Task: {11111111-2222-3333-4444-555555555555} - System32\\Tasks\\Bad\n',
            encoding='utf-8',
        )
        parsed = parse_report(str(report))
        assert 'registry' in parsed['sections']
        assert 'tasks' in parsed['sections']
        run_entry = next(e for e in parsed['entries'] if e['is_run_key'])
        assert run_entry['section'] == 'registry'
        assert run_entry['has_caution'] is True
        assert run_entry['has_no_file'] is True

    def test_english_sections_and_flags(self, tmp_path):
        from report_parser import parse_report

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==================== Registry (Whitelisted) ===================\n'
            'HKLM\\...\\Run: [Bad] => C:\\bad.exe (No File) <==== ATTENTION '
            '[File not signed]\n'
            '==================== Services ===================\n'
            'S2 BadService; C:\\bad.sys [X]\n',
            encoding='utf-8',
        )
        parsed = parse_report(str(report))
        run_entry = next(e for e in parsed['entries'] if e['is_run_key'])
        assert run_entry['has_caution'] is True
        assert run_entry['has_no_file'] is True
        assert run_entry['has_unsigned'] is True
        service = next(e for e in parsed['entries'] if e['is_service_entry'])
        assert service['has_x_marker'] is True

    def test_runonce_is_run_key(self, tmp_path):
        from report_parser import parse_report

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==================== Реестр Windows ===================\n'
            'HKLM\\...\\RunOnce: [Bad] => C:\\bad.exe (Нет файла)\n',
            encoding='utf-8',
        )
        parsed = parse_report(str(report))
        entry = next(e for e in parsed['entries'] if 'RunOnce' in e['normalized'])
        assert entry['is_run_key'] is True

    def test_no_file_arrow_marker(self, tmp_path):
        from report_parser import parse_report

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==================== Запланированные задачи ===================\n'
            'Task: {11111111-2222-3333-4444-555555555555} - System32\\Tasks\\Bad -> Нет файла\n'
            '==================== Internet ===================\n'
            'Edge HomePage: Default -> https://example.com (No File)\n',
            encoding='utf-8',
        )
        parsed = parse_report(str(report))
        task = next(e for e in parsed['entries'] if e['is_task_entry'])
        assert task['has_no_file'] is True
        homepage = next(e for e in parsed['entries'] if e['is_browser_homepage'])
        assert homepage['has_no_file'] is True

    def test_additional_sections_bilingual(self, tmp_path):
        from report_parser import parse_addition

        ru = tmp_path / 'Addition_ru.txt'
        ru.write_text(
            '==================== Правила Брандмауэра (В белом списке) ===========\n'
            'FirewallRules: [TCP] => (Allow) C:\\bad.exe => Нет файла\n',
            encoding='utf-8',
        )
        en = tmp_path / 'Addition_en.txt'
        en.write_text(
            '==================== Firewall Rules (Whitelisted) ===================\n'
            'FirewallRules: [TCP] => (Allow) C:\\bad.exe => No File\n',
            encoding='utf-8',
        )
        for path in (ru, en):
            parsed = parse_addition(str(path))
            assert 'firewall_rules' in parsed['sections']
            entry = next(e for e in parsed['entries'] if e['is_firewall_rule'])
            assert 'FirewallRules:' in entry['normalized']

    def test_parse_fixlist_skips_bom_and_kod(self, tmp_path):
        from report_parser import parse_fixlist

        fixlist = tmp_path / 'fixlist.txt'
        fixlist.write_bytes(
            b'\xef\xbb\xbf' + 'Код:\r\nStart::\r\nHKLM\\...\\Run: [Bad]\r\nEnd::\r\n'.encode('utf-8')
        )
        actions = parse_fixlist(str(fixlist))
        assert actions[0] == 'Start::'
        assert 'Код:' not in actions
        assert any('Bad' in a for a in actions)

    def test_parse_fixlist_utf16(self, tmp_path):
        from report_parser import is_boilerplate_action, parse_fixlist

        fixlist = tmp_path / 'fixlist.txt'
        fixlist.write_bytes(
            'Start::\r\nstartbatch:\r\nsfc /scannow\r\nendbatch:\r\nEnd::\r\n'.encode('utf-16')
        )
        actions = parse_fixlist(str(fixlist))
        assert 'Start::' in actions
        assert 'sfc /scannow' in actions
        assert is_boilerplate_action('startbatch:')
        assert is_boilerplate_action('endbatch:')


class TestEncodingDetection:
    def test_utf8_sig(self, tmp_path):
        from report_parser import detect_encoding
        path = tmp_path / 'a.txt'
        path.write_bytes(b'\xef\xbb\xbfhello')
        assert detect_encoding(path) == 'utf-8-sig'

    def test_utf16(self, tmp_path):
        from report_parser import detect_encoding
        path = tmp_path / 'a.txt'
        path.write_bytes('привет'.encode('utf-16'))
        assert detect_encoding(path) == 'utf-16'

    def test_cp1251(self, tmp_path):
        from report_parser import detect_encoding
        path = tmp_path / 'a.txt'
        path.write_bytes('привет'.encode('cp1251'))
        assert detect_encoding(path) == 'cp1251'

    def test_cp1251_report_is_converted_to_utf8_fixlist(self, tmp_path):
        import GenFix

        report = tmp_path / 'rusecurity-report.txt'
        report.write_bytes((
            '==================== Реестр Windows ===================\n'
            'Task: Bad => C:\\Users\\Иван\\bad.exe (Нет файла) <==== ВНИМАНИЕ\n'
        ).encode('cp1251'))
        output = tmp_path / 'fixlist.txt'
        result = GenFix.generate_fixlist(
            str(report), output_path=str(output),
        )
        assert 'Иван' in result
        assert 'Иван' in output.read_text(encoding='utf-8')


# ===================================================================
# fixlist format / generation
# ===================================================================

def _generate(tmp_path, report_text, addition_text=None, **kwargs):
    import GenFix

    report = tmp_path / 'rusecurity-report.txt'
    report.write_text(report_text, encoding='utf-8')
    if addition_text is not None:
        (tmp_path / 'rusecurity-add.txt').write_text(addition_text, encoding='utf-8')
    output = tmp_path / 'fixlist.txt'
    result = GenFix.generate_fixlist(
        str(report), output_path=str(output), **kwargs
    )
    return result, output


class TestFixlistFormat:
    def test_english_report_end_to_end(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==================== Registry ===================\n'
            'HKLM\\...\\Run: [Bad] => C:\\bad.exe (No File) <==== ATTENTION\n',
            '==================== Firewall Rules ===================\n'
            'FirewallRules: [TCP{1}C:\\Users\\u\\AppData\\Local\\Temp\\bad.exe] => '
            '(Allow) C:\\Users\\u\\AppData\\Local\\Temp\\bad.exe => No File\n',
        )
        assert 'HKLM\\...\\Run: [Bad]' in result
        assert 'AppData\\Local\\Temp\\bad.exe' in result

    def test_custom_clsid_missing_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Пользовательские CLSID ===================\n'
            'CustomCLSID: HKU\\S-1-5-21-1-2-3-1001_Classes\\CLSID\\'
            '{11111111-2222-3333-4444-555555555555}\\InprocServer32 -> '
            'C:\\Users\\u\\AppData\\Local\\Microsoft\\EdgeUpdate\\1.3.1\\psuser_64.dll => Нет файла\n',
        )
        assert 'CustomCLSID:' in result
        assert 'Custom CLSID / Shell Extensions' in result

    def test_context_menu_handler_missing_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Пользовательские CLSID ===================\n'
            'ContextMenuHandlers5: [ACE] -> {5E2121EE-0300-11D4-8D3B-444553540000} =>  -> Нет файла\n',
        )
        assert 'ContextMenuHandlers5:' in result

    def test_services_u4_and_missing_file(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==================== Службы ===================\n'
            'U4 npcap_wifi; отсутствует ImagePath\n'
            'R4 AMDRyzenMasterDriverV20; \\??\\C:\\Windows\\system32\\AMDRyzenMasterDriver.sys (Нет файла)\n',
        )
        assert 'U4 npcap_wifi' in result
        assert 'R4 AMDRyzenMasterDriverV20' in result

    def test_shortcut_missing_in_downloads(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Ярлыки & WMI ===================\n'
            'Shortcut: C:\\Users\\u\\Desktop\\Install.lnk -> C:\\Users\\u\\Downloads\\startup (1).exe '
            '(Нет файла) <==== Cyrillic\n'
            'Shortcut: C:\\Users\\u\\Desktop\\Game.lnk -> E:\\Games\\game.exe '
            '(Нет файла) <==== Cyrillic\n',
        )
        assert 'Install.lnk' in result
        assert 'Game.lnk' not in result

    def test_run_key_with_broken_command(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Registry ====\n'
            'HKU\\S-1-5-21-1-2-3-1001\\...\\Run: [Numpad_1.7.1] => [X]\n',
        )
        assert 'Numpad_1.7.1' in result

    def test_local_pac_proxy_only_review_comment(self, tmp_path, caplog):
        result, output = _generate(
            tmp_path,
            '==== Internet ====\n'
            'AutoConfigURL: [{11111111-2222-3333-4444-555555555555}] => '
            'hxxp://127.0.0.1:1080/pac?hash=abc <==== ВНИМАНИЕ\n',
        )
        assert result == ''
        assert not output.exists()
        assert 'проверьте вручную' in caplog.text.lower()

    def test_local_dns_only_review_comment(self, tmp_path, caplog):
        result, output = _generate(
            tmp_path,
            '==== Internet ====\n'
            'Tcpip\\..\\Interfaces\\{11111111-2222-3333-4444-555555555555}: [NameServer] 127.0.0.1\n',
        )
        assert result == ''
        assert not output.exists()
        assert 'проверьте вручную' in caplog.text.lower()

    def test_dead_microsoft_task_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Scheduled Tasks ====\n'
            'Task: {11111111-2222-3333-4444-555555555555} - '
            'System32\\Tasks\\Microsoft\\Windows\\UpdateOrchestrator\\USO_UxBroker => '
            '%systemroot%\\system32\\MusNotification.exe (Нет файла)\n',
        )
        assert 'USO_UxBroker' in result

    def test_dead_onedrive_overlay_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Registry ====\n'
            'ShellIconOverlayIdentifiers: [ OneDrive1] -> '
            '{BBACC218-34EA-4666-9D7A-C78F2274A524} => -> Нет файла\n',
        )
        assert 'OneDrive1' in result

    def test_policy_restriction_not_skipped(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Другие области ===================\n'
            'HKLM\\SOFTWARE\\Policies\\Mozilla\\Firefox: Ограничение <==== ВНИМАНИЕ\n',
        )
        assert 'Policies\\Mozilla\\Firefox' in result

    def test_unknown_extension_caution_not_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Chrome ====\n'
            'CHR Extension: (Adblock - блокировка рекламы) - '
            'C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\abc '
            '<==== ВНИМАНИЕ\n',
        )
        assert 'Adblock' not in result

    def test_manual_proxies_review_comment(self, tmp_path, caplog):
        result, output = _generate(
            tmp_path,
            '==== Internet ====\n'
            'ManualProxies: 0hxxp://127.0.0.1:10224/proxy.pac <==== ВНИМАНИЕ\n',
        )
        assert result == ''
        assert not output.exists()
        assert 'проверьте вручную' in caplog.text.lower()

    def test_dead_bho_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n'
            'BHO-x32: IEToEdge BHO -> {1FD49718-1D00-4B19-AF5F-070AF6D5D54C} -> '
            'C:\\Program Files (x86)\\Microsoft\\Edge\\BHO\\ie_to_edge_bho.dll => Нет файла\n',
        )
        assert 'IEToEdge BHO' in result

    def test_numbered_context_menu_handler_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Пользовательские CLSID ===================\n'
            'ContextMenuHandlers2: [Kaspersky] -> {AE776072-9FCA-48AF-941C-5759266BB644} => '
            'C:\\Program Files (x86)\\Kaspersky\\shellex.dll -> Нет файла\n',
        )
        assert 'ContextMenuHandlers2' in result

    def test_ff_plugin_hku_missing_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n'
            'FF Plugin HKU\\S-1-5-21-1-2-3-1001: ubisoft.com/uplaypc -> '
            'C:\\Program Files (x86)\\Ubisoft\\npuplaypc.dll [Нет файла]\n',
        )
        assert 'uplaypc' in result

    def test_dcomlaunch_missing_path_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Services ====\n'
            'DcomLaunch: u824334 -> отсутствует путь к файлу.\n',
        )
        assert 'DcomLaunch' in result

    def test_settings_page_visibility_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Другие области ===================\n'
            'HKLM\\...\\Policies\\Explorer: [SettingsPageVisibility] hide:\n',
        )
        assert 'SettingsPageVisibility' in result

    def test_no_kod_marker_and_trailing_newline(self, tmp_path):
        result, output = _generate(tmp_path, '==== Registry ====\n')
        assert result == ''
        assert not output.exists()

    def test_sections_sorted_numerically(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Registry ====\n'
            'HKLM\\...\\Run: [Bad] => C:\\bad.exe (Нет файла)\n'
            '==== Scheduled Tasks ====\n'
            'Task: {11111111-2222-3333-4444-555555555555} - System32\\Tasks\\Bad '
            '=> C:\\bad.exe <==== ВНИМАНИЕ\n',
        )
        assert result.index('; ---- Registry (HKLM) ----') < result.index('; ---- Scheduled Tasks ----')

    def test_shell_overlay_dead_flagged_live_kept(self, tmp_path):
        dead, _ = _generate(
            tmp_path,
            '==== Registry ====\n'
            'ShellIconOverlayIdentifiers: [ AccExtIco1] -> '
            '{11111111-2222-3333-4444-555555555555} => -> Нет файла\n',
        )
        assert 'AccExtIco1' in dead

        live, _ = _generate(
            tmp_path,
            '==== Registry ====\n'
            'ShellIconOverlayIdentifiers: [ AccExtIco2] -> '
            '{22222222-3333-4444-5555-666666666666} => '
            'C:\\Program Files\\App\\ext.dll\n',
        )
        assert 'AccExtIco2' not in live

    def test_firewall_flags_suspicious_and_port_only(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n',
            '==================== Firewall Rules ===================\n'
            'FirewallRules: [TCP{1}C:\\Program Files\\App\\app.exe] => (Allow) '
            'C:\\Program Files\\App\\app.exe => Нет файла\n'
            'FirewallRules: [TCP{2}C:\\Users\\u\\AppData\\Local\\Temp\\bad.exe] => (Allow) '
            'C:\\Users\\u\\AppData\\Local\\Temp\\bad.exe => Нет файла\n'
            'FirewallRules: [TCP{3}D:\\Games\\Old\\launcher.exe] => (Allow) '
            'D:\\Games\\Old\\launcher.exe => Нет файла\n'
            'FirewallRules: [{4}] => (Allow) LPort=445\n',
        )
        assert 'C:\\Program Files\\App\\app.exe' not in result
        assert 'AppData\\Local\\Temp\\bad.exe' in result
        assert 'D:\\Games\\Old\\launcher.exe' not in result
        assert 'LPort=445' in result

    def test_browser_search_only_malicious_domains(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Internet ====\n'
            'CHR DefaultSearchURL: Default -> hxxp://yandex.ru/search?text={searchTerms}\n'
            'CHR DefaultSearchKeyword: Default -> yandex.ru\n'
            'Edge DefaultSearchURL: Default -> hxxp://search-cdn.net/fip/?q={searchTerms}\n',
        )
        assert 'yandex' not in result.lower()
        assert 'search-cdn.net' in result

    def test_hosts_reset_only_for_hijack(self, tmp_path):
        safe, _ = _generate(
            tmp_path, '==== Internet ====\nHosts: 127.0.0.1 example.com\n'
        )
        assert 'Hosts:' not in safe

        hijack, _ = _generate(
            tmp_path, '==== Internet ====\nHosts: 127.0.0.1 google.com\n'
        )
        assert '\nHosts:\n' in hijack
        assert 'Hosts: C:' not in hijack

    def test_hosts_reset_for_raw_addition_section(self, tmp_path):
        report = '==== Процессы ====\nSystem Idle Process (0)\n'
        addition = (
            '==================== Hosts содержимое: =========================\n'
            '2026-01-01 10:00 - 2026-01-01 10:00 - 00000810 _____ '
            'C:\\Windows\\System32\\drivers\\etc\\hosts\n'
            '127.0.0.1 localhost\n'
            '0.0.0.0 ads.example.com\n'
            '127.0.0.1 update.microsoft.com\n')
        hijack, _ = _generate(tmp_path, report, addition_text=addition)
        assert '\nHosts:\n' in hijack

        safe_addition = (
            '==================== Hosts содержимое: =========================\n'
            '127.0.0.1 localhost\n'
            '0.0.0.0 ads.example.com\n')
        safe, _ = _generate(tmp_path, report, addition_text=safe_addition)
        assert 'Hosts:' not in safe

    def test_suspicious_hosts_lines(self):
        from GenFix import is_suspicious_hosts_line

        assert is_suspicious_hosts_line('0.0.0.0 google.com')
        assert is_suspicious_hosts_line('127.0.0.1   update.microsoft.com  # hijack')
        assert is_suspicious_hosts_line('::1 www.kaspersky.com')
        assert is_suspicious_hosts_line('Hosts: 0.0.0.0 google.com')
        assert not is_suspicious_hosts_line('127.0.0.1 localhost')
        assert not is_suspicious_hosts_line('::1 localhost')
        assert not is_suspicious_hosts_line('0.0.0.0 ads.example.com')
        assert not is_suspicious_hosts_line('192.168.1.10 nas.local')
        assert not is_suspicious_hosts_line('# 0.0.0.0 google.com')
        assert not is_suspicious_hosts_line(
            '2026-01-01 10:00 - 2026-01-01 10:00 - 00000810 _____ C:\\hosts')
        assert not is_suspicious_hosts_line('0.0.0.0')

    def test_firewall_legit_program_with_caution_not_flagged(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Firewall Rules ====\n'
            'FirewallRules: [TCP{1}C:\\Program Files\\App\\app.exe] => (Allow) '
            'C:\\Program Files\\App\\app.exe <==== ВНИМАНИЕ\n',
        )
        assert 'C:\\Program Files\\App\\app.exe' not in result

    def test_hidden_program_keywords(self, tmp_path):
        result, _ = _generate(
            tmp_path,
            '==== Installed Programs ====\n'
            'AdBlock Shield 1.0 (HKLM\\...\\Uninstall) Hidden\n',
        )
        assert 'AdBlock Shield' in result


# ===================================================================
# Selection / numbering
# ===================================================================

SAMPLE_FIXLIST = (
    'Start::\n'
    'CloseProcesses:\n'
    'SystemRestore: On\n'
    'CreateRestorePoint:\n'
    '; ---- Tasks ----\n'
    'Task: A\n'
    '; ---- Files ----\n'
    'C:\\bad.exe\n'
    'StartBatch:\n'
    'del /s /q C:\\temp\\*.*\n'
    'EndBatch:\n'
    'ExportKey: HKLM\\X\n'
    'EmptyTemp:\n'
    'Reboot:\n'
    'End::\n'
)


class TestSelection:
    def test_batch_directives_case_insensitive(self):
        import GenFix
        from report_parser import is_boilerplate_action

        assert not GenFix.is_action_line('startbatch:')
        assert not GenFix.is_action_line('ENDBATCH:')
        assert is_boilerplate_action('startbatch:')
        assert is_boilerplate_action('ENDBATCH:')

    def test_numbers_match_highlight(self):
        import GenFix

        _h, body, _f = GenFix.parse_fixlist_content(SAMPLE_FIXLIST)
        actions = [line for line in body if GenFix.is_action_line(line)]
        assert actions == ['Task: A', 'C:\\bad.exe']

        shown = GenFix.highlight_fixlist(SAMPLE_FIXLIST, show_numbers=True)
        numbered = [line.split(')', 1)[1].strip() for line in shown.splitlines()
                    if line.strip()[:1].isdigit() and ')' in line]
        assert numbered == ['Task: A', 'C:\\bad.exe']

    def test_filter_keeps_selected_and_drops_empty_section(self):
        import GenFix

        filtered = GenFix.filter_fixlist_by_numbers(SAMPLE_FIXLIST, '2')
        _h, body, footer = GenFix.parse_fixlist_content(filtered)
        actions = [line for line in body if GenFix.is_action_line(line)]
        assert actions == ['C:\\bad.exe']
        assert '; ---- Tasks ----' not in filtered
        assert '; ---- Files ----' in filtered
        assert 'StartBatch:' in filtered
        assert any(line.startswith('ExportKey:') for line in footer)

    def test_filter_range(self):
        import GenFix

        filtered = GenFix.filter_fixlist_by_numbers(SAMPLE_FIXLIST, '1-2')
        assert 'Task: A' in filtered
        assert 'C:\\bad.exe' in filtered

    def test_filter_space_separated(self):
        import GenFix

        filtered = GenFix.filter_fixlist_by_numbers(SAMPLE_FIXLIST, '1 2')
        assert 'Task: A' in filtered
        assert 'C:\\bad.exe' in filtered

    def test_empty_selection_removes_actions(self):
        import GenFix

        filtered = GenFix.filter_fixlist_by_numbers(SAMPLE_FIXLIST, '99')
        _h, body, _f = GenFix.parse_fixlist_content(filtered)
        assert not any(GenFix.is_action_line(line) for line in body)
        assert 'ExportKey:' in filtered


# ===================================================================
# Misc helpers
# ===================================================================

class TestConfigMerge:
    def test_lists_merged_with_defaults(self, tmp_path):
        import GenFix

        GenFix._cfg_cache = None
        cfg_path = tmp_path / 'cfg.json'
        cfg_path.write_text('{"known_malicious_extensions": ["custom_ext"]}',
                            encoding='utf-8')
        cfg = GenFix.load_config(cfg_path)
        assert 'custom_ext' in cfg['known_malicious_extensions']
        assert cfg['known_malicious_extensions'][0] == 'aegnopegbbhjeeiganiajffnalhlkkjb'
        GenFix._cfg_cache = None


class TestThirdPartyAv:
    @staticmethod
    def _fake_run(output):
        class Result:
            stdout = output

        return lambda *args, **kwargs: Result()

    def test_localized_defender_is_not_third_party(self, monkeypatch):
        import GenFix

        GenFix._av_cache = None
        monkeypatch.setattr(GenFix.subprocess, 'run',
                            self._fake_run('Защитник Windows\n'))
        assert GenFix.check_third_party_av() is False

    def test_kaspersky_is_third_party(self, monkeypatch):
        import GenFix

        GenFix._av_cache = None
        monkeypatch.setattr(GenFix.subprocess, 'run',
                            self._fake_run('Защитник Windows\nKaspersky\n'))
        assert GenFix.check_third_party_av() is True
