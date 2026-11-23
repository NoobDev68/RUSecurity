"""
Tests for generate_fixlist detectors and helpers.

Run:  python -m pytest tests/ -v
  or:  cd Generate_Fixlist && python -m pytest tests/ -v
"""

import json
import sys
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

# Ensure the project root is on sys.path
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

# ---------------------------------------------------------------------------
# Helpers to build mock entries
# ---------------------------------------------------------------------------


def _entry(original: str, **overrides) -> dict:
    """Build a minimal mock entry dict with sensible defaults."""
    from report_parser import normalize_line

    e = {
        'section': 'test',
        'original': original,
        'normalized': normalize_line(original),
        'has_caution': '<==== ВНИМАНИЕ' in original,
        'has_no_file': '(Нет файла)' in original or 'Нет файла' in original,
        'has_unsigned': False,
        'has_x_marker': '[X]' in original,
        'is_mountpoints2': False,
        'is_alternate_stream': 'AlternateDataStreams' in original,
        'is_group_policy': original.strip().startswith('GroupPolicy:'),
        'is_policies': original.strip().startswith('Policies:'),
        'is_firewall_rule': original.strip().startswith('FirewallRules:'),
        'is_browser_homepage': False,
        'is_browser_startup': False,
        'is_browser_search': False,
        'is_browser_extension': 'Extension:' in original,
        'is_task_entry': original.strip().startswith('Task:'),
        'is_service_entry': False,
        'is_run_key': False,
    }
    e.update(overrides)
    return e


# ===================================================================
# check_malicious_domain
# ===================================================================

class TestMaliciousDomain:
    def test_known_malicious_domain(self):
        e = _entry('CHR HomePage: https://search-cdn.net')
        from GenFix import check_malicious_domain
        assert check_malicious_domain(e) is True

    def test_clean_domain(self):
        e = _entry('CHR HomePage: https://google.com')
        from GenFix import check_malicious_domain
        assert check_malicious_domain(e) is False

    def test_mail_ru_cnt(self):
        e = _entry('CHR DefaultSearch: https://mail.ru/cnt/something')
        from GenFix import check_malicious_domain
        assert check_malicious_domain(e) is True


# ===================================================================
# is_legit_extension
# ===================================================================

class TestLegitExtension:
    def test_known_legit(self):
        e = _entry('CHR HKLM\\...\\Extension: [efaidnbmnnnibpcajpcglclefindmkaj]')
        from GenFix import is_legit_extension
        assert is_legit_extension(e) is True

    def test_edge_builtin(self):
        e = _entry('Edge Extension: Microsoft Edge relevant text changes')
        from GenFix import is_legit_extension
        assert is_legit_extension(e) is True

    def test_chrome_component(self):
        e = _entry('CHR Extension: (WASM TTS Engine) - C:\\Users\\Russska\\AppData\\Local\\Google\\Chrome\\User Data\\WasmTtsEngine\\20260528.1 [2026-06-01] [UpdateUrl:0]')
        from GenFix import is_legit_extension
        assert is_legit_extension(e) is True

    def test_chrome_component_pnacl(self):
        e = _entry('CHR Extension: (pnacl) - C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\pnacl\\1.0 [UpdateUrl:0]')
        from GenFix import is_legit_extension
        assert is_legit_extension(e) is True

    def test_unknown_extension(self):
        e = _entry('CHR HKLM\\...\\Extension: [unknown1234567890123456789012]')
        from GenFix import is_legit_extension
        assert is_legit_extension(e) is False

    def test_chrome_microsoft_name_not_legit(self):
        e = _entry(
            'CHR Extension: (Windows Security Update) - '
            'C:\\Users\\u\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\bad'
        )
        from GenFix import is_legit_extension
        assert is_legit_extension(e) is False


# ===================================================================
# is_legit_task / is_suspicious_task
# ===================================================================

class TestTaskDetection:
    def test_legit_task_microsoft(self):
        e = _entry('Task: Microsoft\\Windows\\WindowsUpdate\\Scheduled Start',
                   is_task_entry=True)
        from GenFix import is_suspicious_task
        assert is_suspicious_task(e) is False

    def test_legit_task_onedrive(self):
        e = _entry('Task: OneDrive Standalone Update Task', is_task_entry=True)
        from GenFix import is_suspicious_task
        assert is_suspicious_task(e) is False

    def test_suspicious_indicator_adlock(self):
        e = _entry('Task: AdLock Updater', is_task_entry=True)
        from GenFix import is_suspicious_task
        assert is_suspicious_task(e) is True

    def test_suspicious_no_file(self):
        e = _entry('Task: UnknownTask C:\\temp\\bad.exe (Нет файла)', is_task_entry=True)
        from GenFix import is_suspicious_task
        assert is_suspicious_task(e) is True

    def test_not_task_entry(self):
        e = _entry('C:\\Windows\\System32\\task.exe', is_task_entry=False)
        from GenFix import is_suspicious_task
        assert is_suspicious_task(e) is False

    def test_onedrive_in_payload_does_not_make_task_legit(self):
        e = _entry(
            'Task: {11111111-2222-3333-4444-555555555555} - System32\\Tasks\\Evil '
            '=> C:\\Temp\\evil.exe --tag=onedrive',
            is_task_entry=True,
            has_caution=True,
        )
        from GenFix import is_suspicious_task
        assert is_suspicious_task(e) is True


# ===================================================================
# check_firewall_rule
# ===================================================================

class TestFirewallRule:
    def test_orphan_program_rule_not_auto_removed(self):
        """Осиротевшее правило программы — необязательная чистка, не трогаем."""
        e = _entry('FirewallRules: TCP LPort=2869 C:\\Windows\\System32\\svchost.exe (Нет файла)')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is False

    def test_port_only_rule_flagged(self):
        e = _entry('FirewallRules: [{11111111-2222-3333-4444-555555555555}] => (Allow) LPort=445')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is True

    def test_legit_program_dir_skip(self):
        e = _entry('FirewallRules: UDP C:\\Program Files\\Game\\game.exe [X]')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is False

    def test_no_flag_no_flag(self):
        """Entry without caution or no_file should not flag."""
        e = _entry('FirewallRules: TCP C:\\SomeApp\\app.exe')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is False

    def test_suspicious_temp_dir(self):
        e = _entry('FirewallRules: TCP C:\\Users\\x\\AppData\\Local\\Temp\\bad.exe (Нет файла)')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is True

    def test_not_firewall_rule(self):
        e = _entry('C:\\Windows\\System32\\svchost.exe')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is False

    def test_garbled_path(self):
        e = _entry('FirewallRules: TCP C:\\Users\\\ufffd\ufffd\\app.exe (Нет файла)')
        from GenFix import check_firewall_rule
        assert check_firewall_rule(e) is True


# ===================================================================
# has_suspicious_tld
# ===================================================================

class TestSuspiciousTld:
    def test_live_in_subdomain_not_flagged(self):
        from GenFix import has_suspicious_tld
        assert has_suspicious_tld('hxxps://outlook.live.com') is False

    def test_single_live_not_enough_for_notifications(self):
        from GenFix import has_suspicious_tld
        assert has_suspicious_tld('hxxps://trovo.live', min_count=2) is False

    def test_two_suspicious_tlds_flagged(self):
        from GenFix import has_suspicious_tld
        assert has_suspicious_tld('hxxps://a.xyz; hxxps://b.top', min_count=2) is True


# ===================================================================
# check_hidden_program
# ===================================================================

class TestHiddenProgram:
    def test_hidden_adlock(self):
        e = _entry('AdLock (HKLM\\...\\Uninstall) Hidden')
        from GenFix import check_hidden_program
        assert check_hidden_program(e) is True

    def test_hidden_shield(self):
        e = _entry('Shield Antivirus Hidden')
        from GenFix import check_hidden_program
        assert check_hidden_program(e) is True

    def test_not_hidden(self):
        e = _entry('Adobe Reader (HKLM\\...\\Uninstall)')
        from GenFix import check_hidden_program
        assert check_hidden_program(e) is False


# ===================================================================
# check_suspicious_path
# ===================================================================

class TestSuspiciousPath:
    def test_known_suspicious(self):
        e = _entry('C:\\ProgramData\\Cache\\malware.exe')
        from GenFix import check_suspicious_path
        assert check_suspicious_path(e) is True

    def test_clean_path(self):
        e = _entry('C:\\Windows\\System32\\notepad.exe')
        from GenFix import check_suspicious_path
        assert check_suspicious_path(e) is False


# ===================================================================
# has_garbled_path
# ===================================================================

class TestGarbledPath:
    def test_mostly_ascii(self):
        from GenFix import has_garbled_path
        assert has_garbled_path('C:\\Windows\\System32\\driver.sys') is False

    def test_valid_cyrillic_path(self):
        from GenFix import has_garbled_path
        assert has_garbled_path('C:\\Users\\Иван\\Документы\\Мои программы\\app.exe') is False

    def test_replacement_char(self):
        from GenFix import has_garbled_path
        assert has_garbled_path('C:\\Users\\\ufffd\ufffd\\app.exe') is True

    def test_no_file_prefix(self):
        from GenFix import has_garbled_path
        assert has_garbled_path('C:\\Temp\\bad.exe Нет файла') is False


# ===================================================================
# is_defender_disabled_entry
# ===================================================================

class TestDefenderDisabled:
    def test_defender_disabled(self):
        e = _entry('HKLM\\...\\Windows Defender: [DisableAntiSpyware] Ограничение <==== ВНИМАНИЕ')
        from GenFix import is_defender_disabled_entry
        assert is_defender_disabled_entry(e) is True

    def test_defender_normal(self):
        e = _entry('HKLM\\...\\Windows Defender: [DisableAntiSpyware]')
        from GenFix import is_defender_disabled_entry
        assert is_defender_disabled_entry(e) is False

    def test_not_defender(self):
        e = _entry('HKLM\\...\\Firewall: Ограничение <==== ВНИМАНИЕ')
        from GenFix import is_defender_disabled_entry
        assert is_defender_disabled_entry(e) is False


# ===================================================================
# is_legit_policy_path
# ===================================================================

class TestLegitPolicyPath:
    def test_legit_windows_defender(self):
        from GenFix import is_legit_policy_path
        assert is_legit_policy_path('microsoft\\windows defender') is True

    def test_legit_firefox(self):
        from GenFix import is_legit_policy_path
        assert is_legit_policy_path('mozilla\\firefox') is True

    def test_unknown_policy(self):
        from GenFix import is_legit_policy_path
        assert is_legit_policy_path('malware\\bad policy') is False


# ===================================================================
# is_legit_missing_driver
# ===================================================================

class TestLegitMissingDriver:
    def test_vanguard(self):
        from GenFix import is_legit_missing_driver
        assert is_legit_missing_driver('vgc') is True

    def test_realtek(self):
        from GenFix import is_legit_missing_driver
        assert is_legit_missing_driver('rt640x64') is True

    def test_intel(self):
        from GenFix import is_legit_missing_driver
        assert is_legit_missing_driver('intel wireless driver') is True

    def test_unknown_driver(self):
        from GenFix import is_legit_missing_driver
        assert is_legit_missing_driver('trojan_malware_driver') is False


# ===================================================================
# extract_extension_path
# ===================================================================

class TestExtractExtensionPath:
    def test_chromium_extension(self):
        from GenFix import extract_extension_path
        result = extract_extension_path(
            'CHR Extension: (Chrome Web Store) - C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\abcdef [2024-01-01]'
        )
        assert result == 'C:\\Users\\x\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\abcdef'

    def test_edge_extension_path(self):
        from GenFix import extract_extension_path
        result = extract_extension_path(
            'Edge Extension: (Bad) - D:\\Users\\u\\Edge\\ext [2026-01-01]'
        )
        assert result == 'D:\\Users\\u\\Edge\\ext'

    def test_no_match(self):
        from GenFix import extract_extension_path
        assert extract_extension_path('Just some text') is None


# ===================================================================
# extract_msi_from_task
# ===================================================================

class TestExtractMsiFromTask:
    def test_quoted_msi(self):
        from GenFix import extract_msi_from_task
        result = extract_msi_from_task(
            'Task: SomeTask "C:\\Windows\\Installer\\abc123.msi" /quiet'
        )
        assert 'C:\\Windows\\Installer\\abc123.msi' in result

    def test_unquoted_msi(self):
        from GenFix import extract_msi_from_task
        result = extract_msi_from_task(
            'Task: SomeTask C:\\Temp\\setup.msi'
        )
        assert 'C:\\Temp\\setup.msi' in result

    def test_no_msi(self):
        from GenFix import extract_msi_from_task
        assert extract_msi_from_task('Task: SomeTask C:\\Temp\\setup.exe') == []


# ===================================================================
# resolve_additional_path
# ===================================================================

class TestResolveAdditionalPath:
    def test_addition_by_report_stem(self, tmp_path):
        report = tmp_path / 'scan-report.txt'
        report.write_text('')
        add = tmp_path / 'scan-add.txt'
        add.write_text('')

        from GenFix import _resolve_addition_path
        result = _resolve_addition_path(str(report))
        assert result == str(add)

    def test_addition_fallback(self, tmp_path):
        report = tmp_path / 'rusecurity-report.txt'
        report.write_text('')
        add = tmp_path / 'rusecurity-add.txt'
        add.write_text('')

        from GenFix import _resolve_addition_path
        result = _resolve_addition_path(str(report))
        assert result == str(add)

    def test_no_additional(self, tmp_path):
        report = tmp_path / 'rusecurity-report.txt'
        report.write_text('')

        from GenFix import _resolve_addition_path
        result = _resolve_addition_path(str(report))
        # Возвращается первый ожидаемый файл
        assert 'rusecurity-add.txt' in result


# ===================================================================
# Dead service records (Security Center / MSCONFIG / Chrome registry)
# ===================================================================

class TestDeadSecurityCenter:
    def test_disabled_absent_product_flagged(self):
        e = _entry('AV: Malwarebytes (Disabled - Out of date) '
                   '{0D452135-A081-B000-D6B6-132E52638543}',
                   section='security_center')
        from GenFix import check_dead_av_registration
        assert check_dead_av_registration(e, ['7-zip 26.06 (hklm\\...)']) is True

    def test_installed_product_kept(self):
        e = _entry('AV: Kaspersky (Disabled - Up to date) '
                   '{70E35457-C7D9-669C-FEA5-55382EABDC78}',
                   section='security_center')
        from GenFix import check_dead_av_registration
        installed = ['kaspersky standard (hklm\\...\\uninstall) (version: 21.3)']
        assert check_dead_av_registration(e, installed) is False

    def test_defender_never_removed(self):
        e = _entry('AV: Windows Defender (Enabled - Up to date) {D68DDC3A}',
                   section='security_center')
        from GenFix import check_dead_av_registration
        assert check_dead_av_registration(e, []) is False

    def test_enabled_product_kept(self):
        e = _entry('FW: Kaspersky (Enabled) {48D8D572}', section='security_center')
        from GenFix import check_dead_av_registration
        assert check_dead_av_registration(e, []) is False

    def test_other_section_ignored(self):
        e = _entry('AV: Malwarebytes (Disabled - Out of date) {0D452135}')
        from GenFix import check_dead_av_registration
        assert check_dead_av_registration(e, []) is False


class TestDeadMsconfigService:
    def test_missing_service_flagged(self):
        e = _entry('MSCONFIG\\Services: AmneziaWGTunnel$redlink349utmk5 => 3',
                   section='msconfig')
        from GenFix import check_dead_msconfig_service
        assert check_dead_msconfig_service(e, {'amneziawgtunnel$redlinkp4258kod'}) is True

    def test_existing_service_kept(self):
        e = _entry('MSCONFIG\\Services: AmneziaWGTunnel$redlinkp4258kod => 3',
                   section='msconfig')
        from GenFix import check_dead_msconfig_service
        assert check_dead_msconfig_service(e, {'amneziawgtunnel$redlinkp4258kod'}) is False

    def test_startup_approved_entry_ignored(self):
        e = _entry('HKU\\S-1-5-21-1-2-3-1001\\...\\StartupApproved\\Run: => "KeePassXC"',
                   section='msconfig')
        from GenFix import check_dead_msconfig_service
        assert check_dead_msconfig_service(e, set()) is False


class TestDeadChromeRegExtension:
    def test_missing_path_flagged(self):
        e = _entry('CHR HKU\\S-1-5-21-1-2-3-1001\\SOFTWARE\\Google\\Chrome\\Extensions'
                   '\\...\\Chrome\\Extension: [dngcpimnedloihjnnfngkgjoidhnaolf]'
                   ' - <отсутствует Path/update_url>')
        from GenFix import check_dead_chrome_reg_extension
        assert check_dead_chrome_reg_extension(e) is True

    def test_normal_entry_kept(self):
        e = _entry('CHR HKLM-x32\\...\\Chrome\\Extension: [iifchhfnnmpdbibifmljnfjhpififfog]')
        from GenFix import check_dead_chrome_reg_extension
        assert check_dead_chrome_reg_extension(e) is False


class TestDeadStartMenuShortcut:
    def test_start_menu_program_files_flagged(self):
        e = _entry('Shortcut: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs'
                   '\\Приватный просмотр Firefox.lnk -> '
                   'C:\\Program Files\\Mozilla Firefox\\private_browsing.exe (Нет файла)'
                   ' <==== Cyrillic')
        from GenFix import is_dead_start_menu_shortcut
        assert is_dead_start_menu_shortcut(e) is True

    def test_desktop_shortcut_kept(self):
        e = _entry('Shortcut: C:\\Users\\u\\Desktop\\Game.lnk -> '
                   'D:\\Games\\game.exe (Нет файла)')
        from GenFix import is_dead_start_menu_shortcut
        assert is_dead_start_menu_shortcut(e) is False

    def test_target_outside_program_files_kept(self):
        e = _entry('Shortcut: C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu'
                   '\\Programs\\Tool.lnk -> D:\\portable\\tool.exe (Нет файла)')
        from GenFix import is_dead_start_menu_shortcut
        assert is_dead_start_menu_shortcut(e) is False

    def test_existing_target_kept(self):
        e = _entry('Shortcut: C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs'
                   '\\App.lnk -> C:\\Program Files\\App\\app.exe')
        from GenFix import is_dead_start_menu_shortcut
        assert is_dead_start_menu_shortcut(e) is False


# ===================================================================
# is_known_harmless_entry
# ===================================================================

class TestKnownHarmlessEntry:
    def test_onedrive_overlay_dead_is_not_skipped(self):
        e = _entry('ShellIconOverlayIdentifiers: [ OneDrive1] -> {BBACC218-34EA-4666-9D7A-C78F2274A524} =>  -> Нет файла')
        from GenFix import is_known_harmless_entry
        assert is_known_harmless_entry(e) is False

    def test_onedrive_overlay_x32_dead_is_not_skipped(self):
        e = _entry('ShellIconOverlayIdentifiers-x32: [ OneDrive5] -> {A0396A93-DC06-4AEF-BEE9-95FFCCAEF20E} =>  -> Нет файла')
        from GenFix import is_known_harmless_entry
        assert is_known_harmless_entry(e) is False

    def test_ie_empty_value(self):
        e = _entry('HKLM\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Main,Default_Page_URL =')
        from GenFix import is_known_harmless_entry
        assert is_known_harmless_entry(e) is True

    def test_ie_nonempty_value_not_filtered(self):
        e = _entry('HKLM\\Software\\Wow6432Node\\Microsoft\\Internet Explorer\\Main,Default_Page_URL = http://malware.com')
        from GenFix import is_known_harmless_entry
        assert is_known_harmless_entry(e) is False

    def test_not_harmless(self):
        e = _entry('HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run,Malware = C:\\malware.exe')
        from GenFix import is_known_harmless_entry
        assert is_known_harmless_entry(e) is False


# ===================================================================
# Integration: generate_fixlist (with mock parse functions)
# ===================================================================

class TestGenerateFixlist:
    def test_empty_report(self, tmp_path):
        """Пустой отчёт не создаёт fixlist."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text('==== Раздел ====\n==== Конец ====', encoding='utf-8')

        rules = {
            'exact_set': set(),
            'pattern_dict': {},
            'exact_rules': [],
            'pattern_rules': [],
            'heuristic_rules': [],
            'metadata': {},
        }

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), rules, output_path=str(output))

        assert result == ''
        assert not output.exists()

    def test_registry_only_fix_has_no_optional_footer(self, tmp_path):
        """Правка только реестра не требует EmptyTemp/Reboot."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Group Policy ====\n'
            'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Explorer: '
            '[SettingsPageVisibility] Ограничение <==== ATTENTION\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), output_path=str(output))

        assert 'SettingsPageVisibility' in result
        assert 'EmptyTemp:' not in result
        assert 'Reboot:' not in result

    def test_browser_fix_adds_empty_temp_only(self, tmp_path):
        """Браузерное исправление требует очистки temp, но не перезагрузки."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Chrome ====\n'
            'CHR HKLM\\...\\Chrome\\Extension: [aegnopegbbhjeeiganiajffnalhlkkjb]\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), output_path=str(output))

        assert 'EmptyTemp:' in result
        assert 'Reboot:' not in result

    def test_service_fix_adds_reboot(self, tmp_path):
        """Удаление службы/драйвера требует перезагрузки."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Services ====\n'
            'S2 badsvc; C:\\Windows\\System32\\drivers\\bad.sys <==== ATTENTION\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), output_path=str(output))

        assert 'Reboot:' in result
        assert 'EmptyTemp:' not in result

    def test_dead_service_does_not_add_reboot(self, tmp_path):
        """Мёртвая служба без файла удаляется без перезагрузки."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Services ====\n'
            'S2 deadsvc; C:\\Windows\\System32\\drivers\\dead.sys (Нет файла)\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), output_path=str(output))

        assert 'Reboot:' not in result

    def test_temp_shortcut_adds_empty_temp_only(self, tmp_path):
        """Удаление файла из Temp требует очистки temp, но не перезагрузки."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Shortcuts ====\n'
            'Shortcut: C:\\Users\\x\\AppData\\Local\\Temp\\bad.lnk => '
            'C:\\Users\\x\\AppData\\Local\\Temp\\bad.exe (Нет файла)\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), output_path=str(output))

        assert 'EmptyTemp:' in result
        assert 'Reboot:' not in result

    def test_shortcut_target_in_temp_does_not_need_empty_temp(self, tmp_path):
        """Ярлык с рабочего стола на файл в Temp удаляется без чистки Temp."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Shortcuts ====\n'
            'Shortcut: C:\\Users\\x\\Desktop\\bad.lnk -> '
            'C:\\Users\\x\\AppData\\Local\\Temp\\bad.exe (Нет файла)\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), output_path=str(output))

        assert 'bad.lnk' in result
        assert 'EmptyTemp:' not in result

    def test_malicious_extension_flagged(self, tmp_path):
        """Report with malicious extension → flagged in fixlist."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Chrome ====\n'
            'CHR HKLM\\...\\Chrome\\Extension: [aegnopegbbhjeeiganiajffnalhlkkjb]\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        rules = {
            'exact_set': set(),
            'pattern_dict': {},
            'exact_rules': [],
            'pattern_rules': [],
            'heuristic_rules': [],
            'metadata': {},
        }

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), rules, output_path=str(output))

        assert 'aegnopegbbhjeeiganiajffnalhlkkjb' in result

    def test_legit_extension_skipped(self, tmp_path):
        """Legitimate extension not flagged."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Chrome ====\n'
            'CHR HKLM\\...\\Chrome\\Extension: [efaidnbmnnnibpcajpcglclefindmkaj]\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        rules = {
            'exact_set': set(),
            'pattern_dict': {},
            'exact_rules': [],
            'pattern_rules': [],
            'heuristic_rules': [],
            'metadata': {},
        }

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), rules, output_path=str(output))

        assert 'efaidnbmnnnibpcajpcglclefindmkaj' not in result

    def test_defender_skipped_with_3rd_party_av(self, tmp_path):
        """Defender-disabled entries skipped when 3rd party AV present."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Реестр Windows ====\n'
            'HKLM\\SOFTWARE\\Microsoft\\Windows Defender: [DisableAntiSpyware] Ограничение <==== ВНИМАНИЕ\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        rules = {
            'exact_set': set(),
            'pattern_dict': {},
            'exact_rules': [],
            'pattern_rules': [],
            'heuristic_rules': [],
            'metadata': {},
        }

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), rules, output_path=str(output), has_third_party_av=True)

        assert 'DisableAntiSpyware' not in result

    def test_zone_identifier_skipped(self, tmp_path):
        """Zone.Identifier ADS entries skipped."""
        from GenFix import generate_fixlist

        report = tmp_path / 'rusecurity-report.txt'
        report.write_text(
            '==== Alternate Data Streams ====\n'
            'AlternateDataStreams: C:\\file.exe:Zone.Identifier\n'
            '==== Конец ====',
            encoding='utf-8',
        )

        rules = {
            'exact_set': set(),
            'pattern_dict': {},
            'exact_rules': [],
            'pattern_rules': [],
            'heuristic_rules': [],
            'metadata': {},
        }

        output = tmp_path / 'fixlist.txt'
        result = generate_fixlist(str(report), rules, output_path=str(output))

        assert 'Zone.Identifier' not in result


# ===================================================================
# Config loading
# ===================================================================

class TestConfigLoading:
    def test_load_defaults(self):
        """Without config file, defaults are returned."""
        from GenFix import load_config, _cfg_cache
        # Clear cache
        import GenFix as gf
        gf._cfg_cache = None
        cfg = load_config(Path('/nonexistent/config.json'))
        assert 'known_malicious_extensions' in cfg
        assert len(cfg['known_malicious_extensions']) >= 5

    def test_load_from_file(self, tmp_path):
        """Config file overrides defaults."""
        from GenFix import load_config, _cfg_cache
        import GenFix as gf
        gf._cfg_cache = None

        cfg_path = tmp_path / 'detection_config.json'
        cfg_path.write_text(json.dumps({
            'known_malicious_extensions': ['custom_ext_id'],
            'legit_task_prefixes': ['custom_task\\'],
        }))

        cfg = load_config(cfg_path)
        assert 'custom_ext_id' in cfg['known_malicious_extensions']
        assert 'custom_task\\' in cfg['legit_task_prefixes']
        # Defaults not in override should still be present
        assert 'known_malicious_domains' in cfg


# ===================================================================
# check_weakened_security
# ===================================================================

class TestWeakenedSecurity:
    def _other_entry(self, original: str) -> dict:
        from report_parser import normalize_line
        return {
            'section': 'other_14',
            'original': original,
            'normalized': normalize_line(original),
        }

    def test_smartscreen_off(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer => (SmartScreenEnabled: Off)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 1
        assert 'reg add' in cmds[0]
        assert 'SmartScreenEnabled' in cmds[0]
        assert 'Warn' in cmds[0]

    def test_smartscreen_0(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer => (SmartScreenEnabled: 0)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 1

    def test_smartscreen_warn_unchanged(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer => (SmartScreenEnabled: Warn)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 0

    def test_webcontenteval_0(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKU\\...\\AppHost => (EnableWebContentEvaluation: 0)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 1
        assert 'reg add' in cmds[0]
        assert 'EnableWebContentEvaluation' in cmds[0]

    def test_webcontenteval_1_unchanged(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKU\\...\\AppHost => (EnableWebContentEvaluation: 1)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 0

    def test_tamperprotection_off(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\...\\Windows Defender\\Features => (TamperProtection: 4) (TamperProtectionSource: 2)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 1
        assert 'reg add' in cmds[0]
        assert 'TamperProtection' in cmds[0]

    def test_tamperprotection_source_not_matched(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\...\\Windows Defender\\Features => '
            '(TamperProtection: 5) (TamperProtectionSource: 4)'
        )
        assert check_weakened_security(entry) == []

    def test_tamperprotection_0(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\...\\Windows Defender\\Features => (TamperProtection: 0)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 1

    def test_tamperprotection_on_unchanged(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\...\\Windows Defender\\Features => (TamperProtection: 5)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 0

    def test_unrelated_entry_ignored(self):
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Environment\\Path -> C:\\Windows\\System32'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 0

    def test_dpadisabled_0_not_flagged(self):
        """DpaDisabled 0 = enabled, don't touch."""
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\...\\Real-Time Protection => (DpaDisabled: 0)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 0

    def test_uac_correct_not_flagged(self):
        """ConsentPromptBehaviorAdmin=5 and EnableLUA=1 are correct."""
        from GenFix import check_weakened_security
        entry = self._other_entry(
            'HKLM\\...\\Policies\\System => (ConsentPromptBehaviorAdmin: 5) (EnableLUA: 1)'
        )
        cmds = check_weakened_security(entry)
        assert len(cmds) == 0
