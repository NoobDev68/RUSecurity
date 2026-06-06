import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from frst_parser import parse_frst_report, parse_additional_report, normalize_line

RULES_PATH = Path(__file__).parent / 'rules.json'
FRST_DIR = Path(__file__).parent / 'FRST'
SCRIPT_DIR = Path(__file__).parent

def check_third_party_av():
    """Check if a third-party antivirus is installed via WMI."""
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | '
             'Where-Object { $_.displayName -notlike "*Windows Defender*" } | '
             'Select-Object -ExpandProperty displayName'],
            capture_output=True, text=True, timeout=10
        )
        av_names = [name.strip() for name in result.stdout.split('\n') if name.strip()]
        if av_names:
            return True
    except Exception:
        pass
    return False


def is_defender_disabled_entry(entry):
    """When 3rd party AV present, Defender being disabled is normal."""
    norm = entry['normalized'].lower()
    return (
        (entry['has_caution'] or entry['has_no_file'])
        and ('windows defender' in norm or 'wdefend' in norm)
        and any(kw in norm for kw in ['[disable', 'restriction', 'нет файла', '[x]'])
    )


KNOWN_MALICIOUS_EXTENSIONS = {
    'aegnopegbbhjeeiganiajffnalhlkkjb',
    'mfhcmdonhekjhfbjmeacdjbhlfgpjabp',
    'kadaohckdkghfaclhjmkmplebcdcnfnp',
    'gndelhfhcfbdhndfpcinebijfcjpmpec',
    'kbbidhfplpegemhlbcfboalcjdmgebap',
    'mjmpfdkmpojoeemjmfiddlhkkndcdpno',
    'fhkbfkkohcdgpckffakhbllifkakihmh',
}

KNOWN_MALICIOUS_DOMAINS = {
    'search-cdn.net',
    'rusearch.co',
    'play.worols.com',
    'mail.ru/cnt/',
}

KNOWN_LEGIT_EXTENSIONS = {
    'efaidnbmnnnibpcajpcglclefindmkaj',  # Adobe Acrobat
    'aapbdbdomjkkjkaonfhkkikfgjllcleb',  # Google Translate
    'nmmhkkegccagdldgiimedpiccmgmieda',  # Chrome Web Store Payments
    'jmjflgjpcpepeafmmgdpfkogkghcpiha',  # Edge relevant text changes
}

LEGIT_EDGE_BUILTIN_PREFIXES = [
    'AutoFormFill', 'BookReader', 'LearningTools', 'PinJSAPI',
    'Microsoft', 'Office', 'Windows',
]


def load_rules(path=RULES_PATH):
    if not os.path.exists(path):
        print(f"Rules file not found: {path}")
        print("Run extract_rules.py first to generate rules.json")
        sys.exit(1)
    with open(path, 'r', encoding='utf-8') as f:
        raw = json.load(f)
    exact_set = set()
    for r in raw.get('exact_rules', []):
        exact_set.add(normalize_line(r['pattern']))
    pattern_dict = {}
    for r in raw.get('pattern_rules', []):
        pn = normalize_line(r['pattern'])
        if pn not in pattern_dict:
            pattern_dict[pn] = []
        pattern_dict[pn].append(r['action'])
    return {
        'exact_set': exact_set,
        'pattern_dict': pattern_dict,
        'exact_rules': raw.get('exact_rules', []),
        'pattern_rules': raw.get('pattern_rules', []),
        'heuristic_rules': raw.get('heuristic_rules', []),
        'metadata': raw.get('metadata', {}),
    }


def check_malicious_extension(entry):
    norm = entry['normalized']
    for ext_id in KNOWN_MALICIOUS_EXTENSIONS:
        if ext_id in norm:
            return True
    return False


def check_malicious_domain(entry):
    norm = entry['normalized'].lower()
    for domain in KNOWN_MALICIOUS_DOMAINS:
        if domain in norm:
            return True
    return False


LEGIT_TASK_PREFIXES = [
    'microsoft\\windows\\updateorchestrator\\',
    'microsoft\\windows\\windowsupdate\\',
    'microsoft\\windows\\windows backup\\',
    'microsoft\\windows\\wininet\\',
    'microsoft\\windows\\mobile broadband',
    'microsoft\\windows\\termsrv\\',
    'microsoft\\office\\',
    'microsoft\\windows\\windowsdefender\\',
    'microsoft\\windows\\windowsshell\\',
    'microsoft\\windows\\pla\\',
    'microsoft\\windows\\customer experience',
    'microsoft\\windows\\application experience',
    'microsoft\\windows\\diskdiagnostic',
    'microsoft\\windows\\diskfootprint',
    'microsoft\\windows\\filehistory',
    'microsoft\\windows\\maintenance',
    'microsoft\\windows\\multimedia',
    'microsoft\\windows\\nettrace',
    'microsoft\\windows\\power efficiency',
    'microsoft\\windows\\recovery',
    'microsoft\\windows\\registry',
    'microsoft\\windows\\srv',
    'microsoft\\windows\\task scheduler',
    'microsoft\\windows\\time zone',
    'microsoft\\windows\\universal telemetry',
    'microsoft\\windows\\upnp',
    'microsoft\\windows\\wcm',
    'microsoft\\windows\\ws\\',
    'microsoft\\windows\\wlan',
    'microsoft\\windows\\workplace join',
    'microsoft\\windows\\windows error reporting\\',
    'microsoft\\windows\\feedback\\',
    'microsoft\\windows\\flighting\\',
    'microsoft\\windows\\diagnosis\\',
    'microsoft\\windows\\location\\',
    'microsoft\\windows\\live\\',
    'microsoft\\windows\\languagecomponentsinstaller\\',
    'microsoft\\windows\\defrag\\',
    'microsoft\\windows\\maps\\',
    'microsoft\\windows\\bitlocker\\',
    'microsoft\\windows\\management\\',
    'microsoft\\windows\\exploitguard\\',
    'microsoft\\windows\\windows subsystem for linux\\',
    'microsoft\\windows\\windowsbackup\\',
    'microsoft\\windows\\appid\\',
    'microsoft\\windows\\autochk\\',
    'microsoft\\windows\\bluetooth\\',
    'microsoft\\windows\\clip\\',
    'microsoft\\windows\\cloud experience\\',
    'microsoft\\windows\\data integrity scan\\',
    'microsoft\\windows\\device information\\',
    'microsoft\\windows\\directsound\\',
    'microsoft\\windows\\driver scrutiny\\',
    'microsoft\\windows\\embedded\\',
    'microsoft\\windows\\enterprisemanagement\\',
    'microsoft\\windows\\errordetails\\',
    'microsoft\\windows\\gamebar\\',
    'microsoft\\windows\\hotstart\\',
    'microsoft\\windows\\holographic\\',
    'microsoft\\windows\\kerberos\\',
    'microsoft\\windows\\languagepack\\',
    'microsoft\\windows\\licensing\\',
    'microsoft\\windows\\media center\\',
    'microsoft\\windows\\memory diagnostic\\',
    'microsoft\\windows\\mixed reality\\',
    'microsoft\\windows\\netlogon\\',
    'microsoft\\windows\\notifications\\',
    'microsoft\\windows\\offline files\\',
    'microsoft\\windows\\perftrack\\',
    'microsoft\\windows\\pnrpsvc\\',
    'microsoft\\windows\\printdiagnostics\\',
    'microsoft\\windows\\push\\',
    'microsoft\\windows\\rdp\\',
    'microsoft\\windows\\remoteassistance\\',
    'microsoft\\windows\\retaildemo\\',
    'microsoft\\windows\\setting sync\\',
    'microsoft\\windows\\shell\\',
    'microsoft\\windows\\software protection\\',
    'microsoft\\windows\\software inventory\\',
    'microsoft\\windows\\speech\\',
    'microsoft\\windows\\sru\\',
    'microsoft\\windows\\sync center\\',
    'microsoft\\windows\\sysmain\\',
    'microsoft\\windows\\textservicesframework\\',
    'microsoft\\windows\\tpm\\',
    'microsoft\\windows\\uninstaller\\',
    'microsoft\\windows\\usb\\',
    'microsoft\\windows\\user profile\\',
    'microsoft\\windows\\video\\',
    'microsoft\\windows\\volumepnp\\',
    'microsoft\\windows\\wdi\\',
    'microsoft\\windows\\wired\\',
    'microsoft\\windows\\wpd\\',
    'microsoft\\windows\\wu\\',
    'onedrive',
    'opera scheduled',
    'asus\\',
    'gpu tweak',
    'blueStacks',
    'ccleaner',
    'driver booster',
    'yandexbrowser',
    'восстановление сервиса обновлений',
]


def is_legit_task(norm_lower):
    for prefix in LEGIT_TASK_PREFIXES:
        if prefix in norm_lower:
            return True
    return False


def is_suspicious_task(entry):
    norm = entry['normalized'].lower()
    if not entry['is_task_entry']:
        return False
    if is_legit_task(norm):
        return False
    indicators = [
        'adlock', 'winsetupmon',
        'ivanovsasha224',
        'wproxy',
        'programdata\\reaitek',
        'programdata\\realtek',
    ]
    for ind in indicators:
        if ind in norm:
            return True
    if entry['has_caution'] or entry['has_no_file']:
        return True
    return False


def check_suspicious_path(entry):
    norm = entry['normalized'].lower()
    suspicious_patterns = [
        'ivanovsasha224',
        'programdata\\rdp wrapper',
        'appdata\\roaming\\updates\\',
        'programdata\\cache',
    ]
    for pat in suspicious_patterns:
        if pat in norm:
            return True
    return False


def has_garbled_path(entry_text):
    if 'Нет файла' in entry_text:
        path_part = entry_text.rsplit('Нет файла', 1)[0].strip()
    else:
        path_part = entry_text
    ascii_ratio = sum(1 for c in path_part if ord(c) < 128) / max(len(path_part), 1)
    return ascii_ratio < 0.85


LEGIT_FIREWALL_LPORTS = {'2869', '1900', '10243', '5357', '5358'}

LEGIT_FIREWALL_PROGRAM_DIRS = [
    '\\steam\\', '\\steamapps\\', '\\epic games\\',
    '\\gog\\', '\\gog games\\', '\\origin\\',
    '\\bluestacks\\', '\\kaspersky\\', '\\opera\\',
    '\\zoom\\', '\\adobe\\',
    '\\microsoft\\', '\\windows\\', '\\system32\\',
    '\\program files\\', '\\program files (x86)',
    '\\perfproc\\',
]

SUSPICIOUS_FIREWALL_DIRS = [
    '\\temp\\',
    'appdata\\local\\temp',
    'appdata\\local\\programs',
    '\\downloads\\',
]


def check_firewall_rule(entry):
    if not entry['is_firewall_rule']:
        return False
    norm = entry['normalized']
    if 'LPort=' in norm:
        for lp in LEGIT_FIREWALL_LPORTS:
            if f'LPort={lp}' in norm:
                return False
    if not (entry['has_no_file'] or entry['has_caution'] or 'Нет файла' in norm):
        return False
    norm_lower = norm.lower()
    for d in LEGIT_FIREWALL_PROGRAM_DIRS:
        if d in norm_lower:
            return False
    if has_garbled_path(norm):
        return True
    for d in SUSPICIOUS_FIREWALL_DIRS:
        if d in norm_lower:
            return True
    return False


def check_browser_hijack(entry):
    if entry['is_browser_startup']:
        return True
    if entry['is_browser_homepage'] or entry['is_browser_search']:
        return check_malicious_domain(entry)
    return False


def check_hidden_program(entry):
    norm = entry['normalized']
    if 'Hidden' in norm and any(kw in norm.lower() for kw in ['adblock', 'adlock', 'shield']):
        return True
    return False


def extract_extension_path(original):
    m = re.search(r'[A-Z]+ Extension:.*?-\s+(C:\\[^\[]+)', original)
    if m:
        return m.group(1).strip()
    return None


def extract_msi_from_task(original):
    ms = re.findall(r'"((?:C:\\)[^"]*\.msi)"', original)
    if ms:
        return ms
    ms2 = re.findall(r'((?:C:\\)[^\s"]*\.msi)', original)
    if ms2:
        return [m for m in ms2 if '..\\' not in m and len(m) > 10]
    return []


def clean_file_entry(original):
    stripped = original.strip()
    m = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+-\s+\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+-\s+\d+\s+_RSHD\s+(.*)', stripped)
    if m:
        return m.group(1) + ' ' + m.group(2).strip()
    m2 = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+-\s+(.*)', stripped)
    if m2:
        return m2.group(1) + ' ' + m2.group(2).strip()
    m3 = re.match(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2})\s+(C:\\.+)', stripped)
    if m3:
        return m3.group(1) + ' ' + m3.group(2).strip()
    return None


def is_legit_extension(entry):
    norm = entry['normalized']

    for ext_id in KNOWN_LEGIT_EXTENSIONS:
        if ext_id in norm:
            return True

    if norm.startswith('Edge Extension'):
        for prefix in LEGIT_EDGE_BUILTIN_PREFIXES:
            if prefix in norm:
                return True

    return False


# parse_additional_report moved to frst_parser.py


def get_detected_browsers(report):
    browsers = set()
    for entry in report['entries']:
        norm = entry['normalized']
        if norm.startswith('CHR '):
            browsers.add('chrome')
        elif norm.startswith('Edge '):
            browsers.add('edge')
        elif norm.startswith('YAN ') or 'Yandex' in norm:
            browsers.add('yandex')
    return browsers


def generate_batch_commands(browsers):
    cmds = []
    browser_cache = {
        'chrome': 'del /s /q "%userprofile%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\*.*"',
        'edge': 'del /s /q "%userprofile%\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache\\*.*"',
        'yandex': 'del /s /q "%userprofile%\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default\\Cache\\*.*"',
    }
    cmds.append('StartBatch:')
    for b in ['chrome', 'edge', 'yandex']:
        if b in browsers:
            cmds.append(browser_cache[b])
    cmds.append('del /s /q C:\\Windows\\SoftwareDistribution\\download\\*.*')
    cmds.append('EndBatch:')
    return cmds


def generate_fixlist(frst_path: str, rules: dict, output_path: str = None, cleanup: bool = False, has_third_party_av: bool = False):
    report = parse_frst_report(frst_path)

    base = os.path.basename(frst_path)
    dir_name = os.path.dirname(frst_path) or '.'
    additional_name = base.replace('FRST_', 'Additional_')
    if additional_name == base:
        additional_name = 'Additional' + base[4:] if base.startswith('FRST') else 'Additional.txt'
    additional_path = os.path.join(dir_name, additional_name)
    if not os.path.exists(additional_path):
        additional_path = os.path.join(dir_name, 'Addition.txt')
    if not os.path.exists(additional_path):
        additional_path = os.path.join(dir_name, base.replace('FRST_', 'Additional_'))
    additional_report = parse_additional_report(additional_path)

    fix_entries = []
    seen = set()

    def add_entry(entry_text):
        norm = normalize_line(entry_text)
        if norm and norm not in seen:
            seen.add(norm)
            fix_entries.append(entry_text)

    extra_paths = []
    extra_msi = []

    def match_entry_vs_rules(entry):
        nonlocal extra_paths, extra_msi
        original = entry['original']
        norm = entry['normalized']

        if norm in rules['exact_set']:
            add_entry(original)
            return True

        if norm in rules['pattern_dict']:
            rule_actions = rules['pattern_dict'][norm]
            guid_match = re.search(r'\{[0-9A-Fa-f-]{36}\}', norm)
            for rule_action in rule_actions:
                if guid_match and '{GUID}' in rule_action:
                    action_filled = rule_action.replace('{GUID}', guid_match.group(0))
                    add_entry(action_filled)
                    return True
            add_entry(original)
            return True

        return False

    all_entries = report['entries'] + additional_report['entries']

    for entry in all_entries:
        original = entry['original']
        norm = entry['normalized']

        if is_legit_extension(entry):
            continue

        norm_lower = norm.lower()

        if entry['has_caution'] and '\\policies\\' in norm_lower:
            legit_policy_paths = [
                'microsoft\\windows defender',
                'microsoft\\windows\\windowsupdate',
                'microsoft\\windows defender security center',
                'mozilla\\firefox',
                'google\\chrome',
                'google\\update',
                'microsoft\\edge',
                'microsoft\\internet explorer',
                'microsoft\\office\\',
                'microsoft\\silverlight',
                'microsoft\\windows\\networkconnections',
                'microsoft\\windows\\remotedesktop',
                'microsoft\\windows\\systemrestore',
                'microsoft\\windows\\task scheduler',
                'microsoft\\windows\\windows firewall',
                'microsoft\\windows\\powermanagement',
                'microsoft\\windows\\activedesktop',
                'microsoft\\windows\\control panel',
                'microsoft\\windows\\explorer',
                'microsoft\\windows\\windows search',
                'microsoft\\windows\\printing',
                'microsoft\\windows\\credentials',
                'microsoft\\windows\\bitlocker',
                'microsoft\\windows\\device installation',
                'microsoft\\windows\\dr',
                'microsoft\\windows\\eventlog',
                'microsoft\\windows\\fth',
                'microsoft\\windows\\installer',
                'microsoft\\windows\\peer networking',
                'microsoft\\windows\\sam',
                'microsoft\\windows\\tablet pc',
                'microsoft\\windows\\thememanager',
                'microsoft\\windows\\ton',
                'microsoft\\windows\\windows color system',
                'microsoft\\windows\\windefend',
                'microsoft\\mrt',
                'microsoft\\windows\\windows search',
                'microsoft\\windows\\windows firewall',
            ]
            if any(p in norm_lower for p in legit_policy_paths):
                continue

        if has_third_party_av and is_defender_disabled_entry(entry):
            continue

        if match_entry_vs_rules(entry):
            continue

        if check_malicious_extension(entry):
            path = extract_extension_path(original)
            if path:
                extra_paths.append(path)
            else:
                add_entry(original)
            continue

        if check_malicious_domain(entry):
            add_entry(original)
            continue

        if check_browser_hijack(entry):
            add_entry(original)
            continue

        if is_suspicious_task(entry):
            add_entry(original)
            msifiles = extract_msi_from_task(original)
            extra_msi.extend(msifiles)
            continue

        if check_firewall_rule(entry):
            add_entry(original)
            continue

        if entry['is_alternate_stream']:
            if 'Zone.Identifier' in norm or ':encryptable' in norm:
                continue
            add_entry(original.replace('\u200b', '').replace('\ufeff', ''))
            continue

        if entry['is_mountpoints2']:
            add_entry(original)
            continue

        if entry['is_group_policy'] or entry['is_policies']:
            add_entry(original)
            continue

        if entry['has_caution']:
            add_entry(original)
            continue

        if check_suspicious_path(entry):
            cleaned = clean_file_entry(original)
            add_entry(cleaned if cleaned else original)
            continue

        if check_hidden_program(entry):
            add_entry(original)
            continue

        if entry['is_service_entry'] and entry['has_missing_driver']:
            norm_lower = norm.lower()
            legit_services = [
                'vanguard', 'epiconline', 'vgk', 'vgc',
                'realtek', 'intel', 'nvidia', 'amd',
                'rtwlanu', 'rt640x64', 'rtl8180', 'rtl8185',
                'rtl8192', 'rtl81', 'rt86',
                'xbox', 'xboxnet',
                'appex', 'appexdrv',
                'aida64',
                'aswbdisk',
                'iwdbus', 'iwdbus',
            ]
            if any(d in norm_lower for d in legit_services):
                continue
            add_entry(original)
            continue

    if cleanup:
        browsers = get_detected_browsers(report)
        if browsers:
            for cmd in generate_batch_commands(browsers):
                add_entry(cmd)

    for p in extra_paths:
        add_entry(p)
    for m in extra_msi:
        add_entry(m)

    sections_order = [
        'GroupPolicy', 'Policies', 'HKLM', 'HKU', 'HKCR', 'HKCU',
        'CHR', 'Edge', 'BRA', 'FF', 'YAN', 'Hosts:',
        'Task:', 'Service:', 'S1 ', 'S2 ', 'S3 ',
        'AlternateDataStreams', 'FirewallRules',
        'Startup:', 'ShortcutTarget:',
        'C:\\', '202', 'AdBlock',
    ]

    def sort_key(entry_text):
        text = normalize_line(entry_text)
        for i, prefix in enumerate(sections_order):
            if text.startswith(prefix):
                return (0, i, text)
        return (1, 0, text)

    fix_entries.sort(key=sort_key)

    lines = []
    lines.append('Код:')
    lines.append('Start::')
    lines.append('CloseProcesses:')
    lines.append('SystemRestore: On')
    lines.append('CreateRestorePoint:')

    for entry in fix_entries:
        lines.append(entry)

    lines.append('ExportKey: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions')
    lines.append('EmptyTemp:')
    lines.append('Reboot:')
    lines.append('End::')

    output = '\n'.join(lines)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"FixList saved to: {output_path}")
    else:
        print(output)

    return output


def highlight_fixlist(text, show_numbers=False):
    B = '\033[1m'
    M = '\033[35m'
    R = '\033[31m'
    G = '\033[32m'
    Y = '\033[33m'
    C = '\033[36m'
    N = '\033[0m'

    footer_marks = {'ExportKey:', 'EmptyTemp:', 'Reboot:', 'End::'}
    lines = text.split('\n')
    out = []
    header_done = False
    entry_num = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            out.append(line)
            continue
        if not header_done and stripped in ('Start::', 'CloseProcesses:', 'SystemRestore: On', 'CreateRestorePoint:'):
            out.append(f"{B}{G}{line}{N}")
            if stripped == 'CreateRestorePoint:':
                header_done = True
            continue
        if stripped == 'Код:':
            out.append(f"{B}{C}{line}{N}")
            continue
        if header_done:
            if stripped in footer_marks or stripped.startswith('ExportKey:'):
                out.append(f"{C}{line}{N}" if stripped.startswith('ExportKey:') else f"{G}{line}{N}")
                continue
            entry_num += 1
            prefix = f"{B}{M}{entry_num:2d}){N} " if show_numbers else ""
            if 'ВНИМАНИЕ' in line:
                out.append(f"{B}{R}{prefix}{line}{N}")
            elif 'Нет файла' in line or '[X]' in line:
                out.append(f"{Y}{prefix}{line}{N}")
            elif line.startswith('C:\\'):
                out.append(f"{B}{prefix}{line}{N}")
            else:
                out.append(f"{prefix}{line}")
            if i < len(lines) - 1:
                next_stripped = lines[i + 1].strip()
                if next_stripped and next_stripped not in footer_marks and not next_stripped.startswith('ExportKey:'):
                    out.append('')
            continue
        out.append(line)
    return '\n'.join(out)


def display_fixlist(output_path):
    with open(output_path, 'r', encoding='utf-8') as f:
        content = f.read()

    C = '\033[36m'
    B = '\033[1m'
    N = '\033[0m'

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{C}{'=' * 60}{N}")
    print(f"{B}{C}СГЕНЕРИРОВАННЫЙ FIXLIST{N}")
    print(f"{C}{'=' * 60}{N}")
    try:
        print(highlight_fixlist(content, show_numbers=True))
    except UnicodeEncodeError:
        safe = content.encode('cp1251', errors='replace').decode('cp1251')
        print(highlight_fixlist(safe, show_numbers=True))
    print(f"{C}{'=' * 60}{N}")


def apply_fixlist(frst_exe, fixlist_path):
    print("Запуск FRST для применения исправлений (от имени администратора)...")
    print("В окне FRST будет показан ход выполнения и результат каждой операции.\n")

    try:
        fixlist_name = os.path.basename(fixlist_path)
        subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             f'Start-Process -FilePath "{frst_exe}" -ArgumentList "/F {fixlist_name}" '
             f'-WorkingDirectory "{FRST_DIR}" -Verb RunAs -Wait'],
            capture_output=True, text=True
        )
    except Exception as e:
        print(f"Ошибка при запуске FRST: {e}")
        return False

    FRST_DIR.mkdir(parents=True, exist_ok=True)

    fixlog_paths = [
        FRST_DIR / 'fixlog.txt',
        FRST_DIR / 'FRST_log.txt',
        FRST_DIR / 'FRST_fixlog.txt',
    ]
    for log in fixlog_paths:
        if log.exists():
            with open(log, 'r', encoding='utf-8', errors='replace') as f:
                log_content = f.read()
            if log_content.strip():
                print(f"\nРезультат выполнения ({log.name}):")
                print(log_content)
            break
    else:
        print("\nРезультат выполнения можно увидеть в окне FRST.")

    print("Закройте окно FRST для продолжения.")
    return True


def parse_fixlist_content(content):
    lines = content.split('\n')
    header = []
    entries = []
    footer = []
    state = 'header'
    for line in lines:
        stripped = line.strip()
        if state == 'header':
            header.append(line)
            if stripped == 'CreateRestorePoint:':
                state = 'entries'
        elif state == 'entries':
            if stripped.startswith('ExportKey:'):
                footer.append(line)
                state = 'footer'
            else:
                if stripped:
                    entries.append(line)
        elif state == 'footer':
            footer.append(line)
    return header, entries, footer


def filter_fixlist_by_numbers(content, numbers_input):
    header, entries, footer = parse_fixlist_content(content)
    if not entries:
        return content

    keep = set()
    for part in numbers_input.replace(' ', '').split(','):
        if not part:
            continue
        if '-' in part:
            s, e = part.split('-', 1)
            try:
                for n in range(int(s), int(e) + 1):
                    keep.add(n)
            except ValueError:
                continue
        else:
            try:
                keep.add(int(part))
            except ValueError:
                continue

    if not keep:
        return content

    filtered = list(header)
    for i, entry in enumerate(entries, 1):
        if i in keep:
            filtered.append(entry)
    filtered.extend(footer)
    return '\n'.join(filtered)


def analyse_and_show(frst_path, output_path, rules, has_third_party_av=False):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fixlist = generate_fixlist(str(frst_path), rules, str(output_path), cleanup=False, has_third_party_av=has_third_party_av)
    display_fixlist(output_path)

    while True:
        print("\nЧто дальше?")
        print("1. Выполнить все исправления")
        print("2. Выбрать исправления для применения")
        print("3. Вернуться назад")
        choice = input("> ").strip()
        if choice == '1':
            frst_exe = FRST_DIR / 'FRST64.exe'
            if frst_exe.exists():
                apply_fixlist(frst_exe, output_path)
            else:
                frst_exe = FRST_DIR / 'FRST.exe'
                if frst_exe.exists():
                    apply_fixlist(frst_exe, output_path)
                else:
                    print("FRST64.exe не найден в .\\FRST\\")
                    print("Поместите fixlist.txt в .\\FRST\\ и запустите FRST вручную.")
            break
        elif choice == '2':
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read()
            header, entries, footer = parse_fixlist_content(content)
            total = len(entries)
            if total == 0:
                print("Нет исправлений для выбора.")
                continue
            print(f"\nВведите номера исправлений для применения (1-{total})")
            print("Например: 1,3,5-7")
            nums = input("> ").strip()
            filtered = filter_fixlist_by_numbers(content, nums)
            _, filtered_entries, _ = parse_fixlist_content(filtered)
            print(f"\nВыбрано {len(filtered_entries)} из {total} исправлений.")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(filtered)
            display_fixlist(output_path)
        elif choice == '3':
            break


def menu_analyse(rules):
    has_av = check_third_party_av()

    print("\nПоложите FRST.txt (и Addition.txt/Additional.txt) в папку .\\FRST\\")
    print("затем нажмите Enter.")
    print("Чтобы вернуться назад, нажмите 0.")
    choice = input("> ").strip()

    if choice == '0':
        return

    frst_path = FRST_DIR / 'FRST.txt'

    if not frst_path.exists():
        print("Ошибка: FRST.txt не найден в .\\FRST\\")
        input("Нажмите Enter чтобы вернуться в меню...")
        return

    output_path = FRST_DIR / 'fixlist.txt'
    analyse_and_show(frst_path, output_path, rules, has_third_party_av=has_av)


def wait_for_report(filepath, label, timeout=300):
    """Wait for a report to exist and be fully written (size stable 10s + end marker)."""
    print(f"Ожидание {label}...")
    prev_size = -1
    stable_count = 0
    needed_stable = 10

    for i in range(timeout):
        if not filepath.exists():
            if i % 15 == 0:
                print(f"  {label}: файл ещё не создан ({i} сек)", flush=True)
            time.sleep(1)
            continue

        current_size = filepath.stat().st_size
        if current_size == prev_size and current_size > 0:
            stable_count += 1
        else:
            stable_count = 0

        if stable_count >= needed_stable:
            last_line = ''
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    last_line = line
            if 'Конец' in last_line:
                print(f"  {label}: готов")
                return True

        prev_size = current_size
        if i % 15 == 0:
            status = f"{current_size} байт" if filepath.exists() else "файл не найден"
            print(f"  {label}: {status} ({i} сек)", flush=True)
        time.sleep(1)

    print(f"  {label}: ТАЙМАУТ {timeout} сек")
    return False


def menu_scan(rules):
    has_av = check_third_party_av()
    frst_exe = FRST_DIR / 'FRST64.exe'
    if not frst_exe.exists():
        frst_exe = FRST_DIR / 'FRST.exe'
    if not frst_exe.exists():
        print("Ошибка: FRST64.exe не найден в .\\FRST\\")
        input("Нажмите Enter чтобы вернуться в меню...")
        return

    print("Запуск FRST для сканирования системы (от имени администратора)...")
    FRST_DIR.mkdir(parents=True, exist_ok=True)

    for old in ['FRST.txt', 'Additional.txt', 'Addition.txt']:
        p = FRST_DIR / old
        if p.exists():
            p.unlink()

    try:
        subprocess.Popen(
            ['powershell', '-NoProfile', '-Command',
             'Start-Process', '-FilePath', str(frst_exe),
             '-WorkingDirectory', str(FRST_DIR), '-Verb', 'RunAs'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"Ошибка при запуске FRST: {e}")
        input("Нажмите Enter чтобы вернуться в меню...")
        return

    frst_report = FRST_DIR / 'FRST.txt'
    if not wait_for_report(frst_report, 'FRST.txt'):
        print("\nНе удалось дождаться FRST.txt.")
        input("Нажмите Enter чтобы вернуться в меню...")
        return

    additional_path = FRST_DIR / 'Additional.txt'
    if not additional_path.exists():
        additional_path = FRST_DIR / 'Addition.txt'

    if not wait_for_report(additional_path, 'Additional.txt'):
        print("\nAdditional.txt не дождался, работаю только по FRST.txt.")

    output_path = FRST_DIR / 'fixlist.txt'
    analyse_and_show(frst_report, output_path, rules, has_third_party_av=has_av)


def show_menu():
    B = '\033[1m'
    C = '\033[36m'
    G = '\033[32m'
    Y = '\033[33m'
    R = '\033[0m'

    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{C}{'=' * 60}{R}")
    print(f"{B}{C}ГЕНЕРАТОР FIXLIST ДЛЯ FARBAR RECOVERY SCAN TOOL{R}")
    print(f"{C}{'=' * 60}{R}")
    print()
    print(f"{G}1.{R} {B}Просканировать систему с помощью FRST{R}")
    print(f"{Y}2.{R} {B}Анализировать FRST.txt (Additional/Addition.txt){R}")
    print()
    print(f" 0. Выход")
    print()


def main():
    non_flag_args = [a for a in sys.argv[1:] if not a.startswith('--')]

    if non_flag_args:
        frst_path = non_flag_args[0]
        output_path = non_flag_args[1] if len(non_flag_args) > 1 else None
        cleanup = '--cleanup' in sys.argv

        if not os.path.exists(frst_path):
            print(f"Error: File not found: {frst_path}")
            sys.exit(1)

        if not os.path.exists(RULES_PATH):
            print(f"Error: Rules file not found: {RULES_PATH}")
            print("Run extract_rules.py first to train the model on your pairs")
            sys.exit(1)

        rules = load_rules()
        has_av = check_third_party_av()
        print(f"Loaded {len(rules['exact_set'])} exact rules, "
              f"{len(rules['pattern_dict'])} pattern rules, "
              f"{len(rules['heuristic_rules'])} heuristic rules")
        print(f"Hardcoded: {len(KNOWN_MALICIOUS_EXTENSIONS)} extension IDs, "
              f"{len(KNOWN_MALICIOUS_DOMAINS)} malicious domains")

        generate_fixlist(frst_path, rules, output_path, cleanup, has_third_party_av=has_av)
        return

    if not os.path.exists(RULES_PATH):
        print(f"Rules file not found: {RULES_PATH}")
        print("Run extract_rules.py first to train the model on your pairs")
        sys.exit(1)

    rules = load_rules()

    while True:
        show_menu()
        choice = input("> ").strip()

        if choice == '1':
            menu_scan(rules)
        elif choice == '2':
            menu_analyse(rules)
        elif choice == '0':
            print("Выход.")
            break


if __name__ == '__main__':
    main()
