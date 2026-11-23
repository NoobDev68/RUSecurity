#!/usr/bin/env python3
"""
Движок детекции RUSecurity.

Правила детекции выведены из разбора корпуса экспертных пар «отчёт + список
исправлений» (SafeZone.cc и другие источники) и дополнены эвристиками.

Анализирует отчёты rusecurity-report.txt и rusecurity-add.txt, находит
подозрительные записи и собирает список исправлений.
"""

import argparse
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Set

from report_parser import (
    detect_encoding, normalize_line, parse_addition, parse_report,
)

# ---------------------------------------------------------------------------
# Paths / metadata
# ---------------------------------------------------------------------------
__version__ = '3.0.0'
IS_WINDOWS = os.name == 'nt'
RULES_PATH = Path(__file__).parent / 'rules.json'
CONFIG_PATH = Path(__file__).parent / 'detection_config.json'
SCRIPT_DIR = Path(__file__).parent

# ---------------------------------------------------------------------------
# Logging / console
# ---------------------------------------------------------------------------
log = logging.getLogger('generate_fixlist')
_USE_COLOR = False


def _ensure_truetype_font(kernel32, handle) -> None:
    """В conhost после chcp может включиться растровый Terminal.

    Растровый шрифт не умеет кириллицу в UTF-8, поэтому меню выглядит мусором.
    Если текущий шрифт не TrueType — переключаемся на Consolas.
    """
    import ctypes
    from ctypes import wintypes

    class CONSOLE_FONT_INFOEX(ctypes.Structure):
        _fields_ = [
            ('cbSize', wintypes.ULONG),
            ('nFont', wintypes.DWORD),
            ('dwFontSizeX', wintypes.SHORT),
            ('dwFontSizeY', wintypes.SHORT),
            ('FontFamily', wintypes.UINT),
            ('FontWeight', wintypes.UINT),
            ('FaceName', wintypes.WCHAR * 32),
        ]

    try:
        kernel32.GetCurrentConsoleFontEx.argtypes = [
            wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(CONSOLE_FONT_INFOEX)]
        kernel32.GetCurrentConsoleFontEx.restype = wintypes.BOOL
        kernel32.SetCurrentConsoleFontEx.argtypes = [
            wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(CONSOLE_FONT_INFOEX)]
        kernel32.SetCurrentConsoleFontEx.restype = wintypes.BOOL

        info = CONSOLE_FONT_INFOEX()
        info.cbSize = ctypes.sizeof(info)
        if not kernel32.GetCurrentConsoleFontEx(handle, False, ctypes.byref(info)):
            return
        if info.FontFamily & 0x0004:  # TMPF_TRUETYPE
            return

        info.FontFamily = 0x36
        info.FontWeight = 400
        info.dwFontSizeX = 0
        info.dwFontSizeY = 16
        for face in ('Consolas', 'Lucida Console'):
            info.FaceName = face
            if kernel32.SetCurrentConsoleFontEx(handle, False, ctypes.byref(info)):
                return
    except Exception:
        return


def _init_console() -> None:
    """Настроить UTF-8 и ANSI-цвета в консоли Windows."""
    global _USE_COLOR
    _USE_COLOR = False
    if IS_WINDOWS:
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
            kernel32.GetStdHandle.restype = wintypes.HANDLE
            kernel32.SetConsoleOutputCP(65001)
            kernel32.SetConsoleCP(65001)
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                if kernel32.SetConsoleMode(handle, mode.value | 0x0004):
                    _USE_COLOR = bool(sys.stdout.isatty())
            _ensure_truetype_font(kernel32, handle)
        except Exception:
            _USE_COLOR = False
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding='utf-8', errors='replace')
        except (AttributeError, OSError, ValueError):
            pass


def setup_logging(verbose: bool = False) -> None:
    # Логи пишем в stderr, чтобы `python GenFix.py rusecurity-report.txt` (вывод списка в
    # stdout) можно было перенаправить в файл без примесей служебных строк.
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format='%(levelname)-7s %(message)s',
        stream=sys.stderr, force=True,
    )


# ===================================================================
# Config loading
# ===================================================================

_cfg_cache = None


def load_config(path: Optional[Path] = None) -> dict:
    global _cfg_cache
    if _cfg_cache is not None:
        return _cfg_cache

    defaults = {
        'known_malicious_extensions': [
            'aegnopegbbhjeeiganiajffnalhlkkjb',
            'mfhcmdonhekjhfbjmeacdjbhlfgpjabp',
            'kadaohckdkghfaclhjmkmplebcdcnfnp',
            'gndelhfhcfbdhndfpcinebijfcjpmpec',
            'kbbidhfplpegemhlbcfboalcjdmgebap',
            'mjmpfdkmpojoeemjmfiddlhkkndcdpno',
            'fhkbfkkohcdgpckffakhbllifkakihmh',
            'ellpepcimdiojocjabefpnpkfpkehpec',
            'iepoegkaoeljnbhagabakjodgpfniimo',
            'gkfanndldghlkndfhojpfhclgdnglfmf',
        ],
        'known_malicious_domains': [
            'search-cdn.net', 'rusearch.co', 'play.worols.com', 'mail.ru/cnt/',
            'mail.ru/homepage', 'inline.go.mail.ru',
        ],
        'known_legit_extensions': [
            'efaidnbmnnnibpcajpcglclefindmkaj',
            'aapbdbdomjkkjkaonfhkkikfgjllcleb',
            'nmmhkkegccagdldgiimedpiccmgmieda',
            'jmjflgjpcpepeafmmgdpfkogkghcpiha',
            'ghbmnnjooekpmoecnnnilnnbdlolhkhi',
            'pjkljhegncpnkpknbcohdijeoejaedia',
            'apdfllckaahabafndbhieahigkjlhalf',
            'blpcfgokakmgnkcojhhkbfbldkacnbeo',
            'aohghmighlieiainnegkcijnfilokake',
            'aapocclcgogkmnckokdopfmhonfmgoek',
            'felcaaldnbdncclmgdcncolpebgiejap',
            'pkedcjkdefgpdelpbcmbmeomcjbeemfm',
            'gighmmpiobklfepjocnamgkkbiglidom',
            'hjdkfkdkokphfploiiddakjokndinfgb',
        ],
        'legit_task_prefixes': [
            'microsoft\\windows\\updateorchestrator',
            'microsoft\\windows\\windowsupdate',
            'microsoft\\windows\\winsat',
            'microsoft\\windows\\windows backup',
            'microsoft\\windows\\wininet',
            'microsoft\\windows\\mobile broadband',
            'microsoft\\windows\\termsrv',
            'microsoft\\office',
            'microsoft\\windows\\windowsdefender',
            'microsoft\\windows\\windowsshell',
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
            'microsoft\\windows\\windows error reporting',
            'microsoft\\windows\\feedback',
            'microsoft\\windows\\flighting',
            'microsoft\\windows\\diagnosis',
            'microsoft\\windows\\location',
            'microsoft\\windows\\live',
            'microsoft\\windows\\languagecomponentsinstaller',
            'microsoft\\windows\\defrag',
            'microsoft\\windows\\maps',
            'microsoft\\windows\\bitlocker',
            'microsoft\\windows\\management',
            'microsoft\\windows\\exploitguard',
            'microsoft\\windows\\windows subsystem for linux',
            'microsoft\\windows\\windowsbackup',
            'microsoft\\windows\\appid',
            'microsoft\\windows\\autochk',
            'microsoft\\windows\\bluetooth',
            'microsoft\\windows\\clip',
            'microsoft\\windows\\cloud experience',
            'microsoft\\windows\\data integrity scan',
            'microsoft\\windows\\device information',
            'microsoft\\windows\\directsound',
            'microsoft\\windows\\driver scrutiny',
            'microsoft\\windows\\embedded',
            'microsoft\\windows\\enterprisemanagement',
            'microsoft\\windows\\errordetails',
            'microsoft\\windows\\gamebar',
            'microsoft\\windows\\hotstart',
            'microsoft\\windows\\holographic',
            'microsoft\\windows\\kerberos',
            'microsoft\\windows\\languagepack',
            'microsoft\\windows\\licensing',
            'microsoft\\windows\\media center',
            'microsoft\\windows\\memory diagnostic',
            'microsoft\\windows\\mixed reality',
            'microsoft\\windows\\netlogon',
            'microsoft\\windows\\notifications',
            'microsoft\\windows\\offline files',
            'microsoft\\windows\\perftrack',
            'microsoft\\windows\\pla\\',
            'microsoft\\windows\\pnrpsvc',
            'microsoft\\windows\\printdiagnostics',
            'microsoft\\windows\\push',
            'microsoft\\windows\\rdp',
            'microsoft\\windows\\remoteassistance',
            'microsoft\\windows\\retaildemo',
            'microsoft\\windows\\setting sync',
            'microsoft\\windows\\shell',
            'microsoft\\windows\\software protection',
            'microsoft\\windows\\software inventory',
            'microsoft\\windows\\speech',
            'microsoft\\windows\\sru',
            'microsoft\\windows\\sync center',
            'microsoft\\windows\\sysmain',
            'microsoft\\windows\\textservicesframework',
            'microsoft\\windows\\tpm',
            'microsoft\\windows\\uninstaller',
            'microsoft\\windows\\usb',
            'microsoft\\windows\\user profile',
            'microsoft\\windows\\video',
            'microsoft\\windows\\volumepnp',
            'microsoft\\windows\\wdi',
            'microsoft\\windows\\wired',
            'microsoft\\windows\\wpd',
            'microsoft\\windows\\wu',
            'onedrive',
            'opera scheduled',
            'asus\\',
            'gpu tweak',
            'bluestacks',
            'ccleaner',
            'driver booster',
            'yandexbrowser',
            'восстановление сервиса обновлений',
        ],
        'legit_driver_vendors': [
            'vanguard', 'epiconline', 'vgk', 'vgc',
            'realtek', 'intel', 'nvidia', 'amd',
            'rtwlanu', 'rt640x64', 'rtl81', 'rt86',
            'xbox', 'xboxnet',
            'appex', 'appexdrv', 'aida64', 'aswbdisk',
            'iwdbus',
            'nihsdrk', 'nipsdk', 'nipalk',
            'nimdns', 'nimxs', 'nisvcloc',
            'lkads', 'lktsrv', 'lkcitdl',
            'opcenum',
        ],
        'chrome_components': [
            'WASM TTS Engine', 'WasmTtsEngine', 'pnacl', 'MEIPreload',
            'Crowd Deny', 'SafetyTips', 'CertificateRevocation',
            'SSLErrorAssistant', 'Chrome Media Router',
            'OriginTrials', 'Subresource Filter', 'WebRTC Logging',
            'ZxcvbnData', 'Feedback', 'Hangout Services',
            'Identity API Scope Approval',
        ],
        'legit_edge_builtin_prefixes': [
            'AutoFormFill', 'BookReader', 'LearningTools', 'PinJSAPI',
            'Microsoft', 'Office', 'Windows',
        ],
        'legit_policy_paths': [
            'microsoft\\windows defender',
            'microsoft\\windows\\windowsupdate',
            'microsoft\\windows defender security center',
            'mozilla\\firefox', 'google\\chrome', 'google\\update',
            'microsoft\\edge', 'microsoft\\internet explorer',
            'microsoft\\office\\', 'microsoft\\silverlight',
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
        ],
        'legit_service_names': [
            'vanguard', 'epiconline', 'vgk', 'vgc',
            'realtek', 'intel', 'nvidia', 'amd',
            'rtwlanu', 'rt640x64', 'rtl8180', 'rtl8185',
            'rtl8192', 'rtl81', 'rt86',
            'xbox', 'xboxnet',
            'appex', 'appexdrv',
            'aida64', 'aswbdisk', 'iwdbus',
        ],
        'suspicious_driver_patterns': [
            r'^uti\d+[a-z]*\d+',
            r'^[a-z]{3}\d{4}',
        ],
        'search_hijack_fields': [
            'DefaultSearchURL', 'DefaultSearchKeyword',
            'DefaultNewTabURL', 'DefaultSuggestURL',
            'HomeButtonPage',
        ],
        'adware_ext_names': [
            'новости онлайн', 'gifty box', 'защита от веб-угроз 360',
            'expert+', 'adblock detector', 'search module',
        ],
        'suspicious_tlds': [
            '.fun', '.cc', '.biz', '.live', '.info', '.xyz', '.top', '.click',
        ],
        'suspicious_firewall_dirs': [
            '\\temp\\',
            'appdata\\local\\temp',
            'appdata\\local\\programs',
            '\\downloads\\',
        ],
        'legit_firewall_lports': ['2869', '1900', '10243', '5357', '5358'],
        'legit_firewall_program_dirs': [
            '\\steam\\', '\\steamapps\\', '\\epic games\\',
            '\\gog\\', '\\gog games\\', '\\origin\\',
            '\\bluestacks\\', '\\kaspersky\\', '\\opera\\',
            '\\zoom\\', '\\adobe\\',
            '\\microsoft\\', '\\windows\\', '\\system32\\',
            '\\program files\\', '\\program files (x86)',
            '\\perfproc\\',
        ],
        'suspicious_task_indicators': [
            'adlock', 'winsetupmon',
            'wproxy',
            'programdata\\reaitek',
            'programdata\\realtek',
        ],
        'suspicious_path_patterns': [
            'programdata\\rdp wrapper',
            'appdata\\roaming\\updates\\',
            'programdata\\cache',
        ],
        'hidden_program_keywords': ['adblock', 'adlock', 'shield'],
    }

    cfg_path = path or CONFIG_PATH
    if cfg_path and os.path.exists(cfg_path):
        try:
            import json
            with open(cfg_path, 'r', encoding='utf-8') as f:
                overrides = json.load(f)
            for key, value in overrides.items():
                if key not in defaults:
                    log.debug('Неизвестный ключ конфига: %s — пропущен', key)
                    continue
                if isinstance(defaults[key], list) and isinstance(value, list):
                    merged = list(defaults[key])
                    for item in value:
                        if item not in merged:
                            merged.append(item)
                    defaults[key] = merged
                else:
                    defaults[key] = value
        except json.JSONDecodeError as exc:
            log.warning('Ошибка чтения %s: %s — используются defaults', cfg_path, exc)
        except OSError as exc:
            log.warning('Ошибка доступа к %s: %s — используются defaults', cfg_path, exc)

    _cfg_cache = defaults
    return defaults


# ===================================================================
# EXPERT-DERIVED DETECTION RULES
# Based on analysis of 1078 SafeZone.cc expert-written fixlists
# ===================================================================

cfg = load_config()

MALICIOUS_EXTENSION_IDS: Set[str] = set(cfg['known_malicious_extensions'])
MALICIOUS_DOMAINS: Set[str] = set(cfg['known_malicious_domains'])
CHROME_COMPONENTS: Set[str] = set(cfg['chrome_components'])
LEGIT_EXTENSION_IDS: Set[str] = set(cfg['known_legit_extensions'])
LEGIT_DRIVER_VENDORS: Set[str] = set(cfg['legit_driver_vendors'])
LEGIT_EDGE_BUILTIN_PREFIXES: List[str] = cfg['legit_edge_builtin_prefixes']
LEGIT_POLICY_PATHS: List[str] = cfg['legit_policy_paths']
LEGIT_SERVICE_NAMES: List[str] = cfg['legit_service_names']
SUSPICIOUS_DRIVER_PATTERNS: List[str] = cfg['suspicious_driver_patterns']
LEGIT_TASK_PREFIXES: List[str] = cfg['legit_task_prefixes']
SEARCH_HIJACK_FIELDS: tuple = tuple(cfg['search_hijack_fields'])
ADWARE_EXT_NAMES: List[str] = cfg['adware_ext_names']
SUSPICIOUS_TLDS: List[str] = cfg['suspicious_tlds']
SUSPICIOUS_FIREWALL_DIRS: List[str] = cfg['suspicious_firewall_dirs']
LEGIT_FIREWALL_LPORTS: Set[str] = set(cfg['legit_firewall_lports'])
LEGIT_FIREWALL_PROGRAM_DIRS: List[str] = cfg['legit_firewall_program_dirs']
SUSPICIOUS_TASK_INDICATORS: List[str] = cfg['suspicious_task_indicators']
SUSPICIOUS_PATH_PATTERNS: List[str] = cfg['suspicious_path_patterns']
HIDDEN_PROGRAM_KEYWORDS: List[str] = cfg['hidden_program_keywords']

_RE_EMPTY_RUN_X = re.compile(r'\\Run:\s*\[\]\s*=>\s*\[X\]', re.IGNORECASE)
_RE_TASK_GUID_ONLY = re.compile(r'Task:\s*\{[0-9A-Fa-f-]{36}\}\s*-\s*$')
_RE_DRIVER_PATH = re.compile(r'((?:[A-Za-z]:\\|\\??\\[A-Za-z]:)[^\s;]+\.sys)')
_RE_DRIVER_FNAME = re.compile(r'([a-zA-Z0-9_]+\.sys)')

# -- Known-malicious Chrome extension IDs (force-installed via HKLM) --


def _is_legit_task(norm_lower: str) -> bool:
    """Check if a scheduled task is a known-legitimate Windows/system task."""
    task_name = norm_lower.split('=>', 1)[0]
    return any(prefix in task_name for prefix in LEGIT_TASK_PREFIXES)


def _is_legit_driver_vendor(norm_lower: str) -> bool:
    """Check if a driver/service belongs to a known-legitimate vendor."""
    return any(vendor in norm_lower for vendor in LEGIT_DRIVER_VENDORS)


def _is_suspicious_driver_name(norm: str) -> bool:
    """Check if a driver filename matches known-suspicious patterns."""
    m = _RE_DRIVER_FNAME.search(norm)
    if m:
        fname = m.group(1).lower()
        for pat in SUSPICIOUS_DRIVER_PATTERNS:
            if re.match(pat, fname.replace('.sys', '')):
                return True
    return False


# ===================================================================
# Helper functions for detection
# ===================================================================

def is_known_harmless_entry(entry: dict) -> bool:
    """Check if entry is a known false positive (harmless, skip it)."""
    norm = entry['normalized']
    if 'internet explorer\\main' in norm.lower():
        cleaned = re.sub(r'^\s*\d+\)\s+', '', norm)
        if cleaned.rstrip().endswith('='):
            return True
    return False


def is_defender_disabled_entry(entry: dict) -> bool:
    """When 3rd party AV present, Defender being disabled is normal."""
    norm = entry['normalized'].lower()
    return (
        (entry.get('has_caution', False) or entry.get('has_no_file', False))
        and ('windows defender' in norm or 'wdefend' in norm)
        and any(kw in norm for kw in ['disable', 'restriction', 'нет файла', 'no file', '[x]'])
    )


def is_legit_policy_path(norm_lower: str) -> bool:
    """Check if a policy path string is a known legitimate Windows/browser policy."""
    return any(p in norm_lower for p in LEGIT_POLICY_PATHS)


def is_legit_missing_driver(norm_lower: str) -> bool:
    """Check if a missing driver belongs to known legitimate software."""
    return any(service in norm_lower for service in LEGIT_SERVICE_NAMES)


def check_malicious_domain(entry: dict) -> bool:
    norm = entry['normalized'].lower()
    for domain in MALICIOUS_DOMAINS:
        if domain in norm:
            return True
    return False


def has_suspicious_tld(text: str, min_count: int = 1) -> bool:
    """TLD из списка, но только на границе домена (не внутри .live.com)."""
    low = text.lower()
    found = sum(
        1 for tld in SUSPICIOUS_TLDS
        if re.search(rf'{re.escape(tld)}(?![a-z0-9.-])', low)
    )
    return found >= min_count


def has_garbled_path(entry_text: str) -> bool:
    if 'Нет файла' in entry_text:
        path_part = entry_text.rsplit('Нет файла', 1)[0].strip()
    else:
        path_part = entry_text
    if '\ufffd' in path_part or '????' in path_part:
        return True
    return any(ord(c) < 32 and c not in '\t\r\n' for c in path_part)


# Домены, блокировка которых в hosts — признак вредоносного вмешательства.
# Списки блокировки рекламы обычно не трогают эти адреса.
PROTECTED_HOST_DOMAINS = {
    'google.com', 'www.google.com',
    'microsoft.com', 'www.microsoft.com', 'update.microsoft.com',
    'windowsupdate.com', 'www.windowsupdate.com',
    'kaspersky.com', 'www.kaspersky.com',
    'avast.com', 'www.avast.com',
    'drweb.com', 'www.drweb.com',
    'eset.com', 'www.eset.com',
    'malwarebytes.com', 'www.malwarebytes.com',
    'virustotal.com', 'www.virustotal.com',
}


def is_local_network_entry(norm: str) -> bool:
    """Локальный DNS/прокси: не чиним автоматически, только показываем."""
    low = norm.lower()
    if norm.startswith('Tcpip\\') and '[NameServer]' in norm and (
        '127.0.0.1' in norm or '::1' in norm
    ):
        return True
    if norm.startswith(('ProxyServer:', 'AutoConfigURL:', 'ManualProxies:')) and (
        '127.0.0.1' in low or 'localhost' in low
    ):
        return True
    return False


_HOSTS_META_RE = re.compile(r'^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}\s+-\s+')
_HOSTS_LOCAL_NAMES = {'localhost', 'localhost.localdomain', 'local',
                      'ip6-localhost', 'ip6-loopback', 'broadcasthost'}


def is_suspicious_hosts_line(line: str) -> bool:
    """Подозрительная запись hosts: блокировка защищённого или вредоносного домена.

    Строка может быть как «сырой» (`0.0.0.0 google.com`), так и в нотации
    `Hosts: ...`. Служебная строка с путём к файлу и записи localhost не считаются
    подменой. Остальные блокировки (реклама, телеметрия) не трогаются.
    """
    text = line.strip()
    if not text or text.startswith('#') or _HOSTS_META_RE.match(text):
        return False
    low = text.lower()
    if low.startswith('hosts:'):
        text = text.split(':', 1)[1].strip()
        if not text or text.startswith('#'):
            return False
    text = text.split('#', 1)[0].strip()
    tokens = text.split()
    if len(tokens) < 2:
        return False
    try:
        ipaddress.ip_address(tokens[0])
    except ValueError:
        return False
    hostnames = [token.strip('.').lower() for token in tokens[1:]]
    hostnames = [name for name in hostnames if name]
    if not hostnames or all(name in _HOSTS_LOCAL_NAMES for name in hostnames):
        return False
    if any(domain in name for name in hostnames for domain in MALICIOUS_DOMAINS):
        return True
    return any(
        name == domain or name.endswith('.' + domain)
        for name in hostnames
        for domain in PROTECTED_HOST_DOMAINS
    )


# Совместимость со старым именем в остальном коде.
def _hosts_entry_is_suspicious(norm: str) -> bool:
    return is_suspicious_hosts_line(norm)


def check_firewall_rule(entry: dict) -> bool:
    if not entry.get('is_firewall_rule'):
        return False

    norm = entry['normalized']
    norm_lower = norm.lower()

    # Правило только с портом, без программы — частый признак открытого порта.
    if 'LPort=' in norm and not re.search(r'[A-Za-z]:\\', norm):
        return not any(f'LPort={lp}' in norm for lp in LEGIT_FIREWALL_LPORTS)

    orphan = (
        entry.get('has_no_file')
        or 'Нет файла' in norm or 'No File' in norm
    )
    if orphan:
        if has_garbled_path(norm):
            return True
        for d in SUSPICIOUS_FIREWALL_DIRS:
            if d in norm_lower:
                return True
        # Осиротевшие правила обычных программ — необязательная чистка;
        # эксперты делают её выборочно, поэтому не трогаем автоматически.
        return False

    if not entry.get('has_caution'):
        return False

    for d in LEGIT_FIREWALL_PROGRAM_DIRS:
        if d in norm_lower:
            return False

    if has_garbled_path(norm):
        return True

    for d in SUSPICIOUS_FIREWALL_DIRS:
        if d in norm_lower:
            return True

    return False


_RE_SECURITY_PRODUCT = re.compile(r'^(AV|FW|AS):\s*([^(]+?)\s*\(([^)]*)\)')
_RE_MSCONFIG_SERVICE = re.compile(r'^MSCONFIG\\Services:\s*(\S+)', re.IGNORECASE)
_RE_SERVICE_NAME = re.compile(r'^[RSU]\d\s+([^;]+);')


def check_dead_av_registration(entry: dict, installed_lower: List[str]) -> bool:
    """Запись Центра безопасности об отключённом продукте, которого нет в системе."""
    if entry.get('section') != 'security_center':
        return False
    m = _RE_SECURITY_PRODUCT.match(entry['normalized'])
    if not m:
        return False
    product = m.group(2).strip().lower()
    status = m.group(3).lower()
    if 'defender' in product or 'защитник' in product:
        return False
    if 'disabled' not in status and 'отключ' not in status:
        return False
    return not any(product in prog for prog in installed_lower)


def check_dead_msconfig_service(entry: dict, service_names: Set[str]) -> bool:
    """Запись MSCONFIG о службе или драйвере, которых больше нет в отчёте."""
    if not entry['normalized'].upper().startswith('MSCONFIG'):
        return False
    m = _RE_MSCONFIG_SERVICE.match(entry['normalized'])
    if not m:
        return False
    return m.group(1).lower() not in service_names


def check_dead_chrome_reg_extension(entry: dict) -> bool:
    """Запись Chrome Extension в реестре без Path/update_url — мусор без цели."""
    norm = entry['normalized']
    low = norm.lower()
    if not norm.startswith('CHR ') or 'chrome\\extensions\\' not in low:
        return False
    return ('<отсутствует path' in low
            or 'отсутствует update_url' in low
            or 'missing path' in low)


def _shortcut_target(norm: str) -> str:
    _, sep, target = norm.partition(' -> ')
    return target.strip().lower() if sep else ''


def is_dead_start_menu_shortcut(entry: dict) -> bool:
    """Битый ярлык в меню «Пуск», ведущий в Program Files (программа удалена)."""
    norm = entry['normalized']
    if not norm.startswith('Shortcut:') or not entry.get('has_no_file'):
        return False
    if 'start menu' not in norm.lower():
        return False
    target = _shortcut_target(norm)
    return target.startswith(('c:\\program files\\', 'c:\\program files (x86)\\'))


def is_suspicious_task(entry: dict) -> bool:
    norm = entry['normalized'].lower()
    if not entry.get('is_task_entry'):
        return False
    if _is_legit_task(norm):
        return False
    for ind in SUSPICIOUS_TASK_INDICATORS:
        if ind in norm:
            return True
    if entry.get('has_caution') or entry.get('has_no_file'):
        return True
    return False


def check_hidden_program(entry: dict) -> bool:
    norm_lower = entry['normalized'].lower()
    return 'hidden' in norm_lower and any(
        kw in norm_lower for kw in HIDDEN_PROGRAM_KEYWORDS
    )


def check_suspicious_path(entry: dict) -> bool:
    norm = entry['normalized'].lower()
    for pat in SUSPICIOUS_PATH_PATTERNS:
        if pat in norm:
            return True
    return False


def is_legit_extension(entry: dict) -> bool:
    norm = entry['normalized']

    for ext_id in LEGIT_EXTENSION_IDS:
        if ext_id in norm:
            return True

    if norm.startswith('Edge Extension'):
        name_part = norm
        if ' - C:\\' in norm:
            name_part = norm.split(' - C:\\')[0]
        for prefix in LEGIT_EDGE_BUILTIN_PREFIXES:
            if prefix in name_part:
                return True

    if norm.startswith('CHR Extension'):
        name_part = norm
        if ' - C:\\' in norm:
            name_part = norm.split(' - C:\\')[0]
        if 'Component' in name_part or 'WASM' in name_part or 'pnacl' in name_part.lower():
            return True

    return False


def extract_extension_path(original: str) -> Optional[str]:
    m = re.search(r'[A-Za-z]+ Extension:.*?-\s+([A-Za-z]:\\[^\[]+)', original)
    if m:
        return m.group(1).strip()
    return None


def extract_msi_from_task(original: str) -> List[str]:
    ms = re.findall(r'"((?:C:\\)[^"]*\.msi)"', original)
    if ms:
        return ms
    ms2 = re.findall(r'((?:C:\\)[^\s"]*\.msi)', original)
    if ms2:
        return [m for m in ms2 if '..\\' not in m and len(m) > 10]
    return []


def convert_registry_entry(entry: dict, norm: str, guid_match: Optional[re.Match]) -> Optional[str]:
    """Convert a registry entry with GUID to a proper fix command."""
    if not guid_match:
        return None

    guid = guid_match.group(0).strip('{}')
    is_x32 = '-x32' in norm.lower() or 'wow6432node' in norm.lower()

    if is_x32:
        reg_path = f"HKLM\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved\\{guid}"
    else:
        reg_path = f"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved\\{guid}"

    return f"Reg: {reg_path},{guid}"


# ===================================================================
# Entry classification (what kind of fixlist entry is this?)
# ===================================================================

def _classify_entry(entry: dict) -> str:
    """Return the entry's category for sorting in fixlist."""
    norm = entry['normalized']

    if entry.get('is_group_policy'):
        return '0_grouppolicy'
    if entry.get('is_policies'):
        return '1_policies'
    if re.match(r'^HKLM', norm):
        return '2_hklm'
    if re.match(r'^HKU', norm):
        return '3_hku'
    if re.match(r'^HKCU', norm):
        return '4_hkcu'
    if re.match(r'^HKCR', norm):
        return '5_hkcr'
    if norm.startswith('CHR '):
        return '6_chrome'
    if norm.startswith('Edge '):
        return '7_edge'
    if norm.startswith('FF ') or norm.startswith('FireFox '):
        return '8_firefox'
    if norm.startswith('OPR ') or norm.startswith('Opera '):
        return '9_opera'
    if norm.startswith('YAN '):
        return '10_yandex'
    if norm.startswith('Hosts:'):
        return '11_hosts'
    if norm.startswith('Task:'):
        return '12_task'
    if re.match(r'[RSU]\d\s', norm):
        return '13_service'
    if entry.get('is_alternate_stream'):
        return '14_ads'
    if entry.get('is_firewall_rule'):
        return '15_firewall'
    if norm.startswith('ShortcutTarget:'):
        return '16_shortcut'
    if norm.startswith('C:\\'):
        return '17_files'
    if re.match(r'^\d{4}-\d{2}-\d{2}\s', norm):
        return '17_files'
    return '99_other'


# ===================================================================
# Core detection engine
# ===================================================================

BROWSER_FIX_CATEGORIES = {'6_chrome', '7_edge', '8_firefox', '9_opera', '10_yandex'}
BROWSER_ENTRY_PREFIXES = (
    'chr ', 'edge ', 'ff ', 'firefox ', 'opr ', 'opera ', 'yan ',
)
TEMP_PATH_MARKERS = (
    '\\temp\\', '\\tmp\\', 'appdata\\local\\temp', 'windows\\temp',
)
REBOOT_PATH_MARKERS = ('\\drivers\\',)
DEAD_SERVICE_MARKERS = (
    'нет файла', 'no file', 'отсутствует imagepath', 'imagepath missing',
    'отсутствует путь', 'no filepath',
)


def _needs_empty_temp(fix_entries: List[tuple]) -> bool:
    """Нужна ли очистка временных файлов после этих исправлений."""
    for category, text in fix_entries:
        norm_lower = text.lstrip().lower()
        if category in BROWSER_FIX_CATEGORIES:
            return True
        if norm_lower.startswith(BROWSER_ENTRY_PREFIXES):
            return True
        if category == '16_shortcut':
            # У ярлыка важна его собственная папка, а не путь цели:
            # удаление ярлыка с рабочего стола не требует чистки Temp.
            head = re.split(r'\s(?:->|=>)\s', norm_lower, maxsplit=1)[0]
            if any(marker in head for marker in TEMP_PATH_MARKERS):
                return True
        elif category == '17_files':
            if any(marker in norm_lower for marker in TEMP_PATH_MARKERS):
                return True
    return False


def _needs_reboot(fix_entries: List[tuple]) -> bool:
    """Нужна ли перезагрузка: службы/драйверы и файлы драйверов."""
    for category, text in fix_entries:
        low = text.lower()
        if category == '13_service':
            # Мёртвая запись без файла/ImagePath удаляется без перезагрузки.
            if any(marker in low for marker in DEAD_SERVICE_MARKERS):
                continue
            return True
        if category == '17_files':
            if any(marker in low for marker in REBOOT_PATH_MARKERS):
                return True
            if re.search(r'\.(?:sys|drv)\b', low):
                return True
    return False


def generate_fixlist(
    report_path: str,
    _rules: Optional[dict] = None,
    output_path: Optional[str] = None,
    has_third_party_av: bool = False,
    additional_path: Optional[str] = None,
) -> str:
    """Построить список исправлений по правилам детекции.

    _rules оставлен для обратной совместимости и не используется.
    """
    # Parse report
    try:
        report = parse_report(report_path)
        log.info('Отчёт разобран: %d записей', len(report['entries']))
    except Exception as exc:
        log.error('Не удалось разобрать отчёт %s: %s', report_path, exc)
        raise

    # Resolve and parse Additional report
    if additional_path is None:
        additional_path = _resolve_addition_path(report_path)

    additional_report = {'entries': []}
    if additional_path and os.path.exists(additional_path):
        try:
            additional_report = parse_addition(additional_path)
            log.info('Дополнительный отчёт разобран: %d записей',
                     len(additional_report['entries']))
        except Exception as exc:
            log.warning('Не удалось разобрать дополнительный отчёт: %s — продолжаю', exc)

    # --- Detection state ---
    fix_entries: List[tuple] = []
    seen: Set[str] = set()
    extra_paths: List[str] = []
    extra_msi: List[str] = []
    review_notes: List[str] = []
    flagged = 0

    def _add(entry_text: str, category: str = '99_other') -> None:
        nonlocal flagged
        norm = normalize_line(entry_text)
        if norm and norm not in seen:
            seen.add(norm)
            fix_entries.append((category, entry_text))
            flagged += 1

    has_hosts_issues = False
    all_entries = report['entries'] + additional_report['entries']
    total = len(all_entries)

    installed_programs_lower = [
        e['normalized'].lower()
        for e in additional_report.get('entries', [])
        if e.get('section') == 'installed_programs'
    ]
    service_names: Set[str] = set()
    for e in report['entries']:
        if e.get('is_service_entry'):
            m = _RE_SERVICE_NAME.match(e['normalized'])
            if m:
                service_names.add(m.group(1).lower())

    for entry in all_entries:
        original = entry['original']
        norm = entry['normalized']
        norm_lower = norm.lower()

        # === STEP 0: Skip known-safe entries ===

        # Chrome built-in component extensions
        if any(comp in norm for comp in CHROME_COMPONENTS):
            continue

        # Legitimate extension IDs
        if any(ext_id in norm for ext_id in LEGIT_EXTENSION_IDS):
            continue

        # Edge built-in extensions
        if is_legit_extension(entry):
            continue

        # Policy filter: skip fully benign policies
        if entry.get('has_caution') and '\\policies\\' in norm_lower:
            has_restriction = 'ограничение' in norm_lower or 'restriction' in norm_lower
            if not has_restriction and is_legit_policy_path(norm_lower):
                continue

        # Defender disabled + 3rd party AV = normal
        if has_third_party_av and is_defender_disabled_entry(entry):
            continue

        # Known harmless / false positive entries
        if is_known_harmless_entry(entry):
            continue

        # Локальный DNS/прокси: может быть легитимным (VPN, AdGuard) —
        # не меняем автоматически, только показываем в комментариях.
        if is_local_network_entry(norm):
            if norm not in review_notes:
                review_notes.append(norm)
            continue

        # Hosts: строки секции Hosts (сырые) и записи с префиксом Hosts:
        if entry.get('is_hosts_entry') or norm.startswith('Hosts:'):
            if is_suspicious_hosts_line(norm):
                has_hosts_issues = True
            continue

        # === STEP 1: Always-fix patterns (derived from expert data) ===

        # GroupPolicy with restriction/ATTENTION — 100% fix rate
        if entry.get('is_group_policy') and ('Ограничение' in norm or 'ATTENTION' in norm.upper() or '<====' in norm):
            _add(original, '0_grouppolicy')
            continue

        # Policies with ATTENTION — 100% fix rate
        if entry.get('is_policies') and ('Ограничение' in norm or 'ATTENTION' in norm.upper() or '<====' in norm):
            _add(original, '1_policies')
            continue

        # Политика, скрывающая страницы параметров Windows
        if 'settingspagevisibility' in norm_lower:
            _add(original, '2_hklm')
            continue

        # Empty Run key with [X] (malware remnant) — 100% fix rate
        if _RE_EMPTY_RUN_X.search(norm):
            _add(original, _classify_entry(entry))
            continue

        # MountPoints2 (malware persistence vector) — 100% fix rate
        if entry.get('is_mountpoints2') or 'MountPoints2' in norm:
            _add(original, '4_hkcu')
            continue

        # Run keys with missing file — 100% fix rate
        if entry.get('is_run_key') and entry.get('has_no_file'):
            _add(original, _classify_entry(entry))
            continue

        # Run key with empty/broken command: => [X]
        if entry.get('is_run_key') and re.search(r'=>\s*\[X\]', norm):
            _add(original, _classify_entry(entry))
            continue

        # === STEP 2: High-confidence malicious patterns ===

        # Known-malicious extension IDs (force-installed via HKLM)
        if any(ext_id in norm for ext_id in MALICIOUS_EXTENSION_IDS):
            _add(original, '2_hklm')
            path = extract_extension_path(original)
            if path:
                extra_paths.append(path)
            continue

        # Browser hijack: homepage/startup with known-malicious domains
        if any(domain in norm_lower for domain in MALICIOUS_DOMAINS):
            if entry.get('is_browser_homepage') or entry.get('is_browser_startup') or \
               'homepage' in norm_lower or 'startupurls' in norm_lower:
                _add(original, _classify_entry(entry))
                continue

        # Browser search/newtab/suggest hijack with a known-malicious domain
        if any(field in norm for field in SEARCH_HIJACK_FIELDS) and check_malicious_domain(entry):
            _add(original, _classify_entry(entry))
            continue

        # Firefox Plugin orphans (Нет файла)
        if norm.startswith('FF Plugin') and ('Нет файла' in norm or 'No File' in norm):
            _add(original, '8_firefox')
            continue

        # Chrome notification spam (push adware). Одного «.live» мало:
        # этот TLD бывает у легитимных сервисов (trovo.live).
        if norm.startswith('CHR Notifications:'):
            if check_malicious_domain(entry) or has_suspicious_tld(norm, min_count=2):
                _add(original, '6_chrome')
                continue

        # Tasks with missing file — dead task, remove even under Microsoft paths
        if entry.get('is_task_entry') and entry.get('has_no_file'):
            _add(original, '12_task')
            continue

        # Tasks with no file path
        if entry.get('is_task_entry') and (
            'отсутствует путь к файлу' in norm_lower or
            'no filepath' in norm_lower or
            'не путь к файлу' in norm_lower
        ):
            _add(original, '12_task')
            continue

        # Tasks with GUID-only (no description after the GUID)
        if entry.get('is_task_entry'):
            m = _RE_TASK_GUID_ONLY.match(norm.strip())
            if m:
                _add(original, '12_task')
                continue

        # Прочие записи с явно отсутствующим путём (например, DcomLaunch)
        if not entry.get('is_task_entry') and (
            'отсутствует путь к файлу' in norm_lower
            or 'no filepath' in norm_lower
            or 'не путь к файлу' in norm_lower
        ):
            category = '13_service' if re.match(r'^[RSU]\d|^DcomLaunch', norm) else _classify_entry(entry)
            _add(original, category)
            continue

        # Custom CLSID / shell extensions pointing to a missing file
        if entry.get('is_custom_clsid') and entry.get('has_no_file'):
            _add(original, '5_clsid')
            continue
        if norm.startswith('ContextMenuHandlers') and entry.get('has_no_file'):
            _add(original, '5_clsid')
            continue
        # Мёртвый BHO (Browser Helper Object)
        if norm.startswith(('BHO:', 'BHO-x32:')) and entry.get('has_no_file'):
            _add(original, '5_clsid')
            continue
        # Мёртвые overlay-расширения (файл отсутствует) — безопасная чистка
        if 'ShellIconOverlayIdentifiers' in norm and entry.get('has_no_file'):
            _add(original, '5_clsid')
            continue

        # === STEP 3: Suspicious but not definitely malicious ===

        # Unsigned/missing drivers from suspicious paths or with suspicious names
        if entry.get('is_service_entry'):
            if entry.get('has_x_marker') or entry.get('has_unsigned'):
                if _is_legit_driver_vendor(norm_lower):
                    continue
                if _is_suspicious_driver_name(norm):
                    _add(original, '13_service')
                    m = _RE_DRIVER_PATH.search(norm)
                    if m:
                        extra_paths.append(m.group(1))
                    continue
                if '<====' in norm and not _is_legit_driver_vendor(norm_lower):
                    _add(original, '13_service')
                    continue

        # ShortcutTarget with missing file
        if norm.startswith('ShortcutTarget:') and ('Нет файла' in norm or 'No File' in norm):
            _add(original, '16_shortcut')
            continue

        # Shortcut with missing target in a suspicious folder (Downloads/Temp/...)
        if norm.startswith('Shortcut:') and entry.get('has_no_file'):
            if any(d in norm_lower for d in SUSPICIOUS_FIREWALL_DIRS):
                _add(original, '16_shortcut')
                continue

        # === STEP 4: Firewall rules ===
        if check_firewall_rule(entry):
            _add(original, '15_firewall')
            continue

        # === STEP 5: Alternate Data Streams ===
        if entry.get('is_alternate_stream'):
            if 'Zone.Identifier' in norm or ':encryptable' in norm:
                continue
            _add(original.replace('\u200b', '').replace('\ufeff', ''), '14_ads')
            continue

        # === STEP 6: Browser extensions that look suspicious ===
        if entry.get('is_browser_extension') or 'Extension:' in norm:
            if any(name in norm_lower for name in ADWARE_EXT_NAMES):
                _add(original, _classify_entry(entry))
                path = extract_extension_path(original)
                if path:
                    extra_paths.append(path)
                continue

        # === STEP 7: Suspicious tasks ===
        if is_suspicious_task(entry):
            msifiles = extract_msi_from_task(original)
            extra_msi.extend(msifiles)
            _add(original, '12_task')
            continue

        # === STEP 8: Suspicious paths ===
        if check_suspicious_path(entry):
            _add(original, '17_files')
            continue

        # === STEP 9: Hidden programs (adware) ===
        if check_hidden_program(entry):
            _add(original, '17_files')
            continue

        # === STEP 10: Services/drivers with missing file or [X] marker ===
        if entry.get('is_service_entry'):
            if entry.get('has_no_file'):
                _add(original, '13_service')
                continue
            if entry.get('has_x_marker'):
                if not is_legit_missing_driver(norm_lower):
                    _add(original, '13_service')
                continue
            if ('отсутствует imagepath' in norm_lower
                    or 'imagepath missing' in norm_lower
                    or 'нет imagepath' in norm_lower):
                _add(original, '13_service')
                continue

        # === Мёртвые служебные записи (Центр безопасности, MSCONFIG, Chrome-реестр) ===
        if check_dead_av_registration(entry, installed_programs_lower):
            _add(original, '10_security')
            continue
        if check_dead_msconfig_service(entry, service_names):
            _add(original, '11_msconfig')
            continue

        # Запись Chrome Extension в реестре без Path/update_url
        if check_dead_chrome_reg_extension(entry):
            _add(original, '6_chrome')
            continue

        # Битый ярлык в меню «Пуск» на удалённую программу
        if is_dead_start_menu_shortcut(entry):
            _add(original, '16_shortcut')
            continue

        # === STEP 11: Caution-marked entries (catch-all, but filtered) ===
        if entry.get('has_caution'):
            # Firewall: не трогаем легитимные программы и обычные осиротевшие
            # правила — это необязательная чистка, а не признак вредоноса.
            if entry.get('is_firewall_rule'):
                if any(d in norm_lower for d in LEGIT_FIREWALL_PROGRAM_DIRS):
                    continue
                if (entry.get('has_no_file')
                        or 'нет файла' in norm_lower
                        or 'no file' in norm_lower):
                    continue
            # Skip if it's a Windows Defender policy (handled elsewhere)
            if 'Windows Defender' in norm and 'Policies' in norm:
                continue
            # Skip Malwarebytes self-protection
            if 'Malwarebytes' in norm and 'Доступ не разрешён' in norm:
                continue
            # Skip legitimate policy paths only if there is no restriction
            if 'policies' in norm_lower and any(
                legit in norm_lower for legit in (
                    'mozilla\\firefox', 'google\\chrome', 'microsoft\\edge',
                    'microsoft\\windows defender', 'microsoft\\office',
                )
            ) and not ('ограничение' in norm_lower or 'restriction' in norm_lower):
                continue
            # Неизвестное расширение с одной лишь меткой «ВНИМАНИЕ» не трогаем:
            # подписанные/неподписанные легитимные расширения тоже попадают сюда.
            if 'extension:' in norm_lower and not any(
                name in norm_lower for name in ADWARE_EXT_NAMES
            ):
                continue
            _add(original, _classify_entry(entry))
            continue

    # === STEP 12: Weakened security settings (from Additional report) ===
    for entry in additional_report.get('entries', []):
        if not entry.get('section', '').startswith('other_'):
            continue
        for cmd in check_weakened_security(entry):
            cat = '4_hkcu' if 'HKCU\\' in cmd or 'HKU\\' in cmd else '2_hklm'
            _add(cmd, cat)

    # === POST-PROCESSING ===

    # FLock section: extract suspicious folder paths from FLock section only
    flock_suspicious = {'IntelCore', 'SystemNetwork', 'RealtekHD', 'Windows Tasks Service'}
    flock_lines = report.get('sections', {}).get('flock', [])
    for line in flock_lines:
        stripped = line.strip()
        if stripped.startswith('=') or not stripped:
            continue
        for folder_name in flock_suspicious:
            if folder_name.lower() in stripped.lower():
                m = re.search(r'([A-Za-z]:\\[^\r\n]+)', stripped)
                if m:
                    extra_paths.append(m.group(1).strip())

    # Append extra file paths (extension folders, MSI files)
    for p in extra_paths:
        _add(p, '17_files')
    for m in extra_msi:
        _add(m, '17_files')

    # Sort by category then text (числовой порядок секций, не лексикографический)
    def _cat_rank(cat: str) -> int:
        try:
            return int(cat.split('_', 1)[0])
        except ValueError:
            return 999

    def _sort_key(item):
        cat, text = item
        return (_cat_rank(cat), normalize_line(text))

    fix_entries.sort(key=_sort_key)

    log.info('Проанализировано: %d из %d записей отмечено', flagged, total)
    if fix_entries:
        counts = Counter(cat for cat, _ in fix_entries)
        log.info('Секции: %s', ', '.join(
            f'{cat}={count}' for cat, count in sorted(counts.items(), key=lambda kv: _cat_rank(kv[0]))
        ))

    # Нет автодействий — не создаём fixlist: пустой файл только путает.
    if not fix_entries and not has_hosts_issues:
        if review_notes:
            log.warning('Подозрительных действий не найдено. Локальные DNS/прокси (%d) проверьте вручную:', len(review_notes))
            for note in review_notes:
                log.warning('  %s', note)
        else:
            log.info('Подозрительных записей не найдено — fixlist не создан.')
        return ''

    # === BUILD OUTPUT (with section comments) ===
    lines: List[str] = [
        'Start::',
        'CloseProcesses:',
        'SystemRestore: On',
        'CreateRestorePoint:',
    ]

    if review_notes:
        log.warning(
            'Локальные DNS/прокси (%d) не меняются автоматически — см. комментарии fixlist',
            len(review_notes),
        )
        lines.append('; ---- Проверьте вручную: локальные DNS/прокси ----')
        for note in review_notes:
            lines.append(f'; {note}')

    if has_hosts_issues:
        lines.append('Hosts:')

    # Group entries by section and add comment headers
    section_comments: Dict[str, Optional[str]] = {
        '0_grouppolicy': '; ---- Group Policy / Policies ----',
        '1_policies': None,
        '2_hklm': '; ---- Registry (HKLM) ----',
        '3_hku': '; ---- Registry (HKU) ----',
        '5_clsid': '; ---- Custom CLSID / Shell Extensions ----',
        '6_chrome': '; ---- Chrome ----',
        '7_edge': '; ---- Edge ----',
        '8_firefox': '; ---- Firefox ----',
        '9_opera': '; ---- Opera ----',
        '10_security': '; ---- Security Center ----',
        '11_msconfig': '; ---- MSCONFIG ----',
        '12_task': '; ---- Scheduled Tasks ----',
        '13_service': '; ---- Services / Drivers ----',
        '14_ads': '; ---- Alternate Data Streams ----',
        '15_firewall': '; ---- Firewall Rules ----',
        '16_shortcut': '; ---- Shortcuts ----',
        '17_files': '; ---- Files / Folders ----',
    }

    last_section: Optional[str] = None
    for cat, entry_text in fix_entries:
        parent_cat = {
            '0_grouppolicy': '0_grouppolicy', '1_policies': '0_grouppolicy',
            '2_hklm': '2_hklm', '3_hku': '3_hku', '4_hkcu': '3_hku',
            '5_hkcr': '2_hklm',
        }.get(cat, cat)
        if parent_cat != last_section and parent_cat in section_comments:
            comment = section_comments[parent_cat]
            if comment:
                lines.append(comment)
            last_section = parent_cat
        lines.append(entry_text)

    lines.append('ExportKey: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions')
    if _needs_empty_temp(fix_entries):
        lines.append('EmptyTemp:')
    if _needs_reboot(fix_entries):
        lines.append('Reboot:')
    lines.append('End::')

    output = '\n'.join(lines) + '\n'

    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, 'w', encoding='utf-8') as f:
            f.write(output)
        log.info('Fixlist сохранён: %s', output_path)
    else:
        print(output)

    return output


# ===================================================================
# Helpers
# ===================================================================

def _resolve_addition_path(report_path: str) -> str:
    """Найти дополнительный отчёт рядом с основным."""
    base = os.path.basename(report_path)
    dir_name = os.path.dirname(report_path) or '.'
    stem = os.path.splitext(base)[0]
    candidates = []
    if stem.endswith('-report'):
        candidates.append(os.path.join(dir_name, stem[:-len('-report')] + '-add.txt'))
    candidates += [
        os.path.join(dir_name, 'rusecurity-add.txt'),
        os.path.join(dir_name, 'rusecurity-additional.txt'),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0] if candidates else ''


# ===================================================================
# Third-party AV detection
# ===================================================================

_av_cache = None


def _powershell_path() -> str:
    return shutil.which('powershell') or 'powershell.exe'


def check_third_party_av() -> bool:
    global _av_cache
    if _av_cache is not None:
        return _av_cache
    if not IS_WINDOWS:
        _av_cache = False
        return _av_cache
    try:
        result = subprocess.run(
            [_powershell_path(), '-NoProfile', '-Command',
             '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; '
             'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | '
             'Where-Object { $_.displayName -notlike "*Windows Defender*" } | '
             'Select-Object -ExpandProperty displayName'],
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=15, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
        _names = [n.strip() for n in result.stdout.split('\n') if n.strip()]
        third_party = [
            name for name in _names
            if 'defender' not in name.lower() and 'защитник' not in name.lower()
        ]
        if third_party:
            log.info('Обнаружен сторонний Антивирус: %s', ', '.join(third_party))
        _av_cache = bool(third_party)
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.warning('Не удалось проверить Антивирус: %s', exc)
        _av_cache = False
    return _av_cache


# ===================================================================
# Display helpers
# ===================================================================

HEADER_LINES = ('Start::', 'CloseProcesses:', 'SystemRestore: On', 'CreateRestorePoint:')
FOOTER_LINES = ('EmptyTemp:', 'Reboot:', 'End::')
NON_ACTION_PREFIXES = ('startbatch:', 'endbatch:', 'del ', '"%userprofile%', 'hosts:')
_HEADER_LOWER = {line.lower() for line in HEADER_LINES}
_FOOTER_LOWER = {line.lower() for line in FOOTER_LINES}
_PRE_BODY_LOWER = {line.lower() for line in HEADER_LINES[:3]}


def is_action_line(line: str) -> bool:
    """Строка, которая является исправлением и получает номер при выводе."""
    s = line.strip()
    low = s.lower()
    if not s or low == 'код:' or s.startswith(';'):
        return False
    if low in _HEADER_LOWER or low in _FOOTER_LOWER:
        return False
    if low.startswith('exportkey:'):
        return False
    return not low.startswith(NON_ACTION_PREFIXES)


def highlight_fixlist(text: str, show_numbers: bool = False) -> str:
    if _USE_COLOR:
        B, M, R, G, Y, C, N = '\033[1m', '\033[95m', '\033[31m', '\033[32m', '\033[33m', '\033[36m', '\033[0m'
    else:
        B = M = R = G = Y = C = N = ''

    header, body, footer = parse_fixlist_content(text)
    out: List[str] = []
    for line in header:
        s = line.strip()
        if not s:
            continue
        if s == 'Код:' or s.startswith(';'):
            out.append(f'{C}{line}{N}')
        elif s in HEADER_LINES:
            out.append(f'{B}{G}{line}{N}')
        else:
            out.append(line)

    entry_num = 0
    for line in body:
        s = line.strip()
        if not s:
            continue
        if s.startswith(';'):
            out.append(line)
            out.append('')
            continue
        if not is_action_line(line):
            out.append(line)
            continue
        entry_num += 1
        prefix = f'{B}{M}{entry_num:2d}){N} ' if show_numbers else ''
        if 'ВНИМАНИЕ' in line or 'ATTENTION' in line.upper():
            out.append(f'{B}{R}{prefix}{line}{N}')
        elif 'Нет файла' in line or 'No File' in line or '[X]' in line:
            out.append(f'{Y}{prefix}{line}{N}')
        elif line.lstrip().startswith('C:\\'):
            out.append(f'{B}{prefix}{line}{N}')
        else:
            out.append(f'{prefix}{line}')
        out.append('')

    for line in footer:
        s = line.strip()
        if not s:
            continue
        if s.startswith('ExportKey:'):
            out.append(f'{C}{line}{N}')
        elif s in FOOTER_LINES:
            out.append(f'{G}{line}{N}')
        else:
            out.append(line)

    while out and not out[-1].strip():
        out.pop()
    return '\n'.join(out)


def display_fixlist(output_path: Path) -> None:
    with open(output_path, 'r', encoding='utf-8') as f:
        content = f.read()
    if _USE_COLOR:
        C, B, N = '\033[36m', '\033[1m', '\033[0m'
    else:
        C = B = N = ''
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{C}{'=' * 20}{N}")
    print(f'{B}{C}FIXLIST{N}')
    print(f"{C}{'=' * 20}{N}")
    try:
        print(highlight_fixlist(content, show_numbers=True))
    except UnicodeEncodeError:
        safe = content.encode('cp1251', errors='replace').decode('cp1251')
        print(highlight_fixlist(safe, show_numbers=True))
    print(f"{C}{'=' * 20}{N}")


# ===================================================================
# FixList parsing for interactive selection
# ===================================================================

def parse_fixlist_content(content: str):
    """Разделить fixlist на шапку, тело и хвост.

    Тело — всё между CreateRestorePoint: и ExportKey: (или до конца файла).
    """
    header, body, footer, state = [], [], [], 'header'
    for line in content.split('\n'):
        stripped = line.strip()
        low = stripped.lower()
        if state == 'header':
            header.append(line)
            if low == 'createrestorepoint:':
                state = 'body'
            elif stripped and low != 'код:' and low not in _PRE_BODY_LOWER:
                # fixlist без CreateRestorePoint: первая значимая строка — уже тело
                header.pop()
                body.append(line)
                state = 'body'
        elif state == 'body':
            if low.startswith('exportkey:'):
                footer.append(line)
                state = 'footer'
            else:
                body.append(line)
        else:
            footer.append(line)
    return header, body, footer


def _parse_selection(numbers_input: str) -> Set[int]:
    keep: Set[int] = set()
    for part in re.split(r'[,\s]+', numbers_input.strip()):
        if not part:
            continue
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                keep.update(range(int(start), int(end) + 1))
            except ValueError:
                continue
        else:
            try:
                keep.add(int(part))
            except ValueError:
                continue
    return keep


def filter_fixlist_by_numbers(content: str, numbers_input: str) -> str:
    header, body, footer = parse_fixlist_content(content)
    action_indices = [i for i, line in enumerate(body) if is_action_line(line)]
    if not action_indices:
        return content

    keep = _parse_selection(numbers_input)
    if not keep:
        return content

    kept_indices = {
        index for number, index in enumerate(action_indices, 1) if number in keep
    }
    if not kept_indices:
        return '\n'.join(header + footer).rstrip('\n') + '\n'

    out: List[str] = []
    for index, line in enumerate(body):
        stripped = line.strip()
        if not stripped:
            continue
        if is_action_line(line):
            if index in kept_indices:
                out.append(line)
            continue
        if stripped.startswith(';'):
            next_index = next(
                (j for j in range(index + 1, len(body))
                 if is_action_line(body[j]) or body[j].strip().startswith(';')),
                None,
            )
            if next_index is not None and next_index in kept_indices:
                out.append(line)
            continue
        # пакетный блок, Hosts: и прочие служебные строки оставляем всегда
        out.append(line)

    result = '\n'.join(header + out + footer).rstrip('\n') + '\n'
    return result


# ===================================================================
# Weakened security settings detection
# ===================================================================

SECURITY_FIXES = [
    ('smartscreenenabled', r'(off|0)\b',
     'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer" '
     '/v "SmartScreenEnabled" /t REG_SZ /d "Warn" /f'),
    ('enablewebcontentevaluation', r'0\b',
     'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppHost" '
     '/v "EnableWebContentEvaluation" /t REG_DWORD /d 1 /f'),
    ('tamperprotection', r'(0|4)\b',
     'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features" '
     '/v "TamperProtection" /t REG_DWORD /d 5 /f'),
]


def check_weakened_security(entry: dict) -> List[str]:
    norm_lower = entry['normalized'].lower()
    cmds = []
    for keyword, pattern, fix in SECURITY_FIXES:
        if re.search(rf'\b{re.escape(keyword)}\s*:\s*{pattern}', norm_lower):
            cmds.append(f'Reg: {fix}')
    return cmds

