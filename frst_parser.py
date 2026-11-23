"""Парсинг отчётов FRST.txt / Addition.txt и файлов fixlist.txt."""

import os
import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Section recognition
# ---------------------------------------------------------------------------
# Заголовки FRST выглядят как «========== Реестр Windows ==========».
# Отчёты бывают русскими и английскими, поэтому ищем ключевые слова обоих
# языков. Порядок важен: более конкретные заголовки идут раньше общих.
SECTION_KEYWORDS: List[Tuple[str, str]] = [
    ('one month (created)', 'files_created'),
    ('один месяц (создан)', 'files_created'),
    ('три месяца (создан)', 'files_created'),
    ('one month (modified)', 'files_modified'),
    ('один месяц (изменён)', 'files_modified'),
    ('один месяц (изменен)', 'files_modified'),
    ('три месяца (изменён)', 'files_modified'),
    ('три месяца (изменен)', 'files_modified'),
    ('files in the root', 'root_files'),
    ('файлы в корне', 'root_files'),
    ('scheduled tasks', 'tasks'),
    ('запланированные задачи', 'tasks'),
    ('processes', 'processes'),
    ('процессы', 'processes'),
    ('registry', 'registry'),
    ('реестр', 'registry'),
    ('services', 'services'),
    ('службы', 'services'),
    ('drivers', 'drivers'),
    ('драйверы', 'drivers'),
    ('netsvcs', 'netsvcs'),
    ('svchost', 'netsvcs'),
    ('internet', 'internet'),
    ('firewallrules', 'firewall_rules'),
    ('flock', 'flock'),
    ('fcheck', 'fcheck'),
    ('known dlls', 'known_dlls'),
    ('sigcheck', 'sigcheck'),
    ('association', 'association'),
    ('ассоциация', 'association'),
    ('shortcuts', 'shortcuts'),
    ('ярлыки', 'shortcuts'),
    ('security center', 'security_center'),
    ('центр безопасности', 'security_center'),
    ('installed programs', 'installed_programs'),
    ('установленные программы', 'installed_programs'),
    ('accounts', 'accounts'),
    ('учетные записи', 'accounts'),
    ('учётные записи', 'accounts'),
    ('bcd', 'bcd'),
]

# Заголовки Addition.txt. Неизвестные разделы попадают в other_N — по этому
# префиксу проверяются ослабленные настройки безопасности.
ADDITIONAL_SECTIONS: List[Tuple[str, str]] = [
    ('alternate data streams', 'alternate_streams'),
    ('альтернативные потоки', 'alternate_streams'),
    ('firewall rules', 'firewall_rules'),
    ('правила брандмауэра', 'firewall_rules'),
    ('installed programs', 'installed_programs'),
    ('установленные программы', 'installed_programs'),
    ('custom clsid', 'custom_clsid'),
    ('пользовательские clsid', 'custom_clsid'),
    ('shortcuts', 'shortcuts'),
    ('ярлыки', 'shortcuts'),
    ('hosts', 'hosts'),
    ('internet explorer', 'internet_explorer'),
    ('loaded modules', 'loaded_modules'),
    ('загруженные модули', 'loaded_modules'),
    ('accounts', 'accounts'),
    ('учетные записи', 'accounts'),
    ('учётные записи', 'accounts'),
    ('security center', 'security_center'),
    ('центр безопасности', 'security_center'),
    ('codecs', 'codecs'),
    ('safe mode', 'safe_mode'),
    ('безопасный режим', 'safe_mode'),
    ('association', 'association'),
    ('ассоциация', 'association'),
    ('msconfig', 'msconfig'),
    ('restore points', 'restore_points'),
    ('точки восстановления', 'restore_points'),
    ('faulty device', 'faulty_devices'),
    ('неисправное устройство', 'faulty_devices'),
    ('event log', 'eventlog'),
    ('ошибки журнала', 'eventlog'),
    ('memory info', 'memory_info'),
    ('информация о памяти', 'memory_info'),
    ('drives', 'drives'),
    ('диски', 'drives'),
    ('mbr', 'mbr'),
    ('network', 'network'),
]

RE_CAUTION = re.compile(r'<={4,}\s*(?:ВНИМАНИЕ|ATTENTION)', re.IGNORECASE)
RE_NO_FILE = re.compile(
    r'(?:\(\s*(?:нет файла|no file)\s*\)|(?:->|=>)\s*(?:нет файла|no file)\b)',
    re.IGNORECASE,
)
RE_NOT_SIGNED = re.compile(r'\[(?:файл не подписан|file not signed)\]', re.IGNORECASE)
RE_SERVICE_ENTRY = re.compile(r'^[RSU][0-9]\s')
RE_BROWSER_PREFIXES = ('CHR ', 'Edge ', 'FF ', 'OPR ', 'YAN ', 'Brave ')

# Служебные строки-пояснения FRST, которые не являются записями.
SKIP_PREFIXES = (
    'Если запись', 'Если элемент', 'В fixlist', 'Нет автоматического',
    'If an entry', 'If an element', 'In fixlist', 'No automatic',
)

BOM_UTF8 = b'\xef\xbb\xbf'
BOM_UTF16 = (b'\xff\xfe', b'\xfe\xff')

# Достаточно префикса, чтобы отличить UTF-8 от CP1251: заголовки FRST содержат
# нелатинские символы уже в первых строках. Полное чтение файла здесь излишне
# (detect_encoding вызывается в цикле ожидания отчёта на каждом тике).
_ENCODING_PROBE_SIZE = 64 * 1024


def normalize_line(line: str) -> str:
    """Схлопнуть пробелы и обрезать строку по краям."""
    line = line.strip()
    line = re.sub(r'\s+', ' ', line)
    return line


def detect_encoding(filepath) -> str:
    """Определить кодировку файла по BOM либо попыткой декодировать UTF-8."""
    with open(filepath, 'rb') as f:
        raw = f.read(_ENCODING_PROBE_SIZE)
    if raw.startswith(BOM_UTF8):
        return 'utf-8-sig'
    if raw[:2] in BOM_UTF16:
        return 'utf-16'
    try:
        raw.decode('utf-8')
        return 'utf-8'
    except UnicodeDecodeError:
        return 'cp1251'


def _header_text(line: str) -> Optional[str]:
    """Вернуть текст заголовка секции или None для разделителя/обычной строки."""
    if not line.startswith('='):
        return None
    text = line.strip('= \t').lower()
    return text or None


def _detect_section(line: str) -> Optional[str]:
    text = _header_text(line)
    if not text:
        return None
    for keyword, section in SECTION_KEYWORDS:
        if keyword in text:
            return section
    return None


def _detect_additional_section(line: str) -> Optional[str]:
    text = _header_text(line)
    if not text:
        return None
    for keyword, section in ADDITIONAL_SECTIONS:
        if keyword in text:
            return section
    return None


def _split_sections(lines: List[str], detect) -> Dict[str, List[str]]:
    """Разбить отчёт на секции по строкам-заголовкам."""
    sections: Dict[str, List[str]] = {}
    current = 'header'
    buffer: List[str] = []

    def flush() -> None:
        if not buffer:
            return
        if current in sections:
            sections[current].extend(buffer)
        else:
            sections[current] = list(buffer)

    for raw_line in lines:
        line = raw_line.rstrip('\r\n')
        section = detect(line)
        if section:
            flush()
            current = section
            buffer = [line]
        else:
            buffer.append(line)
    flush()
    return sections


def _browser_field(normalized: str, field: str) -> bool:
    return any(normalized.startswith(prefix + field) for prefix in RE_BROWSER_PREFIXES)


def _make_entry(section: str, line: str) -> Dict:
    """Построить запись с одинаковым набором флагов для FRST и Addition."""
    normalized = normalize_line(line)
    normalized = re.sub(r'[\.\!\?]$', '', normalized)
    low = normalized.lower()

    return {
        'section': section,
        'original': line,
        'normalized': normalized,
        'has_caution': bool(RE_CAUTION.search(line)),
        'has_cyrillic': '<==== Cyrillic' in line,
        'has_no_file': bool(RE_NO_FILE.search(line)),
        'has_unsigned': bool(RE_NOT_SIGNED.search(line)),
        'has_x_marker': '[X]' in line,
        'is_mountpoints2': 'MountPoints2' in normalized,
        'is_alternate_stream': section == 'alternate_streams' or 'AlternateDataStreams' in normalized,
        'is_group_policy': normalized.startswith('GroupPolicy:'),
        'is_policies': normalized.startswith('Policies:'),
        'is_firewall_rule': section == 'firewall_rules' or normalized.startswith('FirewallRules:'),
        'is_browser_homepage': _browser_field(normalized, 'HomePage'),
        'is_browser_startup': _browser_field(normalized, 'StartupUrls'),
        'is_browser_search': _browser_field(normalized, 'DefaultSearch'),
        'is_browser_extension': 'Extension:' in line,
        'is_task_entry': normalized.startswith('Task:'),
        'is_service_entry': bool(RE_SERVICE_ENTRY.match(normalized)),
        'is_run_key': normalized.startswith('HK') and bool(
            re.search(r'\\Run(?:Once(?:Ex)?|Services(?:Once)?)?:', normalized)
        ),
        'is_hosts_entry': section == 'hosts' or normalized.startswith('Hosts:'),
        'is_shortcut_entry': section == 'shortcuts' or normalized.startswith('Shortcut:'),
        'is_hidden_program': section == 'installed_programs' and 'hidden' in low,
        'is_custom_clsid': section == 'custom_clsid',
        'is_shortcut': section == 'shortcuts',
        'is_defender_exclusion': section.startswith('other_') and 'Windows Defender\\Exclusions' in normalized,
    }


def _is_entry_line(normalized: str) -> bool:
    if not normalized or normalized.startswith('(') or normalized.startswith('='):
        return False
    return not normalized.startswith(SKIP_PREFIXES)


def _build_entries(sections: Dict[str, List[str]]) -> List[Dict]:
    entries: List[Dict] = []
    for section, section_lines in sections.items():
        for line in section_lines:
            normalized = normalize_line(line)
            if _is_entry_line(normalized):
                entries.append(_make_entry(section, line))
    return entries


def parse_frst_report(filepath: str) -> Dict:
    """Разобрать FRST.txt на секции и записи."""
    enc = detect_encoding(filepath)
    with open(filepath, 'r', encoding=enc, errors='replace') as f:
        lines = f.readlines()

    sections = _split_sections(lines, _detect_section)
    return {
        'metadata': {},
        'sections': sections,
        'entries': _build_entries(sections),
        'raw_lines': lines,
    }


def parse_additional_report(filepath: str) -> Dict:
    """Разобрать Addition.txt на секции и записи."""
    result: Dict = {'metadata': {}, 'sections': {}, 'entries': []}
    if not os.path.exists(filepath):
        return result

    enc = detect_encoding(filepath)
    with open(filepath, 'r', encoding=enc, errors='replace') as f:
        lines = f.readlines()

    sections: Dict[str, List[str]] = {}
    current = 'header'
    buffer: List[str] = []
    other_counter = 0

    def flush() -> None:
        if not buffer:
            return
        if current in sections:
            sections[current].extend(buffer)
        else:
            sections[current] = list(buffer)

    for raw_line in lines:
        line = raw_line.rstrip('\r\n')
        text = _header_text(line)
        if text:
            flush()
            section = _detect_additional_section(line)
            if section is None:
                other_counter += 1
                section = f'other_{other_counter}'
            current = section
            buffer = [line]
        else:
            buffer.append(line)
    flush()

    result['sections'] = sections
    result['entries'] = _build_entries(sections)
    return result


# ===================================================================
# Research helpers
# -------------------------------------------------------------------
# Ниже — функции, которые используются только исследовательскими скриптами
# (extract_rules.py, compare_pair.py, compare_all.py) для сверки с корпусом
# экспертных fixlist. Рантайм GenFix их не вызывает.
# ===================================================================


def normalize_action_for_matching(action: str) -> str:
    action = action.strip()
    action = re.sub(r'\s+', ' ', action)
    return action


def match_action_to_entry(action: str, entries: List[Dict]) -> Optional[Dict]:
    action_norm = normalize_action_for_matching(action)

    skip_prefixes = [
        'Start::', 'End::', 'CloseProcesses:', 'SystemRestore:',
        'CreateRestorePoint:', 'EmptyTemp:', 'Reboot:', 'Код:',
        'StartBatch:', 'EndBatch:', 'ExportKey:',
    ]
    for prefix in skip_prefixes:
        if action_norm.startswith(prefix):
            return None

    if action_norm.startswith('del ') or action_norm.startswith('"%userprofile%'):
        return None

    for entry in entries:
        if action_norm == entry['normalized']:
            return entry

    for entry in entries:
        entry_norm = entry['normalized']
        if entry_norm.startswith(action_norm) or action_norm.startswith(entry_norm):
            return entry

    action_guid = re.sub(r'\{[0-9A-Fa-f-]{36}\}', '{GUID}', action_norm)
    if action_guid != action_norm:
        for entry in entries:
            entry_guid = re.sub(r'\{[0-9A-Fa-f-]{36}\}', '{GUID}', entry['normalized'])
            if action_guid == entry_guid:
                return entry

    return None


def parse_fixlist(filepath: str) -> List[str]:
    """Прочитать fixlist.txt, отбросив BOM, пустые строки и метку «Код:»."""
    enc = detect_encoding(filepath)
    with open(filepath, 'r', encoding=enc, errors='replace') as f:
        lines = f.readlines()
    actions = []
    for line in lines:
        stripped = line.rstrip('\r\n').strip().lstrip('\ufeff')
        if stripped and stripped != 'Код:':
            actions.append(stripped)
    return actions


def generalize_pattern(text: str) -> str:
    text = re.sub(r'\{[0-9A-Fa-f-]{36}\}', '{GUID}', text)
    text = re.sub(r'\{[0-9A-Fa-f-]{32}\}', '{GUID32}', text)
    text = re.sub(r'[0-9A-Fa-f]{8}[-]?[0-9A-Fa-f]{4}[-]?[0-9A-Fa-f]{4}[-]?[0-9A-Fa-f]{4}[-]?[0-9A-Fa-f]{12}', '{GUID}', text)
    text = re.sub(r'S-1-5-21-\d+-\d+-\d+-\d+', '{SID}', text)
    text = re.sub(r'S-1-5-\d+', '{SID}', text)
    text = re.sub(r'\\[0-9A-Fa-f]{32}\\[ ]', '[HASH]', text)
    text = re.sub(r'\[[0-9]{4}-[0-9]{2}-[0-9]{2}\]', '[DATE]', text)
    text = re.sub(r'\{[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}\}', '{GUID}', text)
    text = re.sub(r'\d{4}-\d{2}-\d{2}', 'YYYY-MM-DD', text)
    text = re.sub(r'\d{2}:\d{2}:\d{2}', 'HH:MM:SS', text)
    return text


def is_boilerplate_action(action: str) -> bool:
    boilerplate = [
        'Start::', 'End::', 'CloseProcesses:', 'SystemRestore:',
        'CreateRestorePoint:', 'EmptyTemp:', 'Reboot:', 'Код:',
        'ExportKey:', 'StartBatch:', 'EndBatch:',
        'StartPowershell:', 'EndPowershell:', 'StartRegedit:', 'EndRegedit:',
    ]
    a = action.strip().lstrip('\ufeff')
    low = a.lower()
    for b in boilerplate:
        if low.startswith(b.lower()):
            return True
    if low.startswith('del ') or low.startswith('"%userprofile%'):
        return True
    return False
