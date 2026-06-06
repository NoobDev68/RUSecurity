import os
import re
from typing import List, Tuple, Dict, Optional

SECTION_HEADERS = {
    r'Процессы': 'processes',
    r'Реестр Windows': 'registry',
    r'Запланированные задачи': 'tasks',
    r'Internet': 'internet',
    r'Службы': 'services',
    r'Драйверы': 'drivers',
    r'NetSvcs': 'netsvcs',
    r'Один месяц \(создан\)': 'files_created',
    r'Один месяц \(изменён\)': 'files_modified',
    r'Файлы в корне каталогов': 'root_files',
    r'SigCheck': 'sigcheck',
    r'Учетные записи': 'accounts',
    r'Центр безопасности': 'security_center',
    r'Установленные программы': 'installed_programs',
}

SECTION_ALIASES = {
    'HKLM': 'registry',
    'HKU': 'registry',
    'HKCR': 'registry',
    'HKCU': 'registry',
    'Tcpip': 'internet',
    'Edge': 'internet',
    'FireFox': 'internet',
    'FF ': 'internet',
    'Chrome': 'internet',
    'CHR ': 'internet',
    'Yandex': 'internet',
    'YAN ': 'internet',
    'Task:': 'tasks',
    'Service:': 'services',
    'R2 ': 'services',
    'R3 ': 'services',
    'S2 ': 'services',
    'S3 ': 'services',
    'S1 ': 'services',
    'S0 ': 'services',
}

def normalize_line(line: str) -> str:
    line = line.strip()
    line = re.sub(r'\s+', ' ', line)
    return line

def parse_frst_report(filepath: str) -> Dict:
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    result = {
        'metadata': {},
        'sections': {},
        'entries': [],
        'raw_lines': lines,
    }

    current_section = 'header'
    section_buffer = []

    for line in lines:
        stripped = line.rstrip('\n\r')

        section_match = None
        if stripped.startswith('===='):
            for header_pattern in SECTION_HEADERS:
                if re.search(header_pattern, stripped):
                    section_match = SECTION_HEADERS[header_pattern]
                    break

        if section_match:
            if section_buffer:
                result['sections'][current_section] = section_buffer
            current_section = section_match
            section_buffer = [stripped]
            continue

        section_buffer.append(stripped)

    if section_buffer:
        result['sections'][current_section] = section_buffer

    for section_name, section_lines in result['sections'].items():
        for line in section_lines:
            normalized = normalize_line(line)
            if not normalized or normalized.startswith('(') or normalized.startswith('='):
                continue
            if normalized.startswith('Если запись'):
                continue
            if normalized.startswith('Если элемент'):
                continue
            if normalized.startswith('В fixlist'):
                continue
            if normalized.startswith('Нет автоматического'):
                continue

            entry = {
                'section': section_name,
                'original': line,
                'normalized': normalized,
                'has_caution': '<==== ВНИМАНИЕ' in normalized,
                'has_no_file': '(Нет файла)' in normalized,
                'has_unsigned': '[Файл не подписан]' in normalized,
                'has_missing_driver': '[X]' in normalized,
                'is_mountpoints2': 'MountPoints2' in normalized,
                'is_alternate_stream': 'AlternateDataStreams' in normalized,
                'is_group_policy': normalized.startswith('GroupPolicy:'),
                'is_policies': normalized.startswith('Policies:'),
                'is_firewall_rule': normalized.startswith('FirewallRules:'),
                'is_browser_homepage': normalized.startswith('CHR HomePage') or normalized.startswith('Edge HomePage'),
                'is_browser_startup': normalized.startswith('CHR StartupUrls') or normalized.startswith('Edge StartupUrls'),
                'is_browser_search': normalized.startswith('CHR DefaultSearch') or normalized.startswith('Edge DefaultSearch'),
                'is_browser_extension': 'Extension:' in normalized,
                'is_task_entry': normalized.startswith('Task:'),
                'is_service_entry': re.match(r'[RSS]\d\s', normalized),
                'is_run_key': normalized.startswith('HK') and 'Run:' in normalized,
            }
            result['entries'].append(entry)

    return result


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
        entry_norm = entry['normalized']
        if action_norm == entry_norm:
            return entry

    for entry in entries:
        entry_norm = entry['normalized']
        if entry_norm.startswith(action_norm) or action_norm.startswith(entry_norm):
            return entry

    action_stripped = re.sub(r'\s+', ' ', action_norm)
    for entry in entries:
        entry_stripped = re.sub(r'\s+', ' ', entry['normalized'])
        if action_stripped == entry_stripped:
            return entry

    action_guid = re.sub(r'\{[0-9A-Fa-f-]{36}\}', '{GUID}', action_norm)
    if action_guid != action_norm:
        for entry in entries:
            entry_guid = re.sub(r'\{[0-9A-Fa-f-]{36}\}', '{GUID}', entry['normalized'])
            if action_guid == entry_guid:
                return entry

    return None


def parse_fixlist(filepath: str) -> List[str]:
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()
    actions = []
    for line in lines:
        stripped = line.rstrip('\n\r')
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


def parse_additional_report(filepath: str) -> Dict:
    result = {
        'metadata': {},
        'sections': {},
        'entries': [],
    }
    if not os.path.exists(filepath):
        return result

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    current_section = 'header'
    section_buffer = []

    section_map = {
        'Alternate Data Streams': 'alternate_streams',
        'Правила Брандмауэра': 'firewall_rules',
        'Установленные программы': 'installed_programs',
        'Пользовательские CLSID': 'custom_clsid',
        'Ярлыки': 'shortcuts',
        'Hosts': 'hosts',
        'Internet Explorer': 'internet_explorer',
        'Загруженные модули': 'loaded_modules',
    }

    for line in lines:
        stripped = line.rstrip('\n\r')

        if stripped.startswith('===='):
            for rus_name, eng_name in section_map.items():
                if rus_name in stripped:
                    if section_buffer:
                        result['sections'][current_section] = section_buffer
                    current_section = eng_name
                    section_buffer = [stripped]
                    break
            else:
                if section_buffer:
                    result['sections'][current_section] = section_buffer
                current_section = 'other'
                section_buffer = [stripped]
            continue

        section_buffer.append(stripped)

    if section_buffer:
        result['sections'][current_section] = section_buffer

    for section_name, section_lines in result['sections'].items():
        for line in section_lines:
            normalized = normalize_line(line)
            if not normalized or normalized.startswith('(') or normalized.startswith('='):
                continue
            if normalized.startswith('Если запись'):
                continue
            if normalized.startswith('Если элемент'):
                continue
            if normalized.startswith('В fixlist'):
                continue
            if normalized.startswith('Нет автоматического'):
                continue

            entry = {
                'section': section_name,
                'original': line,
                'normalized': normalized,
                'has_caution': '<==== ВНИМАНИЕ' in normalized,
                'has_no_file': '(Нет файла)' in normalized,
                'has_unsigned': '[Файл не подписан]' in normalized,
                'has_missing_driver': False,
                'is_mountpoints2': False,
                'is_alternate_stream': 'AlternateDataStreams' in normalized,
                'is_group_policy': False,
                'is_policies': False,
                'is_firewall_rule': normalized.startswith('FirewallRules:'),
                'is_browser_homepage': False,
                'is_browser_startup': False,
                'is_browser_search': False,
                'is_browser_extension': False,
                'is_task_entry': False,
                'is_service_entry': False,
                'is_run_key': False,
                'is_hidden_program': 'Hidden' in normalized and section_name == 'installed_programs',
                'is_custom_clsid': section_name == 'custom_clsid',
                'is_shortcut': section_name == 'shortcuts',
            }
            result['entries'].append(entry)

    return result


def is_boilerplate_action(action: str) -> bool:
    boilerplate = [
        'Start::', 'End::', 'CloseProcesses:', 'SystemRestore:',
        'CreateRestorePoint:', 'EmptyTemp:', 'Reboot:', 'Код:',
        'ExportKey:', 'StartBatch:', 'EndBatch:',
    ]
    a = action.strip()
    for b in boilerplate:
        if a.startswith(b):
            return True
    if a.startswith('del ') or a.startswith('"%userprofile%'):
        return True
    return False
