"""Разбор fixlist на действия, которые умеет выполнять свой фиксер."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# --- виды действий ---------------------------------------------------------
REG_VALUE = 'reg_value'          # удалить значение реестра
REG_KEY = 'reg_key'              # удалить ключ/ветку
REG_SET = 'reg_set'              # восстановить значение (Reg: reg add ...)
SERVICE = 'service'              # удалить службу/драйвер
TASK = 'task'                    # удалить задачу
FIREWALL = 'firewall'            # удалить правило брандмауэра
SECURITY_PROVIDER = 'security_provider'  # мёртвая запись AV/FW
SHORTCUT = 'shortcut'            # удалить .lnk по пути
SHORTCUT_TARGET = 'shortcut_target'  # найти .lnk по имени в Startup
SHORTCUT_CLEAN = 'shortcut_clean'    # перезаписать .lnk без лишнего URL
PROCESS_KILL = 'process_kill'        # завершить процесс и убрать файл
BITS_CANCEL = 'bits_cancel'          # отменить BITS-задание
WEB_DATA = 'web_data'                # удалить поисковый движок из Web Data
SERVICE_QUOTE = 'service_quote'      # взять ImagePath службы в кавычки
FILE = 'file'                    # файл или папка
ADS = 'ads'                      # альтернативный поток
HOSTS = 'hosts'                  # сброс hosts
BROWSER = 'browser'              # поиск/домашняя страница в профиле браузера
EXTENSION = 'extension'          # расширение Chromium: папка и запись в профиле
EMPTY_TEMP = 'empty_temp'
BROWSER_CACHE = 'browser_cache'
EXPORT_KEY = 'export_key'
RESTORE_POINT = 'restore_point'
REBOOT = 'reboot'
CLOSE_PROCESSES = 'close_processes'
NOOP = 'noop'
MANUAL = 'manual'                # не поддерживается автоматически

KIND_LABELS = {
    REG_VALUE: 'значения реестра',
    REG_KEY: 'ключи реестра',
    REG_SET: 'восстановление настроек',
    SERVICE: 'службы и драйверы',
    TASK: 'задачи',
    FIREWALL: 'правила брандмауэра',
    SECURITY_PROVIDER: 'записи Центра безопасности',
    SHORTCUT: 'ярлыки',
    SHORTCUT_TARGET: 'ярлыки автозагрузки',
    SHORTCUT_CLEAN: 'ярлыки браузеров',
    PROCESS_KILL: 'процессы',
    BITS_CANCEL: 'BITS-задания',
    WEB_DATA: 'поисковые движки',
    SERVICE_QUOTE: 'пути служб',
    FILE: 'файлы и папки',
    ADS: 'альтернативные потоки',
    HOSTS: 'hosts',
    BROWSER: 'настройки браузера',
    EXTENSION: 'расширения',
    EMPTY_TEMP: 'очистка Temp',
    BROWSER_CACHE: 'кэш и куки браузеров',
    EXPORT_KEY: 'экспорт веток',
    RESTORE_POINT: 'точка восстановления',
    REBOOT: 'перезагрузка',
    NOOP: 'служебные строки',
    CLOSE_PROCESSES: 'служебные строки',
    MANUAL: 'только вручную',
}

NOOP_LINES = {'start::', 'end::', 'systemrestore: on', 'systemrestore:on'}
SKIP_PREFIXES = (';', '#')

_RE_DRIVE_PATH = re.compile(r'^[A-Za-z]:\\')
_RE_BARE_PATH = re.compile(r'^(?:%[A-Za-z_]+%|[A-Za-z]:\\)')
_RE_TASK = re.compile(r'^Task:\s*(?:\{[0-9A-Fa-f-]+\}\s*-\s*)?(.+?)(?:\s*=>.*)?$')
_RE_SERVICE = re.compile(r'^([RSU][0-9])\s+([^;]+);\s*(.*)$')
_RE_FIREWALL = re.compile(r'^FirewallRules:\s*\[(.+?)\]')
_RE_SECURITY = re.compile(r'^(AV|FW):\s*(.+?)\s*(\{[0-9A-Fa-f-]+\})\s*$')
_RE_CLSID = re.compile(r'^CustomCLSID:\s*(.+?)\s*->')
_RE_BHO = re.compile(r'^BHO(?:-x32)?:\s*.+?\s*->\s*(\{[0-9A-Fa-f-]+\})')
_RE_SHORTCUT = re.compile(r'^Shortcut(?:WithArgument)?:\s*(.+?)\s*->')
_RE_SHORTCUT_TARGET = re.compile(r'^ShortcutTarget:\s*(.+?)\s*->')
_RE_EXTENSION = re.compile(
    r'^(?P<browser>CHR|Edge|Brave|YAN)\s+Extension:\s*\((?P<name>.*?)\)\s*-\s*'
    r'(?P<path>.+?)(?:\s*\[\d{4}-\d{2}-\d{2}\])?$')
_RE_FF_EXTENSION = re.compile(r'^FF\s+Extension:\s*\(.*?\)\s*-\s*(.+?)(?:\s*\[\d{4}-\d{2}-\d{2}\])?$')
_RE_BROWSER = re.compile(
    r'^(?P<browser>CHR|Edge|Brave|YAN|OPR|FF)\s+'
    r'(?P<setting>DefaultSearchURL|DefaultSearchKeyword|HomePage|Homepage|StartupUrls)'
    r'\s*:\s*(?P<target>.+?)\s*->\s*(?P<url>\S.*)$', re.IGNORECASE)
_RE_ADS = re.compile(r'^AlternateDataStreams:\s*(.+?):([^\s:]+)\s*(?:\[\d+\])?$')
_RE_INSTALLED_PROGRAM = re.compile(
    r'^.+?\s+\((?P<path>(?:HKLM(?:-x32)?|HKU|HKCU)\\[^)]+)\)'
    r'(?:\s+\(Version:[^)]*\))?'
    r'\s+Hidden\s*$')
_RE_REG_ADD = re.compile(r'^Reg:\s*reg\s+add\s+"(?P<path>[^"]+)"\s+'
                         r'(?:/v\s+"(?P<name>[^"]*)"\s+)?'
                         r'(?:/t\s+(?P<type>\w+)\s+)?'
                         r'(?:/d\s+"(?P<data>[^"]*)"\s+)?'
                         r'(?:/f)?\s*$', re.IGNORECASE)
_RE_RUN_VALUE = re.compile(r'^([A-Za-z0-9_\\ .-]+?):\s*\[([^\]]*)\]')

# Служебные псевдонимы в путях реестра
_HIVE_PREFIXES = ('HKLM-x32\\...\\', 'HKLM\\...\\', 'HKU\\', 'HKCU\\...\\', 'HKCR\\')


@dataclass
class Action:
    kind: str
    raw: str
    path: str = ''
    name: str = ''
    value: str = ''
    data: str = ''
    reg_type: str = ''
    guid: str = ''
    manual_reason: str = ''
    browser: str = ''
    setting: str = ''
    target: str = ''
    url: str = ''


def parse_fixlist(text: str) -> List[Action]:
    """Разобрать текст fixlist в список действий (без выполнения)."""
    actions: List[Action] = []
    for raw_line in text.splitlines():
        line = raw_line.strip().lstrip('\ufeff')
        if not line or line.startswith(SKIP_PREFIXES):
            continue
        actions.append(_parse_line(line))
    return actions


def _parse_line(line: str) -> Action:
    low = line.lower()

    if low in NOOP_LINES:
        return Action(NOOP, line)
    if low == 'createRestorePoint:'.lower():
        return Action(RESTORE_POINT, line)
    if low == 'emptytemp:':
        return Action(EMPTY_TEMP, line)
    if low == 'clearbrowsercache:':
        return Action(BROWSER_CACHE, line)
    if low == 'reboot:':
        return Action(REBOOT, line)
    if low == 'closeprocesses:':
        return Action(CLOSE_PROCESSES, line)
    if low.startswith('regkey:'):
        path = line.split(':', 1)[1].strip()
        if path:
            return Action(REG_KEY, line, path=path)
        return Action(MANUAL, line, manual_reason='пустой путь ключа реестра')
    if low.startswith('processkill:'):
        payload = line.split(':', 1)[1].strip()
        pid, _, path = payload.partition('|')
        if pid.strip() and path.strip():
            return Action(PROCESS_KILL, line, name=pid.strip(),
                          path=path.strip())
        return Action(MANUAL, line, manual_reason='не разобрать процесс')
    if low.startswith('bitscancel:'):
        name = line.split(':', 1)[1].strip()
        if name:
            return Action(BITS_CANCEL, line, name=name)
        return Action(MANUAL, line, manual_reason='пустое имя BITS-задания')
    if low.startswith('webdata:'):
        parts = [part.strip() for part in line.split(':', 1)[1].split('|', 3)]
        if len(parts) >= 3 and parts[1] and parts[2]:
            return Action(WEB_DATA, line, browser=parts[0], path=parts[1],
                          name=parts[2], target=parts[3] if len(parts) > 3 else '')
        return Action(MANUAL, line, manual_reason='не разобрать Web Data')
    if low.startswith('servicequote:'):
        payload = line.split(':', 1)[1]
        key, _, quoted = payload.partition('->')
        if key.strip() and quoted.strip():
            return Action(SERVICE_QUOTE, line, path=key.strip(),
                          value=quoted.strip())
        return Action(MANUAL, line, manual_reason='не разобрать ImagePath')
    if low.startswith('shortcutclean:'):
        parts = [part.strip() for part in line.split(':', 1)[1].split('->', 2)]
        if len(parts) >= 2 and parts[0] and parts[1]:
            return Action(SHORTCUT_CLEAN, line, path=parts[0],
                          target=parts[1], value=parts[2] if len(parts) > 2 else '')
        return Action(MANUAL, line, manual_reason='не разобрать ярлык')
    if low == 'hosts:':
        return Action(HOSTS, line)
    if low.startswith('exportkey:'):
        return Action(EXPORT_KEY, line, path=line.split(':', 1)[1].strip())

    match = _RE_REG_ADD.match(line)
    if match:
        return Action(REG_SET, line, path=match.group('path'),
                      name=match.group('name') or '', value=match.group('data') or '',
                      reg_type=(match.group('type') or 'REG_SZ'))

    match = _RE_TASK.match(line)
    if match and low.startswith('task:'):
        task_path = match.group(1).strip()
        name = re.split(r'System32\\Tasks\\', task_path, flags=re.IGNORECASE)[-1]
        return Action(TASK, line, name=name, path=task_path)

    match = _RE_SERVICE.match(line)
    if match:
        return Action(SERVICE, line, name=match.group(2).strip())

    match = _RE_FIREWALL.match(line)
    if match:
        return Action(FIREWALL, line, name=match.group(1))

    match = _RE_SECURITY.match(line)
    if match:
        return Action(SECURITY_PROVIDER, line, name=match.group(1),
                      guid=match.group(3))

    match = _RE_CLSID.match(line)
    if match:
        path = match.group(1).strip()
        if path.lower().endswith('\\inprocserver32'):
            path = path.rsplit('\\', 1)[0]
        return Action(REG_KEY, line, path=path)

    match = _RE_BHO.match(line)
    if match:
        guid = match.group(1)
        hive = 'HKLM\\SOFTWARE\\Wow6432Node' if 'bho-x32' in low else 'HKLM\\SOFTWARE'
        return Action(REG_KEY, line,
                      path=f'{hive}\\Microsoft\\Windows\\CurrentVersion\\'
                           f'Explorer\\Browser Helper Objects\\{guid}')

    match = _RE_SHORTCUT.match(line)
    if match:
        return Action(SHORTCUT, line, path=match.group(1).strip())

    match = _RE_SHORTCUT_TARGET.match(line)
    if match:
        return Action(SHORTCUT_TARGET, line, name=match.group(1).strip())

    match = _RE_EXTENSION.match(line)
    if match:
        return Action(EXTENSION, line, browser=match.group('browser'),
                      name=match.group('name').strip(),
                      path=match.group('path').strip())

    match = _RE_FF_EXTENSION.match(line)
    if match:
        return Action(FILE, line, path=match.group(1).strip())

    match = _RE_BROWSER.match(line)
    if match:
        return Action(BROWSER, line, browser=match.group('browser'),
                      setting=match.group('setting'),
                      target=match.group('target').strip(),
                      url=match.group('url').strip())

    match = _RE_ADS.match(line)
    if match:
        return Action(ADS, line, path=match.group(1).strip(), name=match.group(2))

    match = _RE_INSTALLED_PROGRAM.match(line)
    if match:
        return Action(REG_KEY, line, path=match.group('path'))

    if line.lower().startswith(('group policy', 'grouppolicy:', 'policies:')):
        return Action(MANUAL, line,
                      manual_reason='политики групповых политик удаляются вручную')

    if line.lower().startswith(('chr ', 'ff ', 'edge ', 'opr ', 'yan ', 'brave ')):
        return Action(MANUAL, line,
                      manual_reason='настройки браузера правятся в его профиле')

    if line.lower().startswith(('contextmenuhandlers', 'bho', 'ff plugin',
                                'hkcr\\')):
        return Action(MANUAL, line,
                      manual_reason='расширение оболочки удаляется вручную')

    if line.lower().startswith(('hklm', 'hku', 'hkcu')):
        return _parse_registry_line(line)

    if _RE_BARE_PATH.match(line):
        return Action(FILE, line, path=line)

    return Action(MANUAL, line, manual_reason='неизвестная команда fixlist')


def _parse_registry_line(line: str) -> Action:
    """Строка реестра: путь: [значение] ... или путь: {guid} ..."""
    head, _, tail = line.partition(':')
    if not tail:
        return Action(MANUAL, line, manual_reason='не разобрать путь реестра')
    path = head.strip()
    value_match = _RE_RUN_VALUE.match(line)
    if value_match:
        return Action(REG_VALUE, line, path=path, name=value_match.group(2))
    guid_match = re.search(r'(\{[0-9A-Fa-f-]+\})', tail)
    if guid_match and ('mountpoints2' in path.lower()
                       or 'active setup' in path.lower()
                       or 'installed components' in path.lower()):
        return Action(REG_KEY, line, path=path + '\\' + guid_match.group(1))
    return Action(MANUAL, line, manual_reason='нет имени значения реестра')
