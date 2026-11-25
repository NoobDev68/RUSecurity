"""Тщательное сканирование: дополнительные проверки закрепления и автозапуска."""

from __future__ import annotations

import ctypes
import hashlib
import json
import logging
import os
import re
import sqlite3
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

from .core import winapi
from .core.context import ScanCancelled, ScanContext
from .core.sections import system
from .core.textfmt import resolve_command_file
from .fixer import actions as act
from .fixer import browsers

log = logging.getLogger('rusecurity.deep')

_SUSPICIOUS = re.compile(
    r'(?i)(?:mshta|wscript|cscript|rundll32|regsvr32|'
    r'certutil|bitsadmin|curl|wget|cmd(?:\.exe)?\s+/c|'
    r'frombase64|-enc(?:odedcommand)?|https?://)')
_URL = re.compile(r'(?i)(?:https?://|www\.)\S+')
_ROOT_EXT = {'.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.lnk', '.inf',
             '.vbs', '.js', '.jar'}
_BROWSERS = {'chrome.exe', 'msedge.exe', 'brave.exe', 'browser.exe',
             'firefox.exe', 'opera.exe', 'vivaldi.exe'}
_POLICY_NAMES = {
    'ExtensionInstallForcelist', 'ExtensionSettings', 'HomepageLocation',
    'HomepageIsNewTabPage', 'RestoreOnStartup', 'RestoreOnStartupURLs',
    'DefaultSearchProviderEnabled', 'DefaultSearchProviderName',
    'DefaultSearchProviderKeyword', 'DefaultSearchProviderSearchURL',
    'URLBlocklist', 'URLAllowlist', 'Extensions', 'WebsiteFilter',
    'SearchEngines',
}
_POLICY_PATHS = (
    (winapi.HKLM, r'SOFTWARE\Policies\Google\Chrome', 'Chrome'),
    (winapi.HKLM, r'SOFTWARE\Policies\Microsoft\Edge', 'Edge'),
    (winapi.HKLM, r'SOFTWARE\Policies\BraveSoftware\Brave', 'Brave'),
    (winapi.HKLM, r'SOFTWARE\Policies\YandexBrowser', 'Yandex'),
    (winapi.HKLM, r'SOFTWARE\Policies\Mozilla\Firefox', 'Firefox'),
    (winapi.HKCU, r'SOFTWARE\Policies\Google\Chrome', 'Chrome'),
    (winapi.HKCU, r'SOFTWARE\Policies\Microsoft\Edge', 'Edge'),
    (winapi.HKCU, r'SOFTWARE\Policies\BraveSoftware\Brave', 'Brave'),
    (winapi.HKCU, r'SOFTWARE\Policies\YandexBrowser', 'Yandex'),
    (winapi.HKCU, r'SOFTWARE\Policies\Mozilla\Firefox', 'Firefox'),
)
_RUN_RE = re.compile(
    r'^((?:HKLM(?:-x32)?|HKCU|HKU\\S-[0-9-]+)\\\.\.\.\\'
    r'(?:RunOnce|RunServicesOnce|RunServices|Run)): \[([^\]]*)\] => (.*)$')
_SERVICE_RE = re.compile(r'^([RSU][0-9])\s+([^;]+);\s*(.*)$')
_TASK_RE = re.compile(r'^Task:\s*(.*?)\s*=>\s*(.*)$')
_SHORTCUT_RE = re.compile(
    r'^(Shortcut(?:WithArgument)?|ShortcutTarget):\s*(.*?)\s*->\s*(.*)$')
_WINLOGON_RE = re.compile(r'^HKLM\\\.\.\.\\Winlogon: \[([^\]]+)\] (.*)$')
_ACTIVE_RE = re.compile(
    r'^HKLM\\Software\\Microsoft\\Active Setup\\Installed Components: '
    r'\[([^\]]+)\] -> (.*)$')
_APPINIT_RE = re.compile(r'^(AppInit_DLLs(?:-x32)?): (.*?) => (.*)$')
_IFEO_RE = re.compile(r'^IFEO\\([^:]+): \[([^\]]+)\] (.*)$')
_SESSION = r'SYSTEM\CurrentControlSet\Control\Session Manager'
_LEGACY_VALUES = (
    (_SESSION, 'BootExecute'),
    (_SESSION, 'SetupExecute'),
    (_SESSION, 'Execute'),
    (_SESSION, 'S0InitialCommand'),
)
_LEGACY_VALUE_LISTS = (
    (_SESSION + r'\AppCertDlls',
     'DLL сертификации процессов; удаление обратимо'),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
     r'\ShellServiceObjectDelayLoad',
     'Объект оболочки загружается при старте; удаление обратимо'),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
     r'\SharedTaskScheduler',
     'Планировщик общих задач; удаление обратимо'),
)
_LEGACY_SUBKEYS = (
    (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify',
     'DLLName'),
    (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit',
     'MonitorProcess'),
)
_LSA_PACKAGES = ('Authentication Packages', 'Notification Packages',
                 'Security Packages')
_CREDENTIAL_BASES = (
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'
    r'\Credential Providers',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication'
    r'\Credential Provider Filters',
)
_ENV_OVERRIDDEN = ('COMSPEC', 'WINDIR', 'SYSTEMROOT', 'SYSTEMDRIVE')


@dataclass
class DeepItem:
    category: str
    title: str
    evidence: str = ''
    fix_line: str = ''
    kind: str = ''
    recommended: bool = False
    note: str = ''


def _resolved(path: Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def save(path: Path, report_path: Path, items: Sequence[DeepItem]) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps({
        'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'report': _resolved(report_path),
        'items': [asdict(item) for item in items],
    }, ensure_ascii=False, indent=2), encoding='utf-8')
    return target


def load(path: Path, report_path: Path) -> List[DeepItem]:
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict) or data.get('report') != _resolved(report_path):
        return []
    items = data.get('items')
    if not isinstance(items, list):
        return []
    result: List[DeepItem] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        category = item.get('category')
        title = item.get('title')
        if not isinstance(category, str) or not isinstance(title, str):
            continue
        result.append(DeepItem(
            category=category, title=title,
            evidence=str(item.get('evidence') or ''),
            fix_line=str(item.get('fix_line') or ''),
            kind=str(item.get('kind') or ''),
            recommended=bool(item.get('recommended')),
            note=str(item.get('note') or '')))
    return result


def _expand(path: str) -> str:
    return os.path.expandvars(path.strip().strip('"'))


def _user_path(path: str) -> bool:
    lowered = _expand(path).lower()
    if not lowered:
        return False
    if any(part in lowered for part in ('\\temp\\', '\\tmp\\', '\\appdata\\',
                                        '\\downloads\\', '\\programdata\\')):
        return True
    for variable in ('%TEMP%', '%TMP%', '%APPDATA%', '%LOCALAPPDATA%'):
        root = os.path.expandvars(variable).lower().rstrip('\\') + '\\'
        if root.endswith('\\\\'):
            continue
        if lowered.startswith(root):
            return True
    return False


def _temp_download_path(path: str) -> bool:
    lowered = _expand(path).lower()
    return any(part in lowered for part in ('\\temp\\', '\\tmp\\',
                                            '\\downloads\\'))


def _signed(path: str) -> bool:
    if not path or not os.path.isfile(path):
        return False
    return winapi.publisher_of(path)[1]


def _clip(text: str, limit: int = 400) -> str:
    text = ' '.join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1] + '…'


def _value_text(value) -> str:
    if isinstance(value, list):
        return '; '.join(str(item) for item in value)
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _risk(line: str, kind: str, category: str,
          command: str = '') -> Optional[DeepItem]:
    """Оценить строку по подписи, пути и способу запуска."""
    missing = ('Нет файла' in line or 'No File' in line or '=> [X]' in line
               or 'отсутствует ImagePath' in line)
    unsigned = ('Файл не подписан' in line or 'not signed' in line.lower())
    path = ''
    if command:
        path, exists = resolve_command_file(command)
        if not exists and re.match(r'^[A-Za-z]:\\|^%', command.strip('"')):
            missing = True
    user_path = _user_path(path) or (not path and _user_path(command))
    suspicious = bool(command and _SUSPICIOUS.search(command))
    flags = []
    if missing:
        flags.append('файл отсутствует')
    if unsigned:
        flags.append('нет подписи')
    if user_path:
        flags.append('пользовательский путь')
    if suspicious:
        flags.append('подозрительная команда')
    score = (3 if missing else 0) + (2 if user_path else 0) + \
            (1 if unsigned else 0) + (3 if suspicious else 0)
    if score < 3:
        return None
    signed = not unsigned
    if signed and not missing and not user_path and not suspicious:
        return None
    recommended = missing or (score >= 5 and kind != act.SHORTCUT)
    if kind == act.SERVICE:
        recommended = missing or (user_path and unsigned)
    if kind in (act.SHORTCUT, act.SHORTCUT_TARGET):
        recommended = missing
    evidence = ', '.join(flags) + f' (риск {score})'
    return DeepItem(category=category, title=_clip(line), evidence=evidence,
                    fix_line=line, kind=kind, recommended=recommended,
                    note=evidence)


def _analyze_line(line: str) -> Optional[DeepItem]:
    stripped = line.strip()
    if not stripped or stripped.startswith((';', '=')):
        return None
    match = _RUN_RE.match(stripped)
    if match:
        return _risk(stripped, act.REG_VALUE, 'Автозагрузка', match.group(3))
    match = _SERVICE_RE.match(stripped)
    if match:
        return _risk(stripped, act.SERVICE, 'Службы и драйверы', match.group(3))
    match = _TASK_RE.match(stripped)
    if match:
        return _risk(stripped, act.TASK, 'Задачи', match.group(2))
    match = _SHORTCUT_RE.match(stripped)
    if match:
        kind = act.SHORTCUT_TARGET if match.group(1) == 'ShortcutTarget' \
            else act.SHORTCUT
        return _risk(stripped, kind, 'Ярлыки', match.group(3))
    match = _WINLOGON_RE.match(stripped)
    if match:
        item = _risk(stripped, act.REG_VALUE, 'Автозагрузка', match.group(2))
        if item is not None:
            item.recommended = False
        return item
    match = _ACTIVE_RE.match(stripped)
    if match:
        item = _risk(stripped, act.REG_KEY, 'Автозагрузка', match.group(2))
        if item is not None:
            key = (r'HKLM\Software\Microsoft\Active Setup\Installed Components'
                   f'\\{match.group(1)}')
            item.fix_line = f'CustomCLSID: {key} -> {match.group(2)}'
            item.recommended = False
        return item
    match = _APPINIT_RE.match(stripped)
    if match:
        item = _risk(stripped, act.MANUAL, 'Автозагрузка', match.group(3))
        if item is not None:
            item.fix_line = ''
            item.kind = act.MANUAL
            item.recommended = False
        return item
    match = _IFEO_RE.match(stripped)
    if match:
        item = _risk(stripped, act.REG_VALUE, 'Автозагрузка', match.group(3))
        if item is not None:
            key = (r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                   f'\\Image File Execution Options\\{match.group(1)}')
            item.fix_line = f'{key}: [{match.group(2)}] {match.group(3)}'
            item.recommended = False
        return item
    return None


def analyze_report(text: str) -> List[DeepItem]:
    """Риск-оценка уже собранных автозагрузки, служб, задач и ярлыков."""
    result: List[DeepItem] = []
    seen = set()
    for line in text.splitlines():
        item = _analyze_line(line)
        if item is None or item.title in seen:
            continue
        seen.add(item.title)
        result.append(item)
    return result


def _com_hijacks(ctx: ScanContext) -> List[DeepItem]:
    result: List[DeepItem] = []
    seen = set()
    bases = [
        (winapi.HKCU, 'Software\\Classes\\CLSID', 'HKCU'),
        (winapi.HKCU, 'Software\\Classes\\Wow6432Node\\CLSID', 'HKCU'),
        (winapi.HKLM, 'Software\\Classes\\CLSID', 'HKLM'),
        (winapi.HKLM, 'Software\\Classes\\Wow6432Node\\CLSID', 'HKLM'),
    ]
    for sid in ctx.users():
        bases.append((winapi.HKU, f'{sid}\\Software\\Classes\\CLSID', 'HKU'))
    for hive, base, display in bases:
        for guid in winapi.enum_keys(hive, base):
            key = f'{base}\\{guid}'
            raw = winapi.read_value(hive, key + r'\InprocServer32', '')
            if not isinstance(raw, str) or not raw:
                raw = winapi.read_value(hive, key + r'\LocalServer32', '')
            if not isinstance(raw, str) or not raw:
                continue
            path, path_exists = resolve_command_file(raw)
            if not path:
                path = _expand(raw)
            exists = path_exists or os.path.isfile(path)
            suspicious = _temp_download_path(path)
            if hive == winapi.HKLM:
                # В HKLM не перебираем все системные CLSID: проверяем только
                # пользовательские/временные пути, иначе это долго и шумно.
                if not (_user_path(path) or suspicious):
                    continue
                signed = _signed(path) if exists else False
                if exists and signed and not suspicious:
                    continue
                twin = False
                company = ''
            else:
                signed = _signed(path)
                twin = (winapi.key_exists(
                            winapi.HKLM, f'Software\\Classes\\CLSID\\{guid}') or
                        winapi.key_exists(
                            winapi.HKLM,
                            f'Software\\Classes\\CLSID\\{guid}', winapi.VIEW_32))
                company = winapi.company_of(path) if exists else ''
                if not (not exists or suspicious
                        or (twin and not signed and not company)
                        or (_user_path(path) and not signed and not company)):
                    continue
                if exists and signed and not suspicious:
                    continue
            combo = (guid.lower(), raw.lower())
            if combo in seen:
                continue
            seen.add(combo)
            flags = []
            if not exists:
                flags.append('файл отсутствует')
            if not signed:
                flags.append('нет подписи')
            if suspicious:
                flags.append('пользовательский путь')
            if twin:
                flags.append('перекрывает HKLM')
            key_display = f'{display}\\{base}\\{guid}'
            if key_display in seen:
                continue
            seen.add(key_display)
            result.append(DeepItem(
                category='COM-перехват', title=key_display,
                evidence=', '.join(flags) + f' → {raw}',
                fix_line=f'RegKey: {key_display}',
                kind=act.REG_KEY,
                recommended=not exists or (twin and not signed),
                note='Пользовательское переопределение COM-объекта'))
    return result


def _policy_prefix(hive, base: str, view: int) -> str:
    if hive == winapi.HKLM:
        if view == winapi.VIEW_32 and base.upper().startswith('SOFTWARE\\'):
            return 'HKLM\\SOFTWARE\\Wow6432Node\\' + base[len('SOFTWARE\\'):]
        return f'HKLM\\{base}'
    return f'HKCU\\{base}'


def _browser_policies() -> List[DeepItem]:
    result: List[DeepItem] = []
    seen = set()
    for hive, base, browser in _POLICY_PATHS:
        for view in (winapi.VIEW_64, winapi.VIEW_32):
            prefix = _policy_prefix(hive, base, view)
            for name, value in winapi.read_values(hive, base, view).items():
                if name not in _POLICY_NAMES:
                    continue
                text = _value_text(value)
                if not text:
                    continue
                marker = f'{prefix}:{name}'
                if marker in seen:
                    continue
                seen.add(marker)
                result.append(DeepItem(
                    category='Политики браузеров',
                    title=f'{browser}: {prefix}: [{name}] {_clip(text, 200)}',
                    evidence='Политика браузера может быть корпоративной',
                    fix_line=f'{prefix}: [{name}] {text}',
                    kind=act.REG_VALUE, recommended=False,
                    note='Удалите только если политика вам не знакома'))
            settings = f'{base}\\ExtensionSettings'
            for sub in winapi.enum_keys(hive, settings, view):
                key = f'{prefix}\\ExtensionSettings\\{sub}'
                if key in seen:
                    continue
                seen.add(key)
                result.append(DeepItem(
                    category='Политики браузеров',
                    title=f'{browser}: {key}',
                    evidence='Принудительное расширение через политику',
                    fix_line=f'RegKey: {key}', kind=act.REG_KEY,
                    recommended=False,
                    note='Проверьте, не корпоративная ли это политика'))
    return result


def _browser_shortcuts(ctx: ScanContext) -> List[DeepItem]:
    result: List[DeepItem] = []
    folders = []
    for profile in ctx.profiles.values():
        if not profile:
            continue
        folders.extend([
            os.path.join(profile, 'Desktop'),
            os.path.join(profile, 'AppData', 'Roaming', 'Microsoft',
                         'Windows', 'Start Menu'),
            os.path.join(profile, 'AppData', 'Roaming', 'Microsoft',
                         'Internet Explorer', 'Quick Launch'),
            os.path.join(profile, 'AppData', 'Roaming', 'Microsoft',
                         'Internet Explorer', 'Quick Launch', 'User Pinned',
                         'TaskBar'),
        ])
    public = os.environ.get('PUBLIC', r'C:\Users\Public')
    program_data = os.environ.get('ProgramData', r'C:\ProgramData')
    folders.extend([
        os.path.join(public, 'Desktop'),
        os.path.join(program_data, 'Microsoft', 'Windows', 'Start Menu'),
    ])
    seen = set()
    found = 0
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for root, _dirs, files in os.walk(folder):
            for name in files:
                if found >= 1500:
                    break
                if not name.lower().endswith('.lnk'):
                    continue
                lnk = os.path.join(root, name)
                if lnk.lower() in seen:
                    continue
                seen.add(lnk.lower())
                info = winapi.resolve_shortcut(lnk)
                if info is None or not info.target:
                    continue
                target = info.target.strip('"')
                if os.path.basename(target).lower() not in _BROWSERS:
                    continue
                arguments = info.arguments or ''
                if '--app=' in arguments.lower():
                    continue
                if not _URL.search(arguments):
                    continue
                cleaned = _URL.sub('', arguments)
                cleaned = ' '.join(cleaned.split()).strip()
                found += 1
                result.append(DeepItem(
                    category='Ярлыки браузеров', title=lnk,
                    evidence=f'аргументы: {_clip(arguments, 200)}',
                    fix_line=f'ShortcutClean: {lnk} -> {target} -> {cleaned}',
                    kind=act.SHORTCUT_CLEAN, recommended=True,
                    note='URL удаляется из аргументов ярлыка'))
    return result


def _svchost_services() -> List[DeepItem]:
    result: List[DeepItem] = []
    base = r'SYSTEM\CurrentControlSet\Services'
    system32 = os.path.expandvars(r'%SystemRoot%\System32').lower().rstrip('\\')
    for name in winapi.enum_keys(winapi.HKLM, base):
        key = f'{base}\\{name}'
        fix_key = f'HKLM\\{key}'
        image = winapi.read_value(winapi.HKLM, key, 'ImagePath')
        if not isinstance(image, str) or 'svchost.exe' not in image.lower():
            continue
        raw = winapi.read_value(winapi.HKLM, key + r'\Parameters', 'ServiceDll')
        if not isinstance(raw, str) or not raw:
            continue
        path = _expand(raw)
        exists = os.path.isfile(path)
        signed = _signed(path)
        suspicious = _user_path(path)
        outside = not path.lower().startswith(system32 + '\\')
        if not (not exists or not signed or suspicious or outside):
            continue
        flags = []
        if not exists:
            flags.append('DLL отсутствует')
        if not signed:
            flags.append('нет подписи')
        if suspicious:
            flags.append('пользовательский путь')
        if outside:
            flags.append('вне System32')
        result.append(DeepItem(
            category='SvcHost/ServiceDll', title=f'{name}: {raw}',
            evidence=', '.join(flags),
            fix_line=f'{fix_key}\\Parameters: [ServiceDll] {raw}',
            kind=act.REG_VALUE, recommended=not exists,
            note='Удаление ServiceDll остановит службу; проверьте вручную'))
    return result


def _disk_roots() -> List[DeepItem]:
    result: List[DeepItem] = []
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.GetLogicalDrives.restype = ctypes.c_uint
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint
    mask = kernel32.GetLogicalDrives()
    for index in range(26):
        if not mask & (1 << index):
            continue
        root = f'{chr(65 + index)}:\\'
        if kernel32.GetDriveTypeW(root) not in (2, 3, 4):
            continue
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            if os.path.splitext(entry.name)[1].lower() not in _ROOT_EXT:
                continue
            meta = winapi.file_meta(entry.path)
            info = ''
            if meta:
                info = f'{meta[0]} байт, {meta[1]:%Y-%m-%d}'
                publisher, signed = winapi.publisher_of(entry.path)
                info += f', ({publisher})'
                if not signed:
                    info += ', нет подписи'
            result.append(DeepItem(
                category='Корни дисков', title=entry.path, evidence=info,
                fix_line=entry.path, kind=act.FILE, recommended=False,
                note='Исполняемый файл в корне диска — проверьте перед удалением'))
    return result


def _firefox_policy_files() -> List[DeepItem]:
    result: List[DeepItem] = []
    for variable in ('%ProgramFiles%', '%ProgramFiles(x86)%'):
        base = os.path.expandvars(variable)
        if not base or '%' in base:
            continue
        path = Path(base) / 'Mozilla Firefox' / 'distribution' / 'policies.json'
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding='utf-8', errors='replace'))
        except (OSError, ValueError):
            continue
        policies = data.get('policies') if isinstance(data, dict) else None
        if not policies:
            continue
        names = ', '.join(sorted(policies)[:10]) if isinstance(policies, dict) else ''
        result.append(DeepItem(
            category='Политики браузеров', title=str(path),
            evidence=f'Firefox policies.json: {names}',
            kind=act.MANUAL, recommended=False,
            note='Файл политик Firefox; проверьте перед удалением'))
    return result


_SYSTEM_NAMES = {'svchost.exe', 'explorer.exe', 'lsass.exe', 'csrss.exe',
                 'winlogon.exe', 'services.exe', 'spoolsv.exe', 'wininit.exe'}
_PS_UTF8 = '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; '
_SEARCH_HOSTS = (
    'google.com', 'bing.com', 'yandex.ru', 'duckduckgo.com', 'brave.com',
    'youtube.com', 'github.com', 'microsoft.com', 'megalodon.jp',
    'wikipedia.org', 'mail.ru', 'baidu.com', 'ecosia.org', 'startpage.com',
)
_SERVICE_EXE = re.compile(
    r'^([A-Za-z]:\\.*?\.(?:exe|com|bat|cmd))(?:\s|$)', re.IGNORECASE)
_NM_PATHS = (
    (winapi.HKCU, r'Software\Google\Chrome\NativeMessagingHosts', 'Chrome'),
    (winapi.HKLM, r'Software\Google\Chrome\NativeMessagingHosts', 'Chrome'),
    (winapi.HKCU, r'Software\Microsoft\Edge\NativeMessagingHosts', 'Edge'),
    (winapi.HKLM, r'Software\Microsoft\Edge\NativeMessagingHosts', 'Edge'),
    (winapi.HKCU, r'Software\BraveSoftware\Brave\NativeMessagingHosts', 'Brave'),
    (winapi.HKLM, r'Software\BraveSoftware\Brave\NativeMessagingHosts', 'Brave'),
    (winapi.HKCU, r'Software\YandexBrowser\NativeMessagingHosts', 'Yandex'),
    (winapi.HKLM, r'Software\YandexBrowser\NativeMessagingHosts', 'Yandex'),
    (winapi.HKCU, r'Software\Mozilla\NativeMessagingHosts', 'Firefox'),
    (winapi.HKLM, r'Software\Mozilla\NativeMessagingHosts', 'Firefox'),
)
_CLASS_SUBKEYS = (
    (winapi.HKCU, r'Software\Classes\*\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\*\shellex\ContextMenuHandlers'),
    (winapi.HKCU, r'Software\Classes\Directory\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\Directory\shellex\ContextMenuHandlers'),
    (winapi.HKCU, r'Software\Classes\Directory\Background\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\Directory\Background\shellex\ContextMenuHandlers'),
    (winapi.HKCU, r'Software\Classes\Folder\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\Folder\shellex\ContextMenuHandlers'),
    (winapi.HKCU, r'Software\Classes\Drive\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\Drive\shellex\ContextMenuHandlers'),
    (winapi.HKCU, r'Software\Classes\Wow6432Node\*\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\Wow6432Node\*\shellex\ContextMenuHandlers'),
    (winapi.HKCU, r'Software\Classes\Wow6432Node\Directory\shellex\ContextMenuHandlers'),
    (winapi.HKLM, r'Software\Classes\Wow6432Node\Directory\shellex\ContextMenuHandlers'),
)
_EXT_VALUE_PATHS = (
    (winapi.HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'),
    (winapi.HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'),
    (winapi.HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks'),
    (winapi.HKLM, r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'),
    (winapi.HKLM, r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'),
)


def _sha256(path: str) -> str:
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return ''


def _system_process_path(name: str, path: str) -> bool:
    root = os.path.expandvars('%SystemRoot%').lower().rstrip('\\')
    lowered = path.lower()
    if name == 'explorer.exe':
        return lowered in (root + '\\explorer.exe',
                           root + '\\syswow64\\explorer.exe')
    return lowered.startswith((root + '\\system32\\',
                               root + '\\syswow64\\'))


def _processes() -> List[DeepItem]:
    result: List[DeepItem] = []
    current = os.getpid()
    for process in winapi.list_processes():
        if process.pid <= 4 or process.pid == current:
            continue
        path = winapi.process_image_path(process.pid)
        if not path:
            continue
        name = os.path.basename(path).lower()
        user_path = _user_path(path)
        mismatch = (name in _SYSTEM_NAMES
                    and not _system_process_path(name, path))
        if not (user_path or mismatch):
            continue
        signed = _signed(path)
        if signed and not mismatch:
            continue
        flags = []
        if mismatch:
            flags.append('системное имя вне System32')
        if user_path:
            flags.append('пользовательский путь')
        if not signed:
            flags.append('нет подписи')
        digest = _sha256(path)
        if digest:
            flags.append(f'sha256: {digest[:16]}…')
        result.append(DeepItem(
            category='Процессы',
            title=f'PID {process.pid}: {name} — {path}',
            evidence=', '.join(flags), fix_line=f'ProcessKill: {process.pid}|{path}',
            kind=act.PROCESS_KILL,
            recommended=(user_path and not signed and not mismatch
                         and _temp_download_path(path)),
            note='Процесс запущен из пользовательской папки'))
    return result


def _recent_files() -> List[DeepItem]:
    result: List[DeepItem] = []
    cutoff = time.time() - 30 * 24 * 60 * 60
    seen = set()
    examined = 0
    roots = [os.environ.get(name, '') for name in
             ('%TEMP%', '%APPDATA%', '%LOCALAPPDATA%', '%ProgramData%')]
    roots.append(str(Path(os.environ.get('USERPROFILE', '')) / 'Downloads'))
    skip_dirs = {'cache', 'cache2', 'node_modules', 'winsxs', 'packages'}
    for root in roots:
        root = os.path.expandvars(root)
        if not root or not os.path.isdir(root):
            continue
        for folder, dirs, files in os.walk(root):
            dirs[:] = [name for name in dirs if name.lower() not in skip_dirs]
            for name in files:
                if examined >= 20000 or len(result) >= 200:
                    return result
                examined += 1
                if os.path.splitext(name)[1].lower() not in _ROOT_EXT:
                    continue
                path = os.path.join(folder, name)
                if path.lower() in seen:
                    continue
                seen.add(path.lower())
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                if stat.st_mtime < cutoff or stat.st_size > 100 * 1024 * 1024:
                    continue
                if _signed(path):
                    continue
                digest = _sha256(path) if stat.st_size <= 20 * 1024 * 1024 else ''
                result.append(DeepItem(
                    category='Свежие файлы', title=path,
                    evidence=(f'{datetime.fromtimestamp(stat.st_mtime):%Y-%m-%d}, '
                              f'{stat.st_size} байт'
                              + (f', sha256: {digest[:16]}…' if digest else '')),
                    fix_line=path, kind=act.FILE, recommended=False,
                    note='Новый неподписанный файл в пользовательской папке'))
    return result


def _unquoted_services() -> List[DeepItem]:
    result: List[DeepItem] = []
    base = r'SYSTEM\CurrentControlSet\Services'
    for name in winapi.enum_keys(winapi.HKLM, base):
        key = f'{base}\\{name}'
        fix_key = f'HKLM\\{key}'
        image = winapi.read_value(winapi.HKLM, key, 'ImagePath')
        if not isinstance(image, str) or image.strip().startswith('"'):
            continue
        match = _SERVICE_EXE.match(image.strip())
        if match is None:
            continue
        path = match.group(1)
        if ' ' not in path:
            continue
        quoted = f'"{path}"{image.strip()[len(path):]}'
        result.append(DeepItem(
            category='Службы и драйверы', title=f'{name}: {image}',
            evidence='ImagePath без кавычек — возможна подмена бинарника',
            fix_line=f'ServiceQuote: {fix_key} -> {quoted}',
            kind=act.SERVICE_QUOTE, recommended=True,
            note='Путь службы будет взят в кавычки, старая ветка — в бэкап'))
    return result


def _clsid_dll(clsid: str) -> str:
    for hive in (winapi.HKLM, winapi.HKCU):
        for root in ('Software\\Classes\\CLSID',
                     'Software\\Classes\\Wow6432Node\\CLSID'):
            for suffix in ('InprocServer32', 'LocalServer32'):
                raw = winapi.read_value(
                    hive, f'{root}\\{clsid}\\{suffix}', '')
                if isinstance(raw, str) and raw.strip():
                    return raw.strip()
    return ''


def _shell_extension_item(display: str, clsid: str,
                          fix_line: str, kind: str) -> Optional[DeepItem]:
    if not clsid.startswith('{'):
        return None
    raw = _clsid_dll(clsid)
    path = _expand(raw) if raw else ''
    exists = bool(path) and os.path.isfile(path)
    signed = _signed(path)
    user_path = _user_path(path)
    if exists and signed and not user_path:
        return None
    if not (not exists or (user_path and not signed)):
        return None
    flags = []
    if not exists:
        flags.append('файл отсутствует')
    if not signed:
        flags.append('нет подписи')
    if user_path:
        flags.append('пользовательский путь')
    return DeepItem(
        category='Расширения оболочки', title=f'{display} → {clsid}',
        evidence=', '.join(flags) + (f' → {raw}' if raw else ''),
        fix_line=fix_line, kind=kind, recommended=not exists,
        note='Расширение оболочки; удаление обратимо через бэкап реестра')


def _shell_extensions() -> List[DeepItem]:
    result: List[DeepItem] = []
    for hive, base in _CLASS_SUBKEYS:
        display_base = ('HKCU' if hive == winapi.HKCU else 'HKLM') + '\\' + base
        for name in winapi.enum_keys(hive, base):
            clsid = winapi.read_value(hive, f'{base}\\{name}', '')
            if not isinstance(clsid, str):
                continue
            item = _shell_extension_item(
                f'{display_base}\\{name}', clsid,
                f'RegKey: {display_base}\\{name}', act.REG_KEY)
            if item is not None:
                result.append(item)
    bho_paths = (
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
        r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects',
    )
    for bho in bho_paths:
        for name in winapi.enum_keys(winapi.HKLM, bho):
            item = _shell_extension_item(
                f'HKLM\\{bho}\\{name}', name,
                f'RegKey: HKLM\\{bho}\\{name}', act.REG_KEY)
            if item is not None:
                result.append(item)
    for hive, base in _EXT_VALUE_PATHS:
        display_base = ('HKCU' if hive == winapi.HKCU else 'HKLM') + '\\' + base
        for name, value in winapi.read_values(hive, base).items():
            clsid = str(value)
            item = _shell_extension_item(
                f'{display_base}: [{name}]', clsid,
                f'{display_base}: [{name}] {clsid}', act.REG_VALUE)
            if item is not None:
                result.append(item)
    return result


def _native_hosts() -> List[DeepItem]:
    result: List[DeepItem] = []
    seen = set()
    for hive, base, browser in _NM_PATHS:
        for view in (winapi.VIEW_64, winapi.VIEW_32):
            if hive == winapi.HKLM and view == winapi.VIEW_32:
                prefix = ('HKLM\\SOFTWARE\\Wow6432Node\\'
                          + base[len('Software\\'):])
            else:
                prefix = ('HKCU\\' if hive == winapi.HKCU else 'HKLM\\') + base
            for host in winapi.enum_keys(hive, base, view):
                if (browser, host.lower()) in seen:
                    continue
                seen.add((browser, host.lower()))
                raw = winapi.read_value(hive, f'{base}\\{host}', '', view)
                if not isinstance(raw, str) or not raw:
                    continue
                manifest = Path(_expand(raw))
                manifest_exists = manifest.is_file()
                host_path = ''
                if manifest_exists:
                    try:
                        data = json.loads(manifest.read_text(
                            encoding='utf-8', errors='replace'))
                        if isinstance(data, dict):
                            host_path = str(data.get('path') or '')
                            if host_path and not os.path.isabs(host_path):
                                host_path = str(manifest.parent / host_path)
                    except (OSError, ValueError):
                        data = None
                host_path = os.path.expandvars(host_path)
                host_exists = bool(host_path) and os.path.isfile(host_path)
                signed = _signed(host_path)
                user_path = _user_path(host_path)
                if host_exists and signed:
                    continue
                missing = not manifest_exists or (bool(host_path) and not host_exists)
                evidence = raw
                if not manifest_exists:
                    evidence += ' (манифест отсутствует)'
                if host_path:
                    evidence += f' → {host_path}'
                if host_path and not host_exists:
                    evidence += ' (исполняемый файл отсутствует)'
                result.append(DeepItem(
                    category='Native Messaging',
                    title=f'{browser}: {host}',
                    evidence=evidence,
                    fix_line=f'RegKey: {prefix}\\{host}',
                    kind=act.REG_KEY, recommended=missing,
                    note='Хост обмена с расширением; удаление обратимо'))
    return result


def _bits_jobs() -> List[DeepItem]:
    script = ('Get-BitsTransfer -AllUsers | Select-Object DisplayName,JobId,'
              'State,TransferType,Owner | ConvertTo-Json -Compress')
    result: List[DeepItem] = []
    for item in _json_list(_powershell_json(script)):
        job = str(item.get('DisplayName') or item.get('JobId') or '').strip()
        if not job:
            continue
        evidence = ', '.join(
            str(item.get(key)) for key in ('State', 'TransferType', 'Owner')
            if item.get(key))
        result.append(DeepItem(
            category='BITS-задания', title=job, evidence=evidence,
            fix_line=f'BitsCancel: {job}', kind=act.BITS_CANCEL,
            recommended=False,
            note='BITS может использоваться и легитимными обновлениями'))
    return result


def _web_data() -> List[DeepItem]:
    result: List[DeepItem] = []
    for profile, prefix in browsers.chromium_profiles():
        database = profile / 'Web Data'
        if not database.is_file():
            continue
        try:
            connection = sqlite3.connect(
                f'file:{database.as_posix()}?mode=ro', uri=True, timeout=2)
        except sqlite3.Error:
            continue
        try:
            columns = {row[1] for row in connection.execute(
                'PRAGMA table_info(keywords)')}
            if not columns:
                continue
            select = 'id, short_name, keyword, url'
            if 'prepopulate_id' in columns:
                select += ', prepopulate_id'
            rows = connection.execute(f'SELECT {select} FROM keywords').fetchall()
            for row in rows:
                if len(row) >= 5 and row[4]:
                    continue
                engine_id, short_name, keyword, url = row[:4]
                if not url or '{searchTerms}' not in str(url):
                    continue
                parsed = urlparse(str(url))
                host = (parsed.hostname or '').lower()
                if parsed.scheme not in ('http', 'https') or not host:
                    continue
                if any(host == domain or host.endswith('.' + domain)
                       for domain in _SEARCH_HOSTS):
                    continue
                result.append(DeepItem(
                    category='Поисковые движки',
                    title=f'{prefix}: {short_name} — {url}',
                    evidence=f'ключевое слово: {keyword}',
                    fix_line=(f'WebData: {prefix}|{database}|{engine_id}|'
                              f'{str(short_name).replace("|", "/")}'),
                    kind=act.WEB_DATA, recommended=False,
                    note='Пользовательский поисковый движок; браузер будет закрыт'))
        except sqlite3.Error:
            continue
        finally:
            connection.close()
    return result


def _defender() -> List[DeepItem]:
    result: List[DeepItem] = []
    exclusions = r'SOFTWARE\Microsoft\Windows Defender\Exclusions'
    for sub in ('Paths', 'Extensions', 'Processes'):
        base = f'{exclusions}\\{sub}'
        display = f'HKLM\\{base}'
        for name in winapi.read_values(winapi.HKLM, base):
            result.append(DeepItem(
                category='Defender', title=f'{display}: [{name}]',
                evidence='Исключение Defender',
                fix_line=f'{display}: [{name}] 0',
                kind=act.REG_VALUE, recommended=False,
                note='Исключение может быть легитимным; удаление обратимо'))
    status = (
        (r'SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
         'DisableRealtimeMonitoring', 'Отключена защита в реальном времени'),
        (r'SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
         'DisableBehaviorMonitoring', 'Отключен мониторинг поведения'),
        (r'SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
         'DisableScriptScanning', 'Отключено сканирование скриптов'),
        (r'SOFTWARE\Microsoft\Windows Defender\Real-Time Protection',
         'DisableIOAVProtection', 'Отключена проверка загружаемых файлов'),
        (r'SOFTWARE\Policies\Microsoft\Windows Defender',
         'DisableAntiSpyware', 'Политика отключает Defender'),
    )
    for base, name, title in status:
        value = winapi.read_value(winapi.HKLM, base, name)
        if value == 1:
            result.append(DeepItem(
                category='Defender', title=title,
                evidence=f'{base}: [{name}] = 1',
                kind=act.MANUAL, recommended=False,
                note='Защиту нужно включать вручную или через политику'))
    return result


def _extension_permissions() -> List[DeepItem]:
    result: List[DeepItem] = []
    high_permissions = {
        '<all_urls>', '*://*/*', 'webRequest', 'webRequestBlocking', 'cookies',
        'proxy', 'management', 'debugger', 'nativeMessaging', 'tabs',
    }
    for profile, prefix in browsers.chromium_profiles():
        if prefix.upper() not in ('CHR', 'EDGE', 'BRAVE', 'YAN'):
            continue
        try:
            data = json.loads((profile / 'Preferences').read_text(
                encoding='utf-8', errors='replace'))
        except (OSError, ValueError):
            continue
        settings = (data.get('extensions') or {}).get('settings') or {}
        for ext_id, item in settings.items():
            if not isinstance(item, dict):
                continue
            if item.get('location') in (1, 5):
                continue
            manifest = item.get('manifest') or {}
            name = manifest.get('name') or item.get('path') or ext_id
            permissions = set(manifest.get('permissions') or []) | \
                set(manifest.get('host_permissions') or [])
            high = sorted(permission for permission in permissions
                          if permission in high_permissions
                          or '<all_urls>' in str(permission)
                          or '*://*/*' in str(permission))
            update_url = item.get('update_url') or manifest.get('update_url')
            if not high and update_url:
                continue
            raw_path = item.get('path')
            if isinstance(raw_path, str) and raw_path:
                path = Path(os.path.expandvars(raw_path))
                if not path.is_absolute():
                    path = profile / path
            else:
                path = profile / 'Extensions' / ext_id
            evidence = []
            if high:
                evidence.append('права: ' + ', '.join(high[:8]))
            if not update_url:
                evidence.append('нет update_url (side-load)')
            result.append(DeepItem(
                category='Расширения браузеров',
                title=f'{prefix}: {name} — {path}',
                evidence='; '.join(evidence),
                fix_line=f'{prefix} Extension: ({name}) - {path}',
                kind=act.EXTENSION, recommended=False,
                note='Расширение с широкими правами или side-load'))
    return result


def _network_connections() -> List[DeepItem]:
    script = (
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin "
        "@('0.0.0.0','::','127.0.0.1','::1') } | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,"
        "OwningProcess | ConvertTo-Json -Compress")
    result: List[DeepItem] = []
    seen = set()
    for item in _json_list(_powershell_json(script)):
        try:
            pid = int(item.get('OwningProcess') or 0)
        except (TypeError, ValueError):
            continue
        if pid <= 4 or pid in seen:
            continue
        path = winapi.process_image_path(pid)
        if not path or not _user_path(path) or _signed(path):
            continue
        seen.add(pid)
        remote = f'{item.get("RemoteAddress")}:{item.get("RemotePort")}'
        result.append(DeepItem(
            category='Сеть',
            title=f'PID {pid}: {os.path.basename(path)} → {remote}',
            evidence=f'{path}; состояние: {item.get("State")}',
            fix_line=f'ProcessKill: {pid}|{path}',
            kind=act.PROCESS_KILL, recommended=False,
            note='Неподписанный процесс из пользовательской папки'))
    return result


def _public_dns(server: str) -> bool:
    """Публичный DNS: статический частный обычно ставит VPN или роутер."""
    if not server:
        return False
    if ':' in server:
        return True
    return not _private_ip(server)


def _static_dns() -> List[DeepItem]:
    """Статически заданные публичные DNS — частая подмена поиска и рекламы."""
    servers = set()
    interfaces = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    for interface in winapi.enum_keys(winapi.HKLM, interfaces):
        value = winapi.read_value(winapi.HKLM, f'{interfaces}\\{interface}',
                                  'NameServer')
        if not isinstance(value, str):
            continue
        for server in re.split(r'[,\s]+', value.strip()):
            if _public_dns(server):
                servers.add(server)
    if not servers:
        return []
    return [DeepItem(
        category='Сеть', title='DNS: ' + '; '.join(sorted(servers)),
        evidence='Статические публичные DNS-серверы',
        kind=act.MANUAL, recommended=False,
        note='Частные DNS (VPN, роутер) не показываются')]


def _network_settings() -> List[DeepItem]:
    result: List[DeepItem] = []
    base = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    pac = winapi.read_value(winapi.HKCU, base, 'AutoConfigURL')
    if isinstance(pac, str) and pac.strip():
        result.append(DeepItem(
            category='Сеть', title=f'AutoConfigURL: {pac}',
            evidence='Автонастройка прокси (PAC)',
            fix_line=f'HKCU\\{base}: [AutoConfigURL] {pac}',
            kind=act.REG_VALUE, recommended=False,
            note='PAC может быть корпоративным'))
    enabled = winapi.read_value(winapi.HKCU, base, 'ProxyEnable')
    proxy = winapi.read_value(winapi.HKCU, base, 'ProxyServer')
    if enabled and isinstance(proxy, str) and proxy.strip():
        result.append(DeepItem(
            category='Сеть', title=f'Прокси включён: {proxy}',
            evidence='ProxyEnable=1',
            fix_line=f'Reg: reg add "HKCU\\{base}" /v ProxyEnable '
                     '/t REG_DWORD /d "0" /f',
            kind=act.REG_SET, recommended=False,
            note='Прокси может быть корпоративным'))
    result.extend(_static_dns())
    try:
        completed = subprocess.run(
            ['netsh', 'winhttp', 'show', 'proxy'], capture_output=True,
            timeout=30, creationflags=0x08000000)
        raw = completed.stdout or b''
        decoded = [raw.decode(encoding, errors='replace')
                   for encoding in ('utf-8', 'cp866')]
        text = next((value for value in decoded
                     if 'direct access' in value.lower()
                     or 'прямой доступ' in value.lower()),
                    decoded[0]).lower()
    except (OSError, subprocess.SubprocessError):
        text = ''
    if text and 'direct access' not in text and 'прямой доступ' not in text:
        result.append(DeepItem(
            category='Сеть', title='WinHTTP-прокси',
            evidence=text.strip()[:300], kind=act.MANUAL, recommended=False,
            note='Проверьте прокси WinHTTP; сброс — вручную'))
    return result


def _task_metadata() -> List[DeepItem]:
    script = (
        'Get-ScheduledTask | ForEach-Object { $a = @($_.Actions | '
        'Where-Object { $_.Execute })[0]; [pscustomobject]@{ '
        'TaskPath=$_.TaskPath; TaskName=$_.TaskName; Author=$_.Author; '
        'UserId=$_.Principal.UserId; Hidden=[bool]$_.Settings.Hidden; '
        'Execute=if($a){$a.Execute}else{""}; '
        'Arguments=if($a){$a.Arguments}else{""} } } | '
        'ConvertTo-Json -Compress -Depth 4')
    result: List[DeepItem] = []
    for item in _json_list(_powershell_json(script)):
        path = str(item.get('TaskPath') or '\\')
        name = str(item.get('TaskName') or '')
        if not name:
            continue
        execute = str(item.get('Execute') or '')
        arguments = str(item.get('Arguments') or '')
        command = (execute + ' ' + arguments).strip()
        author = str(item.get('Author') or '')
        user = str(item.get('UserId') or '')
        hidden = bool(item.get('Hidden'))
        execute_path, resolve_exists = resolve_command_file(execute)
        if not execute_path:
            execute_path = _expand(execute)
        exists = resolve_exists or (bool(execute_path)
                                    and os.path.isfile(execute_path))
        user_path = _user_path(execute_path)
        temp_path = _temp_download_path(execute_path)
        signed = _signed(execute_path)
        full = (path + name).lstrip('\\')
        is_microsoft = full.lower().startswith('microsoft\\windows\\')
        system_root = os.path.expandvars('%SystemRoot%').lower().rstrip('\\')
        in_system = execute_path.lower().startswith(system_root + '\\')
        suspicious_cmd = bool(command and _SUSPICIOUS.search(command))
        if is_microsoft and in_system:
            suspicious_cmd = False
        masquerade = (is_microsoft and bool(execute_path)
                      and not in_system and not signed)
        hidden_bad = hidden and not is_microsoft and not signed
        metadata_issue = (
            hidden_bad or masquerade or suspicious_cmd
            or (temp_path and not signed)
            or (user_path and not signed and (not exists or suspicious_cmd)))
        if not metadata_issue:
            continue
        line = f'Task: System32\\Tasks\\{full}'
        if command:
            line += f' => {command}'
        evidence = []
        if hidden:
            evidence.append('скрытая задача')
        if masquerade:
            evidence.append('Microsoft-путь, но действие вне System32')
        if author:
            evidence.append(f'автор: {author}')
        if user:
            evidence.append(f'пользователь: {user}')
        if user_path:
            evidence.append('действие в пользовательской папке')
        if not exists:
            evidence.append('файл отсутствует')
        if suspicious_cmd:
            evidence.append('подозрительная команда')
        result.append(DeepItem(
            category='Задачи', title=line, evidence='; '.join(evidence),
            fix_line=line, kind=act.TASK,
            recommended=(masquerade or hidden_bad or temp_path
                         or (user_path and not signed and not exists)),
            note='Метаданные задачи; удаление с XML-бэкапом'))
    return result


def _all_tasks(ctx: ScanContext) -> List[DeepItem]:
    result: List[DeepItem] = []
    for line in system.scheduled_tasks(ctx, include_microsoft=True):
        item = _analyze_line(line)
        if item is not None:
            result.append(item)
    return result


def _powershell_json(script: str, timeout: int = 90):
    """Вывод PowerShell-скрипта, разобранный как JSON (None при ошибке)."""
    try:
        completed = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command',
             _PS_UTF8 + script],
            capture_output=True, timeout=timeout, creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        return json.loads(completed.stdout.decode('utf-8', errors='replace'))
    except ValueError:
        return None


def _json_list(data) -> List[dict]:
    if data is None:
        return []
    items = data if isinstance(data, list) else [data]
    return [item for item in items if isinstance(item, dict)]


def _value_string(value) -> str:
    """Текст значения реестра: строка или список строк через пробел."""
    if isinstance(value, (list, tuple)):
        return ' '.join(str(part).strip() for part in value if str(part).strip())
    if isinstance(value, str):
        return value.strip().strip('\x00').strip()
    return ''


def _string_list(value) -> List[str]:
    parts = value if isinstance(value, (list, tuple)) else [value]
    result: List[str] = []
    for part in parts:
        if not isinstance(part, str):
            continue
        text = part.strip().strip('"').strip()
        if text:
            result.append(text)
    return result


def _in_system_dir(path: str) -> bool:
    root = os.path.expandvars('%SystemRoot%').lower().rstrip('\\')
    lowered = path.lower()
    if lowered == root + '\\explorer.exe':
        return True
    return lowered.startswith((root + '\\system32\\', root + '\\syswow64\\'))


def _in_system_or_program_files(path: str) -> bool:
    if _in_system_dir(path):
        return True
    lowered = path.lower()
    for variable in ('%ProgramFiles%', '%ProgramFiles(x86)%'):
        root = os.path.expandvars(variable).lower().rstrip('\\')
        if not root or '%' in root:
            continue
        if lowered.startswith(root + '\\'):
            return True
    return False


def _payload_flags(raw: str) -> Tuple[str, List[str], bool]:
    """Путь, флаги и «стоит рекомендовать удаление» для ссылки на DLL/EXE."""
    text = _expand(raw)
    if not text:
        return '', [], False
    if text.startswith('{') and text.endswith('}'):
        resolved = _expand(_clsid_dll(text))
        if not resolved:
            return text, ['COM-объект не найден'], False
        text = resolved
    path, exists = resolve_command_file(text)
    if not path:
        path = text
    flags: List[str] = []
    if not exists:
        flags.append('файл отсутствует')
    signed = _signed(path) if exists else False
    if exists and not signed:
        flags.append('нет подписи')
    if _user_path(path):
        flags.append('пользовательский путь')
    recommend = (not exists) or (exists and not signed and _user_path(path))
    return path, flags, recommend


def _private_ip(address: str) -> bool:
    """Частный или служебный IPv4-адрес (не IPv4 считаем нормальным)."""
    parts = address.split('.')
    if len(parts) != 4 or not all(part.isdigit() for part in parts):
        return True
    first, second = int(parts[0]), int(parts[1])
    return (first in (10, 127) or (first == 169 and second == 254)
            or (first == 192 and second == 168)
            or (first == 172 and 16 <= second <= 31)
            or (first == 100 and 64 <= second <= 127))


def _writable_dirs(folders: Sequence[str]) -> set:
    """Папки, куда могут писать обычные пользователи (по ACL)."""
    return {folder for folder in folders if winapi.dir_writable_by_users(folder)}


def _legacy_item(display: str, name: str, raw: str, fix_line: str,
                 kind: str, note: str) -> Optional[DeepItem]:
    path, flags, recommend = _payload_flags(raw)
    if not flags:
        return None
    evidence = ', '.join(flags) + (f' → {path}' if path else '')
    return DeepItem('Устаревшая автозагрузка',
                    f'{display}: [{name}] {_clip(raw, 160)}', evidence,
                    fix_line, kind, recommend, note)


def _legacy_persistence() -> List[DeepItem]:
    """Редко используемые точки автозагрузки: AppCertDlls, Notify и другие."""
    result: List[DeepItem] = []
    for key, name in _LEGACY_VALUES:
        raw = _value_string(winapi.read_value(winapi.HKLM, key, name))
        if not raw:
            continue
        if name == 'BootExecute' and ' '.join(raw.split()).lower() == \
                'autocheck autochk *':
            continue
        display = f'HKLM\\{key}'
        item = _legacy_item(display, name, raw, f'{display}: [{name}] {raw}',
                            act.REG_VALUE, 'Устаревшая точка автозагрузки')
        if item is not None:
            result.append(item)
    for key, note in _LEGACY_VALUE_LISTS:
        display = f'HKLM\\{key}'
        for name, value in winapi.read_values(winapi.HKLM, key).items():
            parts = _string_list(value)
            path = ''
            flags: List[str] = []
            recommend = False
            for part in parts:
                part_path, part_flags, part_recommend = _payload_flags(part)
                if not part_flags:
                    continue
                path = path or part_path
                flags.extend(part_flags)
                recommend = recommend or part_recommend
            if not flags:
                continue
            data = '; '.join(parts)
            result.append(DeepItem(
                category='Устаревшая автозагрузка',
                title=f'{display}: [{name}] {_clip(data, 160)}',
                evidence=', '.join(dict.fromkeys(flags))
                          + (f' → {path}' if path else ''),
                fix_line=f'{display}: [{name}] {data}',
                kind=act.REG_VALUE, recommended=recommend, note=note))
    for key, value_name in _LEGACY_SUBKEYS:
        for sub in winapi.enum_keys(winapi.HKLM, key):
            raw = _value_string(winapi.read_value(
                winapi.HKLM, f'{key}\\{sub}', value_name))
            if not raw:
                continue
            display = f'HKLM\\{key}\\{sub}'
            item = _legacy_item(display, value_name, raw,
                                f'RegKey: {display}', act.REG_KEY,
                                'Устаревшая точка автозагрузки')
            if item is not None:
                result.append(item)
    return result


def _package_dll(name: str) -> str:
    """DLL пакета LSA: явный путь или имя в System32/SysWOW64."""
    text = _expand(name)
    if not text:
        return ''
    root = os.environ.get('SystemRoot', r'C:\Windows')
    if '\\' in text or text.lower().endswith('.dll'):
        if not os.path.isabs(text):
            text = os.path.join(root, text)
        return text if os.path.isfile(text) else ''
    for folder in ('System32', 'SysWOW64', 'System32\\drivers'):
        candidate = os.path.join(root, folder, text + '.dll')
        if os.path.isfile(candidate):
            return candidate
    return ''


def _lsa_extensions() -> List[DeepItem]:
    """Пакеты LSA и поставщики учётных данных."""
    result: List[DeepItem] = []
    key = r'SYSTEM\CurrentControlSet\Control\Lsa'
    for name in _LSA_PACKAGES:
        for entry in _string_list(winapi.read_value(winapi.HKLM, key, name)):
            resolved = _package_dll(entry)
            flags = []
            if not resolved:
                flags.append('DLL не найдена')
            else:
                if not _signed(resolved):
                    flags.append('нет подписи')
                if not _in_system_dir(resolved):
                    flags.append('вне System32')
                if _user_path(resolved):
                    flags.append('пользовательский путь')
            if not flags:
                continue
            result.append(DeepItem(
                category='LSA и учётные данные',
                title=f'LSA {name}: {entry}',
                evidence=', '.join(flags) + (f' → {resolved}' if resolved else ''),
                kind=act.MANUAL, recommended=False,
                note='Пакет LSA участвует во входе в систему; правьте вручную'))
    for base in _CREDENTIAL_BASES:
        for guid in winapi.enum_keys(winapi.HKLM, base):
            raw = _value_string(winapi.read_value(
                winapi.HKLM, f'{base}\\{guid}\\InprocServer32', ''))
            if not raw:
                continue
            path, exists = resolve_command_file(raw)
            flags = []
            if not exists:
                flags.append('файл отсутствует')
            elif not _signed(path):
                flags.append('нет подписи')
            if _user_path(path):
                flags.append('пользовательский путь')
            if not flags:
                continue
            result.append(DeepItem(
                category='LSA и учётные данные',
                title=f'Credential Provider {guid}: {_clip(raw, 160)}',
                evidence=', '.join(flags),
                kind=act.MANUAL, recommended=False,
                note='Поставщик учётных данных; правьте только вручную'))
    return result


def _service_binaries() -> List[DeepItem]:
    """Двоичные файлы служб вне системных каталогов: подпись и ACL папки."""
    base = r'SYSTEM\CurrentControlSet\Services'
    candidates: List[Tuple[str, str, str, bool]] = []
    for name in winapi.enum_keys(winapi.HKLM, base):
        image = winapi.read_value(winapi.HKLM, f'{base}\\{name}', 'ImagePath')
        if not isinstance(image, str) or not image.strip():
            continue
        path, exists = resolve_command_file(image)
        if not path or _in_system_or_program_files(path):
            continue
        candidates.append((name, image, path, exists))
        if len(candidates) >= 200:
            break
    if not candidates:
        return []
    folders = sorted({os.path.dirname(path) for _name, _image, path, exists
                      in candidates
                      if exists and os.path.isdir(os.path.dirname(path))})
    writable = _writable_dirs(folders)
    result: List[DeepItem] = []
    for name, image, path, exists in candidates:
        signed = _signed(path) if exists else False
        writable_dir = os.path.dirname(path) in writable
        if exists and signed and not writable_dir:
            continue
        flags = []
        if not exists:
            flags.append('файл отсутствует')
        else:
            if not signed:
                flags.append('нет подписи')
            if writable_dir:
                flags.append('папка доступна на запись')
        result.append(DeepItem(
            category='Службы и драйверы', title=f'{name}: {_clip(image, 200)}',
            evidence=', '.join(flags), kind=act.MANUAL, recommended=False,
            note='Двоичный файл службы вне системных каталогов'))
    return result


def _process_modules() -> List[DeepItem]:
    """DLL вне системных каталогов, загруженные в процессы."""
    script = (
        "$sys=@($env:SystemRoot,$env:ProgramFiles,${env:ProgramFiles(x86)})"
        "|Where-Object{$_};"
        "Get-Process -ErrorAction SilentlyContinue|ForEach-Object{"
        "$p=$_;try{$img=$p.Path}catch{$img=$null};if(-not $img){return};"
        "try{$mods=@($p.Modules)}catch{return};"
        "foreach($m in $mods){$f=$m.FileName;if(-not $f){continue};"
        "$inSys=$false;"
        "foreach($r in $sys){"
        "if($f.StartsWith($r,[StringComparison]::OrdinalIgnoreCase))"
        "{$inSys=$true}};"
        "if(-not $inSys){[pscustomobject]@{Pid=$p.Id;Process=$p.ProcessName;"
        "Host=$img;Module=$f}}}}|ConvertTo-Json -Compress -Depth 3")
    result: List[DeepItem] = []
    seen = set()
    for entry in _json_list(_powershell_json(script)):
        try:
            pid = int(entry.get('Pid') or 0)
        except (TypeError, ValueError):
            continue
        host = str(entry.get('Host') or '')
        module = str(entry.get('Module') or '')
        process = str(entry.get('Process') or '')
        if pid <= 4 or not host or not module:
            continue
        key = (pid, module.lower())
        if key in seen or len(result) >= 100:
            continue
        seen.add(key)
        system_host = _in_system_dir(host)
        temp_module = _temp_download_path(module)
        if not system_host and \
                os.path.dirname(module).lower() == os.path.dirname(host).lower():
            continue
        signed = _signed(module)
        if not temp_module and (not system_host or signed):
            continue
        flags = []
        if system_host:
            flags.append('загружен в системный процесс')
        if temp_module:
            flags.append('временный путь')
        if not signed:
            flags.append('нет подписи')
        evidence = ', '.join(flags) + f'; хост: {process} — {host}'
        digest = _sha256(module)
        if digest:
            evidence += f'; sha256: {digest[:16]}…'
        result.append(DeepItem(
            category='Модули процессов',
            title=f'PID {pid} ({process}): {module}', evidence=evidence,
            kind=act.MANUAL, recommended=False,
            note='Модуль вне системных каталогов; проверьте перед удалением'))
    return result


def _firewall_rules() -> List[DeepItem]:
    """Входящие разрешающие правила для программ из пользовательских папок."""
    script = (
        "$apps=@{};"
        "Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue|"
        "ForEach-Object{if($_.Program){$apps[$_.InstanceID]=$_.Program}};"
        "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True "
        "-ErrorAction SilentlyContinue|ForEach-Object{"
        "$p=$apps[$_.InstanceID];if(-not $p){return};"
        "[pscustomobject]@{Name=$_.Name;Display=$_.DisplayName;Program=$p}}|"
        "ConvertTo-Json -Compress -Depth 3")
    result: List[DeepItem] = []
    seen = set()
    for entry in _json_list(_powershell_json(script)):
        name = str(entry.get('Name') or '').strip()
        program = _expand(str(entry.get('Program') or ''))
        display = str(entry.get('Display') or '').strip()
        if not name or not program or any(char in name for char in '|[]'):
            continue
        if not re.match(r'^(?:[A-Za-z]:\\|%|\\\\)', program):
            continue
        if _in_system_or_program_files(program):
            continue
        exists = os.path.isfile(program)
        if exists and _signed(program):
            continue
        if name.lower() in seen or len(result) >= 100:
            continue
        seen.add(name.lower())
        flags = ['программа отсутствует'] if not exists else ['нет подписи']
        if _user_path(program):
            flags.append('пользовательский путь')
        result.append(DeepItem(
            category='Сеть',
            title=f'Входящее правило: {display or name} → {_clip(program, 160)}',
            evidence=', '.join(flags), fix_line=f'FirewallRules: [{name}]',
            kind=act.FIREWALL, recommended=False,
            note='Правило брандмауэра; удаление с бэкапом'))
    return result


def _listening_ports() -> List[DeepItem]:
    """Процессы из пользовательских папок, слушающие внешние интерфейсы."""
    script = (
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|"
        "Where-Object{$_.LocalAddress -in @('0.0.0.0','::')}|"
        "Select-Object LocalPort,OwningProcess|ConvertTo-Json -Compress")
    ports: Dict[int, List[int]] = {}
    for entry in _json_list(_powershell_json(script)):
        try:
            pid = int(entry.get('OwningProcess') or 0)
            port = int(entry.get('LocalPort') or 0)
        except (TypeError, ValueError):
            continue
        if pid <= 4 or port <= 0:
            continue
        ports.setdefault(pid, [])
        if port not in ports[pid]:
            ports[pid].append(port)
    result: List[DeepItem] = []
    for pid in list(ports)[:50]:
        path = winapi.process_image_path(pid)
        if not path or _in_system_or_program_files(path) or _signed(path):
            continue
        if not _user_path(path):
            continue
        listing = ', '.join(str(port) for port in sorted(ports[pid]))
        result.append(DeepItem(
            category='Сеть',
            title=f'PID {pid}: {os.path.basename(path)} слушает порт {listing}',
            evidence=f'{path}; все интерфейсы', kind=act.MANUAL,
            recommended=False,
            note='Неподписанный процесс из пользовательской папки ждёт подключений'))
    return result


def _routes() -> List[DeepItem]:
    """Маршруты по умолчанию через шлюз не из частных диапазонов."""
    script = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' "
        "-ErrorAction SilentlyContinue|"
        "Select-Object NextHop,InterfaceAlias,RouteMetric|"
        "ConvertTo-Json -Compress")
    result: List[DeepItem] = []
    for entry in _json_list(_powershell_json(script)):
        next_hop = str(entry.get('NextHop') or '').strip()
        if not next_hop or next_hop in ('0.0.0.0', '::'):
            continue
        if _private_ip(next_hop):
            continue
        alias = str(entry.get('InterfaceAlias') or '').strip()
        metric = entry.get('RouteMetric')
        evidence = ', '.join(part for part in (
            alias, f'метрика {metric}' if metric is not None else '') if part)
        result.append(DeepItem(
            category='Сеть',
            title=f'Маршрут по умолчанию через внешний шлюз {next_hop}',
            evidence=evidence or 'шлюз не из частных диапазонов',
            kind=act.MANUAL, recommended=False,
            note='Необычный шлюз может означать подмену сети'))
    return result


def _wmi_subscriptions() -> List[DeepItem]:
    """WMI-подписки (персистентность через EventConsumer)."""
    script = (
        "$ns='root\\subscription';$out=@();"
        "Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer "
        "-ErrorAction SilentlyContinue|ForEach-Object{"
        "$out+=[pscustomobject]@{Class='CommandLineEventConsumer';"
        "Name=$_.Name;Command=$_.CommandLineTemplate;Working=$_.WorkingDirectory}};"
        "Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer "
        "-ErrorAction SilentlyContinue|ForEach-Object{"
        "$out+=[pscustomobject]@{Class='ActiveScriptEventConsumer';"
        "Name=$_.Name;Command=$_.ScriptText;Working=''}};"
        "$out|ConvertTo-Json -Compress -Depth 3")
    result: List[DeepItem] = []
    seen = set()
    for entry in _json_list(_powershell_json(script)):
        name = str(entry.get('Name') or '').strip()
        command = str(entry.get('Command') or '').strip()
        klass = str(entry.get('Class') or '')
        if not name or not command:
            continue
        marker = (klass, name.lower())
        if marker in seen:
            continue
        seen.add(marker)
        suspicious = bool(_SUSPICIOUS.search(command))
        path, exists = resolve_command_file(command)
        user_path = bool(path) and _user_path(path)
        missing = bool(path) and not exists and \
            bool(re.match(r'^[A-Za-z]:\\|^%', command.strip('"')))
        if not (suspicious or user_path or missing):
            continue
        flags = []
        if suspicious:
            flags.append('подозрительная команда')
        if user_path:
            flags.append('пользовательский путь')
        if missing:
            flags.append('файл отсутствует')
        result.append(DeepItem(
            category='WMI-подписки',
            title=f'{klass}: {name}',
            evidence=', '.join(flags) + f' → {_clip(command, 200)}',
            kind=act.MANUAL, recommended=False,
            note=('Постоянная WMI-подписка; удаление — вручную: '
                  'Get-CimInstance -Namespace root/subscription -ClassName '
                  f'{klass} -Filter "Name=\'{name}\'" | Remove-CimInstance')))
    return result


def _environment(ctx: ScanContext) -> List[DeepItem]:
    """Переопределённые пользователем переменные окружения."""
    result: List[DeepItem] = []
    bases = [(winapi.HKCU, 'Environment', 'HKCU')]
    for sid in ctx.users():
        bases.append((winapi.HKU, f'{sid}\\Environment', f'HKU\\{sid}'))
    seen = set()
    for hive, key, display in bases:
        for name, value in winapi.read_values(hive, key).items():
            if not isinstance(value, str) or not value.strip():
                continue
            marker = (display, name.upper())
            if marker in seen:
                continue
            seen.add(marker)
            if name.upper() in _ENV_OVERRIDDEN:
                result.append(DeepItem(
                    category='Переменные окружения',
                    title=f'{display}\\{key}: [{name}] {_clip(value, 200)}',
                    evidence='Системная переменная переопределена пользователем',
                    fix_line=f'{display}\\{key}: [{name}] {value}',
                    kind=act.REG_VALUE, recommended=True,
                    note='Удаление вернёт системное значение (бэкап ветки)'))
            elif name.upper() == 'PATHEXT':
                result.append(DeepItem(
                    category='Переменные окружения',
                    title=f'{display}\\{key}: [PATHEXT] {_clip(value, 200)}',
                    evidence='Порядок расширений задан пользователем',
                    kind=act.MANUAL, recommended=False,
                    note='Переопределённый PATHEXT меняет порядок поиска программ'))
            elif name.upper() == 'PATH':
                first = next((part.strip().strip('"') for part in value.split(';')
                              if part.strip()), '')
                if first and _temp_download_path(first):
                    result.append(DeepItem(
                        category='Переменные окружения',
                        title=f'{display}\\{key}: [PATH] {_clip(value, 200)}',
                        evidence=f'Temp/Downloads в начале PATH: {first}',
                        kind=act.MANUAL, recommended=False,
                        note='Каталог в начале PATH перехватывает запуск программ'))
    return result


def collect(ctx: ScanContext) -> List[DeepItem]:
    """Собрать дополнительные записи для тщательного режима."""
    result: List[DeepItem] = []
    checks = (
        ('Тщательно: COM', _com_hijacks),
        ('Тщательно: политики браузеров', lambda _ctx: _browser_policies()),
        ('Тщательно: политики Firefox', lambda _ctx: _firefox_policy_files()),
        ('Тщательно: ярлыки браузеров', _browser_shortcuts),
        ('Тщательно: SvcHost', lambda _ctx: _svchost_services()),
        ('Тщательно: корни дисков', lambda _ctx: _disk_roots()),
        ('Тщательно: процессы', lambda _ctx: _processes()),
        ('Тщательно: BITS', lambda _ctx: _bits_jobs()),
        ('Тщательно: расширения оболочки', lambda _ctx: _shell_extensions()),
        ('Тщательно: свежие файлы', lambda _ctx: _recent_files()),
        ('Тщательно: пути служб', lambda _ctx: _unquoted_services()),
        ('Тщательно: поисковые движки', lambda _ctx: _web_data()),
        ('Тщательно: Native Messaging', lambda _ctx: _native_hosts()),
        ('Тщательно: Defender', lambda _ctx: _defender()),
        ('Тщательно: права расширений', lambda _ctx: _extension_permissions()),
        ('Тщательно: сетевые соединения', lambda _ctx: _network_connections()),
        ('Тщательно: сеть', lambda _ctx: _network_settings()),
        ('Тщательно: метаданные задач', lambda _ctx: _task_metadata()),
        ('Тщательно: все задачи', _all_tasks),
        ('Тщательно: устаревшая автозагрузка',
         lambda _ctx: _legacy_persistence()),
        ('Тщательно: LSA', lambda _ctx: _lsa_extensions()),
        ('Тщательно: двоичные файлы служб', lambda _ctx: _service_binaries()),
        ('Тщательно: модули процессов', lambda _ctx: _process_modules()),
        ('Тщательно: правила брандмауэра', lambda _ctx: _firewall_rules()),
        ('Тщательно: порты', lambda _ctx: _listening_ports()),
        ('Тщательно: маршруты', lambda _ctx: _routes()),
        ('Тщательно: WMI-подписки', lambda _ctx: _wmi_subscriptions()),
        ('Тщательно: переменные окружения', _environment),
    )
    for label, check in checks:
        ctx.step(label)
        ctx.check_cancel()
        try:
            result.extend(check(ctx))
        except ScanCancelled:
            raise
        except Exception as exc:  # noqa: BLE001 - один раздел не должен рвать скан
            log.warning('Тщательная проверка «%s» не выполнена: %s', label, exc)
    seen = set()
    unique: List[DeepItem] = []
    for item in result:
        marker = (item.category, item.fix_line or item.title)
        if marker in seen:
            continue
        seen.add(marker)
        unique.append(item)
    return unique
