"""Правка настроек браузеров: поиск, домашняя страница, стартовые вкладки.

Правятся файлы профилей: `Preferences` и `Secure Preferences` у Chromium и
`prefs.js` у Firefox. Копию файла перед изменением делает фиксер, поэтому
изменение обратимо. Браузер перед правкой закрывается: иначе он перезапишет
настройки из памяти при выходе.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Callable, List, Tuple

from ..core import winapi

CHROMIUM_DIRS = {
    'CHR': r'Google\Chrome\User Data',
    'Edge': r'Microsoft\Edge\User Data',
    'Brave': r'BraveSoftware\Brave-Browser\User Data',
    'YAN': r'Yandex\YandexBrowser\User Data',
}

PROCESSES = {
    'CHR': ('chrome.exe',),
    'Edge': ('msedge.exe',),
    'Brave': ('brave.exe',),
    'YAN': ('browser.exe',),
    'FF': ('firefox.exe',),
}

_SEARCH_SETTINGS = {'defaultsearchurl', 'defaultsearchkeyword'}
_SEARCH_KEYS = ('default_search_provider', 'default_search_provider_data')
_HOMEPAGE_KEYS = ('homepage', 'homepage_is_newtabpage')
_CHROMIUM_FILES = ('Preferences', 'Secure Preferences')

_PREF_HOMEPAGE = re.compile(
    r'user_pref\(\s*"browser\.startup\.homepage"\s*,\s*'
    r'"(?:[^"\\]|\\.)*"\s*\)\s*;')
_PREF_HOMEPAGE_VALUE = re.compile(
    r'user_pref\(\s*"browser\.startup\.homepage"\s*,\s*'
    r'"((?:[^"\\]|\\.)*)"\s*\)\s*;')


def _expected(url: str) -> str:
    """Отчёт хранит URL в defang-виде (hxxp://), сравниваем с настоящим."""
    low = url.lower()
    if low.startswith('hxxp://'):
        return 'http://' + url[7:]
    if low.startswith('hxxps://'):
        return 'https://' + url[8:]
    return url


def _same(current: str, url: str) -> bool:
    return (current.strip().rstrip('/').lower() ==
            _expected(url).strip().rstrip('/').lower())


def _current_values(prefix: str, folder: Path, setting: str) -> List[str]:
    """Что сейчас записано в профиле — чтобы не тронуть уже изменённую настройку."""
    if prefix.upper() == 'FF':
        try:
            text = (folder / 'prefs.js').read_text(encoding='utf-8', errors='replace')
        except OSError:
            return []
        match = _PREF_HOMEPAGE_VALUE.search(text)
        return [match.group(1).replace('\\"', '"')] if match else []
    values: List[str] = []
    for name in _CHROMIUM_FILES:
        path = folder / name
        if not path.is_file():
            continue
        data = _load_json(path)
        if not isinstance(data, dict):
            continue
        if setting.lower() in _SEARCH_SETTINGS:
            provider = data.get('default_search_provider')
            if isinstance(provider, dict) and isinstance(provider.get('url'), str):
                values.append(provider['url'])
            provider = data.get('default_search_provider_data')
            if isinstance(provider, dict):
                template = provider.get('template_url_data')
                if isinstance(template, dict) and isinstance(template.get('url'), str):
                    values.append(template['url'])
        elif setting.lower() == 'homepage':
            value = data.get('homepage')
            if isinstance(value, str) and value:
                values.append(value)
        elif setting.lower() == 'startupurls':
            session = data.get('session')
            urls = session.get('startup_urls') if isinstance(session, dict) else None
            if isinstance(urls, list):
                values.extend(url for url in urls if isinstance(url, str))
    return values


def close(prefix: str) -> List[str]:
    """Закрыть процессы браузера, чтобы он не перезаписал настройки."""
    names = {name.lower() for name in PROCESSES.get(prefix.upper(), ())}
    if not names:
        return []
    closed: List[str] = []
    current = os.getpid()
    for process in winapi.list_processes():
        if process.pid <= 4 or process.pid == current:
            continue
        image = winapi.process_image_path(process.pid)
        if not image or os.path.basename(image).lower() not in names:
            continue
        if winapi.terminate_process(process.pid):
            closed.append(process.name or os.path.basename(image))
    if closed:
        time.sleep(1.5)
    return closed


def chromium_profiles() -> List[Tuple[Path, str]]:
    """Все профили Chromium-браузеров: (каталог профиля, префикс из отчёта)."""
    found: List[Tuple[Path, str]] = []
    local = os.environ.get('LOCALAPPDATA', '')
    if not local:
        return found
    for prefix, relative in CHROMIUM_DIRS.items():
        user_data = Path(local) / relative
        if not user_data.is_dir():
            continue
        for entry in user_data.iterdir():
            if entry.is_dir() and (entry / 'Preferences').is_file():
                found.append((entry, prefix))
    return found


def _profiles(prefix: str, target: str) -> List[Path]:
    if prefix.upper() == 'FF':
        root = Path(os.environ.get('APPDATA', '')) / target.replace('/', '\\')
        return [root] if (root / 'prefs.js').is_file() else []
    relative = CHROMIUM_DIRS.get(prefix)
    if not relative:
        return []
    user_data = Path(os.environ.get('LOCALAPPDATA', '')) / relative
    if not user_data.is_dir():
        return []
    found: List[Path] = []
    for entry in user_data.iterdir():
        if not entry.is_dir() or entry.name.lower() != target.lower():
            continue
        if (entry / 'Preferences').is_file():
            found.append(entry)
    return found


def apply(prefix: str, setting: str, target: str, url: str,
          on_backup: Callable[[Path], None]) -> Tuple[str, str]:
    """Применить исправление. Возвращает статус и пояснение для журнала."""
    closed = close(prefix)
    folders = _profiles(prefix, target)
    if not folders:
        return 'not_found', f'профиль не найден: {target}'
    changed = 0
    mismatched = 0
    for folder in folders:
        current = _current_values(prefix, folder, setting)
        if not any(_same(value, url) for value in current):
            mismatched += 1
            continue
        names = (('prefs.js',) if prefix.upper() == 'FF' else _CHROMIUM_FILES)
        for name in names:
            path = folder / name
            if not path.is_file():
                continue
            on_backup(path)
            if _fix_file(prefix, path, setting):
                changed += 1
    if not changed:
        if mismatched:
            return 'skipped', 'значение в профиле не совпадает с отчётом'
        return 'skipped', 'настройка уже в исходном состоянии'
    detail = f'изменено файлов: {changed}'
    if closed:
        detail += f'; закрыт браузер: {", ".join(sorted(set(closed)))}'
    return 'done', detail


def _fix_file(prefix: str, path: Path, setting: str) -> bool:
    if prefix.upper() == 'FF':
        return _fix_firefox(path, setting)
    return _fix_chromium(path, setting)


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None


def _write_json(path: Path, data: dict) -> None:
    temp = path.with_name(path.name + '.rusecurity')
    temp.write_text(json.dumps(data, ensure_ascii=False, separators=(',', ':')),
                    encoding='utf-8')
    os.replace(temp, path)


def _fix_chromium(path: Path, setting: str) -> bool:
    data = _load_json(path)
    if not isinstance(data, dict):
        return False
    if not _mutate_chromium(data, setting):
        return False
    _write_json(path, data)
    return True


def _mutate_chromium(data: dict, setting: str) -> bool:
    key = setting.lower()
    if key == 'startupurls':
        session = data.get('session')
        if not isinstance(session, dict) or 'startup_urls' not in session:
            return False
        session.pop('startup_urls', None)
        return True
    names = _SEARCH_KEYS if key in _SEARCH_SETTINGS else _HOMEPAGE_KEYS
    changed = False
    for name in names:
        if name in data:
            data.pop(name)
            changed = True
    protection = data.get('protection')
    macs = protection.get('macs') if isinstance(protection, dict) else None
    if isinstance(macs, dict):
        for mac in list(macs):
            if any(mac == name or mac.startswith(name + '.') for name in names):
                macs.pop(mac)
                changed = True
    return changed


def _fix_firefox(path: Path, setting: str) -> bool:
    if setting.lower() != 'homepage':
        return False
    try:
        text = path.read_text(encoding='utf-8', errors='surrogateescape')
    except OSError:
        return False
    if not _PREF_HOMEPAGE.search(text):
        return False
    updated = _PREF_HOMEPAGE.sub(
        'user_pref("browser.startup.homepage", "about:home");', text)
    try:
        path.write_text(updated, encoding='utf-8', errors='surrogateescape',
                        newline='')
    except OSError:
        return False
    return True
