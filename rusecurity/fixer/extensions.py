"""Удаление расширений Chromium: запись в профиле и папка с файлами.

Запись расширения лежит в `Preferences` и, у защищённых сборок, дублируется в
`Secure Preferences` с HMAC. Второй файл без пересчёта подписи трогать нельзя —
Chrome посчитает настройки повреждёнными и сбросит весь список расширений,
поэтому такую запись не удаляем, а честно сообщаем: она исчезнет при следующем
запуске браузера (папка расширения уже удалена).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Callable, List, Tuple

from . import browsers


def _same(first: Path, second: Path) -> bool:
    try:
        return (os.path.normcase(os.path.abspath(first)) ==
                os.path.normcase(os.path.abspath(second)))
    except OSError:
        return False


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(path: Path, data: dict) -> None:
    temp = path.with_name(path.name + '.rusecurity')
    temp.write_text(json.dumps(data, ensure_ascii=False, separators=(',', ':')),
                    encoding='utf-8')
    os.replace(temp, path)


def _settings(data: dict) -> dict:
    extensions = data.get('extensions')
    if not isinstance(extensions, dict):
        return {}
    settings = extensions.get('settings')
    return settings if isinstance(settings, dict) else {}


def _matches(entry: dict, profile: Path, ext_id: str, target: Path) -> bool:
    raw = entry.get('path')
    if isinstance(raw, str) and raw:
        candidate = Path(os.path.expandvars(raw))
        if _same(candidate, target) or _same(candidate.parent, target):
            return True
    return _same(profile / 'Extensions' / ext_id, target)


def _remove_mac(data: dict, ext_id: str) -> None:
    protection = data.get('protection')
    macs = protection.get('macs') if isinstance(protection, dict) else None
    if not isinstance(macs, dict):
        return
    macs.pop(f'extensions.settings.{ext_id}', None)


def apply(browser: str, path: str, on_backup: Callable[[Path], None]) -> Tuple[str, str]:
    """Найти и удалить запись расширения. Возвращает статус и пояснение."""
    target = Path(os.path.expandvars(path))
    matches: List[Tuple[Path, List[str], bool]] = []
    for profile, prefix in browsers.chromium_profiles():
        if prefix != browser.upper():
            continue
        prefs_path = profile / 'Preferences'
        secure_path = profile / 'Secure Preferences'
        prefs = _load(prefs_path)
        settings = _settings(prefs)
        ids = [ext_id for ext_id, entry in settings.items()
               if isinstance(entry, dict) and _matches(entry, profile, ext_id, target)]
        if not ids:
            continue
        protected = bool(set(ids) & set(_settings(_load(secure_path))))
        matches.append((profile, ids, protected))
    if not matches:
        return 'not_found', 'запись расширения в профиле не найдена'

    browsers.close(browser)
    removed = 0
    protected_ids: List[str] = []
    for profile, ids, _protected in matches:
        prefs_path = profile / 'Preferences'
        secure_path = profile / 'Secure Preferences'
        prefs = _load(prefs_path)
        secure = _load(secure_path)
        secure_settings = _settings(secure)
        safe_ids = [ext_id for ext_id in ids if ext_id not in secure_settings]
        protected_ids += [ext_id for ext_id in ids if ext_id in secure_settings]
        if not safe_ids:
            continue
        on_backup(prefs_path)
        settings = _settings(prefs)
        for ext_id in safe_ids:
            settings.pop(ext_id, None)
            _remove_mac(prefs, ext_id)
            removed += 1
        _write(prefs_path, prefs)

    if removed:
        detail = f'удалено записей расширения: {removed}'
        if protected_ids:
            detail += '; запись в защищённых настройках браузера исчезнет ' \
                      'после его запуска'
        return 'done', detail
    return 'skipped', ('запись хранится в защищённых настройках браузера и не '
                       'правится без Chrome; удалите расширение в браузере')


def folder(path: str) -> Path:
    return Path(os.path.expandvars(path))
