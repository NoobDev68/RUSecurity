"""Реестр: нотация FRST → реальный путь, удаление, восстановление, экспорт."""

from __future__ import annotations

import os
import re
import subprocess
import winreg
from typing import List, Optional, Tuple

from ..core import winapi

_HIVES = {
    'HKLM': winreg.HKEY_LOCAL_MACHINE,
    'HKCU': winreg.HKEY_CURRENT_USER,
    'HKU': winreg.HKEY_USERS,
    'HKCR': winreg.HKEY_CLASSES_ROOT,
}

_VIEW_64 = winreg.KEY_WOW64_64KEY

# Сокращение FRST «...» означает разный префикс в зависимости от ключа:
# ...\Run → Microsoft\Windows\CurrentVersion, ...\MountPoints2 →
# ...\CurrentVersion\Explorer, ...\Windows Defender → Policies\Microsoft.
_ALIAS_ROOTS = (
    r'Microsoft\Windows\CurrentVersion',
    r'Microsoft\Windows\CurrentVersion\Explorer',
    r'Microsoft\Windows\CurrentVersion\Uninstall',
    r'Microsoft\Windows NT\CurrentVersion',
    r'Policies\Microsoft',
    r'Policies',
    '',
)


def _subkey_exists(hive_name: str, subkey: str) -> bool:
    hive = _HIVES.get(hive_name)
    if hive is None:
        return False
    try:
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | _VIEW_64)
    except OSError:
        return False
    winreg.CloseKey(key)
    return True


def _expand_alias(hive_name: str, bases: Tuple[str, ...], tail: str) -> str:
    """Выбрать существующий префикс для «...»; иначе — самый частый вариант."""
    candidates = [
        base + ('\\' + root if root else '') + '\\' + tail
        for base in bases
        for root in _ALIAS_ROOTS
    ]
    for candidate in candidates:
        if _subkey_exists(hive_name, candidate):
            return candidate
    return candidates[0]


def split_notation(notation: str) -> Tuple[str, str]:
    """'HKLM\\...\\Run' → ('HKLM', 'SOFTWARE\\Microsoft\\...\\Run')."""
    text = notation.strip()
    upper = text.upper()
    if upper.startswith('HKLM-X32\\...\\'):
        tail = text[len('HKLM-x32\\...\\'):]
        return 'HKLM', _expand_alias('HKLM', (r'SOFTWARE\Wow6432Node', 'SOFTWARE'), tail)
    if upper.startswith('HKLM\\...\\'):
        tail = text[len('HKLM\\...\\'):]
        return 'HKLM', _expand_alias('HKLM', ('SOFTWARE',), tail)
    if upper.startswith('HKU\\'):
        rest = text[len('HKU\\'):]
        sid, _, tail = rest.partition('\\')
        if tail.lower().startswith('...\\'):
            tail = tail[len('...\\'):]
            return 'HKU', _expand_alias('HKU', (sid + r'\Software',), tail)
        return 'HKU', sid + ('\\' + tail if tail else '')
    if upper.startswith('HKCU\\...\\'):
        tail = text[len('HKCU\\...\\'):]
        return 'HKCU', _expand_alias('HKCU', ('Software',), tail)
    hive, _, sub = text.partition('\\')
    return hive.upper(), sub


def open_path(notation: str, access: int = winreg.KEY_READ):
    hive_name, subkey = split_notation(notation)
    hive = _HIVES.get(hive_name)
    if hive is None:
        raise ValueError(f'неизвестная ветвь реестра: {notation}')
    return winreg.OpenKey(hive, subkey, 0, access | _VIEW_64), hive_name, subkey


def exists(notation: str) -> bool:
    try:
        key, _hive, _sub = open_path(notation)
    except OSError:
        return False
    winreg.CloseKey(key)
    return True


def enum_subkeys(hive: int, path: str) -> List[str]:
    names: List[str] = []
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | _VIEW_64)
    except OSError:
        return names
    try:
        index = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, index))
            except OSError:
                break
            index += 1
    finally:
        winreg.CloseKey(key)
    return names


def read_value(hive: int, path: str, name: str):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | _VIEW_64)
    except OSError:
        return None
    try:
        value, _kind = winreg.QueryValueEx(key, name)
        return value
    except OSError:
        return None
    finally:
        winreg.CloseKey(key)


def delete_value(notation: str, name: str) -> str:
    """Удалить значение; вернуть done / not_found."""
    try:
        key, _hive, _sub = open_path(notation, winreg.KEY_SET_VALUE)
    except FileNotFoundError:
        return 'not_found'
    try:
        winreg.DeleteValue(key, name)
        return 'done'
    except FileNotFoundError:
        return 'not_found'
    finally:
        winreg.CloseKey(key)


def _delete_tree(hive, subkey: str) -> None:
    handle = winreg.OpenKey(hive, subkey, 0, winreg.KEY_ALL_ACCESS | _VIEW_64)
    try:
        while True:
            try:
                child = winreg.EnumKey(handle, 0)
            except OSError:
                break
            _delete_tree(hive, subkey + '\\' + child)
    finally:
        winreg.CloseKey(handle)
    winreg.DeleteKey(hive, subkey)


def delete_key(notation: str) -> str:
    """Удалить ключ со всем содержимым; вернуть done / not_found."""
    hive_name, subkey = split_notation(notation)
    hive = _HIVES.get(hive_name)
    if hive is None:
        raise ValueError(f'неизвестная ветвь реестра: {notation}')
    try:
        _delete_tree(hive, subkey)
        return 'done'
    except FileNotFoundError:
        return 'not_found'
    except OSError:
        # Защищённые ключи (TrustedInstaller/System): снимаем защиту и повторяем.
        if winapi.take_registry_ownership(hive, subkey):
            _delete_tree(hive, subkey)
            return 'done'
        raise


_REG_TYPES = {
    'REG_SZ': winreg.REG_SZ,
    'REG_EXPAND_SZ': winreg.REG_EXPAND_SZ,
    'REG_DWORD': winreg.REG_DWORD,
    'REG_QWORD': winreg.REG_QWORD,
    'REG_BINARY': winreg.REG_BINARY,
    'REG_MULTI_SZ': winreg.REG_MULTI_SZ,
}


def set_value(notation: str, name: str, reg_type: str, data: str) -> str:
    """Восстановить значение реестра (команда Reg: reg add ...)."""
    hive_name, subkey = split_notation(notation)
    hive = _HIVES.get(hive_name)
    if hive is None:
        raise ValueError(f'неизвестная ветвь реестра: {notation}')
    key = winreg.CreateKeyEx(hive, subkey, 0, winreg.KEY_SET_VALUE | _VIEW_64)
    try:
        kind = _REG_TYPES.get(reg_type.upper(), winreg.REG_SZ)
        if kind in (winreg.REG_DWORD, winreg.REG_QWORD):
            value = int(data, 0)
        elif kind == winreg.REG_MULTI_SZ:
            value = [part for part in data.split('\\0') if part]
        else:
            value = data
        winreg.SetValueEx(key, name, 0, kind, value)
        return 'done'
    finally:
        winreg.CloseKey(key)


def export_key(notation: str, target: str) -> Tuple[bool, str]:
    """Сохранить ветку в .reg через reg.exe. Возвращает (успех, сообщение)."""
    hive_name, subkey = split_notation(notation)
    if hive_name not in ('HKLM', 'HKCU', 'HKU', 'HKCR'):
        return False, f'экспорт ветви {hive_name} не поддерживается'
    os.makedirs(os.path.dirname(target) or '.', exist_ok=True)
    command = ['reg', 'export', f'{hive_name}\\{subkey}', target, '/y']
    try:
        completed = subprocess.run(command, capture_output=True, timeout=60,
                                   creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if completed.returncode != 0:
        text = completed.stderr.decode('cp866', errors='replace').strip()
        return False, text or 'reg export завершился ошибкой'
    return True, target


def safe_name(notation: str) -> str:
    """Имя файла бэкапа из пути реестра."""
    name = re.sub(r'[^A-Za-z0-9_.-]+', '_', notation)
    return name[:120] or 'key'
