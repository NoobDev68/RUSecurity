"""Сведения о системе для шапки отчёта."""

from __future__ import annotations

import ctypes
import os
from datetime import datetime
from typing import List

from . import winapi

_WINDOWS_CAPTION = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion'

_LCID_NAMES = {
    0x0409: 'English (United States)',
    0x0419: 'Русский (Россия)',
    0x0407: 'Deutsch (Deutschland)',
    0x040C: 'Français (France)',
    0x0410: 'Italiano (Italia)',
    0x040A: 'Español (España)',
    0x0415: 'Polski (Polska)',
    0x0422: 'Українська (Україна)',
}


def windows_product() -> str:
    product = winapi.read_value(winapi.HKLM, _WINDOWS_CAPTION, 'ProductName') or 'Windows'
    display = winapi.read_value(winapi.HKLM, _WINDOWS_CAPTION, 'DisplayVersion') or ''
    build = winapi.read_value(winapi.HKLM, _WINDOWS_CAPTION, 'CurrentBuildNumber') or ''
    ubr = winapi.read_value(winapi.HKLM, _WINDOWS_CAPTION, 'UBR')
    try:
        if int(build) >= 22000:
            product = product.replace('Windows 10', 'Windows 11')
    except (TypeError, ValueError):
        pass
    version = f'Версия {display} {build}' if display else f'Версия {build}'
    if ubr:
        version += f'.{ubr}'
    return f'{product} {version}'


def install_date() -> str:
    value = winapi.read_value(winapi.HKLM, _WINDOWS_CAPTION, 'InstallDate')
    if isinstance(value, int) and value:
        return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
    return ''


def architecture() -> str:
    value = winapi.read_value(
        winapi.HKLM,
        r'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'PROCESSOR_ARCHITECTURE')
    return 'X64' if str(value).upper() in ('AMD64', 'X64') else 'X86'


def ui_language() -> str:
    try:
        lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
    except (AttributeError, OSError):
        return ''
    return _LCID_NAMES.get(int(lcid), f'LCID {lcid:04X}')


def computer_model() -> str:
    manufacturer = winapi.read_value(winapi.HKLM,
                                     r'HARDWARE\DESCRIPTION\System\BIOS',
                                     'SystemManufacturer') or ''
    model = winapi.read_value(winapi.HKLM, r'HARDWARE\DESCRIPTION\System\BIOS',
                              'SystemProductName') or ''
    return f'{manufacturer} {model}'.strip()


def user_display_name() -> str:
    name = os.environ.get('USERNAME', '')
    return name or 'Пользователь'


def default_browser() -> str:
    base = (r'Software\Microsoft\Windows\Shell\Associations\UrlAssociations'
            r'\http\UserChoice')
    prog_id = winapi.read_value(winapi.HKCU, base, 'ProgId') or ''
    mapping = {
        'MSEdgeHTM': 'Edge', 'ChromeHTML': 'Chrome', 'FirefoxURL': 'Firefox',
        'OperaStable': 'Opera', 'BraveHTML': 'Brave', 'YandexBrowser': 'Yandex',
    }
    return mapping.get(str(prog_id), str(prog_id) or 'не определён')


def profiles_line(users: List[str]) -> str:
    names = [user for user in users if user]
    return ' & '.join(names)


def launcher_path() -> str:
    import sys
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
