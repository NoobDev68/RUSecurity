"""Секции реестра: автозагрузка, Winlogon, Active Setup, политики, IFEO."""

from __future__ import annotations

import os
from typing import List

from .. import winapi
from ..context import ScanContext
from ..textfmt import command_suffix, file_suffix, resolve_command_file

RUN_VALUES = (
    ('Run', 'Run'),
    ('RunOnce', 'RunOnce'),
    ('RunServices', 'RunServices'),
    ('RunServicesOnce', 'RunServicesOnce'),
)

# Ограничительные политики, которые FRST помечает как нежелательные.
POLICY_VALUES = {
    'DisableTaskMgr', 'DisableRegistryTools', 'DisableCMD', 'RestrictRun',
    'DisallowRun', 'DisableSR', 'DisableConfig',
}


def _run_key_lines(root: int, path: str, prefix: str, view: int) -> List[str]:
    lines: List[str] = []
    for name, value in winapi.read_values(root, path, view).items():
        text = str(value) if value is not None else ''
        if not text.strip():
            text = '[X]'
        suffix = command_suffix(text)
        lines.append(f'{prefix}: [{name}] => {text}{suffix}')
    return lines


def run_keys(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    for name, _ in RUN_VALUES:
        base = rf'SOFTWARE\Microsoft\Windows\CurrentVersion\{name}'
        lines += _run_key_lines(winapi.HKLM, base, rf'HKLM\...\{name}', winapi.VIEW_64)
        lines += _run_key_lines(winapi.HKLM, base, rf'HKLM-x32\...\{name}', winapi.VIEW_32)
        for sid in ctx.users():
            user_base = rf'{sid}\Software\Microsoft\Windows\CurrentVersion\{name}'
            lines += _run_key_lines(winapi.HKU, user_base, rf'HKU\{sid}\...\{name}',
                                    winapi.VIEW_64)
    return lines


def winlogon() -> List[str]:
    path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    lines: List[str] = []
    for name in ('Shell', 'Userinit', 'Taskman', 'UIHost', 'AppSetup'):
        value = winapi.read_value(winapi.HKLM, path, name)
        if not isinstance(value, str) or not value.strip():
            continue
        lines.append(f'HKLM\\...\\Winlogon: [{name}] {value}{command_suffix(value)}')
    return lines


def active_setup() -> List[str]:
    path = r'SOFTWARE\Microsoft\Active Setup\Installed Components'
    lines: List[str] = []
    for guid in winapi.enum_keys(winapi.HKLM, path):
        stub = winapi.read_value(winapi.HKLM, f'{path}\\{guid}', 'StubPath')
        if not isinstance(stub, str) or not stub.strip():
            continue
        target, exists = resolve_command_file(stub)
        suffix = ''
        if exists:
            meta = winapi.file_meta(target)
            publisher, _signed = winapi.publisher_of(target)
            suffix = f' [{meta[1]:%Y-%m-%d}] ({publisher})' if meta else ''
        lines.append(f'HKLM\\Software\\Microsoft\\Active Setup\\Installed Components: '
                     f'[{guid}] -> {stub}{suffix}')
    return lines


def startup_folder(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    folders = [
        os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'),
                     r'Microsoft\Windows\Start Menu\Programs\Startup'),
    ]
    for sid in ctx.users():
        folders.append(ctx.user_startup(sid))
    for folder in folders:
        if not os.path.isdir(folder):
            continue
        for entry in sorted(os.listdir(folder)):
            if not entry.lower().endswith('.lnk'):
                continue
            path = os.path.join(folder, entry)
            meta = winapi.file_meta(path)
            stamp = f' [{meta[1]:%Y-%m-%d}]' if meta else ''
            lines.append(f'Startup: {path}{stamp}')
            info = winapi.resolve_shortcut(path)
            target = info.target if info else ''
            if target:
                suffix = _shortcut_target_suffix(target)
                lines.append(f'ShortcutTarget: {entry} -> {target}{suffix}')
    return lines


def _shortcut_target_suffix(target: str) -> str:
    if not target or not os.path.isfile(target):
        return ' (Нет файла)'
    meta = winapi.file_meta(target)
    publisher, signed = winapi.publisher_of(target)
    suffix = f' ({publisher})' if meta else ''
    if not signed:
        suffix += ' [Файл не подписан]'
    return suffix


def mountpoints2(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    for sid in ctx.users():
        path = rf'{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2'
        for guid in winapi.enum_keys(winapi.HKU, path):
            command = winapi.read_value(winapi.HKU, f'{path}\\{guid}', '')
            if not isinstance(command, str) or not command.strip():
                command = winapi.read_value(
                    winapi.HKU, f'{path}\\{guid}\\shell\\autorun\\command', '')
            text = command if isinstance(command, str) and command.strip() else ''
            if text:
                lines.append(f'HKU\\{sid}\\...\\MountPoints2: {guid} - {text}')
    return lines


def _policy_lines(root: int, path: str, prefix: str, view: int = winapi.VIEW_64) -> List[str]:
    lines: List[str] = []
    for name, value in winapi.read_values(root, path, view).items():
        if name not in POLICY_VALUES:
            continue
        text = str(value) if value is not None else ''
        lines.append(f'{prefix}: [{name}] {text} <==== ВНИМАНИЕ')
    return lines


def policies(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    base = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies'
    for sub in ('Explorer', 'System', 'WinOldApp', 'Network', 'ActiveDesktop'):
        lines += _policy_lines(winapi.HKLM, f'{base}\\{sub}', rf'HKLM\...\Policies\{sub}')
    for sid in ctx.users():
        user_base = rf'{sid}\Software\Microsoft\Windows\CurrentVersion\Policies'
        for sub in ('Explorer', 'System'):
            lines += _policy_lines(winapi.HKU, f'{user_base}\\{sub}',
                                   rf'HKU\{sid}\...\Policies\{sub}')
    settings_page = winapi.read_value(winapi.HKLM, rf'{base}\Explorer', 'SettingsPageVisibility')
    if isinstance(settings_page, str) and settings_page:
        lines.append(f'HKLM\\...\\Policies\\Explorer: [SettingsPageVisibility] {settings_page}')
    return lines


def app_init() -> List[str]:
    lines: List[str] = []
    base = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    for prefix, view in ((r'AppInit_DLLs', winapi.VIEW_64),
                         (r'AppInit_DLLs-x32', winapi.VIEW_32)):
        value = winapi.read_value(winapi.HKLM, base, 'AppInit_DLLs', view)
        if not isinstance(value, str) or not value.strip():
            continue
        for dll in value.split(','):
            dll = dll.strip()
            if not dll:
                continue
            target, exists = resolve_command_file(dll)
            suffix = file_suffix(target)
            lines.append(f'{prefix}: {dll} => {dll}{suffix}')
    return lines


def image_file_options() -> List[str]:
    path = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    lines: List[str] = []
    for exe in winapi.enum_keys(winapi.HKLM, path):
        key = f'{path}\\{exe}'
        for value_name in ('Debugger', 'VerifierDlls', 'GlobalFlag'):
            value = winapi.read_value(winapi.HKLM, key, value_name)
            if isinstance(value, str) and value.strip():
                lines.append(f'IFEO\\{exe}: [{value_name}] {value}')
    return lines


def collect(ctx: ScanContext) -> List[str]:
    ctx.step('Реестр: автозагрузка')
    lines: List[str] = []
    lines += run_keys(ctx)
    lines += winlogon()
    lines += active_setup()
    lines += startup_folder(ctx)
    lines += mountpoints2(ctx)
    ctx.step('Реестр: политики')
    lines += policies(ctx)
    lines += app_init()
    lines += image_file_options()
    return lines
