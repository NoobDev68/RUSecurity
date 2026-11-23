"""Секции rusecurity-add.txt: программы, брандмауэр, hosts, ярлыки, WMI и прочее."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from typing import Dict, List

from .. import winapi
from ..context import ScanContext
from ..textfmt import format_shortcut

_HOSTS_PATH = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                           r'System32\drivers\etc\hosts')


def installed_programs(ctx: ScanContext) -> List[str]:
    ctx.step('Установленные программы')
    lines: List[str] = []
    sources = [
        (winapi.HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
         r'HKLM\...', winapi.VIEW_64),
        (winapi.HKLM, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
         r'HKLM-x32\...', winapi.VIEW_32),
    ]
    for sid in ctx.users():
        sources.append((winapi.HKU,
                        rf'{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall',
                        rf'HKU\{sid}\...', winapi.VIEW_64))
    for root, base, prefix, view in sources:
        for key in winapi.enum_keys(root, base, view):
            path = f'{base}\\{key}'
            display = winapi.read_value(root, path, 'DisplayName', view)
            if not isinstance(display, str) or not display.strip():
                continue
            version = winapi.read_value(root, path, 'DisplayVersion', view) or ''
            publisher = winapi.read_value(root, path, 'Publisher', view) or ''
            hidden = winapi.read_value(root, path, 'SystemComponent', view) == 1 or \
                winapi.read_value(root, path, 'NoDisplay', view) == 1
            line = f'{display} ({prefix}\\{key})'
            if version or publisher:
                line += f' (Version: {version} - {publisher})'
            if hidden:
                line += ' Hidden'
            lines.append(line)
    return lines


def security_center() -> List[str]:
    base = r'SOFTWARE\Microsoft\Security Center\Provider'
    lines: List[str] = []
    for kind in ('Av', 'Fw'):
        prefix = 'AV' if kind == 'Av' else 'FW'
        path = f'{base}\\{kind}'
        for guid in winapi.enum_keys(winapi.HKLM, path):
            key = f'{path}\\{guid}'
            name = winapi.read_value(winapi.HKLM, key, 'DISPLAYNAME')
            state = winapi.read_value(winapi.HKLM, key, 'STATE')
            if not isinstance(name, str) or not name:
                continue
            state_int = int(state) if isinstance(state, int) else 0
            enabled = 'Enabled' if state_int & 0x1000 else 'Disabled'
            updated = 'Up to date' if (state_int & 0x60000) == 0x60000 else 'Out of date'
            guid_text = '{' + guid.strip('{}').upper() + '}'
            lines.append(f'{prefix}: {name} ({enabled} - {updated}) {guid_text}')
    return lines


def custom_clsid(ctx: ScanContext) -> List[str]:
    ctx.step('Пользовательские CLSID')
    lines: List[str] = []
    for sid in ctx.users():
        base = rf'{sid}_Classes\CLSID'
        for guid in winapi.enum_keys(winapi.HKU, base):
            path = f'{base}\\{guid}\\InprocServer32'
            dll = winapi.read_value(winapi.HKU, path, '')
            if not isinstance(dll, str) or not dll.strip():
                continue
            dll = os.path.expandvars(dll)
            prefix = f'CustomCLSID: HKU\\{sid}_Classes\\CLSID\\{guid}\\InprocServer32'
            if os.path.isfile(dll):
                lines.append(f'{prefix} -> {dll} ({winapi.publisher_of(dll)[0]})')
            else:
                lines.append(f'{prefix} -> {dll} => Нет файла')
    return lines


def firewall_rules() -> List[str]:
    path = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
    lines: List[str] = []
    for name, value in winapi.read_values(winapi.HKLM, path).items():
        if not isinstance(value, str):
            continue
        fields: Dict[str, str] = {}
        for part in value.split('|'):
            if '=' in part:
                key, _, val = part.partition('=')
                fields[key.lower()] = val
        action = fields.get('action', 'Allow')
        app = fields.get('app', '')
        if app:
            app = os.path.expandvars(app)
            if os.path.isfile(app):
                lines.append(f'FirewallRules: [{name}] => ({action}) {app} '
                             f'({winapi.publisher_of(app)[0]})')
            else:
                lines.append(f'FirewallRules: [{name}] => ({action}) {app} => Нет файла')
            continue
        if fields.get('lport'):
            lines.append(f'FirewallRules: [{name}] => ({action}) LPort={fields["lport"]}')
        elif fields.get('rport'):
            lines.append(f'FirewallRules: [{name}] => ({action}) RPort={fields["rport"]}')
    return lines


def hosts_content() -> List[str]:
    lines: List[str] = []
    if not os.path.isfile(_HOSTS_PATH):
        lines.append(f'Hosts: {_HOSTS_PATH} => Нет файла')
        return lines
    meta = winapi.file_meta(_HOSTS_PATH)
    if meta:
        lines.append(f'{meta[1]:%Y-%m-%d %H:%M} - {meta[1]:%Y-%m-%d %H:%M} - '
                     f'{meta[0]:08d} _____ {_HOSTS_PATH}')
    try:
        with open(_HOSTS_PATH, 'r', encoding='utf-8', errors='replace') as handle:
            for raw in handle:
                text = raw.strip()
                if not text or text.startswith('#'):
                    continue
                lines.append(text)
    except OSError:
        pass
    return lines


def msconfig_disabled(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    base = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
    for sub, label in (('Run', r'HKLM\...\StartupApproved\Run'),
                       ('Run32', r'HKLM\...\StartupApproved\Run32')):
        for name, data in winapi.read_values(winapi.HKLM, f'{base}\\{sub}').items():
            if isinstance(data, bytes) and data and data[0] & 0x01:
                lines.append(f'{label}: => "{name}"')
    for sid in ctx.users():
        user_base = rf'{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved'
        for sub in ('Run', 'Run32'):
            for name, data in winapi.read_values(winapi.HKU, f'{user_base}\\{sub}').items():
                if isinstance(data, bytes) and data and data[0] & 0x01:
                    lines.append(f'HKU\\{sid}\\...\\StartupApproved\\{sub}: => "{name}"')
    return lines


def accounts(ctx: ScanContext) -> List[str]:
    base = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    admins = winapi.local_admins()
    lines: List[str] = []
    for sid in winapi.enum_keys(winapi.HKLM, base):
        if not sid.startswith('S-1-5-21-'):
            continue
        path = f'{base}\\{sid}'
        profile = winapi.read_value(winapi.HKLM, path, 'ProfileImagePath')
        if not isinstance(profile, str):
            continue
        name = os.path.basename(profile)
        is_admin = sid.endswith('-500') or name.lower() in admins
        flags = 'Administrator' if is_admin else 'Limited'
        lines.append(f'{name} ({sid} - {flags} - Enabled) => {profile}')
    return lines


def other_areas(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    uac = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    parts = []
    for value_name in ('ConsentPromptBehaviorAdmin', 'ConsentPromptBehaviorUser', 'EnableLUA'):
        value = winapi.read_value(winapi.HKLM, uac, value_name)
        if value is not None:
            parts.append(f'({value_name}: {value})')
    if parts:
        lines.append(f'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System '
                     f'=> {" ".join(parts)}')
    dns = winapi.read_value(winapi.HKLM,
                            r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
                            'NameServer')
    if isinstance(dns, str) and dns.strip():
        lines.append(f'DNS Servers: {dns.strip()}')
    return lines


def drives_and_memory() -> List[str]:
    lines: List[str] = []
    try:
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ('dwLength', wintypes.DWORD), ('dwMemoryLoad', wintypes.DWORD),
                ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                ('ullTotalPageFile', ctypes.c_ulonglong),
                ('ullAvailPageFile', ctypes.c_ulonglong),
                ('ullTotalVirtual', ctypes.c_ulonglong),
                ('ullAvailVirtual', ctypes.c_ulonglong),
                ('ullAvailExtendedVirtual', ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            lines.append(f'Процент используемой памяти: {status.dwMemoryLoad}%')
        mask = kernel32.GetLogicalDrives()
        for index in range(26):
            if not mask & (1 << index):
                continue
            letter = chr(ord('A') + index)
            root = f'{letter}:\\'
            total = ctypes.c_ulonglong()
            free = ctypes.c_ulonglong()
            if kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free), ctypes.byref(total),
                                            None):
                lines.append(f'Drive {letter.lower()}: () (Fixed) '
                             f'(Total:{total.value / 1024 ** 3:.2f} GB) '
                             f'(Free:{free.value / 1024 ** 3:.2f} GB)')
    except OSError:
        pass
    return lines


def wmi_subscriptions() -> List[str]:
    script = (
        'Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter'
        ' | Select-Object Name,Query | ConvertTo-Json -Compress;'
        'Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer'
        ' | Select-Object Name,CommandLineTemplate,WorkingDirectory | ConvertTo-Json -Compress;'
        'Get-CimInstance -Namespace root\\subscription -ClassName ActiveScriptEventConsumer'
        ' | Select-Object Name,ScriptText | ConvertTo-Json -Compress;'
        'Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding'
        ' | Select-Object Filter,Consumer | ConvertTo-Json -Compress'
    )
    try:
        import subprocess
        completed = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                                    script], capture_output=True, timeout=90,
                                   creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    import json
    lines: List[str] = []
    for chunk in completed.stdout.decode('utf-8', errors='replace').splitlines():
        chunk = chunk.strip()
        if not chunk or chunk in ('null', '[]'):
            continue
        try:
            data = json.loads(chunk)
        except ValueError:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            if not isinstance(item, dict):
                continue
            name = item.get('Name')
            if 'Query' in item:
                lines.append(f'WMI:subscription\\__EventFilter->{name}::[Query => {item["Query"]}]')
            elif 'CommandLineTemplate' in item:
                lines.append(f'WMI:subscription\\CommandLineEventConsumer->{name}'
                             f'::[CommandLineTemplate => {item.get("CommandLineTemplate")}]'
                             f'[WorkingDirectory => {item.get("WorkingDirectory")}]')
            elif 'ScriptText' in item:
                lines.append(f'WMI:subscription\\ActiveScriptEventConsumer->{name}'
                             f'::[ScriptText => ...]')
            elif 'Filter' in item:
                lines.append(f'WMI:subscription\\__FilterToConsumerBinding'
                             f'->{item.get("Consumer")}::{item.get("Filter")}')
    return lines


def shortcuts(ctx: ScanContext, limit: int = 400) -> List[str]:
    ctx.step('Ярлыки')
    lines: List[str] = []
    folders: List[str] = []
    for sid in ctx.users():
        profile = ctx.profiles.get(sid) or ''
        if not profile:
            continue
        folders += [
            os.path.join(profile, 'Desktop'),
            os.path.join(profile, r'AppData\Roaming\Microsoft\Windows\Start Menu'),
            os.path.join(profile, r'AppData\Roaming\Microsoft\Windows\SendTo'),
            os.path.join(profile, r'AppData\Local\Microsoft\Windows\WinX'),
            os.path.join(profile, r'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch'),
        ]
    for folder in folders:
        if len(lines) >= limit:
            break
        for root, _dirs, files in os.walk(folder):
            for name in files:
                if not name.lower().endswith('.lnk'):
                    continue
                path = os.path.join(root, name)
                info = winapi.resolve_shortcut(path)
                if not info or not info.target:
                    continue
                lines.append(format_shortcut(path, info.target, info.arguments))
                if len(lines) >= limit:
                    break
    return lines
