"""Секция Internet: браузеры, расширения, поиск, DNS и прокси."""

from __future__ import annotations

import json
import os
import re
import zipfile
from typing import Dict, List, Optional

from .. import winapi
from ..context import ScanContext

CHROMIUM_BROWSERS = (
    ('CHR', r'Google\Chrome\User Data'),
    ('Edge', r'Microsoft\Edge\User Data'),
    ('Brave', r'BraveSoftware\Brave-Browser\User Data'),
    ('YAN', r'Yandex\YandexBrowser\User Data'),
    ('OPR', r'Opera Software\Opera Stable'),
)

_HTTP_RE = re.compile(r'^(https?)://', re.IGNORECASE)


def defang(url: str) -> str:
    return _HTTP_RE.sub(lambda m: 'hxxp' + m.group(0)[4:], url)


def _load_json(path: str) -> Dict:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def _profile_label(profile_dir: str) -> str:
    name = os.path.basename(profile_dir.rstrip('\\/'))
    return name or 'Default'


def _chromium_profile_lines(prefix: str, profile_dir: str) -> List[str]:
    prefs = _load_json(os.path.join(profile_dir, 'Preferences'))
    label = _profile_label(profile_dir)
    meta = winapi.file_meta(profile_dir)
    lines = [f'{prefix} Profile: {profile_dir}' +
             (f' [{meta[1]:%Y-%m-%d}]' if meta else '')]
    extensions = (prefs.get('extensions') or {}).get('settings') or {}
    for ext_id, settings in extensions.items():
        raw_path = settings.get('path')
        if isinstance(raw_path, str) and raw_path:
            ext_dir = os.path.expandvars(raw_path)
            if not os.path.isabs(ext_dir):
                ext_dir = os.path.join(profile_dir, ext_dir)
        else:
            ext_dir = os.path.join(profile_dir, 'Extensions', ext_id)
        manifest = settings.get('manifest') or {}
        name = manifest.get('name') or settings.get('path') or ext_id
        stamp = winapi.file_meta(ext_dir)
        date = f' [{stamp[1]:%Y-%m-%d}]' if stamp else ''
        lines.append(f'{prefix} Extension: ({name}) - {ext_dir}{date}')
    provider = prefs.get('default_search_provider') or {}
    if isinstance(provider, dict) and provider.get('url'):
        lines.append(f'{prefix} DefaultSearchURL: {label} -> {defang(str(provider["url"]))}')
    if isinstance(provider, dict) and provider.get('keyword'):
        lines.append(f'{prefix} DefaultSearchKeyword: {label} -> {provider["keyword"]}')
    homepage = prefs.get('homepage') or ''
    if isinstance(homepage, str) and homepage:
        lines.append(f'{prefix} HomePage: {label} -> {defang(homepage)}')
    startup = prefs.get('session') or {}
    urls = startup.get('startup_urls') or []
    if isinstance(urls, list):
        for url in urls[:3]:
            if isinstance(url, str) and url:
                lines.append(f'{prefix} StartupUrls: {label} -> {defang(url)}')
    return lines


def chromium_browsers(ctx: ScanContext) -> List[str]:
    ctx.step('Браузеры Chromium')
    lines: List[str] = []
    local = os.environ.get('LOCALAPPDATA', '')
    for prefix, relative in CHROMIUM_BROWSERS:
        user_data = os.path.join(local, relative)
        if not os.path.isdir(user_data):
            continue
        for entry in sorted(os.listdir(user_data)):
            profile = os.path.join(user_data, entry)
            if not os.path.isfile(os.path.join(profile, 'Preferences')):
                continue
            lines += _chromium_profile_lines(prefix, profile)
    return lines


def _firefox_pref(prefs_path: str, name: str) -> Optional[str]:
    pattern = re.compile(r'user_pref\(\s*"' + re.escape(name) + r'"\s*,\s*"(.*)"\s*\)\s*;')
    try:
        with open(prefs_path, 'r', encoding='utf-8', errors='replace') as handle:
            for line in handle:
                match = pattern.search(line)
                if match:
                    return match.group(1).replace('\\"', '"').replace('\\\\', '\\')
    except OSError:
        return None
    return None


def _xpi_name(path: str) -> str:
    try:
        with zipfile.ZipFile(path) as archive:
            for name in ('manifest.json',):
                if name in archive.namelist():
                    data = json.loads(archive.read(name).decode('utf-8', 'replace'))
                    return str(data.get('name') or os.path.basename(path))
    except (OSError, zipfile.BadZipFile, ValueError):
        pass
    return os.path.basename(path)


def firefox(ctx: ScanContext) -> List[str]:
    ctx.step('Браузер Firefox')
    lines: List[str] = []
    for sid in ctx.users():
        profile_root = os.path.join(ctx.profiles.get(sid) or '',
                                    r'AppData\Roaming\Mozilla\Firefox\Profiles')
        if not os.path.isdir(profile_root):
            continue
        for entry in sorted(os.listdir(profile_root)):
            profile = os.path.join(profile_root, entry)
            meta = winapi.file_meta(profile)
            lines.append(f'FF ProfilePath: {profile}' +
                         (f' [{meta[1]:%Y-%m-%d}]' if meta else ''))
            prefs = os.path.join(profile, 'prefs.js')
            homepage = _firefox_pref(prefs, 'browser.startup.homepage')
            if homepage:
                lines.append(f'FF Homepage: Mozilla\\Firefox\\Profiles\\{entry} -> '
                             f'{defang(homepage)}')
            extensions_dir = os.path.join(profile, 'Extensions')
            if os.path.isdir(extensions_dir):
                for item in sorted(os.listdir(extensions_dir)):
                    path = os.path.join(extensions_dir, item)
                    if not item.lower().endswith('.xpi'):
                        continue
                    stamp = winapi.file_meta(path)
                    date = f' [{stamp[1]:%Y-%m-%d}]' if stamp else ''
                    lines.append(f'FF Extension: ({_xpi_name(path)}) - {path}{date}')
            search_dir = os.path.join(profile, 'searchplugins')
            if os.path.isdir(search_dir):
                for item in sorted(os.listdir(search_dir)):
                    path = os.path.join(search_dir, item)
                    stamp = winapi.file_meta(path)
                    date = f' [{stamp[1]:%Y-%m-%d}]' if stamp else ''
                    lines.append(f'FF SearchPlugin: {path}{date}')
    return lines


def tcpip() -> List[str]:
    path = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    lines: List[str] = []
    for value_name in ('NameServer', 'DhcpNameServer'):
        value = winapi.read_value(winapi.HKLM, path, value_name)
        if isinstance(value, str) and value.strip():
            lines.append(f'Tcpip\\Parameters: [{value_name}] {value.strip()}')
    interfaces = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    for guid in winapi.enum_keys(winapi.HKLM, interfaces):
        for value_name in ('NameServer', 'DhcpNameServer'):
            value = winapi.read_value(winapi.HKLM, f'{interfaces}\\{guid}', value_name)
            if isinstance(value, str) and value.strip():
                lines.append(f'Tcpip\\..\\Interfaces\\{{{guid}}}: [{value_name}] '
                             f'{value.strip()}')
    return lines


def proxy_settings(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    path = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    for sid in ctx.users():
        key = rf'{sid}\{path}'
        server = winapi.read_value(winapi.HKU, key, 'ProxyServer')
        enabled = winapi.read_value(winapi.HKU, key, 'ProxyEnable')
        if isinstance(server, str) and server.strip():
            lines.append(f'HKU\\{sid}\\...\\Internet Settings: [ProxyServer] {server}')
        if enabled:
            lines.append(f'HKU\\{sid}\\...\\Internet Settings: [ProxyEnable] {enabled}')
        auto = winapi.read_value(winapi.HKU, key, 'AutoConfigURL')
        if isinstance(auto, str) and auto.strip():
            lines.append(f'HKU\\{sid}\\...\\Internet Settings: [AutoConfigURL] {auto}')
    return lines


def collect(ctx: ScanContext) -> List[str]:
    lines: List[str] = []
    lines += chromium_browsers(ctx)
    lines += firefox(ctx)
    lines += tcpip()
    lines += proxy_settings(ctx)
    return lines
