"""Раздел «Ассоциация»: чем открываются исполняемые расширения."""

from __future__ import annotations

import os
import winreg
from typing import List, Optional

from .. import winapi
from ..context import ScanContext

CRITICAL_EXTENSIONS = {
    '.exe': 'exefile',
    '.com': 'comfile',
    '.bat': 'batfile',
    '.cmd': 'cmdfile',
    '.reg': 'regfile',
    '.scr': 'scrfile',
    '.pif': 'piffile',
    '.js': 'JSFile',
    '.vbs': 'VBSFile',
    '.hta': 'htafile',
    '.lnk': 'lnkfile',
}

_SAFE_DIRS = ('\\windows\\', '\\system32\\', '\\syswow64\\',
              '\\program files\\', '\\program files (x86)\\')
_SAFE_NAMES = {'regedit.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe',
               'notepad.exe', 'explorer.exe'}
_MARK = ' <==== ВНИМАНИЕ'

# Пустое пользовательское переопределение опасно только для исполняемых типов.
_STRICT_EMPTY = {'.exe', '.com', '.bat', '.cmd', '.reg', '.scr', '.pif'}


def _key_exists(root: int, path: str, view: int = winapi.VIEW_64) -> bool:
    try:
        key = winreg.OpenKey(root, path, 0, winreg.KEY_READ | view)
    except OSError:
        return False
    winreg.CloseKey(key)
    return True


def _read_class(root: int, base: str, ext: str) -> Optional[str]:
    value = winapi.read_value(root, base + '\\' + ext, '')
    return value if isinstance(value, str) else None


def _read_command(root: int, classes: str, class_name: str) -> Optional[str]:
    if not class_name:
        return None
    value = winapi.read_value(root, f'{classes}\\{class_name}\\shell\\open\\command', '')
    return value if isinstance(value, str) else None


def _command_is_safe(command: str) -> bool:
    text = os.path.expandvars(command).strip().lower()
    if '%1' not in text:
        return False
    if text.startswith('"%1"') or text.startswith('%1'):
        return True
    first = text.split('"')[1] if text.startswith('"') else text.split(' ')[0]
    name = os.path.basename(first)
    if name in _SAFE_NAMES:
        return True
    return any(marker in first for marker in _SAFE_DIRS)


def _entry(root: int, prefix: str, classes: str, ext: str,
           strict_empty: bool = False) -> Optional[str]:
    key = f'{classes}\\{ext}'
    if not _key_exists(root, key):
        return None
    class_name = _read_class(root, classes, ext)
    if strict_empty and root == winapi.HKU and not class_name and ext not in _STRICT_EMPTY:
        return None
    command = _read_command(root, classes, class_name or '')
    expected = CRITICAL_EXTENSIONS[ext]
    suspicious = not class_name or class_name.lower() != expected.lower()
    if ext != '.lnk' and (not command or not _command_is_safe(command)):
        suspicious = True
    line = f'{prefix}\\{ext}: {class_name or ""} => {command or ""}'
    return line + (_MARK if suspicious else '')


def collect(ctx: ScanContext) -> List[str]:
    ctx.step('Ассоциации файлов')
    lines: List[str] = []
    for ext in CRITICAL_EXTENSIONS:
        line = _entry(winapi.HKLM, r'HKLM\Software\Classes', r'SOFTWARE\Classes', ext)
        if line:
            lines.append(line)
    for sid in ctx.users():
        base = rf'{sid}\Software\Classes'
        prefix = rf'HKU\{sid}\Software\Classes'
        for ext in CRITICAL_EXTENSIONS:
            line = _entry(winapi.HKU, prefix, base, ext, strict_empty=True)
            if line:
                lines.append(line)
        file_exts = (rf'{sid}\Software\Microsoft\Windows\CurrentVersion'
                     rf'\Explorer\FileExts')
        for ext in CRITICAL_EXTENSIONS:
            prog_id = winapi.read_value(winapi.HKU, f'{file_exts}\\{ext}\\UserChoice',
                                        'ProgId')
            if not isinstance(prog_id, str) or not prog_id:
                continue
            expected = CRITICAL_EXTENSIONS[ext]
            mark = '' if prog_id.lower() == expected.lower() else _MARK
            lines.append(
                f'HKU\\{sid}\\...\\FileExts\\{ext}\\UserChoice => {prog_id}{mark}')
    return lines
