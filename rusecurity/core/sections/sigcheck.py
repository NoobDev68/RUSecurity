"""Раздел SigCheck: контрольные системные файлы, подпись и MD5."""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from typing import List, Optional

from .. import winapi

NOTE = '(Нет автоматического исправления файлов, которые не проходят проверку.)'

SYSTEM_FILES = (
    r'System32\winlogon.exe',
    r'System32\wininit.exe',
    r'System32\services.exe',
    r'System32\svchost.exe',
    r'System32\lsass.exe',
    r'System32\csrss.exe',
    r'System32\explorer.exe',
    r'System32\userinit.exe',
    r'System32\user32.dll',
    r'System32\rpcss.dll',
    r'System32\dnsapi.dll',
    r'System32\dllhost.exe',
    r'SysWOW64\explorer.exe',
    r'SysWOW64\svchost.exe',
    r'SysWOW64\userinit.exe',
    r'SysWOW64\user32.dll',
    r'SysWOW64\dnsapi.dll',
    r'SysWOW64\dllhost.exe',
    r'System32\drivers\volsnap.sys',
)


def _md5(path: str) -> str:
    digest = hashlib.md5()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest().upper()


def _detail_line(path: str) -> Optional[str]:
    try:
        stat = os.stat(path)
    except OSError:
        return None
    created = datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M')
    modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
    publisher, signed = winapi.publisher_of(path)
    note = f'({publisher})' if publisher else '()'
    if not signed:
        note += ' [Файл не подписан]'
    try:
        checksum = _md5(path)
    except OSError:
        checksum = 'недоступен'
    return f'[{created}] - [{modified}] - {stat.st_size:09d} _____ {note} {checksum}'


def collect(testsigning: bool = False) -> List[str]:
    root = os.environ.get('SystemRoot', r'C:\Windows')
    lines: List[str] = [NOTE, '']
    if testsigning:
        lines.append('testsigning: ==> Установлен "testsigning". '
                     'Проверьте возможное присутствие неподписанного драйвера')
        lines.append('')
    for relative in SYSTEM_FILES:
        path = os.path.join(root, relative)
        if not os.path.isfile(path):
            continue
        lines.append(path)
        detail = _detail_line(path)
        if detail:
            lines.append(detail)
        lines.append('')
    return lines
