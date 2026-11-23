"""Alternate Data Streams: обход временных и пользовательских папок."""

from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from typing import Iterator, List, Tuple

from ..context import ScanContext

_MAX_FILES = 25000
_TIME_BUDGET = 25.0

# Сравниваем без ведущего двоеточия: так приходит cStreamName.
_SKIP_STREAMS = {
    'data',
    'zone.identifier',
    'index_allocation',
    'ea',
    'encryptable',
    '{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}',
}
_SKIP_DIRS = (
    r'programdata\microsoft\windows defender',
    r'programdata\package cache',
    r'programdata\microsoft\windows\wer',
    r'programdata\microsoft\windows\appreadiness',
    r'programdata\microsoft\windows\caches',
)


class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ('StreamSize', ctypes.c_longlong),
        ('cStreamName', wintypes.WCHAR * 296),
    ]


def _streams(path: str) -> List[Tuple[str, int]]:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.FindFirstStreamW.restype = wintypes.HANDLE
    kernel32.FindFirstStreamW.argtypes = [
        wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(_WIN32_FIND_STREAM_DATA),
        wintypes.DWORD]
    kernel32.FindNextStreamW.restype = wintypes.BOOL
    kernel32.FindNextStreamW.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(_WIN32_FIND_STREAM_DATA)]
    kernel32.FindClose.restype = wintypes.BOOL
    kernel32.FindClose.argtypes = [wintypes.HANDLE]
    data = _WIN32_FIND_STREAM_DATA()
    handle = kernel32.FindFirstStreamW(path, 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value or not handle:
        return []
    found: List[Tuple[str, int]] = []
    try:
        while True:
            name = data.cStreamName
            if name.lower().endswith(':$data'):
                name = name[:-len(':$data')]
            stripped = name.lstrip(':')
            if stripped and stripped.lower() not in _SKIP_STREAMS:
                found.append((stripped, int(data.StreamSize)))
            if not kernel32.FindNextStreamW(handle, ctypes.byref(data)):
                break
    finally:
        kernel32.FindClose(handle)
    return found


def _downloads(ctx: ScanContext) -> List[str]:
    folders: List[str] = []
    for sid in ctx.users():
        profile = ctx.profiles.get(sid) or ''
        if profile:
            folders.append(os.path.join(profile, 'Downloads'))
    return folders


def _scope(ctx: ScanContext) -> List[str]:
    folders = [os.path.expandvars('%TEMP%'),
               os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'Temp'),
               os.path.expandvars(r'%ProgramData%')]
    folders += _downloads(ctx)
    seen = set()
    unique = []
    for folder in folders:
        key = os.path.normcase(os.path.abspath(folder))
        if key not in seen and os.path.isdir(folder):
            seen.add(key)
            unique.append(folder)
    return unique


def _iter_files(folder: str, started: float) -> Iterator[str]:
    stack = [folder]
    visited = 0
    while stack:
        if time.monotonic() - started > _TIME_BUDGET or visited >= _MAX_FILES:
            return
        current = stack.pop()
        lowered = current.lower()
        if any(skip in lowered for skip in _SKIP_DIRS):
            continue
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            if time.monotonic() - started > _TIME_BUDGET or visited >= _MAX_FILES:
                return
            try:
                if entry.is_dir(follow_symlinks=False):
                    stack.append(entry.path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            visited += 1
            yield entry.path


def collect(ctx: ScanContext) -> List[str]:
    ctx.step('Альтернативные потоки данных')
    started = time.monotonic()
    lines: List[str] = []
    for folder in _scope(ctx):
        for path in _iter_files(folder, started):
            ctx.check_cancel()
            for name, size in _streams(path):
                lines.append(f'AlternateDataStreams: {path}:{name} [{size}]')
            if time.monotonic() - started > _TIME_BUDGET:
                break
        if time.monotonic() - started > _TIME_BUDGET:
            break
    return lines
