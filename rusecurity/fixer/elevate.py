"""Запуск фиксера с правами администратора через штатный UAC."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from ctypes import wintypes
from pathlib import Path
from typing import List, Optional, Tuple

from ..config import APP_DIR

_SEE_MASK_NOCLOSEPROCESS = 0x00000040
_SEE_MASK_FLAG_NO_UI = 0x00000400
_ERROR_CANCELLED = 1223
_INFINITE = 0xFFFFFFFF


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('fMask', wintypes.ULONG),
        ('hwnd', wintypes.HWND),
        ('lpVerb', wintypes.LPCWSTR),
        ('lpFile', wintypes.LPCWSTR),
        ('lpParameters', wintypes.LPCWSTR),
        ('lpDirectory', wintypes.LPCWSTR),
        ('nShow', ctypes.c_int),
        ('hInstApp', wintypes.HINSTANCE),
        ('lpIDList', ctypes.c_void_p),
        ('lpClass', wintypes.LPCWSTR),
        ('hkeyClass', wintypes.HKEY),
        ('dwHotKey', wintypes.DWORD),
        ('hIcon', wintypes.HANDLE),
        ('hProcess', wintypes.HANDLE),
    ]


def _python_gui() -> str:
    exe = Path(sys.executable)
    windowed = exe.with_name('pythonw.exe')
    return str(windowed) if windowed.is_file() else str(exe)


def run_elevated(args: List[str], timeout: int = 900) -> Tuple[bool, Optional[int], str]:
    """Запустить `python -m rusecurity <args>` от администратора и дождаться.

    Возвращает (запущено, код выхода, сообщение). При отказе UAC —
    (False, None, 'отменено пользователем').
    """
    shell32 = ctypes.WinDLL('shell32', use_last_error=True)
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    params = subprocess.list2cmdline(['-m', 'rusecurity'] + list(args))
    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(_SHELLEXECUTEINFOW)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS | _SEE_MASK_FLAG_NO_UI
    info.lpVerb = 'runas'
    info.lpFile = _python_gui()
    info.lpParameters = params
    info.lpDirectory = str(APP_DIR)
    info.nShow = 0
    ok = shell32.ShellExecuteExW(ctypes.byref(info))
    if not ok:
        error = ctypes.get_last_error()
        if error == _ERROR_CANCELLED:
            return False, None, 'запрос прав отменён'
        return False, None, f'не удалось запустить с правами администратора (код {error})'
    try:
        kernel32.WaitForSingleObject(info.hProcess, timeout * 1000)
        code = wintypes.DWORD()
        kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
        return True, int(code.value), ''
    finally:
        kernel32.CloseHandle(info.hProcess)
