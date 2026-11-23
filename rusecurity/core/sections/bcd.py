"""Раздел BCD: вывод bcdedit (только чтение)."""

from __future__ import annotations

import subprocess
from typing import List

_output: List[str] = []
_loaded = False


def _bcdedit() -> List[str]:
    global _loaded, _output
    if _loaded:
        return _output
    _loaded = True
    try:
        completed = subprocess.run(['bcdedit', '/enum', 'all'], capture_output=True,
                                   timeout=60, creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        _output = []
        return _output
    if completed.returncode != 0:
        _output = []
        return _output
    text = completed.stdout.decode('cp866', errors='replace')
    _output = [line.rstrip() for line in text.splitlines()]
    return _output


def testsigning_enabled() -> bool:
    for line in _bcdedit():
        stripped = line.strip().lower()
        if stripped.startswith('testsigning') and stripped.endswith('yes'):
            return True
    return False


def collect() -> List[str]:
    lines = _bcdedit()
    if not lines:
        return ['(Список BCD недоступен: bcdedit не ответил)']
    return lines
