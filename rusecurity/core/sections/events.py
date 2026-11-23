"""Точки восстановления и ошибки журнала событий (справочные разделы)."""

from __future__ import annotations

import json
import subprocess
from typing import List, Optional

_PS = ['powershell', '-NoProfile', '-NonInteractive', '-Command']


def _decode(raw: bytes) -> str:
    for encoding in ('utf-8', 'cp866'):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode('cp1251', errors='replace')


def _run_ps(script: str, timeout: int = 90) -> Optional[str]:
    try:
        completed = subprocess.run(_PS + [script], capture_output=True, timeout=timeout,
                                   creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return _decode(completed.stdout)


def restore_points() -> List[str]:
    script = ("Get-CimInstance -ClassName SystemRestore -Namespace root\\default "
              "-ErrorAction SilentlyContinue | Sort-Object CreationTime -Descending "
              "| Select-Object -First 10 "
              "@{n='Created';e={$_.CreationTime.ToString('dd-MM-yyyy HH:mm:ss')}},"
              "Description | ConvertTo-Json -Compress")
    output = _run_ps(script)
    if not output:
        return ['(Точки восстановления недоступны или восстановление системы отключено)']
    try:
        data = json.loads(output)
    except ValueError:
        return ['(Не удалось разобрать список точек восстановления)']
    items = data if isinstance(data, list) else [data]
    lines: List[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        created = str(item.get('Created') or '').strip()
        description = str(item.get('Description') or '').strip()
        if created:
            lines.append(f'{created} {description}'.strip())
    return lines or ['(Точки восстановления не найдены)']


def _event_lines(log_name: str, title: str, days: int = 7, limit: int = 6) -> List[str]:
    script = ("$ErrorActionPreference='SilentlyContinue'; "
              f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Level=2; "
              f"StartTime=(Get-Date).AddDays(-{days})}} -MaxEvents {limit} "
              "| Select-Object "
              "@{n='Time';e={$_.TimeCreated.ToString('dd-MM-yyyy HH:mm:ss')}},"
              "ProviderName,Id,Message | ConvertTo-Json -Compress")
    output = _run_ps(script)
    lines = [title]
    if not output:
        lines.append('  (журнал недоступен)')
        return lines
    try:
        data = json.loads(output)
    except ValueError:
        lines.append('  (не удалось разобрать журнал)')
        return lines
    items = data if isinstance(data, list) else [data]
    for item in items:
        if not isinstance(item, dict):
            continue
        created = str(item.get('Time') or '').strip()
        provider = str(item.get('ProviderName') or '').strip()
        event_id = item.get('Id')
        message = ' '.join(str(item.get('Message') or '').split())[:160]
        lines.append(f'  {created} - {provider} (EventID: {event_id}) - {message}')
    if len(lines) == 1:
        lines.append('  (ошибок не найдено)')
    return lines


def event_errors() -> List[str]:
    return (_event_lines('Application', 'Ошибки приложения:') +
            _event_lines('System', 'Ошибки системы:'))
