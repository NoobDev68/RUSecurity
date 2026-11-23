"""Секции: процессы, службы, драйверы, запланированные задачи."""

from __future__ import annotations

import csv
import io
import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, List, Tuple

from .. import winapi
from ..context import ScanContext
from ..textfmt import command_suffix

_START_TYPES = {0: 'S0', 1: 'S1', 2: 'S2', 3: 'S3', 4: 'S4'}
_SERVICE_TYPE_DRIVER = 0x0B
_SERVICE_TYPES = (0x10, 0x20, 0x110, 0x120)


def processes(ctx: ScanContext) -> List[str]:
    ctx.step('Процессы')
    items = winapi.list_processes()
    names = {item.pid: item.name for item in items}
    counters: Dict[str, int] = {}
    order: List[str] = []
    for item in items:
        if item.pid == 0:
            continue
        path = winapi.process_image_path(item.pid) or item.path
        if not path:
            line = f'Не удалось получить доступ к процессу -> {item.name}'
            counters[line] = counters.get(line, 0) + 1
            if line not in order:
                order.append(line)
            continue
        parent = names.get(item.parent_pid, '')
        head = f'({parent} ->) ' if parent and parent.lower() != item.name.lower() else ''
        publisher, signed = winapi.publisher_of(path)
        note = f'({publisher})' if publisher else '()'
        if not signed:
            note += ' [Файл не подписан]'
        line = f'{head}{note} {path}'
        if line not in counters:
            order.append(line)
        counters[line] = counters.get(line, 0) + 1
    lines: List[str] = []
    for line in order:
        count = counters[line]
        lines.append(f'{line} <{count}>' if count > 1 else line)
    return lines


def _render_service(prefix: str, name: str, image: str) -> str:
    if not image:
        return f'{prefix} {name}; отсутствует ImagePath'
    return f'{prefix} {name}; {image}{command_suffix(image)}'


def services_and_drivers(ctx: ScanContext) -> Tuple[List[str], List[str]]:
    ctx.step('Службы и драйверы')
    base = r'SYSTEM\CurrentControlSet\Services'
    services: List[str] = []
    drivers: List[str] = []
    for name in winapi.enum_keys(winapi.HKLM, base):
        key = f'{base}\\{name}'
        start = winapi.read_value(winapi.HKLM, key, 'Start')
        service_type = winapi.read_value(winapi.HKLM, key, 'Type')
        image = winapi.read_value(winapi.HKLM, key, 'ImagePath')
        if start is None or service_type is None:
            continue
        try:
            start_int = int(start)
            type_int = int(service_type)
        except (TypeError, ValueError):
            continue
        prefix = _START_TYPES.get(start_int, 'S4')
        text = image if isinstance(image, str) else ''
        if not text and type_int in (0x01, 0x02, 0x03, 0x08):
            continue
        if type_int & _SERVICE_TYPE_DRIVER and not type_int & 0x20:
            drivers.append(_render_service(prefix, name, text))
        elif type_int in _SERVICE_TYPES:
            services.append(_render_service(prefix, name, text))
    return services, drivers


def _registry_tasks() -> List[str]:
    """Задачи из TaskCache: работает без schtasks (и когда тот недоступен)."""
    tree = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    tasks = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks'
    lines: List[str] = []

    def walk(path: str, prefix: str) -> None:
        for name in winapi.enum_keys(winapi.HKLM, path):
            sub = f'{path}\\{name}'
            guid = winapi.read_value(winapi.HKLM, sub, 'Id')
            full = f'{prefix}\\{name}' if prefix else name
            if isinstance(guid, str) and guid:
                brace = '{' + guid.strip('{}').upper() + '}'
                command = ''
                for key_name in (guid, brace, guid.strip('{}').upper()):
                    image = winapi.read_value(winapi.HKLM, f'{tasks}\\{key_name}', 'Path')
                    if isinstance(image, str) and image:
                        arguments = winapi.read_value(
                            winapi.HKLM, f'{tasks}\\{key_name}', 'Arguments')
                        command = image
                        if isinstance(arguments, str) and arguments:
                            command += ' ' + arguments
                        break
                line = f'Task: {brace} - System32\\Tasks\\{full}'
                if command:
                    line += f' => {command}{command_suffix(command)}'
                lines.append(line)
            walk(sub, full)

    walk(tree, '')
    return lines


def scheduled_tasks(ctx: ScanContext) -> List[str]:
    ctx.step('Запланированные задачи')
    guid_map = _task_guids()
    output = _schtasks_csv()
    lines: List[str] = []
    if output:
        for row in csv.DictReader(io.StringIO(output)):
            name = (row.get('TaskName') or row.get('Имя задачи') or '').strip()
            if not name or name.lower().startswith('\\microsoft\\windows\\'):
                continue
            command = (row.get('Task To Run') or row.get('Задача для запуска') or '').strip()
            relative = name.lstrip('\\')
            guid = guid_map.get(relative.lower())
            task_path = f'System32\\Tasks\\{relative}'
            prefix = f'Task: {guid} - ' if guid else 'Task: '
            if not command or command.upper() in ('N/A', 'Н/Д'):
                lines.append(f'{prefix}{task_path}')
            else:
                lines.append(f'{prefix}{task_path} => {command}{command_suffix(command)}')
        return lines

    registry_lines = _registry_tasks()
    if registry_lines:
        return registry_lines

    task_dir = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'Tasks')
    for root, _dirs, files in os.walk(task_dir):
        for name in files:
            path = os.path.join(root, name)
            relative = os.path.relpath(path, task_dir)
            command = _task_command(path)
            guid = guid_map.get(relative.lower())
            prefix = f'Task: {guid} - ' if guid else 'Task: '
            line = f'{prefix}System32\\Tasks\\{relative}'
            if command:
                line += f' => {command}{command_suffix(command)}'
            lines.append(line)
    if not lines:
        lines.append('(Задачи недоступны: служба планировщика не ответила)')
    return lines


def _task_command(task_file: str) -> str:
    try:
        root = ET.parse(task_file).getroot()
    except (OSError, ET.ParseError):
        return ''
    namespace = '{http://schemas.microsoft.com/windows/2004/02/mit/task}'
    for element in root.iter(f'{namespace}Exec'):
        command = element.find(f'{namespace}Command')
        arguments = element.find(f'{namespace}Arguments')
        if command is not None and command.text:
            text = command.text.strip()
            if arguments is not None and arguments.text:
                text += ' ' + arguments.text.strip()
            return text
    return ''


def _schtasks_csv() -> str:
    try:
        completed = subprocess.run(['schtasks', '/query', '/fo', 'CSV', '/v'],
                                   capture_output=True, creationflags=0x08000000,
                                   timeout=60)
    except (OSError, subprocess.SubprocessError):
        return ''
    if completed.returncode != 0:
        return ''
    return completed.stdout.decode('cp866', errors='replace')


def _task_guids() -> Dict[str, str]:
    base = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
    result: Dict[str, str] = {}

    def walk(path: str, prefix: str) -> None:
        for name in winapi.enum_keys(winapi.HKLM, path):
            sub = f'{path}\\{name}'
            guid = winapi.read_value(winapi.HKLM, sub, 'Id')
            full = f'{prefix}\\{name}' if prefix else name
            if isinstance(guid, str) and guid:
                result[full.lower()] = '{' + guid.strip('{}').upper() + '}'
            walk(sub, full)

    walk(base, '')
    return result
