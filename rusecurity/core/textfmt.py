"""Форматирование записей отчёта: пути, команды, суффиксы файлов."""

from __future__ import annotations

import os
import re
import shutil
from typing import Tuple

from . import winapi

_DRIVE_RE = re.compile(r'^[A-Za-z]:[\\/]')
_NO_FILE = '(Нет файла)'


def strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def normalize_image_path(image: str) -> str:
    """Привести ImagePath/команду к обычному пути Windows."""
    if not image:
        return ''
    image = os.path.expandvars(image.strip())
    if image.startswith('"'):
        image = strip_quotes(image.split('"')[1] if image.count('"') >= 2 else image)
    for prefix in ('\\??\\', '\\\\?\\'):
        if image.startswith(prefix):
            image = image[len(prefix):]
            break
    if image.lower().startswith('\\systemroot\\'):
        image = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                             image[len('\\SystemRoot\\'):])
    return image


def _candidate_prefixes(text: str):
    """Префиксы команды от длинного к короткому — ищем существующий файл."""
    parts = text.split(' ')
    for index in range(len(parts), 0, -1):
        yield ' '.join(parts[:index])


def resolve_command_file(command: str) -> Tuple[str, bool]:
    """(путь к исполняемому файлу, существует ли он) из командной строки."""
    text = normalize_image_path(command)
    if not text:
        return '', False
    if os.path.isfile(text):
        return text, True
    for candidate in _candidate_prefixes(text):
        if os.path.isfile(candidate):
            return candidate, True
    if _DRIVE_RE.match(text) or text.startswith('\\\\'):
        return text, False
    name = text.split(' ')[0]
    search_dirs = [
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32'),
        os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'SysWOW64'),
        os.environ.get('SystemRoot', r'C:\Windows'),
    ]
    for directory in search_dirs:
        candidate = os.path.join(directory, name)
        if os.path.isfile(candidate):
            return candidate, True
    found = shutil.which(name)
    if found:
        return found, True
    return os.path.join(search_dirs[0], name), False


def file_suffix(path: str, missing: str = _NO_FILE) -> str:
    """' [размер дата] (издатель)' либо ' (Нет файла)'."""
    if not path or not os.path.isfile(path):
        return f' {missing}'
    return winapi.format_file_info(path)


def publisher_note(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ''
    publisher, _signed = winapi.publisher_of(path)
    return f' ({publisher})' if publisher else ' ()'
def command_suffix(command: str) -> str:
    """Суффикс для Run/Task/Service-записи по их командной строке."""
    path, exists = resolve_command_file(command)
    if not exists:
        return f' {_NO_FILE}'
    return winapi.format_file_info(path)




def format_shortcut(path: str, target: str, arguments: str) -> str:
    """Строка ярлыка: Shortcut/ShortcutWithArgument."""
    arguments = arguments.strip()
    if os.path.isfile(target):
        note = publisher_note(target)
    elif os.path.exists(target):
        note = ''
    else:
        note = f' {_NO_FILE}'
    if arguments:
        line = f'ShortcutWithArgument: {path} -> {target}{note} -> {arguments}'
    else:
        line = f'Shortcut: {path} -> {target}{note}'
    if _has_cyrillic(path):
        line += ' <==== Cyrillic'
    return line


def _has_cyrillic(text: str) -> bool:
    return any('а' <= ch.lower() <= 'я' or ch.lower() in 'ё' for ch in text)
