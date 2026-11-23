"""Анализ отчётов и генерация fixlist поверх движка GenFix."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import GenFix
from report_parser import is_boilerplate_action

from . import names
from .fixer import actions as act

# Категории fixlist (комментарии GenFix) → подписи для интерфейса
_SECTION_LABELS: Dict[str, str] = {
    'Group Policy / Policies': 'Политики',
    'Registry (HKLM)': 'Реестр',
    'Registry (HKU)': 'Реестр',
    'Custom CLSID / Shell Extensions': 'Расширения оболочки',
    'Chrome': 'Браузеры',
    'Edge': 'Браузеры',
    'Firefox': 'Браузеры',
    'Opera': 'Браузеры',
    'Security Center': 'Центр безопасности',
    'MSCONFIG': 'Автозагрузка',
    'Scheduled Tasks': 'Задачи',
    'Services / Drivers': 'Службы и драйверы',
    'Alternate Data Streams': 'Потоки NTFS',
    'Firewall Rules': 'Брандмауэр',
    'Shortcuts': 'Ярлыки',
    'Files / Folders': 'Файлы',
}

_DIRECTIVES = ('restore_point', 'close_processes', 'empty_temp', 'reboot')
_DIRECTIVE_LINES = {
    'restore_point': 'createrestorepoint:',
    'close_processes': 'closeprocesses:',
    'empty_temp': 'emptytemp:',
    'reboot': 'reboot:',
}
_SKIP_KINDS = {act.NOOP, act.CLOSE_PROCESSES, act.RESTORE_POINT, act.REBOOT,
               act.EMPTY_TEMP, act.EXPORT_KEY}


@dataclass
class Finding:
    """Найденный элемент, который фиксер умеет исправить."""

    category: str
    text: str
    kind: str
    kind_label: str
    manual: bool = False
    note: str = ''


@dataclass
class AnalysisResult:
    text: str
    fix_count: int
    entries: int
    actions: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    directives: Dict[str, bool] = field(default_factory=dict)


class _Collector(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.messages.append(record.getMessage())
        except Exception:  # noqa: BLE001 - сообщение не должно ронять анализ
            self.messages.append(str(record.msg))


def analyze(report_path: Path, addition_path: Optional[Path] = None,
            output_path: Optional[Path] = None,
            options: Optional['ScanOptions'] = None) -> AnalysisResult:
    """Разобрать отчёты и вернуть текст fixlist. Пустой текст — автодействий нет."""
    collector = _Collector()
    logger = logging.getLogger('generate_fixlist')
    logger.addHandler(collector)
    try:
        text = GenFix.generate_fixlist(
            str(report_path),
            additional_path=str(addition_path) if addition_path else None,
            output_path=str(output_path) if output_path else None,
        )
    finally:
        logger.removeHandler(collector)
    text = text or ''
    actions = [line for line in parse_fixlist_text(text) if not is_boilerplate_action(line)]
    items = _filter_findings(findings(text), options)
    return AnalysisResult(text=text, fix_count=len(actions), entries=_entry_count(collector),
                          actions=actions, findings=items,
                          directives=directives(text))


def _filter_findings(items: List[Finding],
                     options: Optional['ScanOptions']) -> List[Finding]:
    """Убрать проверки, которым не хватает отключённых разделов.

    Без списка установленных программ любая запись Центра безопасности выглядит
    «мёртвой», а без списка служб — любая запись MSCONFIG. Такие находки опасны,
    поэтому при отключённых разделах они не показываются.
    """
    if options is None:
        return items
    skip = set()
    if not options.programs:
        skip.add('Центр безопасности')
    if not options.services:
        skip.add('Автозагрузка')
    return [item for item in items if item.category not in skip]


def parse_fixlist_text(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().startswith(';')]


def findings(text: str) -> List[Finding]:
    """Список найденных элементов с категориями и видом действия."""
    result: List[Finding] = []
    category = 'Прочее'
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith('; ----') and stripped.endswith('----'):
            title = stripped.strip('; -').strip()
            if 'Проверьте вручную' in title:
                continue
            category = _SECTION_LABELS.get(title, 'Прочее')
            continue
        if stripped.startswith(';'):
            continue
        actions = act.parse_fixlist(stripped)
        if not actions:
            continue
        action = actions[0]
        if action.kind in _SKIP_KINDS:
            continue
        if action.kind == act.HOSTS:
            result.append(Finding('Hosts', stripped, action.kind,
                                  act.KIND_LABELS[action.kind]))
            continue
        result.append(Finding(
            category=category,
            text=stripped,
            kind=action.kind,
            kind_label=act.KIND_LABELS.get(action.kind, action.kind),
            manual=action.kind == act.MANUAL,
            note=action.manual_reason,
        ))
    return result


def directives(text: str) -> Dict[str, bool]:
    """Какие директивы рекомендует анализ (для галочек Reboot/EmptyTemp/...)."""
    lines = {line.strip().lower() for line in text.splitlines()}
    result = {name: _DIRECTIVE_LINES[name] in lines for name in _DIRECTIVES}
    if result['close_processes']:
        # Закрывать имеет смысл только процессы, держащие удаляемые файлы:
        # для реестра, служб и задач директива — пустая операция.
        actions = act.parse_fixlist(text)
        result['close_processes'] = any(
            action.kind in (act.FILE, act.ADS, act.EXTENSION) for action in actions)
    return result


def compose_fixlist(selected: List[str], restore_point: bool = True,
                    close_processes: bool = True, empty_temp: bool = False,
                    reboot: bool = False) -> str:
    """Собрать fixlist из выбранных элементов и директив."""
    lines = ['Start::']
    if close_processes:
        lines.append('CloseProcesses:')
    lines.append('SystemRestore: On')
    if restore_point:
        lines.append('CreateRestorePoint:')
    lines.extend(selected)
    if empty_temp:
        lines.append('EmptyTemp:')
    if reboot:
        lines.append('Reboot:')
    lines.append('End::')
    return '\n'.join(lines) + '\n'


def save_fixlist(text: str, output_path: Path) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding='utf-8', newline='')
    return output_path


def resolve_addition(report_path: Path) -> Optional[Path]:
    """Найти дополнительный отчёт рядом с основным."""
    for candidate in names.addition_candidates(Path(report_path)):
        if candidate.is_file():
            return candidate
    resolved = GenFix._resolve_addition_path(str(report_path))
    if resolved and Path(resolved).is_file():
        return Path(resolved)
    return None


def _entry_count(collector: _Collector) -> int:
    for message in collector.messages:
        if message.startswith('Проанализировано:'):
            try:
                return int(message.split()[1])
            except (IndexError, ValueError):
                return 0
    return 0
