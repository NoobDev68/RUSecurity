"""Сборка отчётов RUSecurity."""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from .. import deep, names
from . import sysinfo
from .context import ScanContext
from .model import Report
from .sections import (addition, ads, association, bcd, events, internet, registry,
                       sigcheck, system)

# Виды сканирования: (поле ScanOptions, подпись в интерфейсе)
REPORT_OPTIONS: Tuple[Tuple[str, str], ...] = (
    ('processes', 'Процессы'),
    ('registry', 'Реестр'),
    ('tasks', 'Задачи'),
    ('internet', 'Internet'),
    ('services', 'Службы'),
    ('drivers', 'Драйверы'),
    ('sigcheck', 'SigCheck'),
    ('bcd', 'BCD'),
)

ADDITION_OPTIONS: Tuple[Tuple[str, str], ...] = (
    ('accounts', 'Учётные записи'),
    ('security_center', 'Центр безопасности'),
    ('programs', 'Программы'),
    ('clsid', 'CLSID'),
    ('ads', 'Потоки NTFS'),
    ('firewall', 'Брандмауэр'),
    ('msconfig', 'Автозагрузка'),
    ('association', 'Ассоциации'),
    ('restore_points', 'Точки восстановления'),
    ('shortcuts', 'Ярлыки'),
    ('hosts', 'Hosts'),
    ('drives', 'Диски'),
    ('event_errors', 'Ошибки журнала'),
    ('other_areas', 'Другие области'),
)


@dataclass
class ScanOptions:
    """Что собирать при сканировании. По умолчанию включено всё."""

    processes: bool = True
    registry: bool = True
    tasks: bool = True
    internet: bool = True
    services: bool = True
    drivers: bool = True
    sigcheck: bool = True
    bcd: bool = True
    accounts: bool = True
    security_center: bool = True
    programs: bool = True
    clsid: bool = True
    ads: bool = True
    firewall: bool = True
    msconfig: bool = True
    association: bool = True
    restore_points: bool = True
    shortcuts: bool = True
    hosts: bool = True
    drives: bool = True
    event_errors: bool = True
    other_areas: bool = True
    deep: bool = False

    def with_addition(self, enabled: bool) -> 'ScanOptions':
        return replace(self, **{name: enabled for name, _label in ADDITION_OPTIONS})

    def addition_enabled(self) -> bool:
        return any(getattr(self, name) for name, _label in ADDITION_OPTIONS)

    def enabled_labels(self) -> List[str]:
        labels = [label for name, label in REPORT_OPTIONS + ADDITION_OPTIONS
                  if getattr(self, name)]
        if self.deep:
            labels.append('Тщательное сканирование')
        return labels


@dataclass
class ScanResult:
    report: Path
    addition: Optional[Path]
    entries: int
    addition_entries: int = 0
    deep: Optional[Path] = None
    deep_count: int = 0


def _date() -> str:
    return datetime.now().strftime('%d-%m-%Y')


def _timestamp() -> str:
    return datetime.now().strftime('%d-%m-%Y %H:%M:%S')


def _platform_line() -> str:
    created = sysinfo.install_date()
    suffix = f' ({created})' if created else ''
    return (f'{sysinfo.windows_product()} ({sysinfo.architecture()}){suffix} '
            f'Язык: {sysinfo.ui_language()}')


def report_header(ctx: ScanContext, launcher: str) -> List[str]:
    return [
        f'Отчёт RUSecurity (x64) Версия: {_date()}',
        f'Запущено с помощью {sysinfo.user_display_name()} на {os.environ.get("COMPUTERNAME", "")}'
        f' ({sysinfo.computer_model()}) ({_timestamp()})',
        f'Запущено из {launcher}',
        f'Загруженные профили: {sysinfo.profiles_line([os.path.basename(ctx.profiles.get(s, "")) for s in ctx.users()])}',
        f'Платформа: {_platform_line()}',
        f'Браузер по умолчанию: {sysinfo.default_browser()}',
        'Режим загрузки: Normal',
        '',
    ]


def addition_header(ctx: ScanContext, launcher: str) -> List[str]:
    return [
        f'Дополнительный отчёт RUSecurity (x64) Версия: {_date()}',
        f'Запущено с помощью {sysinfo.user_display_name()} ({_timestamp()})',
        f'Запущено из {launcher}',
        f'{sysinfo.windows_product()} ({sysinfo.architecture()})',
        'Режим загрузки: Normal',
        '=' * 58,
        '',
        '',
    ]


def build_report(ctx: ScanContext, launcher: str,
                 options: Optional[ScanOptions] = None) -> Report:
    options = options or ScanOptions()
    report = Report(header=report_header(ctx, launcher))
    if options.processes:
        report.add('Процессы (Все)', system.processes(ctx))
    if options.registry:
        report.add('Реестр Windows (Все)', registry.collect(ctx))
    if options.tasks:
        report.add('Запланированные задачи (Все)', system.scheduled_tasks(ctx))
    if options.internet:
        report.add('Internet (Все)', internet.collect(ctx))
    if options.services or options.drivers:
        services, drivers = system.services_and_drivers(ctx)
        if options.services:
            report.add('Службы (Все)', services)
        if options.drivers:
            report.add('Драйверы (Все)', drivers)
    if options.sigcheck:
        report.add('SigCheck', sigcheck.collect(
            testsigning=bcd.testsigning_enabled() if options.bcd else False))
    if options.bcd:
        report.add('BCD', bcd.collect())
    report.add('Конец отчёта RUSecurity', [])
    return report


def build_addition(ctx: ScanContext, launcher: str,
                   options: Optional[ScanOptions] = None) -> Report:
    options = options or ScanOptions()
    report = Report(header=addition_header(ctx, launcher))
    if options.accounts:
        report.add('Учетные записи:', addition.accounts(ctx), note='')
    if options.security_center:
        report.add('Центр безопасности', addition.security_center())
    if options.programs:
        report.add('Установленные программы', addition.installed_programs(ctx))
    if options.clsid:
        report.add('Пользовательские CLSID:', addition.custom_clsid(ctx))
    if options.ads:
        report.add('Alternate Data Streams', ads.collect(ctx))
    if options.firewall:
        report.add('Правила Брандмауэра', addition.firewall_rules())
    if options.msconfig:
        report.add('MSCONFIG/TASK MANAGER отключённые элементы',
                   addition.msconfig_disabled(ctx))
    if options.association:
        report.add('Ассоциация', association.collect(ctx))
    if options.other_areas:
        report.add('Другие области', addition.other_areas(ctx))
    if options.restore_points:
        report.add('Точки восстановления', events.restore_points())
    if options.shortcuts:
        shortcuts = addition.shortcuts(ctx)
        report.add('Ярлыки & WMI', shortcuts + addition.wmi_subscriptions())
    if options.hosts:
        report.add('Hosts содержимое:', addition.hosts_content())
    if options.drives:
        report.add('Диски', addition.drives_and_memory())
    if options.event_errors:
        report.add('Ошибки журнала событий:', events.event_errors())
    report.add('Конец дополнительного отчёта', [])
    return report


def scan(output_dir: Path, include_addition: bool = True,
         progress: Optional[Callable[[str], None]] = None,
         options: Optional[ScanOptions] = None,
         cancel: Optional[Callable[[], bool]] = None) -> ScanResult:
    options = options or ScanOptions()
    if not include_addition:
        options = options.with_addition(False)
    ctx = ScanContext.detect(progress=progress, cancel=cancel)
    launcher = str(Path(sysinfo.launcher_path()).resolve())
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    ctx.check_cancel()
    report = build_report(ctx, launcher, options)
    ctx.check_cancel()
    report_path = report.write(output_dir / names.REPORT)
    addition_path: Optional[Path] = None
    addition_entries = 0
    if options.addition_enabled():
        ctx.check_cancel()
        addition_report = build_addition(ctx, launcher, options)
        ctx.check_cancel()
        addition_path = addition_report.write(output_dir / names.ADDITION)
        addition_entries = sum(len(section.lines) for section in addition_report.sections)
    else:
        # Дополнительный отчёт не собирали: старые файлы не должны попасть в анализ.
        for candidate in names.addition_candidates(output_dir / names.REPORT):
            try:
                candidate.unlink()
            except OSError:
                pass
    entries = sum(len(section.lines) for section in report.sections)
    deep_path: Optional[Path] = None
    deep_count = 0
    if options.deep:
        ctx.check_cancel()
        items = deep.collect(ctx)
        ctx.check_cancel()
        deep_path = deep.save(output_dir / names.DEEP, report_path, items)
        deep_count = len(items)
    else:
        try:
            (output_dir / names.DEEP).unlink()
        except OSError:
            pass
    return ScanResult(report=report_path, addition=addition_path, entries=entries,
                      addition_entries=addition_entries, deep=deep_path,
                      deep_count=deep_count)
