"""Фоновые задачи интерфейса: сканирование, исправление, восстановление."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QThread, Signal

from .. import names
from ..core import scanner
from ..core.scanner import ScanOptions, ScanResult


@dataclass
class ScanBundle:
    """Итог сканирования: отчёты, найденные элементы и время работы."""

    result: ScanResult
    analysis: object
    options: ScanOptions
    duration: float
    started: datetime


class ScanWorker(QThread):
    progress = Signal(str)
    finished_ok = Signal(object)
    failed = Signal(str)

    def __init__(self, output_dir: Path, options: ScanOptions) -> None:
        super().__init__()
        self.output_dir = output_dir
        self.options = options

    def run(self) -> None:
        from .. import analyzer
        started = datetime.now()
        began = time.monotonic()
        try:
            result = scanner.scan(self.output_dir, options=self.options,
                                  progress=self.progress.emit)
            analysis = analyzer.analyze(result.report, result.addition,
                                        options=self.options)
        except Exception as exc:  # noqa: BLE001 - показываем пользователю текст ошибки
            self.failed.emit(str(exc))
            return
        self.finished_ok.emit(ScanBundle(result, analysis, self.options,
                                         time.monotonic() - began, started))


class HardeningWorker(QThread):
    """Проверка безопасности: чтение параметров и список отклонений."""

    finished_ok = Signal(object)
    failed = Signal(str)

    def run(self) -> None:
        from ..core import hardening
        try:
            issues = hardening.evaluate()
        except Exception as exc:  # noqa: BLE001 - показываем текст ошибки
            self.failed.emit(str(exc))
            return
        self.finished_ok.emit(issues)


class FixWorker(QThread):
    """Выполнение выбранных исправлений; при необходимости — через UAC."""

    progress = Signal(str, str, str)
    finished_ok = Signal(object, str)
    failed = Signal(str)

    def __init__(self, text: str, log_path: Path, backup_dir: Path,
                 create_restore_point: bool = True,
                 allow_reboot: bool = False) -> None:
        super().__init__()
        self.text = text
        self.log_path = Path(log_path)
        self.backup_dir = Path(backup_dir)
        self.create_restore_point = create_restore_point
        self.allow_reboot = allow_reboot

    def run(self) -> None:
        from ..fixer import Fixer, elevate
        try:
            if elevate.is_admin():
                report = Fixer(self.backup_dir, self.log_path,
                               allow_reboot=self.allow_reboot,
                               create_restore_point=self.create_restore_point,
                               progress=self.progress.emit).run(self.text)
                self.finished_ok.emit(report, str(self.log_path))
                return
            fixlist = self.log_path.with_name(names.FIXLIST)
            fixlist.parent.mkdir(parents=True, exist_ok=True)
            fixlist.write_text(self.text, encoding='utf-8', newline='')
            args = ['apply', str(fixlist), '--yes', '--log', str(self.log_path),
                    '--backup-dir', str(self.backup_dir)]
            if not self.create_restore_point:
                args.append('--no-restore-point')
            if self.allow_reboot:
                args.append('--reboot')
            ok, _code, message = elevate.run_elevated(args)
            if not ok:
                self.failed.emit(message)
                return
            self.finished_ok.emit(None, str(self.log_path))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class QuarantineDeleteWorker(QThread):
    """Удаление записей карантина: выбранных или всего каталога Backups."""

    finished_ok = Signal(int, int)
    failed = Signal(str)

    def __init__(self, entries: list | None = None, reports_dir: Path | None = None,
                 clear_all: bool = False) -> None:
        super().__init__()
        self.entries = list(entries or [])
        self.reports_dir = Path(reports_dir) if reports_dir else None
        self.clear_all = clear_all

    def run(self) -> None:
        from ..fixer import restore as quarantine
        try:
            if self.clear_all:
                deleted, failed = quarantine.clear_quarantine(self.reports_dir)
            else:
                results = quarantine.delete_entries(self.entries)
                deleted = sum(1 for _entry, status in results
                              if not status.startswith('failed'))
                failed = len(results) - deleted
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
            return
        self.finished_ok.emit(deleted, failed)


class RestoreWorker(QThread):
    """Возврат объектов из карантина (через UAC при необходимости)."""
    finished_ok = Signal(int)
    failed = Signal(str)

    def __init__(self, entries: list) -> None:
        super().__init__()
        self.entries = entries

    def run(self) -> None:
        from ..fixer import elevate
        from ..fixer import restore as quarantine
        groups: dict = {}
        for entry in self.entries:
            groups.setdefault(entry.manifest, []).append(entry.item_id)
        try:
            if elevate.is_admin():
                failed = 0
                for manifest, ids in groups.items():
                    items = quarantine.resolve_entries(manifest, ids)
                    results = quarantine.restore_many(
                        items, manifest.parent / 'restore-log.txt')
                    failed += sum(1 for _entry, status in results
                                  if status.startswith('failed'))
                self.finished_ok.emit(1 if failed else 0)
                return
            for manifest, ids in groups.items():
                args = ['restore', str(manifest), '--yes']
                for item_id in ids:
                    args += ['--item', str(item_id)]
                ok, code, message = elevate.run_elevated(args)
                if not ok:
                    self.failed.emit(message)
                    return
                if code:
                    self.finished_ok.emit(int(code))
                    return
            self.finished_ok.emit(0)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
