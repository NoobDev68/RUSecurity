"""Выполнение fixlist: бэкапы, удаление, журнал."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import time
import winreg
from ctypes import wintypes
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

from ..core import winapi
from . import actions as act
from . import registry

_TEMP_DIRS = ('%TEMP%', '%TMP%', r'%SystemRoot%\Temp', '%LOCALAPPDATA%\\Temp')

_DEFAULT_HOSTS = (
    '# hosts — сброшено RUSecurity {date}\n'
    '127.0.0.1 localhost\n'
    '::1 localhost\n'
)

_NOOP_KINDS = {act.NOOP, act.CLOSE_PROCESSES}
_MUTATING_KINDS = {
    act.REG_VALUE, act.REG_KEY, act.REG_SET, act.SERVICE, act.TASK, act.FIREWALL,
    act.SECURITY_PROVIDER, act.SHORTCUT, act.SHORTCUT_TARGET, act.SHORTCUT_CLEAN,
    act.PROCESS_KILL, act.BITS_CANCEL, act.WEB_DATA, act.SERVICE_QUOTE,
    act.FILE, act.ADS, act.HOSTS, act.EMPTY_TEMP, act.BROWSER_CACHE, act.EXPORT_KEY,
    act.BROWSER, act.EXTENSION,
}


@dataclass
class Outcome:
    action: act.Action
    status: str
    detail: str = ''


@dataclass
class FixReport:
    outcomes: List[Outcome] = field(default_factory=list)
    reboot_required: bool = False
    restore_point: str = ''
    backup_dir: Optional[Path] = None
    log_path: Optional[Path] = None
    dry_run: bool = False

    @property
    def changed(self) -> int:
        return sum(1 for item in self.outcomes if item.status == 'done')

    @property
    def failed(self) -> int:
        return sum(1 for item in self.outcomes if item.status == 'failed')

    @property
    def manual(self) -> int:
        return sum(1 for item in self.outcomes if item.status == 'manual')


def _run(command: List[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, timeout=timeout,
                          creationflags=0x08000000)


def schedule_reboot(delay: int = 30) -> bool:
    """Запланировать перезагрузку Windows с предупреждением за delay секунд."""
    try:
        completed = _run(['shutdown', '/r', '/t', str(delay), '/c', 'RUSecurity'],
                         timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def _schedule_delete(path: str) -> bool:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.MoveFileExW.restype = wintypes.BOOL
    kernel32.MoveFileExW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    return bool(kernel32.MoveFileExW(path, None, 0x4))


def _delete_ads(path: str, stream: str) -> bool:
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.DeleteFileW.restype = wintypes.BOOL
    return bool(kernel32.DeleteFileW(f'{path}:{stream}'))


class Fixer:
    """Исполнитель fixlist. Все изменения — только после бэкапа."""

    def __init__(self, backup_dir: Path, log_path: Path, dry_run: bool = False,
                 allow_reboot: bool = False, hosts_path: Optional[Path] = None,
                 progress: Optional[Callable[[str, str, str], None]] = None,
                 create_restore_point: bool = True) -> None:
        self.backup_dir = Path(backup_dir)
        self.log_path = Path(log_path)
        self.dry_run = dry_run
        self.allow_reboot = allow_reboot
        self.hosts_path = Path(hosts_path) if hosts_path else Path(
            os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                         r'System32\drivers\etc\hosts'))
        self.progress = progress
        self.create_restore_point = create_restore_point
        self._firewall_backed_up = False
        self._firewall_reloaded = False
        self._restore_point_done = False
        self._restore_message = ''
        self._pending_reboot = False
        self._manifest: List[dict] = []
        self._edited_files: set = set()
        self._log_lines: List[str] = []

    # --- публичный запуск --------------------------------------------------
    def run(self, text: str) -> FixReport:
        parsed = act.parse_fixlist(text)
        report = FixReport(dry_run=self.dry_run)
        if not parsed:
            return report
        if not self.dry_run:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            report.backup_dir = self.backup_dir
            if self.create_restore_point and any(a.kind in _MUTATING_KINDS for a in parsed):
                report.restore_point = self._create_restore_point()
        if any(a.kind == act.CLOSE_PROCESSES for a in parsed):
            self._close_processes(parsed)
        for action in parsed:
            outcome = self._execute(action)
            report.outcomes.append(outcome)
            self._log(outcome)
            if self.progress:
                self.progress(action.raw, outcome.status, outcome.detail)
        report.reboot_required = (self._pending_reboot or
                                  any(a.kind in (act.SERVICE, act.REBOOT) for a in parsed))
        if self.dry_run:
            return report
        self._write_manifest()
        if report.reboot_required and self.allow_reboot:
            self._log_line('[reboot] перезагрузка через 30 секунд')
            _run(['shutdown', '/r', '/t', '30', '/c', 'RUSecurity'], timeout=20)
        report.log_path = self._write_log(report)
        return report

    # --- выполнение --------------------------------------------------------
    def _execute(self, action: act.Action) -> Outcome:
        try:
            handler = getattr(self, f'_do_{action.kind}', None)
            if handler is None:
                return Outcome(action, 'manual', action.manual_reason or 'нет обработчика')
            return handler(action)
        except Exception as exc:  # noqa: BLE001 - любая ошибка не должна рвать прогон
            return Outcome(action, 'failed', str(exc))

    def _do_noop(self, action: act.Action) -> Outcome:
        return Outcome(action, 'skipped', 'служебная строка')

    _do_close_processes = _do_noop

    def _do_manual(self, action: act.Action) -> Outcome:
        return Outcome(action, 'manual', action.manual_reason)

    def _do_reg_value(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить значение')
        self._backup_registry_value(action.path)
        status = registry.delete_value(action.path, action.name)
        return Outcome(action, status, f'значение [{action.name}]')

    def _do_reg_key(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить ключ')
        if not registry.exists(action.path):
            return Outcome(action, 'not_found', action.path)
        self._backup_registry(action.path)
        status = registry.delete_key(action.path)
        return Outcome(action, status, action.path)

    def _do_reg_set(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'восстановить значение')
        # Значение до исправления может отсутствовать, поэтому для отката
        # запоминаем само значение: при возврате его нужно удалить.
        self._manifest.append({
            'kind': 'reg_new',
            'original': f'{action.path}\\{action.name}',
            'stored': '',
        })
        self._backup_registry_value(action.path)
        status = registry.set_value(action.path, action.name, action.reg_type, action.value)
        return Outcome(action, status, f'{action.name}={action.value}')

    def _do_service(self, action: act.Action) -> Outcome:
        name = action.name
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить службу')
        self._backup_registry(f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}')
        _run(['sc', 'stop', name], timeout=30)
        time.sleep(1.5)
        service_key = f'HKLM\\SYSTEM\\CurrentControlSet\\Services\\{name}'
        try:
            status = registry.delete_key(service_key)
        except OSError as exc:
            try:
                if winapi.take_registry_ownership(
                        winapi.HKLM, f'SYSTEM\\CurrentControlSet\\Services\\{name}'):
                    status = registry.delete_key(service_key)
                else:
                    raise exc
            except OSError:
                return Outcome(action, 'failed',
                               f'служба занята: {exc} (перезагрузите и повторите)')
        if status == 'not_found':
            return Outcome(action, 'not_found', name)
        return Outcome(action, 'done', f'служба {name}')

    def _do_task(self, action: act.Action) -> Outcome:
        name = action.name.strip('\\')
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить задачу')
        if not self._backup_task(name):
            return Outcome(action, 'failed',
                           'не удалось сохранить XML задачи для отката')
        completed = _run(['schtasks', '/Delete', '/TN', '\\' + name, '/F'])
        if completed.returncode != 0:
            text = completed.stderr.decode('cp866', errors='replace').strip()
            return Outcome(action, 'failed', text or 'schtasks не удалил задачу')
        return Outcome(action, 'done', f'задача {name}')

    def _do_firewall(self, action: act.Action) -> Outcome:
        key = ('HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters'
               '\\FirewallPolicy\\FirewallRules')
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить правило брандмауэра')
        if not self._firewall_backed_up:
            self._backup_registry(key)
            self._firewall_backed_up = True
        status = registry.delete_value(key, action.name)
        detail = f'правило [{action.name}]'
        if status == 'done' and not self._firewall_reloaded:
            self._reload_firewall()
            self._firewall_reloaded = True
            detail += '; служба брандмауэра перезапущена'
        return Outcome(action, status, detail)

    def _reload_firewall(self) -> None:
        """Применить удаление правил сразу — перезапустить службу брандмауэра."""
        try:
            _run(['powershell', '-NoProfile', '-NonInteractive', '-Command',
                  'Restart-Service mpssvc -Force -ErrorAction SilentlyContinue'],
                 timeout=90)
        except (OSError, subprocess.SubprocessError):
            pass

    def _do_security_provider(self, action: act.Action) -> Outcome:
        path = (f'HKLM\\SOFTWARE\\Microsoft\\Security Center\\Provider'
                f'\\{action.name}\\{action.guid}')
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить мёртвую запись AV/FW')
        if not registry.exists(path):
            return Outcome(action, 'not_found', path)
        self._backup_registry(path)
        return Outcome(action, registry.delete_key(path), path)

    def _do_shortcut(self, action: act.Action) -> Outcome:
        return self._delete_path(action, action.path)

    def _do_shortcut_target(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить ярлык из автозагрузки')
        for folder in self._startup_folders():
            candidate = Path(folder) / action.name
            if candidate.is_file():
                return self._delete_path(action, str(candidate))
        return Outcome(action, 'not_found', action.name)

    def _do_shortcut_clean(self, action: act.Action) -> Outcome:
        if not action.target:
            return Outcome(action, 'failed', 'в ярлыке нет цели')
        source = Path(action.path)
        if not source.is_file():
            return Outcome(action, 'not_found', str(source))
        if self.dry_run:
            return Outcome(action, 'planned', 'исправить ярлык')
        self._backup_edit(source)
        if winapi.create_shortcut(str(source), action.target, action.value):
            return Outcome(action, 'done', f'{source} -> {action.target}')
        return Outcome(action, 'failed', 'ярлык не перезаписан')

    def _do_process_kill(self, action: act.Action) -> Outcome:
        try:
            pid = int(action.name)
        except (TypeError, ValueError):
            return Outcome(action, 'failed', 'некорректный PID')
        target = Path(os.path.expandvars(action.path))
        if self.dry_run:
            return Outcome(action, 'planned', 'завершить процесс и убрать файл')
        actual = winapi.process_image_path(pid)
        if not actual:
            return Outcome(action, 'not_found', f'PID {pid} уже завершён')
        if os.path.normcase(os.path.abspath(actual)) != os.path.normcase(
                os.path.abspath(str(target))):
            return Outcome(action, 'failed', 'PID уже занят другим процессом')
        if not winapi.terminate_process(pid):
            return Outcome(action, 'failed', 'процесс не завершён')
        if target.exists():
            if self._quarantine(target):
                return Outcome(action, 'done', f'PID {pid}, файл в карантине')
            return Outcome(action, 'failed', 'процесс закрыт, файл убрать не удалось')
        return Outcome(action, 'done', f'PID {pid}, файла уже нет')

    def _do_bits_cancel(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'отменить BITS-задание')
        try:
            completed = _run(['bitsadmin', '/cancel', action.name], timeout=60)
        except (OSError, subprocess.SubprocessError) as exc:
            return Outcome(action, 'failed', str(exc))
        if completed.returncode != 0:
            text = completed.stderr.decode('cp866', errors='replace').strip()
            return Outcome(action, 'failed', text or 'bitsadmin /cancel')
        return Outcome(action, 'done', f'BITS: {action.name}')

    def _do_web_data(self, action: act.Action) -> Outcome:
        from . import browsers

        database = Path(action.path)
        if not database.is_file():
            return Outcome(action, 'not_found', str(database))
        try:
            row_id = int(action.name)
        except (TypeError, ValueError):
            return Outcome(action, 'failed', 'некорректный id движка')
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить поисковый движок')
        browsers.close(action.browser)
        try:
            checkpoint = sqlite3.connect(database)
            try:
                checkpoint.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                checkpoint.commit()
            finally:
                checkpoint.close()
            self._backup_edit(database)
            connection = sqlite3.connect(database)
            try:
                cursor = connection.execute(
                    'DELETE FROM keywords WHERE id = ?', (row_id,))
                connection.commit()
                if cursor.rowcount <= 0:
                    return Outcome(action, 'not_found', f'id {row_id}')
            finally:
                connection.close()
        except sqlite3.Error as exc:
            return Outcome(action, 'failed', str(exc))
        return Outcome(action, 'done', f'{database.name}: id {row_id}')

    def _do_service_quote(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'взять ImagePath в кавычки')
        if not registry.exists(action.path):
            return Outcome(action, 'not_found', action.path)
        self._backup_registry_value(action.path)
        status = registry.set_value(action.path, 'ImagePath',
                                    'REG_EXPAND_SZ', action.value)
        return Outcome(action, status, action.value)

    def _do_file(self, action: act.Action) -> Outcome:
        return self._delete_path(action, action.path)

    def _do_ads(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'удалить поток')
        if _delete_ads(action.path, action.name):
            return Outcome(action, 'done', f'{action.path}:{action.name}')
        return Outcome(action, 'failed', 'поток не удалён (нет прав или файла)')

    def _do_browser(self, action: act.Action) -> Outcome:
        from . import browsers

        if self.dry_run:
            return Outcome(action, 'planned', 'исправить настройку браузера')
        status, detail = browsers.apply(
            action.browser, action.setting, action.target, action.url,
            self._backup_edit)
        return Outcome(action, status, detail)

    def _do_extension(self, action: act.Action) -> Outcome:
        from . import extensions

        if self.dry_run:
            return Outcome(action, 'planned', 'удалить расширение')
        status, detail = extensions.apply(action.browser, action.path,
                                          self._backup_edit)
        folder = extensions.folder(action.path)
        if folder.exists():
            if self._quarantine(folder):
                status = 'done'
                detail += '; папка расширения в карантине'
            else:
                try:
                    shutil.rmtree(folder)
                    status = 'done'
                    detail += '; папка расширения удалена'
                except OSError as exc:
                    detail += f'; папку удалить не удалось: {exc}'
        return Outcome(action, status, detail)

    def _do_hosts(self, action: act.Action) -> Outcome:
        from GenFix import is_suspicious_hosts_line

        if self.dry_run:
            return Outcome(action, 'planned', 'удалить подозрительные записи hosts')
        path = self.hosts_path
        if path.is_file():
            try:
                text = path.read_bytes().decode('utf-8', errors='surrogateescape')
            except OSError as exc:
                return Outcome(action, 'failed', str(exc))
            kept: List[str] = []
            suspicious: List[str] = []
            for line in text.splitlines(keepends=True):
                target = suspicious if is_suspicious_hosts_line(line) else kept
                target.append(line)
            if not suspicious:
                return Outcome(action, 'skipped',
                               'подозрительных записей не найдено')
            self._backup_hosts(path)
            content = ''.join(kept)
            if content and not content.endswith('\n'):
                content += '\n'
            for line in suspicious[:5]:
                self._log_line(f'[hosts] удалено: {line.strip()[:160]}')
            if len(suspicious) > 5:
                self._log_line(f'[hosts] удалено ещё: {len(suspicious) - 5}')
            detail = f'удалено записей: {len(suspicious)}'
        else:
            content = _DEFAULT_HOSTS.format(date=datetime.now().strftime('%Y-%m-%d'))
            detail = 'файл создан заново'
        try:
            self._make_writable(path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode('utf-8', errors='surrogateescape'))
        except OSError as exc:
            return Outcome(action, 'failed', str(exc))
        return Outcome(action, 'done', detail)

    def _backup_hosts(self, source: Path) -> None:
        target = (self.backup_dir / 'files' / 'hosts'
                  / f'hosts_{datetime.now():%Y%m%d_%H%M%S}.txt')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        self._manifest.append({
            'kind': 'hosts',
            'original': str(source),
            'stored': str(target.relative_to(self.backup_dir)),
        })

    @staticmethod
    def _make_writable(path: Path) -> None:
        try:
            if path.exists():
                path.chmod(path.stat().st_mode | 0o200)
        except OSError:
            pass

    def _do_empty_temp(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'очистить Temp')
        removed = 0
        for pattern in _TEMP_DIRS:
            folder = os.path.expandvars(pattern)
            if not os.path.isdir(folder):
                continue
            for entry in os.scandir(folder):
                try:
                    if entry.is_dir(follow_symlinks=False):
                        shutil.rmtree(entry.path, ignore_errors=True)
                    else:
                        os.unlink(entry.path)
                    removed += 1
                except OSError:
                    continue
        return Outcome(action, 'done', f'удалено объектов: {removed}')

    def _do_browser_cache(self, action: act.Action) -> Outcome:
        from . import browsers

        if self.dry_run:
            return Outcome(action, 'planned', 'очистить кэш и куки браузеров')
        removed = browsers.clear_cache_and_cookies()
        return Outcome(action, 'done', f'очищено кэша/куки: {removed}')

    def _do_export_key(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'экспорт ветки')
        target = self.backup_dir / 'reg_export' / f'{registry.safe_name(action.path)}.reg'
        ok, message = registry.export_key(action.path, str(target))
        return Outcome(action, 'done' if ok else 'failed', message)

    def _do_restore_point(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'skipped', 'точка восстановления не создаётся в dry-run')
        return Outcome(action, 'skipped', self._restore_message or 'точка восстановления создана')

    def _do_reboot(self, action: act.Action) -> Outcome:
        if self.dry_run:
            return Outcome(action, 'planned', 'требуется перезагрузка')
        if not self.allow_reboot:
            return Outcome(action, 'skipped', 'перезагрузка не запрошена')
        return Outcome(action, 'done', 'перезагрузка запланирована')

    # --- бэкапы ------------------------------------------------------------
    def _backup_task(self, name: str) -> bool:
        """Сохранить XML задачи перед удалением (для отката)."""
        try:
            completed = _run(['schtasks', '/Query', '/TN', '\\' + name, '/XML'],
                             timeout=60)
        except (OSError, subprocess.SubprocessError):
            return False
        if completed.returncode != 0 or not completed.stdout:
            return False
        digest = hashlib.sha1(name.encode('utf-8')).hexdigest()[:8]
        filename = f'{registry.safe_name(name)[:80]}_{digest}.xml'
        target = self.backup_dir / 'tasks' / filename
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(completed.stdout)
        except OSError:
            return False
        self._manifest.append({
            'kind': 'task',
            'original': '\\' + name,
            'stored': str(target.relative_to(self.backup_dir)),
        })
        return True

    def _backup_registry(self, notation: str) -> None:
        target = self.backup_dir / 'reg' / f'{registry.safe_name(notation)}.reg'
        ok, _message = registry.export_key(notation, str(target))
        if ok:
            self._manifest.append({
                'kind': 'reg',
                'original': notation,
                'stored': str(target.relative_to(self.backup_dir)),
            })

    def _backup_registry_value(self, notation: str) -> None:
        hive_name, subkey = registry.split_notation(notation)
        parent = f'{hive_name}\\{subkey}'
        self._backup_registry(parent)

    def _backup_edit(self, source: Path) -> None:
        """Сохранить копию файла, который будет изменён (для отката)."""
        if source in self._edited_files:
            return
        target = self.backup_dir / 'files' / self._backup_relative(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        self._edited_files.add(source)
        self._manifest.append({
            'kind': 'file_edit',
            'original': str(source),
            'stored': str(target.relative_to(self.backup_dir)),
        })

    @staticmethod
    def _backup_relative(source: Path) -> Path:
        try:
            return Path(source.drive.rstrip(':\\')) / source.relative_to(source.anchor)
        except ValueError:
            return Path(source.name)

    def _delete_path(self, action: act.Action, path: str) -> Outcome:
        expanded = os.path.expandvars(path)
        source = Path(expanded)
        if not source.exists():
            return Outcome(action, 'not_found', expanded)
        if self.dry_run:
            kind = 'папка' if source.is_dir() else 'файл'
            return Outcome(action, 'planned', f'удалить {kind}')
        if self._quarantine(source):
            return Outcome(action, 'done', f'{expanded} (в карантин)')
        try:
            if source.is_dir() and not source.is_symlink():
                shutil.rmtree(source)
            else:
                source.unlink()
        except OSError as exc:
            if not source.is_dir() and _schedule_delete(str(source)):
                self._pending_reboot = True
                return Outcome(action, 'done',
                               f'{expanded} — будет удалён после перезагрузки')
            return Outcome(action, 'failed', str(exc))
        return Outcome(action, 'done', expanded)

    def _quarantine(self, source: Path) -> bool:
        """Перенести объект в папку бэкапа; True — источник уже перемещён."""
        target = self.backup_dir / 'files' / self._backup_relative(source)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(target))
            self._manifest.append({
                'kind': 'file',
                'original': str(source),
                'stored': str(target.relative_to(self.backup_dir)),
            })
            return True
        except (OSError, shutil.Error):
            return False

    # --- служебное ---------------------------------------------------------
    def _close_processes(self, actions: List[act.Action]) -> None:
        """Закрыть процессы, чьи файлы выбраны к удалению (директива CloseProcesses)."""
        if self.dry_run:
            return
        targets = [os.path.normcase(os.path.abspath(os.path.expandvars(action.path)))
                   for action in actions
                   if action.kind in (act.FILE, act.SHORTCUT, act.ADS) and action.path]
        if not targets:
            return
        closed: List[str] = []
        current_pid = os.getpid()
        for process in winapi.list_processes():
            if process.pid <= 4 or process.pid == current_pid:
                continue
            image = winapi.process_image_path(process.pid)
            if not image:
                continue
            image_path = os.path.normcase(os.path.abspath(image))
            if not any(image_path == target or image_path.startswith(target + os.sep)
                       for target in targets):
                continue
            if winapi.terminate_process(process.pid):
                closed.append(process.name or image)
        if closed:
            self._log_line(f'[close] закрыто процессов: {len(closed)} — '
                           f'{", ".join(closed[:10])}')

    def _startup_folders(self) -> List[str]:
        folders = [os.path.join(os.environ.get('ProgramData', r'C:\ProgramData'),
                                r'Microsoft\Windows\Start Menu\Programs\Startup')]
        base = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        hive = winreg.HKEY_LOCAL_MACHINE
        for sid in registry.enum_subkeys(hive, base):
            profile = registry.read_value(hive, f'{base}\\{sid}', 'ProfileImagePath')
            if isinstance(profile, str) and profile:
                folders.append(os.path.join(
                    os.path.expandvars(profile),
                    r'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
        return folders

    def _create_restore_point(self) -> str:
        script = ("Checkpoint-Computer -Description 'RUSecurity' "
                  "-RestorePointType 'MODIFY_SETTINGS'")
        try:
            completed = _run(['powershell', '-NoProfile', '-NonInteractive',
                              '-Command', script], timeout=180)
        except (OSError, subprocess.SubprocessError) as exc:
            self._restore_message = f'точка восстановления не создана: {exc}'
            return self._restore_message
        if completed.returncode != 0:
            self._restore_message = ('точка восстановления не создана '
                                     '(восстановление системы выключено?)')
            return self._restore_message
        self._restore_point_done = True
        self._restore_message = 'точка восстановления создана'
        return self._restore_message

    def _log(self, outcome: Outcome) -> None:
        text = f'[{outcome.status}] {outcome.action.raw}'
        if outcome.detail:
            text += f' — {outcome.detail}'
        self._log_line(text)

    def _log_line(self, text: str) -> None:
        self._log_lines.append(f'[{datetime.now():%H:%M:%S}] {text}')

    def _write_manifest(self) -> None:
        if not self._manifest or self.dry_run:
            return
        payload = {
            'created': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'items': [dict(item, id=index + 1)
                      for index, item in enumerate(self._manifest)],
        }
        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            (self.backup_dir / 'manifest.json').write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding='utf-8')
        except OSError:
            pass

    def _write_log(self, report: FixReport) -> Path:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        header = [
            f'RUSecurity — журнал исправления {datetime.now():%Y-%m-%d %H:%M:%S}',
            f'Бэкапы: {self.backup_dir}',
            f'Точка восстановления: {report.restore_point or "нет"}',
            '',
        ]
        summary = [
            '',
            f'Итог: изменено {report.changed}, ошибок {report.failed}, '
            f'вручную {report.manual}',
        ]
        if report.reboot_required:
            summary.append('Требуется перезагрузка.')
        self.log_path.write_text('\n'.join(header + self._log_lines + summary) + '\n',
                                 encoding='utf-8', newline='\r\n')
        return self.log_path
