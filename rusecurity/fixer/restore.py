"""Карантин: чтение манифестов и восстановление файлов/веток реестра."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple


@dataclass
class QuarantineEntry:
    manifest: Path
    backup: Path
    item_id: int
    kind: str
    original: str
    stored: Path

    @property
    def created(self) -> str:
        try:
            data = json.loads(self.manifest.read_text(encoding='utf-8'))
            return str(data.get('created') or '')
        except (OSError, ValueError):
            return ''


def load_entries(reports_dir: Path) -> List[QuarantineEntry]:
    """Все записи карантина из Reports/Backups/*/manifest.json."""
    entries: List[QuarantineEntry] = []
    for manifest in sorted(Path(reports_dir).glob('Backups/*/manifest.json'), reverse=True):
        try:
            data = json.loads(manifest.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        backup = manifest.parent
        for item in data.get('items', []):
            if not isinstance(item, dict):
                continue
            try:
                entries.append(QuarantineEntry(
                    manifest=manifest,
                    backup=backup,
                    item_id=int(item.get('id', 0)),
                    kind=str(item.get('kind', 'file')),
                    original=str(item.get('original', '')),
                    stored=backup / str(item.get('stored', '')),
                ))
            except (TypeError, ValueError):
                continue
    return entries


@dataclass
class FixRun:
    """Одно исправление: каталог бэкапа с манифестом и набором объектов."""

    manifest: Path
    created: str
    kinds: Dict[str, int]

    @property
    def backup(self) -> Path:
        return self.manifest.parent

    @property
    def total(self) -> int:
        return sum(self.kinds.values())


def load_runs(reports_dir: Path) -> List[FixRun]:
    """Исправления, для которых сохранились бэкапы; новые сверху."""
    runs: List[FixRun] = []
    for manifest in Path(reports_dir).glob('Backups/*/manifest.json'):
        try:
            data = json.loads(manifest.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            continue
        kinds: Dict[str, int] = {}
        for item in data.get('items', []):
            if not isinstance(item, dict):
                continue
            kind = str(item.get('kind', 'file'))
            kinds[kind] = kinds.get(kind, 0) + 1
        if not kinds:
            continue
        created = str(data.get('created') or manifest.parent.name)
        runs.append(FixRun(manifest=manifest, created=created, kinds=kinds))
    runs.sort(key=lambda run: run.manifest.parent.name, reverse=True)
    return runs


def run_entries(run: FixRun) -> List[QuarantineEntry]:
    """Все записи одного исправления — для полного отката."""
    return resolve_entries(run.manifest, [])


def _restore_new_value(entry: QuarantineEntry) -> str:
    """Убрать значение, которое фиксер добавил или перезаписал при исправлении."""
    hive_name, _, rest = entry.original.partition('\\')
    subkey, _, name = rest.rpartition('\\')
    if not subkey or not name:
        return 'failed: не разобрать путь'
    from . import registry
    status = registry.delete_value(f'{hive_name}\\{subkey}', name)
    return 'done' if status in ('done', 'not_found') else status


def _restore_registry(entry: QuarantineEntry) -> str:
    if not entry.stored.is_file():
        return 'missing'
    try:
        completed = subprocess.run(['reg', 'import', str(entry.stored)],
                                   capture_output=True, timeout=120,
                                   creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError) as exc:
        return f'failed: {exc}'
    if completed.returncode != 0:
        text = completed.stderr.decode('cp866', errors='replace').strip()
        return f'failed: {text or "reg import"}'
    return 'done'


def _restore_file(entry: QuarantineEntry) -> str:
    if not entry.stored.exists():
        return 'missing'
    target = Path(entry.original)
    if target.exists():
        # Не затираем то, что появилось после исправления: убираем в бэкап.
        displaced = entry.backup / 'replaced' / entry.stored.name
        try:
            displaced.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(displaced))
        except (OSError, shutil.Error) as exc:
            return f'failed: путь занят, не удалось убрать текущий файл ({exc})'
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(entry.stored), str(target))
        return 'done'
    except (OSError, shutil.Error) as exc:
        return f'failed: {exc}'


def _restore_edited_file(entry: QuarantineEntry) -> str:
    """Вернуть сохранённую копию поверх изменённого файла."""
    if not entry.stored.is_file():
        return 'missing'
    target = Path(entry.original)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(entry.stored, target)
        return 'done'
    except (OSError, shutil.Error) as exc:
        return f'failed: {exc}'


def _restore_hosts(entry: QuarantineEntry) -> str:
    if not entry.stored.is_file():
        return 'missing'
    target = Path(entry.original)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            target.chmod(target.stat().st_mode | 0o200)
        shutil.copy2(entry.stored, target)
        return 'done'
    except (OSError, shutil.Error) as exc:
        return f'failed: {exc}'


def _restore_task(entry: QuarantineEntry) -> str:
    if not entry.stored.is_file():
        return 'missing'
    try:
        completed = subprocess.run(
            ['schtasks', '/Create', '/TN', entry.original,
             '/XML', str(entry.stored), '/F'],
            capture_output=True, timeout=120, creationflags=0x08000000)
    except (OSError, subprocess.SubprocessError) as exc:
        return f'failed: {exc}'
    if completed.returncode != 0:
        text = completed.stderr.decode('cp866', errors='replace').strip()
        return f'failed: {text or "schtasks /Create"}'
    return 'done'


def restore_entry(entry: QuarantineEntry) -> Tuple[QuarantineEntry, str]:
    if entry.kind == 'reg_new':
        status = _restore_new_value(entry)
    elif entry.kind == 'reg':
        status = _restore_registry(entry)
    elif entry.kind == 'hosts':
        status = _restore_hosts(entry)
    elif entry.kind == 'task':
        status = _restore_task(entry)
    elif entry.kind == 'file_edit':
        status = _restore_edited_file(entry)
    else:
        status = _restore_file(entry)
    return entry, status


def restore_many(entries: List[QuarantineEntry], log_path: Path) -> List[Tuple[QuarantineEntry, str]]:
    results = [restore_entry(entry) for entry in entries]
    lines = [f'RUSecurity — восстановление {datetime.now():%Y-%m-%d %H:%M:%S}', '']
    for entry, status in results:
        lines.append(f'[{status}] {entry.kind}: {entry.original}')
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text('\n'.join(lines) + '\n', encoding='utf-8', newline='\r\n')
    return results


def _prune_manifest(manifest: Path, removed_ids: Set[int]) -> None:
    try:
        data = json.loads(manifest.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return
    items = []
    for item in data.get('items', []):
        if not isinstance(item, dict):
            continue
        try:
            item_id = int(item.get('id', 0))
        except (TypeError, ValueError):
            item_id = 0
        if item_id not in removed_ids:
            items.append(item)
    if items:
        data['items'] = items
        try:
            manifest.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                                encoding='utf-8')
        except OSError:
            pass
        return
    try:
        manifest.unlink()
    except OSError:
        pass
    _remove_empty_tree(manifest.parent)


def _remove_empty_tree(backup: Path) -> None:
    for path in sorted(backup.rglob('*'), key=lambda item: len(item.parts),
                       reverse=True):
        if path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass
    try:
        backup.rmdir()
    except OSError:
        return
    parent = backup.parent
    if parent.name.lower() == 'backups':
        try:
            parent.rmdir()
        except OSError:
            pass


def delete_entries(entries: List[QuarantineEntry]) -> List[Tuple[QuarantineEntry, str]]:
    """Удалить объекты карантина навсегда (без восстановления)."""
    results: List[Tuple[QuarantineEntry, str]] = []
    for manifest, group in entries_by_manifest(entries).items():
        removed: Set[int] = set()
        for entry in group:
            status = 'done'
            if entry.stored == entry.backup:
                # У записи вида reg_new нет своего файла — только строка манифеста.
                removed.add(entry.item_id)
                results.append((entry, status))
                continue
            try:
                if entry.stored.is_dir():
                    shutil.rmtree(entry.stored)
                elif entry.stored.exists():
                    entry.stored.unlink()
            except OSError as exc:
                status = f'failed: {exc}'
            if not status.startswith('failed'):
                removed.add(entry.item_id)
            results.append((entry, status))
        if removed:
            _prune_manifest(manifest, removed)
    return results


def clear_quarantine(reports_dir: Path) -> Tuple[int, int]:
    """Очистить карантин полностью. Возвращает (удалено записей, ошибок)."""
    entries = load_entries(reports_dir)
    results = delete_entries(entries)
    failed = sum(1 for _entry, status in results if status.startswith('failed'))
    deleted = len(results) - failed
    backups = Path(reports_dir) / 'Backups'
    if backups.is_dir():
        for child in list(backups.iterdir()):
            try:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
            except OSError:
                failed += 1
        try:
            backups.rmdir()
        except OSError:
            pass
    return deleted, failed


def entries_by_manifest(entries: List[QuarantineEntry]) -> dict:
    grouped: dict = {}
    for entry in entries:
        grouped.setdefault(entry.manifest, []).append(entry)
    return grouped


def resolve_entries(target: Path, ids: List[int]) -> List[QuarantineEntry]:
    """Найти записи по каталогу бэкапа или файлу манифеста."""
    target = Path(target)
    manifest = target if target.name == 'manifest.json' else target / 'manifest.json'
    reports_dir = manifest.parent.parent.parent
    entries = [entry for entry in load_entries(reports_dir)
               if entry.manifest == manifest]
    if ids:
        wanted = set(ids)
        entries = [entry for entry in entries if entry.item_id in wanted]
    return entries
