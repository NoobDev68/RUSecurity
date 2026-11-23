"""Командная строка RUSecurity."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import __version__, config, names
from .core import scanner
from .fixer.actions import KIND_LABELS



def _scan(args: argparse.Namespace) -> int:
    settings = config.load()
    output = Path(args.output) if args.output else config.reports_dir(settings)
    print(f'Сканирование в {output} ...', flush=True)
    result = scanner.scan(output, include_addition=not args.no_addition,
                          progress=lambda message: print(f'  {message}', flush=True),
                          history=not args.no_history)
    print(f'Готово: {result.report}')
    if result.addition:
        print(f'       {result.addition}')
    print(f'Записей в отчёте: {result.entries}')
    if result.history_available:
        print(f'С прошлого скана: новых {len(result.new_entries)}, '
              f'исчезло {len(result.gone_entries)}')
        if args.delta:
            for line in result.new_entries[:30]:
                print(f'  + {line[:160]}')
            for line in result.gone_entries[:30]:
                print(f'  - {line[:160]}')
    if args.summary:
        Path(args.summary).write_text(json.dumps({
            'report': str(result.report),
            'addition': str(result.addition) if result.addition else None,
            'entries': result.entries,
        }, ensure_ascii=False), encoding='utf-8')
    return 0


def _analyze(args: argparse.Namespace) -> int:
    from . import analyzer
    report = Path(args.report)
    addition = Path(args.addition) if args.addition else analyzer.resolve_addition(report)
    result = analyzer.analyze(report, addition)
    if not result.text:
        print('Подозрительных записей не найдено — fixlist не нужен.', file=sys.stderr)
        return 0
    if args.output:
        analyzer.save_fixlist(result.text, Path(args.output))
        print(f'fixlist сохранён: {args.output}', file=sys.stderr)
    else:
        sys.stdout.write(result.text)
    print(f'Записей на исправление: {result.fix_count}', file=sys.stderr)
    return 0


def _hardening(args: argparse.Namespace) -> int:
    from .core import hardening

    issues = hardening.evaluate()
    if not issues:
        print('Отклонений от рекомендуемых значений безопасности не найдено.')
        return 0
    total = hardening.counts(issues)
    print(f'Найдено отклонений: {len(issues)} (высокая {total[hardening.ISSUE_HIGH]}, '
          f'средняя {total[hardening.ISSUE_MEDIUM]}, '
          f'низкая {total[hardening.ISSUE_LOW]})')
    for section in hardening.SECTIONS:
        group = [item for item in issues if item.section == section]
        if not group:
            continue
        print(f'\n{section}:')
        for issue in group:
            mark = '' if issue.fix_line else '  [вручную]'
            print(f'  [{issue.severity_label}] {issue.title}: {issue.current} '
                  f'(нужно: {issue.expected}){mark}')
            if args.verbose and issue.note:
                print(f'      {issue.note}')

    selected = hardening.fixable(issues)
    if not (args.fix or args.dry_run):
        print(f'\nАвтоматически исправляется {len(selected)} из {len(issues)}. '
              f'Запустите с --fix (или --dry-run для плана).')
        return 0
    if not selected:
        print('\nАвтоматически исправлять нечего.')
        return 0

    target = config.reports_dir(config.load()) / names.FIXLIST
    target.write_text(hardening.compose_fixlist(selected), encoding='utf-8',
                      newline='')
    print(f'\nfixlist проверки безопасности: {target}')
    apply_args = argparse.Namespace(fixlist=str(target), dry_run=args.dry_run,
                                    yes=args.yes, reboot=False, log=args.log,
                                    backup_dir=args.backup_dir, hosts=None,
                                    no_restore_point=args.no_restore_point)
    return _apply(apply_args)


def _gui(args: argparse.Namespace) -> int:
    try:
        from .ui.app import run
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return run()


def _apply(args: argparse.Namespace) -> int:
    from .fixer import Fixer, parse_fixlist
    from .fixer import elevate

    fixlist = Path(args.fixlist)
    if not fixlist.is_file():
        print(f'fixlist не найден: {fixlist}', file=sys.stderr)
        return 1
    text = fixlist.read_text(encoding='utf-8-sig', errors='replace')
    actions = parse_fixlist(text)
    if not actions:
        print('В fixlist нет действий.', file=sys.stderr)
        return 0

    _print_plan(actions, fixlist)
    if args.dry_run:
        report = Fixer(Path('.'), Path('.'), dry_run=True, hosts_path=args.hosts).run(text)
        _print_outcomes(report)
        return 0

    if not args.yes and not _confirm():
        print('Отменено.', file=sys.stderr)
        return 1

    log_path = Path(args.log) if args.log else fixlist.with_name(names.FIXLOG)
    backup = Path(args.backup_dir) if args.backup_dir else (
        fixlist.parent / names.BACKUPS / datetime.now().strftime('%Y%m%d_%H%M%S'))

    if not elevate.is_admin():
        print('Требуются права администратора — запрашиваю UAC...', file=sys.stderr)
        code = _apply_elevated(fixlist, log_path, backup, args.no_restore_point)
        return code

    report = Fixer(backup, log_path, allow_reboot=args.reboot,
                   hosts_path=Path(args.hosts) if args.hosts else None,
                   create_restore_point=not args.no_restore_point).run(text)
    _print_outcomes(report)
    print(f'\nЖурнал: {report.log_path}')
    print(f'Бэкапы: {report.backup_dir}')
    if report.reboot_required and not args.reboot:
        print('Нужна перезагрузка, чтобы завершить изменения (ключ --reboot).')
    return 1 if report.failed else 0


def _apply_elevated(fixlist: Path, log_path: Path, backup: Path,
                    no_restore_point: bool = False) -> int:
    from .fixer import elevate
    args = ['apply', str(fixlist), '--yes', '--log', str(log_path),
            '--backup-dir', str(backup)]
    if no_restore_point:
        args.append('--no-restore-point')
    ok, code, message = elevate.run_elevated(args)
    if not ok:
        print(message, file=sys.stderr)
        return 1
    if log_path.is_file():
        print(log_path.read_text(encoding='utf-8', errors='replace'))
    return 0 if code == 0 else 1


def _confirm() -> bool:
    try:
        answer = input('Применить исправления? Будут созданы бэкапы. [y/N]: ')
    except EOFError:
        return False
    return answer.strip().lower() in ('y', 'yes', 'д', 'да')


def _print_plan(actions: list, fixlist: Path) -> None:
    print(f'fixlist: {fixlist}')
    counts: dict = {}
    for action in actions:
        counts[action.kind] = counts.get(action.kind, 0) + 1
    for kind, count in sorted(counts.items(), key=lambda item: -item[1]):
        label = KIND_LABELS.get(kind, kind)
        if kind in ('noop', 'close_processes', 'restore_point'):
            continue
        print(f'  {label}: {count}')
    manual = [a for a in actions if a.kind == 'manual']
    for action in manual[:10]:
        print(f'  [вручную] {action.raw[:150]}')


def _print_outcomes(report) -> None:
    for outcome in report.outcomes:
        if outcome.status in ('skipped',):
            continue
        label = 'план' if outcome.status == 'planned' else outcome.status
        detail = f' — {outcome.detail}' if outcome.detail else ''
        print(f'  [{label}] {outcome.action.raw[:120]}{detail}')
    print(f'Итог: изменено {report.changed}, ошибок {report.failed}, '
          f'вручную {report.manual}')


def _restore(args: argparse.Namespace) -> int:
    from .fixer import elevate
    from .fixer import restore as quarantine

    backup = Path(args.backup)
    ids = [int(value) for value in (args.item or [])]
    entries = quarantine.resolve_entries(backup, ids)
    if not entries:
        print('В карантине нечего восстанавливать.', file=sys.stderr)
        return 0
    print(f'К восстановлению: {len(entries)}')
    for entry in entries:
        print(f'  #{entry.item_id} {entry.kind}: {entry.original}')
    if not args.yes:
        try:
            answer = input('Вернуть выбранное? [y/N]: ')
        except EOFError:
            answer = ''
        if answer.strip().lower() not in ('y', 'yes', 'д', 'да'):
            print('Отменено.', file=sys.stderr)
            return 1

    log_path = backup / 'restore-log.txt' if backup.is_dir() else \
        backup.with_name('restore-log.txt')
    if not elevate.is_admin():
        print('Требуются права администратора — запрашиваю UAC...', file=sys.stderr)
        child_args = ['restore', str(backup), '--yes']
        for item_id in ids:
            child_args += ['--item', str(item_id)]
        ok, code, message = elevate.run_elevated(child_args)
        if not ok:
            print(message, file=sys.stderr)
            return 1
        if log_path.is_file():
            print(log_path.read_text(encoding='utf-8', errors='replace'))
        return 0 if code == 0 else 1

    results = quarantine.restore_many(entries, log_path)
    failed = 0
    for entry, status in results:
        print(f'  [{status}] {entry.original}')
        if status.startswith('failed'):
            failed += 1
    print(f'Журнал: {log_path}')
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='rusecurity',
        description='RUSecurity — сканер системы, анализ и свой фиксер.')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command')

    scan = sub.add_parser('scan', help='просканировать систему и сохранить отчёты')
    scan.add_argument('-o', '--output', help='каталог для отчётов')
    scan.add_argument('--no-addition', action='store_true', help='не создавать дополнительный отчёт')
    scan.add_argument('--summary', help='записать итог сканирования в JSON')
    scan.add_argument('--delta', action='store_true',
                      help='показать новые и исчезнувшие записи')
    scan.add_argument('--no-history', action='store_true',
                      help='не сравнивать с прошлым сканом')
    scan.set_defaults(func=_scan)

    analyze = sub.add_parser('analyze', help='разобрать отчёты и создать список исправлений')
    analyze.add_argument('report', help='путь к отчёту RUSecurity')
    analyze.add_argument('addition', nargs='?', help='путь к дополнительному отчёту')
    analyze.add_argument('-o', '--output', help=f'куда сохранить {names.FIXLIST}')
    analyze.set_defaults(func=_analyze)

    apply = sub.add_parser('apply', help='выполнить список исправлений (нужны права админа)')
    apply.add_argument('fixlist', metavar='FILE', help='путь к файлу исправлений')
    apply.add_argument('--dry-run', action='store_true', help='только показать план')
    apply.add_argument('--yes', action='store_true', help='без подтверждения')
    apply.add_argument('--reboot', action='store_true', help='перезагрузить по завершении')
    apply.add_argument('--log', help='куда писать журнал')
    apply.add_argument('--backup-dir', help='куда складывать бэкапы')
    apply.add_argument('--hosts', help='путь к hosts (для тестов)')
    apply.add_argument('--no-restore-point', action='store_true',
                       help='не создавать точку восстановления')
    apply.set_defaults(func=_apply)

    restore = sub.add_parser('restore', help='вернуть файлы и ветки из карантина')
    restore.add_argument('backup', help='каталог бэкапа или manifest.json')
    restore.add_argument('--item', action='append', type=int,
                         help='номер записи (можно несколько)')
    restore.add_argument('--yes', action='store_true', help='без подтверждения')
    restore.set_defaults(func=_restore)

    hardening = sub.add_parser(
        'hardening', help='проверить настройки безопасности и исправить отклонения')
    hardening.add_argument('--fix', action='store_true', help='исправить найденное')
    hardening.add_argument('--dry-run', action='store_true',
                           help='только показать план исправления')
    hardening.add_argument('--yes', action='store_true', help='без подтверждения')
    hardening.add_argument('--verbose', action='store_true',
                          help='показывать пояснения к проверкам')
    hardening.add_argument('--log', help='куда писать журнал')
    hardening.add_argument('--backup-dir', help='куда складывать бэкапы')
    hardening.add_argument('--no-restore-point', action='store_true',
                           help='не создавать точку восстановления')
    hardening.set_defaults(func=_hardening)

    gui = sub.add_parser('gui', help='открыть графический интерфейс')
    gui.set_defaults(func=_gui)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, 'command', None):
        return _gui(args)
    return args.func(args)
