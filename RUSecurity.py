"""Точка входа для сборки RUSecurity.exe (PyInstaller)."""

import sys
import traceback
from pathlib import Path


def _base_dir() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _ensure_streams() -> None:
    """В windowed-сборке stdout/stderr = None: пишем их в файл рядом с exe."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    log_path = _base_dir() / 'RUSecurity-output.log'
    try:
        stream = open(log_path, 'a', encoding='utf-8', buffering=1)
    except OSError:
        return
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream


def main() -> int:
    _ensure_streams()
    from rusecurity.cli import main as cli_main
    return cli_main()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception:  # noqa: BLE001
        log_path = _base_dir() / 'RUSecurity-error.log'
        try:
            log_path.write_text(traceback.format_exc(), encoding='utf-8')
        except OSError:
            pass
        if len(sys.argv) == 1:
            try:
                from PySide6.QtWidgets import QApplication, QMessageBox
                app = QApplication.instance() or QApplication([])
                QMessageBox.critical(None, 'RUSecurity',
                                     f'Не удалось запустить программу.\n'
                                     f'Подробности: {log_path}')
            except Exception:  # noqa: BLE001
                pass
        sys.exit(1)
