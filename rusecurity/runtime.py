"""Гарантия того, что PySide6 доступен из портативной папки .runtime."""

from __future__ import annotations

import importlib
import sys

from .config import APP_DIR


def ensure_gui_runtime() -> None:
    try:
        importlib.import_module('PySide6')
        return
    except ImportError:
        pass
    runtime = APP_DIR / '.runtime'
    if runtime.is_dir():
        sys.path.insert(0, str(runtime))
    try:
        importlib.import_module('PySide6')
    except ImportError as exc:
        raise RuntimeError(
            'Не найден PySide6. Положите папку .runtime с PySide6 рядом '
            'с программой (она нужна только для интерфейса).'
        ) from exc
