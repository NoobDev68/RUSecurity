"""Портативные пути и настройки RUSecurity.

Всё хранится рядом с программой: настройки — rusecurity.json, отчёты — Reports/.
Никаких записей в реестр и AppData.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict

if getattr(sys, 'frozen', False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = APP_DIR / 'rusecurity.json'
REPORTS_DIR = APP_DIR / 'Reports'

DONATE_URL = "https://boosty.to/threer/donate"

_DEFAULTS: Dict[str, str] = {
    'reports_dir': str(REPORTS_DIR),
}


def load() -> Dict[str, str]:
    config = dict(_DEFAULTS)
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return config
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, str):
                config[key] = value
    return config


def save(config: Dict[str, str]) -> None:
    CONFIG_PATH.write_text(json.dumps(config, ensure_ascii=False, indent=2),
                           encoding='utf-8')


def reports_dir(config: Dict[str, str]) -> Path:
    path = Path(config.get('reports_dir') or REPORTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path


def resource_path(*parts: str) -> Path:
    """Путь к встроенному ресурсу: в onefile-сборке — из временного каталога."""
    base = Path(getattr(sys, '_MEIPASS', APP_DIR))
    return base.joinpath(*parts)
