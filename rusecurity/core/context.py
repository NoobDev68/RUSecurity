"""Контекст сканирования: пользователи, прогресс, кэши."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import winapi


class ScanCancelled(Exception):
    """Сканирование остановлено пользователем."""


@dataclass
class ScanContext:
    sids: List[str] = field(default_factory=list)
    profiles: Dict[str, str] = field(default_factory=dict)
    progress: Optional[Callable[[str], None]] = None
    options: Dict[str, bool] = field(default_factory=dict)
    cancel: Optional[Callable[[], bool]] = None

    @classmethod
    def detect(cls, progress: Optional[Callable[[str], None]] = None,
               cancel: Optional[Callable[[], bool]] = None) -> 'ScanContext':
        sids = winapi.loaded_user_sids()
        profiles = {sid: winapi.profile_path(sid) for sid in sids}
        return cls(sids=sids, profiles=profiles, progress=progress, cancel=cancel)

    def check_cancel(self) -> None:
        if self.cancel and self.cancel():
            raise ScanCancelled()

    def step(self, message: str) -> None:
        self.check_cancel()
        if self.progress:
            self.progress(message)

    def users(self) -> List[str]:
        return [sid for sid in self.sids if not sid.endswith('_Classes')]

    def user_startup(self, sid: str) -> str:
        profile = self.profiles.get(sid) or ''
        return f'{profile}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup'
