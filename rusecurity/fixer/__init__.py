"""Свой фиксер: разбор списка исправлений, бэкапы и выполнение."""

from .actions import Action, parse_fixlist  # noqa: F401
from .execute import FixReport, Fixer, Outcome, schedule_reboot  # noqa: F401
