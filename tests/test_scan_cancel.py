"""Тест отмены сканирования через контекст."""

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.core.context import ScanCancelled, ScanContext  # noqa: E402
from rusecurity.core import scanner  # noqa: E402


def test_step_raises_when_cancel_requested():
    ctx = ScanContext(cancel=lambda: True)
    with pytest.raises(ScanCancelled):
        ctx.step('Процессы')


def test_step_without_cancel_calls_progress():
    seen = []
    ctx = ScanContext(progress=seen.append, cancel=lambda: False)
    ctx.step('Процессы')
    assert seen == ['Процессы']


def test_scan_accepts_cancel_callback():
    parameters = scanner.scan.__code__.co_varnames[:scanner.scan.__code__.co_argcount]
    assert 'cancel' in parameters
