"""Точка входа графического интерфейса."""

from __future__ import annotations

import sys

from .. import i18n
from ..runtime import ensure_gui_runtime

ensure_gui_runtime()

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from . import theme  # noqa: E402
from .main_window import MainWindow  # noqa: E402


def make_icon() -> QIcon:
    pixmap = QPixmap(128, 128)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    painter.setBrush(QColor(theme.ACCENT))
    painter.setPen(Qt.PenStyle.NoPen)
    painter.drawRoundedRect(6, 6, 116, 116, 30, 30)
    painter.setPen(QColor('#04101F'))
    painter.setFont(QFont('Segoe UI', 62, QFont.Weight.Bold))
    painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, 'R')
    painter.end()
    return QIcon(pixmap)


def run() -> int:
    app = QApplication.instance() or QApplication(sys.argv[:1])
    app.setApplicationName('RUSecurity')
    app.setApplicationDisplayName('RUSecurity')
    app.setWindowIcon(make_icon())
    theme.apply(app)
    i18n.load()
    window = MainWindow()
    if i18n.current() != 'ru':
        i18n.translate_widgets(window)
    window.show()
    return app.exec()
