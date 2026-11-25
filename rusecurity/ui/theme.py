"""Тёмная тема и оформление интерфейса."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import (QColor, QFont, QPainter, QPainterPath, QPalette,
                           QPen, QPixmap)
from PySide6.QtWidgets import QApplication

from ..config import APP_DIR

_CHECK_ICON = '__CHECK_ICON__'


def _check_icon_path() -> str:
    """Нарисовать галочку один раз и вернуть путь для QSS."""
    folder = APP_DIR / '.ui'
    path = folder / 'check.png'
    if path.is_file():
        return path.as_posix()
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        return ''
    pixmap = QPixmap(18, 18)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor('#04101F'))
    pen.setWidthF(2.4)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    painter.setPen(pen)
    check = QPainterPath()
    check.moveTo(4.0, 9.3)
    check.lineTo(7.4, 12.7)
    check.lineTo(14.2, 5.4)
    painter.drawPath(check)
    painter.end()
    try:
        pixmap.save(str(path))
        return path.as_posix()
    except RuntimeError:
        return ''

ACCENT = '#4C8DFF'
ACCENT_HOVER = '#6BA0FF'
OK = '#22C55E'
WARN = '#F59E0B'
MUTED = '#8A93A6'
BG = '#0E1116'
CARD = '#161A22'
CARD_ALT = '#1C212B'
BORDER = '#252B38'
TEXT = '#E6EAF2'

STYLE = f"""
QWidget {{
    color: {TEXT};
    font-family: 'Segoe UI', 'Inter', sans-serif;
    font-size: 14px;
}}
QMainWindow, QDialog {{ background: {BG}; }}
QStackedWidget {{ background: transparent; }}
QFrame#Card {{
    background: {CARD};
    border: 1px solid {BORDER};
    border-radius: 14px;
}}
QLabel#PageTitle {{ font-size: 26px; font-weight: 600; }}
QLabel#PageSubtitle {{ color: {MUTED}; font-size: 14px; }}
QLabel#SectionTitle {{ font-size: 16px; font-weight: 600; }}
QLabel#Muted {{ color: {MUTED}; }}
QLabel#Metric {{ font-size: 30px; font-weight: 700; color: {ACCENT}; }}
QLabel#MetricCaption {{ color: {MUTED}; font-size: 12px; }}
QLabel#Path {{ color: {MUTED}; font-family: 'Cascadia Mono', 'Consolas', monospace;
              font-size: 12px; }}
QLabel#GroupCaption {{ color: {MUTED}; font-size: 12px; font-weight: 600; }}

QFrame#Sidebar {{
    background: #0B0E12;
    border-right: 1px solid {BORDER};
}}
QLabel#Logo {{ font-size: 19px; font-weight: 700; color: {TEXT}; }}
QLabel#LogoSub {{ color: {MUTED}; font-size: 11px; }}

QPushButton#Nav {{
    background: transparent;
    border: none;
    border-radius: 10px;
    padding: 11px 14px;
    text-align: left;
    color: {MUTED};
    font-size: 14px;
}}
QPushButton#Nav:hover {{ background: {CARD}; color: {TEXT}; }}
QPushButton#Nav:checked {{ background: {CARD_ALT}; color: {TEXT}; font-weight: 600; }}

QPushButton#Primary {{
    background: {ACCENT};
    border: none;
    border-radius: 10px;
    padding: 11px 22px;
    color: #04101F;
    font-weight: 600;
}}
QPushButton#Primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#Primary:disabled {{ background: {BORDER}; color: {MUTED}; }}

QPushButton#Secondary {{
    background: transparent;
    border: 1px solid {BORDER};
    border-radius: 10px;
    padding: 10px 18px;
    color: {TEXT};
}}
QPushButton#Secondary:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
QPushButton#Secondary:disabled {{ color: {MUTED}; border-color: {BORDER}; }}

QPushButton#Donate {{
    background: transparent;
    border: 1px solid #2A3550;
    border-radius: 10px;
    padding: 8px 12px;
    color: #8FA6D8;
    font-size: 12px;
}}
QPushButton#Donate:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}

QPushButton#Lang {{
    background: transparent;
    border: 1px solid #2A3550;
    border-radius: 8px;
    padding: 5px 0;
    color: #8FA6D8;
    font-size: 12px;
    font-weight: 600;
}}
QPushButton#Lang:hover {{ border-color: {ACCENT}; color: {ACCENT}; }}
QPushButton#Lang:checked {{
    background: {CARD_ALT};
    border-color: {ACCENT};
    color: {TEXT};
}}

QPushButton#Danger {{
    background: #E5484D;
    border: none;
    border-radius: 10px;
    padding: 11px 22px;
    color: #1A0507;
    font-weight: 600;
}}
QPushButton#Danger:hover {{ background: #F2686C; }}
QPushButton#Danger:disabled {{ background: {BORDER}; color: {MUTED}; }}

QCheckBox {{ spacing: 9px; color: {TEXT}; }}
QCheckBox::indicator {{
    width: 18px; height: 18px; border-radius: 5px;
    border: 1px solid {BORDER}; background: {CARD_ALT};
}}
QCheckBox::indicator:hover {{ border-color: {ACCENT}; }}
QCheckBox::indicator:checked {{
    background: {ACCENT}; border-color: {ACCENT};
    image: url({_CHECK_ICON});
}}
QCheckBox#Deep {{ color: #FFFFFF; font-weight: 600; }}
QCheckBox#Deep::indicator {{ border-color: #E5484D; }}
QCheckBox#Deep::indicator:hover {{ border-color: #F87171; }}
QCheckBox#Deep::indicator:checked {{
    background: #E5484D; border-color: #E5484D;
    image: url({_CHECK_ICON});
}}
QTableView::indicator {{
    width: 16px; height: 16px; border-radius: 4px;
    border: 1px solid {BORDER}; background: {CARD_ALT};
}}
QTableView::indicator:checked {{
    background: {ACCENT}; border-color: {ACCENT};
    image: url({_CHECK_ICON});
}}

QProgressBar {{
    background: {CARD_ALT};
    border: none;
    border-radius: 6px;
    height: 8px;
    text-align: center;
    color: transparent;
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 6px; }}

QTableWidget {{
    background: {CARD};
    alternate-background-color: {CARD_ALT};
    border: 1px solid {BORDER};
    border-radius: 12px;
    gridline-color: transparent;
    selection-background-color: #23324A;
    selection-color: {TEXT};
}}
QHeaderView::section {{
    background: {CARD_ALT};
    color: {MUTED};
    border: none;
    padding: 9px 12px;
    font-size: 12px;
    font-weight: 600;
}}
QTableWidget::item {{ padding: 8px 12px; border: none; }}
QTableWidget#Results {{ font-size: 13px; }}
QTableWidget#Results::item {{ padding: 2px 8px; border: none; }}

QPlainTextEdit, QTextEdit {{
    background: #0B0E12;
    border: 1px solid {BORDER};
    border-radius: 12px;
    padding: 12px;
    font-family: 'Cascadia Mono', 'Consolas', monospace;
    font-size: 12px;
    selection-background-color: #23324A;
}}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 4px; }}
QScrollBar::handle:vertical {{ background: {BORDER}; border-radius: 5px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 4px; }}
QScrollBar::handle:horizontal {{ background: {BORDER}; border-radius: 5px; min-width: 30px; }}

QSplitter::handle {{ background: transparent; }}
QToolTip {{ background: {CARD_ALT}; color: {TEXT}; border: 1px solid {BORDER}; padding: 6px; }}
"""


def apply(app: QApplication) -> None:
    app.setStyle('Fusion')
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(BG))
    palette.setColor(QPalette.ColorRole.Base, QColor(CARD))
    palette.setColor(QPalette.ColorRole.Text, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.WindowText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Button, QColor(CARD))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor(TEXT))
    palette.setColor(QPalette.ColorRole.Highlight, QColor(ACCENT))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor('#04101F'))
    app.setPalette(palette)
    app.setStyleSheet(STYLE.replace(_CHECK_ICON, _check_icon_path()))
    app.setFont(QFont('Segoe UI', 10))
