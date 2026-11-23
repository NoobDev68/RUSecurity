"""Главное окно RUSecurity."""

from __future__ import annotations

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QDesktopServices, QIcon, QPixmap
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QPushButton, QStackedWidget, QStatusBar, QVBoxLayout, QWidget,
)

from .. import __version__, config, i18n, names
from ..journal import Journal
from .hardening_page import HardeningPage
from .pages import LogPage, ScanPage
from .quarantine_page import QuarantinePage


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle('RUSecurity')
        self.resize(1180, 860)
        self.setMinimumSize(960, 660)
        icon_file = config.resource_path('assets', 'RUSecurity.ico')
        if icon_file.is_file():
            self.setWindowIcon(QIcon(str(icon_file)))

        central = QWidget()
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self._build_sidebar())

        self.pages = QStackedWidget()
        journal = Journal(config.reports_dir(config.load()) / names.JOURNAL)
        self.log_page = LogPage(journal)
        self.scan_page = ScanPage(self.append_log)
        self.hardening_page = HardeningPage(self.append_log)
        self.quarantine_page = QuarantinePage(self.append_log)
        self.pages.addWidget(self.scan_page)
        self.pages.addWidget(self.hardening_page)
        self.pages.addWidget(self.quarantine_page)
        self.pages.addWidget(self.log_page)
        layout.addWidget(self.pages, 1)
        self.setCentralWidget(central)

        status = QStatusBar()
        status.setSizeGripEnabled(False)
        status.setStyleSheet('QStatusBar { background: #0B0E12; color: #8A93A6; }')
        self.setStatusBar(status)
        rights = 'администратор' if self._is_admin() else 'пользователь'
        self.append_log(f'RUSecurity {__version__} запущен, права: {rights}')

    @staticmethod
    def _is_admin() -> bool:
        from ..fixer import elevate
        return elevate.is_admin()

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName('Sidebar')
        sidebar.setFixedWidth(238)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(18, 24, 18, 20)
        layout.setSpacing(6)

        logo = QLabel()
        logo.setObjectName('Logo')
        logo_file = config.resource_path('assets', 'rusecurity-logo.png')
        if logo_file.is_file():
            pixmap = QPixmap(str(logo_file))
            pixmap.setDevicePixelRatio(2.0)
            logo.setPixmap(pixmap)
        else:
            logo.setText('RUSecurity')
        layout.addWidget(logo)
        layout.addSpacing(26)

        self._nav_group = QButtonGroup(self)
        self._nav_group.setExclusive(True)
        for index, title in enumerate(('Сканирование', 'Проверка безопасности',
                                       'Карантин', 'Журнал')):
            button = QPushButton(title)
            button.setObjectName('Nav')
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            if index == 0:
                button.setChecked(True)
            self._nav_group.addButton(button, index)
            layout.addWidget(button)
        self._nav_group.idClicked.connect(self.pages_set_index)
        layout.addStretch(1)

        lang_row = QHBoxLayout()
        lang_row.setSpacing(6)
        self._lang_buttons = {}
        for code, label in (('ru', 'RU'), ('en', 'EN')):
            button = QPushButton(label)
            button.setObjectName('Lang')
            button.setCheckable(True)
            button.setChecked(i18n.current() == code)
            button.setToolTip(i18n.tr('Сменить язык интерфейса'))
            button.clicked.connect(
                lambda _checked=False, c=code: self._switch_language(c))
            self._lang_buttons[code] = button
            lang_row.addWidget(button)
        lang_row.addStretch(1)
        layout.addLayout(lang_row)

        donate = QPushButton('Отблагодарить автора')
        donate.setObjectName('Donate')
        donate.setCursor(Qt.CursorShape.PointingHandCursor)
        donate.setToolTip(config.DONATE_URL)
        donate.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl(config.DONATE_URL)))
        layout.addWidget(donate)
        layout.addSpacing(8)
        footer = QLabel(f'v{__version__} · ' + i18n.tr('портативная'))
        footer.setObjectName('LogoSub')
        layout.addWidget(footer)
        credits = QLabel('Создатели: ThreeR и DeepSeek.')
        credits.setObjectName('LogoSub')
        layout.addWidget(credits)
        return sidebar

    def _switch_language(self, code: str) -> None:
        for name, button in self._lang_buttons.items():
            button.setChecked(name == code)
        if code == i18n.current():
            return
        i18n.set_language(code)
        QMessageBox.information(
            self, i18n.tr('Язык'),
            i18n.tr('Язык интерфейса изменён. Перезапустите RUSecurity, '
                    'чтобы применить.'))

    def pages_set_index(self, index: int) -> None:
        self.pages.setCurrentIndex(index)
        button = self._nav_group.button(index)
        if button:
            button.setChecked(True)

    def append_log(self, message: str) -> None:
        self.log_page.append(message)
        self.statusBar().showMessage(message, 6000)
