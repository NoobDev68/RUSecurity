"""Управление исключениями: вернуть скрытые элементы или очистить список."""

from __future__ import annotations

from typing import Iterable, List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QHeaderView, QLabel, QMessageBox,
    QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from .. import i18n


class ExclusionsDialog(QDialog):
    """Список скрытых строк с возможностью вернуть выбранные или очистить всё."""

    def __init__(self, items: Iterable[str], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(i18n.tr('Исключения'))
        self.resize(760, 420)
        self._items = list(items)
        self.removed: List[str] = []
        self.clear_all = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)
        title = QLabel(i18n.tr('Скрытые элементы не показываются при следующих сканированиях.'))
        title.setWordWrap(True)
        title.setObjectName('SectionTitle')
        layout.addWidget(title)
        hint = QLabel(i18n.tr(
            'Снимите галочки с тех, что нужно вернуть в результаты проверки.'))
        hint.setObjectName('Muted')
        hint.setWordWrap(True)
        layout.addWidget(hint)

        self._table = QTableWidget(len(self._items), 1)
        self._table.setHorizontalHeaderLabels([i18n.tr('Элемент')])
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setWordWrap(True)
        self._table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)
        for row, text in enumerate(self._items):
            item = QTableWidgetItem(text)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable |
                          Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Unchecked)
            item.setToolTip(text)
            self._table.setItem(row, 0, item)
        self._table.resizeRowsToContents()
        layout.addWidget(self._table, 1)

        buttons = QDialogButtonBox()
        self._remove = buttons.addButton(
            i18n.tr('Вернуть выбранные'), QDialogButtonBox.ButtonRole.AcceptRole)
        self._clear = buttons.addButton(
            i18n.tr('Очистить всё'), QDialogButtonBox.ButtonRole.DestructiveRole)
        buttons.addButton(i18n.tr('Закрыть'),
                          QDialogButtonBox.ButtonRole.RejectRole)
        self._remove.clicked.connect(self._accept_remove)
        self._clear.clicked.connect(self._accept_clear)
        buttons.rejected.connect(self.reject)
        self._remove.setEnabled(bool(self._items))
        self._clear.setEnabled(bool(self._items))
        layout.addWidget(buttons)

    def _checked(self) -> List[str]:
        result: List[str] = []
        for row, text in enumerate(self._items):
            item = self._table.item(row, 0)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                result.append(text)
        return result

    def _accept_remove(self) -> None:
        self.removed = self._checked()
        if not self.removed:
            QMessageBox.information(self, i18n.tr('Исключения'),
                                    i18n.tr('Отметьте элементы, которые нужно вернуть.'))
            return
        self.accept()

    def _accept_clear(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Очистить исключения?'))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Все скрытые элементы снова появятся в результатах.'))
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() == QMessageBox.StandardButton.Yes:
            self.clear_all = True
            self.accept()
