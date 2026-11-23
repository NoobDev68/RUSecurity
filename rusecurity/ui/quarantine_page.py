"""Страница карантина: что удалено, как вернуть и как очистить."""

from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QFrame, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import config, i18n
from ..fixer import restore as quarantine
from .pages import page_header
from .workers import QuarantineDeleteWorker, RestoreWorker


class QuarantinePage(QWidget):
    def __init__(self, log) -> None:
        super().__init__()
        self._log = log
        self._entries: List[quarantine.QuarantineEntry] = []
        self._worker: RestoreWorker | None = None
        self._delete_worker: QuarantineDeleteWorker | None = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(18)
        layout.addWidget(page_header(
            'Карантин',
            'Всё, что удалил фиксер, лежит в Reports\\Backups. Можно вернуть файлы '
            'и ветки реестра, удалить выбранные записи или очистить карантин полностью.'))

        frame = QFrame()
        frame.setObjectName('Card')
        card = QVBoxLayout(frame)
        card.setContentsMargins(22, 20, 22, 20)
        card.setSpacing(12)
        self._table = QTableWidget(0, 3)
        self._table.setHorizontalHeaderLabels(['Когда', 'Тип', 'Что вернуть'])
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        card.addWidget(self._table, 1)

        row = QHBoxLayout()
        self._refresh = QPushButton('Обновить')
        self._refresh.setObjectName('Secondary')
        self._refresh.clicked.connect(self.reload)
        self._restore = QPushButton('Вернуть выбранное')
        self._restore.setObjectName('Primary')
        self._restore.clicked.connect(self.restore_selected)
        self._delete = QPushButton('Удалить выбранное')
        self._delete.setObjectName('Secondary')
        self._delete.clicked.connect(self.delete_selected)
        self._clear = QPushButton('Очистить карантин')
        self._clear.setObjectName('Danger')
        self._clear.clicked.connect(self.clear_quarantine)
        row.addWidget(self._refresh)
        row.addWidget(self._restore)
        row.addWidget(self._delete)
        row.addStretch(1)
        card.addLayout(row)

        status_row = QHBoxLayout()
        self._status = QLabel('')
        self._status.setObjectName('Muted')
        self._status.setWordWrap(True)
        status_row.addWidget(self._status, 1)
        status_row.addWidget(self._clear)
        card.addLayout(status_row)
        layout.addWidget(frame, 1)
        self.reload()

    def reload(self) -> None:
        settings = config.load()
        self._entries = quarantine.load_entries(config.reports_dir(settings))
        self._table.setRowCount(len(self._entries))
        for index, entry in enumerate(self._entries):
            created = QTableWidgetItem(entry.created or entry.backup.name)
            kind_label = {'reg': 'реестр', 'reg_new': 'значение реестра',
                          'hosts': 'hosts',
                          'file_edit': 'файл настроек'}.get(entry.kind, 'файл')
            kind = QTableWidgetItem(i18n.tr(kind_label))
            target = QTableWidgetItem(entry.original)
            target.setToolTip(str(entry.stored))
            for column, item in enumerate((created, kind, target)):
                item.setData(Qt.ItemDataRole.UserRole, index)
                self._table.setItem(index, column, item)
        self._status.setText(i18n.tr('Записей: {count}', count=len(self._entries))
                             if self._entries else i18n.tr('Карантин пуст'))

    def _selected_entries(self) -> List[quarantine.QuarantineEntry]:
        rows = sorted({self._table.item(item.row(), 0).data(Qt.ItemDataRole.UserRole)
                       for item in self._table.selectedItems()})
        return [self._entries[row] for row in rows
                if 0 <= row < len(self._entries)]

    def _busy(self) -> bool:
        return bool((self._worker and self._worker.isRunning())
                    or (self._delete_worker and self._delete_worker.isRunning()))

    def _set_busy(self, busy: bool) -> None:
        for button in (self._refresh, self._restore, self._delete, self._clear):
            button.setEnabled(not busy)

    # --- восстановление ---------------------------------------------------
    def restore_selected(self) -> None:
        if self._busy():
            return
        entries = self._selected_entries()
        if not entries:
            self._status.setText(i18n.tr('Сначала выделите строки'))
            return
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Вернуть из карантина?'))
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(i18n.tr('Будет восстановлено объектов: {count}',
                            count=len(entries)))
        box.setInformativeText(i18n.tr(
            'Файлы вернутся на прежние места, hosts будет перезаписан, ветки реестра '
            'импортируются из бэкапа. Существующие файлы не перезаписываются, кроме hosts.'))
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(True)
        self._status.setText(i18n.tr('Восстановление...'))
        self._log(f'Восстановление из карантина: {len(entries)} объектов')
        self._worker = RestoreWorker(entries)
        self._worker.finished_ok.connect(self._on_restored)
        self._worker.failed.connect(self._on_restore_failed)
        self._worker.start()

    def _on_restored(self, code: int) -> None:
        self._set_busy(False)
        self._log('Восстановление завершено' if not code
                  else 'Восстановление завершено с ошибками')
        self.reload()

    def _on_restore_failed(self, message: str) -> None:
        self._set_busy(False)
        self._status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Ошибка восстановления: {message}')

    # --- удаление ---------------------------------------------------------
    def delete_selected(self) -> None:
        if self._busy():
            return
        entries = self._selected_entries()
        if not entries:
            self._status.setText(i18n.tr('Сначала выделите строки'))
            return
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Удалить из карантина?'))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Безвозвратно удалить записей: {count}',
                            count=len(entries)))
        box.setInformativeText(i18n.tr(
            'Файлы и .reg-бэкапы будут удалены. Восстановить их после этого нельзя.'))
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(True)
        self._status.setText(i18n.tr('Удаление...'))
        self._log(f'Удаление из карантина: {len(entries)} объектов')
        self._delete_worker = QuarantineDeleteWorker(entries=entries)
        self._delete_worker.finished_ok.connect(self._on_deleted)
        self._delete_worker.failed.connect(self._on_delete_failed)
        self._delete_worker.start()

    def clear_quarantine(self) -> None:
        if self._busy():
            return
        if not self._entries:
            self._status.setText(i18n.tr('Карантин уже пуст'))
            return
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Очистить карантин?'))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Карантин будет очищен полностью.'))
        box.setInformativeText(i18n.tr(
            'Будет удалено записей: {count}. Все файлы и .reg-бэкапы '
            'исчезнут без возможности восстановления.', count=len(self._entries)))
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(True)
        self._status.setText(i18n.tr('Очистка карантина...'))
        self._log('Очистка карантина')
        self._delete_worker = QuarantineDeleteWorker(
            reports_dir=config.reports_dir(config.load()), clear_all=True)
        self._delete_worker.finished_ok.connect(self._on_deleted)
        self._delete_worker.failed.connect(self._on_delete_failed)
        self._delete_worker.start()

    def _on_deleted(self, deleted: int, failed: int) -> None:
        self._set_busy(False)
        self._log(f'Карантин: удалено записей — {deleted}, ошибок — {failed}')
        self.reload()
        text = i18n.tr('Удалено: {count}', count=deleted)
        if failed:
            text += i18n.tr(', ошибок: {count}', count=failed)
        self._status.setText(text)

    def _on_delete_failed(self, message: str) -> None:
        self._set_busy(False)
        self._status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Ошибка очистки карантина: {message}')
        QMessageBox.critical(self, i18n.tr('Не удалось удалить'),
                             i18n.tr('{message}\n\nПодробности — в разделе «Журнал».',
                                     message=message))
