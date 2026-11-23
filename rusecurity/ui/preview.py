"""Предпросмотр плана исправления: dry-run и диалог подтверждения."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QDialog, QDialogButtonBox, QHeaderView, QLabel,
    QMessageBox, QTableWidget, QTableWidgetItem, QVBoxLayout,
)

from .. import i18n
from ..fixer import Fixer
from ..fixer import actions as act

_HIDDEN_KINDS = {act.NOOP, act.CLOSE_PROCESSES, act.RESTORE_POINT}


class FixPreviewDialog(QDialog):
    """Таблица «что будет сделано» перед реальным исправлением."""

    def __init__(self, report, parent=None, intro: str = '',
                 note: str = '') -> None:
        super().__init__(parent)
        self.setWindowTitle(i18n.tr('Предпросмотр исправления'))
        self.resize(860, 480)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        layout.setSpacing(10)

        title = QLabel(i18n.tr('Проверьте план перед применением.'))
        title.setObjectName('SectionTitle')
        layout.addWidget(title)
        if intro:
            intro_label = QLabel(intro)
            intro_label.setWordWrap(True)
            layout.addWidget(intro_label)

        rows = [item for item in report.outcomes
                if item.action.kind not in _HIDDEN_KINDS]
        counts = {status: sum(1 for item in rows if item.status == status)
                  for status in ('planned', 'manual', 'not_found', 'failed', 'skipped')}
        summary = i18n.tr(
            'Будет изменено: {planned} · вручную: {manual} · не найдено: {missing}',
            planned=counts['planned'], manual=counts['manual'],
            missing=counts['not_found'])
        if counts['failed']:
            summary += ' · ' + i18n.tr('ошибок: {count}', count=counts['failed'])
        summary_label = QLabel(summary)
        summary_label.setObjectName('Muted')
        summary_label.setWordWrap(True)
        layout.addWidget(summary_label)

        table = QTableWidget(len(rows), 3)
        table.setHorizontalHeaderLabels([
            i18n.tr('Действие'), i18n.tr('Объект'), i18n.tr('Что будет сделано')])
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setWordWrap(True)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        for row, outcome in enumerate(rows):
            action = outcome.action
            kind = QTableWidgetItem(i18n.tr(act.KIND_LABELS.get(action.kind, action.kind)))
            target_text = action.path or action.name or action.raw
            target = QTableWidgetItem(target_text)
            target.setToolTip(action.raw)
            detail = QTableWidgetItem(outcome.detail)
            for item in (kind, target, detail):
                item.setToolTip(action.raw)
            table.setItem(row, 0, kind)
            table.setItem(row, 1, target)
            table.setItem(row, 2, detail)
        table.resizeRowsToContents()
        layout.addWidget(table, 1)

        if note:
            note_label = QLabel(note)
            note_label.setWordWrap(True)
            note_label.setObjectName('Muted')
            layout.addWidget(note_label)

        buttons = QDialogButtonBox()
        self._apply = buttons.addButton(
            i18n.tr('Применить'), QDialogButtonBox.ButtonRole.AcceptRole)
        self._apply.setObjectName('Danger')
        self._apply.setEnabled(bool(counts['planned']))
        buttons.addButton(i18n.tr('Отмена'),
                          QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        if not counts['planned']:
            empty = QLabel(i18n.tr('В плане нет изменений — исправлять нечего.'))
            empty.setObjectName('Muted')
            empty.setWordWrap(True)
            layout.addWidget(empty)


def preview_fix(parent, text: str, intro: str, note: str = '') -> bool:
    """Прогнать dry-run и показать план. True — пользователь подтвердил."""
    try:
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            report = Fixer(Path('.'), Path('.'), dry_run=True).run(text)
        finally:
            QApplication.restoreOverrideCursor()
    except Exception as exc:  # noqa: BLE001 - показываем пользователю
        QMessageBox.warning(
            parent, i18n.tr('Предпросмотр не удался'),
            i18n.tr('{message}\n\nИсправление не запущено.', message=exc))
        return False
    if not report.outcomes:
        QMessageBox.information(parent, i18n.tr('Предпросмотр исправления'),
                                i18n.tr('В плане нет изменений — исправлять нечего.'))
        return False
    return FixPreviewDialog(report, parent, intro=intro,
                            note=note).exec() == QDialog.DialogCode.Accepted
