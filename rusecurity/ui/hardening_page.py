"""Страница «Проверка безопасности»: аудит настроек и исправление отклонений."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFrame, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QProgressBar, QPushButton, QScrollArea, QSizePolicy,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .. import analyzer, config, i18n, names
from ..core import hardening
from ..fixer import schedule_reboot
from . import theme
from .pages import card, page_header
from .preview import preview_fix
from .workers import FixWorker, HardeningWorker

_COLUMNS = ('', 'Раздел', 'Проверка', 'Сейчас', 'Должно быть', 'Важность')
_SEVERITY_COLOR = {
    hardening.ISSUE_HIGH: '#F87171',
    hardening.ISSUE_MEDIUM: theme.WARN,
    hardening.ISSUE_LOW: theme.MUTED,
}


class HardeningPage(QWidget):
    """Проверка рекомендованных значений безопасности с выборочным исправлением."""

    def __init__(self, log) -> None:
        super().__init__()
        self._log = log
        self._check_worker: Optional[HardeningWorker] = None
        self._fix_worker: Optional[FixWorker] = None
        self._issues: List[hardening.Issue] = []
        self._stale = False
        self._preview = True

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(14)
        layout.addWidget(page_header(
            'Проверка безопасности',
            'Проверяет параметры, которые ослабляют защиту: учётные данные, '
            'удалённый доступ, SMB, брандмауэр, журналирование и обновления. '
            'Ниже — весь список проверок; нажмите на строку, чтобы прочитать '
            'описание до запуска.'))
        layout.addWidget(self._build_controls())
        self._summary = QLabel('')
        self._summary.setObjectName('Muted')
        self._summary.setWordWrap(True)
        self._summary.setSizePolicy(QSizePolicy.Policy.Preferred,
                                    QSizePolicy.Policy.Maximum)
        layout.addWidget(self._summary)
        layout.addWidget(self._build_empty_card())
        layout.addWidget(self._build_table(), 1)
        layout.addWidget(self._build_details())
        layout.addWidget(self._build_actions())
        self._hint = QLabel('')
        self._hint.setObjectName('Muted')
        self._hint.setWordWrap(True)
        self._hint.setSizePolicy(QSizePolicy.Policy.Preferred,
                                 QSizePolicy.Policy.Maximum)
        layout.addWidget(self._hint)
        self._scroll.setWidget(content)
        outer.addWidget(self._scroll)
        self._show_preview()

    def _show_preview(self) -> None:
        """До первой проверки показываем список параметров без значений."""
        self._preview = True
        self._issues = hardening.rule_preview()
        self._fill(self._issues)
        self._summary.setText(i18n.tr(
            'Проверка ещё не запускалась — показаны все проверяемые параметры.'))
        self._show_empty(False)
        self._update_state()

    # --- построение -------------------------------------------------------
    def _build_controls(self) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        self._start = QPushButton('Проверить')
        self._start.setObjectName('Primary')
        self._start.clicked.connect(self.start_check)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setMinimumHeight(10)
        self._progress.setVisible(False)
        self._status = QLabel('Готово к проверке.')
        self._status.setObjectName('Muted')
        self._status.setWordWrap(True)
        row.addWidget(self._start)
        row.addWidget(self._progress, 1)
        row.addWidget(self._status, 1)
        return holder

    def _build_empty_card(self) -> QFrame:
        frame, layout = card()
        frame.setSizePolicy(QSizePolicy.Policy.Preferred,
                            QSizePolicy.Policy.Maximum)
        title = QLabel('Отклонений не найдено')
        title.setObjectName('SectionTitle')
        self._empty_hint = QLabel('')
        self._empty_hint.setObjectName('Muted')
        self._empty_hint.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(self._empty_hint)
        self._empty_card = frame
        return frame

    def _build_table(self) -> QTableWidget:
        table = QTableWidget(0, len(_COLUMNS))
        table.setHorizontalHeaderLabels([i18n.tr(name) for name in _COLUMNS])
        table.verticalHeader().setVisible(False)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header = table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        for column in (3, 4, 5):
            header.setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents)
        table.verticalHeader().setDefaultSectionSize(30)
        table.setMinimumHeight(220)
        table.itemChanged.connect(self._update_state)
        table.itemSelectionChanged.connect(self._show_details)
        self._table = table
        return table

    def _build_details(self) -> QFrame:
        frame, layout = card()
        layout.setContentsMargins(22, 16, 22, 16)
        layout.setSpacing(8)
        frame.setSizePolicy(QSizePolicy.Policy.Preferred,
                            QSizePolicy.Policy.Maximum)
        self._d_title = QLabel('')
        self._d_title.setObjectName('SectionTitle')
        self._d_title.setWordWrap(True)
        self._d_meta = QLabel('')
        self._d_meta.setObjectName('Muted')
        self._d_meta.setWordWrap(True)
        self._d_values = QLabel('')
        self._d_values.setWordWrap(True)
        self._d_reason = QLabel('')
        self._d_reason.setWordWrap(True)
        self._d_risk = QLabel('')
        self._d_risk.setWordWrap(True)
        self._d_how = QLabel('')
        self._d_how.setWordWrap(True)
        self._d_cmd_title = QLabel('Команда PowerShell (от администратора):')
        self._d_cmd_title.setObjectName('Muted')
        self._d_cmd = QLabel('')
        self._d_cmd.setObjectName('Path')
        self._d_cmd.setWordWrap(True)
        self._d_cmd.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self._d_footer = QLabel('')
        self._d_footer.setObjectName('Muted')
        self._d_footer.setWordWrap(True)
        for label in (self._d_title, self._d_meta, self._d_values,
                      self._d_reason, self._d_risk, self._d_how,
                      self._d_cmd_title, self._d_cmd, self._d_footer):
            layout.addWidget(label)
        frame.setVisible(False)
        self._details = frame
        return frame

    def _build_actions(self) -> QWidget:
        holder = QWidget()
        row = QHBoxLayout(holder)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        self._restore_point = QCheckBox('Точка восстановления')
        self._restore_point.setChecked(True)
        self._restore_point.setToolTip(i18n.tr(
            'Создать точку восстановления перед исправлением.'))
        self._recommend = QPushButton('Рекомендовано')
        self._recommend.setObjectName('Secondary')
        self._recommend.setToolTip(i18n.tr(
            'Отметить рекомендуемые проверки — важные исправления без риска '
            'для сети и устройств. Уже отмеченные остаются.'))
        self._recommend.clicked.connect(self.recommend)
        self._mark_all = QPushButton('Отметить всё')
        self._mark_all.setObjectName('Secondary')
        self._mark_all.setToolTip(i18n.tr(
            'Отметить все проверки, которые исправляются автоматически'))
        self._mark_all.clicked.connect(self.mark_all)
        self._fix = QPushButton('Исправить')
        self._fix.setObjectName('Danger')
        self._fix.setEnabled(False)
        self._fix.clicked.connect(self.start_fix)
        row.addWidget(self._restore_point)
        row.addWidget(self._recommend)
        row.addWidget(self._mark_all)
        row.addStretch(1)
        row.addWidget(self._fix)
        return holder

    def _show_empty(self, empty: bool) -> None:
        self._empty_card.setVisible(empty)
        self._table.setVisible(not empty)

    # --- проверка ---------------------------------------------------------
    def _running(self) -> bool:
        return bool((self._check_worker and self._check_worker.isRunning())
                    or (self._fix_worker and self._fix_worker.isRunning()))

    def start_check(self) -> None:
        if self._running():
            return
        self._start.setEnabled(False)
        self._progress.setVisible(True)
        self._status.setText(i18n.tr('Идёт проверка...'))
        self._hint.setText('')
        self._log('Проверка безопасности начата')
        self._check_worker = HardeningWorker()
        self._check_worker.finished_ok.connect(self._on_checked)
        self._check_worker.failed.connect(self._on_check_failed)
        self._check_worker.start()

    def _on_checked(self, issues: List[hardening.Issue]) -> None:
        self._start.setEnabled(True)
        self._progress.setVisible(False)
        self._preview = False
        self._issues = list(issues)
        self._stale = False
        self._fill(issues)
        total = hardening.counts(issues)
        self._status.setText(i18n.tr('Проверка завершена.'))
        self._summary.setText(i18n.tr(
            'Отклонений: {count} · высокая {high} · средняя {medium} · низкая {low}',
            count=len(issues), high=total[hardening.ISSUE_HIGH],
            medium=total[hardening.ISSUE_MEDIUM], low=total[hardening.ISSUE_LOW]))
        self._log(f'Проверка безопасности: отклонений — {len(issues)} '
                  f'(высокая {total[hardening.ISSUE_HIGH]}, '
                  f'средняя {total[hardening.ISSUE_MEDIUM]}, '
                  f'низкая {total[hardening.ISSUE_LOW]})')
        for issue in issues:
            self._log(f'  • [{issue.severity_label}] {issue.title}: '
                      f'{issue.current} → нужно {issue.expected}')
        if issues:
            self._show_empty(False)
            self._empty_hint.setText('')
        else:
            self._empty_hint.setText(i18n.tr(
                'Все проверяемые параметры соответствуют рекомендуемым значениям.'))
            self._show_empty(True)
        self._update_state()

    def _on_check_failed(self, message: str) -> None:
        self._start.setEnabled(True)
        self._progress.setVisible(False)
        self._status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Проверка безопасности не выполнена: {message}')
        QMessageBox.warning(self, i18n.tr('Проверка не выполнена'), message)

    def _fill(self, issues: List[hardening.Issue]) -> None:
        self._table.blockSignals(True)
        self._table.setRowCount(len(issues))
        for row, issue in enumerate(issues):
            checkable = not issue.manual and not self._preview
            check = QTableWidgetItem('—' if issue.manual else '')
            flags = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
            if checkable:
                flags |= Qt.ItemFlag.ItemIsUserCheckable
                check.setCheckState(Qt.CheckState.Unchecked)
            elif self._preview:
                check.setText('—')
            check.setFlags(flags)
            self._table.setItem(row, 0, check)

            tooltip = issue.title
            if issue.note:
                tooltip += f'\n{issue.note}'
            if issue.risk:
                tooltip += f'\n{issue.risk}'
            if issue.manual:
                tooltip += f'\n{i18n.tr("исправляется только вручную")}'
            severity = QTableWidgetItem(i18n.tr(issue.severity_label))
            severity.setForeground(QBrush(QColor(
                _SEVERITY_COLOR.get(issue.severity, theme.MUTED))))
            cells = (
                QTableWidgetItem(i18n.tr(issue.section)),
                QTableWidgetItem(issue.title),
                QTableWidgetItem(issue.current),
                QTableWidgetItem(issue.expected),
                severity,
            )
            for index, item in enumerate(cells, start=1):
                item.setToolTip(tooltip)
                self._table.setItem(row, index, item)
        self._table.blockSignals(False)
        self._table.clearSelection()
        self._show_details()

    def _show_details(self) -> None:
        issue = self._current_issue()
        self._details.setVisible(issue is not None)
        if issue is None:
            return
        if issue.manual:
            verdict = i18n.tr('исправляется только вручную')
        elif issue.recommended:
            verdict = i18n.tr('рекомендуется к исправлению')
        else:
            verdict = i18n.tr('необязательная проверка')
        self._d_title.setText(i18n.tr(issue.title))
        self._d_meta.setText(' · '.join((i18n.tr(issue.section),
                                         i18n.tr(issue.severity_label), verdict)))
        self._d_values.setText(i18n.tr(
            'Сейчас: {current} · должно быть: {expected}',
            current=issue.current, expected=issue.expected))
        self._d_reason.setText(i18n.tr(
            'Почему исправлять: {reason}', reason=issue.note))
        self._d_reason.setVisible(bool(issue.note))
        self._d_risk.setText(i18n.tr(
            'Возможные минусы: {risk}', risk=issue.risk))
        self._d_risk.setVisible(bool(issue.risk))
        self._d_how.setText(i18n.tr('Как исправить: {how}', how=issue.how_to))
        self._d_how.setVisible(bool(issue.how_to))
        self._d_cmd_title.setVisible(bool(issue.command))
        self._d_cmd.setText(issue.command)
        self._d_cmd.setVisible(bool(issue.command))
        self._d_footer.setText(i18n.tr(
            'Изменение обратимо: перед исправлением сохраняется копия ветки '
            'реестра.'))
        self._d_footer.setVisible(not issue.manual)

    def _current_issue(self) -> Optional[hardening.Issue]:
        rows = sorted({index.row() for index in self._table.selectedIndexes()})
        if not rows:
            return None
        row = rows[0]
        return self._issues[row] if row < len(self._issues) else None

    def _selected(self) -> List[hardening.Issue]:
        selected: List[hardening.Issue] = []
        for row, issue in enumerate(self._issues):
            item = self._table.item(row, 0)
            if item is None or issue.manual:
                continue
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(issue)
        return selected

    def _update_state(self, *_args) -> None:
        running = self._running()
        selected = self._selected()
        self._fix.setEnabled(bool(selected) and not running and not self._stale)
        self._recommend.setEnabled(bool(hardening.recommended(self._issues))
                                   and not running and not self._stale)
        self._mark_all.setEnabled(bool(hardening.fixable(self._issues))
                                  and not running and not self._stale)

    def recommend(self) -> None:
        recommended_ids = {issue.rule_id
                           for issue in hardening.recommended(self._issues)}
        self._table.blockSignals(True)
        for row, issue in enumerate(self._issues):
            if issue.manual or issue.rule_id not in recommended_ids:
                continue
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        self._update_state()
        fixable_total = len(hardening.fixable(self._issues))
        self._hint.setText(i18n.tr(
            'Отмечены рекомендуемые проверки: {count} из {total} исправляемых. '
            'Остальные выберите сами.',
            count=len(recommended_ids), total=fixable_total))
        self._log(f'«Рекомендовано»: отмечено {len(recommended_ids)} из '
                  f'{fixable_total} исправляемых (важные исправления без риска '
                  f'для сети и устройств)')

    def mark_all(self) -> None:
        self._table.blockSignals(True)
        for row, issue in enumerate(self._issues):
            if issue.manual:
                continue
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        self._update_state()

    # --- исправление ------------------------------------------------------
    def start_fix(self) -> None:
        if self._running():
            return
        selected = self._selected()
        text = hardening.compose_fixlist(selected)
        if not text:
            QMessageBox.information(
                self, i18n.tr('Исправлять нечего'),
                i18n.tr('Выбранные отклонения исправляются только вручную.'))
            return
        total = hardening.counts(selected)
        intro = i18n.tr('Будут изменены параметры безопасности системы.')
        intro += '\n\n' + i18n.tr(
            'Отклонений выбрано: {count} (высокая {high}, средняя {medium}, '
            'низкая {low}).',
            count=len(selected), high=total[hardening.ISSUE_HIGH],
            medium=total[hardening.ISSUE_MEDIUM], low=total[hardening.ISSUE_LOW])
        intro += '\n\n' + i18n.tr(
            'Перед изменениями создаются точка восстановления и резервные копии '
            'веток реестра, поэтому исправление обратимо.')
        note = ''
        if hardening.needs_reboot(selected):
            note = i18n.tr(
                'Часть изменений вступит в силу после перезагрузки — '
                'программа предложит её.')
        if not preview_fix(self, text, intro, note):
            return

        target = config.reports_dir(config.load()) / names.FIXLIST
        analyzer.save_fixlist(text, target)
        log_path = target.with_name(names.FIXLOG)
        backup = target.parent / names.BACKUPS / datetime.now().strftime('%Y%m%d_%H%M%S')
        self._start.setEnabled(False)
        self._mark_all.setEnabled(False)
        self._fix.setEnabled(False)
        self._progress.setVisible(True)
        self._status.setText(i18n.tr('Исправление...'))
        self._log(f'Исправление проверки безопасности: отклонений — {len(selected)}')
        self._log(f'Резервные копии: {backup}')
        self._fix_worker = FixWorker(
            text, log_path, backup,
            create_restore_point=self._restore_point.isChecked(),
            allow_reboot=False)
        self._fix_worker.progress.connect(self._on_fix_progress)
        self._fix_worker.finished_ok.connect(self._on_fixed)
        self._fix_worker.failed.connect(self._on_fix_failed)
        self._fix_worker.start()

    def _on_fix_progress(self, raw: str, status: str, detail: str) -> None:
        self._status.setText(f'{raw[:80]} — {detail[:60]}')

    def _on_fixed(self, report, log_path: str) -> None:
        self._start.setEnabled(True)
        self._progress.setVisible(False)
        self._status.setText(i18n.tr('Исправление завершено.'))
        if report is not None:
            summary = i18n.tr(
                'Итог: изменено {changed}, ошибок {failed}, вручную {manual}',
                changed=report.changed, failed=report.failed,
                manual=report.manual)
        else:
            summary = i18n.tr('Исправление выполнено')
        self._read_fixlog(log_path)
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)
        self._table.blockSignals(False)
        self._stale = True
        self._update_state()
        self._hint.setText(i18n.tr(
            'Запустите проверку заново, чтобы убедиться в результате.'))
        if report is not None and report.failed:
            QMessageBox.warning(self, i18n.tr('Исправление завершено с ошибками'),
                                summary)
        else:
            QMessageBox.information(self, i18n.tr('Исправление выполнено'), summary)
        needs_reboot = bool(report.reboot_required) if report is not None else False
        self._offer_reboot(needs_reboot)

    def _on_fix_failed(self, message: str) -> None:
        self._start.setEnabled(True)
        self._progress.setVisible(False)
        self._status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Исправление не выполнено: {message}')
        self._update_state()
        QMessageBox.critical(self, i18n.tr('Исправление не выполнено'), message)

    def _read_fixlog(self, log_path: str) -> None:
        from pathlib import Path
        try:
            text = Path(log_path).read_text(encoding='utf-8', errors='replace')
        except OSError:
            self._log('Журнал исправления не найден.')
            return
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(('RUSecurity', 'Бэкапы:')):
                continue
            self._log(stripped)

    def _offer_reboot(self, needed: bool) -> None:
        if not needed:
            return
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Требуется перезагрузка'))
        box.setIcon(QMessageBox.Icon.Question)
        box.setText(i18n.tr(
            'Для завершения исправления нужно перезагрузить компьютер.'))
        box.setInformativeText(i18n.tr(
            'Можно перезагрузить сейчас (через 30 секунд) или отложить '
            'и сделать это вручную позже.'))
        reboot_button = box.addButton(i18n.tr('Перезагрузить сейчас'),
                                      QMessageBox.ButtonRole.AcceptRole)
        later_button = box.addButton(i18n.tr('Позже'),
                                     QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(later_button)
        box.exec()
        if box.clickedButton() is reboot_button:
            if schedule_reboot():
                self._log('Перезагрузка запланирована через 30 секунд')
            else:
                self._log('Не удалось запланировать перезагрузку')
                QMessageBox.warning(self, i18n.tr('Требуется перезагрузка'),
                                    i18n.tr('Запланировать перезагрузку не '
                                            'удалось — перезагрузите вручную.'))
        else:
            self._log('Перезагрузка отложена')