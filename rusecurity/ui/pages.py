"""Страницы интерфейса: сканирование, результаты и журнал."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
    QSizePolicy, QSpacerItem, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .. import analyzer, config, i18n, names
from ..core.scanner import ADDITION_OPTIONS, REPORT_OPTIONS, ScanOptions
from ..fixer import parse_fixlist, restore as backup_restore, schedule_reboot
from ..fixer.actions import BROWSER, KIND_LABELS
from ..journal import Journal
from .workers import FixWorker, RestoreWorker, ScanBundle, ScanWorker

_STATUS_RU = {
    'done': 'выполнено',
    'failed': 'ошибка',
    'not_found': 'не найдено',
    'manual': 'вручную',
    'skipped': 'пропущено',
    'planned': 'план',
    'close': 'процессы',
}


def _plural(count: int, one: str, few: str, many: str) -> str:
    if count % 10 == 1 and count % 100 != 11:
        return one
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return few
    return many


def card() -> Tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setObjectName('Card')
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(22, 20, 22, 20)
    layout.setSpacing(12)
    return frame, layout


def page_header(title: str, subtitle: str) -> QWidget:
    holder = QWidget()
    holder.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
    layout = QVBoxLayout(holder)
    layout.setContentsMargins(0, 0, 0, 4)
    layout.setSpacing(4)
    title_label = QLabel(title)
    title_label.setObjectName('PageTitle')
    subtitle_label = QLabel(subtitle)
    subtitle_label.setObjectName('PageSubtitle')
    subtitle_label.setWordWrap(True)
    layout.addWidget(title_label)
    layout.addWidget(subtitle_label)
    return holder


class ScanPage(QWidget):
    """Два экрана: настройки сканирования и найденные элементы."""

    def __init__(self, log: Callable[[str], None]) -> None:
        super().__init__()
        self._log = log
        self._scan_worker: Optional[ScanWorker] = None
        self._fix_worker: Optional[FixWorker] = None
        self._findings: List[analyzer.Finding] = []
        self._recommended: Dict[str, bool] = {}
        self._option_boxes: Dict[str, QCheckBox] = {}
        self._stale = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self._stack = QStackedWidget()
        self._stack.addWidget(self._build_form())
        self._stack.addWidget(self._build_results())
        layout.addWidget(self._stack)
        self._refresh_privileges()

    # --- экран настроек ---------------------------------------------------
    def _build_form(self) -> QWidget:
        view = QWidget()
        outer = QVBoxLayout(view)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(18)
        scroll.setWidget(content)
        outer.addWidget(scroll)
        self._form_scroll = scroll

        layout.addWidget(page_header(
            'Сканирование',
            'Отметьте разделы и нажмите «Сканировать». Найденные элементы можно '
            'исправить выборочно или отметить всё кнопкой «Рекомендовано».'))

        options_card, options_layout = card()
        title_row = QHBoxLayout()
        title = QLabel('Виды сканирования')
        title.setObjectName('SectionTitle')
        hint = QLabel('включены все — снимите галочки у ненужных')
        hint.setObjectName('Muted')
        title_row.addWidget(title)
        title_row.addSpacing(12)
        title_row.addWidget(hint)
        title_row.addStretch(1)
        options_layout.addLayout(title_row)
        options_layout.addLayout(self._build_options())
        self._privileges = QLabel('')
        self._privileges.setObjectName('Muted')
        self._privileges.setWordWrap(True)
        options_layout.addWidget(self._privileges)
        layout.addWidget(options_card)

        controls = QHBoxLayout()
        controls.setSpacing(14)
        self._start = QPushButton('Сканировать')
        self._start.setObjectName('Primary')
        self._start.clicked.connect(self.start_scan)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setMinimumWidth(240)
        self._progress.setMinimumHeight(10)
        self._progress.setVisible(False)
        self._status = QLabel('Готово к сканированию.')
        self._status.setObjectName('Muted')
        self._status.setWordWrap(True)
        self._status.setFixedWidth(200)
        self._status.setSizePolicy(QSizePolicy.Policy.Fixed,
                                   QSizePolicy.Policy.Preferred)
        controls.addWidget(self._start)
        controls.addWidget(self._progress, 1)
        controls.addWidget(self._status)
        layout.addLayout(controls)
        layout.addStretch(1)
        return view

    def _build_options(self) -> QHBoxLayout:
        groups = QHBoxLayout()
        groups.setSpacing(30)
        left = QVBoxLayout()
        left.setSpacing(4)
        left.addWidget(self._group_label('Основной отчёт'))
        for name, label in REPORT_OPTIONS:
            left.addWidget(self._option(name, label))
        left.addStretch(1)
        right = QVBoxLayout()
        right.setSpacing(4)
        right.addWidget(self._group_label('Дополнительный отчёт'))
        grid = QGridLayout()
        grid.setHorizontalSpacing(24)
        grid.setVerticalSpacing(4)
        for index, (name, label) in enumerate(ADDITION_OPTIONS):
            grid.addWidget(self._option(name, label), index % 7, index // 7)
        right.addLayout(grid)
        right.addStretch(1)
        groups.addLayout(left, 1)
        groups.addLayout(right, 2)
        return groups

    @staticmethod
    def _group_label(text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName('GroupCaption')
        return label

    def _option(self, name: str, label: str) -> QCheckBox:
        box = QCheckBox(label)
        box.setChecked(True)
        self._option_boxes[name] = box
        return box

    def _refresh_privileges(self) -> None:
        from ..fixer import elevate
        if elevate.is_admin():
            self._privileges.setText(i18n.tr(
                'Права: администратор — доступны все разделы (BCD, службы, журналы).'))
        else:
            self._privileges.setText(i18n.tr(
                'Права: пользователь — BCD, часть служб и журналы будут недоступны. '
                'Запустите программу от имени администратора.'))

    # --- экран результатов ------------------------------------------------
    def _build_results(self) -> QWidget:
        view = QWidget()
        layout = QVBoxLayout(view)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(14)

        header = QHBoxLayout()
        header.addWidget(page_header(
            'Найденные элементы',
            'Отметьте то, что нужно исправить, или нажмите «Рекомендовано».'),
            1)
        self._back = QPushButton('Изменить разделы')
        self._back.setObjectName('Secondary')
        self._back.clicked.connect(self.show_form)
        header.addWidget(self._back, 0, Qt.AlignmentFlag.AlignTop)
        layout.addLayout(header)

        self._count = QLabel('Найдено элементов: 0')
        self._count.setObjectName('SectionTitle')
        self._count.setSizePolicy(QSizePolicy.Policy.Preferred,
                                  QSizePolicy.Policy.Maximum)
        layout.addWidget(self._count)
        self._breakdown = QLabel('')
        self._breakdown.setObjectName('Muted')
        self._breakdown.setWordWrap(True)
        self._breakdown.setSizePolicy(QSizePolicy.Policy.Preferred,
                                      QSizePolicy.Policy.Maximum)
        layout.addWidget(self._breakdown)
        self._summary = QLabel('')
        self._summary.setObjectName('Muted')
        self._summary.setWordWrap(True)
        self._summary.setSizePolicy(QSizePolicy.Policy.Preferred,
                                    QSizePolicy.Policy.Maximum)
        layout.addWidget(self._summary)

        self._empty_card, empty_layout = card()
        self._empty_card.setSizePolicy(QSizePolicy.Policy.Preferred,
                                       QSizePolicy.Policy.Maximum)
        self._empty_card.setVisible(False)
        empty_title = QLabel('Подозрительных элементов не найдено')
        empty_title.setObjectName('SectionTitle')
        self._empty_hint = QLabel('')
        self._empty_hint.setObjectName('Muted')
        self._empty_hint.setWordWrap(True)
        empty_layout.addWidget(empty_title)
        empty_layout.addWidget(self._empty_hint)
        self._empty_back = QPushButton('К разделам сканирования')
        self._empty_back.setObjectName('Secondary')
        self._empty_back.clicked.connect(self.show_form)
        empty_layout.addWidget(self._empty_back, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._empty_card)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(['', 'Категория', 'Действие', 'Элемент'])
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        header_view = self._table.horizontalHeader()
        header_view.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header_view.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.verticalHeader().setDefaultSectionSize(30)
        self._table.setWordWrap(True)
        self._table.setMinimumHeight(220)
        self._table.itemChanged.connect(self._update_fix_state)
        layout.addWidget(self._table, 1)

        directives = QGridLayout()
        directives.setHorizontalSpacing(18)
        directives.setVerticalSpacing(4)
        directives_title = QLabel('Директивы:')
        directives_title.setObjectName('Muted')
        self._restore_point = QCheckBox('Точка восстановления')
        self._restore_point.setChecked(True)
        self._restore_point.setToolTip(
            'CreateRestorePoint: создать точку восстановления перед исправлением.')
        self._reboot = QCheckBox('Перезагрузить систему')
        self._reboot.setToolTip(
            'Reboot: перезагрузить систему после исправления (службы и драйверы).')
        self._empty_temp = QCheckBox('Очистить временные файлы')
        self._empty_temp.setToolTip(
            'EmptyTemp: очистить временные файлы и кэши '
            '(нужно после браузерных исправлений).')
        self._close_processes = QCheckBox('Закрыть блокирующие процессы')
        self._close_processes.setToolTip(
            'CloseProcesses: завершить только процессы, чьи файлы выбраны к удалению '
            '(например, браузер перед удалением папки расширения). '
            'Остальные программы не трогает.')
        directives.addWidget(directives_title, 0, 0, 2, 1,
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        directives.addWidget(self._restore_point, 0, 1)
        directives.addWidget(self._empty_temp, 0, 2)
        directives.addWidget(self._close_processes, 1, 1)
        directives.addWidget(self._reboot, 1, 2)
        directives.setColumnStretch(3, 1)
        self._directives_holder = QWidget()
        self._directives_holder.setLayout(directives)
        self._directives_holder.setSizePolicy(QSizePolicy.Policy.Preferred,
                                              QSizePolicy.Policy.Maximum)
        layout.addWidget(self._directives_holder)

        actions = QHBoxLayout()
        actions.setSpacing(14)
        self._recommend = QPushButton('Рекомендовано')
        self._recommend.setObjectName('Secondary')
        self._recommend.setToolTip(
            'Отметить найденные элементы и включить нужные директивы по анализу')
        self._recommend.clicked.connect(self.recommend)
        self._result_progress = QProgressBar()
        self._result_progress.setRange(0, 0)
        self._result_progress.setMinimumHeight(10)
        self._result_progress.setVisible(False)
        self._result_status = QLabel('')
        self._result_status.setObjectName('Muted')
        self._result_status.setWordWrap(True)
        self._fix = QPushButton('Исправить')
        self._fix.setObjectName('Danger')
        self._fix.setEnabled(False)
        self._fix.clicked.connect(self.start_fix)
        actions.addWidget(self._recommend)
        actions.addWidget(self._result_progress, 1)
        actions.addWidget(self._result_status, 1)
        actions.addWidget(self._fix)
        self._actions_holder = QWidget()
        self._actions_holder.setLayout(actions)
        self._actions_holder.setSizePolicy(QSizePolicy.Policy.Preferred,
                                           QSizePolicy.Policy.Maximum)
        layout.addWidget(self._actions_holder)
        self._results_hint = QLabel('')
        self._results_hint.setObjectName('Muted')
        self._results_hint.setWordWrap(True)
        self._results_hint.setSizePolicy(QSizePolicy.Policy.Preferred,
                                         QSizePolicy.Policy.Maximum)
        layout.addWidget(self._results_hint)
        self._empty_spacer = QSpacerItem(0, 0, QSizePolicy.Policy.Minimum,
                                         QSizePolicy.Policy.Minimum)
        layout.addItem(self._empty_spacer)
        return view

    # --- переключение экранов --------------------------------------------
    def show_form(self) -> None:
        self._stack.setCurrentIndex(0)
        self._form_scroll.verticalScrollBar().setValue(0)

    def _show_results(self) -> None:
        self._stack.setCurrentIndex(1)

    # --- сканирование ----------------------------------------------------
    def start_scan(self) -> None:
        if self._running():
            return
        options = ScanOptions(**{name: box.isChecked()
                                 for name, box in self._option_boxes.items()})
        if not options.enabled_labels():
            QMessageBox.information(self, i18n.tr('Ничего не выбрано'),
                                    i18n.tr('Отметьте хотя бы один раздел сканирования.'))
            return
        output = config.reports_dir(config.load())
        self.show_form()
        self._start.setEnabled(False)
        self._stale = False
        self._status.setText(i18n.tr('Сканирование...'))
        self._progress.setVisible(True)
        self._results_hint.setText('')
        self._log('Сканирование начато')
        self._log('Разделы: ' + ', '.join(options.enabled_labels()))
        self._scan_worker = ScanWorker(output, options)
        self._scan_worker.progress.connect(self._on_progress)
        self._scan_worker.finished_ok.connect(self._on_scanned)
        self._scan_worker.failed.connect(self._on_scan_failed)
        self._scan_worker.start()

    def _running(self) -> bool:
        return bool((self._scan_worker and self._scan_worker.isRunning())
                    or (self._fix_worker and self._fix_worker.isRunning()))

    def _on_progress(self, message: str) -> None:
        self._status.setText(i18n.tr(message))

    def _on_scanned(self, bundle: ScanBundle) -> None:
        result = bundle.result
        self._start.setEnabled(True)
        self._progress.setVisible(False)
        duration = i18n.decimal(bundle.duration)
        self._status.setText(i18n.tr('Сканирование завершено за {seconds} с.',
                                     seconds=duration))
        addition_log = (f', {result.addition_entries} в дополнительном'
                        if result.addition else '')
        addition_ui = (i18n.tr(', {count} в дополнительном',
                               count=result.addition_entries)
                       if result.addition else '')
        self._log(f'Сканирование завершено за {duration} с: записей — '
                  f'{result.entries} в основном отчёте{addition_log}')
        findings = list(bundle.analysis.findings)
        self._findings = findings
        self._recommended = dict(bundle.analysis.directives)
        self._stale = False
        self._fill_results(findings)
        self._summary.setText(i18n.tr(
            'Собрано записей: {entries} в основном отчёте{addition} · время: {seconds} с',
            entries=result.entries, addition=addition_ui, seconds=duration))
        self._log(f'Анализ: найдено элементов — {len(findings)}')
        counts = Counter(finding.category for finding in findings)
        for category, count in counts.most_common():
            self._log(f'  • {category}: {count}')
        if findings:
            self._breakdown.setText(' · '.join(
                f'{i18n.tr(category)}: {count}'
                for category, count in counts.most_common()))
            self._table.setVisible(True)
            self._directives_holder.setVisible(True)
            self._actions_holder.setVisible(True)
            self._empty_card.setVisible(False)
            self._empty_spacer.changeSize(0, 0, QSizePolicy.Policy.Minimum,
                                          QSizePolicy.Policy.Minimum)
            self._restore_point.setChecked(True)
            self._reboot.setChecked(False)
            self._empty_temp.setChecked(False)
            self._close_processes.setChecked(False)
        else:
            self._breakdown.setText('')
            self._table.setVisible(False)
            self._directives_holder.setVisible(False)
            self._actions_holder.setVisible(False)
            self._empty_hint.setText(i18n.tr(
                'Проверены выбранные разделы — исправлять нечего. При необходимости '
                'измените разделы и запустите сканирование заново.'))
            self._empty_card.setVisible(True)
            self._empty_spacer.changeSize(0, 0, QSizePolicy.Policy.Minimum,
                                          QSizePolicy.Policy.Expanding)
        self._update_fix_state()
        self._show_results()

    def _on_scan_failed(self, message: str) -> None:
        self._start.setEnabled(True)
        self._progress.setVisible(False)
        self._status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Ошибка сканирования: {message}')
        self.show_form()
        QMessageBox.warning(self, i18n.tr('Сканирование не удалось'),
                            i18n.tr('{message}\n\nПодробности — в разделе «Журнал».',
                                    message=message))

    # --- список найденного -----------------------------------------------
    def _fill_results(self, findings: List[analyzer.Finding]) -> None:
        self._table.blockSignals(True)
        self._table.setRowCount(len(findings))
        for row, finding in enumerate(findings):
            check = QTableWidgetItem('—' if finding.manual else '')
            flags = (Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            if not finding.manual:
                flags |= Qt.ItemFlag.ItemIsUserCheckable
                check.setCheckState(Qt.CheckState.Unchecked)
            check.setFlags(flags)
            self._table.setItem(row, 0, check)
            category = QTableWidgetItem(i18n.tr(finding.category))
            if finding.manual:
                action_text = i18n.tr('только вручную')
            else:
                action_text = i18n.tr(finding.kind_label)
            action = QTableWidgetItem(action_text)
            text = QTableWidgetItem(finding.text)
            tooltip = finding.text
            if finding.note:
                tooltip += f'\n{i18n.tr(finding.note)}'
            for item in (category, action, text):
                item.setToolTip(tooltip)
            self._table.setItem(row, 1, category)
            self._table.setItem(row, 2, action)
            self._table.setItem(row, 3, text)
        self._table.blockSignals(False)
        self._table.resizeRowsToContents()
        self._count.setText(i18n.tr('Найдено элементов: {count}', count=len(findings)))

    def _selected(self) -> List[analyzer.Finding]:
        selected: List[analyzer.Finding] = []
        for row, finding in enumerate(self._findings):
            item = self._table.item(row, 0)
            if item is None or finding.manual:
                continue
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(finding)
        return selected

    def _update_fix_state(self, *_args) -> None:
        running = bool(self._fix_worker and self._fix_worker.isRunning())
        has_findings = (any(not finding.manual for finding in self._findings)
                        and not self._stale)
        self._recommend.setEnabled(has_findings and not running)
        self._fix.setEnabled(bool(self._selected()) and not running)

    def _directive_summary(self) -> str:
        names = []
        if self._restore_point.isChecked():
            names.append('CreateRestorePoint')
        if self._close_processes.isChecked():
            names.append('CloseProcesses')
        if self._empty_temp.isChecked():
            names.append('EmptyTemp')
        if self._reboot.isChecked():
            names.append('Reboot')
        return ', '.join(names) if names else i18n.tr('нет')

    def recommend(self) -> None:
        if not self._findings:
            return
        self._table.blockSignals(True)
        for row, finding in enumerate(self._findings):
            if finding.manual:
                continue
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        self._restore_point.setChecked(self._recommended.get('restore_point', True))
        self._close_processes.setChecked(self._recommended.get('close_processes', False))
        self._empty_temp.setChecked(self._recommended.get('empty_temp', False))
        self._reboot.setChecked(self._recommended.get('reboot', False))
        count = len(self._selected())
        self._result_status.setText(i18n.tr(
            'Отмечено: {count} {word}.', count=count,
            word=i18n.element_word(count)))
        self._log(f'«Рекомендовано»: отмечено {count} '
                  f'{_plural(count, "элемент", "элемента", "элементов")}; '
                  f'директивы — {self._directive_summary()}')
        self._update_fix_state()

    # --- исправление ------------------------------------------------------
    def start_fix(self) -> None:
        if self._running():
            return
        selected = self._selected()
        if not selected:
            return
        text = analyzer.compose_fixlist(
            [finding.text for finding in selected],
            restore_point=self._restore_point.isChecked(),
            close_processes=self._close_processes.isChecked(),
            empty_temp=self._empty_temp.isChecked(),
            reboot=self._reboot.isChecked())
        counts: Counter = Counter()
        for action in parse_fixlist(text):
            if action.kind in ('noop', 'close_processes', 'restore_point',
                               'reboot', 'empty_temp'):
                continue
            counts[action.kind] += 1
        summary = '\n'.join(
            f'• {i18n.tr(KIND_LABELS.get(kind, kind))}: {count}'
            for kind, count in counts.most_common())
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Исправить выбранное?'))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Будут изменены системные настройки.'))
        informative = (summary + '\n\n' +
                       i18n.tr('Директивы: {names}',
                               names=self._directive_summary()) + '\n\n' +
                       i18n.tr('Перед изменениями создаются точка восстановления и '
                               'резервные копии, удалённое сохраняется в карантин.'))
        if self._reboot.isChecked():
            informative += ('\n\n' + i18n.tr(
                'После исправления потребуется перезагрузка — программа предложит её.'))
        if any(finding.kind == BROWSER for finding in selected):
            informative += ('\n\n' + i18n.tr(
                'Настройки браузера правятся в файлах профиля, поэтому браузер '
                'будет закрыт; вкладки восстановятся при следующем запуске.'))
        box.setInformativeText(informative)
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return

        target = config.reports_dir(config.load()) / names.FIXLIST
        analyzer.save_fixlist(text, target)
        log_path = target.with_name(names.FIXLOG)
        backup = target.parent / names.BACKUPS / datetime.now().strftime('%Y%m%d_%H%M%S')
        self._fix.setEnabled(False)
        self._start.setEnabled(False)
        self._recommend.setEnabled(False)
        self._back.setEnabled(False)
        self._result_progress.setVisible(True)
        self._result_status.setText(i18n.tr('Исправление...'))
        self._results_hint.setText('')
        self._log(f'Исправление начато: элементов — {len(selected)}; '
                  f'директивы — {self._directive_summary()}')
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
        label = i18n.tr(_STATUS_RU.get(status, status))
        self._result_status.setText(f'{label}: {raw[:90]}')

    def _on_fixed(self, report, log_path: str) -> None:
        self._start.setEnabled(True)
        self._back.setEnabled(True)
        self._result_progress.setVisible(False)
        self._result_status.setText(i18n.tr('Исправление завершено.'))
        text = self._read_fixlog(log_path)
        if report is not None:
            failed = report.failed
            summary = i18n.tr(
                'Итог: изменено {changed}, ошибок {failed}, вручную {manual}',
                changed=report.changed, failed=report.failed,
                manual=report.manual)
        else:
            match = re.search(r'ошибок (\d+)', text)
            failed = int(match.group(1)) if match else 0
            summary = next((line for line in text.splitlines()
                            if line.startswith('Итог:')), '')
            if not summary:
                summary = i18n.tr(
                    'Итог: изменено {changed}, ошибок {failed}, вручную {manual}',
                    changed=0, failed=failed, manual=0)
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)
        self._table.blockSignals(False)
        needs_reboot = (bool(report.reboot_required) if report is not None
                        else 'Требуется перезагрузка.' in text)
        self._stale = True
        self._update_fix_state()
        self._results_hint.setText(i18n.tr(
            'Исправление завершено. Запустите сканирование заново, '
            'чтобы проверить результат.'))
        if failed:
            QMessageBox.warning(
                self, i18n.tr('Исправление завершено с ошибками'),
                summary + '\n\n' + i18n.tr('Подробности — в разделе «Журнал».'))
        else:
            QMessageBox.information(
                self, i18n.tr('Исправление выполнено'),
                summary + '\n\n' + i18n.tr(
                    'Подробности и пути резервных копий — в разделе «Журнал».'))
        self._offer_reboot(needs_reboot)

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
        reboot_button = box.addButton(
            i18n.tr('Перезагрузить сейчас'), QMessageBox.ButtonRole.AcceptRole)
        later_button = box.addButton(
            i18n.tr('Позже'), QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(later_button)
        box.exec()
        if box.clickedButton() is reboot_button:
            if schedule_reboot():
                self._log('Перезагрузка запланирована через 30 секунд')
                self._results_hint.setText(i18n.tr(
                    'Перезагрузка запланирована через 30 секунд. '
                    'Отменить: shutdown /a.'))
            else:
                self._log('Не удалось запланировать перезагрузку')
                QMessageBox.warning(
                    self, i18n.tr('Требуется перезагрузка'),
                    i18n.tr('Не удалось запланировать перезагрузку. '
                            'Перезагрузите компьютер вручную.'))
        else:
            self._log('Перезагрузка отложена — пользователь перезагрузит '
                      'компьютер вручную')
            self._results_hint.setText(i18n.tr(
                'Требуется перезагрузка — перезагрузите компьютер вручную позже.'))

    def _on_fix_failed(self, message: str) -> None:
        self._start.setEnabled(True)
        self._back.setEnabled(True)
        self._result_progress.setVisible(False)
        self._result_status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Исправление не выполнено: {message}')
        self._update_fix_state()
        QMessageBox.critical(self, i18n.tr('Исправление не выполнено'),
                             i18n.tr('{message}\n\nПодробности — в разделе «Журнал».',
                                     message=message))

    def _read_fixlog(self, log_path: str) -> str:
        try:
            text = Path(log_path).read_text(encoding='utf-8', errors='replace')
        except OSError:
            self._log('Журнал исправления не найден.')
            return ''
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('RUSecurity — журнал'):
                continue
            if stripped.startswith('Бэкапы:'):
                continue
            if stripped.startswith('Точка восстановления:'):
                self._log(stripped)
                continue
            match = re.match(r'^\[\d\d:\d\d:\d\d\]\s+\[([a-z_]+)\]\s+(.*)$', stripped)
            if match:
                status, body = match.group(1), match.group(2)
                if status == 'skipped' and body.endswith('— служебная строка'):
                    continue
                label = _STATUS_RU.get(status, status)
                self._log(f'[{label}] {body}')
                continue
            self._log(stripped)
        return text


class LogPage(QWidget):
    def __init__(self, journal: Journal) -> None:
        super().__init__()
        self._journal = journal
        self._runs: List[backup_restore.FixRun] = []
        self._restore_worker: Optional[RestoreWorker] = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(12)
        layout.addWidget(page_header(
            'Журнал',
            'Подробный лог: время запуска, разделы сканирования, найденные элементы, '
            'исправления, ошибки и резервные копии. Здесь же можно откатить '
            'сделанное исправление.'))
        layout.addWidget(self._build_rollback())
        frame, frame_layout = card()
        row = QHBoxLayout()
        clear = QPushButton('Очистить журнал')
        clear.setObjectName('Secondary')
        clear.setToolTip(i18n.tr('Удалить все записи журнала'))
        clear.clicked.connect(self.clear)
        row.addWidget(clear)
        row.addStretch(1)
        frame_layout.addLayout(row)
        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setMinimumHeight(60)
        frame_layout.addWidget(self._view)
        layout.addWidget(frame, 1)
        self._view.setPlainText(journal.load())
        self._view.moveCursor(QTextCursor.MoveOperation.End)

    # --- откат исправлений -------------------------------------------------
    def _build_rollback(self) -> QFrame:
        frame, layout = card()
        layout.setSpacing(8)
        frame.setSizePolicy(QSizePolicy.Policy.Preferred,
                            QSizePolicy.Policy.Maximum)
        title = QLabel('Откат исправлений')
        title.setObjectName('SectionTitle')
        hint = QLabel(
            'Каждое исправление сохраняет бэкап — выберите его, чтобы вернуть '
            'файлы и реестр.')
        hint.setObjectName('Muted')
        hint.setWordWrap(True)
        self._runs_table = QTableWidget(0, 3)
        self._runs_table.setHorizontalHeaderLabels(
            [i18n.tr(text) for text in ('Когда', 'Что изменено', 'Объектов')])
        self._runs_table.verticalHeader().setVisible(False)
        self._runs_table.setAlternatingRowColors(True)
        self._runs_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._runs_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self._runs_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        header = self._runs_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._runs_table.setFixedHeight(150)
        self._runs_table.itemSelectionChanged.connect(self._update_rollback)
        row = QHBoxLayout()
        self._runs_refresh = QPushButton('Обновить')
        self._runs_refresh.setObjectName('Secondary')
        self._runs_refresh.clicked.connect(self.reload_runs)
        self._rollback = QPushButton('Откатить выбранное')
        self._rollback.setObjectName('Primary')
        self._rollback.setEnabled(False)
        self._rollback.setToolTip(i18n.tr(
            'Вернуть файлы и параметры реестра из выбранного исправления'))
        self._rollback.clicked.connect(self.rollback_selected)
        row.addWidget(self._runs_refresh)
        row.addWidget(self._rollback)
        row.addStretch(1)
        self._runs_status = QLabel('')
        self._runs_status.setObjectName('Muted')
        self._runs_status.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(hint)
        layout.addWidget(self._runs_table)
        layout.addLayout(row)
        layout.addWidget(self._runs_status)
        self.reload_runs()
        return frame

    @staticmethod
    def _kinds_text(kinds: dict) -> str:
        labels = {'file': 'файлы', 'reg': 'реестр', 'reg_new': 'значение реестра',
                  'file_edit': 'файл настроек', 'hosts': 'hosts'}
        parts = []
        for kind, count in sorted(kinds.items()):
            if count:
                parts.append(f'{i18n.tr(labels.get(kind, kind))}: {count}')
        return ' · '.join(parts)

    def reload_runs(self) -> None:
        self._runs = backup_restore.load_runs(config.reports_dir(config.load()))
        self._runs_table.blockSignals(True)
        self._runs_table.setRowCount(len(self._runs))
        for row, run in enumerate(self._runs):
            cells = (QTableWidgetItem(run.created),
                     QTableWidgetItem(self._kinds_text(run.kinds)),
                     QTableWidgetItem(str(run.total)))
            for column, item in enumerate(cells):
                item.setData(Qt.ItemDataRole.UserRole, row)
                item.setToolTip(str(run.backup))
                self._runs_table.setItem(row, column, item)
        self._runs_table.blockSignals(False)
        if self._runs:
            self._runs_status.setText(i18n.tr('Доступно откатов: {count}',
                                              count=len(self._runs)))
        else:
            self._runs_status.setText(i18n.tr(
                'Откатывать нечего — исправлений с бэкапами нет'))
        self._update_rollback()

    def _selected_run(self) -> Optional[backup_restore.FixRun]:
        rows = {item.row() for item in self._runs_table.selectedItems()}
        if not rows:
            return None
        row = min(rows)
        return self._runs[row] if row < len(self._runs) else None

    def _busy(self) -> bool:
        return bool(self._restore_worker and self._restore_worker.isRunning())

    def _update_rollback(self, *_args) -> None:
        busy = self._busy()
        self._runs_refresh.setEnabled(not busy)
        self._rollback.setEnabled(not busy and self._selected_run() is not None)

    def rollback_selected(self) -> None:
        if self._busy():
            return
        run = self._selected_run()
        if run is None:
            self._runs_status.setText(i18n.tr('Сначала выделите исправление'))
            return
        entries = backup_restore.run_entries(run)
        if not entries:
            self._runs_status.setText(
                i18n.tr('В бэкапе этого исправления нет данных'))
            return
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Откатить исправление от {created}?',
                                   created=run.created))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Будут возвращены объекты из бэкапа: {count}.',
                            count=len(entries)))
        box.setInformativeText(i18n.tr(
            'Файлы вернутся на прежние места, ветки реестра импортируются, '
            'hosts перезаписывается. Службы и драйверы заработают после '
            'перезагрузки.'))
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() != QMessageBox.StandardButton.Yes:
            return
        self._rollback.setEnabled(False)
        self._runs_refresh.setEnabled(False)
        self._runs_status.setText(i18n.tr('Откат...'))
        self.append(f'Откат исправления от {run.created}: объектов — {len(entries)}')
        self._restore_worker = RestoreWorker(entries)
        self._restore_worker.finished_ok.connect(
            lambda code, run=run, count=len(entries):
            self._on_rolled_back(code, count, run))
        self._restore_worker.failed.connect(self._on_rollback_failed)
        self._restore_worker.start()

    def _on_rolled_back(self, code: int, count: int,
                        run: backup_restore.FixRun) -> None:
        self.reload_runs()
        if code:
            self.append(f'Откат исправления от {run.created} завершён с ошибками')
            QMessageBox.warning(self, i18n.tr('Откат завершён с ошибками'),
                                i18n.tr('Часть объектов вернуть не удалось. '
                                        'Подробности — в журнале и в '
                                        'restore-log.txt папки бэкапа.'))
            return
        self.append(f'Откат исправления от {run.created} выполнен: '
                    f'объектов — {count}')
        QMessageBox.information(self, i18n.tr('Откат выполнен'),
                                i18n.tr('Обработано объектов: {count}.\n\n'
                                        'Службы и драйверы заработают после '
                                        'перезагрузки.', count=count))

    def _on_rollback_failed(self, message: str) -> None:
        self._runs_status.setText(i18n.tr('Ошибка: {message}', message=message))
        self.append(f'Откат не выполнен: {message}')
        self._update_rollback()
        QMessageBox.critical(self, i18n.tr('Откат не выполнен'), message)

    def showEvent(self, event) -> None:  # noqa: N802 - событие Qt
        super().showEvent(event)
        self.reload_runs()

    def append(self, message: str) -> None:
        self._view.appendPlainText(self._journal.append(message))
        self._view.moveCursor(QTextCursor.MoveOperation.End)
        self._view.ensureCursorVisible()

    def clear(self) -> None:
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Очистить журнал?'))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Все записи журнала будут удалены.'))
        box.setStandardButtons(QMessageBox.StandardButton.Yes |
                               QMessageBox.StandardButton.No)
        box.setDefaultButton(QMessageBox.StandardButton.No)
        if box.exec() == QMessageBox.StandardButton.Yes:
            self._journal.clear()
            self._view.clear()
