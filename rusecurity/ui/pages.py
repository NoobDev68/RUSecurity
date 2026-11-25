"""Страницы интерфейса: сканирование, результаты и журнал."""

from __future__ import annotations

import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from PySide6.QtCore import Qt, QProcess, QUrl
from PySide6.QtGui import QDesktopServices, QTextCursor
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QFileDialog,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
    QSizePolicy, QSpacerItem, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .. import analyzer, config, exclusions, i18n, names, report_export
from ..core.scanner import ADDITION_OPTIONS, REPORT_OPTIONS, ScanOptions
from ..fixer import actions as act
from ..fixer import parse_fixlist, restore as backup_restore, schedule_reboot
from ..fixer.actions import BROWSER, KIND_LABELS
from ..journal import Journal
from .exclusions_dialog import ExclusionsDialog
from .preview import preview_fix
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
        self._all_findings: List[analyzer.Finding] = []
        self._hidden_findings: List[analyzer.Finding] = []
        self._rows: List[analyzer.Finding] = []
        self._last_bundle: Optional[ScanBundle] = None
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
        self._deep = QCheckBox('Тщательное сканирование')
        self._deep.setObjectName('Deep')
        self._deep.setToolTip(i18n.tr(
            'Дополнительные проверки: COM-перехват, политики браузеров, '
            'ярлыки, SvcHost, устаревшая автозагрузка, LSA, модули процессов, '
            'брандмауэр, сеть, WMI-подписки, переменные окружения и все задачи. '
            'Скан дольше.'))
        options_layout.addWidget(self._deep)
        deep_hint = QLabel(i18n.tr(
            'Включите тщательное сканирование для проверки COM-перехватов, '
            'политик браузеров, ярлыков, SvcHost, процессов, BITS, расширений '
            'оболочки, свежих файлов, путей служб, поисковых движков, '
            'Native Messaging, устаревших точек автозагрузки, LSA, двоичных '
            'файлов служб, модулей процессов, правил брандмауэра, портов, '
            'маршрутов, WMI-подписок, переменных окружения, корней дисков и '
            'всех задач.'))
        deep_hint.setObjectName('Muted')
        deep_hint.setWordWrap(True)
        options_layout.addWidget(deep_hint)
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
        self._stop = QPushButton('Остановить')
        self._stop.setObjectName('Secondary')
        self._stop.setVisible(False)
        self._stop.clicked.connect(self.stop_scan)
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
        controls.addWidget(self._stop)
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
        layout.setContentsMargins(34, 26, 34, 20)
        layout.setSpacing(12)

        header = QHBoxLayout()
        header.addWidget(page_header(
            'Найденные элементы',
            'Отметьте то, что нужно исправить, или нажмите «Рекомендовано».'),
            1)
        self._export = QPushButton('Экспорт')
        self._export.setObjectName('Secondary')
        export_menu = QMenu(self._export)
        export_menu.addAction(i18n.tr('Сводка (Markdown)'), self.export_summary)
        export_menu.addAction(i18n.tr('Архив для поддержки (ZIP)'),
                              self.export_archive)
        self._export.setMenu(export_menu)
        self._export.setEnabled(False)
        header.addWidget(self._export, 0, Qt.AlignmentFlag.AlignTop)
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

        filters = QHBoxLayout()
        filters.setSpacing(10)
        self._search = QLineEdit()
        self._search.setPlaceholderText(i18n.tr('Поиск по найденному…'))
        self._search.setClearButtonEnabled(True)
        self._search.setFixedWidth(260)
        self._search.textChanged.connect(self._apply_filter)
        self._category = QComboBox()
        self._category.addItem(i18n.tr('Все категории'), None)
        self._category.currentIndexChanged.connect(self._apply_filter)
        self._filter_info = QLabel('')
        self._filter_info.setObjectName('Muted')
        filters.addWidget(self._search)
        filters.addWidget(self._category)
        filters.addWidget(self._filter_info)
        filters.addStretch(1)
        self._excluded_manage = QPushButton('Исключения…')
        self._excluded_manage.setObjectName('Secondary')
        self._excluded_manage.setToolTip(i18n.tr(
            'Посмотреть скрытые элементы и вернуть их в результаты'))
        self._excluded_manage.clicked.connect(self.manage_exclusions)
        filters.addWidget(self._excluded_manage)
        layout.addLayout(filters)
        self._excluded_label = QLabel('')
        self._excluded_label.setObjectName('Muted')
        self._excluded_label.setWordWrap(True)
        self._excluded_label.setVisible(False)
        layout.addWidget(self._excluded_label)
        self._no_matches = QLabel(i18n.tr('Ничего не найдено по фильтру.'))
        self._no_matches.setObjectName('Muted')
        self._no_matches.setVisible(False)
        layout.addWidget(self._no_matches)

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
        self._table.setObjectName('Results')
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
        self._table.verticalHeader().setDefaultSectionSize(24)
        self._table.setWordWrap(True)
        self._table.setMinimumHeight(220)
        self._table.itemChanged.connect(self._update_fix_state)
        self._table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
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
        self._empty_temp.setToolTip(i18n.tr(
            'EmptyTemp: удалить содержимое папок Temp (%TEMP%, %TMP%, '
            'C:\\Windows\\Temp). Куки и профили браузеров не затрагиваются.'))
        self._browser_cache = QCheckBox('Очистить кэш и куки браузеров')
        self._browser_cache.setToolTip(i18n.tr(
            'ClearBrowserCache: удалить кэш и куки Chrome, Edge, Brave, Yandex '
            'и Firefox. Вы выйдете из всех аккаунтов на сайтах.'))
        self._close_processes = QCheckBox('Закрыть блокирующие процессы')
        self._close_processes.setToolTip(
            'CloseProcesses: завершить только процессы, чьи файлы выбраны к удалению '
            '(например, браузер перед удалением папки расширения). '
            'Остальные программы не трогает.')
        directives.addWidget(directives_title, 0, 0, 2, 1,
                             Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        directives.addWidget(self._restore_point, 0, 1)
        directives.addWidget(self._empty_temp, 0, 2)
        directives.addWidget(self._browser_cache, 0, 3)
        directives.addWidget(self._close_processes, 1, 1)
        directives.addWidget(self._reboot, 1, 2)
        directives.setColumnStretch(4, 1)
        self._directives_holder = QWidget()
        self._directives_holder.setLayout(directives)
        self._directives_holder.setSizePolicy(QSizePolicy.Policy.Preferred,
                                              QSizePolicy.Policy.Maximum)
        layout.addWidget(self._directives_holder)

        actions = QHBoxLayout()
        actions.setSpacing(14)
        self._recommend = QPushButton('Рекомендовано')
        self._recommend.setObjectName('Secondary')
        self._recommend.setToolTip(i18n.tr(
            'Отметить рекомендованные элементы и включить нужные директивы '
            'по анализу. Остальные элементы остаются на ваше усмотрение.'))
        self._recommend.clicked.connect(self.recommend)
        self._mark_all = QPushButton('Отметить всё')
        self._mark_all.setObjectName('Secondary')
        self._mark_all.setToolTip(i18n.tr(
            'Отметить все элементы, которые исправляются автоматически'))
        self._mark_all.clicked.connect(self.mark_all)
        self._unmark_all = QPushButton('Снять всё')
        self._unmark_all.setObjectName('Secondary')
        self._unmark_all.setToolTip(i18n.tr('Снять галочки со всех элементов'))
        self._unmark_all.clicked.connect(self.unmark_all)
        self._exclude = QPushButton('Исключить выбранное')
        self._exclude.setObjectName('Secondary')
        self._exclude.setEnabled(False)
        self._exclude.setToolTip(i18n.tr(
            'Скрыть выбранные элементы при следующих сканированиях'))
        self._exclude.clicked.connect(self.exclude_selected)
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
        actions.addWidget(self._mark_all)
        actions.addWidget(self._unmark_all)
        actions.addWidget(self._exclude)
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
        self._results_hint.setVisible(False)
        layout.addWidget(self._results_hint)
        self._empty_spacer = QSpacerItem(0, 0, QSizePolicy.Policy.Minimum,
                                         QSizePolicy.Policy.Minimum)
        layout.addItem(self._empty_spacer)
        return view

    def _set_results_hint(self, text: str) -> None:
        """Показать подсказку под кнопками только когда есть текст."""
        self._results_hint.setText(text)
        self._results_hint.setVisible(bool(text.strip()))

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
                                 for name, box in self._option_boxes.items()},
                              deep=self._deep.isChecked())
        if not options.enabled_labels():
            QMessageBox.information(self, i18n.tr('Ничего не выбрано'),
                                    i18n.tr('Отметьте хотя бы один раздел сканирования.'))
            return
        output = config.reports_dir(config.load())
        self.show_form()
        self._start.setEnabled(False)
        self._deep.setEnabled(False)
        self._stop.setVisible(True)
        self._stop.setEnabled(True)
        self._stale = False
        self._status.setText(i18n.tr('Сканирование...'))
        self._progress.setVisible(True)
        self._set_results_hint('')
        self._log('Сканирование начато')
        self._log('Разделы: ' + ', '.join(options.enabled_labels()))
        self._scan_worker = ScanWorker(output, options)
        self._scan_worker.progress.connect(self._on_progress)
        self._scan_worker.finished_ok.connect(self._on_scanned)
        self._scan_worker.cancelled.connect(self._on_scan_cancelled)
        self._scan_worker.failed.connect(self._on_scan_failed)
        self._scan_worker.start()

    def stop_scan(self) -> None:
        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.cancel()
            self._stop.setEnabled(False)
            self._status.setText(i18n.tr('Останавливаю…'))
            self._log('Сканирование останавливается по запросу пользователя')

    def _on_scan_cancelled(self) -> None:
        self._start.setEnabled(True)
        self._deep.setEnabled(True)
        self._stop.setVisible(False)
        self._progress.setVisible(False)
        self._status.setText(i18n.tr('Сканирование отменено.'))
        self._log('Сканирование отменено пользователем')
        self.show_form()

    def _running(self) -> bool:
        return bool((self._scan_worker and self._scan_worker.isRunning())
                    or (self._fix_worker and self._fix_worker.isRunning()))

    def _on_progress(self, message: str) -> None:
        self._status.setText(i18n.tr(message))

    def _on_scanned(self, bundle: ScanBundle) -> None:
        result = bundle.result
        self._start.setEnabled(True)
        self._deep.setEnabled(True)
        self._stop.setVisible(False)
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
        self._last_bundle = bundle
        self._all_findings = list(bundle.analysis.findings)
        self._recommended = dict(bundle.analysis.directives)
        self._stale = False
        self._summary.setText(i18n.tr(
            'Собрано записей: {entries} в основном отчёте{addition} · время: {seconds} с',
            entries=result.entries, addition=addition_ui, seconds=duration))
        self._log(f'Анализ: найдено элементов — {len(self._all_findings)}')
        if bundle.analysis.deep_count:
            self._log(i18n.tr('Тщательных находок: {count}',
                              count=bundle.analysis.deep_count))
        counts = Counter(finding.category for finding in self._all_findings)
        for category, count in counts.most_common():
            self._log(f'  • {category}: {count}')
        self._search.clear()
        self._category.setCurrentIndex(0)
        self._refresh_results(reset_directives=True)
        if self._hidden_findings:
            self._log(f'Скрыто исключениями: {len(self._hidden_findings)}')
        self._export.setEnabled(True)
        self._show_results()

    def _refresh_results(self, reset_directives: bool = False) -> None:
        """Пересобрать таблицу с учётом исключений и текущих фильтров."""
        items = exclusions.load(config.reports_dir(config.load()))
        self._findings = [finding for finding in self._all_findings
                          if not exclusions.contains(items, finding.text)
                          and not (finding.fix and exclusions.contains(items, finding.fix))]
        self._hidden_findings = [finding for finding in self._all_findings
                                 if exclusions.contains(items, finding.text)
                                 or (finding.fix and exclusions.contains(items, finding.fix))]
        self._populate_categories()
        self._fill_results(self._findings)
        counts = Counter(finding.category for finding in self._findings)
        if counts:
            self._breakdown.setText(' · '.join(
                f'{i18n.tr(category)}: {count}'
                for category, count in counts.most_common()))
        else:
            self._breakdown.setText('')
        self._update_exclusions_note()
        self._update_empty_state()
        if reset_directives and self._findings:
            self._restore_point.setChecked(True)
            self._reboot.setChecked(False)
            self._empty_temp.setChecked(False)
            self._browser_cache.setChecked(False)
            self._close_processes.setChecked(False)
        self._update_fix_state()

    def _update_empty_state(self) -> None:
        if self._findings:
            self._table.setVisible(True)
            self._directives_holder.setVisible(True)
            self._actions_holder.setVisible(True)
            self._empty_card.setVisible(False)
            self._empty_spacer.changeSize(0, 0, QSizePolicy.Policy.Minimum,
                                          QSizePolicy.Policy.Minimum)
            return
        self._table.setVisible(False)
        self._directives_holder.setVisible(False)
        self._actions_holder.setVisible(False)
        if self._hidden_findings:
            self._empty_hint.setText(i18n.tr(
                'Все найденные элементы скрыты исключениями: {count}. '
                'Верните их через «Исключения…».',
                count=len(self._hidden_findings)))
        else:
            self._empty_hint.setText(i18n.tr(
                'Проверены выбранные разделы — исправлять нечего. При необходимости '
                'измените разделы и запустите сканирование заново.'))
        self._empty_card.setVisible(True)
        self._empty_spacer.changeSize(0, 0, QSizePolicy.Policy.Minimum,
                                      QSizePolicy.Policy.Expanding)

    def _update_exclusions_note(self) -> None:
        items = exclusions.load(config.reports_dir(config.load()))
        self._excluded_manage.setText(i18n.tr('Исключения ({count})',
                                              count=len(items)))
        if self._hidden_findings:
            text = i18n.tr('Скрыто исключениями: {count}',
                           count=len(self._hidden_findings))
        elif items:
            text = i18n.tr('Исключений: {count}', count=len(items))
        else:
            text = ''
        self._excluded_label.setText(text)
        self._excluded_label.setVisible(bool(text))

    def _on_scan_failed(self, message: str) -> None:
        self._start.setEnabled(True)
        self._deep.setEnabled(True)
        self._stop.setVisible(False)
        self._progress.setVisible(False)
        self._status.setText(i18n.tr('Ошибка: {message}', message=message))
        self._log(f'Ошибка сканирования: {message}')
        self.show_form()
        QMessageBox.warning(self, i18n.tr('Сканирование не удалось'),
                            i18n.tr('{message}\n\nПодробности — в разделе «Журнал».',
                                    message=message))

    # --- список найденного -----------------------------------------------
    def _fill_results(self, findings: List[analyzer.Finding]) -> None:
        self._rows = list(findings)
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
        self._apply_filter()

    def _populate_categories(self) -> None:
        current = self._category.currentData() if self._category.count() else None
        categories = sorted({finding.category for finding in self._findings},
                            key=lambda value: i18n.tr(value))
        self._category.blockSignals(True)
        self._category.clear()
        self._category.addItem(i18n.tr('Все категории'), None)
        for category in categories:
            self._category.addItem(i18n.tr(category), category)
        index = self._category.findData(current)
        self._category.setCurrentIndex(index if index >= 0 else 0)
        self._category.blockSignals(False)

    def _apply_filter(self, *_args) -> None:
        query = self._search.text().strip().casefold()
        category = self._category.currentData()
        shown = 0
        for row, finding in enumerate(self._rows):
            haystack = ' '.join((
                finding.text, finding.category, i18n.tr(finding.category),
                finding.kind_label, i18n.tr(finding.kind_label),
                finding.note, finding.fix)).casefold()
            visible = ((not query or query in haystack)
                       and (category is None or finding.category == category))
            self._table.setRowHidden(row, not visible)
            if visible:
                shown += 1
        self._no_matches.setVisible(bool(self._rows) and shown == 0)
        if query or category is not None:
            self._filter_info.setText(i18n.tr(
                'Показано: {shown} из {total}', shown=shown, total=len(self._rows)))
        else:
            self._filter_info.setText('')

    def _selected(self) -> List[analyzer.Finding]:
        selected: List[analyzer.Finding] = []
        for row, finding in enumerate(self._rows):
            item = self._table.item(row, 0)
            if item is None or finding.manual:
                continue
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(finding)
        return selected

    def _update_fix_state(self, *_args) -> None:
        running = bool(self._fix_worker and self._fix_worker.isRunning())
        has_findings = (any(not finding.manual for finding in self._rows)
                        and not self._stale)
        selected = bool(self._selected())
        self._recommend.setEnabled(has_findings and not running)
        self._mark_all.setEnabled(has_findings and not running)
        self._unmark_all.setEnabled(has_findings and not running)
        self._exclude.setEnabled(selected and not running)
        self._fix.setEnabled(selected and not running)

    def _directive_summary(self) -> str:
        names = []
        if self._restore_point.isChecked():
            names.append('CreateRestorePoint')
        if self._close_processes.isChecked():
            names.append('CloseProcesses')
        if self._empty_temp.isChecked():
            names.append('EmptyTemp')
        if self._browser_cache.isChecked():
            names.append('ClearBrowserCache')
        if self._reboot.isChecked():
            names.append('Reboot')
        return ', '.join(names) if names else i18n.tr('нет')

    def recommend(self) -> None:
        if not self._rows:
            return
        self._table.blockSignals(True)
        for row, finding in enumerate(self._rows):
            if finding.manual or not finding.recommended:
                continue
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        # Включаем рекомендованные директивы, не снимая выбранные пользователем.
        for checkbox, name, default in (
            (self._restore_point, 'restore_point', True),
            (self._close_processes, 'close_processes', False),
            (self._empty_temp, 'empty_temp', False),
            (self._browser_cache, 'browser_cache', False),
            (self._reboot, 'reboot', False),
        ):
            if self._recommended.get(name, default):
                checkbox.setChecked(True)
        available = sum(1 for finding in self._rows if not finding.manual)
        recommended_count = sum(1 for finding in self._rows
                                if not finding.manual and finding.recommended)
        text = i18n.tr('Отмечено рекомендуемых: {count} из {total}.',
                       count=recommended_count, total=available)
        if recommended_count < available:
            text += ' ' + i18n.tr('Остальные требуют вашего решения.')
        self._result_status.setText(text)
        self._log(f'«Рекомендовано»: отмечено рекомендуемых '
                  f'{recommended_count} из {available}; '
                  f'директивы — {self._directive_summary()}')
        self._update_fix_state()

    def mark_all(self) -> None:
        self._table.blockSignals(True)
        for row, finding in enumerate(self._rows):
            if finding.manual:
                continue
            item = self._table.item(row, 0)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)
        self._table.blockSignals(False)
        self._result_status.setText(i18n.tr(
            'Отмечено: {count} {word}.', count=len(self._selected()),
            word=i18n.element_word(len(self._selected()))))
        self._update_fix_state()

    def unmark_all(self) -> None:
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item is not None and item.flags() & Qt.ItemFlag.ItemIsUserCheckable:
                item.setCheckState(Qt.CheckState.Unchecked)
        self._table.blockSignals(False)
        self._result_status.setText(i18n.tr('Галочки сняты.'))
        self._update_fix_state()

    # --- исключения, контекстное меню и экспорт ---------------------------
    def exclude_selected(self) -> None:
        if self._running():
            return
        selected = self._selected()
        if not selected:
            return
        added = exclusions.add(config.reports_dir(config.load()),
                               [finding.fix or finding.text for finding in selected])
        self._log(f'Исключено элементов: {added}')
        self._result_status.setText(i18n.tr('Исключено: {count}', count=added))
        self._refresh_results()

    def _exclude_one(self, finding: analyzer.Finding) -> None:
        added = exclusions.add(config.reports_dir(config.load()),
                               [finding.fix or finding.text])
        self._log(f'Исключён элемент: {finding.text[:120]} ({added})')
        self._result_status.setText(i18n.tr('Исключено: {count}', count=added))
        self._refresh_results()

    def manage_exclusions(self) -> None:
        if self._running():
            return
        reports = config.reports_dir(config.load())
        dialog = ExclusionsDialog(exclusions.load(reports), self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        if dialog.added:
            exclusions.add(reports, dialog.added)
            self._log(f'Добавлено в исключения: {len(dialog.added)}')
        if dialog.clear_all:
            exclusions.clear(reports)
            self._log('Список исключений очищен')
        else:
            removed = exclusions.remove(reports, dialog.removed)
            self._log(f'Возвращено из исключений: {removed}')
        self._refresh_results()

    def _show_context_menu(self, pos) -> None:
        if self._running():
            return
        row = self._table.rowAt(pos.y())
        if row < 0 or row >= len(self._rows):
            return
        finding = self._rows[row]
        actions = parse_fixlist(finding.fix or finding.text)
        action = actions[0] if actions else None
        file_path = self._file_target(action)
        registry_path = self._registry_target(action)
        menu = QMenu(self)
        if file_path:
            menu.addAction(i18n.tr('Открыть папку файла'),
                           lambda value=file_path: self._open_folder(value))
        if registry_path and '...' not in registry_path:
            menu.addAction(i18n.tr('Открыть в Regedit'),
                           lambda value=registry_path: self._open_regedit(value))
        if file_path or registry_path:
            value = file_path or registry_path
            menu.addAction(i18n.tr('Скопировать путь'),
                           lambda target=value: self._copy_text(target))
        menu.addAction(i18n.tr('Скопировать строку'),
                       lambda text=finding.text: self._copy_text(text))
        if '...' in registry_path:
            menu.addAction(i18n.tr(
                'Путь реестра сокращён в отчёте — проверьте в Regedit вручную')) \
                .setEnabled(False)
        menu.addSeparator()
        menu.addAction(i18n.tr('Исключить из проверок'),
                       lambda item=finding: self._exclude_one(item))
        menu.exec(self._table.viewport().mapToGlobal(pos))

    @staticmethod
    def _file_target(action) -> str:
        if action is None:
            return ''
        if action.kind in (act.FILE, act.SHORTCUT, act.ADS, act.EXTENSION) and action.path:
            return os.path.expandvars(action.path)
        return ''

    @staticmethod
    def _registry_target(action) -> str:
        if action is None or action.kind not in (act.REG_KEY, act.REG_VALUE,
                                                 act.REG_SET):
            return ''
        match = re.search(r'((?:HKLM|HKCU|HKU|HKCR)(?:-x32)?\\[^\[\]"]+)',
                          action.raw)
        path = match.group(1) if match else action.path
        return path.strip().rstrip(',').rstrip(':').strip()

    def _open_folder(self, path: str) -> None:
        target = Path(os.path.expandvars(path))
        folder = target if target.is_dir() else target.parent
        if not folder.exists():
            QMessageBox.information(
                self, i18n.tr('Путь не найден'),
                i18n.tr('Папка не существует: {path}', path=folder))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def _open_regedit(self, path: str) -> None:
        QApplication.clipboard().setText(path)
        QProcess.startDetached('regedit.exe', [])
        self._result_status.setText(i18n.tr(
            'Путь скопирован — вставьте его в адресную строку Regedit (Ctrl+L).'))

    def _copy_text(self, text: str) -> None:
        QApplication.clipboard().setText(text)
        self._result_status.setText(i18n.tr('Скопировано.'))

    def _summary_text(self) -> str:
        bundle = self._last_bundle
        if bundle is None:
            return ''
        result = bundle.result
        reports = config.reports_dir(config.load())
        fixlog = reports / names.FIXLOG
        return report_export.summary_markdown(
            created=bundle.started,
            duration=bundle.duration,
            entries=result.entries,
            addition_entries=result.addition_entries,
            findings=self._findings,
            hidden=self._hidden_findings,
            directives=self._recommended,
            report=result.report,
            addition=result.addition,
            fixlog=fixlog if fixlog.is_file() else None,
            backup_dir=report_export.latest_backup(reports))

    def _export_path(self, prefix: str, suffix: str) -> str:
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        return str(config.reports_dir(config.load()) /
                   f'rusecurity-{prefix}-{stamp}{suffix}')

    def export_summary(self) -> None:
        if self._last_bundle is None:
            return
        filename, _filter = QFileDialog.getSaveFileName(
            self, i18n.tr('Сохранить сводку'),
            self._export_path('summary', '.md'), 'Markdown (*.md)')
        if not filename:
            return
        try:
            target = report_export.export_markdown(Path(filename), self._summary_text())
        except OSError as exc:
            QMessageBox.critical(self, i18n.tr('Не удалось сохранить сводку'),
                                 str(exc))
            return
        self._log(f'Сводка сохранена: {target}')
        self._result_status.setText(i18n.tr('Сводка сохранена: {path}', path=target))
        QMessageBox.information(self, i18n.tr('Сводка сохранена'), str(target))

    def export_archive(self) -> None:
        if self._last_bundle is None:
            return
        filename, _filter = QFileDialog.getSaveFileName(
            self, i18n.tr('Сохранить архив для поддержки'),
            self._export_path('support', '.zip'), 'ZIP (*.zip)')
        if not filename:
            return
        try:
            target = report_export.export_zip(
                Path(filename), config.reports_dir(config.load()),
                self._summary_text())
        except OSError as exc:
            QMessageBox.critical(self, i18n.tr('Не удалось сохранить архив'),
                                 str(exc))
            return
        self._log(f'Архив для поддержки сохранён: {target}')
        self._result_status.setText(i18n.tr('Архив сохранён: {path}', path=target))
        QMessageBox.information(self, i18n.tr('Архив сохранён'), str(target))

    # --- исправление ------------------------------------------------------
    def start_fix(self) -> None:
        if self._running():
            return
        selected = self._selected()
        if not selected:
            return
        text = analyzer.compose_fixlist(
            [finding.fix or finding.text for finding in selected],
            restore_point=self._restore_point.isChecked(),
            close_processes=self._close_processes.isChecked(),
            empty_temp=self._empty_temp.isChecked(),
            browser_cache=self._browser_cache.isChecked(),
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
        intro = (i18n.tr('Будут изменены системные настройки.') + '\n\n' +
                 summary + '\n\n' +
                 i18n.tr('Директивы: {names}',
                         names=self._directive_summary()) + '\n\n' +
                 i18n.tr('Перед изменениями создаются точка восстановления и '
                         'резервные копии, удалённое сохраняется в карантин.'))
        note = ''
        if self._reboot.isChecked():
            note += i18n.tr(
                'После исправления потребуется перезагрузка — программа предложит её.')
        if self._empty_temp.isChecked():
            note += ('\n\n' if note else '') + i18n.tr(
                'Очистка Temp удалит содержимое папок %TEMP%, %TMP% и '
                'C:\\Windows\\Temp. Незавершённые установки и обновления '
                'могут прерваться, а открытые программы — потерять временные '
                'данные. Куки, сохранённые пароли и входы в аккаунты не '
                'затрагиваются.')
        if self._browser_cache.isChecked():
            note += ('\n\n' if note else '') + i18n.tr(
                'Будут удалены кэш и куки Chrome, Edge, Brave, Yandex и '
                'Firefox. Браузеры будут закрыты, и вы выйдете из всех '
                'аккаунтов на сайтах.')
        if any(finding.kind == BROWSER for finding in selected):
            note += ('\n\n' if note else '') + i18n.tr(
                'Настройки браузера правятся в файлах профиля, поэтому браузер '
                'будет закрыт; вкладки восстановятся при следующем запуске.')
        if not preview_fix(self, text, intro, note):
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
        self._set_results_hint('')
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
        self._set_results_hint(i18n.tr(
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
                self._set_results_hint(i18n.tr(
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
            self._set_results_hint(i18n.tr(
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


class RestorePage(QWidget):
    """Откат исправлений: выбрать бэкап и отметить объекты для возврата."""

    def __init__(self, log: Callable[[str], None]) -> None:
        super().__init__()
        self._log = log
        self._runs: List[backup_restore.FixRun] = []
        self._entries: List[backup_restore.QuarantineEntry] = []
        self._entries_for: Optional[backup_restore.FixRun] = None
        self._restore_worker: Optional[RestoreWorker] = None
        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(12)
        layout.addWidget(page_header(
            'Откат исправлений',
            'Каждое исправление сохраняет бэкап: выберите его, отметьте объекты '
            'и верните файлы, ветки реестра и hosts.'))
        layout.addWidget(self._build_rollback(), 1)

    # --- откат исправлений -------------------------------------------------
    def _build_rollback(self) -> QFrame:
        frame, layout = card()
        layout.setSpacing(8)
        frame.setSizePolicy(QSizePolicy.Policy.Preferred,
                            QSizePolicy.Policy.Expanding)
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
        self._runs_table.setMinimumHeight(140)
        self._runs_table.itemSelectionChanged.connect(self._update_rollback)
        self._entries_table = QTableWidget(0, 2)
        self._entries_table.setHorizontalHeaderLabels(
            [i18n.tr(text) for text in ('Объект', 'Тип')])
        self._entries_table.verticalHeader().setVisible(False)
        self._entries_table.setAlternatingRowColors(True)
        self._entries_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._entries_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        entry_header = self._entries_table.horizontalHeader()
        entry_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        entry_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._entries_table.setMinimumHeight(140)
        self._entries_table.setVisible(False)
        self._entries_table.itemChanged.connect(self._update_rollback)
        self._entries_title = QLabel('Объекты выбранного исправления:')
        self._entries_title.setObjectName('Muted')
        self._entries_title.setVisible(False)
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
        self._runs_open = QPushButton('Открыть папку')
        self._runs_open.setObjectName('Secondary')
        self._runs_open.setEnabled(False)
        self._runs_open.setToolTip(i18n.tr('Открыть папку с бэкапами выбранного исправления'))
        self._runs_open.clicked.connect(self.open_selected_folder)
        row.addWidget(self._runs_refresh)
        row.addWidget(self._rollback)
        row.addWidget(self._runs_open)
        row.addStretch(1)
        self._runs_status = QLabel('')
        self._runs_status.setObjectName('Muted')
        self._runs_status.setWordWrap(True)
        layout.addLayout(row)
        layout.addWidget(self._runs_table, 3)
        layout.addWidget(self._entries_title)
        layout.addWidget(self._entries_table, 2)
        layout.addWidget(self._runs_status)
        self.reload_runs()
        return frame

    @staticmethod
    def _kinds_text(kinds: dict) -> str:
        labels = {'file': 'файлы', 'reg': 'реестр', 'reg_new': 'значение реестра',
                  'file_edit': 'файл настроек', 'hosts': 'hosts',
                  'task': 'задачи'}
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
        run = self._selected_run()
        if run is None:
            if self._entries_for is not None:
                self._entries = []
                self._entries_for = None
                self._entries_table.setRowCount(0)
                self._entries_table.setVisible(False)
                self._entries_title.setVisible(False)
        elif self._entries_for is not run:
            self._fill_entries(run)
        has_run = run is not None
        self._runs_refresh.setEnabled(not busy)
        self._rollback.setEnabled(not busy and has_run and bool(self._checked_entries()))
        self._runs_open.setEnabled(has_run)

    _KIND_LABELS = {'file': 'файл', 'reg': 'реестр', 'reg_new': 'значение реестра',
                    'file_edit': 'файл настроек', 'hosts': 'hosts', 'task': 'задача'}

    def _fill_entries(self, run: backup_restore.FixRun) -> None:
        self._entries = backup_restore.run_entries(run)
        self._entries_for = run
        table = self._entries_table
        table.blockSignals(True)
        table.setRowCount(len(self._entries))
        for row, entry in enumerate(self._entries):
            item = QTableWidgetItem(entry.original)
            item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable |
                          Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked)
            item.setToolTip(str(entry.stored))
            table.setItem(row, 0, item)
            kind = QTableWidgetItem(i18n.tr(self._KIND_LABELS.get(entry.kind, entry.kind)))
            kind.setToolTip(str(entry.stored))
            table.setItem(row, 1, kind)
        table.blockSignals(False)
        table.setVisible(bool(self._entries))
        self._entries_title.setVisible(bool(self._entries))

    def _checked_entries(self) -> List[backup_restore.QuarantineEntry]:
        result: List[backup_restore.QuarantineEntry] = []
        for row, entry in enumerate(self._entries):
            item = self._entries_table.item(row, 0)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                result.append(entry)
        return result

    def open_selected_folder(self) -> None:
        run = self._selected_run()
        if run is None:
            return
        folder = run.backup
        if not folder.is_dir():
            self._runs_status.setText(i18n.tr('Папка бэкапа не найдена'))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    def rollback_selected(self) -> None:
        if self._busy():
            return
        run = self._selected_run()
        if run is None:
            self._runs_status.setText(i18n.tr('Сначала выделите исправление'))
            return
        entries = self._checked_entries()
        if not entries:
            self._runs_status.setText(i18n.tr(
                'Отметьте объекты, которые нужно вернуть'))
            return
        box = QMessageBox(self)
        box.setWindowTitle(i18n.tr('Откатить исправление от {created}?',
                                   created=run.created))
        box.setIcon(QMessageBox.Icon.Warning)
        box.setText(i18n.tr('Будут возвращены объекты из бэкапа: {count}.',
                            count=len(entries)))
        box.setInformativeText(i18n.tr(
            'Файлы вернутся на прежние места, ветки реестра импортируются, '
            'hosts перезаписывается. Если по прежнему пути появился другой '
            'файл, он будет перемещён в папку бэкапа. Службы и драйверы '
            'заработают после перезагрузки.'))
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
        self._log(message)


class LogPage(QWidget):
    """Подробный журнал действий и кнопка его очистки."""

    def __init__(self, journal: Journal) -> None:
        super().__init__()
        self._journal = journal
        layout = QVBoxLayout(self)
        layout.setContentsMargins(34, 30, 34, 30)
        layout.setSpacing(12)
        layout.addWidget(page_header(
            'Журнал',
            'Подробный лог: время запуска, разделы сканирования, найденные '
            'элементы, исправления, ошибки и резервные копии.'))
        frame, frame_layout = card()
        row = QHBoxLayout()
        clear = QPushButton('Очистить журнал')
        clear.setObjectName('Secondary')
        clear.setToolTip(i18n.tr('Удалить все записи журнала'))
        clear.clicked.connect(self.clear)
        open_folder = QPushButton('Открыть папку журнала')
        open_folder.setObjectName('Secondary')
        open_folder.setToolTip(i18n.tr('Открыть папку с журналом и отчётами'))
        open_folder.clicked.connect(self.open_folder)
        row.addWidget(clear)
        row.addWidget(open_folder)
        row.addStretch(1)
        frame_layout.addLayout(row)
        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setMinimumHeight(60)
        frame_layout.addWidget(self._view)
        layout.addWidget(frame, 1)
        self._view.setPlainText(journal.load())
        self._view.moveCursor(QTextCursor.MoveOperation.End)

    def append(self, message: str) -> None:
        self._view.appendPlainText(self._journal.append(message))
        self._view.moveCursor(QTextCursor.MoveOperation.End)
        self._view.ensureCursorVisible()

    def open_folder(self) -> None:
        folder = self._journal.path.parent
        if not folder.is_dir():
            QMessageBox.information(
                self, i18n.tr('Путь не найден'),
                i18n.tr('Папка не существует: {path}', path=folder))
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

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
