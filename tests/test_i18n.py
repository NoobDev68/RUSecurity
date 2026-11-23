"""Тесты локализации интерфейса."""

import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity import i18n  # noqa: E402


def test_translations_switch():
    previous = i18n.current()
    try:
        i18n.set_language('en', save=False)
        assert i18n.tr('Сканирование') == 'Scanning'
        assert i18n.tr('Найдено элементов: {count}', count=3) == 'Found items: 3'
        assert i18n.element_word(1) == 'element'
        assert i18n.element_word(2) == 'elements'
        assert i18n.decimal(1.5) == '1.5'
        assert i18n.tr('неизвестная строка') == 'неизвестная строка'

        i18n.set_language('ru', save=False)
        assert i18n.tr('Сканирование') == 'Сканирование'
        assert i18n.element_word(2) == 'элемента'
        assert i18n.decimal(1.5) == '1,5'
    finally:
        i18n.set_language(previous, save=False)


def test_unknown_language_ignored():
    previous = i18n.current()
    try:
        assert i18n.set_language('de', save=False) == previous
    finally:
        i18n.set_language(previous, save=False)
