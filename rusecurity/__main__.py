"""Запуск RUSecurity: python -m rusecurity [gui|scan|analyze]."""

import sys

from .cli import main

if __name__ == '__main__':
    sys.exit(main())
