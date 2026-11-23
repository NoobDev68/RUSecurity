@echo off
chcp 65001 >nul
rem Портативный запуск RUSecurity: интерфейс на PySide6 из папки .runtime
setlocal
cd /d "%~dp0"

set "PYEXE="
for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PYEXE=%%i"
if not defined PYEXE for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PYEXE=%%i"

if not defined PYEXE (
    echo Python 3.11+ не найден. Установите Python или положите портативный Python в папку программы.
    pause
    exit /b 1
)

if not exist "%~dp0.runtime\PySide6" (
    echo Не найдена папка .runtime с PySide6.
    echo Интерфейс не запустится, но работают команды:
    echo   "%PYEXE%" -m rusecurity scan
    echo   "%PYEXE%" -m rusecurity analyze rusecurity-report.txt
    pause
    exit /b 1
)

set "PYW=%PYEXE:python.exe=pythonw.exe%"
if exist "%PYW%" (
    start "" "%PYW%" -m rusecurity gui
) else (
    "%PYEXE%" -m rusecurity gui
)
