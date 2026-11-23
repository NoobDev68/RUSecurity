@echo off
chcp 1251 >nul
setlocal
cd /d "%~dp0"
title GenFix - генератор fixlist для FRST

if not exist "%~dp0GenFix.py" (
    echo.
    echo Не найден GenFix.py рядом с этим файлом.
    echo Положите батник в папку проекта.
    echo.
    pause
    exit /b 1
)

set "PY_CMD="
py -3 -c "import sys" >nul 2>&1
if not errorlevel 1 set "PY_CMD=py -3"
if not defined PY_CMD (
    python -c "import sys" >nul 2>&1
    if not errorlevel 1 set "PY_CMD=python"
)
if not defined PY_CMD (
    echo.
    echo Python не найден.
    echo Установите Python 3.11+ или запустите setup_environment.bat.
    echo.
    pause
    exit /b 1
)

%PY_CMD% "%~dp0GenFix.py"
set "EXITCODE=%ERRORLEVEL%"
chcp 1251 >nul
if not "%EXITCODE%"=="0" (
    echo.
    echo GenFix завершился с ошибкой. Код: %EXITCODE%
    echo.
    pause
)
exit /b %EXITCODE%
