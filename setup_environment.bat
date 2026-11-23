@echo off
chcp 1251 >nul
setlocal enabledelayedexpansion
title Generate_Fixlist — установка окружения

echo.
echo  ======================================================
echo      Generate_Fixlist — Подготовка окружения
echo  ======================================================
echo.

:: 1. Поиск Python
set "PYTHON_EXE="
for %%C in (python python3 py) do (
    if not defined PYTHON_EXE (
        %%C -c "import sys" >nul 2>&1
        if !errorlevel!==0 set "PYTHON_EXE=%%C"
    )
)
if not defined PYTHON_EXE goto :install_python
%PYTHON_EXE% -c "import sys; sys.exit(0 if sys.version_info >= (3, 7) else 1)" >nul 2>&1
if errorlevel 1 goto :install_python

echo  [OK] Найден Python: %PYTHON_EXE%
goto :check_deps

:: 2. Установка Python
:install_python
echo.
echo  -- Установка Python 3.12 ---------------------------

set ARCH=amd64
set PY_URL=https://www.python.org/ftp/python/3.12.9/python-3.12.9-amd64.exe
set PY_INSTALLER=%TEMP%\python_installer.exe

where curl >nul 2>&1
if !errorlevel!==0 (
    echo  [->] Скачивание через curl...
    curl -L -o "%PY_INSTALLER%" "%PY_URL%" --progress-bar
) else (
    echo  [-^>] Скачивание через bitsadmin...
    bitsadmin /transfer PythonDownload "%PY_URL%" "%PY_INSTALLER%" >nul
)

if not exist "%PY_INSTALLER%" (
    echo  [ERROR] Не удалось скачать установщик
    echo  Скачайте вручную: %PY_URL%
    pause
    exit /b 1
)

echo  [-^>] Установка (тихая, 1-2 минуты)...
"%PY_INSTALLER%" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
timeout /t 5 /nobreak >nul
del "%PY_INSTALLER%" 2>nul

set "PATH=%PATH%;%ProgramFiles%\Python312;%ProgramFiles%\Python312\Scripts;%LocalAppData%\Programs\Python\Python312;%LocalAppData%\Programs\Python\Python312\Scripts"

where python >nul 2>&1
if !errorlevel! neq 0 (
    for %%D in (
        "%ProgramFiles%\Python312\python.exe"
        "%LocalAppData%\Programs\Python\Python312\python.exe"
        "%SystemDrive%\Python312\python.exe"
    ) do (
        if exist %%D (
            set "PATH=!PATH!;%%~dpD;%%~dpDScripts"
            set "PYTHON_EXE=%%D"
        )
    )
)

where python >nul 2>&1
if !errorlevel! neq 0 (
    echo  [ERROR] Python не найден после установки
    echo  Перезагрузите ПК и запустите батник снова.
    pause
    exit /b 1
)
echo  [OK] Python установлен
set PYTHON_EXE=python

:: 3. Проверка файлов проекта
:check_deps
echo.
echo  -- Проверка файлов проекта -------------------------
set SCRIPT_DIR=%~dp0
set MISSING=

if not exist "%SCRIPT_DIR%GenFix.py"  set MISSING=!MISSING! GenFix.py
if not exist "%SCRIPT_DIR%frst_parser.py"      set MISSING=!MISSING! frst_parser.py
if not exist "%SCRIPT_DIR%detection_config.json" set MISSING=!MISSING! detection_config.json

if not "!MISSING!"=="" (
    echo  [ERROR] Отсутствуют файлы:!MISSING!
    pause
    exit /b 1
)

echo  [OK] Все файлы на месте
echo  [OK] Сторонние pip-пакеты не требуются (чистая stdlib)
echo.

:: Проверка stdlib
for %%M in (json logging os re subprocess sys time pathlib typing) do (
    "%PYTHON_EXE%" -c "import %%M" >nul 2>&1
    if !errorlevel! neq 0 (
        echo  [ERROR] Ошибка импорта: %%M
        pause
        exit /b 1
    )
)
echo  [OK] Модули stdlib доступны

:: 4. Запуск
echo.
echo  ======================================================
echo      Окружение готово.
echo.
echo  Поместите FRST.txt и Additional.txt в папку FRST
echo   и запустите:  python GenFix.py
echo  ======================================================
echo.
set /p RUN="  Запустить генератор сейчас? [Y/n]: "
if /i "%RUN%"=="n" goto :end
echo.
echo  [-^>] Запуск...
"%PYTHON_EXE%" "%~dp0GenFix.py"
goto :end

:end
echo.
endlocal
pause
exit /b 0
