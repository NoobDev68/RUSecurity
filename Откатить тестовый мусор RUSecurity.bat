@echo off
chcp 65001 >nul
setlocal EnableExtensions
title Откат тестового мусора RUSecurity
cd /d "%~dp0"

rem ============================================================
rem  Удаляет всё, что создаёт «Тестовый мусор RUSecurity.bat».
rem  Файл самодостаточный: генератор рядом не нужен.
rem  Имена и GUID должны совпадать с генератором.
rem  Двойной клик - подтверждение и пауза в конце;
rem  /yes - без вопросов (для автоматизации), /help - справка.
rem ============================================================

set "TESTDIR=%ProgramData%\RusSecurityTest"
set "TEMPJUNK=%TEMP%\RusSecurityTest"
set "CHROMEPROF=%LOCALAPPDATA%\Google\Chrome\User Data\RusSecurityTest"
set "FFPROF=%APPDATA%\Mozilla\Firefox\Profiles\russecuritytest.default"
set "GUID_MP={DEADBEEF-0001-4000-8000-000000000001}"
set "GUID_CLSID={DEADBEEF-0002-4000-8000-000000000002}"
set "GUID_AV={DEADBEEF-0003-4000-8000-000000000003}"

set /a REMOVED=0

if /i "%~1"=="/help" goto :help

fltmc >nul 2>&1
if errorlevel 1 goto :elevate

set "AUTO=0"
if /i "%~1"=="/yes" set "AUTO=1"
if "%AUTO%"=="1" goto :run

echo.
echo  Будет удалено всё, что создаёт генератор тестового мусора:
echo    Run/RunOnce, MountPoints2, политики, службы и драйверы,
echo    задача планировщика, правила брандмауэра, CustomCLSID,
echo    запись Центра безопасности, скрытая программа, поток NTFS,
echo    ярлыки, профили Chrome и Firefox, служебные папки.
echo.
set "OK="
set /p "OK=Продолжить? [y/N]: "
if /i "%OK%"=="y" goto :run
if /i "%OK%"=="д" goto :run
echo  Отменено.
pause
exit /b 0

:run
call :cleanup_all
if "%AUTO%"=="1" exit /b 0
echo.
pause
exit /b 0

rem ============================================================
rem  Очистка
rem ============================================================

:cleanup_all
echo.
echo  === Удаление тестовых записей ===
set /a REMOVED=0
call :del_autostart
call :del_policies
call :del_services
call :del_tasks
call :del_firewall
call :del_clsid
call :del_security
call :del_hidden
call :del_ads
call :del_shortcuts
call :del_browsers
if exist "%TESTDIR%" rmdir /s /q "%TESTDIR%" >nul 2>&1
rem Пустые родительские папки, созданные генератором (непустые не тронутся).
rmdir "%LOCALAPPDATA%\Google\Chrome\User Data" >nul 2>&1
rmdir "%APPDATA%\Mozilla\Firefox\Profiles" >nul 2>&1
rmdir "%APPDATA%\Mozilla\Firefox" >nul 2>&1
echo.
echo  Удалено записей: %REMOVED%
echo  Если службы уже были замечены системой, они исчезнут после перезагрузки.
exit /b 0

:del_autostart
echo.
echo  --- Автозагрузка ---
call :reg_del_value "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" RusSecTest_Run_HKLM "HKLM Run"
call :reg_del_value "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" RusSecTest_Run_HKLM32 "HKLM-x32 Run"
call :reg_del_value "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" RusSecTest_Run_HKCU "HKCU Run"
call :reg_del_value "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" RusSecTest_Empty "HKLM RunOnce"
call :reg_del_key "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\%GUID_MP%" "MountPoints2"
exit /b 0

:del_policies
echo.
echo  --- Политики ---
call :reg_del_value "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" DisableTaskMgr "Политика: диспетчер задач"
call :reg_del_value "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" DisableRegistryTools "Политика: редактор реестра"
call :reg_del_value "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" SettingsPageVisibility "Политика: скрытая страница"
exit /b 0

:del_services
echo.
echo  --- Службы и драйверы ---
call :reg_del_key "HKLM\SYSTEM\CurrentControlSet\Services\RusSecTestSvc" "служба RusSecTestSvc"
call :reg_del_key "HKLM\SYSTEM\CurrentControlSet\Services\RusSecTestSvcNoImage" "служба RusSecTestSvcNoImage"
call :reg_del_key "HKLM\SYSTEM\CurrentControlSet\Services\RusSecTestDrv" "драйвер RusSecTestDrv"
exit /b 0

:del_tasks
echo.
echo  --- Запланированные задачи ---
schtasks /Delete /TN "RusSecurityTest_Task" /F >nul 2>&1
if errorlevel 1 (
    echo   [нет] задача RusSecurityTest_Task
) else (
    echo   [удалено] задача RusSecurityTest_Task
    set /a REMOVED+=1
)
exit /b 0

:del_firewall
echo.
echo  --- Брандмауэр ---
netsh advfirewall firewall delete rule name="RusSecurityTest App" >nul 2>&1
if errorlevel 1 (
    echo   [нет] правило с несуществующей программой
) else (
    echo   [удалено] правило с несуществующей программой
    set /a REMOVED+=1
)
netsh advfirewall firewall delete rule name="RusSecurityTest Port" >nul 2>&1
if errorlevel 1 (
    echo   [нет] правило с открытым портом 45678
) else (
    echo   [удалено] правило с открытым портом 45678
    set /a REMOVED+=1
)
exit /b 0

:del_clsid
echo.
echo  --- Расширения оболочки ---
call :reg_del_key "HKCU\Software\Classes\CLSID\%GUID_CLSID%" "CustomCLSID"
exit /b 0

:del_security
echo.
echo  --- Центр безопасности ---
call :reg_del_key "HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av\%GUID_AV%" "запись антивируса"
exit /b 0

:del_hidden
echo.
echo  --- Скрытая программа ---
call :reg_del_key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RusSecurityTestHidden" "скрытая программа"
exit /b 0

:del_ads
echo.
echo  --- Потоки NTFS ---
if exist "%TEMPJUNK%" (
    rmdir /s /q "%TEMPJUNK%" >nul 2>&1
    echo   [удалено] файл с потоком RusSecTestStream
    set /a REMOVED+=1
) else (
    echo   [нет] файл с потоком RusSecTestStream
)
exit /b 0

:del_shortcuts
echo.
echo  --- Ярлыки ---
if exist "%APPDATA%\Microsoft\Windows\Start Menu\Programs\RusSecurityTest.lnk" (
    del /f /q "%APPDATA%\Microsoft\Windows\Start Menu\Programs\RusSecurityTest.lnk" >nul 2>&1
    echo   [удалено] ярлык в меню «Пуск»
    set /a REMOVED+=1
) else (
    echo   [нет] ярлык в меню «Пуск»
)
if exist "%USERPROFILE%\Desktop\RusSecurityTest.lnk" (
    del /f /q "%USERPROFILE%\Desktop\RusSecurityTest.lnk" >nul 2>&1
    echo   [удалено] ярлык на рабочем столе
    set /a REMOVED+=1
) else (
    echo   [нет] ярлык на рабочем столе
)
exit /b 0

:del_browsers
echo.
echo  --- Браузеры ---
if exist "%CHROMEPROF%" (
    rmdir /s /q "%CHROMEPROF%" >nul 2>&1
    echo   [удалено] профиль Chrome
    set /a REMOVED+=1
) else (
    echo   [нет] профиль Chrome
)
if exist "%FFPROF%" (
    rmdir /s /q "%FFPROF%" >nul 2>&1
    echo   [удалено] профиль Firefox
    set /a REMOVED+=1
) else (
    echo   [нет] профиль Firefox
)
exit /b 0

rem ============================================================
rem  Вспомогательные команды очистки
rem ============================================================

:reg_del_value
reg delete "%~1" /v "%~2" /f >nul 2>&1
if errorlevel 1 (
    echo   [нет] %~3
    exit /b 1
)
echo   [удалено] %~3
set /a REMOVED+=1
exit /b 0

:reg_del_key
reg delete "%~1" /f >nul 2>&1
if errorlevel 1 (
    echo   [нет] %~2
    exit /b 1
)
echo   [удалено] %~2
set /a REMOVED+=1
exit /b 0

rem ============================================================
rem  Прочее
rem ============================================================

:elevate
echo.
echo  Нужны права администратора: запрашиваю UAC...
if not "%~1"=="" goto :elevate_args
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
goto :elevate_done
:elevate_args
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs -ArgumentList '%~1'"
:elevate_done
if errorlevel 1 (
    echo  Не удалось получить права администратора.
    pause
)
exit /b 0

:help
echo.
echo  Откат тестового мусора RUSecurity.
echo.
echo  Запуск без параметров: подтверждение и очистка.
echo    /yes   удалить без подтверждения (для автоматизации)
echo    /help  эта справка
echo.
exit /b 0
