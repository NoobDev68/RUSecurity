@echo off
chcp 65001 >nul
setlocal EnableExtensions
title RUSecurity: тестовый мусор
cd /d "%~dp0"

rem ============================================================
rem  Генератор тестовых записей для проверки детекции RUSecurity.
rem  Все записи помечены RusSecTest и удаляются пунктом 0.
rem  Предназначен для тестовой машины: часть записей меняет
rem  реальные настройки Windows (политики, брандмауэр, службы).
rem ============================================================

set "TESTDIR=%ProgramData%\RusSecurityTest"
set "TEMPJUNK=%TEMP%\RusSecurityTest"
set "CHROMEPROF=%LOCALAPPDATA%\Google\Chrome\User Data\RusSecurityTest"
set "FFPROF=%APPDATA%\Mozilla\Firefox\Profiles\russecuritytest.default"
set "GUID_MP={DEADBEEF-0001-4000-8000-000000000001}"
set "GUID_CLSID={DEADBEEF-0002-4000-8000-000000000002}"
set "GUID_AV={DEADBEEF-0003-4000-8000-000000000003}"

set /a ADDED=0
set /a REMOVED=0

if /i "%~1"=="/help" goto :help

fltmc >nul 2>&1
if errorlevel 1 goto :elevate

if /i "%~1"=="/all" goto :run_all
if /i "%~1"=="/cleanup" goto :run_cleanup

:menu
cls
echo.
echo  ============================================================
echo    RUSecurity: тестовый мусор для проверки детекции
echo  ============================================================
echo.
echo   Записи создаются в реальной системе и удаляются пунктом 0.
echo   Порядок проверки: добавить, запустить RUSecurity и сканер,
echo   убедиться, что все пункты попали в «Найденные элементы».
echo.
echo    1. Автозагрузка          Run/RunOnce без файла, MountPoints2
echo    2. Политики              DisableTaskMgr, DisableRegistryTools
echo    3. Службы и драйверы     без ImagePath и с пропавшим файлом
echo    4. Задачи                задача с несуществующим файлом
echo    5. Брандмауэр            правило без файла и открытый порт
echo    6. Расширения оболочки   CustomCLSID с несуществующей DLL
echo    7. Центр безопасности    мёртвая запись антивируса
echo    8. Скрытая программа     Hidden-запись в списке программ
echo    9. Потоки NTFS           поток в файле Temp
echo   10. Ярлыки                битые ярлыки в меню и на рабочем столе
echo   11. Браузеры              профили Chrome и Firefox с подменой
echo.
echo    A. Добавить ВСЁ
echo    0. Удалить ВСЁ
echo    Q. Выход
echo.
set "CHOICE="
set /p "CHOICE=Выбор: "
if not defined CHOICE goto :menu
if "%CHOICE%"=="1" goto :m_auto
if "%CHOICE%"=="2" goto :m_pol
if "%CHOICE%"=="3" goto :m_svc
if "%CHOICE%"=="4" goto :m_task
if "%CHOICE%"=="5" goto :m_fw
if "%CHOICE%"=="6" goto :m_clsid
if "%CHOICE%"=="7" goto :m_sec
if "%CHOICE%"=="8" goto :m_hidden
if "%CHOICE%"=="9" goto :m_ads
if /i "%CHOICE%"=="10" goto :m_lnk
if /i "%CHOICE%"=="11" goto :m_br
if /i "%CHOICE%"=="a" goto :m_all
if /i "%CHOICE%"=="а" goto :m_all
if "%CHOICE%"=="0" goto :m_clean
if /i "%CHOICE%"=="q" goto :bye
goto :menu

:m_auto
set /a ADDED=0
call :add_autostart
goto :after

:m_pol
set /a ADDED=0
call :add_policies
goto :after

:m_svc
set /a ADDED=0
call :add_services
goto :after

:m_task
set /a ADDED=0
call :add_tasks
goto :after

:m_fw
set /a ADDED=0
call :add_firewall
goto :after

:m_clsid
set /a ADDED=0
call :add_clsid
goto :after

:m_sec
set /a ADDED=0
call :add_security
goto :after

:m_hidden
set /a ADDED=0
call :add_hidden
goto :after

:m_ads
set /a ADDED=0
call :add_ads
goto :after

:m_lnk
set /a ADDED=0
call :add_shortcuts
goto :after

:m_br
set /a ADDED=0
call :add_browsers
goto :after

:m_all
echo.
echo  ВНИМАНИЕ: будут созданы все тестовые записи, в том числе:
echo    - блокировка диспетчера задач и редактора реестра;
echo    - правило брандмауэра, открывающее входящий порт 45678;
echo    - две несуществующие службы и запись драйвера;
echo    - задача планировщика с несуществующим файлом.
echo  Всё это удаляется пунктом 0.
echo.
set "OK="
set /p "OK=Продолжить? [y/N]: "
if /i "%OK%"=="y" goto :m_all_go
if /i "%OK%"=="д" goto :m_all_go
goto :menu
:m_all_go
set /a ADDED=0
call :add_all
goto :after

:m_clean
echo.
set "OK="
set /p "OK=Удалить все тестовые записи? [y/N]: "
if /i "%OK%"=="y" goto :m_clean_go
if /i "%OK%"=="д" goto :m_clean_go
goto :menu
:m_clean_go
call :cleanup_all
pause
goto :menu

:after
echo.
if "%ADDED%"=="0" (
    echo  Ничего не добавлено, смотрите строки [ОШИБКА].
) else (
    echo  Добавлено записей: %ADDED%
)
echo.
echo  Теперь запустите RUSecurity, нажмите «Сканировать» и проверьте
echo  список найденного. После проверки вернитесь и нажмите 0.
echo.
pause
set /a ADDED=0
goto :menu

:run_all
set /a ADDED=0
call :add_all
echo.
echo  Добавлено записей: %ADDED%
exit /b 0

:run_cleanup
call :cleanup_all
exit /b 0

:bye
endlocal
exit /b 0

rem ============================================================
rem  Добавление
rem ============================================================

:ensure_dirs
if not exist "%TESTDIR%" mkdir "%TESTDIR%" >nul 2>&1
if not exist "%TEMPJUNK%" mkdir "%TEMPJUNK%" >nul 2>&1
exit /b 0

:add_all
call :add_autostart
call :add_policies
call :add_services
call :add_tasks
call :add_firewall
call :add_clsid
call :add_security
call :add_hidden
call :add_ads
call :add_shortcuts
call :add_browsers
exit /b 0

:add_autostart
echo.
echo  --- Автозагрузка ---
call :ensure_dirs
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" RusSecTest_Run_HKLM REG_SZ "%TESTDIR%\missing_hklm.exe" "HKLM Run: файл отсутствует"
call :reg_add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run" RusSecTest_Run_HKLM32 REG_SZ "%TESTDIR%\missing_hklm32.exe" "HKLM-x32 Run: файл отсутствует"
call :reg_add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" RusSecTest_Run_HKCU REG_SZ "%TESTDIR%\missing_hkcu.exe" "HKCU Run: файл отсутствует"
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" RusSecTest_Empty REG_SZ " " "HKLM RunOnce: пустая команда, будет [X]"
call :reg_add_default "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\%GUID_MP%" "%TESTDIR%\missing_mount.exe" "MountPoints2: команда автозапуска"
exit /b 0

:add_policies
echo.
echo  --- Политики ---
call :reg_add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" DisableTaskMgr REG_DWORD 1 "Политика: блокировка диспетчера задач"
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" DisableRegistryTools REG_DWORD 1 "Политика: блокировка редактора реестра"
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" SettingsPageVisibility REG_SZ "hide:windowsupdate" "Политика: скрытая страница обновления"
exit /b 0

:add_services
echo.
echo  --- Службы и драйверы ---
call :ensure_dirs
call :make_service RusSecTestSvc "%TESTDIR%\missing_service.exe" "служба с несуществующим файлом"
call :make_service RusSecTestSvcNoImage "" "служба без ImagePath"
call :make_service RusSecTestDrv "%TESTDIR%\missing_driver.sys" "драйвер с несуществующим файлом" 1
exit /b 0

:add_tasks
echo.
echo  --- Запланированные задачи ---
call :ensure_dirs
schtasks /Delete /TN "RusSecurityTest_Task" /F >nul 2>&1
schtasks /Create /TN "RusSecurityTest_Task" /TR "%TESTDIR%\missing_task.exe" /SC ONCE /ST 23:59 /F >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] задача RusSecurityTest_Task
    exit /b 1
)
echo   [добавлено] задача RusSecurityTest_Task: файл отсутствует
set /a ADDED+=1
exit /b 0

:add_firewall
echo.
echo  --- Брандмауэр ---
call :ensure_dirs
netsh advfirewall firewall delete rule name="RusSecurityTest App" >nul 2>&1
netsh advfirewall firewall add rule name="RusSecurityTest App" dir=in action=allow program="%TESTDIR%\missing_fw.exe" enable=yes >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] правило с несуществующей программой
) else (
    echo   [добавлено] правило с несуществующей программой
    set /a ADDED+=1
)
netsh advfirewall firewall delete rule name="RusSecurityTest Port" >nul 2>&1
netsh advfirewall firewall add rule name="RusSecurityTest Port" dir=in action=allow protocol=TCP localport=45678 >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] правило с открытым портом 45678
) else (
    echo   [добавлено] правило с открытым портом 45678
    set /a ADDED+=1
)
exit /b 0

:add_clsid
echo.
echo  --- Расширения оболочки ---
call :ensure_dirs
call :reg_add_default "HKCU\Software\Classes\CLSID\%GUID_CLSID%\InprocServer32" "%TESTDIR%\missing_shell.dll" "CustomCLSID: DLL отсутствует"
exit /b 0

:add_security
echo.
echo  --- Центр безопасности ---
call :reg_add "HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av\%GUID_AV%" DISPLAYNAME REG_SZ "Rus Test AV" "Центр безопасности: имя продукта"
call :reg_add "HKLM\SOFTWARE\Microsoft\Security Center\Provider\Av\%GUID_AV%" STATE REG_DWORD 0 "Центр безопасности: состояние Disabled"
exit /b 0

:add_hidden
echo.
echo  --- Скрытая программа ---
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RusSecurityTestHidden" DisplayName REG_SZ "Rus Test Adblock Shield" "Скрытая программа: DisplayName"
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RusSecurityTestHidden" DisplayVersion REG_SZ "1.0" "Скрытая программа: версия"
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RusSecurityTestHidden" Publisher REG_SZ "Rus Test" "Скрытая программа: издатель"
call :reg_add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\RusSecurityTestHidden" SystemComponent REG_DWORD 1 "Скрытая программа: флаг Hidden"
exit /b 0

:add_ads
echo.
echo  --- Потоки NTFS ---
call :ensure_dirs
>>"%TEMPJUNK%\ads_target.txt" echo RUSecurity test ADS target
>>"%TEMPJUNK%\ads_target.txt:RusSecTestStream" echo RUSecurity test stream
if errorlevel 1 (
    echo   [ОШИБКА] поток RusSecTestStream
    exit /b 1
)
echo   [добавлено] поток RusSecTestStream у %TEMPJUNK%\ads_target.txt
set /a ADDED+=1
exit /b 0

:add_shortcuts
echo.
echo  --- Ярлыки ---
powershell -NoProfile -Command "$w=New-Object -ComObject WScript.Shell; $a=$w.CreateShortcut($env:APPDATA+'\Microsoft\Windows\Start Menu\Programs\RusSecurityTest.lnk'); $a.TargetPath=$env:ProgramFiles+'\RusSecurityTest\missing.exe'; $a.Save(); $b=$w.CreateShortcut($env:USERPROFILE+'\Desktop\RusSecurityTest.lnk'); $b.TargetPath=$env:TEMP+'\RusSecurityTest\missing_desktop.exe'; $b.Save()" >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] битые ярлыки
    exit /b 1
)
echo   [добавлено] битые ярлыки в меню «Пуск» и на рабочем столе
set /a ADDED+=1
exit /b 0

:add_browsers
echo.
echo  --- Браузеры ---
if not exist "%CHROMEPROF%" mkdir "%CHROMEPROF%" >nul 2>&1
>"%CHROMEPROF%\Preferences" echo {"homepage":"http://rusearch.co/","default_search_provider":{"url":"http://search-cdn.net/?q={searchTerms}","keyword":"rus"},"extensions":{"settings":{"deadbeefdeadbeefdeadbeefdeadbeef":{"manifest":{"name":"Gifty Box"},"path":"C:\\ProgramData\\RusSecurityTest\\GiftyBox"}}}}
if errorlevel 1 (
    echo   [ОШИБКА] профиль Chrome
) else (
    echo   [добавлено] профиль Chrome с подменой поиска и расширением
    set /a ADDED+=1
)
if not exist "%FFPROF%\Extensions" mkdir "%FFPROF%\Extensions" >nul 2>&1
>"%FFPROF%\prefs.js" echo user_pref("browser.startup.homepage", "http://rusearch.co/");
>"%FFPROF%\Extensions\Gifty Box.xpi" echo RUSecurity test extension
if errorlevel 1 (
    echo   [ОШИБКА] профиль Firefox
) else (
    echo   [добавлено] профиль Firefox с подменой домашней страницы
    set /a ADDED+=1
)
exit /b 0

rem ============================================================
rem  Вспомогательные команды добавления
rem ============================================================

:reg_add
reg add "%~1" /v "%~2" /t %~3 /d "%~4" /f >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] %~5
    exit /b 1
)
echo   [добавлено] %~5
set /a ADDED+=1
exit /b 0

:reg_add_default
reg add "%~1" /ve /d "%~2" /f >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] %~3
    exit /b 1
)
echo   [добавлено] %~3
set /a ADDED+=1
exit /b 0

:make_service
set "STYPE=%~4"
if not defined STYPE set "STYPE=16"
set "SKEY=HKLM\SYSTEM\CurrentControlSet\Services\%~1"
reg add "%SKEY%" /v Type /t REG_DWORD /d %STYPE% /f >nul 2>&1
if errorlevel 1 (
    echo   [ОШИБКА] %~3
    exit /b 1
)
reg add "%SKEY%" /v Start /t REG_DWORD /d 4 /f >nul 2>&1
if not "%~2"=="" reg add "%SKEY%" /v ImagePath /t REG_SZ /d "%~2" /f >nul 2>&1
echo   [добавлено] %~3
set /a ADDED+=1
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
echo.
echo  Удалено записей: %REMOVED%
echo  Если что-то осталось, перезагрузите систему и повторите очистку.
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
echo  RUSecurity: тестовый мусор для проверки детекции.
echo.
echo  Запуск без параметров: интерактивное меню.
echo    /all      добавить все тестовые записи
echo    /cleanup  удалить все тестовые записи
echo    /help     эта справка
echo.
exit /b 0
