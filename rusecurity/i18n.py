"""Локализация интерфейса: русский и английский.

Ключ перевода — русская строка, как она написана в интерфейсе. Так проще
поддерживать: непереведённые строки остаются на русском, а не превращаются
в технические ключи. Язык хранится в rusecurity.json и применяется при старте.
"""

from __future__ import annotations

from typing import Dict

from . import config

LANGUAGES = {'ru': 'Русский', 'en': 'English'}

_current = 'ru'

_TRANSLATIONS: Dict[str, str] = {
    # --- оболочка ---------------------------------------------------------
    'Сканирование': 'Scanning',
    'Карантин': 'Quarantine',
    'Журнал': 'Log',
    'Отблагодарить автора': 'Support the author',
    'Создатели: ThreeR и DeepSeek.': 'Creators: ThreeR and DeepSeek.',
    'портативная': 'portable',
    'Сменить язык интерфейса': 'Switch interface language',
    'Язык': 'Language',
    'Язык интерфейса: {name}': 'Interface language: {name}',
    'Дождитесь завершения текущей операции.':
        'Wait for the current operation to finish.',

    # --- экран сканирования ----------------------------------------------
    'Отметьте разделы и нажмите «Сканировать». Найденные элементы можно '
    'исправить выборочно или отметить всё кнопкой «Рекомендовано».':
        'Select the sections and click “Scan”. Found items can be fixed '
        'selectively or all at once with “Recommended”.',
    'Виды сканирования': 'Scan sections',
    'включены все — снимите галочки у ненужных':
        'all enabled — clear the ones you don’t need',
    'Основной отчёт': 'Main report',
    'Дополнительный отчёт': 'Additional report',
    'Сканировать': 'Scan',
    'Готово к сканированию.': 'Ready to scan.',
    'Права: администратор — доступны все разделы (BCD, службы, журналы).':
        'Privileges: administrator — all sections are available (BCD, services, logs).',
    'Права: пользователь — BCD, часть служб и журналы будут недоступны. '
    'Запустите программу от имени администратора.':
        'Privileges: standard user — BCD, some services and logs will be '
        'unavailable. Run the program as administrator.',

    # --- варианты сканирования -------------------------------------------
    'Процессы': 'Processes',
    'Реестр': 'Registry',
    'Задачи': 'Tasks',
    'Службы': 'Services',
    'Драйверы': 'Drivers',
    'Учётные записи': 'Accounts',
    'Центр безопасности': 'Security Center',
    'Программы': 'Programs',
    'Потоки NTFS': 'NTFS streams',
    'Брандмауэр': 'Firewall',
    'Автозагрузка': 'Startup',
    'Ассоциации': 'Associations',
    'Точки восстановления': 'Restore points',
    'Ярлыки': 'Shortcuts',
    'Диски': 'Drives',
    'Ошибки журнала': 'Event log errors',
    'Другие области': 'Other areas',

    # --- результаты -------------------------------------------------------
    'Найденные элементы': 'Found items',
    'Отметьте то, что нужно исправить, или нажмите «Рекомендовано».':
        'Check what to fix, or click “Recommended”.',
    'Изменить разделы': 'Change sections',
    'Найдено элементов: 0': 'Found items: 0',
    'Найдено элементов: {count}': 'Found items: {count}',
    'Подозрительных элементов не найдено': 'No suspicious items found',
    'К разделам сканирования': 'Back to scan sections',
    'Проверены выбранные разделы — исправлять нечего. При необходимости '
    'измените разделы и запустите сканирование заново.':
        'The selected sections were checked — nothing to fix. Change the '
        'sections and run a new scan if needed.',
    'Директивы:': 'Directives:',
    'Точка восстановления': 'Restore point',
    'Перезагрузить систему': 'Restart system',
    'Очистить временные файлы': 'Clear temporary files',
    'Закрыть блокирующие процессы': 'Close blocking processes',
    'CreateRestorePoint: создать точку восстановления перед исправлением.':
        'CreateRestorePoint: create a restore point before fixing.',
    'Reboot: перезагрузить систему после исправления (службы и драйверы).':
        'Reboot: restart the system after fixing (services and drivers).',
    'EmptyTemp: очистить временные файлы и кэши (нужно после браузерных исправлений).':
        'EmptyTemp: clear temporary files and caches (needed after browser fixes).',
    'CloseProcesses: завершить только процессы, чьи файлы выбраны к удалению '
    '(например, браузер перед удалением папки расширения). Остальные программы не трогает.':
        'CloseProcesses: terminate only processes whose files are selected for '
        'deletion (for example, the browser before deleting an extension folder). '
        'Other programs are not touched.',
    'Рекомендовано': 'Recommended',
    'Отметить найденные элементы и включить нужные директивы по анализу':
        'Select found items and enable the directives suggested by the analysis',
    'Исправить': 'Fix',
    'только вручную': 'manual only',
    'Отмечено: {count} {word}.': 'Selected: {count} {word}.',
    'Исправление...': 'Fixing…',
    'Исправление завершено.': 'Fix completed.',
    'Исправление завершено. Запустите сканирование заново, чтобы проверить результат.':
        'Fix completed. Run a new scan to verify the result.',

    # --- исправление ------------------------------------------------------
    'Исправить выбранное?': 'Fix selected items?',
    'Будут изменены системные настройки.': 'System settings will be changed.',
    'Перед изменениями создаются точка восстановления и резервные копии, '
    'удалённое сохраняется в карантин.':
        'A restore point and backups are created before changes; removed items '
        'are kept in quarantine.',
    'После исправления потребуется перезагрузка — программа предложит её.':
        'A restart will be required after fixing — the program will offer it.',
    'Настройки браузера правятся в файлах профиля, поэтому браузер '
    'будет закрыт; вкладки восстановятся при следующем запуске.':
        'Browser settings are edited in profile files, so the browser will be '
        'closed; tabs will be restored on the next start.',
    'Требуется перезагрузка': 'Restart required',
    'Для завершения исправления нужно перезагрузить компьютер.':
        'The computer must be restarted to complete the fix.',
    'Можно перезагрузить сейчас (через 30 секунд) или отложить '
    'и сделать это вручную позже.':
        'You can restart now (in 30 seconds) or postpone and do it manually later.',
    'Перезагрузить сейчас': 'Restart now',
    'Позже': 'Later',
    'Перезагрузка запланирована через 30 секунд. Отменить: shutdown /a.':
        'Restart scheduled in 30 seconds. Cancel with: shutdown /a.',
    'Не удалось запланировать перезагрузку. Перезагрузите компьютер вручную.':
        'Could not schedule the restart. Restart the computer manually.',
    'Требуется перезагрузка — перезагрузите компьютер вручную позже.':
        'Restart required — restart the computer manually later.',
    'Директивы: {names}': 'Directives: {names}',
    'Исправление завершено с ошибками': 'Fix completed with errors',
    'Исправление выполнено': 'Fix completed',
    'Исправление не выполнено': 'Fix not completed',
    'Итог: изменено {changed}, ошибок {failed}, вручную {manual}':
        'Result: changed {changed}, failed {failed}, manual {manual}',
    'Подробности — в разделе «Журнал».': 'See the “Log” section for details.',
    'Подробности и пути резервных копий — в разделе «Журнал».':
        'Details and backup paths are in the “Log” section.',
    '{message}\n\nПодробности — в разделе «Журнал».':
        '{message}\n\nSee the “Log” section for details.',

    # --- таблица найденного ----------------------------------------------
    'Категория': 'Category',
    'Действие': 'Action',
    'Элемент': 'Item',

    # --- сканирование -----------------------------------------------------
    'Сканирование...': 'Scanning…',
    'Сканирование завершено за {seconds} с.': 'Scan completed in {seconds} s.',
    'Собрано записей: {entries} в основном отчёте{addition} · время: {seconds} с':
        'Records collected: {entries} in the main report{addition} · time: {seconds} s',
    ', {count} в дополнительном': ', {count} in the additional report',
    'Ошибка: {message}': 'Error: {message}',
    'Сканирование не удалось': 'Scan failed',
    'Ничего не выбрано': 'Nothing selected',
    'Отметьте хотя бы один раздел сканирования.':
        'Select at least one scan section.',

    # --- прогресс сканера -------------------------------------------------
    'Запланированные задачи': 'Scheduled tasks',
    'Реестр: автозагрузка': 'Registry: startup',
    'Реестр: политики': 'Registry: policies',
    'Установленные программы': 'Installed programs',
    'Пользовательские CLSID': 'Custom CLSIDs',
    'Альтернативные потоки данных': 'Alternate data streams',
    'Ассоциации файлов': 'File associations',
    'Браузеры Chromium': 'Chromium browsers',
    'Браузер Firefox': 'Firefox browser',

    # --- карантин ---------------------------------------------------------
    'Всё, что удалил фиксер, лежит в Reports\\Backups. Можно вернуть файлы '
    'и ветки реестра, удалить выбранные записи или очистить карантин полностью.':
        'Everything the fixer removed is stored in Reports\\Backups. You can '
        'restore files and registry keys, delete selected entries or clear the '
        'whole quarantine.',
    'Когда': 'When',
    'Тип': 'Type',
    'Что вернуть': 'What to restore',
    'Обновить': 'Refresh',
    'Вернуть выбранное': 'Restore selected',
    'Удалить выбранное': 'Delete selected',
    'Очистить карантин': 'Clear quarantine',
    'Удалить из карантина?': 'Delete from quarantine?',
    'Безвозвратно удалить записей: {count}': 'Permanently delete {count} entries',
    'Файлы и .reg-бэкапы будут удалены. Восстановить их после этого нельзя.':
        'Files and .reg backups will be deleted. They cannot be restored afterwards.',
    'Очистить карантин?': 'Clear quarantine?',
    'Карантин будет очищен полностью.': 'The quarantine will be cleared completely.',
    'Будет удалено записей: {count}. Все файлы и .reg-бэкапы исчезнут '
    'без возможности восстановления.':
        'Entries to delete: {count}. All files and .reg backups will be gone '
        'permanently.',
    'Восстановление...': 'Restoring…',
    'Удаление...': 'Deleting…',
    'Очистка карантина...': 'Clearing quarantine…',
    'Удалено: {count}': 'Deleted: {count}',
    ', ошибок: {count}': ', errors: {count}',
    'Не удалось удалить': 'Delete failed',
    'Карантин уже пуст': 'Quarantine is already empty',
    'реестр': 'registry',
    'файл': 'file',
    'hosts': 'hosts',
    'Записей: {count}': 'Entries: {count}',
    'Карантин пуст': 'Quarantine is empty',
    'Сначала выделите строки': 'Select rows first',
    'Вернуть из карантина?': 'Restore from quarantine?',
    'Будет восстановлено объектов: {count}': 'Objects to restore: {count}',
    'Файлы вернутся на прежние места, hosts будет перезаписан, ветки реестра '
    'импортируются из бэкапа. Существующие файлы не перезаписываются, кроме hosts.':
        'Files will be returned to their original locations, hosts will be '
        'overwritten, registry keys will be imported from the backup. Existing '
        'files are not overwritten, except hosts.',

    # --- журнал -----------------------------------------------------------
    'Подробный лог: время запуска, разделы сканирования, найденные элементы, '
    'исправления, ошибки и резервные копии. Здесь же можно откатить '
    'сделанное исправление.':
        'Detailed log: start time, scan sections, found items, fixes, errors '
        'and backups. A finished fix can be rolled back here too.',
    'Очистить журнал': 'Clear log',
    'Удалить все записи журнала': 'Delete all log entries',
    'Очистить журнал?': 'Clear log?',
    'Все записи журнала будут удалены.': 'All log entries will be deleted.',

    # --- статусы и категории ---------------------------------------------
    'выполнено': 'done',
    'ошибка': 'failed',
    'не найдено': 'not found',
    'вручную': 'manual',
    'пропущено': 'skipped',
    'план': 'planned',
    'процессы': 'processes',
    'нет': 'none',
    'Политики': 'Policies',
    'Расширения оболочки': 'Shell extensions',
    'Браузеры': 'Browsers',
    'Службы и драйверы': 'Services and drivers',
    'Файлы': 'Files',
    'Прочее': 'Other',

    # --- виды действий фиксера -------------------------------------------
    'значения реестра': 'registry values',
    'ключи реестра': 'registry keys',
    'восстановление настроек': 'settings restore',
    'задачи': 'tasks',
    'правила брандмауэра': 'firewall rules',
    'записи Центра безопасности': 'Security Center entries',
    'ярлыки': 'shortcuts',
    'ярлыки автозагрузки': 'startup shortcuts',
    'файлы и папки': 'files and folders',
    'альтернативные потоки': 'alternate streams',
    'очистка Temp': 'Temp cleanup',
    'экспорт веток': 'key export',
    'точка восстановления': 'restore point',
    'перезагрузка': 'reboot',
    'служебные строки': 'service lines',

    # --- причины «только вручную» ----------------------------------------
    'политики групповых политик удаляются вручную':
        'group policies are removed manually',
    'настройки браузера правятся в его профиле':
        'browser settings are edited in its profile',
    'расширение оболочки удаляется вручную':
        'shell extension is removed manually',
    'неизвестная команда fixlist': 'unknown fixlist command',
    'не разобрать путь реестра': 'cannot parse registry path',
    'нет имени значения реестра': 'no registry value name',

    # --- откат исправлений ------------------------------------------------
    'Откат исправлений': 'Rollback',
    'Каждое исправление сохраняет бэкап — выберите его, чтобы вернуть '
    'файлы и реестр.':
        'Every fix keeps a backup — select one to restore its files and '
        'registry keys.',
    'Что изменено': 'Changes',
    'Объектов': 'Items',
    'файлы': 'files',
    'реестр': 'registry',
    'значение реестра': 'registry value',
    'файл настроек': 'settings file',
    'настройки браузера': 'browser settings',
    'расширения': 'extensions',
    'Доступно откатов: {count}': 'Available rollbacks: {count}',
    'Откатывать нечего — исправлений с бэкапами нет':
        'Nothing to roll back — no fixes with backups',
    'Откатить выбранное': 'Roll back selected',
    'Вернуть файлы и параметры реестра из выбранного исправления':
        'Restore files and registry values from the selected fix',
    'Сначала выделите исправление': 'Select a fix first',
    'В бэкапе этого исправления нет данных':
        'This backup has no recoverable items',
    'Откатить исправление от {created}?': 'Roll back the fix from {created}?',
    'Будут возвращены объекты из бэкапа: {count}.':
        'Items will be restored from the backup: {count}.',
    'Файлы вернутся на прежние места, ветки реестра импортируются, '
    'hosts перезаписывается. Службы и драйверы заработают после '
    'перезагрузки.':
        'Files return to their original places, registry keys are imported, '
        'hosts is overwritten. Services and drivers will work after a reboot.',
    'Откат...': 'Rolling back...',
    'Откат выполнен': 'Rollback completed',
    'Обработано объектов: {count}.\n\nСлужбы и драйверы заработают после '
    'перезагрузки.':
        'Items processed: {count}.\n\nServices and drivers will work after a '
        'reboot.',
    'Откат завершён с ошибками': 'Rollback finished with errors',
    'Часть объектов вернуть не удалось. Подробности — в журнале и в '
    'restore-log.txt папки бэкапа.':
        'Some items could not be restored. See the log and restore-log.txt in '
        'the backup folder.',
    'Откат не выполнен': 'Rollback failed',

    # --- проверка безопасности -------------------------------------------
    'Проверка безопасности': 'Security check',
    'Проверяет параметры, которые ослабляют защиту: учётные данные, '
    'удалённый доступ, SMB, брандмауэр, журналирование и обновления. '
    'Ниже — весь список проверок; нажмите на строку, чтобы прочитать '
    'описание до запуска.':
        'Checks the settings that weaken protection: credentials, remote '
        'access, SMB, firewall, logging and updates. The full list of checks '
        'is shown below — click a row to read its description before running.',
    'Проверка ещё не запускалась — показаны все проверяемые параметры.':
        'The check has not run yet — all checked parameters are listed below.',
    'Проверить': 'Check',
    'Готово к проверке.': 'Ready to check.',
    'Идёт проверка...': 'Checking...',
    'Проверка завершена.': 'Check completed.',
    'Проверка не выполнена': 'Check failed',
    'Отклонений не найдено': 'No deviations found',
    'Все проверяемые параметры соответствуют рекомендуемым значениям.':
        'All checked settings match the recommended values.',
    'Отклонений: {count} · высокая {high} · средняя {medium} · низкая {low}':
        'Deviations: {count} · high {high} · medium {medium} · low {low}',
    'Отметить всё': 'Select all',
    'Отметить все проверки, которые исправляются автоматически':
        'Select every check that can be fixed automatically',
    'Отметить только важные проверки — исправления без риска для сети '
    'и устройств':
        'Select only the important checks — fixes that do not risk the '
        'network or devices',
    'рекомендуется к исправлению': 'recommended for fixing',
    'необязательная проверка': 'optional check',
    'Сейчас: {current} · должно быть: {expected}':
        'Current: {current} · expected: {expected}',
    'Почему исправлять: {reason}': 'Why fix: {reason}',
    'Возможные минусы: {risk}': 'Possible downsides: {risk}',
    'Как исправить: {how}': 'How to fix: {how}',
    'Команда PowerShell (от администратора):':
        'PowerShell command (run as administrator):',
    'Изменение обратимо: перед исправлением сохраняется копия ветки реестра.':
        'The change is reversible: the registry key is backed up before fixing.',
    'Отмечены рекомендуемые проверки: {count} из {total} найденных.':
        'Recommended checks selected: {count} of {total} found.',
    'Раздел': 'Section',
    'Проверка': 'Check',
    'Сейчас': 'Current',
    'Должно быть': 'Expected',
    'Важность': 'Severity',
    'высокая': 'high',
    'средняя': 'medium',
    'низкая': 'low',
    'исправляется только вручную': 'fixed manually only',
    'Исправлять нечего': 'Nothing to fix',
    'Выбранные отклонения исправляются только вручную.':
        'The selected deviations can only be fixed manually.',
    'Будут изменены параметры безопасности системы.':
        'System security settings will be changed.',
    'Отклонений выбрано: {count} (высокая {high}, средняя {medium}, '
    'низкая {low}).':
        'Selected deviations: {count} (high {high}, medium {medium}, '
        'low {low}).',
    'Перед изменениями создаются точка восстановления и резервные копии '
    'веток реестра, поэтому исправление обратимо.':
        'A restore point and registry backups are created first, so the '
        'change can be reverted.',
    'Часть изменений вступит в силу после перезагрузки — '
    'программа предложит её.':
        'Some changes take effect after a reboot — the program will offer it.',
    'Запустите проверку заново, чтобы убедиться в результате.':
        'Run the check again to confirm the result.',
    'Создать точку восстановления перед исправлением.':
        'Create a restore point before fixing.',
    'Запланировать перезагрузку не удалось — перезагрузите вручную.':
        'Could not schedule the reboot — restart manually.',

    # --- разделы проверки безопасности -----------------------------------
    'Учётные данные и аутентификация': 'Credentials and authentication',
    'Удалённый доступ': 'Remote access',
    'Сетевое окружение': 'Network environment',
    'Журналирование': 'Logging',
    'Обновления и прочее': 'Updates and other',

    # --- проверки безопасности -------------------------------------------
    'Уровень проверки подлинности NTLM': 'NTLM authentication level',
    'Защита LSASS (LSA protection)': 'LSASS protection (LSA protection)',
    'Запрет анонимного перечисления': 'Anonymous enumeration disabled',
    'Запрет анонимного доступа к SAM': 'Anonymous SAM access disabled',
    'Запрет входа с пустым паролем': 'Blank password logon disabled',
    'Запрет хранения LM-хэшей': 'LM hash storage disabled',
    'Запрет хранения паролей в WDigest': 'WDigest password storage disabled',
    'Ограничение исходящего NTLM': 'Outgoing NTLM restriction',
    'Удалённый рабочий стол отключён': 'Remote Desktop is disabled',
    'RDP требует Network Level Authentication':
        'RDP requires Network Level Authentication',
    'RDP использует TLS': 'RDP uses TLS',
    'Минимальный уровень шифрования RDP': 'Minimum RDP encryption level',
    'Сервер SMB1 отключён': 'SMB1 server disabled',
    'Анонимный доступ к сетевым папкам запрещён':
        'Anonymous access to network shares disabled',
    'Подпись SMB для входящих подключений': 'SMB signing for incoming connections',
    'Подпись SMB для исходящих подключений': 'SMB signing for outgoing connections',
    'LLMNR отключён': 'LLMNR disabled',
    'Брандмауэр: профиль «Домен»': 'Firewall: domain profile',
    'Брандмауэр: профиль «Частный»': 'Firewall: private profile',
    'Брандмауэр: профиль «Публичный»': 'Firewall: public profile',
    'Журнал блоков PowerShell': 'PowerShell script block log',
    'Журнал модулей PowerShell': 'PowerShell module log',
    'Стенограмма PowerShell': 'PowerShell transcript',
    'Размер журнала Security': 'Security log size',
    'Служба журналов событий включена': 'Event log service is enabled',
    'Автоматическое обновление не отключено': 'Automatic updates are not disabled',
    'Сервер обновлений не подменён': 'Update server is not redirected',

    # --- отмена, фильтры, исключения и экспорт ----------------------------
    'Остановить': 'Stop',
    'Останавливаю…': 'Stopping…',
    'Сканирование отменено.': 'Scan cancelled.',
    'Поиск по найденному…': 'Search found items…',
    'Все категории': 'All categories',
    'Ничего не найдено по фильтру.': 'Nothing matches the filter.',
    'Показано: {shown} из {total}': 'Shown: {shown} of {total}',
    'Скрыто исключениями: {count}': 'Hidden by exclusions: {count}',
    'Исключений: {count}, в этом скане совпадений нет':
        'Exclusions: {count}, no matches in this scan',
    'Все найденные элементы скрыты исключениями: {count}. '
    'Верните их через «Исключения…».':
        'All found items are hidden by exclusions: {count}. '
        'Restore them via “Exclusions…”.',
    'Исключения…': 'Exclusions…',
    'Исключения ({count})': 'Exclusions ({count})',
    'Посмотреть скрытые элементы и вернуть их в результаты':
        'View hidden items and restore them to the results',
    'Исключить выбранное': 'Exclude selected',
    'Скрыть выбранные элементы при следующих сканированиях':
        'Hide the selected items in future scans',
    'Исключено: {count}': 'Excluded: {count}',
    'Исключения': 'Exclusions',
    'Скрытые элементы не показываются при следующих сканированиях.':
        'Hidden items are not shown in future scans.',
    'Снимите галочки с тех, что нужно вернуть в результаты проверки.':
        'Clear the checkboxes of the items to restore.',
    'Элемент': 'Item',
    'Вернуть выбранные': 'Restore selected',
    'Очистить всё': 'Clear all',
    'Закрыть': 'Close',
    'Отметьте элементы, которые нужно вернуть.':
        'Check the items to restore.',
    'Очистить исключения?': 'Clear exclusions?',
    'Все скрытые элементы снова появятся в результатах.':
        'All hidden items will appear in the results again.',
    'Исключить из проверок': 'Exclude from checks',
    'Открыть папку файла': 'Open file folder',
    'Открыть в Regedit': 'Open in Regedit',
    'Скопировать путь': 'Copy path',
    'Скопировать строку': 'Copy line',
    'Путь реестра сокращён в отчёте — проверьте в Regedit вручную':
        'The registry path is shortened in the report — check it in Regedit manually',
    'Путь не найден': 'Path not found',
    'Папка не существует: {path}': 'The folder does not exist: {path}',
    'Путь скопирован — вставьте его в адресную строку Regedit (Ctrl+L).':
        'Path copied — paste it into the Regedit address bar (Ctrl+L).',
    'Скопировано.': 'Copied.',
    'Экспорт': 'Export',
    'Сводка (Markdown)': 'Summary (Markdown)',
    'Архив для поддержки (ZIP)': 'Support archive (ZIP)',
    'Сохранить сводку': 'Save summary',
    'Сохранить архив для поддержки': 'Save support archive',
    'Сводка сохранена': 'Summary saved',
    'Сводка сохранена: {path}': 'Summary saved: {path}',
    'Архив сохранён': 'Archive saved',
    'Архив сохранён: {path}': 'Archive saved: {path}',
    'Не удалось сохранить сводку': 'Could not save the summary',
    'Не удалось сохранить архив': 'Could not save the archive',

    # --- предпросмотр исправления -----------------------------------------
    'Предпросмотр исправления': 'Fix preview',
    'Проверьте план перед применением.':
        'Review the plan before applying.',
    'Действие': 'Action',
    'Объект': 'Object',
    'Что будет сделано': 'What will be done',
    'Будет изменено: {planned} · вручную: {manual} · не найдено: {missing}':
        'Will be changed: {planned} · manual: {manual} · not found: {missing}',
    'ошибок: {count}': 'errors: {count}',
    'Применить': 'Apply',
    'Отмена': 'Cancel',
    'В плане нет изменений — исправлять нечего.':
        'There are no changes in the plan — nothing to fix.',
    'Предпросмотр не удался': 'Preview failed',
    '{message}\n\nИсправление не запущено.':
        '{message}\n\nThe fix was not started.',
}


def current() -> str:
    return _current


def load() -> str:
    """Прочитать язык из настроек; неизвестное значение — русский."""
    global _current
    code = str(config.load().get('language') or 'ru').lower()
    _current = code if code in LANGUAGES else 'ru'
    return _current


def set_language(code: str, save: bool = True) -> str:
    global _current
    if code not in LANGUAGES:
        return _current
    _current = code
    if save:
        try:
            settings = config.load()
            settings['language'] = code
            config.save(settings)
        except OSError:
            pass
    return _current


def tr(text: str, **kwargs) -> str:
    """Перевести строку; без перевода вернуть исходную."""
    result = text if _current == 'ru' else _TRANSLATIONS.get(text, text)
    return result.format(**kwargs) if kwargs else result


def decimal(value: float) -> str:
    """Десятичный разделитель выбранного языка."""
    text = f'{value:.1f}'
    return text.replace('.', ',') if _current == 'ru' else text


def element_word(count: int) -> str:
    if _current == 'en':
        return 'element' if count == 1 else 'elements'
    if count % 10 == 1 and count % 100 != 11:
        return 'элемент'
    if 2 <= count % 10 <= 4 and not 12 <= count % 100 <= 14:
        return 'элемента'
    return 'элементов'


def translate_widgets(root) -> None:
    """Перевести статические подписи готового окна (один раз при старте)."""
    from PySide6.QtWidgets import QCheckBox, QLabel, QPushButton, QTableWidget

    for widget in root.findChildren(QLabel) + root.findChildren(QPushButton) + \
            root.findChildren(QCheckBox):
        if widget.objectName() == 'Lang':
            continue
        text = widget.text()
        if text:
            widget.setText(tr(text))
        tip = widget.toolTip()
        if tip:
            widget.setToolTip(tr(tip))
    for table in root.findChildren(QTableWidget):
        for column in range(table.columnCount()):
            item = table.horizontalHeaderItem(column)
            if item is not None and item.text():
                item.setText(tr(item.text()))
