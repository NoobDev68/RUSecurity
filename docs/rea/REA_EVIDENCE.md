# REA: доказательная база по FRST64.exe

Здесь собраны статические наблюдения REA по `FRST\FRST64.exe` (v17-11-2026),
на которые опирается RUSecurity. Глубокий дизассемблер (Ghidra/IDA/Hopper)
не использовался: формат отчёта восстанавливается по корпусу реальных отчётов,
а REA подтверждает, как устроен сам FRST.

## Команды

```powershell
npx -y rea-agents@latest inspect-artifact FRST\FRST64.exe --json
npx -y rea-agents@latest inspect-pe-imports FRST\FRST64.exe --json
npx -y rea-agents@latest inspect-pe-certificates FRST\FRST64.exe --json
```

Сырые ответы: `frst64-artifact.json`, `frst64-imports.json`,
`frst64-certificates.json` в этой папке.

## Наблюдения

| Свойство | Значение |
| --- | --- |
| Формат | PE32+ (x64), machine `0x8664` |
| SHA-256 | `01bf81dc7ba1c24db129bde1e548b694a15ee863718f88c0bc708c7aa3a547a1` |
| Размер | 2 460 160 байт |
| Authenticode-таблица | отсутствует (`IMAGE_DIRECTORY_ENTRY_SECURITY` не найден) |
| Imphash (pefile) | `638af1c562ad8f76992023c9692ec222` |
| Импортируемых DLL | 18 |

Встроенной подписи в файле нет. REA не проверяет каталожные подписи, поэтому
вывод «файл не подписан» здесь ограничен: `inspect-pe-certificates` сообщает
только об отсутствии таблицы сертификатов.

## Импорты как карта поведения

- `ADVAPI32.dll` — `RegEnumKeyExW`, `RegEnumValueW`, `RegQueryValueExW`,
  `RegDeleteKeyW`, `RegSetValueExW`, `RegConnectRegistryW`: чтение и правка
  реестра (автозагрузка, службы, политики), в том числе удалённых кустов.
- `ole32.dll` / `OLEAUT32.dll` — `CoCreateInstance`, `CLSIDFromString`,
  `CLSIDFromProgID`, `CreateStreamOnHGlobal`: COM (планировщик задач, WMI,
  оболочка).
- `SHELL32.dll` — `ShellExecuteExW`, `SHFileOperationW`, `SHGetPathFromIDListW`,
  `SHGetSpecialFolderLocation`: запуск процессов и работа с оболочкой/ярлыками.
- `COMCTL32.dll` (`ImageList_*`, `InitCommonControlsEx`), `UxTheme.dll`,
  `USER32.dll`/`GDI32.dll` — VCL-приложение Delphi с собственным интерфейсом.
- `WININET.dll` — сетевые запросы (обновление версии/базы), `WSOCK32.dll` —
  сетевые проверки, `IPHLPAPI.dll` — ICMP.
- `PSAPI.DLL`, `KERNEL32.dll` — процессы и память.

Практический вывод для сканера: те же источники данных (реестр через `winreg`,
COM через `ctypes`, файловая система и запуск `schtasks`), но без правки системы.

## Почему формат берётся из корпуса, а не из бинарника

- Строки вида `==================== Процессы (Все) =================` в файле не
  встречаются: раздел `.rsrc` занимает 1,4 МБ при энтропии ≈ 8.0, то есть
  шаблоны отчёта лежат в сжатом ресурсе и собираются во время работы.
- В корпусе `Parse_FRST_SafeZone/pairs` — 1078 отчётов FRST и 1066 Addition с
  русскими и английскими заголовками. Это точнее и дешевле, чем реверс
  шаблонов: форматтеры `rusecurity/core/sections/*` сверены с этими строками.

## Что осталось за рамками

- Декомпиляция логики FRST (нужен Ghidra/IDA/Hopper как провайдер REA).
- Проверка каталожной подписи самого FRST64.exe (REA этого не делает).
- Восстановление точных эвристик, по которым FRST ставит `<==== ВНИМАНИЕ`:
  в RUSecurity такие метки ставятся только для явно ограничивающих
  политик, остальное оставлено на анализ GenFix.
