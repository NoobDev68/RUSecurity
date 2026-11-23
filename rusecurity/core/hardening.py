"""Проверка безопасности: аудит рекомендованных параметров Windows.

Функция работает независимо от сканирования системы: читает заранее известный
набор параметров, сравнивает их с рекомендуемыми значениями и формирует
fixlist из строк ``Reg: reg add ...``, которые выполняет штатный фиксер
(бэкап ветки, точка восстановления, журнал — как при обычном исправлении).

Здесь только то, чего нет в детекторах GenFix: ослабление учётных данных,
удалённого доступа, SMB, брандмауэра, журналирования и обновлений. UAC,
SmartScreen и отключение Defender уже разбираются по отчёту и намеренно
не дублируются.

Проверка консервативная: находкой считается только значение, которое
действительно ослабляет защиту. Для параметров, чьё отсутствие означает
безопасное значение Windows по умолчанию, ставится ``missing='ok'``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Tuple

from . import winapi

ISSUE_HIGH = 'high'
ISSUE_MEDIUM = 'medium'
ISSUE_LOW = 'low'

SEVERITY_LABELS = {
    ISSUE_HIGH: 'высокая',
    ISSUE_MEDIUM: 'средняя',
    ISSUE_LOW: 'низкая',
}
_SEVERITY_ORDER = {ISSUE_HIGH: 0, ISSUE_MEDIUM: 1, ISSUE_LOW: 2}

SEC_CREDENTIALS = 'Учётные данные и аутентификация'
SEC_REMOTE = 'Удалённый доступ'
SEC_NETWORK = 'Сетевое окружение'
SEC_FIREWALL = 'Брандмауэр'
SEC_LOGGING = 'Журналирование'
SEC_OTHER = 'Обновления и прочее'

SECTIONS: Tuple[str, ...] = (SEC_CREDENTIALS, SEC_REMOTE, SEC_NETWORK,
                             SEC_FIREWALL, SEC_LOGGING, SEC_OTHER)
_SECTION_ORDER = {name: index for index, name in enumerate(SECTIONS)}

_OPS: Dict[str, Callable[[object, object], bool]] = {
    '==': lambda a, b: a == b,
    '!=': lambda a, b: a != b,
    '>=': lambda a, b: a >= b,
    '<=': lambda a, b: a <= b,
}

# --- пути реестра ----------------------------------------------------------
_LSA = r'SYSTEM\CurrentControlSet\Control\Lsa'
_RDP_TS = r'SYSTEM\CurrentControlSet\Control\Terminal Server'
_RDP_TCP = r'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
_LANMAN_SERVER = r'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
_LANMAN_STATION = r'SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
_FIREWALL = r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
_EVENTLOG = r'SYSTEM\CurrentControlSet\Services\EventLog'
_PS_POLICY = r'SOFTWARE\Policies\Microsoft\Windows\PowerShell'
_WU = r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
_DNSCLIENT = r'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
_DEFENDER = r'SOFTWARE\Microsoft\Windows Defender'

_SECURITY_LOG_MIN_BYTES = 20971520  # 20 МБ — размер журнала Security по умолчанию


@dataclass(frozen=True)
class Rule:
    """Одно проверяемое значение: что читать и какое значение считается нормой."""

    id: str
    section: str
    path: str
    name: str
    title: str
    op: str
    expected: object
    fix_value: str = ''
    severity: str = ISSUE_MEDIUM
    missing: str = 'ok'   # 'ok' — отсутствие значения безопасно, 'bad' — нет
    kind: str = 'REG_DWORD'
    note: str = ''
    risk: str = ''        # возможные минусы исправления — для описания в GUI
    how_to: str = ''      # как исправить вручную: путь в интерфейсе Windows
    command: str = ''     # то же командой PowerShell
    reboot: bool = False
    needs_rdp: bool = False
    expect_label: str = ''
    view: int = winapi.VIEW_64
    # «Рекомендовано» отмечает только проверки без побочных эффектов для сети,
    # устройств и дискового пространства.
    recommended: bool = True

    @property
    def fixable(self) -> bool:
        return bool(self.fix_value)

    def violates(self, value: object) -> bool:
        if value is None:
            return self.missing == 'bad'
        try:
            return not _OPS[self.op](value, self.expected)
        except TypeError:
            return True


def _r(rid: str, section: str, path: str, name: str, title: str, op: str,
       expected: object, fix_value: str = '', severity: str = ISSUE_MEDIUM,
       missing: str = 'ok', note: str = '', risk: str = '', how_to: str = '',
       command: str = '', reboot: bool = False,
       needs_rdp: bool = False, expect_label: str = '',
       kind: str = 'REG_DWORD', recommended: bool = True) -> Rule:
    return Rule(rid, section, path, name, title, op, expected, fix_value,
                severity, missing, kind, note, risk, how_to, command, reboot,
                needs_rdp, expect_label, recommended=recommended)


# ===========================================================================
#  Правила проверки
# ===========================================================================
RULES: Tuple[Rule, ...] = (
    # --- учётные данные и аутентификация ---------------------------------
    _r('lsa_lmcompat', SEC_CREDENTIALS, _LSA, 'LmCompatibilityLevel',
       'Уровень проверки подлинности NTLM', '>=', 3, '5', ISSUE_HIGH,
       note='Ниже 3 разрешены LM и NTLMv1 — их хэши подбираются за минуты.',
       risk='Ставится 5 (только NTLMv2): старые NAS, принтеры и серверы '
            'Windows XP/2003, которые умеют только NTLMv1/LM, перестанут '
            'аутентифицироваться.'),
    _r('lsa_runasppl', SEC_CREDENTIALS, _LSA, 'RunAsPPL',
       'Защита LSASS (LSA protection)', '>=', 1, '1', ISSUE_MEDIUM,
       missing='bad', reboot=True, expect_label='включена',
       note='Не даёт читать память LSASS — оттуда забирают дампы учётных '
            'записей.',
       risk='Нужна перезагрузка. Сторонние антивирусы, средства резервного '
            'копирования и отладчики, читающие память LSASS, могут перестать '
            'работать; при проблемах со входом удалите RunAsPPL и '
            'перезагрузитесь. Значение 2 дополнительно включает UEFI-блокировку.'),
    _r('lsa_restrictanon', SEC_CREDENTIALS, _LSA, 'RestrictAnonymous',
       'Запрет анонимного перечисления', '==', 1, '1', ISSUE_MEDIUM,
       missing='bad',
       note='Анонимный доступ позволяет перечислять учётные записи и ресурсы.',
       risk='Сетевые устройства и программы, которые подключаются без учётной '
            'записи (старые NAS, принтеры), могут перестать видеть общие '
            'ресурсы.'),
    _r('lsa_restrictanonsam', SEC_CREDENTIALS, _LSA, 'RestrictAnonymousSAM',
       'Запрет анонимного доступа к SAM', '==', 1, '1', ISSUE_MEDIUM,
       missing='bad',
       note='Иначе список учётных записей можно получить анонимным '
            'подключением к SAM.',
       risk='Программы, которые перечисляют пользователей без входа в '
            'систему, перестанут их видеть.'),
    _r('lsa_limitblank', SEC_CREDENTIALS, _LSA, 'LimitBlankPasswordUse',
       'Запрет входа с пустым паролем', '==', 1, '1', ISSUE_MEDIUM,
       note='Учётные записи без пароля доступны для входа по сети без '
            'аутентификации.',
       risk='Учётные записи с пустым паролем перестанут входить по сети; '
            'локальный вход останется.'),
    _r('lsa_nolmhash', SEC_CREDENTIALS, _LSA, 'NoLMHash',
       'Запрет хранения LM-хэшей', '==', 1, '1', ISSUE_MEDIUM,
       note='LM-хэш обрезает пароль до 14 символов и подбирается за минуты.',
       risk='Уже сохранённые LM-хэши остаются до смены пароля; системы, '
            'которым нужен LM (Windows 9x/XP, старые сетевые устройства), не '
            'смогут аутентифицироваться.'),
    _r('lsa_wdigest', SEC_CREDENTIALS,
       r'SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest',
       'UseLogonCredential', 'Запрет хранения паролей в WDigest', '==', 0, '0',
       ISSUE_MEDIUM,
       note='WDigest держит пароли в открытом виде в памяти LSASS — их '
            'забирает Mimikatz.',
       risk='Редкие программы, которые получают пароль через WDigest (старые '
            'VPN/SSO-клиенты), могут запросить учётные данные заново.'),
    # report-only: «Запретить весь исходящий NTLM» ломает доступ к сетевым
    # ресурсам, где используется NTLM, поэтому только показываем
    _r('lsa_restrictntlm', SEC_CREDENTIALS, _LSA + r'\MSV1_0',
       'RestrictSendingNTLMTraffic', 'Ограничение исходящего NTLM',
       '>=', 2, severity=ISSUE_LOW, missing='bad',
       expect_label='не менее 2', recommended=False,
       note='Без ограничения учётные данные могут уйти на чужой сервер.',
       risk='Значение 2 запрещает весь исходящий NTLM: доступ к сетевым '
            'папкам и принтерам, которые не используют Kerberos, пропадёт — '
            'включайте осознанно.',
       how_to='secpol.msc → Локальные политики → Параметры безопасности → '
              '«Сетевая безопасность: ограничить NTLM...» → «Требовать NTLMv2 '
              'и отказ от LM и NTLM» или «Отклонить всё».',
       command=r"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
               r"\MSV1_0' -Name RestrictSendingNTLMTraffic -Value 2 "
               r"-Type DWord"),

    # --- удалённый доступ -------------------------------------------------
    # report-only: RDP выключить автоматически нельзя — это решение пользователя
    _r('rdp_enabled', SEC_REMOTE, _RDP_TS, 'fDenyTSConnections',
       'Удалённый рабочий стол отключён', '==', 1,
       severity=ISSUE_LOW, recommended=False,
       note='Удалённый рабочий стол включён: до входа в систему доступен экран '
            'блокировки и часть сетевых служб.',
       risk='Если вы подключаетесь к этому компьютеру удалённо, доступ '
            'пропадёт.',
       how_to='Параметры → Система → Удалённый рабочий стол → выключить '
              '«Удалённый рабочий стол».',
       command=r"Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control"
               r"\Terminal Server' -Name fDenyTSConnections -Value 1"),
    _r('rdp_nla', SEC_REMOTE, _RDP_TCP, 'UserAuthentication',
       'RDP требует Network Level Authentication', '==', 1, '1', ISSUE_HIGH,
       missing='bad', needs_rdp=True,
       note='Без NLA до входа в систему доступен экран блокировки и часть '
            'сетевых служб.',
       risk='Клиенты без поддержки NLA (старые Windows, аппаратные терминалы, '
            'сторонние RDP-клиенты) не смогут подключиться.'),
    _r('rdp_layer', SEC_REMOTE, _RDP_TCP, 'SecurityLayer',
       'RDP использует TLS', '>=', 2, '2', ISSUE_MEDIUM, needs_rdp=True,
       note='Без TLS трафик RDP передаётся без шифрования (уязвимость '
            'CredSSP/Man-in-the-Middle).',
       risk='Клиенты, которые не поддерживают TLS (Windows XP/2003), не смогут '
            'подключиться.'),
    _r('rdp_encrypt', SEC_REMOTE, _RDP_TCP, 'MinEncryptionLevel',
       'Минимальный уровень шифрования RDP', '>=', 3, '3', ISSUE_MEDIUM,
       needs_rdp=True,
       note='Без минимального уровня RDP разрешает слабое шифрование трафика.',
       risk='Устаревшие RDP-клиенты с низким уровнем шифрования не подключатся.'),

    # --- сетевое окружение ------------------------------------------------
    _r('smb1_server', SEC_NETWORK, _LANMAN_SERVER, 'SMB1',
       'Сервер SMB1 отключён', '==', 0, '0', ISSUE_HIGH, missing='ok',
       note='SMB1 уязвим (EternalBlue/WannaCry) и не нужен современным системам.',
       risk='Устройства, которые умеют только SMB1 (старые NAS, сетевые '
            'принтеры, Windows XP), перестанут быть доступны.'),
    _r('smb_guest', SEC_NETWORK, _LANMAN_STATION, 'AllowInsecureGuestAuth',
       'Анонимный доступ к сетевым папкам запрещён', '==', 0, '0', ISSUE_MEDIUM,
       note='Гостевой вход в общие папки обходит проверку подлинности.',
       risk='Гостевые подключения к общим папкам и старые NAS, которым нужен '
            'гостевой вход, перестанут работать.'),
    _r('smb_sign_server', SEC_NETWORK, _LANMAN_SERVER, 'RequireSecuritySignature',
       'Подпись SMB для входящих подключений', '==', 1, '1', ISSUE_MEDIUM,
       missing='bad', recommended=False,
       note='Защищает от подмены трафика SMB (атаки типа relay).',
       risk='Старые сетевые хранилища и клиенты с отключённой подписью могут '
            'перестать подключаться; скорость SMB немного снизится.'),
    _r('smb_sign_client', SEC_NETWORK, _LANMAN_STATION, 'RequireSecuritySignature',
       'Подпись SMB для исходящих подключений', '==', 1, '1', ISSUE_LOW,
       missing='bad', recommended=False,
       note='Защищает от подмены трафика SMB (атаки типа relay).',
       risk='Доступ к старым NAS и сетевым дискам без поддержки подписи станет '
            'невозможен; возможен небольшой рост нагрузки.'),
    _r('llmnr', SEC_NETWORK, _DNSCLIENT, 'EnableMulticast',
       'LLMNR отключён', '==', 0, '0', ISSUE_MEDIUM, missing='bad',
       recommended=False,
       note='LLMNR перехватывают (Responder) для кражи хэшей.',
       risk='Может ухудшиться обнаружение устройств и разрешение имён в '
            'локальной сети (принтеры, медиасерверы, имена без DNS).'),

    # --- брандмауэр -------------------------------------------------------
    _r('fw_domain', SEC_FIREWALL, _FIREWALL + r'\DomainProfile', 'EnableFirewall',
       'Брандмауэр: профиль «Домен»', '==', 1, '1', ISSUE_HIGH,
       note='Выключенный брандмауэр пропускает входящие подключения из сети.',
       risk='В домене профиль обычно управляется групповой политикой — '
            'значение может вернуться при следующем обновлении политики.'),
    _r('fw_private', SEC_FIREWALL, _FIREWALL + r'\StandardProfile', 'EnableFirewall',
       'Брандмауэр: профиль «Частный»', '==', 1, '1', ISSUE_HIGH,
       note='Выключенный брандмауэр пропускает входящие подключения из '
            'локальной сети.',
       risk='Программы и игры, для которых брандмауэр отключали вручную, '
            'перестанут принимать подключения, пока для них не добавлено '
            'правило.'),
    _r('fw_public', SEC_FIREWALL, _FIREWALL + r'\PublicProfile', 'EnableFirewall',
       'Брандмауэр: профиль «Публичный»', '==', 1, '1', ISSUE_HIGH,
       note='В общедоступной сети выключенный брандмауэр открывает компьютер '
            'для чужих подключений.',
       risk='Программы, которые ждут входящих подключений (мессенджеры, игры, '
            'удалённый доступ), перестанут работать без правила исключения.'),

    # --- журналирование ---------------------------------------------------
    _r('ps_scriptblock', SEC_LOGGING, _PS_POLICY + r'\ScriptBlockLogging',
       'EnableScriptBlockLogging', 'Журнал блоков PowerShell', '==', 1, '1',
       ISSUE_MEDIUM, missing='bad',
       note='Без него обфусцированный PowerShell-код не оставляет следов.',
       risk='Журнал событий станет больше, немного растёт нагрузка при '
            'выполнении скриптов; в журнал попадает текст скриптов, включая '
            'чувствительные данные.'),
    _r('ps_module', SEC_LOGGING, _PS_POLICY + r'\ModuleLogging',
       'EnableModuleLogging', 'Журнал модулей PowerShell', '==', 1, '1',
       ISSUE_MEDIUM, missing='bad',
       note='Без журнала модулей не видно, какие модули загружал скрипт.',
       risk='Небольшой рост размера журнала и нагрузки при работе PowerShell.'),
    _r('ps_transcript', SEC_LOGGING, _PS_POLICY + r'\Transcription',
       'EnableTranscripting', 'Стенограмма PowerShell', '==', 1, '1',
       ISSUE_LOW, missing='bad', recommended=False,
       note='Пишет весь ввод и вывод PowerShell в файлы — полезно для разбора '
            'инцидента.',
       risk='Занимает место на диске и может сохранить чувствительные данные '
            '(например, пароли из команд).'),
    _r('evt_security_size', SEC_LOGGING, _EVENTLOG + r'\Security', 'MaxSize',
       'Размер журнала Security', '>=', _SECURITY_LOG_MIN_BYTES, '20971520',
       ISSUE_MEDIUM,
       note='Маленький журнал быстро перезаписывается и теряет следы атаки.',
       risk='Журнал Security будет занимать больше диска (до 20 МБ); изменение '
            'применяется после перезапуска службы журналов.'),
    _r('evt_service', SEC_LOGGING, _EVENTLOG, 'Start',
       'Служба журналов событий включена', '==', 2, '2', ISSUE_HIGH,
       note='Отключённая служба журналов означает отсутствие любых записей '
            'событий.',
       risk='Если службу отключили намеренно (например, на слабой машине), она '
            'снова начнёт писать события — вернутся расход диска и памяти.'),

    # --- обновления и прочее ----------------------------------------------
    _r('wu_noautoupdate', SEC_OTHER, _WU + r'\AU', 'NoAutoUpdate',
       'Автоматическое обновление не отключено', '==', 0, '0', ISSUE_HIGH,
       note='Отключённое автообновление оставляет систему без исправлений.',
       risk='Windows начнёт скачивать и устанавливать обновления сама: '
            'возможны внезапные перезагрузки и нагрузка, если обновления давно '
            'не ставились.'),
    # report-only: значение '' означает «ключ не задан» (норма)
    _r('wu_server', SEC_OTHER, _WU, 'WUServer',
       'Сервер обновлений не подменён', '==', '', severity=ISSUE_LOW,
       expect_label='не задан', recommended=False,
       note='Обновления идут не с серверов Microsoft. В домене это нормально, '
            'на домашнем компьютере — признак подмены.',
       risk='В домене это может быть штатный WSUS — смена сервера сломает '
            'обновления.',
       how_to='gpedit.msc → Конфигурация компьютера → Административные шаблоны '
              '→ Компоненты Windows → Центр обновления Windows → «Указать '
              'местонахождение службы обновлений» → «Не задана».',
       command=r"Remove-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows"
               r"\WindowsUpdate' -Name WUServer -ErrorAction SilentlyContinue"),
)

_RULES_BY_ID: Dict[str, Rule] = {rule.id: rule for rule in RULES}


@dataclass
class Issue:
    """Найденное отклонение. Пустой ``fix_line`` — только отчёт, без автолечения."""

    rule_id: str
    section: str
    title: str
    severity: str
    current: str
    expected: str
    fix_line: str = ''
    note: str = ''
    risk: str = ''
    how_to: str = ''
    command: str = ''
    reboot: bool = False
    # Входит в набор «Рекомендовано»: важное исправление без побочных эффектов.
    recommended: bool = False

    @property
    def manual(self) -> bool:
        return not self.fix_line

    @property
    def severity_label(self) -> str:
        return SEVERITY_LABELS.get(self.severity, self.severity)


# ===========================================================================
#  Оценка состояния
# ===========================================================================
def _format_value(value: object) -> str:
    if value is None:
        return 'не задано'
    if isinstance(value, str):
        return value if value else 'пусто'
    return str(value)


def _expected_label(rule: Rule) -> str:
    if rule.expect_label:
        return rule.expect_label
    if rule.op == '==':
        return _format_value(rule.expected)
    if rule.op == '>=':
        return f'не менее {rule.expected}'
    if rule.op == '<=':
        return f'не более {rule.expected}'
    return f'{rule.op} {rule.expected}'


def _fix_line(rule: Rule) -> str:
    return (f'Reg: reg add "HKLM\\{rule.path}" /v "{rule.name}" '
            f'/t {rule.kind} /d "{rule.fix_value}" /f')


def _issue(rule: Rule, value: object) -> Issue:
    return Issue(
        rule_id=rule.id,
        section=rule.section,
        title=rule.title,
        severity=rule.severity,
        current=_format_value(value),
        expected=_expected_label(rule),
        fix_line=_fix_line(rule) if rule.fixable else '',
        note=rule.note,
        risk=rule.risk,
        how_to=rule.how_to,
        command=rule.command,
        reboot=rule.reboot,
        recommended=rule.recommended and rule.fixable,
    )


def _rdp_enabled() -> bool:
    value = winapi.read_value(winapi.HKLM, _RDP_TS, 'fDenyTSConnections')
    return value == 0


# Исключения Defender: путь во временных папках — типичный след малвари.
_EXCLUSION_KINDS = (('Paths', 'путь', 'ExclusionPath'),
                    ('Processes', 'процесс', 'ExclusionProcess'),
                    ('Extensions', 'расширение', 'ExclusionExtension'))
_SUSPICIOUS_MARKERS = ('\\temp\\', '\\downloads\\', '\\$recycle.bin\\')
_EXCLUSION_LIMIT = 50


def _is_suspicious_exclusion(text: str) -> bool:
    lowered = text.lower().replace('/', '\\')
    if not lowered.endswith('\\'):
        lowered += '\\'
    return any(marker in lowered for marker in _SUSPICIOUS_MARKERS)


def _exclusion_issues() -> List[Issue]:
    issues: List[Issue] = []
    for kind, label, cmdlet in _EXCLUSION_KINDS:
        key = f'{_DEFENDER}\\Exclusions\\{kind}'
        for name in sorted(winapi.read_values(winapi.HKLM, key)):
            if len(issues) >= _EXCLUSION_LIMIT:
                return issues
            suspicious = _is_suspicious_exclusion(name)
            issues.append(Issue(
                rule_id=f'defender_exclusion_{kind.lower()}',
                section=SEC_OTHER,
                title=f'Исключение Defender ({label}): {name}',
                severity=ISSUE_HIGH if suspicious else ISSUE_LOW,
                current=name,
                expected='исключения нет',
                fix_line=f'HKLM\\{key}: [{name}]' if suspicious else '',
                note=('Исключение указывает на временную папку — типичный '
                      'приём вредоносных программ.' if suspicious else
                      'Проверьте, что исключение добавлено осознанно.'),
                risk=('Если исключение добавлено для доверенной программы, '
                      'антивирус снова начнёт проверять её файлы и может '
                      'удалить их как угрозу; при необходимости исключение '
                      'можно добавить заново.' if suspicious else
                      'Антивирус снова начнёт проверять содержимое папки: '
                      'возможны ложные срабатывания на доверенных файлах.'),
                how_to=('' if suspicious else
                        'Безопасность Windows → Защита от вирусов и угроз → '
                        'Управление параметрами → Исключения → удалить запись.'),
                command=(f"Remove-MpPreference -{cmdlet} '{name}'"
                         if not suspicious else ''),
                recommended=suspicious,
            ))
    return issues


def _sort_key(issue: Issue) -> Tuple[int, int, str]:
    return (_SEVERITY_ORDER.get(issue.severity, 9),
            _SECTION_ORDER.get(issue.section, 99), issue.title.lower())


def rule_preview() -> List[Issue]:
    """Все проверяемые параметры без чтения системы — для показа до проверки."""
    return [Issue(
        rule_id=rule.id,
        section=rule.section,
        title=rule.title,
        severity=rule.severity,
        current='—',
        expected=_expected_label(rule),
        note=rule.note,
        risk=rule.risk,
        how_to=rule.how_to,
        command=rule.command,
        recommended=False,
    ) for rule in RULES]


def evaluate() -> List[Issue]:
    """Проверить систему. Возвращает только отклонения, отсортированные по важности."""
    issues: List[Issue] = []
    if not winapi.IS_WINDOWS:
        return issues
    rdp_on = _rdp_enabled()
    for rule in RULES:
        if rule.needs_rdp and not rdp_on:
            continue
        value = winapi.read_value(winapi.HKLM, rule.path, rule.name, rule.view)
        if rule.violates(value):
            issues.append(_issue(rule, value))
    issues.extend(_exclusion_issues())
    issues.sort(key=_sort_key)
    return issues


def counts(issues: List[Issue]) -> Dict[str, int]:
    """Сколько находок каждой важности (для сводки в интерфейсе)."""
    result = {level: 0 for level in _SEVERITY_ORDER}
    for issue in issues:
        result[issue.severity] = result.get(issue.severity, 0) + 1
    return result


def needs_reboot(issues: List[Issue]) -> bool:
    return any(issue.reboot for issue in issues if issue.fix_line)


def compose_fixlist(issues: List[Issue]) -> str:
    """Собрать fixlist из строк исправления. Пустой текст — исправлять нечего."""
    lines = [issue.fix_line for issue in issues if issue.fix_line]
    if not lines:
        return ''
    result = ['Start::'] + lines
    if needs_reboot(issues):
        result.append('Reboot:')
    result.append('End::')
    return '\n'.join(result) + '\n'


def fixable(issues: List[Issue]) -> List[Issue]:
    return [issue for issue in issues if issue.fix_line]


def recommended(issues: List[Issue]) -> List[Issue]:
    """Набор «Рекомендовано»: важные исправления без риска для сети и устройств."""
    return [issue for issue in issues if issue.recommended and issue.fix_line]