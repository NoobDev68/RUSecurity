"""Тесты проверки безопасности: правила, оценка и формирование fixlist."""

import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.core import hardening  # noqa: E402
from rusecurity.fixer import actions as act  # noqa: E402


def _baseline() -> dict:
    """Значения, при которых все правила соблюдены (отсутствие = норма)."""
    values = {
        (r'SYSTEM\CurrentControlSet\Control\Terminal Server',
         'fDenyTSConnections'): 1,
    }
    for rule in hardening.RULES:
        if rule.missing == 'bad':
            values[(rule.path, rule.name)] = rule.expected
    return values


class _FakeWinapi:
    IS_WINDOWS = True
    HKLM = 'HKLM'
    VIEW_64 = 0

    def __init__(self, values: dict, exclusions: dict | None = None) -> None:
        self.values = values
        self.exclusions = exclusions or {}

    def read_value(self, _root, path, name, _view=0):
        return self.values.get((path, name))

    def read_values(self, _root, path, _view=0):
        return self.exclusions.get(path, {})


@pytest.fixture()
def fake(monkeypatch):
    def build(values=None, exclusions=None):
        stand = _FakeWinapi(_baseline() if values is None else values, exclusions)
        monkeypatch.setattr(hardening, 'winapi', stand)
        return stand

    return build


def test_rule_ids_unique():
    ids = [rule.id for rule in hardening.RULES]
    assert len(ids) == len(set(ids))


def test_rule_sections_are_known():
    assert {rule.section for rule in hardening.RULES} <= set(hardening.SECTIONS)


def test_missing_value_bad_when_rule_says_so():
    rule = hardening._RULES_BY_ID['lsa_restrictanon']
    assert rule.missing == 'bad'
    assert rule.violates(None) is True
    assert rule.violates(1) is False


def test_lsa_protection_accepts_uefi_level():
    """RunAsPPL=2 — защита включена с UEFI-блокировкой, это не отклонение."""
    rule = hardening._RULES_BY_ID['lsa_runasppl']
    assert rule.violates(2) is False
    assert rule.violates(1) is False
    assert rule.violates(0) is True


def test_missing_value_ok_for_default_safe_rule():
    rule = hardening._RULES_BY_ID['lsa_limitblank']
    assert rule.missing == 'ok'
    assert rule.violates(None) is False
    assert rule.violates(0) is True


def test_string_rule_wrong_type_counts_as_violation():
    rule = hardening._RULES_BY_ID['wu_noautoupdate']
    assert rule.violates('текст') is True
    assert rule.violates(0) is False


@pytest.mark.parametrize('rule', [rule for rule in hardening.RULES if rule.fixable],
                         ids=lambda rule: rule.id)
def test_fix_line_parses_back_into_reg_set(rule):
    line = hardening._fix_line(rule)
    actions = act.parse_fixlist(line)
    assert len(actions) == 1
    action = actions[0]
    assert action.kind == act.REG_SET
    assert action.path == f'HKLM\\{rule.path}'
    assert action.name == rule.name
    assert action.reg_type == rule.kind
    assert action.value == rule.fix_value


def test_evaluate_reports_nothing_on_hardened_system(fake):
    fake()
    assert hardening.evaluate() == []


def test_evaluate_finds_weak_ntlm_level(fake):
    values = _baseline()
    values[(hardening._LSA, 'LmCompatibilityLevel')] = 2
    fake(values)
    issues = hardening.evaluate()
    assert [issue.rule_id for issue in issues] == ['lsa_lmcompat']
    assert issues[0].current == '2'
    assert issues[0].severity == hardening.ISSUE_HIGH
    assert issues[0].fix_line.startswith('Reg: reg add')


def test_evaluate_skips_rdp_details_when_rdp_disabled(fake):
    values = _baseline()
    values[(hardening._RDP_TCP, 'UserAuthentication')] = 0
    fake(values)
    assert hardening.evaluate() == []


def test_evaluate_checks_rdp_details_when_rdp_enabled(fake):
    values = _baseline()
    values[(hardening._RDP_TS, 'fDenyTSConnections')] = 0
    values[(hardening._RDP_TCP, 'UserAuthentication')] = 0
    fake(values)
    ids = [issue.rule_id for issue in hardening.evaluate()]
    assert 'rdp_nla' in ids


def test_rdp_enabled_is_report_only(fake):
    values = _baseline()
    values[(hardening._RDP_TS, 'fDenyTSConnections')] = 0
    fake(values)
    issue = next(issue for issue in hardening.evaluate()
                 if issue.rule_id == 'rdp_enabled')
    assert issue.manual is True
    assert issue.fix_line == ''


def test_wus_server_is_report_only(fake):
    values = _baseline()
    values[(hardening._WU, 'WUServer')] = 'http://wsus.example.local'
    fake(values)
    issue = next(issue for issue in hardening.evaluate()
                 if issue.rule_id == 'wu_server')
    assert issue.manual is True
    assert 'wsus' in issue.current


def test_suspicious_defender_exclusion_is_fixable(fake):
    exclusion_key = hardening._DEFENDER + r'\Exclusions\Paths'
    fake(None, {exclusion_key: {
        r'C:\Users\u\AppData\Local\Temp': 0,
        r'D:\Games': 0,
    }})
    issues = [issue for issue in hardening.evaluate()
              if issue.rule_id == 'defender_exclusion_paths']
    suspicious = next(i for i in issues if 'Temp' in i.current)
    ordinary = next(i for i in issues if 'Games' in i.current)
    assert suspicious.fix_line == f'HKLM\\{exclusion_key}: [{suspicious.current}]'
    assert suspicious.severity == hardening.ISSUE_HIGH
    assert suspicious.recommended is True
    assert suspicious.risk and ordinary.risk
    assert ordinary.manual is True
    assert ordinary.recommended is False
    assert 'Исключения' in ordinary.how_to
    assert ordinary.command == r"Remove-MpPreference -ExclusionPath 'D:\Games'"
    assert suspicious.how_to == '' and suspicious.command == ''


def test_ordinary_exclusion_deletion_line_parses_as_reg_value():
    path = hardening._DEFENDER + r'\Exclusions\Paths'
    line = f'HKLM\\{path}: [C:\\Users\\u\\AppData\\Local\\Temp]'
    actions = act.parse_fixlist(line)
    assert actions[0].kind == act.REG_VALUE
    assert actions[0].path == f'HKLM\\{path}'
    assert actions[0].name == r'C:\Users\u\AppData\Local\Temp'


def test_compose_fixlist_has_start_and_end(fake):
    values = _baseline()
    values[(hardening._LSA, 'LmCompatibilityLevel')] = 1
    fake(values)
    text = hardening.compose_fixlist(hardening.evaluate())
    assert text.startswith('Start::\n')
    assert text.endswith('End::\n')
    assert 'LmCompatibilityLevel' in text
    assert 'Reboot:' not in text


def test_compose_fixlist_adds_reboot_for_lsa_protection(fake):
    values = _baseline()
    values[(hardening._LSA, 'RunAsPPL')] = None
    fake(values)
    issues = hardening.evaluate()
    assert hardening.needs_reboot(issues) is True
    assert 'Reboot:' in hardening.compose_fixlist(issues)


def test_compose_fixlist_empty_without_fixable_issues():
    assert hardening.compose_fixlist([]) == ''
    manual = hardening.Issue(rule_id='x', section=hardening.SEC_REMOTE,
                             title='t', severity=hardening.ISSUE_LOW,
                             current='0', expected='1')
    assert hardening.compose_fixlist([manual]) == ''


def test_issues_sorted_by_severity(fake):
    values = _baseline()
    values[(hardening._LSA, 'LmCompatibilityLevel')] = 1     # высокая
    values[(hardening._DNSCLIENT, 'EnableMulticast')] = None  # средняя
    fake(values)
    severities = [issue.severity for issue in hardening.evaluate()]
    assert severities == sorted(severities, key=lambda s: hardening._SEVERITY_ORDER[s])


def test_counts_and_fixable_helpers(fake):
    values = _baseline()
    values[(hardening._LSA, 'LmCompatibilityLevel')] = 1
    values[(hardening._RDP_TS, 'fDenyTSConnections')] = 0
    fake(values)
    issues = hardening.evaluate()
    total = hardening.counts(issues)
    assert sum(total.values()) == len(issues)
    assert len(hardening.fixable(issues)) < len(issues)


def test_recommended_rules_are_fixable():
    assert all(rule.fixable for rule in hardening.RULES if rule.recommended)


def test_every_rule_explains_reason_and_risk():
    """В описании проверки должны быть и польза, и возможные минусы."""
    for rule in hardening.RULES:
        assert rule.note, rule.id
        assert rule.risk, rule.id


def test_issue_carries_risk_from_rule(fake):
    values = _baseline()
    values[(hardening._LSA, 'LmCompatibilityLevel')] = 1
    fake(values)
    issue = next(i for i in hardening.evaluate()
                 if i.rule_id == 'lsa_lmcompat')
    assert issue.risk == hardening._RULES_BY_ID['lsa_lmcompat'].risk
    assert issue.note == hardening._RULES_BY_ID['lsa_lmcompat'].note


def test_rule_preview_lists_every_check_without_values():
    rows = hardening.rule_preview()
    assert len(rows) == len(hardening.RULES)
    assert [row.rule_id for row in rows] == [rule.id for rule in hardening.RULES]
    assert all(row.current == '—' for row in rows)
    assert all(row.fix_line == '' for row in rows)
    assert all(row.expected for row in rows)
    assert all(row.note and row.risk for row in rows)


def test_manual_rules_explain_how_to_fix():
    """У проверок без автолечения должна быть инструкция для пользователя."""
    for rule in hardening.RULES:
        if rule.fixable:
            continue
        assert rule.how_to, rule.id
        assert rule.command, rule.id


def test_manual_issue_carries_instruction(fake):
    values = _baseline()
    values[(hardening._RDP_TS, 'fDenyTSConnections')] = 0
    values[(hardening._WU, 'WUServer')] = 'http://wsus.example.local'
    fake(values)
    issues = {issue.rule_id: issue for issue in hardening.evaluate()}
    rdp = issues['rdp_enabled']
    assert rdp.manual is True
    assert 'Удалённый рабочий стол' in rdp.how_to
    assert 'fDenyTSConnections' in rdp.command
    assert 'gpedit.msc' in issues['wu_server'].how_to
    assert 'WUServer' in issues['wu_server'].command


def test_recommended_set_keeps_core_protections():
    ids = {rule.id for rule in hardening.RULES if rule.recommended}
    assert {'lsa_lmcompat', 'lsa_runasppl', 'rdp_nla', 'smb1_server',
            'fw_public', 'evt_service', 'wu_noautoupdate'} <= ids


def test_recommended_set_skips_risky_rules():
    """Исправления, способные сломать сеть или забить диск, — вне набора."""
    ids = {rule.id for rule in hardening.RULES
           if rule.fixable and not rule.recommended}
    assert ids == {'smb_sign_server', 'smb_sign_client', 'llmnr',
                   'ps_transcript', 'asr_drivers', 'asr_obfuscation'}


def test_recommended_issues_skip_optional_and_manual(fake):
    values = _baseline()
    values[(hardening._LSA, 'LmCompatibilityLevel')] = 1
    values[(hardening._DNSCLIENT, 'EnableMulticast')] = None
    values[(hardening._RDP_TS, 'fDenyTSConnections')] = 0
    fake(values)
    picked = hardening.recommended(hardening.evaluate())
    assert [issue.rule_id for issue in picked] == ['lsa_lmcompat']
    assert picked[0].recommended is True


def test_ntlm_receive_restrict_is_report_only(fake):
    values = _baseline()
    values[(hardening._LSA + r'\MSV1_0', 'RestrictReceivingNTLMTraffic')] = 0
    fake(values)
    issue = next(i for i in hardening.evaluate()
                 if i.rule_id == 'ntlm_restrict_receive')
    assert issue.manual is True
    assert 'RestrictReceivingNTLMTraffic' in issue.command
    assert issue.how_to


def test_audit_ntlm_receive_is_fixable(fake):
    values = _baseline()
    values[(hardening._LSA + r'\MSV1_0', 'AuditReceivingNTLMTraffic')] = 0
    fake(values)
    issue = next(i for i in hardening.evaluate()
                 if i.rule_id == 'ntlm_audit_receive')
    assert issue.manual is False
    assert issue.fix_line.startswith('Reg: reg add')


def test_asr_rule_fix_line_writes_guid():
    line = hardening._fix_line(hardening._RULES_BY_ID['asr_lsass'])
    assert '01443614-cd74-433a-b99e-2ecdc07bfc25' in line
    assert line.startswith('Reg: reg add')


def test_defender_pua_is_recommended():
    rule = hardening._RULES_BY_ID['defender_pua']
    assert rule.recommended is True
    assert rule.missing == 'bad'


def test_evaluate_is_empty_on_non_windows(monkeypatch):
    class _Plain:
        IS_WINDOWS = False
        HKLM = 'HKLM'
        VIEW_64 = 0

        def read_value(self, *_args, **_kwargs):
            raise AssertionError('на не-Windows реестр не читается')

        def read_values(self, *_args, **_kwargs):
            raise AssertionError('на не-Windows реестр не читается')

    monkeypatch.setattr(hardening, 'winapi', _Plain())
    assert hardening.evaluate() == []


def test_cli_exposes_hardening_command():
    from rusecurity import cli

    args = cli.build_parser().parse_args(['hardening'])
    assert args.command == 'hardening'
    assert callable(args.func)


def test_cli_hardening_accepts_fix_flags():
    from rusecurity import cli

    args = cli.build_parser().parse_args(
        ['hardening', '--fix', '--dry-run', '--yes', '--verbose'])
    assert args.fix and args.dry_run and args.yes and args.verbose