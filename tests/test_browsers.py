"""Тесты автоисправления настроек браузеров и их отката."""

import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.fixer import Fixer  # noqa: E402
from rusecurity.fixer import actions, browsers  # noqa: E402
from rusecurity.fixer import restore as quarantine  # noqa: E402


def test_browser_lines_parse_as_actions():
    text = '\n'.join([
        'CHR DefaultSearchURL: Default -> hxxp://search-cdn.net/?q={searchTerms}',
        'CHR HomePage: Default -> hxxp://rusearch.co/',
        'CHR StartupUrls: Default -> hxxp://rusearch.co/',
        r'FF Homepage: Mozilla\Firefox\Profiles\test.default -> hxxp://rusearch.co/',
    ])
    parsed = actions.parse_fixlist(text)
    assert [action.kind for action in parsed] == [actions.BROWSER] * 4
    assert parsed[0].browser == 'CHR'
    assert parsed[0].setting == 'DefaultSearchURL'
    assert parsed[0].target == 'Default'
    assert parsed[0].url == 'hxxp://search-cdn.net/?q={searchTerms}'
    assert parsed[3].browser == 'FF'
    assert parsed[3].setting == 'Homepage'
    assert parsed[3].target == r'Mozilla\Firefox\Profiles\test.default'


def test_chromium_settings_are_fixed_and_restorable(tmp_path, monkeypatch):
    local = tmp_path / 'Local'
    profile = local / r'Google\Chrome\User Data\Default'
    profile.mkdir(parents=True)
    prefs = {
        'default_search_provider': {'url': 'http://evil/?q={searchTerms}',
                                    'keyword': 'evil'},
        'homepage': 'http://evil/',
        'homepage_is_newtabpage': False,
        'session': {'startup_urls': ['http://evil/']},
        'other': 1,
    }
    secure = {
        'default_search_provider_data': {'template_url_data': {'url': 'http://evil/'}},
        'homepage': 'http://evil/',
        'protection': {'macs': {'default_search_provider_data': 'x',
                                'homepage': 'y',
                                'other': 'z'}},
    }
    (profile / 'Preferences').write_text(json.dumps(prefs), encoding='utf-8')
    (profile / 'Secure Preferences').write_text(json.dumps(secure), encoding='utf-8')
    monkeypatch.setenv('LOCALAPPDATA', str(local))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])

    backup = tmp_path / 'Backups' / '20260101_200000'
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False)
    report = fixer.run('\n'.join([
        'CHR DefaultSearchURL: Default -> hxxp://evil/?q={searchTerms}',
        'CHR HomePage: Default -> hxxp://evil/',
        'CHR StartupUrls: Default -> hxxp://evil/',
    ]))
    assert report.changed == 3

    data = json.loads((profile / 'Preferences').read_text(encoding='utf-8'))
    assert 'default_search_provider' not in data
    assert 'homepage' not in data
    assert 'startup_urls' not in data['session']
    assert data['other'] == 1
    secured = json.loads((profile / 'Secure Preferences').read_text(encoding='utf-8'))
    assert 'default_search_provider_data' not in secured
    assert 'homepage' not in secured
    assert set(secured['protection']['macs']) == {'other'}

    entries = quarantine.load_entries(tmp_path)
    assert [entry.kind for entry in entries] == ['file_edit', 'file_edit']
    quarantine.restore_many(entries, backup / 'restore-log.txt')
    assert json.loads((profile / 'Preferences').read_text(encoding='utf-8')) == prefs
    restored = json.loads((profile / 'Secure Preferences').read_text(encoding='utf-8'))
    assert restored == secure


def test_firefox_homepage_is_fixed_and_restorable(tmp_path, monkeypatch):
    appdata = tmp_path / 'Roaming'
    profile = appdata / r'Mozilla\Firefox\Profiles\test.default'
    profile.mkdir(parents=True)
    prefs = profile / 'prefs.js'
    original = ('user_pref("browser.startup.homepage", "http://rusearch.co/");\n'
                'user_pref("browser.startup.page", 3);\n')
    prefs.write_text(original, encoding='utf-8')
    monkeypatch.setenv('APPDATA', str(appdata))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])

    backup = tmp_path / 'Backups' / '20260101_210000'
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False)
    report = fixer.run(r'FF Homepage: Mozilla\Firefox\Profiles\test.default -> '
                       r'hxxp://rusearch.co/')
    assert report.changed == 1
    text = prefs.read_text(encoding='utf-8')
    assert 'about:home' in text
    assert 'rusearch.co' not in text

    entries = quarantine.load_entries(tmp_path)
    assert [entry.kind for entry in entries] == ['file_edit']
    quarantine.restore_many(entries, backup / 'restore-log.txt')
    assert prefs.read_text(encoding='utf-8') == original


def test_browser_fix_reports_missing_profile(tmp_path, monkeypatch):
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'empty'))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])
    fixer = Fixer(tmp_path / 'Backups' / 'x', tmp_path / 'log.txt',
                  create_restore_point=False)
    report = fixer.run('CHR HomePage: NoProfile -> hxxp://evil/')
    assert [outcome.status for outcome in report.outcomes] == ['not_found']


def test_clear_browser_cache_and_cookies(tmp_path, monkeypatch):
    local = tmp_path / 'Local'
    profile = local / r'Google\Chrome\User Data\Default'
    (profile / 'Cache').mkdir(parents=True)
    (profile / 'Cache' / 'data').write_text('x', encoding='utf-8')
    (profile / 'Code Cache').mkdir()
    (profile / 'Cookies').write_text('cookie', encoding='utf-8')
    (profile / 'Network').mkdir()
    (profile / 'Network' / 'Cookies').write_text('netcookie', encoding='utf-8')
    (profile / 'Preferences').write_text('{}', encoding='utf-8')
    appdata = tmp_path / 'Roaming'
    firefox = appdata / r'Mozilla\Firefox\Profiles\test.default'
    (firefox / 'cache2').mkdir(parents=True)
    (firefox / 'cache2' / 'entry').write_text('y', encoding='utf-8')
    (firefox / 'cookies.sqlite').write_text('ffcookie', encoding='utf-8')
    (firefox / 'prefs.js').write_text('//', encoding='utf-8')

    monkeypatch.setenv('LOCALAPPDATA', str(local))
    monkeypatch.setenv('APPDATA', str(appdata))
    monkeypatch.setattr(browsers, '_close_all', lambda: [])

    removed = browsers.clear_cache_and_cookies()
    assert removed >= 5
    assert not (profile / 'Cache').exists()
    assert not (profile / 'Cookies').exists()
    assert not (profile / 'Network' / 'Cookies').exists()
    assert (profile / 'Preferences').exists()
    assert not (firefox / 'cache2').exists()
    assert not (firefox / 'cookies.sqlite').exists()
    assert (firefox / 'prefs.js').exists()


def test_clear_browser_cache_line_parses():
    [action] = actions.parse_fixlist('ClearBrowserCache:')
    assert action.kind == actions.BROWSER_CACHE
