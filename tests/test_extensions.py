"""Удаление расширений Chromium: запись в профиле, папка и откат."""

import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.core.sections import internet  # noqa: E402
from rusecurity.fixer import Fixer, actions, browsers  # noqa: E402
from rusecurity.fixer import restore as quarantine  # noqa: E402

EXT_ID = 'deadbeefdeadbeefdeadbeefdeadbeef'


def _profile(tmp_path: Path) -> Path:
    profile = tmp_path / 'Local' / r'Google\Chrome\User Data\Default'
    profile.mkdir(parents=True)
    return profile


def _write_prefs(profile: Path, entry: dict) -> Path:
    path = profile / 'Preferences'
    path.write_text(json.dumps({'extensions': {'settings': {EXT_ID: entry}}}),
                    encoding='utf-8')
    return path


def test_extension_line_parsing():
    line = (r'CHR Extension: (Gifty Box) - '
            r'C:\ProgramData\RusSecurityTest\GiftyBox [2024-01-01]')
    parsed = actions.parse_fixlist(line)
    assert [action.kind for action in parsed] == [actions.EXTENSION]
    assert parsed[0].browser == 'CHR'
    assert parsed[0].name == 'Gifty Box'
    assert parsed[0].path == r'C:\ProgramData\RusSecurityTest\GiftyBox'


def test_scanner_reports_real_extension_path(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    real = tmp_path / 'ProgramData' / 'GiftyBox'
    real.mkdir(parents=True)
    _write_prefs(profile, {'path': str(real), 'manifest': {'name': 'Gifty Box'}})
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'Local'))
    lines = internet._chromium_profile_lines('CHR', str(profile))
    assert any('CHR Extension: (Gifty Box) - ' + str(real) in line for line in lines)


def test_extension_entry_and_folder_are_removed_and_restored(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    folder = tmp_path / 'ProgramData' / 'GiftyBox'
    folder.mkdir(parents=True)
    (folder / 'manifest.json').write_text('{"name": "Gifty Box"}', encoding='utf-8')
    prefs_path = _write_prefs(profile, {'path': str(folder),
                                       'manifest': {'name': 'Gifty Box'}})
    original = prefs_path.read_bytes()
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'Local'))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])

    backup = tmp_path / 'Backups' / '20260101_220000'
    fixer = Fixer(backup, tmp_path / 'fixlog.txt', create_restore_point=False)
    report = fixer.run(f'CHR Extension: (Gifty Box) - {folder}')
    assert [outcome.status for outcome in report.outcomes] == ['done']
    data = json.loads(prefs_path.read_text(encoding='utf-8'))
    assert data['extensions']['settings'] == {}
    assert not folder.exists()

    entries = quarantine.load_entries(tmp_path)
    assert {entry.kind for entry in entries} == {'file', 'file_edit'}
    quarantine.restore_many(entries, backup / 'restore-log.txt')
    assert prefs_path.read_bytes() == original
    assert (folder / 'manifest.json').is_file()


def test_dead_extension_entry_is_removed(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    missing = tmp_path / 'ProgramData' / 'GiftyBox'
    prefs_path = _write_prefs(profile, {'path': str(missing),
                                       'manifest': {'name': 'Gifty Box'}})
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'Local'))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])

    fixer = Fixer(tmp_path / 'Backups' / 'x', tmp_path / 'log.txt',
                  create_restore_point=False)
    report = fixer.run(f'CHR Extension: (Gifty Box) - {missing}')
    assert [outcome.status for outcome in report.outcomes] == ['done']
    data = json.loads(prefs_path.read_text(encoding='utf-8'))
    assert data['extensions']['settings'] == {}


def test_protected_extension_entry_is_not_touched(tmp_path, monkeypatch):
    profile = _profile(tmp_path)
    prefs_path = _write_prefs(profile, {'path': str(tmp_path / 'gone'),
                                       'manifest': {'name': 'Gifty Box'}})
    secure = {'extensions': {'settings': {EXT_ID: {'path': str(tmp_path / 'gone')}}},
              'protection': {'macs': {f'extensions.settings.{EXT_ID}': 'hash'}}}
    (profile / 'Secure Preferences').write_text(json.dumps(secure), encoding='utf-8')
    original = prefs_path.read_bytes()
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'Local'))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])

    fixer = Fixer(tmp_path / 'Backups' / 'x', tmp_path / 'log.txt',
                  create_restore_point=False)
    report = fixer.run(f'CHR Extension: (Gifty Box) - {tmp_path / "gone"}')
    assert [outcome.status for outcome in report.outcomes] == ['skipped']
    assert prefs_path.read_bytes() == original
    secure_data = json.loads((profile / 'Secure Preferences').read_text(encoding='utf-8'))
    assert secure_data == secure
