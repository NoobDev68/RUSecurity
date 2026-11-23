"""Строка из старого отчёта не должна менять уже другое значение в профиле."""

import json
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

from rusecurity.fixer import Fixer, browsers  # noqa: E402


def test_stale_line_does_not_touch_changed_setting(tmp_path, monkeypatch):
    local = tmp_path / 'Local'
    profile = local / r'Google\Chrome\User Data\Default'
    profile.mkdir(parents=True)
    prefs = {
        'homepage': 'http://good.example/',
        'default_search_provider': {'url': 'http://good.example/?q={searchTerms}'},
    }
    (profile / 'Preferences').write_text(json.dumps(prefs), encoding='utf-8')
    monkeypatch.setenv('LOCALAPPDATA', str(local))
    monkeypatch.setattr(browsers, 'close', lambda prefix: [])

    fixer = Fixer(tmp_path / 'Backups' / 'x', tmp_path / 'log.txt',
                  create_restore_point=False)
    report = fixer.run('CHR HomePage: Default -> hxxp://evil/\n'
                       'CHR DefaultSearchURL: Default -> hxxp://evil/?q={searchTerms}')
    assert [outcome.status for outcome in report.outcomes] == ['skipped', 'skipped']
    data = json.loads((profile / 'Preferences').read_text(encoding='utf-8'))
    assert data == prefs
    assert (tmp_path / 'Backups' / 'x' / 'manifest.json').is_file() is False
