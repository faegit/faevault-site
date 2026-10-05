from pathlib import Path

import time as _time

import pytest

import browser_host as native_host
from core.browser_autofill import ProtocolError
from core.storage import Vault
from ui import widgets


def _configure_account(monkeypatch, path: Path):
    state = {"fail_count": 0, "lockout_until": 0, "lockout_rounds": 0}
    monkeypatch.setattr(native_host.config, "get", lambda key, default=None: state.get(key, default))
    monkeypatch.setattr(native_host.config, "set", lambda key, value: state.__setitem__(key, value))
    record = {"name": "FAE", "file": path.name}
    monkeypatch.setattr(native_host.config, "get_current_user", lambda: "FAE")
    monkeypatch.setattr(native_host.config, "list_users", lambda: [record])
    monkeypatch.setattr(native_host.config, "user_vault_path", lambda _record: path)
    monkeypatch.setattr(native_host.config, "set_current_user", lambda _name: None)

    def _fake_record():
        count0 = state.get("fail_count", 0)
        rounds0 = state.get("lockout_rounds", 0)
        count = min(count0 + 1, 5)
        remaining = 5 - count
        if remaining > 0:
            state["fail_count"] = count
            return count, 2.0 ** (count - 1) * 0.25, False, 0
        new_rounds = rounds0 + 1
        cooldown = 30 * new_rounds
        state["fail_count"] = 0
        state["lockout_rounds"] = new_rounds
        state["lockout_until"] = _time.time() + cooldown
        return 0, 0.0, True, cooldown

    def _fake_clear():
        state["fail_count"] = 0
        state["lockout_rounds"] = 0
        state["lockout_until"] = 0

    def _fake_remaining():
        return max(0.0, float(state.get("lockout_until", 0)) - _time.time())

    monkeypatch.setattr(native_host.config, "record_password_failure", _fake_record)
    monkeypatch.setattr(native_host.config, "clear_password_lockout", _fake_clear)
    monkeypatch.setattr(native_host.config, "password_cooling_remaining", _fake_remaining)
    monkeypatch.setattr(native_host.time, "sleep", lambda _seconds: None)
    return state


def test_popup_unlock_uses_current_account_and_resets_failure_count(monkeypatch, tmp_path):
    path = tmp_path / "vault_FAE.pmv"
    Vault.create(path, "master").close()
    state = _configure_account(monkeypatch, path)

    with pytest.raises(ProtocolError) as caught:
        native_host._unlock_vault_with_password("wrong")
    assert caught.value.code == "WRONG_PASSWORD"
    assert state["fail_count"] == 1

    vault = native_host._unlock_vault_with_password("master")
    try:
        assert vault.path == path
        assert state["fail_count"] == 0
        assert state["lockout_until"] == 0
        assert state["lockout_rounds"] == 0
    finally:
        vault.close()


def test_popup_unlock_rejects_missing_current_account(monkeypatch):
    monkeypatch.setattr(native_host.config, "get_current_user", lambda: None)
    monkeypatch.setattr(native_host.config, "list_users", lambda: [])

    with pytest.raises(ProtocolError) as caught:
        native_host._unlock_vault_with_password("master")
    assert caught.value.code == "NO_ACCOUNT"


def test_private_origin_authorization_is_confirmed_once_and_persisted(monkeypatch):
    stored = []
    confirmations = []
    monkeypatch.setattr(native_host, "_application", lambda: None)
    monkeypatch.setattr(native_host.config, "browser_private_origins", lambda: (list(stored), True))
    monkeypatch.setattr(
        native_host.config,
        "set_browser_private_origins",
        lambda values: stored.__setitem__(slice(None), values),
    )
    monkeypatch.setattr(widgets, "confirm", lambda *_args, **_kwargs: confirmations.append(True) or True)

    origin = "https://192.168.1.10:8443"
    assert native_host._authorize_ip_origin(origin)
    assert native_host._authorize_ip_origin(origin)
    assert stored == [origin]
    assert len(confirmations) == 1


def test_browser_first_unlock_migrates_legacy_exclusions_once_for_current_vault(monkeypatch, tmp_path):
    path = tmp_path / "vault_FAE.pmv"
    Vault.create(path, "master").close()
    state = _configure_account(monkeypatch, path)
    state["browser_autofill_excluded_hosts"] = ["Example.com"]
    state["native_autofill_excluded"] = ["APP.EXE"]
    vault = native_host._unlock_vault_with_password("master")
    assert vault.autofill_exclusions["hosts"] == ["example.com"]
    assert vault.autofill_exclusions["processes"] == ["app.exe"]
    marker = state["autofill_exclusions_migrated_vault_id"]
    vault.set_autofill_exclusions("hosts", [])
    vault.close()
    # A remote deletion wins over a stale local cache after migration.
    state["browser_autofill_excluded_hosts"] = ["example.com"]
    reopened = native_host._unlock_vault_with_password("master")
    assert reopened.autofill_exclusions["hosts"] == []
    assert state["browser_autofill_excluded_hosts"] == []
    assert state["autofill_exclusions_migrated_vault_id"] == marker
    reopened.close()
