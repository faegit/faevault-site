import json
import shutil
from pathlib import Path

import pytest

from core import autofill_exclusions as exclusions, backup, config
from core.storage import Vault

PASSWORD = "correct horse battery staple"
RECOVERY = bytes(range(32))


def test_synced_android_exclusions_are_visible_without_local_cache(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from PySide6.QtWidgets import QApplication, QLabel
    from ui.dialogs import NativeAutofillExcludeDialog
    from ui.settings_page import SettingsPage

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(config, "get", lambda key, default=None: default)
    vault = Vault.create_pmve(tmp_path / "visible.pmv", PASSWORD, RECOVERY)
    dialog = None
    try:
        vault.set_autofill_exclusions("packages", ["com.example.app"])
        host = SimpleNamespace(_window=SimpleNamespace(vault=vault), _native_exclude_count=QLabel())
        host._refresh_native_exclude_count = lambda: SettingsPage._refresh_native_exclude_count(host)
        SettingsPage.refresh(host, None)
        assert "1" in host._native_exclude_count.text()
        dialog = NativeAutofillExcludeDialog(vault=vault)
        assert dialog._list_lay.itemAt(0).widget().property("exclusion_value") == "com.example.app"
        assert dialog._list_lay.itemAt(0).widget().property("exclusion_category") == "packages"
        vault.set_autofill_exclusions("hosts", ["example.com"])
        SettingsPage.refresh(host, None)
        dialog._reload()
        assert "2" in host._native_exclude_count.text()
        assert {dialog._list_lay.itemAt(i).widget().property("exclusion_value")
                for i in range(dialog._list_lay.count())} == {"com.example.app", "example.com"}
        assert vault.autofill_exclusions["packages"] == ["com.example.app"]
    finally:
        if dialog is not None:
            dialog.deleteLater()
        app.processEvents()
        vault.close()


def test_shared_vectors_converge():
    fixtures = json.loads((Path(__file__).parents[1] / "spec/autofill_exclusions_v1_fixtures.json").read_text(encoding="utf-8"))
    for case in fixtures["cases"]:
        merged = exclusions.merge(case["local"], case["remote"])
        assert {key: merged[key] for key in exclusions.CATEGORIES} == case["expected"], case["name"]
        assert merged == exclusions.merge(case["remote"], case["local"]), case["name"]
        assert merged == exclusions.merge(merged, case["local"]), case["name"]


def test_monotonic_readd_and_platform_preservation():
    value = exclusions.update({"packages": ["com.example.app"]}, "hosts", ["https://EXAMPLE.COM/login"], now=50)
    removed = exclusions.update(value, "hosts", [], now=49)
    added = exclusions.update(removed, "hosts", ["example.com"], now=48)
    assert removed["states"]["hosts:example.com"] == {"updated_at": 51, "deleted": True}
    assert added["states"]["hosts:example.com"] == {"updated_at": 52, "deleted": False}
    assert added["packages"] == ["com.example.app"]
    assert exclusions.merge(removed, value)["hosts"] == []


def test_vault_immediate_save_reopen_and_failed_write_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    try:
        vault.set_autofill_exclusions("hosts", ["https://例子.测试/login"])
        vault.set_autofill_exclusions("processes", ["CHROME.EXE"])
        before = vault.autofill_exclusions
        reopened = Vault.open(path, PASSWORD)
        try:
            assert reopened.autofill_exclusions == before
        finally:
            reopened.close()
        def fail():
            raise OSError("disk full")
        monkeypatch.setattr(vault, "save", fail)
        with pytest.raises(OSError):
            vault.set_autofill_exclusions("hosts", [])
        assert vault.autofill_exclusions == before
    finally:
        vault.close()


def test_legacy_migration_does_not_resurrect_remote_tombstones(tmp_path, monkeypatch):
    settings = {"browser_autofill_excluded_hosts": ["legacy.example", "removed.example"], "native_autofill_excluded": ["CHROME.EXE"]}
    monkeypatch.setattr(config, "get", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    vault = Vault.create_pmve(tmp_path / "vault.pmv", PASSWORD, RECOVERY)
    try:
        vault.replace_autofill_exclusions({"packages": ["com.example.app"], "states": {"hosts:removed.example": {"updated_at": 1, "deleted": True}}})
        exclusions.sync_local_config(vault, migrate=True)
        assert vault.autofill_exclusions["hosts"] == ["legacy.example"]
        assert vault.autofill_exclusions["processes"] == ["chrome.exe"]
        vault.set_autofill_exclusions("hosts", [])
        exclusions.sync_local_config(vault, migrate=True)
        assert settings["browser_autofill_excluded_hosts"] == []
        assert vault.autofill_exclusions["packages"] == ["com.example.app"]
    finally:
        vault.close()


def test_diverged_pmve_merge_keeps_each_platform_and_removal(tmp_path):
    base, local_path, remote_path = (tmp_path / name for name in ("base.pmv", "local.pmv", "remote.pmv"))
    vault = Vault.create_pmve(base, PASSWORD, RECOVERY)
    vault.set_autofill_exclusions("hosts", ["old.example"])
    vault.close()
    shutil.copy2(base, local_path)
    shutil.copy2(base, remote_path)
    local, remote = Vault.open(local_path, PASSWORD), Vault.open(remote_path, PASSWORD)
    try:
        local.set_autofill_exclusions("hosts", [])
        local.set_autofill_exclusions("processes", ["chrome.exe"])
        remote.set_autofill_exclusions("packages", ["com.example.app"])
        remote.close()
        local.merge_and_adopt_authenticated_file(remote_path)
        assert local.autofill_exclusions["hosts"] == []
        assert local.autofill_exclusions["processes"] == ["chrome.exe"]
        assert local.autofill_exclusions["packages"] == ["com.example.app"]
        assert local.autofill_exclusions["states"]["hosts:old.example"]["deleted"]
        local.close()
        local = Vault.open(local_path, PASSWORD)
        assert local.autofill_exclusions["hosts"] == []
    finally:
        local.close()
        remote.close()


def test_fast_forward_file_replacement_restores_local_cache(tmp_path, monkeypatch):
    settings = {}
    monkeypatch.setattr(config, "get", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    local_path, remote_path = tmp_path / "local.pmv", tmp_path / "remote.pmv"
    local = Vault.create_pmve(local_path, PASSWORD, RECOVERY)
    local.set_autofill_exclusions("hosts", ["old.example"])
    exclusions.sync_local_config(local, migrate=True)
    shutil.copy2(local_path, remote_path)
    remote = Vault.open(remote_path, PASSWORD)
    try:
        remote.set_autofill_exclusions("hosts", ["new.example"])
        remote.set_autofill_exclusions("processes", ["chrome.exe"])
        remote.close()
        local.replace_authenticated_file(remote_path)
        exclusions.sync_local_config(local)
        assert settings["browser_autofill_excluded_hosts"] == ["new.example"]
        assert settings["native_autofill_excluded"] == ["chrome.exe"]
        assert local.autofill_exclusions["states"]["hosts:old.example"]["deleted"]
    finally:
        local.close()
        remote.close()


def test_backup_exclusions_roundtrip_and_import_merge(tmp_path):
    path = tmp_path / "backup.pmbak"
    value = exclusions.update({}, "hosts", ["example.com"], now=1)
    value = exclusions.update(value, "hosts", [], now=2)
    backup.export_encrypted([], path, PASSWORD, autofill_exclusions=value)
    payload = backup.import_encrypted_with_meta(path, PASSWORD)
    assert payload.autofill_exclusions == value
    vault = Vault.create_pmve(tmp_path / "vault.pmv", PASSWORD, RECOVERY)
    try:
        vault.replace_autofill_exclusions({"hosts": ["example.com"], "packages": ["com.example.app"]})
        vault.sync_merge([], payload.export_epoch, incoming_autofill_exclusions=payload.autofill_exclusions)
        assert vault.autofill_exclusions["hosts"] == []
        assert vault.autofill_exclusions["packages"] == ["com.example.app"]
    finally:
        vault.close()


def test_dialog_edits_are_saved_in_encrypted_vault(tmp_path, monkeypatch):
    from PySide6.QtWidgets import QApplication
    from ui.dialogs import NativeAutofillExcludeDialog
    app = QApplication.instance() or QApplication([])
    settings = {}
    monkeypatch.setattr(config, "get", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    dialog = NativeAutofillExcludeDialog(vault=vault)
    try:
        original_save = vault.save
        def fail():
            raise OSError("disk full")
        monkeypatch.setattr(vault, "save", fail)
        dialog._input.setText("CHROME.EXE")
        dialog._add_from_input()
        assert not dialog._hint.isHidden()
        assert "disk full" in dialog._hint.text()
        assert dialog._input.text() == "CHROME.EXE"
        assert settings == {}
        assert vault.autofill_exclusions["processes"] == []
        monkeypatch.setattr(vault, "save", original_save)
        dialog._add("CHROME.EXE")
        dialog._input.setText("https://Login.Example.com/path")
        dialog._add_from_input()
        reopened = Vault.open(path, PASSWORD)
        try:
            assert reopened.autofill_exclusions["processes"] == ["chrome.exe"]
            assert reopened.autofill_exclusions["hosts"] == ["login.example.com"]
        finally:
            reopened.close()
        dialog._remove_exclusion("hosts", "login.example.com")
        dialog._remove("chrome.exe")
        assert vault.autofill_exclusions["hosts"] == []
        assert vault.autofill_exclusions["processes"] == []
        assert all(state["deleted"] for state in vault.autofill_exclusions["states"].values())
    finally:
        dialog.deleteLater()
        app.processEvents()
        vault.close()


def test_account_switch_migrates_each_accounts_legacy_exclusions_once(tmp_path, monkeypatch):
    from types import MethodType, SimpleNamespace
    from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QListWidget, QPushButton
    from ui import app as app_ui
    application = QApplication.instance() or QApplication([])
    current = ["A"]
    accounts = {
        "A": {"browser_autofill_excluded_hosts": ["a.example"], "native_autofill_excluded": ["A.EXE"]},
        "B": {"browser_autofill_excluded_hosts": ["b.example"], "native_autofill_excluded": ["B.EXE"]},
    }
    monkeypatch.setattr(config, "get_current_user", lambda: current[0])
    monkeypatch.setattr(config, "get", lambda key, default=None: accounts[current[0]].get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: accounts[current[0]].__setitem__(key, value))
    monkeypatch.setattr(app_ui.media_files, "ensure_vault_context", lambda vault: None)
    monkeypatch.setattr(app_ui.QTimer, "singleShot", lambda *args: None)
    vault_a = Vault.create_pmve(tmp_path / "a.pmv", PASSWORD, RECOVERY)
    vault_b = Vault.create_pmve(tmp_path / "b.pmv", PASSWORD, RECOVERY)
    host = SimpleNamespace(vault=vault_a, _locked=False, search=QLineEdit(), list=QListWidget(),
                           count_label=QLabel(), _list_add_btn=QPushButton(), _active_type=None,
                           _leak_attempted_revisions=set())
    for method in ("_sync_kdf_profile_to_config", "_rebuild_tag_chips", "_update_alpha_nav",
                   "_update_recycle_btn", "_update_password_stats", "_schedule_leak_audit", "_show_empty",
                   "_close_workspace_pages", "_install_local_backup_hooks", "_flash", "_run_auto_maintenance"):
        setattr(host, method, lambda *args: None)
    host.reload = MethodType(app_ui.MainWindow.reload, host)
    try:
        host.reload()
        assert vault_a.autofill_exclusions["hosts"] == ["a.example"]
        current[0] = "B"
        app_ui.MainWindow._switch_vault(host, vault_b)
        assert vault_b.autofill_exclusions["hosts"] == ["b.example"]
        assert vault_b.autofill_exclusions["processes"] == ["b.exe"]
        assert accounts["B"]["browser_autofill_excluded_hosts"] == ["b.example"]
        vault_b.set_autofill_exclusions("hosts", [])
        vault_b.set_autofill_exclusions("processes", [])
        current[0] = "A"
        app_ui.MainWindow._switch_vault(host, vault_a)
        assert accounts["A"]["browser_autofill_excluded_hosts"] == ["a.example"]
        current[0] = "B"
        app_ui.MainWindow._switch_vault(host, vault_b)
        assert accounts["B"]["browser_autofill_excluded_hosts"] == []
        assert accounts["B"]["native_autofill_excluded"] == []
        assert vault_b.autofill_exclusions["hosts"] == []
    finally:
        application.processEvents()
        vault_a.close()
        vault_b.close()


def test_locked_account_switch_migrates_before_reload(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from ui import app as app_ui
    settings = {"browser_autofill_excluded_hosts": ["b.example"], "native_autofill_excluded": ["B.EXE"]}
    monkeypatch.setattr(config, "get_current_user", lambda: "B")
    monkeypatch.setattr(config, "get", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    monkeypatch.setattr(app_ui.media_files, "ensure_vault_context", lambda vault: None)
    monkeypatch.setattr(app_ui.QTimer, "singleShot", lambda *args: None)
    path = tmp_path / "b.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    def reload_while_locked():
        assert host._locked
        reopened = Vault.open(path, PASSWORD)
        try:
            assert reopened.autofill_exclusions["hosts"] == ["b.example"]
            assert reopened.autofill_exclusions["processes"] == ["b.exe"]
        finally:
            reopened.close()
    host = SimpleNamespace(_locked=True, _close_workspace_pages=lambda reason: None,
                           _install_local_backup_hooks=lambda: None, _leak_attempted_revisions=set(),
                           search=SimpleNamespace(clear=lambda: None), reload=reload_while_locked,
                           _flash=lambda message: None, _run_auto_maintenance=lambda: None)
    try:
        app_ui.MainWindow._switch_vault(host, vault)
        assert settings["native_autofill_excluded"] == ["b.exe"]
        assert settings["autofill_exclusions_migrated_vault_id"] == str(vault.vault_identity.vault_id)
    finally:
        vault.close()


def test_unified_exclusions_have_no_platform_sections_and_remove_synced_android_item(tmp_path, monkeypatch):
    from PySide6.QtWidgets import QApplication, QLabel, QPushButton
    from ui.dialogs import NativeAutofillExcludeDialog
    app = QApplication.instance() or QApplication([])
    settings = {}
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    path = tmp_path / "unified.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.replace_autofill_exclusions({"packages": ["com.example.app"],
                                       "hosts": ["example.com"], "processes": ["example.exe"]})
    dialog = NativeAutofillExcludeDialog(vault=vault)
    try:
        assert dialog._list_lay.count() == 3
        assert not hasattr(dialog, "_package_list")
        assert not hasattr(dialog, "_site_list")
        rows = [dialog._list_lay.itemAt(i).widget() for i in range(3)]
        assert [row.findChild(QLabel).text() for row in rows] == ["com.example.app", "example.com", "example.exe"]
        assert all(len(row.findChildren(QLabel)) == 1 for row in rows)
        package_row = next(row for row in rows if row.property("exclusion_category") == "packages")
        package_row.findChild(QPushButton).click()
        assert dialog._list_lay.count() == 2
        reopened = Vault.open(path, PASSWORD)
        try:
            value = reopened.autofill_exclusions
            assert value["packages"] == []
            assert value["hosts"] == ["example.com"]
            assert value["processes"] == ["example.exe"]
            assert value["states"]["packages:com.example.app"]["deleted"]
        finally:
            reopened.close()
        assert not any(key != "device_identities" and not key.startswith("vault_history_v1_") for key in settings)
    finally:
        dialog.deleteLater()
        app.processEvents()
        vault.close()


def test_unified_input_and_background_program_picker(monkeypatch):
    from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QLabel
    from ui import dialogs
    from core import native_autofill
    app = QApplication.instance() or QApplication([])
    settings = {}
    monkeypatch.setattr(config, "get", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    monkeypatch.setattr(dialogs.window_tracker, "running_process_identities", lambda: [
        ("background-agent.exe", r"C:\Apps\background-agent.exe"), ("example.exe", "")])
    monkeypatch.setattr(dialogs.window_tracker, "foreground_process_name", lambda: pytest.fail("used foreground instead of list"))
    monkeypatch.setattr(native_autofill, "signer_certificate_sha256", lambda _: pytest.fail("unneeded signer probe"))

    def choose(picker):
        assert any(label.text() == "选择排除程序" for label in picker.findChildren(QLabel))
        assert picker._list.count() == 2
        picker._search.setText("background")
        assert not picker._list.item(0).isHidden()
        assert picker._list.item(1).isHidden()
        picker._list.setCurrentRow(0)
        picker.accept()
        return QDialog.Accepted

    monkeypatch.setattr(dialogs.ProgramPickerDialog, "exec", choose)
    dialog = dialogs.NativeAutofillExcludeDialog()
    try:
        assert not hasattr(dialog, "_site_input")
        assert dialog.findChildren(QLineEdit) == [dialog._input]
        dialog._input.setText("https://Login.Example.com/path")
        dialog._add_from_input()
        assert settings["browser_autofill_excluded_hosts"] == ["login.example.com"]
        assert dialog._input.text() == ""
        dialog._input.setText("EXAMPLE.EXE")
        dialog._add_from_input()
        dialog._choose_program.click()
        assert settings["native_autofill_excluded"] == ["background-agent.exe", "example.exe"]
        assert dialog._list_lay.count() == 3
        dialog._input.setText("https://example.exe")
        dialog._add_from_input()
        assert settings["browser_autofill_excluded_hosts"] == ["example.exe", "login.example.com"]
        assert settings["native_autofill_excluded"] == ["background-agent.exe", "example.exe"]
    finally:
        dialog.deleteLater()
        app.processEvents()
