from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import sys

import pytest
from PySide6.QtWidgets import QDialog

from core import config, startup
from ui import startup as startup_ui


def test_packaged_startup_command_quotes_path_and_contains_no_credentials(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", r"C:\Program Files\FAE Vault\FAEVault.exe")
    assert startup.launch_command() == '"C:\\Program Files\\FAE Vault\\FAEVault.exe" --autostart'


def test_source_startup_command_uses_absolute_script_and_windowless_python(monkeypatch, tmp_path):
    python = tmp_path / "Python Test" / "python.exe"
    python.parent.mkdir()
    python.with_name("pythonw.exe").touch()
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(sys, "executable", str(python))
    command = startup.launch_command()
    assert str(python.with_name("pythonw.exe")) in command
    assert str(Path(startup.__file__).resolve().parents[1] / "__main__.py") in command
    assert command.endswith(" --autostart")


@pytest.fixture
def registry(monkeypatch):
    values = {"UnrelatedApp": "keep"}
    def query(key, name):
        if name not in values:
            raise FileNotFoundError
        return values[name], 1
    def delete(key, name):
        if name not in values:
            raise FileNotFoundError
        del values[name]
    fake = SimpleNamespace(
        HKEY_CURRENT_USER="current-user", KEY_SET_VALUE=2, REG_SZ=1,
        OpenKey=lambda *args: nullcontext("key"),
        CreateKeyEx=lambda *args: nullcontext("key"), QueryValueEx=query,
        SetValueEx=lambda key, name, reserved, kind, value: values.update({name: value}),
        DeleteValue=delete,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(sys, "platform", "win32")
    return values


def test_startup_toggle_round_trip_does_not_touch_other_apps(registry):
    assert not startup.is_enabled()
    startup.set_enabled(True)
    assert startup.is_enabled()
    assert registry[startup.RUN_VALUE] == startup.launch_command()
    startup.set_enabled(False)
    startup.set_enabled(False)
    assert not startup.is_enabled()
    assert registry == {"UnrelatedApp": "keep"}


@pytest.mark.parametrize("saved,args,expected", [
    (False, [], False), (True, [], True), (True, ["--autostart"], True),
    (False, ["--autostart"], False), (False, ["--silent"], True),
    (True, ["--passkey-unlock"], False), (True, ["--show"], False),
])
def test_silent_launch_preferences_and_explicit_activation(monkeypatch, saved, args, expected):
    monkeypatch.setattr(config, "get", lambda key, default=None: saved)
    assert startup.silent_requested(args) is expected


def test_silent_setting_is_shared_across_accounts():
    data = {"current_user": "first", "account_settings": {"second": {}}}
    config._write_key(data, "silent_start", True)
    data["current_user"] = "second"
    assert config._read_key(data, "silent_start") is True
    assert data["silent_start"] is True


def test_silent_start_never_constructs_unlock_dialog_until_tray_activation(monkeypatch):
    callbacks, quit_settings = [], []
    monkeypatch.setattr(startup_ui.tray, "setup_tray", lambda callback: callbacks.append(callback) or object())
    monkeypatch.setattr(startup_ui, "UnlockDialog", lambda: pytest.fail("unexpected unlock prompt"))
    session = startup_ui.LockedStartupSession(SimpleNamespace(setQuitOnLastWindowClosed=quit_settings.append))
    assert session.start()
    assert len(callbacks) == 1
    assert session.window is None
    assert quit_settings == [False]


def test_missing_tray_falls_back_without_disabling_normal_exit(monkeypatch):
    monkeypatch.setattr(startup_ui.tray, "setup_tray", lambda callback: None)
    session = startup_ui.LockedStartupSession(SimpleNamespace(
        setQuitOnLastWindowClosed=lambda _: pytest.fail("changed lifetime without tray")))
    assert not session.start()


def test_cancelled_unlock_keeps_locked_tray_session_reopenable(monkeypatch):
    calls = []
    monkeypatch.setattr(startup_ui.widgets, "app_icon", lambda: None)
    monkeypatch.setattr(startup_ui, "UnlockDialog", lambda: SimpleNamespace(
        setWindowIcon=lambda _: None, exec=lambda: calls.append("prompt") or QDialog.Rejected))
    session = startup_ui.LockedStartupSession(object())
    session.open()
    session.open()
    assert calls == ["prompt", "prompt"]
    assert session.window is None
    assert not session._opening


def test_successful_unlock_opens_window_once_and_restores_exit_behavior(monkeypatch):
    from ui import app as app_ui
    events = []
    monkeypatch.setattr(startup_ui.widgets, "app_icon", lambda: None)
    monkeypatch.setattr(startup_ui, "UnlockDialog", lambda: SimpleNamespace(
        setWindowIcon=lambda _: None, exec=lambda: QDialog.Accepted, vault="fake-vault"))
    monkeypatch.setattr(app_ui, "MainWindow", lambda vault: SimpleNamespace(
        show=lambda: events.append(("show", vault)), _show_from_tray=lambda: events.append("restore")))
    session = startup_ui.LockedStartupSession(SimpleNamespace(
        setQuitOnLastWindowClosed=lambda value: events.append(("quit", value))))
    session.open()
    session.open()
    assert events == [("quit", True), ("show", "fake-vault"), "restore"]


def test_registry_failure_rolls_back_checkbox_and_reports_error(monkeypatch):
    from ui.settings_page import SettingsPage
    def fail(enabled):
        raise PermissionError("denied")
    monkeypatch.setattr(startup, "set_enabled", fail)
    states, notes = [], []
    page = SimpleNamespace(start_at_login=SimpleNamespace(
        blockSignals=lambda _: None, setChecked=states.append),
        _startup_note=SimpleNamespace(setText=notes.append))
    SettingsPage._on_start_at_login_toggled(page, True)
    assert states == [False]
    assert "denied" in notes[0]


def test_tray_reuse_refreshes_actions_after_unlock(monkeypatch):
    from PySide6.QtWidgets import QApplication
    from ui import tray
    app = QApplication.instance() or QApplication([])
    connections = []

    class FakeTray:
        def __init__(self, icon):
            self.activated = SimpleNamespace(connect=connections.append)
            self.messageClicked = SimpleNamespace(connect=lambda callback: None)
        @staticmethod
        def isSystemTrayAvailable():
            return True
        def setToolTip(self, text):
            pass
        def setContextMenu(self, menu):
            self.menu = menu
        def show(self):
            pass

    monkeypatch.setattr(tray, "_tray", None)
    monkeypatch.setattr(tray, "_menu", None)
    monkeypatch.setattr(tray, "_on_open", None)
    monkeypatch.setattr(tray, "QSystemTrayIcon", FakeTray)
    monkeypatch.setattr(tray.widgets, "app_icon", lambda: None)
    initial = tray.setup_tray(lambda: None)
    callback = lambda: None
    reused = tray.setup_tray(callback, extra_actions=[("Lock simulation", lambda: None)])
    assert reused is initial
    assert "Lock simulation" in [a.text() for a in reused.menu.actions()]
    assert tray._on_open is callback
    assert len(connections) == 1
    assert app is not None
