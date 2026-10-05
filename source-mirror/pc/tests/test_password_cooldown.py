"""Password cooldown deadlines, restart persistence and UI recovery."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from core import config
from ui.dialogs import ConfirmPasswordDialog


def test_failure_rounds_and_backoff_survive_reopening(monkeypatch):
    values = {}
    clock = [100.0]
    monkeypatch.setattr(config, "get_lockout", lambda key, default=0: (values.get(key, default), True))
    monkeypatch.setattr(config, "set_lockout", lambda key, value: values.__setitem__(key, value))
    monkeypatch.setattr(config.time, "time", lambda: clock[0])
    for expected in (30, 60):
        for count in range(1, 5):
            result = config.record_password_failure()
            assert result[0] == count
            assert config.password_cooling_remaining() == 0.25 * 2 ** (count - 1)
            clock[0] += result[1]
        assert config.record_password_failure() == (0, 0.0, True, expected)
        assert config.password_cooling_remaining() == expected
        clock[0] += expected - 0.01
        assert config.password_cooling_remaining() > 0
        clock[0] += 0.01
        assert config.password_cooling_remaining() == 0
    config.clear_password_lockout()
    assert all(values[key] == 0 for key in ("fail_count", "lockout_rounds", "lockout_until", "next_attempt_at"))


def test_countdown_recomputes_deadline_and_typing_cannot_hide_it(monkeypatch):
    app = QApplication.instance() or QApplication([])
    remaining = [30.0]
    monkeypatch.setattr(config, "password_cooling_remaining", lambda: remaining[0])
    writes = []
    monkeypatch.setattr(config, "set_lockout", lambda *args: writes.append(args))
    dialog = ConfirmPasswordDialog(lambda pw: True, "确认", "请输入主密码")
    try:
        assert "30" in dialog.hint.text()
        remaining[0] = 4.2
        dialog._lk_tick()
        assert "5" in dialog.hint.text()
        dialog._set_hint("")
        assert "5" in dialog.hint.text()
        remaining[0] = 0.01
        dialog._lk_tick()
        assert "1" in dialog.hint.text()
        assert not dialog.btn.isEnabled()
        remaining[0] = 0.0
        dialog._lk_tick()
        assert dialog.btn.isEnabled()
        assert not dialog.cooling_down
        assert dialog.hint.text() == ""
        assert writes == []
    finally:
        dialog.close()


def test_switching_accounts_keeps_each_cooldown_and_updates_notice(monkeypatch):
    app = QApplication.instance() or QApplication([])
    from ui import dialogs
    selected = ["locked"]
    cooldowns = {"locked": 30.0, "ready": 0.0}
    monkeypatch.setattr(config, "list_users", lambda: [{"name": name, "file": name + ".pmv"} for name in cooldowns])
    monkeypatch.setattr(config, "get_current_user", lambda: selected[0])
    monkeypatch.setattr(config, "set_current_user", lambda name: selected.__setitem__(0, name))
    monkeypatch.setattr(config, "password_cooling_remaining", lambda: cooldowns.get(selected[0], 0))
    monkeypatch.setattr(config, "user_vault_path", lambda record: "missing.pmv")
    monkeypatch.setattr(dialogs, "_supports_recovery_unlock", lambda path: False)
    monkeypatch.setattr(dialogs.UnlockDialog, "_load_hello_availability", lambda self: None)
    dialog = dialogs.UnlockDialog()
    try:
        assert not dialog.btn.isEnabled()
        assert "30" in dialog.sub_label.text()
        assert dialog.pw.isEnabled()
        dialog.user_combo.setCurrentIndex(1)
        assert selected[0] == "ready"
        assert not dialog.cooling_down
        assert dialog.btn.isEnabled()
        dialog.user_combo.setCurrentIndex(0)
        assert selected[0] == "locked"
        assert not dialog.btn.isEnabled()
        assert "30" in dialog.sub_label.text()
        assert cooldowns["locked"] == 30.0
    finally:
        dialog.close()
