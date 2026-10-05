import hashlib
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from ui import _clipboard


def test_expired_clipboard_text_is_cleared_only_when_it_still_matches(monkeypatch):
    app = QApplication.instance() or QApplication([])
    state = {}
    monkeypatch.setattr(_clipboard.config, "get", lambda key: state.get(key))
    monkeypatch.setattr(_clipboard.config, "set", lambda key, value: state.__setitem__(key, value))
    monkeypatch.setattr(_clipboard.time, "time", lambda: 100.0)
    clipboard = app.clipboard()

    clipboard.setText("vault secret")
    _clipboard.remember_text_expiry("vault secret", 60)
    assert state["clipboard_cleanup"]["digest"] == hashlib.sha256(b"vault secret").hexdigest()
    monkeypatch.setattr(_clipboard.time, "time", lambda: 161.0)
    _clipboard.sweep_expired_text()
    assert clipboard.text() == ""
    assert state["clipboard_cleanup"] is None

    clipboard.setText("vault secret")
    monkeypatch.setattr(_clipboard.time, "time", lambda: 200.0)
    _clipboard.remember_text_expiry("vault secret", 60)
    clipboard.setText("somebody else's text")
    monkeypatch.setattr(_clipboard.time, "time", lambda: 261.0)
    _clipboard.sweep_expired_text()
    assert clipboard.text() == "somebody else's text"
    assert state["clipboard_cleanup"] is None
