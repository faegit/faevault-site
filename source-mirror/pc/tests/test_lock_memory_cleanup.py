from PySide6.QtWidgets import QApplication, QDialog
from PySide6.QtTest import QTest

from core import config
from core.models import Entry
from core.storage import Vault
from ui.dialogs import RelockDialog


def test_close_clears_cached_entries_password_metadata_and_root_buffers(tmp_path):
    path = tmp_path / "memory.pmv"
    vault = Vault.create_pmve(path, "master-password", bytes(range(32)))
    source = Entry(title="Sensitive title", username="alice", password="secret", notes="private", fields={"pin": "1234"})
    vault.add(source)
    cached = vault.read_entry(source.id)
    assert cached.password == "secret"
    cached_before_save = vault.entries[0]
    vault.save()
    store = vault._pmve_store
    buffers = list(store._secret_buffers_for_test())
    assert any(any(buffer) for buffer in buffers)
    vault.close()
    assert not cached.password and not cached.title and not cached.fields
    assert cached.vault is None
    assert not cached_before_save.password and not cached_before_save.title
    assert cached_before_save.vault is None
    assert vault._password.is_empty()
    assert not vault._payloads and not vault._entry_cache and not vault._entry_meta
    assert not vault._pmve_metadata and not vault.entries
    assert all(not any(buffer) for buffer in buffers)
    reopened = Vault.open(path, "master-password")
    try:
        assert reopened.read_entry(source.id).password == "secret"
    finally:
        reopened.close()


def test_relock_opens_a_new_session_and_wrong_password_keeps_it_closed(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(config, "get_lockout", lambda _: (0, True))
    monkeypatch.setattr(config, "clear_password_lockout", lambda: None)
    path = tmp_path / "reopen.pmv"
    vault = Vault.create_pmve(path, "master-password", bytes(range(32)))
    identity = vault.pmve_identity
    vault.close()
    dialog = RelockDialog("", None, reopen_path=path, expected_pmve_identity=identity)
    try:
        wrong = []
        monkeypatch.setattr(dialog, "wrong_password", lambda: wrong.append(True))
        dialog.pw.setText("wrong-password")
        dialog.accept()
        assert wrong == [True] and dialog.vault is None and not dialog.unlocked
        assert dialog.pw.text() == ""
        dialog.pw.setText("master-password")
        dialog.accept()
        assert dialog.unlocked and dialog.result() == QDialog.Accepted
        assert dialog.vault is not vault
        assert dialog.vault.pmve_identity == identity
        assert dialog.pw.text() == ""
        dialog.vault.close()
    finally:
        dialog.deleteLater()
        app.processEvents()


def test_real_window_lock_releases_session_and_reloads_after_unlock(tmp_path, monkeypatch):
    from ui.app import MainWindow
    app = QApplication.instance() or QApplication([])
    settings = {}
    monkeypatch.setattr(config, "get", lambda key, default=None: settings.get(key, default))
    monkeypatch.setattr(config, "set", lambda key, value: settings.__setitem__(key, value))
    monkeypatch.setattr(config, "set_many", lambda values: settings.update(values))
    monkeypatch.setattr(MainWindow, "_start_passkey_broker", lambda self: None)
    monkeypatch.setattr(MainWindow, "_run_auto_maintenance", lambda self: None)
    monkeypatch.setattr(MainWindow, "apply_native_autofill_settings", lambda self: None)
    monkeypatch.setattr(MainWindow, "_setup_tray", lambda self: None)
    monkeypatch.setattr(MainWindow, "_register_session_notifications", lambda self: None)
    path = tmp_path / "window.pmv"
    vault = Vault.create_pmve(path, "master-password", bytes(range(32)))
    source = Entry(title="Private entry", password="secret")
    vault.add(source)
    window = MainWindow(vault)
    try:
        window._native_autofill_pending = ("secret snapshot",)
        window._enter_locked_state(None)
        for _ in range(200):
            app.processEvents()
            if not window._lock_cleanup_pending:
                break
            QTest.qWait(10)
        assert not window._lock_cleanup_pending
        assert window._locked and not window.isVisible()
        assert window._native_autofill_pending is None
        assert not window._filter_source_entries and not window._filter_query_entries
        assert window._detail_entry is None
        assert window.list.count() == 0 and window.detail.count() == 0
        assert vault._password.is_empty() and vault._pmve_store is None
        reopened = Vault.open(path, "master-password")
        window._restore_locked_session(reopened)
        assert not window._locked and window.vault is reopened
        assert window.list.count() == 1
        assert reopened.read_entry(source.id).password == "secret"
    finally:
        window._locked = True
        window._close_workspace_pages("exit")
        window.vault.close()
        window.deleteLater()
        app.processEvents()


def test_cleanup_waits_for_active_worker_before_destroying_keys():
    from PySide6.QtCore import QThread
    from PySide6.QtWidgets import QWidget
    from types import SimpleNamespace
    from ui.lock_cleanup import finish_cleanup
    app = QApplication.instance() or QApplication([])
    calls = []

    class Worker(QThread):
        def run(self):
            self.msleep(150)

    window = QWidget()
    worker = Worker(window)
    worker.start()
    window.vault = SimpleNamespace(close=lambda: calls.append("close"))
    window._lock_cleanup_pending = True
    window._lock_workers = [worker]
    window._lock_dialogs = []
    window._lock_futures = []
    finish_cleanup(window)
    assert calls == [] and window._lock_cleanup_pending
    for _ in range(100):
        QTest.qWait(10)
        if not window._lock_cleanup_pending:
            break
    assert calls == ["close"] and not window._lock_cleanup_pending
    window.deleteLater()
    app.processEvents()


def test_hello_relock_retains_the_new_vault_session(tmp_path, monkeypatch):
    from ui import dialogs
    app = QApplication.instance() or QApplication([])
    path = tmp_path / "hello.pmv"
    vault = Vault.create_pmve(path, "master-password", bytes(range(32)))
    identity = vault.pmve_identity
    vault.close()
    opened = Vault.open(path, "master-password")
    monkeypatch.setattr(config, "clear_password_lockout", lambda: None)
    monkeypatch.setattr(dialogs.biometric, "open_vault", lambda p: opened)
    dialog = RelockDialog("test-user", None, reopen_path=path, expected_pmve_identity=identity)
    monkeypatch.setattr(dialog, "_load_hello_availability", lambda *args: None)
    try:
        dialog._unlock_with_hello()
        assert dialog.unlocked and dialog.vault is opened
        assert opened._pmve_store is not None
        assert not opened._password.is_empty()
    finally:
        opened.close()
        dialog.deleteLater()
        app.processEvents()
