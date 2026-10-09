import time
import threading

from PySide6.QtWidgets import QApplication, QDialog

from core import backup, crypto
from core.models import Entry
from ui import dialogs


def _app():
    return QApplication.instance() or QApplication([])


def _wait(app, predicate):
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.005)
    assert predicate()


def test_passkey_backup_rejects_weak_password_without_finishing_dialog():
    app = _app()
    dialog = dialogs.BackupPasswordDialog("export", requires_strong_password=True)
    finished = []
    dialog.finished.connect(finished.append)
    dialog.pw.setText("weak")
    dialog.pw2.setText("weak")
    dialog.accept()
    assert not finished and dialog.password == ""
    assert dialog.hint.text()
    dialog.pw.setText("StrongBackup123!")
    dialog.pw2.setText("StrongBackup123!")
    dialog.accept()
    assert dialog.result() == QDialog.Accepted
    assert dialog.password == "StrongBackup123!"


def test_import_wrong_password_retries_inside_same_dialog(monkeypatch):
    app = _app()
    calls = []
    payload = backup.BackupPayload()

    def decrypt(path, password):
        calls.append(password)
        if password == "wrong":
            raise crypto.DecryptError()
        return payload

    monkeypatch.setattr(backup, "import_encrypted_with_meta", decrypt)
    dialog = dialogs.BackupPasswordDialog("import", import_path="backup.pmbak")
    finished = []
    dialog.finished.connect(finished.append)
    dialog.pw.setText("wrong")
    dialog.accept()
    _wait(app, lambda: dialog._worker is None)
    assert not finished and dialog.hint.text()
    dialog.pw.setText("correct")
    dialog.accept()
    _wait(app, lambda: dialog.result() == QDialog.Accepted)
    assert calls == ["wrong", "correct"]
    assert dialog.payload is payload


def test_archive_mismatch_keeps_window_and_can_be_corrected():
    app = _app()
    dialog = dialogs.ArchivePasswordDialog()
    finished = []
    dialog.finished.connect(finished.append)
    dialog.pw.setText("password")
    dialog.pw2.setText("other")
    dialog.accept()
    assert not finished and dialog.hint.text()
    dialog.pw2.setText("password")
    dialog.accept()
    assert dialog.result() == QDialog.Accepted


def test_cancel_during_decryption_does_not_accept_or_retain_late_plaintext(monkeypatch):
    app = _app()
    started = threading.Event()
    release = threading.Event()
    done = threading.Event()
    entry = Entry(title="Private", password="secret")

    def decrypt(path, password):
        started.set()
        assert release.wait(3)
        return backup.BackupPayload(entries=[entry])

    monkeypatch.setattr(backup, "import_encrypted_with_meta", decrypt)
    dialog = dialogs.BackupPasswordDialog("import", import_path="backup.pmbak")
    dialog.pw.setText("password")
    dialog.accept()
    worker = dialog._worker
    worker.finished.connect(done.set)
    try:
        _wait(app, started.is_set)
        dialog.reject()
        release.set()
        _wait(app, done.is_set)
        assert dialog.result() == QDialog.Rejected
        assert dialog.payload is None and dialog.password == ""
        assert entry.password == "" and entry.title == ""
        assert not any(worker._password)
    finally:
        release.set()
        worker.wait(3000)


def test_lock_cleanup_rejection_clears_verified_backup_payload():
    app = _app()
    dialog = dialogs.BackupPasswordDialog("import", import_path="backup.pmbak")
    entry = Entry(title="Private", password="secret")
    dialog._verified(backup.BackupPayload(entries=[entry]))
    dialog.reject()
    assert dialog.payload is None
    assert entry.password == "" and entry.title == ""
