import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMessageBox
from core import crypto, storage, device_identity, device_activity
from core.models import Entry
from core.vault_history import HistoryStore
from ui import i18n
from ui.devices_history import DevicesHistoryPage, HistoryWorker, preview_rows


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def vault(tmp_path, monkeypatch):
    import uuid
    monkeypatch.setattr(storage, "vault_dir", lambda: tmp_path)
    identity = uuid.uuid4()
    monkeypatch.setattr(device_identity, "load_or_create", lambda _: (identity, bytes(range(32))))
    value = storage.Vault.create_pmve_with_password_buffer(tmp_path / "vault.pmv", bytearray(b"password"), bytes(range(32)))
    yield value
    value.close()


def test_preview_rows_drop_deleted_and_all_secret_values():
    active = Entry(title="Login", username="user", password="NEVER SHOW", fields={"secret": "NEVER SHOW"})
    deleted = Entry(title="Trash", deleted_at=10)
    rows = preview_rows(SimpleNamespace(entries=[active, deleted]))
    assert rows == [{"id": active.id, "title": "Login", "username": "user"}]
    assert "NEVER SHOW" not in repr(rows)


def test_page_requires_preview_and_selection_and_has_local_entry(app, monkeypatch):
    monkeypatch.setattr(DevicesHistoryPage, "_start", lambda *_a, **_k: None)
    page = DevicesHistoryPage(SimpleNamespace())
    page._buttons()
    assert not page.restore_button.isEnabled()
    page._worker = SimpleNamespace(generation=page._generation, cancelled=SimpleNamespace(set=lambda: None))
    monkeypatch.setattr(page, "_current_sender", lambda: page._worker)
    page._completed({"rows": [{"id": "one", "title": "Title", "username": "user"}], "snapshot_id": "snapshot"})
    page.entries_list.item(0).setSelected(True)
    assert page.restore_button.isEnabled()
    page.close_page("lock")
    assert page.entries_list.count() == 0 and not page._snapshot_id


def test_restore_confirmation_cancellation_never_starts_write(app, monkeypatch):
    calls = []
    monkeypatch.setattr(DevicesHistoryPage, "_start", lambda *_a, **_k: None)
    page = DevicesHistoryPage(SimpleNamespace())
    from PySide6.QtWidgets import QListWidgetItem
    item = QListWidgetItem("safe title")
    item.setData(Qt.UserRole, "one")
    page.entries_list.addItem(item)
    item.setSelected(True)
    page._snapshot_id = "snapshot"
    monkeypatch.setattr(page, "_start", lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.No)
    page._restore()
    assert calls == []


def test_worker_preview_and_restore_actual_vault_preserves_other_entries(app, vault):
    first = Entry(title="Old title", username="old user", password="old secret")
    untouched = Entry(title="Keep", password="keep secret")
    vault.add(first)
    vault.add(untouched)
    record = HistoryStore(vault).capture()
    import copy
    edited = copy.deepcopy(first)
    edited.title, edited.password = "New title", "new secret"
    vault.update(edited)
    results = []
    errors = []
    preview = HistoryWorker(vault, "preview", 0, snapshot_id=record["snapshot_id"])
    preview.completed.connect(results.append)
    preview.failed.connect(errors.append)
    preview.run()
    assert not errors
    assert "old secret" not in repr(results)
    assert any(row["title"] == "Old title" for row in results[0]["rows"])
    restore = HistoryWorker(vault, "restore", 0, snapshot_id=record["snapshot_id"], entry_ids=[first.id])
    restore.completed.connect(results.append)
    restore.failed.connect(errors.append)
    restore.run()
    assert not errors and results[-1] == {"adopt": True}
    fresh = storage.Vault.open(vault.path, "password")
    try:
        by_id = {entry.id: entry for entry in fresh.entries}
        assert by_id[first.id].password == "old secret"
        assert by_id[untouched.id].password == "keep secret"
        assert any(row["reason"] == "pre-restore" and row["protected"] for row in HistoryStore(fresh).list())
    finally:
        fresh.close()


def test_worker_stale_current_head_rejects_restore(app, vault):
    entry = Entry(title="Before")
    vault.add(entry)
    record = HistoryStore(vault).capture()
    worker = HistoryWorker(vault, "restore", 0, snapshot_id=record["snapshot_id"], entry_ids=[entry.id])
    vault.add(Entry(title="Concurrent change"))
    failures = []
    worker.failed.connect(failures.append)
    worker.run()
    assert failures
    assert len(vault.entries) == 2


def test_writer_only_uses_authenticated_same_version_profile(app, monkeypatch):
    from ui.cloud_sync_controller import authenticated_writer_line
    monkeypatch.setattr(device_activity, "verified_last_writer", lambda _: None)
    assert i18n.tr("未知设备") in authenticated_writer_line(SimpleNamespace())
    monkeypatch.setattr(device_activity, "verified_last_writer", lambda _: {"name": "Verified PC"})
    assert "Verified PC" in authenticated_writer_line(SimpleNamespace())


def test_biometric_root_key_session_can_load_history(app, vault):
    root_session = storage.Vault.open_with_root_key(vault.path, vault.root_key_for_device_unlock())
    try:
        worker = HistoryWorker(root_session, "load", 0)
        results, failures = [], []
        worker.completed.connect(results.append)
        worker.failed.connect(failures.append)
        worker.run()
        assert results and not failures
        assert worker.root_key._closed and worker.password._closed
    finally:
        root_session.close()


def test_cancelled_worker_clears_secrets_and_never_emits(app, vault):
    worker = HistoryWorker(vault, "load", 0)
    results = []
    worker.completed.connect(results.append)
    worker.cancelled.set()
    worker.run()
    assert not results and worker.password._closed


def test_historical_password_needed_is_separate_from_failure_and_clears_secrets(app, vault, monkeypatch):
    from core.vault_history import HistoricalPasswordRequired
    def need_password(*_a, **_k):
        raise HistoricalPasswordRequired()
    monkeypatch.setattr(HistoryStore, "preview", need_password)
    worker = HistoryWorker(vault, "preview", 0, snapshot_id="snapshot")
    requests, failures = [], []
    worker.passwordRequired.connect(lambda: requests.append(True))
    worker.failed.connect(failures.append)
    worker.run()
    assert requests == [True] and not failures and worker.password._closed


def test_restore_worker_uses_head_approved_in_preview(app,vault):
    entry=Entry(title="before");vault.add(entry)
    record=HistoryStore(vault).capture()
    approved=vault.pmve_identity.root_digest
    vault.add(Entry(title="concurrent"))
    worker=HistoryWorker(vault,"restore",0,snapshot_id=record['snapshot_id'],entry_ids=[entry.id],expected_head=approved)
    failures=[];worker.failed.connect(failures.append);worker.run()
    assert failures and len(vault.entries)==2
