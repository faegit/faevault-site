"""PMVE LAN sync device authorization integration (server + client + registry)."""

import dataclasses
import secrets
import ssl
import threading
import time
import urllib.parse
import urllib.request
import uuid

import pytest

from core import device_identity, sync_server
from core.storage import Vault
from core.sync_client import SYNC_OP, TRANSFER_OP, LanSyncClient, SyncError


def _start_server(monkeypatch, vault):
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(vault, lambda **_: True)
    server.device_auth_enabled = True
    url, pin = server.start()
    return server, url, pin


def test_pmve_sync_authenticates_self_enrolled_device_and_rejects_unknown(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "core.device_identity.default_vault_path",
        lambda: tmp_path / "default.pmv",
    )
    vault = Vault.create_pmve(
        tmp_path / "vault.pmv",
        "correct horse battery staple",
        bytes(range(32)),
    )
    vault.ensure_device_authorized()
    vault_id = vault.vault_identity.vault_id
    own_identity = device_identity.load_or_create(vault_id)

    # 自注册设备可完成授权并拉取
    server, url, pin = _start_server(monkeypatch, vault)
    try:
        client = LanSyncClient(url, pin, op=SYNC_OP)
        client.authenticate_device(vault_id, own_identity)
        context = ssl._create_unverified_context()
        headers = {
            "Connection": "close",
            sync_server.PAIRING_HEADER: client.ticket,
            sync_server.SESSION_HEADER: client._session,
        }
        parsed = urllib.parse.urlparse(url)
        base = f"https://{parsed.hostname}:{parsed.port}"
        request = urllib.request.Request(f"{base}/api/sync/vault", headers=headers)
        with urllib.request.urlopen(request, context=context, timeout=3) as response:
            assert response.status == 200
            assert response.read()
    finally:
        server.stop()

    # 未注册设备（同一库，另一身份）认证被拒
    server2, url2, pin2 = _start_server(monkeypatch, vault)
    try:
        stranger = (uuid.uuid4(), secrets.token_bytes(32))
        client2 = LanSyncClient(url2, pin2, op=SYNC_OP)
        with pytest.raises(SyncError):
            client2.authenticate_device(vault_id, stranger)
    finally:
        server2.stop()


def test_pmve_sync_rejects_revoked_device(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "core.device_identity.default_vault_path",
        lambda: tmp_path / "default.pmv",
    )
    vault = Vault.create_pmve(
        tmp_path / "vault.pmv",
        "correct horse battery staple",
        bytes(range(32)),
    )
    vault.ensure_device_authorized()
    vault_id = vault.vault_identity.vault_id
    device_id, seed = device_identity.load_or_create(vault_id)
    from core import pmv_device_registry, pmv_sync_authorization

    store = vault._pmve_store
    metadata = store.metadata()
    records = pmv_device_registry.decode(metadata)
    existing = pmv_device_registry.latest(records, device_id)
    revoked = store.sign_device_authorization(
        dataclasses.replace(
            existing,
            revoked_at_epoch_millis=int(time.time() * 1000),
            epoch=existing.epoch + 1,
        )
    )
    updated = pmv_device_registry.with_registry(
        metadata,
        [record for record in records if record.device_id != device_id] + [revoked],
    )
    entries = []
    for summary in store.list():
        entry = store.read_entry(summary.entry_id)
        if entry is not None:
            entries.append(entry)
    store.save_full(expected_sequence=store.identity.sequence, metadata=updated, entries=entries)

    server, url, pin = _start_server(monkeypatch, vault)
    try:
        client = LanSyncClient(url, pin, op=SYNC_OP)
        with pytest.raises(SyncError):
            client.authenticate_device(vault_id, (device_id, seed))
    finally:
        server.stop()


def test_pmve_sync_waits_for_host_approval_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "core.device_identity.default_vault_path",
        lambda: tmp_path / "default.pmv",
    )
    vault = Vault.create_pmve(
        tmp_path / "vault.pmv",
        "correct horse battery staple",
        bytes(range(32)),
    )
    vault.ensure_device_authorized()
    vault_id = vault.vault_identity.vault_id

    server, url, pin = _start_server(monkeypatch, vault)
    server.sync_approval_enabled = True
    try:
        stranger = (uuid.uuid4(), secrets.token_bytes(32))
        client = LanSyncClient(url, pin, op=SYNC_OP)
        outcome = {}

        def run_auth():
            try:
                client.authenticate_device(vault_id, stranger)
                outcome["ok"] = True
            except Exception as exc:  # noqa: BLE001
                outcome["error"] = str(exc)

        thread = threading.Thread(target=run_auth, daemon=True)
        thread.start()
        deadline = time.time() + 10
        while server.pending_sync_device is None and time.time() < deadline:
            time.sleep(0.05)
        assert server.pending_sync_device is not None  # 主机等待确认，客户端停在 423 重试
        assert outcome.get("ok") is None
        assert server.approve_sync()
        thread.join(timeout=15)
        assert outcome.get("ok") is True
        assert "error" not in outcome
    finally:
        server.stop()
        vault.close()


def test_transfer_requires_device_proof_and_explicit_session_approval(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "core.device_identity.default_vault_path",
        lambda: tmp_path / "default.pmv",
    )
    vault = Vault.create_pmve(
        tmp_path / "vault.pmv",
        "correct horse battery staple",
        bytes(range(32)),
    )
    server, url, pin = _start_server(monkeypatch, vault)
    try:
        stranger = (uuid.uuid4(), secrets.token_bytes(32))
        client = LanSyncClient(url, pin, op=TRANSFER_OP)
        outcome = {}

        def authenticate():
            try:
                client.authenticate_device(vault.vault_identity.vault_id, stranger)
                outcome["ok"] = True
            except Exception as exc:  # noqa: BLE001
                outcome["error"] = str(exc)

        worker = threading.Thread(target=authenticate, daemon=True)
        worker.start()
        deadline = time.time() + 10
        while server.pending_transfer_device is None and time.time() < deadline:
            time.sleep(0.05)
        pending = server.pending_transfer_device
        assert pending is not None
        assert pending[1] == stranger[0]
        assert outcome.get("ok") is None
        assert server.approve_transfer(pending[0])
        worker.join(timeout=15)
        assert outcome.get("ok") is True
        assert "error" not in outcome
        assert client.list_transfer_items() == []
    finally:
        server.stop()
        vault.close()
