from __future__ import annotations

import json
import http.client
import hashlib
import os
import shutil
import socket
import time
import uuid
from pathlib import Path

import pytest

from core import crypto, storage, sync_server
from core.models import Entry
from core.storage import ExternalVaultChange, PmvEIdentity, Vault, VaultLineage
from core.sync_client import LanSyncClient


def _spec_root() -> Path:
    configured = os.environ.get("VAULT_SHARED_SPEC_DIR")
    root = (
        Path(configured)
        if configured
        else Path(__file__).resolve().parents[2]
        / "vault_android"
        / "spec"
        / "interop"
        / "pmv_next"
        / "v1"
    )
    return root


def _fixture_pair(writer: str = "android") -> tuple[Path, Path, str]:
    root = _spec_root()
    document = json.loads((root / "store_interop.json").read_text(encoding="utf-8"))
    seq1 = next(
        item for item in document["cases"]
        if item["writer"] == writer and item["sequence"] == 1
    )
    seq2 = next(
        item for item in document["cases"]
        if item.get("continuedFrom") == seq1["id"] and item["sequence"] == 2
    )
    return root / seq1["blob"], root / seq2["blob"], document["passwordUtf8"]


def _identity(**overrides) -> PmvEIdentity:
    values = {
        "vault_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "signing_public_key": bytes(range(32)),
        "key_revision": 1,
        "header_revision": 1,
        "sequence": 1,
        "commit_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
        "parent_commit_id": None,
        "root_digest": bytes([7]) * 32,
    }
    values.update(overrides)
    return PmvEIdentity(**values)


def test_lineage_uses_commit_parent_and_signer_not_key_revision_or_device_metadata() -> None:
    local = _identity()
    same = _identity(key_revision=99, header_revision=100)
    fast_forward = _identity(
        sequence=2,
        commit_id=uuid.UUID("33333333-3333-3333-3333-333333333333"),
        parent_commit_id=local.commit_id,
        root_digest=bytes([8]) * 32,
    )
    divergent = _identity(
        sequence=2,
        commit_id=uuid.UUID("44444444-4444-4444-4444-444444444444"),
        parent_commit_id=uuid.UUID("55555555-5555-5555-5555-555555555555"),
        root_digest=bytes([9]) * 32,
    )

    assert Vault.classify_lineage(local, same) is VaultLineage.SAME
    assert Vault.classify_lineage(local, fast_forward) is VaultLineage.FAST_FORWARD
    assert Vault.classify_lineage(fast_forward, local) is VaultLineage.REMOTE_STALE
    assert Vault.classify_lineage(local, divergent) is VaultLineage.DIVERGED
    assert Vault.classify_lineage(local, _identity(signing_public_key=bytes(32))) is VaultLineage.DIFFERENT
    assert Vault.classify_lineage(local, None) is VaultLineage.INVALID


def test_lineage_accepts_authenticated_non_adjacent_ancestor() -> None:
    ancestor = _identity(sequence=1)
    descendant = _identity(
        sequence=4,
        commit_id=uuid.uuid4(),
        parent_commit_id=uuid.uuid4(),
        authenticated_ancestor_commit_ids=frozenset({ancestor.commit_id}),
    )
    assert Vault.classify_lineage(ancestor, descendant) is VaultLineage.FAST_FORWARD
    assert Vault.classify_lineage(descendant, ancestor) is VaultLineage.REMOTE_STALE


@pytest.mark.parametrize(
    "identity",
    [
        _identity(sequence=-1),
        _identity(sequence=True),
        _identity(key_revision=0),
        _identity(header_revision=0),
        _identity(vault_id="11111111-1111-1111-1111-111111111111"),
        _identity(commit_id="22222222-2222-2222-2222-222222222222"),
        _identity(root_digest=bytearray(32)),
    ],
)
def test_malformed_identity_is_invalid(identity) -> None:
    assert Vault.classify_lineage(_identity(), identity) is VaultLineage.INVALID


def test_shared_android_pc_seq1_seq2_authenticate_and_replace_as_fast_forward(tmp_path) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local_path = tmp_path / "local.pmv"
    shutil.copy2(seq1, local_path)
    vault = Vault.open(local_path, password)
    before = vault.pmve_identity

    remote = vault.authenticate_external_file(seq2)
    assert remote.sequence == 2
    assert remote.parent_commit_id == before.commit_id
    assert vault.classify_lineage(before, remote) is VaultLineage.FAST_FORWARD
    adopted = vault.replace_authenticated_file(seq2)

    assert adopted == remote
    assert vault.pmve_identity == remote
    assert local_path.read_bytes() == seq2.read_bytes()
    vault.close()


def test_truncated_or_different_signer_file_is_never_adopted(tmp_path) -> None:
    seq1, seq2, password = _fixture_pair("android")
    different, _different_seq2, _password = _fixture_pair("pc")
    local_path = tmp_path / "local.pmv"
    truncated = tmp_path / "truncated.pmv"
    shutil.copy2(seq1, local_path)
    with seq2.open("rb") as source, truncated.open("wb") as output:
        output.write(source.read(seq2.stat().st_size // 2))
    original = local_path.read_bytes()
    vault = Vault.open(local_path, password)

    with pytest.raises(crypto.DecryptError, match="认证失败"):
        vault.authenticate_external_file(truncated)
    with pytest.raises(crypto.DecryptError, match="认证失败"):
        vault.authenticate_external_file(different)
    assert local_path.read_bytes() == original
    vault.close()


def test_external_pmve_authentication_enforces_file_size_limit(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local_path = tmp_path / "local.pmv"
    shutil.copy2(seq1, local_path)
    vault = Vault.open(local_path, password)
    monkeypatch.setattr(storage, "MAX_SYNC_BYTES", seq2.stat().st_size - 1)

    with pytest.raises(crypto.DecryptError, match="10 GB"):
        vault.authenticate_external_file(seq2)
    vault.close()


@pytest.mark.parametrize("lineage", [
    VaultLineage.REMOTE_STALE,
    VaultLineage.DIVERGED,
    VaultLineage.DIFFERENT,
    VaultLineage.INVALID,
])
def test_replace_authenticated_file_rejects_every_non_descendant_lineage(
    tmp_path, monkeypatch, lineage
) -> None:
    seq1, seq2, password = _fixture_pair("android")
    local_path = tmp_path / "local.pmv"
    shutil.copy2(seq2, local_path)
    vault = Vault.open(local_path, password)
    local = vault.pmve_identity
    remotes = {
        VaultLineage.REMOTE_STALE: _identity(
            vault_id=local.vault_id,
            signing_public_key=local.signing_public_key,
            key_revision=local.key_revision,
            header_revision=local.header_revision,
            sequence=local.sequence - 1,
            commit_id=local.parent_commit_id,
            parent_commit_id=None,
            root_digest=bytes([3]) * 32,
        ),
        VaultLineage.DIVERGED: _identity(
            vault_id=local.vault_id,
            signing_public_key=local.signing_public_key,
            sequence=local.sequence,
        ),
        VaultLineage.DIFFERENT: _identity(vault_id=uuid.uuid4()),
        VaultLineage.INVALID: _identity(sequence=-1),
    }
    original = local_path.read_bytes()
    monkeypatch.setattr(Vault, "authenticate_external_file", lambda _self, _path: remotes[lineage])

    with pytest.raises(ExternalVaultChange, match=lineage.value):
        vault.replace_authenticated_file(tmp_path / "untrusted.pmv")
    assert local_path.read_bytes() == original
    assert vault.pmve_identity == local
    vault.close()


def test_lan_sync_retains_exclusions_from_both_platforms(tmp_path, monkeypatch) -> None:
    seq1, _, password = _fixture_pair("android")
    server_path = tmp_path / "server.pmv"
    client_path = tmp_path / "client.pmv"
    shutil.copy2(seq1, server_path)
    shutil.copy2(seq1, client_path)
    server_vault = Vault.open(server_path, password)
    client_vault = Vault.open(client_path, password)
    server_vault.set_autofill_exclusions("packages", ["com.example.app"])
    client_vault.set_autofill_exclusions("processes", ["example.exe"])
    client_vault.set_autofill_exclusions("hosts", ["example.com"])
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: False)
    try:
        pairing_url, pin = server.start()
        result = LanSyncClient(pairing_url, pin).sync_vault(client_vault)
        assert result["verified"] is True
        for vault in (server_vault, client_vault):
            assert vault.autofill_exclusions["packages"] == ["com.example.app"]
            assert vault.autofill_exclusions["processes"] == ["example.exe"]
            assert vault.autofill_exclusions["hosts"] == ["example.com"]
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        client_vault.close()
        server_vault.close()


def test_lan_v2_pushes_direct_descendant_as_file_without_bytes_merge(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    server_path = tmp_path / "server.pmv"
    client_path = tmp_path / "client.pmv"
    shutil.copy2(seq1, server_path)
    shutil.copy2(seq2, client_path)
    server_vault = Vault.open(server_path, password)
    client_vault = Vault.open(client_path, password)
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: False)
    pairing_url, pin = server.start()
    try:
        result = LanSyncClient(pairing_url, pin).sync_vault(client_vault)
        assert {key: result[key] for key in ("lineage", "replaced", "pushed")} == {
            "lineage": "REMOTE_STALE",
            "replaced": False,
            "pushed": True,
        }
        assert result["local_count"] == len(client_vault.entries)
        assert result["merged_count"] == len(client_vault.entries)
        # remote_bytes records the downloaded pre-sync snapshot; the server file
        # grows after the client pushes its descendant commit.
        assert result["remote_bytes"] == seq1.stat().st_size
        assert result["uploaded"] is True
        assert result["verified"] is True
        assert server_vault.pmve_identity == client_vault.pmve_identity
        # Android sends /api/sync/cancel after the successful push.  The PC
        # host must retain the committed result rather than report cancelled.
        deadline = time.monotonic() + 2
        while server._server is not None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert isinstance(server._result, dict)
        assert server._result.get("verified") is True
        assert server._server is None
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        client_vault.close()
        server_vault.close()


def test_lan_v2_exposes_sync_progress_and_verify_phase(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    server_path = tmp_path / "server.pmv"
    client_path = tmp_path / "client.pmv"
    shutil.copy2(seq1, server_path)
    shutil.copy2(seq2, client_path)
    server_vault = Vault.open(server_path, password)
    client_vault = Vault.open(client_path, password)
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: False)
    pairing_url, pin = server.start()

    phases_seen = []
    try:
        result = LanSyncClient(pairing_url, pin).sync_vault(
            client_vault,
            on_phase=lambda phase, sent, total: phases_seen.append(phase),
        )
        # 客户端经历 接收 -> 验证 -> 发送
        assert "download" in phases_seen
        assert "verify" in phases_seen
        assert "upload" in phases_seen
        # 服务端完成接收/验证并最终标记完成；收发字节进度均已记录
        assert server.sync_phase == "done"
        assert server.sync_receive_progress is not None
        assert server.sync_receive_progress[0] == server.sync_receive_progress[1] > 0
        assert server.sync_send_progress is not None
        assert server.sync_send_progress[0] == server.sync_send_progress[1] > 0
        assert result["uploaded"] is True
        assert result["verified"] is True
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        client_vault.close()
        server_vault.close()


def test_lan_v2_diverged_vaults_converge_bidirectionally(tmp_path, monkeypatch) -> None:
    seq1, _seq2, password = _fixture_pair("android")
    server_path = tmp_path / "server-diverged.pmv"
    client_path = tmp_path / "client-diverged.pmv"
    shutil.copy2(seq1, server_path)
    shutil.copy2(seq1, client_path)
    server_vault = Vault.open(server_path, password)
    client_vault = Vault.open(client_path, password)
    base_titles = {entry.title for entry in server_vault.entries}
    server_vault.add(Entry(title="Server edit", username="server", password="one"))
    client_vault.add(Entry(title="Client edit", username="client", password="two"))
    assert Vault.classify_lineage(
        client_vault.pmve_identity,
        server_vault.pmve_identity,
    ) is VaultLineage.DIVERGED

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: False)
    pairing_url, pin = server.start()
    try:
        result = LanSyncClient(pairing_url, pin).sync_vault(client_vault)

        assert result["lineage"] == "DIVERGED"
        assert result["merged"] is True
        assert result["pushed"] is True
        assert result["verified"] is True
        expected_titles = base_titles | {"Server edit", "Client edit"}
        assert {entry.title for entry in client_vault.entries} == expected_titles
        assert {entry.title for entry in server_vault.entries} == expected_titles
        assert server_vault.pmve_identity == client_vault.pmve_identity
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        client_vault.close()
        server_vault.close()


def test_diverged_merge_copies_local_only_media(tmp_path, monkeypatch) -> None:
    from io import BytesIO
    from core.pmv_attachment import AttachmentKind
    from core.pmv_media_ref import from_store_ref
    from core.pmv_vault_store import PmvVaultStore, ObjectImport, MutationContent

    seq1, _, password = _fixture_pair("android")
    local, candidate = tmp_path / "local.pmv", tmp_path / "candidate.pmv"
    shutil.copy2(seq1, local)
    shutil.copy2(seq1, candidate)
    plain, object_id = b"local only image", uuid.uuid4()
    with PmvVaultStore.open_password(local, password.encode()) as source:
        entries = [source.read_entry(s.entry_id) for s in source.list()]
        source.apply_mutation(
            expected_sequence=source.identity.sequence,
            object_imports=[ObjectImport(BytesIO(plain), len(plain), object_id, 1, AttachmentKind.IMAGE)],
            prepare=lambda refs: MutationContent(source.metadata(), entries + [
                Entry(title="Local image", fields={"images": [from_store_ref(refs[0]).to_json()]})
            ]),
        )
    with PmvVaultStore.open_password(candidate, password.encode()) as remote:
        remote.save_full(expected_sequence=remote.identity.sequence, metadata=remote.metadata(),
                         entries=[remote.read_entry(s.entry_id) for s in remote.list()] + [Entry(title="Remote edit")])
    vault = Vault.open(local, password)
    server_vault = Vault.open(candidate, password)
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: False)
    url, pin = server.start()
    try:
        result = LanSyncClient(url, pin).sync_vault(vault)
        assert result["merged"] and result["verified"] and result["pushed"]
        assert vault.pmve_identity == server_vault.pmve_identity
        assert {"Local image", "Remote edit"} <= {e.title for e in vault.entries}
        for path in (local, candidate):
            with PmvVaultStore.open_password(path, password.encode()) as merged:
                output = BytesIO()
                merged.open_object(object_id, 1, output)
                assert output.getvalue() == plain
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        server_vault.close()
        vault.close()


def test_lan_v2_fast_forward_converges_password_slot(tmp_path, monkeypatch) -> None:
    seq1, _seq2, password = _fixture_pair("android")
    new_password = "aligned-new-password"
    server_path = tmp_path / "server-password.pmv"
    client_path = tmp_path / "client-password.pmv"
    shutil.copy2(seq1, server_path)
    shutil.copy2(seq1, client_path)
    server_vault = Vault.open(server_path, password)
    client_vault = Vault.open(client_path, password)
    server_vault.change_password(new_password)

    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: False)
    pairing_url, pin = server.start()
    try:
        result = LanSyncClient(pairing_url, pin).sync_vault(client_vault)

        assert result["lineage"] == "FAST_FORWARD"
        assert result["key_converged"] is True
        assert result["password_changed"] is True
        assert server_vault.pmve_identity == client_vault.pmve_identity
    finally:
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        client_vault.close()
        server_vault.close()

    reopened = Vault.open(client_path, new_password)
    reopened.close()
    with pytest.raises(crypto.DecryptError):
        Vault.open(client_path, password)


def test_pmve_removes_bytes_sync_entry_points(tmp_path) -> None:
    seq1, _seq2, password = _fixture_pair("pc")
    local_path = tmp_path / "local.pmv"
    shutil.copy2(seq1, local_path)
    vault = Vault.open(local_path, password)
    assert not hasattr(vault, "read_sync_bytes")
    assert not hasattr(vault, "replace_from_remote_bytes")
    vault.close()


def test_lan_v2_truncated_pmve_upload_never_changes_committed_file(tmp_path, monkeypatch) -> None:
    seq1, seq2, password = _fixture_pair("android")
    server_path = tmp_path / "server.pmv"
    shutil.copy2(seq1, server_path)
    original = server_path.read_bytes()
    server_vault = Vault.open(server_path, password)
    monkeypatch.setattr(sync_server, "PORT", 0)
    monkeypatch.setattr(sync_server, "_local_ip", lambda: "127.0.0.1")
    server = sync_server.SyncServer(server_vault, lambda **_: True)
    pairing_url, pin = server.start()
    client = LanSyncClient(pairing_url, pin)
    connection = client._connect("/api/sync/vault")
    try:
        client._check_pinned(connection)
        connection.putrequest("PUT", "/api/sync/vault")
        headers = client._headers(
            {
                "Content-Type": "application/octet-stream",
                "Content-Length": str(seq2.stat().st_size),
                "X-Vault-Content-Sha256": hashlib.sha256(seq2.read_bytes()).hexdigest(),
            }
        )
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        with seq2.open("rb") as source:
            connection.send(source.read(seq2.stat().st_size // 2))
        connection.sock.shutdown(socket.SHUT_WR)
        try:
            response = connection.getresponse()
            assert response.status == 400
            response.read()
        except (http.client.HTTPException, OSError):
            # A TLS peer that has already closed its write side may be
            # unable to receive the server's best-effort 400 response.
            # The security contract is that no truncated candidate is
            # committed, verified below.
            pass
        assert server_path.read_bytes() == original
        assert server_vault.pmve_identity.sequence == 1
    finally:
        connection.close()
        server.stop()
        if server._thread:
            server._thread.join(timeout=2)
        server_vault.close()
