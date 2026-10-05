"""PMVE DIVERGED merge-and-adopt: registry union committed on the remote head."""

import shutil
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import pmv_device_registry, pmv_sync_authorization
from core.models import Entry
from core.pmv_vault_store import PmvVaultStore
from core.storage import Vault


PASSWORD = "correct horse battery staple"
RECOVERY = bytes(range(32))


def _public_key(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _enroll(base, out, device_id: uuid.UUID, seed: bytes) -> None:
    shutil.copy2(base, out)
    store = PmvVaultStore.open_password(out, PASSWORD.encode("utf-8"))
    try:
        identity = store.identity
        authorization = store.sign_device_authorization(
            pmv_sync_authorization.DeviceAuthorization(
                vault_id=identity.vault_id,
                device_id=device_id,
                device_public_key=_public_key(seed),
                permissions=(
                    pmv_sync_authorization.PERMISSION_READ
                    | pmv_sync_authorization.PERMISSION_WRITE
                    | pmv_sync_authorization.PERMISSION_AUTHORIZE
                ),
                issued_at_epoch_millis=100,
                expires_at_epoch_millis=0,
                revoked_at_epoch_millis=0,
                epoch=1,
            )
        )
        metadata = pmv_device_registry.with_registry(store.metadata(), [authorization])
        entries = []
        for summary in store.list():
            entry = store.read_entry(summary.entry_id)
            if entry is not None:
                entries.append(entry)
        store.save_full(
            expected_sequence=identity.sequence,
            metadata=metadata,
            entries=entries,
        )
    finally:
        store.close()


def test_divergent_self_enrolled_vaults_converge_by_merge_adopt(tmp_path) -> None:
    base = tmp_path / "base.pmv"
    file_a = tmp_path / "a.pmv"
    file_b = tmp_path / "b.pmv"
    store = PmvVaultStore.create(
        base,
        PASSWORD.encode("utf-8"),
        RECOVERY,
        {
            "schema": "pmv-vault-metadata",
            "version": 1,
            "vault_id": str(uuid.UUID(int=1)),
            "entry_order": [],
            "trash_order": [],
            "sync_meta": {"device_id": str(uuid.UUID(int=2))},
            "key_revision": 1,
            "export_epoch": None,
            "purge_tombstones": {},
        },
        (),
    )
    store.close()

    device_a = uuid.UUID(int=3)
    device_b = uuid.UUID(int=4)
    seed_a = bytes(range(32))
    seed_b = bytes((index * 5 + 3) & 0xFF for index in range(32))
    _enroll(base, file_a, device_a, seed_a)
    _enroll(base, file_b, device_b, seed_b)

    vault_b = Vault.open(file_b, PASSWORD)
    try:
        vault_b.merge_and_adopt_authenticated_file(file_a)
        records = pmv_device_registry.decode(vault_b._pmve_store.metadata())
        assert {record.device_id for record in records} == {device_a, device_b}
        # 本地库现在是合并文件（身份为合并 Commit）
        assert vault_b.vault_identity is not None
        # 重新打开仍可读且注册表保留
        reopened = Vault.open(file_b, PASSWORD)
        try:
            again = pmv_device_registry.decode(reopened._pmve_store.metadata())
            assert {record.device_id for record in again} == {device_a, device_b}
        finally:
            reopened.close()
    finally:
        vault_b.close()


def test_divergent_merge_removes_obsolete_passkey_keyset_metadata(tmp_path) -> None:
    base = tmp_path / "keyset-base.pmv"
    file_a = tmp_path / "keyset-a.pmv"
    file_b = tmp_path / "keyset-b.pmv"
    store = PmvVaultStore.create(
        base,
        PASSWORD.encode("utf-8"),
        RECOVERY,
        {
            "schema": "pmv-vault-metadata",
            "version": 1,
            "vault_id": str(uuid.UUID(int=11)),
            "entry_order": [],
            "trash_order": [],
            "sync_meta": {"device_id": str(uuid.UUID(int=12))},
            "key_revision": 1,
            "export_epoch": None,
            "purge_tombstones": {},
            "passkey_keyset": {"obsolete": True},
        },
        (),
    )
    store.close()
    _enroll(base, file_a, uuid.UUID(int=13), bytes(range(32)))
    _enroll(base, file_b, uuid.UUID(int=14), bytes(reversed(range(32))))

    local_store = PmvVaultStore.open_password(file_b, PASSWORD.encode("utf-8"))
    try:
        identity = local_store.identity
        metadata = local_store.metadata()
        metadata["passkey_keyset"] = {"obsolete": "local"}
        local_store.save_full(
            expected_sequence=identity.sequence,
            metadata=metadata,
            entries=(),
        )
    finally:
        local_store.close()

    vault_b = Vault.open(file_b, PASSWORD)
    try:
        vault_b.merge_and_adopt_authenticated_file(file_a)
        assert "passkey_keyset" not in vault_b._pmve_store.metadata()
    finally:
        vault_b.close()


def test_divergent_merge_keeps_equal_time_conflict_and_propagates_purge(tmp_path) -> None:
    base = tmp_path / "base.pmv"
    file_a = tmp_path / "a.pmv"
    file_b = tmp_path / "b.pmv"
    conflict_id = str(uuid.uuid4())
    purged_id = str(uuid.uuid4())
    base_entries = (
        Entry(id=conflict_id, title="Original", updated_at=10.0),
        Entry(id=purged_id, title="Delete me", updated_at=10.0),
    )
    store = PmvVaultStore.create(
        base, PASSWORD.encode("utf-8"), RECOVERY,
        {
            "schema": "pmv-vault-metadata", "version": 1,
            "vault_id": str(uuid.uuid4()), "entry_order": [], "trash_order": [],
            "sync_meta": {"device_id": str(uuid.uuid4())}, "key_revision": 1,
            "export_epoch": None, "purge_tombstones": {},
        },
        base_entries,
    )
    store.close()
    _enroll(base, file_a, uuid.uuid4(), bytes(range(32)))
    _enroll(base, file_b, uuid.uuid4(), bytes(reversed(range(32))))

    for path, title, purge in ((file_a, "Remote", True), (file_b, "Local", False)):
        store = PmvVaultStore.open_password(path, PASSWORD.encode("utf-8"))
        try:
            metadata = store.metadata()
            if purge:
                metadata["purge_tombstones"] = {purged_id: 20.0}
            store.save_full(
                expected_sequence=store.identity.sequence,
                metadata=metadata,
                entries=(Entry(id=conflict_id, title=title, updated_at=11.0),)
                if purge else (
                    Entry(id=conflict_id, title=title, updated_at=11.0),
                    base_entries[1],
                ),
            )
        finally:
            store.close()

    vault = Vault.open(file_b, PASSWORD)
    try:
        vault.merge_and_adopt_authenticated_file(file_a)
        merged = vault._pmve_store.metadata()
        assert merged["purge_tombstones"][purged_id] == 20.0
        entries = [vault._pmve_store.read_entry(summary.entry_id) for summary in vault._pmve_store.list()]
        assert {entry.title for entry in entries} == {"Local", "Remote"}
        assert all(entry.id != purged_id for entry in entries)
    finally:
        vault.close()
