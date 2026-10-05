from __future__ import annotations

import uuid

import pytest

from core.pmv_container import BLOCK_HEADER_SIZE, BlockType
from core.pmv_entry_index import EntryIndexState
from core.pmv_tombstone import FLAG_PURGED, SIZE, Tombstone, decode_tombstone, encode_tombstone
from core.pmv_vault_store import PmvVaultStore


PASSWORD = b"tombstone-password"
RECOVERY = bytes(range(32))


def _entry(entry_id: uuid.UUID) -> dict:
    return {
        "id": str(entry_id), "title": "purge me", "username": "a", "password": "b",
        "url": "", "target_app": "", "notes": "", "tags": [], "created_at": 1.0,
        "updated_at": 2.0, "secret_type": "login", "fields": {}, "deleted_at": None,
        "leak_check_revision": None, "leak_pwned_count": None,
        "leak_common_weak": False, "leak_checked_at": None,
    }


def _metadata(entry_ids=(), purges=None) -> dict:
    return {
        "schema": "pmv-vault-metadata", "version": 1, "vault_id": str(uuid.UUID(int=1)),
        "entry_order": [str(value) for value in entry_ids], "trash_order": [],
        "sync_meta": {"device_id": "11111111-2222-3333-4444-555555555555"},
        "key_revision": 1, "export_epoch": None,
        "purge_tombstones": {} if purges is None else purges,
    }


def test_tombstone_wire_round_trip_and_reserved_rejection() -> None:
    value = Tombstone(uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f"), 7, 1234, bytes(range(32)))
    raw = encode_tombstone(value)
    assert len(raw) == SIZE
    assert raw[:4] == b"PMVT"
    assert decode_tombstone(raw) == value
    damaged = bytearray(raw)
    damaged[-1] = 1
    with pytest.raises(ValueError, match="reserved"):
        decode_tombstone(bytes(damaged))
    with pytest.raises(ValueError, match="flags"):
        Tombstone(value.entry_id, 1, 1, bytes(32), FLAG_PURGED + 1)


def test_purge_publishes_authenticated_tombstone_and_never_resurrects(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata((entry_id,)), [_entry(entry_id)])
    store.save_full(
        expected_sequence=1,
        metadata=_metadata((), {str(entry_id): 9.25}),
        entries=[],
    )
    record = store._reader().find_record(entry_id)
    assert record is not None and record.state is EntryIndexState.TOMBSTONE
    assert record.modified_at_epoch_millis == 9250
    assert store.read_entry(entry_id) is None
    assert store.list() == ()

    with path.open("r+b", buffering=0) as stream:
        stream.seek(record.offset + BLOCK_HEADER_SIZE)
        original = stream.read(1)
        stream.seek(-1, 1)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
    with pytest.raises(ValueError, match="tombstone"):
        store.read_entry(entry_id)
    store.close()


def test_compact_reclaims_obsolete_blocks_without_changing_commit_identity(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata((entry_id,)), [_entry(entry_id)])
    for revision in range(2, 7):
        changed = _entry(entry_id)
        changed["title"] = f"revision-{revision}"
        changed["updated_at"] = float(revision)
        store.save_full(
            expected_sequence=revision - 1,
            metadata=_metadata((entry_id,)),
            entries=[changed],
        )
    identity = store.identity
    before_size = path.stat().st_size
    assert store.compact() == identity
    assert path.stat().st_size < before_size
    assert store.identity == identity
    assert store.read_entry(entry_id).title == "revision-6"
    store.close()
    reopened = PmvVaultStore.open_password(path, PASSWORD)
    assert reopened.identity == identity
    assert reopened.read_entry(entry_id).title == "revision-6"
    reopened.close()


def test_interrupted_compact_leaves_source_authoritative(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    entry_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata((entry_id,)), [_entry(entry_id)])
    changed = _entry(entry_id)
    changed["title"] = "latest"
    changed["updated_at"] = 3.0
    store.save_full(expected_sequence=1, metadata=_metadata((entry_id,)), entries=[changed])
    identity = store.identity
    length = path.stat().st_size

    import core.pmv_compact as compact_module
    monkeypatch.setattr(compact_module.os, "replace", lambda *_: (_ for _ in ()).throw(OSError("injected")))
    with pytest.raises(OSError, match="injected"):
        store.compact()
    assert path.stat().st_size == length
    assert store.identity == identity
    assert store.read_entry(entry_id).title == "latest"
    assert not tuple(tmp_path.glob("*.compact.tmp"))
    store.close()
