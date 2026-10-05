from __future__ import annotations

import io
import uuid

import pytest

from core.pmv_attachment import CHUNK_SIZE, AttachmentKind
from core.pmv_vault_store import PmvVaultStore


PASSWORD = b"object-store-password"
RECOVERY = bytes(range(32))


def _metadata() -> dict[str, object]:
    return {
        "schema": "pmv-vault-metadata",
        "version": 1,
        "vault_id": str(uuid.UUID(int=1)),
        "entry_order": [],
        "trash_order": [],
        "sync_meta": {"device_id": "11111111-2222-3333-4444-555555555555"},
        "key_revision": 1,
        "export_epoch": None,
        "purge_tombstones": {},
    }


class _BoundedStream(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.max_request = 0

    def read(self, size: int = -1) -> bytes:
        assert 0 <= size <= CHUNK_SIZE
        self.max_request = max(self.max_request, size)
        return super().read(size)


class _FailAfterFirstChunk(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.calls = 0

    def read(self, size: int = -1) -> bytes:
        self.calls += 1
        if self.calls > 1:
            raise OSError("injected source failure")
        return super().read(size)


def test_import_open_and_range_are_streaming_and_publish_both_indexes(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(), [])
    object_id = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")
    plain = bytes(value & 0xFF for value in range(CHUNK_SIZE + 37))
    source = _BoundedStream(plain)

    identity = store.import_object(
        expected_sequence=1,
        stream=source,
        expected_size=len(plain),
        object_id=object_id,
        generation=1,
        kind=AttachmentKind.ATTACHMENT,
    )

    assert identity.sequence == 2
    assert source.max_request <= CHUNK_SIZE
    snapshot = next(store._authenticated_snapshots())
    assert snapshot.vault_root.object_index is not None
    assert snapshot.vault_root.chunk_index is not None
    output = io.BytesIO()
    store.open_object(object_id, 1, output)
    assert output.getvalue() == plain
    ranged = io.BytesIO()
    store.open_object_range(object_id, 1, CHUNK_SIZE - 3, 11, ranged)
    assert ranged.getvalue() == plain[CHUNK_SIZE - 3 : CHUNK_SIZE + 8]
    store.close()


def test_import_cow_merges_old_records_and_save_full_unlinks_unreferenced_objects(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    first_id = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")
    second_id = uuid.UUID("20213243-5465-7687-98a9-bacbdcedfe0f")
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(), [])
    store.import_object(
        expected_sequence=1,
        stream=io.BytesIO(b"first object"),
        expected_size=12,
        object_id=first_id,
        generation=3,
        kind=AttachmentKind.IMAGE,
    )
    store.import_object(
        expected_sequence=2,
        stream=io.BytesIO(b"second object"),
        expected_size=13,
        object_id=second_id,
        generation=4,
        kind=AttachmentKind.ATTACHMENT,
    )

    first = io.BytesIO()
    second = io.BytesIO()
    store.open_object(first_id, 3, first)
    store.open_object(second_id, 4, second)
    assert first.getvalue() == b"first object"
    assert second.getvalue() == b"second object"

    store.save_full(expected_sequence=3, metadata=_metadata(), entries=[])
    after = next(store._authenticated_snapshots()).vault_root
    assert after.object_index is None
    assert after.chunk_index is None
    with pytest.raises(ValueError, match="does not exist"):
        store.open_object(first_id, 3, io.BytesIO())
    store.close()


def test_failed_import_appends_no_published_root(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(), [])
    before = store.identity
    before_root = next(store._authenticated_snapshots()).vault_root
    source = _FailAfterFirstChunk(bytes(CHUNK_SIZE + 1))

    with pytest.raises(OSError, match="injected source failure"):
        store.import_object(
            expected_sequence=before.sequence,
            stream=source,
            expected_size=CHUNK_SIZE + 1,
            object_id=uuid.uuid4(),
            generation=1,
            kind=AttachmentKind.ATTACHMENT,
        )

    assert store.identity.sequence == before.sequence
    after_root = next(store._authenticated_snapshots()).vault_root
    assert after_root.object_index == before_root.object_index
    assert after_root.chunk_index == before_root.chunk_index
    store.close()


def test_object_read_uses_one_authenticated_snapshot_for_all_index_and_data_reads(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "vault.pmv"
    object_id = uuid.uuid4()
    store = PmvVaultStore.create(path, PASSWORD, RECOVERY, _metadata(), [])
    store.import_object(
        expected_sequence=1,
        stream=io.BytesIO(b"snapshot-bound"),
        expected_size=14,
        object_id=object_id,
        generation=7,
        kind=AttachmentKind.ATTACHMENT,
    )
    states: list[object] = []
    original = store._container.read_block

    def tracked(snapshot, offset, expected_type=None):
        states.append(snapshot)
        return original(snapshot, offset, expected_type)

    monkeypatch.setattr(store._container, "read_block", tracked)
    output = io.BytesIO()
    store.open_object(object_id, 7, output)

    assert output.getvalue() == b"snapshot-bound"
    assert states and all(state is states[0] for state in states)
    store.close()
