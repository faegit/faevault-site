from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.pmv_append import DATA_START, PmvAppendOnlyFile
from core.pmv_container import (
    BLOCK_HEADER_SIZE,
    GCM_TAG_SIZE,
    BlockType,
    EncodedBlock,
    encode_block_header,
    seal,
)
from core.pmv_entry_index import (
    EntryIndexPage,
    EntryIndexRecord,
    EntryIndexRoot,
    EntryIndexRootRecord,
    EntryIndexState,
    PAGE_SIZE,
    encode_entry_index_page,
    encode_entry_index_root,
)
from core.pmv_entry_reader import Cursor, PmvEntryReader
from core.pmv_integrity import encrypted_block_digest, entry_page_digest
from core.pmv_key_schedule import (
    IndexPageType,
    derive_entry_generation_key,
    derive_index_page_key,
)


VAULT_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
AUTH_KEY = bytes(range(32))
INTEGRITY_KEY = bytes(range(32, 64))
INDEX_ROOT_KEY = bytes(range(64, 96))
ENTRY_ROOT_KEY = bytes(range(96, 128))
SIGNING_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
TRUSTED_PUBLIC_KEY = SIGNING_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)


def _length(block: EncodedBlock) -> int:
    return BLOCK_HEADER_SIZE + len(block.ciphertext)


@dataclass(frozen=True)
class Prepared:
    data: tuple[EncodedBlock, ...]
    indexes: tuple[EncodedBlock, ...]
    entry_id: uuid.UUID
    plaintext: bytes
    base_sequence: int


def _prepare(
    container: PmvAppendOnlyFile,
    *,
    entry_id: uuid.UUID,
    plaintext: bytes,
    title: str,
    index_flags: int = 0,
    index_revision_delta: int = 0,
    root_key_type: IndexPageType = IndexPageType.ENTRY_INDEX,
    leaf_key_type: IndexPageType = IndexPageType.ENTRY_INDEX,
    mismatch_root_key_object_id: bool = False,
) -> Prepared:
    current = container.candidate_states()[0].superblock
    revision = current.sequence + 1
    entry_key = derive_entry_generation_key(ENTRY_ROOT_KEY, entry_id, revision)
    entry = seal(
        VAULT_ID, entry_key, BlockType.ENTRY, entry_id, revision, plaintext
    )
    entry_offset = current.committed_file_end
    root_offset = entry_offset + _length(entry)
    leaf_offset = root_offset + BLOCK_HEADER_SIZE + PAGE_SIZE + GCM_TAG_SIZE
    record = EntryIndexRecord(
        entry_id=entry_id,
        entry_type="login",
        revision=revision,
        offset=entry_offset,
        length=_length(entry),
        state=EntryIndexState.ACTIVE,
        display_title=title,
        content_digest=encrypted_block_digest(entry),
    )
    leaf_page = EntryIndexPage((record,))
    leaf_id = uuid.uuid4()
    index_revision = revision + index_revision_delta
    leaf = seal(
        VAULT_ID,
        derive_index_page_key(
            INDEX_ROOT_KEY, leaf_id, index_revision, leaf_key_type
        ),
        BlockType.INDEX_PAGE,
        leaf_id,
        index_revision,
        encode_entry_index_page(leaf_page),
        flags=index_flags,
    )
    root = EntryIndexRoot(
        (
            EntryIndexRootRecord(
                min_entry_id=entry_id,
                max_entry_id=entry_id,
                page_offset=leaf_offset,
                page_digest=entry_page_digest(leaf_page),
            ),
        )
    )
    root_id = uuid.uuid4()
    root_key_object_id = uuid.uuid4() if mismatch_root_key_object_id else root_id
    root_block = seal(
        VAULT_ID,
        derive_index_page_key(
            INDEX_ROOT_KEY, root_key_object_id, index_revision, root_key_type
        ),
        BlockType.INDEX_PAGE,
        root_id,
        index_revision,
        encode_entry_index_root(root),
        flags=index_flags,
    )
    return Prepared((entry,), (root_block, leaf), entry_id, plaintext, current.sequence)


def _publish(container: PmvAppendOnlyFile, prepared: Prepared):
    return container.commit(
        data_blocks=prepared.data,
        index_blocks=prepared.indexes,
        integrity_key=INTEGRITY_KEY,
        index_root_key=INDEX_ROOT_KEY,
        signing_private_key=SIGNING_KEY,
        trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
        expected_base_sequence=prepared.base_sequence,
    )


def _reader(container: PmvAppendOnlyFile, **overrides) -> PmvEntryReader:
    values = dict(
        vault_id=VAULT_ID,
        integrity_key=INTEGRITY_KEY,
        index_root_key=INDEX_ROOT_KEY,
        trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
        entry_root_key=ENTRY_ROOT_KEY,
    )
    values.update(overrides)
    return PmvEntryReader(container, **values)


def test_create_refuses_to_overwrite_any_existing_file(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"do not replace")
    with pytest.raises(FileExistsError):
        PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    assert path.read_bytes() == b"do not replace"


def test_signed_commit_round_trip_and_targeted_entry_read(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    entry_id = uuid.UUID("11111111-2222-3333-4444-555555555555")
    prepared = _prepare(
        container, entry_id=entry_id, plaintext=b'{"secret":"one"}', title="One"
    )

    snapshot = _publish(container, prepared)

    assert snapshot.state.slot == 1
    assert snapshot.state.superblock.sequence == 1
    assert snapshot.commit is not None
    assert snapshot.commit.index_root_offset == snapshot.state.superblock.latest_index_offset
    assert prepared.data[0].header.object_revision == 1
    assert prepared.indexes[0].header.object_revision == 1
    assert snapshot.vault_root is not None
    assert snapshot.vault_root.entry.offset < snapshot.commit.index_root_offset
    assert snapshot.vault_root.login is None
    assert snapshot.vault_root.object_index is None
    assert snapshot.vault_root.chunk_index is None
    assert snapshot.vault_root.metadata is None
    assert snapshot.root.records[0].page_offset > snapshot.vault_root.entry.offset
    assert DATA_START == 16 * 1024
    reader = _reader(PmvAppendOnlyFile(path, AUTH_KEY))
    assert reader.find(entry_id) == prepared.plaintext
    assert reader.find(uuid.uuid4()) is None
    page = reader.list_page()
    assert [item.display_title for item in page.items] == ["One"]
    assert page.next_cursor is None


def test_find_reads_only_the_selected_leaf_and_entry_blocks(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container, entry_id=uuid.uuid4(), plaintext=b"target", title="Target"
    )
    published = _publish(container, prepared)
    reader = _reader(container)
    observed: list[tuple[int, BlockType | None]] = []
    original = container.read_block

    def tracked(snapshot, offset, expected_type=None):
        observed.append((offset, expected_type))
        return original(snapshot, offset, expected_type)

    monkeypatch.setattr(container, "read_block", tracked)
    assert reader.find(prepared.entry_id) == b"target"
    assert observed == [
        (published.root.records[0].page_offset, BlockType.INDEX_PAGE),
        (published.root.records[0].page_offset - _length(prepared.data[0])
         - (BLOCK_HEADER_SIZE + PAGE_SIZE + GCM_TAG_SIZE), BlockType.ENTRY),
    ]


def test_wrong_commit_key_or_untrusted_signer_cannot_authenticate_published_commit(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    _publish(
        container,
        _prepare(container, entry_id=uuid.uuid4(), plaintext=b"entry", title="Entry"),
    )

    # Slot 0 is the legitimate pre-commit snapshot.  Bad credentials may fall
    # back to it, but must never expose the signed sequence-1 state.
    assert _reader(container, integrity_key=bytes(32)).snapshot().state.superblock.sequence == 0
    assert (
        _reader(container, trusted_signing_public_key=bytes(32))
        .snapshot().state.superblock.sequence
        == 0
    )


def test_writer_never_downgrades_or_changes_file_when_newest_authentication_fails(
    tmp_path,
) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    _publish(
        container,
        _prepare(container, entry_id=uuid.uuid4(), plaintext=b"first", title="First"),
    )
    pending = _prepare(
        container, entry_id=uuid.uuid4(), plaintext=b"pending", title="Pending"
    )
    before = path.read_bytes()

    with pytest.raises(ValueError, match="newest PMV snapshot"):
        container.commit(
            data_blocks=pending.data,
            index_blocks=pending.indexes,
            integrity_key=bytes(32),
            index_root_key=INDEX_ROOT_KEY,
            signing_private_key=SIGNING_KEY,
            trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
            expected_base_sequence=pending.base_sequence,
        )

    assert path.read_bytes() == before


def test_writer_rejects_unsupported_index_header_metadata(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container,
        entry_id=uuid.uuid4(),
        plaintext=b"entry",
        title="Entry",
        index_flags=1,
    )

    with pytest.raises(ValueError, match="header metadata"):
        _publish(container, prepared)
    assert container.candidate_states()[0].superblock.sequence == 0


def test_corrupt_newest_commit_falls_back_to_older_authenticated_slot(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    first_id = uuid.UUID("10000000-0000-0000-0000-000000000001")
    first = _prepare(container, entry_id=first_id, plaintext=b"first", title="First")
    _publish(container, first)
    second = _prepare(
        container,
        entry_id=uuid.UUID("20000000-0000-0000-0000-000000000002"),
        plaintext=b"second",
        title="Second",
    )
    newest = _publish(container, second)
    assert newest.state.superblock.sequence == 2

    with path.open("r+b") as stream:
        stream.seek(newest.state.superblock.latest_commit_offset + BLOCK_HEADER_SIZE)
        original = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
        os.fsync(stream.fileno())

    reader = _reader(PmvAppendOnlyFile(path, AUTH_KEY))
    assert reader.snapshot().state.superblock.sequence == 1
    assert reader.find(first_id) == b"first"
    assert reader.find(second.entry_id) is None


@pytest.mark.parametrize("corrupted_layer", ["vault_root", "entry_root", "entry_page"])
def test_corrupt_composite_root_layer_falls_back_to_older_authenticated_slot(
    tmp_path, corrupted_layer
) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    first = _prepare(
        container,
        entry_id=uuid.UUID("10000000-0000-0000-0000-000000000001"),
        plaintext=b"first",
        title="First",
    )
    _publish(container, first)
    second = _prepare(
        container,
        entry_id=uuid.UUID("20000000-0000-0000-0000-000000000002"),
        plaintext=b"second",
        title="Second",
    )
    newest = _publish(container, second)
    assert newest.vault_root is not None
    offsets = {
        "vault_root": newest.state.superblock.latest_index_offset,
        "entry_root": newest.vault_root.entry.offset,
        "entry_page": newest.root.records[0].page_offset,
    }

    with path.open("r+b") as stream:
        stream.seek(offsets[corrupted_layer] + BLOCK_HEADER_SIZE)
        original = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
        os.fsync(stream.fileno())

    # PMVR and PMER corruption are rejected while authenticating the candidate;
    # a PMEI leaf is rejected lazily by the targeted reader.  All three paths
    # must expose the older complete snapshot, never a partial newest one.
    reader = _reader(PmvAppendOnlyFile(path, AUTH_KEY))
    page = reader.list_page()
    assert [item.display_title for item in page.items] == ["First"]


@pytest.mark.parametrize("failed_fsync", [1, 2])
def test_interruption_before_superblock_publication_keeps_old_snapshot(
    tmp_path, monkeypatch, failed_fsync
) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container, entry_id=uuid.uuid4(), plaintext=b"uncommitted", title="Pending"
    )
    real_fsync = os.fsync
    calls = 0

    def interrupted(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == failed_fsync:
            raise OSError("simulated power loss")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", interrupted)
    with pytest.raises(OSError, match="power loss"):
        _publish(container, prepared)
    monkeypatch.setattr(os, "fsync", real_fsync)

    reader = _reader(PmvAppendOnlyFile(path, AUTH_KEY))
    assert reader.snapshot().state.superblock.sequence == 0
    assert reader.find(prepared.entry_id) is None


def test_two_instances_serialize_and_reject_the_stale_prepared_transaction(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    first = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    second = PmvAppendOnlyFile(path, AUTH_KEY)
    left = _prepare(first, entry_id=uuid.uuid4(), plaintext=b"left", title="Left")
    right = _prepare(second, entry_id=uuid.uuid4(), plaintext=b"rght", title="Right")
    gate = threading.Barrier(2)

    def attempt(container: PmvAppendOnlyFile, prepared: Prepared):
        gate.wait(timeout=5)
        return _publish(container, prepared)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(attempt, first, left), pool.submit(attempt, second, right)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=10))
            except ValueError:
                outcomes.append(None)

    assert sum(result is not None for result in outcomes) == 1
    reopened = PmvAppendOnlyFile(path, AUTH_KEY)
    assert _reader(reopened).snapshot().state.superblock.sequence == 1


def test_cursor_is_bound_to_the_commit_sequence(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(container, entry_id=uuid.uuid4(), plaintext=b"one", title="One")
    _publish(container, prepared)

    with pytest.raises(ValueError, match="another committed snapshot"):
        _reader(container).list_page(Cursor(sequence=0, page_index=0))


def test_fallback_snapshot_cursor_continues_across_entry_index_pages(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    # A login record occupies 113 bytes, so 145 records cannot fit in one 16 KiB page.
    entry_ids = tuple(uuid.UUID(int=value) for value in range(1, 146))
    entries = tuple(
        seal(
            VAULT_ID,
            derive_entry_generation_key(ENTRY_ROOT_KEY, entry_id, 1),
            BlockType.ENTRY,
            entry_id,
            1,
            f"entry-{entry_id}".encode(),
        )
        for entry_id in entry_ids
    )
    entry_offset = DATA_START
    records = []
    for entry_id, entry in zip(entry_ids, entries):
        records.append(EntryIndexRecord(
            entry_id=entry_id,
            entry_type="login",
            revision=1,
            offset=entry_offset,
            length=_length(entry),
            state=EntryIndexState.ACTIVE,
            content_digest=encrypted_block_digest(entry),
        ))
        entry_offset += _length(entry)
    pages = (EntryIndexPage(tuple(records[:144])), EntryIndexPage(tuple(records[144:])))

    def index_blocks(root_offset: int, revision: int):
        block_length = BLOCK_HEADER_SIZE + PAGE_SIZE + GCM_TAG_SIZE
        leaf_offsets = (root_offset + block_length, root_offset + 2 * block_length)
        leaves = []
        root_records = []
        for page, leaf_offset in zip(pages, leaf_offsets):
            leaf_id = uuid.uuid4()
            leaves.append(seal(
                VAULT_ID,
                derive_index_page_key(
                    INDEX_ROOT_KEY, leaf_id, revision, IndexPageType.ENTRY_INDEX
                ),
                BlockType.INDEX_PAGE,
                leaf_id,
                revision,
                encode_entry_index_page(page),
            ))
            root_records.append(EntryIndexRootRecord(
                min_entry_id=page.records[0].entry_id,
                max_entry_id=page.records[-1].entry_id,
                page_offset=leaf_offset,
                page_digest=entry_page_digest(page),
            ))
        root_id = uuid.uuid4()
        root = seal(
            VAULT_ID,
            derive_index_page_key(
                INDEX_ROOT_KEY, root_id, revision, IndexPageType.ENTRY_INDEX
            ),
            BlockType.INDEX_PAGE,
            root_id,
            revision,
            encode_entry_index_root(EntryIndexRoot(tuple(root_records))),
        )
        return (root, *leaves), leaf_offsets

    old_indexes, _ = index_blocks(entry_offset, 1)
    container.commit(
        data_blocks=entries,
        index_blocks=old_indexes,
        integrity_key=INTEGRITY_KEY,
        index_root_key=INDEX_ROOT_KEY,
        signing_private_key=SIGNING_KEY,
        trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
        expected_base_sequence=0,
    )
    new_root_offset = container.candidate_states()[0].superblock.committed_file_end
    new_indexes, new_leaf_offsets = index_blocks(new_root_offset, 2)
    container.commit(
        data_blocks=(),
        index_blocks=new_indexes,
        integrity_key=INTEGRITY_KEY,
        index_root_key=INDEX_ROOT_KEY,
        signing_private_key=SIGNING_KEY,
        trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
        expected_base_sequence=1,
    )
    with path.open("r+b") as stream:
        stream.seek(new_leaf_offsets[0] + BLOCK_HEADER_SIZE)
        original = stream.read(1)
        stream.seek(-1, os.SEEK_CUR)
        stream.write(bytes((original[0] ^ 1,)))
        stream.flush()
        os.fsync(stream.fileno())

    reader = _reader(PmvAppendOnlyFile(path, AUTH_KEY))
    first_page = reader.list_page()
    assert len(first_page.items) == 144
    assert first_page.next_cursor == Cursor(sequence=1, page_index=1)

    second_page = reader.list_page(first_page.next_cursor)
    assert [item.entry_id for item in second_page.items] == [entry_ids[-1]]
    assert second_page.next_cursor is None


def test_entry_content_digest_is_mandatory(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    current = container.candidate_states()[0].superblock
    entry_id = uuid.uuid4()
    entry_key = derive_entry_generation_key(ENTRY_ROOT_KEY, entry_id, 1)
    entry = seal(VAULT_ID, entry_key, BlockType.ENTRY, entry_id, 1, b"entry")
    root_offset = current.committed_file_end + _length(entry)
    leaf_offset = root_offset + BLOCK_HEADER_SIZE + PAGE_SIZE + GCM_TAG_SIZE
    bad_record = EntryIndexRecord(
        entry_id=entry_id,
        entry_type="login",
        revision=1,
        offset=current.committed_file_end,
        length=_length(entry),
        state=EntryIndexState.ACTIVE,
        content_digest=bytes(32),
    )
    leaf_page = EntryIndexPage((bad_record,))
    leaf_id = uuid.uuid4()
    leaf = seal(
        VAULT_ID,
        derive_index_page_key(INDEX_ROOT_KEY, leaf_id, 1, IndexPageType.ENTRY_INDEX),
        BlockType.INDEX_PAGE, leaf_id, 1,
        encode_entry_index_page(leaf_page),
    )
    root = EntryIndexRoot((EntryIndexRootRecord(
        entry_id, entry_id, leaf_offset, entry_page_digest(leaf_page)
    ),))
    root_id = uuid.uuid4()
    root_block = seal(
        VAULT_ID,
        derive_index_page_key(INDEX_ROOT_KEY, root_id, 1, IndexPageType.ENTRY_INDEX),
        BlockType.INDEX_PAGE, root_id, 1,
        encode_entry_index_root(root),
    )

    with pytest.raises(ValueError, match="digest"):
        container.commit(
            data_blocks=(entry,),
            index_blocks=(root_block, leaf),
            integrity_key=INTEGRITY_KEY,
            index_root_key=INDEX_ROOT_KEY,
            signing_private_key=SIGNING_KEY,
            trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
            expected_base_sequence=0,
        )


def test_production_writer_rejects_deprecated_static_block_keys(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container, entry_id=uuid.uuid4(), plaintext=b"entry", title="Entry"
    )

    with pytest.raises(ValueError, match="integrity_key"):
        container.commit(
            data_blocks=prepared.data,
            index_blocks=prepared.indexes,
            integrity_key=None,
            index_root_key=None,
            commit_key=INTEGRITY_KEY,
            index_key=INDEX_ROOT_KEY,
            signing_private_key=SIGNING_KEY,
            trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
            expected_base_sequence=0,
        )


def test_production_reader_rejects_deprecated_static_block_keys(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)

    with pytest.raises(ValueError, match="integrity_key"):
        PmvEntryReader(
            container,
            vault_id=VAULT_ID,
            integrity_key=None,
            index_root_key=None,
            commit_key=INTEGRITY_KEY,
            index_key=INDEX_ROOT_KEY,
            trusted_signing_public_key=TRUSTED_PUBLIC_KEY,
            entry_root_key=ENTRY_ROOT_KEY,
        )


def test_writer_rejects_index_header_revision_outside_new_commit(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container,
        entry_id=uuid.uuid4(),
        plaintext=b"entry",
        title="Entry",
        index_revision_delta=1,
    )

    with pytest.raises(ValueError, match="revision"):
        _publish(container, prepared)


def test_writer_rejects_index_key_derived_for_another_object_id(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container,
        entry_id=uuid.uuid4(),
        plaintext=b"entry",
        title="Entry",
        mismatch_root_key_object_id=True,
    )

    with pytest.raises(ValueError, match="derived page role"):
        _publish(container, prepared)


def test_writer_rejects_index_key_derived_for_wrong_page_type(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    prepared = _prepare(
        container,
        entry_id=uuid.uuid4(),
        plaintext=b"entry",
        title="Entry",
        root_key_type=IndexPageType.VAULT_ROOT,
    )

    with pytest.raises(ValueError, match="derived page role"):
        _publish(container, prepared)


@pytest.mark.parametrize("header_field", ["object_id", "object_revision"])
def test_reader_rejects_commit_header_with_wrong_derivation_context(
    tmp_path, header_field
) -> None:
    path = tmp_path / "vault.pmv"
    container = PmvAppendOnlyFile.create(path, VAULT_ID, AUTH_KEY)
    published = _publish(
        container,
        _prepare(container, entry_id=uuid.uuid4(), plaintext=b"entry", title="Entry"),
    )
    commit_offset = published.state.superblock.latest_commit_offset
    commit_block = container.read_block(
        published.state, commit_offset, BlockType.COMMIT
    )
    replacement = (
        uuid.uuid4()
        if header_field == "object_id"
        else commit_block.header.object_revision + 1
    )
    damaged_header = replace(commit_block.header, **{header_field: replacement})
    with path.open("r+b") as stream:
        stream.seek(commit_offset)
        stream.write(encode_block_header(damaged_header))
        stream.flush()
        os.fsync(stream.fileno())

    # The altered header derives another key and also changes AEAD AAD, so the
    # published commit is rejected and only the authenticated initial slot remains.
    recovered = _reader(PmvAppendOnlyFile(path, AUTH_KEY)).snapshot()
    assert recovered.state.superblock.sequence == 0
