"""Streaming reachability compaction for authenticated PMVE vaults."""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

from .pmv_append import PmvAppendOnlyFile, _exclusive_os_lock, _fsync_parent_directory, _process_lock, _write_all
from .pmv_commit import Commit, encode_commit
from .pmv_container import (
    BLOCK_HEADER_SIZE, DATA_START, SUPERBLOCK_SIZE, BlockType, EncodedBlock, Superblock,
    encode_block_header, encode_superblock, seal,
)
from .pmv_entry_index import (
    EntryIndexPage, EntryIndexRoot, EntryIndexRootRecord,
    encode_entry_index_page, encode_entry_index_root,
)
from .pmv_integrity import entry_page_digest, entry_root_digest
from .pmv_key_schedule import IndexPageType, derive_commit_block_key, derive_index_page_key
from .pmv_login_fast_index import (
    PageRange as LoginPageRange, Root as LoginRoot, encode_root as encode_login_root,
    logical_page_digest as login_page_digest, logical_root_digest as login_root_digest,
)
from .pmv_object_index import ChunkRecord, ObjectRecord
from .pmv_vault_root import PmvVaultRootCodec, RootReference, RootType, VaultRoot


# ── 自动压缩策略（与安卓端 AutoCompactPolicy 保持一致） ──────────────

#: 距上次压缩至少累计的提交数，避免频繁重写。
AUTO_COMPACT_MIN_COMMITS = 200
#: 距上次压缩至少增长的文件字节数，小库/无实际垃圾时不重写。
AUTO_COMPACT_MIN_GROWTH = 1024 * 1024
#: 库文件达到该大小时才考虑自动压缩。
AUTO_COMPACT_MIN_FILE_SIZE = 512 * 1024
#: 连续自动压缩之间的最短间隔（秒）。
AUTO_COMPACT_MIN_INTERVAL_SECONDS = 24 * 60 * 60
#: 导入后的冷却期：导入完成先正常使用，冷却期内不自动压缩，避免刚导入即重写。
IMPORT_COOLDOWN_SECONDS = 24 * 60 * 60

# ── 媒体提交后的机会式压缩（与安卓端 compactAfterLargeMediaCommit 保持一致） ──

#: 距上次压缩的最短间隔：短间隔内连续压缩会把整库反复重写。
MEDIA_COMPACT_MIN_INTERVAL_SECONDS = 10 * 60
#: 文件相对上次压缩的最小增长量，低于此值不值得重写。
MEDIA_COMPACT_MIN_GROWTH = 32 * 1024 * 1024


def should_auto_compact(
    current_revision: int,
    last_compact_revision: int,
    file_size: int,
    last_compact_size: int,
    last_compact_at: float = 0.0,
    last_import_at: float = 0.0,
    now: float | None = None,
) -> bool:
    """判断 PMVE 库是否需要后台自动压缩一次。"""
    if file_size < AUTO_COMPACT_MIN_FILE_SIZE:
        return False
    now = time.time() if now is None else now
    if now - last_compact_at < AUTO_COMPACT_MIN_INTERVAL_SECONDS:
        return False
    if last_import_at > 0 and now - last_import_at < IMPORT_COOLDOWN_SECONDS:
        return False
    if current_revision - last_compact_revision < AUTO_COMPACT_MIN_COMMITS:
        return False
    return file_size - last_compact_size >= AUTO_COMPACT_MIN_GROWTH


@dataclass(frozen=True, slots=True)
class _Ref:
    offset: int
    length: int


class _Relocator:
    def __init__(self, stream) -> None:
        self.stream = stream
        self.tail = DATA_START

    def append_block(self, block: EncodedBlock) -> _Ref:
        self.stream.seek(self.tail)
        _write_all(self.stream, encode_block_header(block.header))
        _write_all(self.stream, block.ciphertext)
        result = _Ref(self.tail, BLOCK_HEADER_SIZE + len(block.ciphertext))
        self.tail += result.length
        return result


class _Discard:
    def write(self, value: bytes) -> int:
        return len(value)


def compact_store(store):
    """Copy only blocks reachable from the latest Commit and atomically replace the file.

    Physical references are relocated, while the signed logical Commit identity is
    preserved. Any logical digest or child-root length drift aborts before replacement.
    """

    store._require_open()
    source = Path(store.path)
    temporary = source.with_name(f".{source.name}.{uuid.uuid4().hex}.compact.tmp")
    old_identity = store.identity
    authentication_key = bytes(store._container._authentication_key)

    with _process_lock(source), _exclusive_os_lock(source):
        snapshot = store._latest_authenticated_snapshot()
        commit = snapshot.commit
        old_root = snapshot.vault_root
        if commit is None or old_root is None:
            raise ValueError("cannot compact an uncommitted PMV")
        reader = store._reader()
        try:
            with temporary.open("x+b", buffering=0) as output:
                output.truncate(DATA_START)
                with source.open("rb") as original:
                    for offset in (8192, 12288):
                        original.seek(offset)
                        raw = original.read(4096)
                        if len(raw) != 4096:
                            raise ValueError("PMV header slot is truncated")
                        output.seek(offset)
                        _write_all(output, raw)
                writer = _Relocator(output)

                # 压缩只回收历史数据块；提交链（谱系）必须完整保留。祖先 COMMIT 块
                # 按原样复制，与安卓端 PmvVaultStore.compactInternal 一致，避免
                # 同步端因父提交块缺失而报“缺少父提交”。
                scan_offset = DATA_START
                while scan_offset < snapshot.state.superblock.committed_file_end:
                    block = store._container.read_block(snapshot.state, scan_offset)
                    if (
                        block.header.block_type is BlockType.COMMIT
                        and block.header.object_id != commit.commit_id
                    ):
                        writer.append_block(block)
                    scan_offset += BLOCK_HEADER_SIZE + block.header.cipher_size

                entry_ranges: list[EntryIndexRootRecord] = []
                for selected in snapshot.root.records:
                    page = reader._read_leaf(snapshot, selected)
                    moved = []
                    for record in page.records:
                        if record.state.name == "ACTIVE":
                            reader._read_entry(snapshot, record)
                            expected_type = BlockType.ENTRY
                        else:
                            reader._read_tombstone(snapshot, record)
                            expected_type = BlockType.TOMBSTONE
                        block = store._container.read_block(snapshot.state, record.offset, expected_type)
                        ref = writer.append_block(block)
                        moved.append(replace(record, offset=ref.offset, length=ref.length))
                    moved_page = EntryIndexPage(tuple(moved))
                    digest = entry_page_digest(moved_page)
                    if digest != selected.page_digest:
                        raise ValueError("EntryIndex logical digest changed during compaction")
                    page_ref = _append_index(
                        store, writer, commit.revision, IndexPageType.ENTRY_INDEX,
                        BlockType.INDEX_PAGE, encode_entry_index_page(moved_page),
                    )
                    entry_ranges.append(EntryIndexRootRecord(
                        moved_page.records[0].entry_id, moved_page.records[-1].entry_id,
                        page_ref.offset, digest,
                    ))
                entry_root = EntryIndexRoot(tuple(entry_ranges))
                if entry_root_digest(entry_root) != old_root.entry.digest:
                    raise ValueError("EntryIndex root digest changed during compaction")
                entry_root_ref = _append_index(
                    store, writer, commit.revision, IndexPageType.ENTRY_INDEX,
                    BlockType.INDEX_PAGE, encode_entry_index_root(entry_root),
                )
                entry_reference = RootReference(
                    RootType.ENTRY, entry_root_ref.offset, entry_root_ref.length,
                    entry_root_digest(entry_root),
                )
                _require_same_logical_reference(entry_reference, old_root.entry, "EntryIndex")

                login_reference = None
                old_login = store._read_login_root(snapshot)
                if old_login is not None:
                    ranges = []
                    for selected in old_login.ranges:
                        page = store._read_login_page(snapshot, selected)
                        if login_page_digest(page) != selected.page_logical_digest:
                            raise ValueError("LoginFastIndex leaf digest mismatch")
                        block = store._container.read_block(
                            snapshot.state, selected.page_offset, BlockType.LOGIN_INDEX
                        )
                        leaf_ref = writer.append_block(block)
                        ranges.append(LoginPageRange(
                            selected.min_kind, selected.min_token, selected.max_kind, selected.max_token,
                            leaf_ref.offset, leaf_ref.length, selected.page_logical_digest,
                        ))
                    login_root = LoginRoot(tuple(ranges))
                    if login_root_digest(login_root) != old_root.login.digest:
                        raise ValueError("LoginFastIndex root digest changed during compaction")
                    login_root_ref = _append_index(
                        store, writer, commit.revision, IndexPageType.LOGIN_INDEX,
                        BlockType.LOGIN_INDEX, encode_login_root(login_root),
                    )
                    login_reference = RootReference(
                        RootType.LOGIN, login_root_ref.offset, login_root_ref.length,
                        login_root_digest(login_root),
                    )
                    _require_same_logical_reference(login_reference, old_root.login, "LoginFastIndex")
                elif old_root.login is not None:
                    raise ValueError("LoginFastIndex root disappeared during compaction")

                object_records, chunk_records, _, _ = store._read_all_object_records(snapshot)
                moved_objects: list[ObjectRecord] = []
                moved_chunks: list[ChunkRecord] = []
                chunks_by_object: dict[tuple[uuid.UUID, int], list[ChunkRecord]] = {}
                for record in chunk_records:
                    chunks_by_object.setdefault((record.key.object_id, record.key.generation), []).append(record)
                for record in object_records:
                    store.open_object(record.key.object_id, record.key.generation, _Discard())
                    manifest = store._container.read_block(
                        snapshot.state, record.manifest_offset, BlockType.OBJECT_METADATA
                    )
                    manifest_ref = writer.append_block(manifest)
                    moved_objects.append(replace(
                        record, manifest_offset=manifest_ref.offset, manifest_length=manifest_ref.length
                    ))
                    for chunk in chunks_by_object.get((record.key.object_id, record.key.generation), ()):
                        block = store._container.read_block(snapshot.state, chunk.block_offset)
                        if block.header.block_type not in (BlockType.IMAGE_CHUNK, BlockType.ATTACHMENT_CHUNK):
                            raise ValueError("ChunkIndex references a non-media chunk block")
                        block_ref = writer.append_block(block)
                        moved_chunks.append(replace(
                            chunk, block_offset=block_ref.offset, block_length=block_ref.length
                        ))

                object_reference = None
                chunk_reference = None
                if moved_objects:
                    object_reference, chunk_reference = store._write_object_indexes(
                        writer, commit.revision,
                        tuple(sorted(moved_objects, key=lambda value: value.key)),
                        tuple(sorted(moved_chunks, key=lambda value: value.key)),
                        (), (),
                    )
                    _require_same_logical_reference(object_reference, old_root.object_index, "ObjectIndex")
                    if chunk_reference is not None or old_root.chunk_index is not None:
                        _require_same_logical_reference(chunk_reference, old_root.chunk_index, "ChunkIndex")
                elif old_root.object_index is not None or old_root.chunk_index is not None:
                    raise ValueError("empty ObjectIndex is not canonical during compaction")

                store._read_metadata(snapshot)
                old_metadata = old_root.metadata
                if old_metadata is None:
                    raise ValueError("PMV commit has no metadata root")
                metadata_block = store._container.read_block(
                    snapshot.state, old_metadata.offset, BlockType.OBJECT_METADATA
                )
                metadata_ref = writer.append_block(metadata_block)
                metadata_reference = RootReference(
                    RootType.METADATA, metadata_ref.offset, metadata_ref.length, old_metadata.digest
                )
                _require_same_logical_reference(metadata_reference, old_metadata, "Metadata")

                new_root = VaultRoot(
                    entry_reference, login_reference, object_reference, chunk_reference, metadata_reference
                )
                new_root_digest = PmvVaultRootCodec.logical_digest(new_root)
                if new_root_digest != commit.root_digest:
                    raise ValueError("VaultRoot logical digest changed during compaction")
                root_ref = _append_index(
                    store, writer, commit.revision, IndexPageType.VAULT_ROOT,
                    BlockType.INDEX_PAGE, PmvVaultRootCodec.encode(new_root),
                )

                relocated_commit = Commit(
                    commit.vault_id, commit.commit_id, commit.parent_commit_id, commit.revision,
                    root_ref.offset, root_ref.length, commit.root_digest,
                    commit.signing_public_key, commit.signature,
                )
                commit_key = bytearray(derive_commit_block_key(
                    bytes(store._integrity_key), commit.commit_id, commit.revision
                ))
                try:
                    commit_block = seal(
                        store._header.vault_id, commit_key, BlockType.COMMIT,
                        commit.commit_id, commit.revision, encode_commit(relocated_commit),
                    )
                finally:
                    commit_key[:] = bytes(len(commit_key))
                commit_ref = writer.append_block(commit_block)
                output.flush()
                os.fsync(output.fileno())

                superblock = Superblock(
                    store._header.vault_id, commit.revision, commit_ref.offset, root_ref.offset,
                    writer.tail, snapshot.state.superblock.kdf_parameters_offset,
                    snapshot.state.superblock.feature_flags,
                )
                encoded_superblock = encode_superblock(superblock, authentication_key)
                for offset in (0, SUPERBLOCK_SIZE):
                    output.seek(offset)
                    _write_all(output, encoded_superblock)
                output.truncate(writer.tail)
                output.flush()
                os.fsync(output.fileno())

            # Full independent verification before the atomic installation.
            root_key = bytes(store._vault_root_key)
            from .pmv_vault_store import PmvVaultStore
            with PmvVaultStore.open_root_key(temporary, root_key) as candidate:
                if candidate.identity != old_identity:
                    raise ValueError("compacted PMV identity changed")
                candidate.metadata()
                for summary in candidate.list():
                    if candidate.read_entry(summary.entry_id) is None:
                        raise ValueError("compacted PMV lost a live Entry")
                candidate_snapshot = candidate._latest_authenticated_snapshot()
                candidate_objects = candidate._read_all_object_records(candidate_snapshot)[0]
                for record in candidate_objects:
                    candidate.open_object(record.key.object_id, record.key.generation, _Discard())

            os.replace(temporary, source)
            _fsync_parent_directory(source)
            store._container = PmvAppendOnlyFile(source, authentication_key)
            store._refresh_identity()
            if store.identity != old_identity:
                raise ValueError("installed compacted PMV identity changed")
            return store.identity
        finally:
            temporary.unlink(missing_ok=True)


def _append_index(store, writer: _Relocator, revision: int, page_type: IndexPageType,
                  block_type: BlockType, plaintext: bytes) -> _Ref:
    object_id = uuid.uuid4()
    key = bytearray(derive_index_page_key(bytes(store._index_key), object_id, revision, page_type))
    try:
        block = seal(store._header.vault_id, key, block_type, object_id, revision, plaintext)
    finally:
        key[:] = bytes(len(key))
    return writer.append_block(block)


def _require_same_logical_reference(new: RootReference | None, old: RootReference | None, label: str) -> None:
    if new is None or old is None:
        if new is not old:
            raise ValueError(f"{label} presence changed during compaction")
        return
    if new.type is not old.type or new.length != old.length or new.digest != old.digest:
        raise ValueError(f"{label} logical reference changed during compaction")
