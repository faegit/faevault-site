"""Crash-safe append-only PMV writer and authenticated snapshot access.

The two 4 KiB superblocks are publication records, not authorities by
themselves.  A non-empty snapshot is accepted only after its encrypted commit,
trusted Ed25519 identity, encrypted entry-index root, and logical root digest
have all been authenticated.
"""

from __future__ import annotations

import contextlib
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .pmv_commit import Commit, decode_commit, encode_commit, sign_commit
from .pmv_container import (
    BLOCK_HEADER_SIZE,
    DATA_START,
    SUPERBLOCK_SIZE,
    BlockType,
    EncodedBlock,
    Superblock,
    decode_block_header,
    decode_superblock,
    encode_block_header,
    encode_superblock,
    open as open_block,
    seal,
)
from .pmv_entry_index import (
    EntryIndexRoot,
    decode_entry_index_page,
    decode_entry_index_root,
)
from .pmv_integrity import encrypted_block_digest, entry_page_digest, entry_root_digest
from .pmv_key_schedule import (
    IndexPageType,
    derive_commit_block_key,
    derive_index_page_key,
)
from .pmv_vault_root import (
    PmvVaultRootCodec,
    RootReference,
    RootType,
    VaultRoot,
)


# PMVE data begins after two superblocks and two PMVH header slots. The shared
# container constant is authoritative so append and store layers cannot drift.


def _key(
    value: bytes,
    label: str,
    *,
    minimum: int = 32,
    exact: int | None = None,
) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be bytes")
    if exact is not None and len(value) != exact:
        raise ValueError(f"{label} must be exactly {exact} bytes")
    if exact is None and len(value) < minimum:
        raise ValueError(f"{label} must be at least {minimum} bytes")
    return value


def _block_length(block: EncodedBlock) -> int:
    if not isinstance(block, EncodedBlock):
        raise TypeError("block must be an EncodedBlock")
    return BLOCK_HEADER_SIZE + len(block.ciphertext)


def _canonical_path(path: os.PathLike[str] | str) -> str:
    return os.path.normcase(str(Path(path).resolve(strict=False)))


_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


def _process_lock(path: os.PathLike[str] | str) -> threading.RLock:
    canonical = _canonical_path(path)
    with _LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(canonical, threading.RLock())


@contextlib.contextmanager
def _exclusive_os_lock(path: os.PathLike[str] | str) -> Iterator[None]:
    """Hold a cross-process writer lock without locking readable PMV bytes.

    Windows byte-range locks are mandatory, so locking byte zero of the PMV
    itself would make concurrent readers fail while slot 0 is being read.  A
    stable sidecar inode avoids that conflict.  The sidecar is intentionally
    retained: deleting it would let another process lock a different inode.

    One-shot temporary files (name ends with ``.tmp``) are excluded: their
    paths are unique per operation (usually UUID-tagged) and owned by a single
    writer, so no other process can race on the same inode.  Skipping the
    sidecar means a temp file never leaves an orphaned ``.tmp.lock`` behind,
    which previously accumulated on every cloud download / migration / merge.
    The in-process lock still serialises same-process writers.
    """

    if str(Path(path).name).endswith(".tmp"):
        yield
        return

    lock_path = Path(f"{Path(path)}.lock")
    with lock_path.open("a+b", buffering=0) as lock_stream:
        lock_stream.seek(0, os.SEEK_END)
        if lock_stream.tell() == 0:
            _write_all(lock_stream, b"\0")
            lock_stream.flush()
            os.fsync(lock_stream.fileno())
        if os.name == "nt":
            import msvcrt

            lock_stream.seek(0)
            msvcrt.locking(lock_stream.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_stream.seek(0)
                msvcrt.locking(lock_stream.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True, slots=True)
class SnapshotState:
    slot: int
    superblock: Superblock


@dataclass(frozen=True, slots=True)
class AuthenticatedSnapshot:
    state: SnapshotState
    commit: Commit | None
    root: EntryIndexRoot
    vault_root: VaultRoot | None = None


@dataclass(frozen=True, slots=True)
class BlockRef:
    offset: int
    length: int
    block_type: BlockType
    object_id: uuid.UUID
    revision: int
    chunk_index: int


class WriteStage:
    AFTER_APPEND = "after_append"
    BEFORE_COMMIT = "before_commit"
    BEFORE_SUPERBLOCK = "before_superblock"


def _read_exact_at(stream: BinaryIO, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0:
        raise ValueError("negative file range")
    stream.seek(offset)
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError("PMV file range is truncated")
    return raw


def _write_all(stream: BinaryIO, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        written = stream.write(view)
        if written is None or written <= 0:
            raise OSError("short write while publishing PMV snapshot")
        view = view[written:]


def _fsync_parent_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_index_block_role(
    block: EncodedBlock,
) -> None:
    header = block.header
    if header.block_type is not BlockType.INDEX_PAGE:
        raise ValueError("index block has the wrong role")
    if header.chunk_index != -1 or header.flags != 0 or header.codec_id != 0:
        raise ValueError("index block contains unsupported header metadata")


def _read_block(
    stream: BinaryIO,
    snapshot: SnapshotState,
    offset: int,
    expected_type: BlockType | None = None,
) -> EncodedBlock:
    end = snapshot.superblock.committed_file_end
    if not DATA_START <= offset <= end - BLOCK_HEADER_SIZE:
        raise ValueError("block header is outside the committed snapshot")
    header = decode_block_header(_read_exact_at(stream, offset, BLOCK_HEADER_SIZE))
    if expected_type is not None and header.block_type is not expected_type:
        raise ValueError("block type does not match its referenced role")
    block_end = offset + BLOCK_HEADER_SIZE + header.cipher_size
    if block_end > end:
        raise ValueError("block ciphertext is outside the committed snapshot")
    ciphertext = _read_exact_at(stream, offset + BLOCK_HEADER_SIZE, header.cipher_size)
    return EncodedBlock(header, ciphertext)


def _published_superblock_states(
    stream: BinaryIO,
    authentication_key: bytes,
) -> list[SnapshotState]:
    stream.seek(0, os.SEEK_END)
    file_length = stream.tell()
    if file_length < DATA_START:
        raise ValueError("PMV file is shorter than its two superblocks")
    published: list[SnapshotState] = []
    for slot in (0, 1):
        try:
            superblock = decode_superblock(
                _read_exact_at(stream, slot * SUPERBLOCK_SIZE, SUPERBLOCK_SIZE),
                authentication_key,
            )
            if superblock.committed_file_end > file_length:
                raise ValueError("committed boundary exceeds the physical file")
            published.append(SnapshotState(slot, superblock))
        except (OSError, TypeError, ValueError):
            continue
    if not published:
        raise ValueError("no authenticated PMV superblock")
    if len({candidate.superblock.vault_id for candidate in published}) != 1:
        raise ValueError("PMV superblocks disagree on vault identity")
    return sorted(published, key=lambda item: item.superblock.sequence, reverse=True)


def _candidate_states(
    stream: BinaryIO,
    authentication_key: bytes,
) -> list[SnapshotState]:
    candidates: list[SnapshotState] = []
    for candidate in _published_superblock_states(stream, authentication_key):
        try:
            slot = candidate.slot
            superblock = candidate.superblock
            if superblock.sequence == 0:
                if superblock.latest_commit_offset or superblock.latest_index_offset:
                    raise ValueError("initial superblock references a commit")
            else:
                if not superblock.latest_commit_offset or not superblock.latest_index_offset:
                    raise ValueError("committed superblock omits its commit or index root")
                _read_block(stream, SnapshotState(slot, superblock),
                            superblock.latest_commit_offset, BlockType.COMMIT)
                _read_block(stream, SnapshotState(slot, superblock),
                            superblock.latest_index_offset, BlockType.INDEX_PAGE)
            candidates.append(candidate)
        except (OSError, TypeError, ValueError):
            continue
    if not candidates:
        raise ValueError("no recoverable PMV superblock")
    return sorted(candidates, key=lambda item: item.superblock.sequence, reverse=True)


def authenticate_snapshot(
    stream: BinaryIO,
    candidate: SnapshotState,
    *,
    vault_id: uuid.UUID,
    integrity_key: bytes | None,
    index_root_key: bytes | None,
    trusted_signing_public_key: bytes,
    commit_key: bytes | None = None,
    index_key: bytes | None = None,
    allow_legacy_static_keys: bool = False,
) -> AuthenticatedSnapshot:
    """Authenticate one candidate completely or raise ``ValueError``."""

    if candidate.superblock.vault_id != vault_id:
        raise ValueError("snapshot belongs to another vault")
    if candidate.superblock.sequence == 0:
        return AuthenticatedSnapshot(candidate, None, EntryIndexRoot(()), None)

    commit_block = _read_block(
        stream, candidate, candidate.superblock.latest_commit_offset, BlockType.COMMIT
    )
    if integrity_key is not None:
        commit_block_key = derive_commit_block_key(
            _key(integrity_key, "integrity_key", exact=32),
            commit_block.header.object_id,
            commit_block.header.object_revision,
        )
    elif allow_legacy_static_keys and commit_key is not None:
        commit_block_key = _key(commit_key, "commit_key", exact=32)
    else:
        raise ValueError("integrity_key is required for commit authentication")
    commit_plaintext = open_block(vault_id, commit_block_key, commit_block)
    try:
        commit = decode_commit(commit_plaintext)
    finally:
        # bytes are immutable; retain no additional plaintext reference here.
        commit_plaintext = b""
    if commit.vault_id != vault_id:
        raise ValueError("commit belongs to another vault")
    if commit.signing_public_key != _key(
        trusted_signing_public_key, "trusted_signing_public_key", exact=32
    ):
        raise ValueError("commit signing key is not the trusted vault identity")
    if commit.revision != candidate.superblock.sequence:
        raise ValueError("commit revision does not bind the superblock sequence")
    if commit_block.header.object_id != commit.commit_id:
        raise ValueError("commit block object ID does not match its plaintext")
    if commit_block.header.object_revision != commit.revision:
        raise ValueError("commit block revision does not match its plaintext")
    if commit.index_root_offset != candidate.superblock.latest_index_offset:
        raise ValueError("commit does not bind the published index-root offset")

    vault_root_block = _read_block(
        stream, candidate, commit.index_root_offset, BlockType.INDEX_PAGE
    )
    _validate_index_block_role(vault_root_block)
    if vault_root_block.header.object_revision != commit.revision:
        raise ValueError("vault-root block revision does not match the commit")
    actual_root_length = _block_length(vault_root_block)
    if commit.index_root_length != actual_root_length:
        raise ValueError("commit does not bind the vault-root length")
    if index_root_key is not None:
        checked_index_root_key = _key(index_root_key, "index_root_key", exact=32)
        vault_root_key = derive_index_page_key(
            checked_index_root_key,
            vault_root_block.header.object_id,
            vault_root_block.header.object_revision,
            IndexPageType.VAULT_ROOT,
        )
    elif allow_legacy_static_keys and index_key is not None:
        checked_index_root_key = None
        vault_root_key = _key(index_key, "index_key", exact=32)
    else:
        raise ValueError("index_root_key is required for index authentication")
    vault_root_plaintext = open_block(
        vault_id, vault_root_key, vault_root_block
    )
    try:
        vault_root = PmvVaultRootCodec.decode(vault_root_plaintext)
    finally:
        vault_root_plaintext = b""
    if PmvVaultRootCodec.logical_digest(vault_root) != commit.root_digest:
        raise ValueError("vault-root digest does not match the commit")

    entry_reference = vault_root.entry
    entry_root_block = _read_block(
        stream, candidate, entry_reference.offset, BlockType.INDEX_PAGE
    )
    _validate_index_block_role(entry_root_block)
    if entry_root_block.header.object_revision != commit.revision:
        raise ValueError("entry-root block revision does not match the commit")
    if _block_length(entry_root_block) != entry_reference.length:
        raise ValueError("entry-root length does not match the vault-root reference")
    entry_root_key = (
        derive_index_page_key(
            checked_index_root_key,
            entry_root_block.header.object_id,
            entry_root_block.header.object_revision,
            IndexPageType.ENTRY_INDEX,
        )
        if checked_index_root_key is not None
        else vault_root_key
    )
    entry_root_plaintext = open_block(vault_id, entry_root_key, entry_root_block)
    try:
        root = decode_entry_index_root(entry_root_plaintext)
    finally:
        entry_root_plaintext = b""
    if entry_root_digest(root) != entry_reference.digest:
        raise ValueError("entry-root digest does not match the vault-root reference")
    if candidate.superblock.latest_commit_offset + _block_length(commit_block) != (
        candidate.superblock.committed_file_end
    ):
        raise ValueError("commit block is not the final block in the snapshot")
    return AuthenticatedSnapshot(candidate, commit, root, vault_root)


class WriteTransaction:
    """A locked streaming writer that retains block references, never ciphertext."""

    def __init__(self, owner, expected_base_sequence: int, fault_injector=None):
        if type(expected_base_sequence) is not int or expected_base_sequence < 0:
            raise ValueError("expected_base_sequence must be a non-negative integer")
        self._owner = owner
        self._process_lock = _process_lock(owner.path)
        self._process_lock.acquire()
        self._os_context = None
        self._stream = None
        self._finished = False
        self._last_ref = None
        self._append_tail = None
        self._fault_injector = fault_injector
        try:
            os_context = _exclusive_os_lock(owner.path)
            os_context.__enter__()
            self._os_context = os_context
            self._stream = owner.path.open("r+b", buffering=0)
            current = _candidate_states(self._stream, owner._authentication_key)[0]
            published = _published_superblock_states(self._stream, owner._authentication_key)[0]
            if current.superblock.sequence != published.superblock.sequence:
                raise ValueError("newest published PMV superblock is structurally damaged")
            if current.superblock.sequence != expected_base_sequence:
                raise ValueError("prepared transaction is based on a stale PMV sequence")
            self.base_snapshot = current
            self.vault_id = current.superblock.vault_id
            self.base_sequence = current.superblock.sequence
            self.next_revision = self.base_sequence + 1
            if self.base_sequence:
                parent_block = _read_block(
                    self._stream, current, current.superblock.latest_commit_offset, BlockType.COMMIT
                )
                self.parent_commit_id = parent_block.header.object_id
            else:
                self.parent_commit_id = None
            self._stream.truncate(current.superblock.committed_file_end)
            self._stream.seek(current.superblock.committed_file_end)
            self._append_tail = current.superblock.committed_file_end
        except BaseException:
            self._release()
            raise

    def append_block(self, block: EncodedBlock) -> BlockRef:
        self._check_active()
        try:
            if not isinstance(block, EncodedBlock):
                raise TypeError("block must be an EncodedBlock")
            if block.header.block_type is BlockType.COMMIT:
                raise ValueError("commit blocks may only be written by publish")
            offset = self._stream.tell()
            PmvAppendOnlyFile._write_block(self._stream, block)
            ref = BlockRef(offset, _block_length(block), block.header.block_type,
                           block.header.object_id, block.header.object_revision,
                           block.header.chunk_index)
            self._last_ref = ref
            self._append_tail = offset + ref.length
            self._inject(WriteStage.AFTER_APPEND)
            return ref
        except BaseException as failure:
            try:
                self.abort()
            except BaseException as rollback:
                failure.add_note(f"transaction rollback also failed: {rollback!r}")
            raise

    def publish(
        self,
        *,
        index_root_ref: BlockRef,
        encrypted_commit: EncodedBlock,
        commit: Commit,
        index_root_key: bytes,
        integrity_key: bytes,
        trusted_signing_public_key: bytes,
    ) -> SnapshotState:
        self._check_active()
        try:
            root_key = _key(index_root_key, "index_root_key", exact=32)
            integrity = _key(integrity_key, "integrity_key", exact=32)
            trusted = _key(trusted_signing_public_key, "trusted_signing_public_key", exact=32)
            newest = _candidate_states(self._stream, self._owner._authentication_key)[0]
            published = _published_superblock_states(self._stream, self._owner._authentication_key)[0]
            if newest.superblock.sequence != published.superblock.sequence:
                raise ValueError("newest published PMV superblock is structurally damaged")
            if newest.superblock.sequence != self.base_sequence:
                raise ValueError("write transaction base sequence is stale")
            if not isinstance(commit, Commit) or commit.vault_id != self.vault_id:
                raise ValueError("commit belongs to another vault")
            if commit.revision != self.next_revision or commit.parent_commit_id != self.parent_commit_id:
                raise ValueError("commit revision or parent does not bind the transaction base")
            if commit.signing_public_key != trusted:
                raise ValueError("commit signer is not the trusted vault identity")
            if not isinstance(encrypted_commit, EncodedBlock):
                raise TypeError("encrypted_commit must be an EncodedBlock")
            if (encrypted_commit.header.block_type is not BlockType.COMMIT or
                    encrypted_commit.header.object_id != commit.commit_id or
                    encrypted_commit.header.object_revision != commit.revision or
                    encrypted_commit.header.chunk_index != -1 or encrypted_commit.header.flags != 0):
                raise ValueError("encrypted commit header does not bind the typed commit")
            if self._last_ref != index_root_ref:
                raise ValueError("index root must be the final block appended by this transaction")
            if index_root_ref.block_type is not BlockType.INDEX_PAGE:
                raise ValueError("index root has the wrong block role")
            if (commit.index_root_offset != index_root_ref.offset or
                    commit.index_root_length != index_root_ref.length):
                raise ValueError("commit does not bind the streamed index root")

            if self.base_sequence:
                authenticate_snapshot(
                    self._stream, self.base_snapshot, vault_id=self.vault_id,
                    integrity_key=integrity, index_root_key=root_key,
                    trusted_signing_public_key=trusted,
                )
            root_block = self._read_streamed(index_root_ref)
            _validate_index_block_role(root_block)
            if root_block.header.object_revision != self.next_revision:
                raise ValueError("vault-root revision does not match the transaction")
            derived_root_key = derive_index_page_key(
                root_key, root_block.header.object_id, root_block.header.object_revision,
                IndexPageType.VAULT_ROOT,
            )
            vault_root = PmvVaultRootCodec.decode(
                open_block(self.vault_id, derived_root_key, root_block)
            )
            if PmvVaultRootCodec.logical_digest(vault_root) != commit.root_digest:
                raise ValueError("commit root digest does not match streamed vault root")
            derived_commit_key = derive_commit_block_key(
                integrity, commit.commit_id, commit.revision
            )
            decoded_commit = decode_commit(
                open_block(self.vault_id, derived_commit_key, encrypted_commit)
            )
            if decoded_commit != commit:
                raise ValueError("encrypted commit does not match typed commit")

            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._inject(WriteStage.BEFORE_COMMIT)
            commit_offset = self._stream.tell()
            PmvAppendOnlyFile._write_block(self._stream, encrypted_commit)
            committed_end = self._stream.tell()
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._inject(WriteStage.BEFORE_SUPERBLOCK)
            updated = Superblock(
                vault_id=self.vault_id, sequence=self.next_revision,
                latest_commit_offset=commit_offset,
                latest_index_offset=index_root_ref.offset,
                committed_file_end=committed_end,
                kdf_parameters_offset=self.base_snapshot.superblock.kdf_parameters_offset,
                feature_flags=self.base_snapshot.superblock.feature_flags,
            )
            target_slot = 1 - self.base_snapshot.slot
            self._stream.seek(target_slot * SUPERBLOCK_SIZE)
            _write_all(self._stream, encode_superblock(updated, self._owner._authentication_key))
            self._stream.flush()
            os.fsync(self._stream.fileno())
            self._finished = True
            self._release()
            return SnapshotState(target_slot, updated)
        except BaseException as failure:
            try:
                self.abort()
            except BaseException as rollback:
                failure.add_note(f"transaction rollback also failed: {rollback!r}")
            raise

    def abort(self) -> None:
        if self._finished:
            return
        try:
            if self._stream is not None:
                self._stream.truncate(self.base_snapshot.superblock.committed_file_end)
                self._stream.flush()
                os.fsync(self._stream.fileno())
        finally:
            self._finished = True
            self._release()

    def close(self) -> None:
        self.abort()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()

    def _read_streamed(self, ref: BlockRef) -> EncodedBlock:
        header = decode_block_header(_read_exact_at(self._stream, ref.offset, BLOCK_HEADER_SIZE))
        if BLOCK_HEADER_SIZE + header.cipher_size != ref.length:
            raise ValueError("streamed block length changed")
        if (header.block_type is not ref.block_type or header.object_id != ref.object_id or
                header.object_revision != ref.revision or header.chunk_index != ref.chunk_index):
            raise ValueError("streamed block header does not match its reference")
        ciphertext = _read_exact_at(self._stream, ref.offset + BLOCK_HEADER_SIZE, header.cipher_size)
        self._stream.seek(self._append_tail)
        return EncodedBlock(header, ciphertext)

    def _inject(self, stage: str) -> None:
        if self._fault_injector is not None:
            self._fault_injector(stage)

    def _check_active(self) -> None:
        if self._finished:
            raise RuntimeError("write transaction is closed")

    def _release(self) -> None:
        try:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
        finally:
            try:
                if self._os_context is not None:
                    self._os_context.__exit__(None, None, None)
                    self._os_context = None
            finally:
                if self._process_lock is not None:
                    self._process_lock.release()
                    self._process_lock = None


class PmvAppendOnlyFile:
    """Append prepared immutable blocks and publish a signed PMV snapshot."""

    def __init__(self, path: os.PathLike[str] | str, authentication_key: bytes):
        self.path = Path(path)
        self._authentication_key = _key(authentication_key, "authentication_key")
        if not self.path.is_file():
            raise FileNotFoundError(self.path)
        with self.path.open("rb") as stream:
            _candidate_states(stream, self._authentication_key)

    def begin_write(self, expected_base_sequence: int) -> WriteTransaction:
        return WriteTransaction(self, expected_base_sequence)

    def _begin_write_for_test(self, expected_base_sequence: int, fault_injector) -> WriteTransaction:
        return WriteTransaction(self, expected_base_sequence, fault_injector)

    @classmethod
    def create(
        cls,
        path: os.PathLike[str] | str,
        vault_id: uuid.UUID,
        authentication_key: bytes,
        *,
        kdf_parameters_offset: int = 0,
        feature_flags: int = 0,
    ) -> "PmvAppendOnlyFile":
        target = Path(path)
        if target.exists() and target.is_dir():
            raise IsADirectoryError(target)
        auth = _key(authentication_key, "authentication_key")
        initial = Superblock(
            vault_id=vault_id,
            sequence=0,
            latest_commit_offset=0,
            latest_index_offset=0,
            committed_file_end=DATA_START,
            kdf_parameters_offset=kdf_parameters_offset,
            feature_flags=feature_flags,
        )
        lock = _process_lock(target)
        with lock, _exclusive_os_lock(target):
            # Exclusive creation is the non-destructive arbiter between processes.
            with target.open("x+b") as stream:
                stream.truncate(DATA_START)
                stream.seek(0)
                _write_all(stream, encode_superblock(initial, auth))
                _write_all(stream, bytes(SUPERBLOCK_SIZE))
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent_directory(target)
        return cls(target, auth)

    def candidate_states(self) -> list[SnapshotState]:
        with self.path.open("rb") as stream:
            return _candidate_states(stream, self._authentication_key)

    def read_block(
        self,
        snapshot: SnapshotState,
        offset: int,
        expected_type: BlockType | None = None,
    ) -> EncodedBlock:
        with self.path.open("rb") as stream:
            return _read_block(stream, snapshot, offset, expected_type)

    def commit(
        self,
        *,
        data_blocks: Iterable[EncodedBlock],
        index_blocks: Iterable[EncodedBlock],
        integrity_key: bytes | None,
        index_root_key: bytes | None,
        signing_private_key: Ed25519PrivateKey,
        trusted_signing_public_key: bytes,
        expected_base_sequence: int,
        commit_id: uuid.UUID | None = None,
        commit_key: bytes | None = None,
        index_key: bytes | None = None,
        allow_legacy_static_keys: bool = False,
    ) -> AuthenticatedSnapshot:
        """Publish one transaction using data -> indexes/commit -> superblock fsyncs.

        ``index_blocks`` is the deprecated prototype entry-index input: it
        contains exactly one entry root followed by its leaf pages.  The writer
        wraps that entry root in the canonical composite PMVR before signing
        and publishing the commit.  Their physical offsets must already match
        the entry-root directory.
        This keeps page construction separate while making publication and
        authentication indivisible.
        """

        data = tuple(data_blocks)
        indexes = tuple(index_blocks)
        if not indexes:
            raise ValueError("a commit requires an entry-index root block")
        if any(block.header.block_type in (BlockType.INDEX_PAGE, BlockType.COMMIT)
               for block in data):
            raise ValueError("data block has an index or commit role")
        if any(block.header.block_type is not BlockType.INDEX_PAGE for block in indexes):
            raise ValueError("all index blocks must have the INDEX_PAGE role")
        if not isinstance(signing_private_key, Ed25519PrivateKey):
            raise TypeError("signing_private_key must be an Ed25519PrivateKey")
        trusted_key = _key(
            trusted_signing_public_key, "trusted_signing_public_key", exact=32
        )
        actual_public_key = signing_private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if actual_public_key != trusted_key:
            raise ValueError("signing private key does not match the trusted vault identity")
        checked_integrity_key = (
            _key(integrity_key, "integrity_key", exact=32)
            if integrity_key is not None else None
        )
        checked_index_root_key = (
            _key(index_root_key, "index_root_key", exact=32)
            if index_root_key is not None else None
        )
        checked_commit_key = (
            _key(commit_key, "commit_key", exact=32)
            if allow_legacy_static_keys and commit_key is not None else None
        )
        checked_index_key = (
            _key(index_key, "index_key", exact=32)
            if allow_legacy_static_keys and index_key is not None else None
        )
        if checked_integrity_key is None and checked_commit_key is None:
            raise ValueError("integrity_key is required for production commits")
        if checked_index_root_key is None and checked_index_key is None:
            raise ValueError("index_root_key is required for production commits")
        if type(expected_base_sequence) is not int or expected_base_sequence < 0:
            raise ValueError("expected_base_sequence must be a non-negative integer")

        process_lock = _process_lock(self.path)
        with process_lock, _exclusive_os_lock(self.path):
            with self.path.open("r+b", buffering=0) as stream:
                candidates = _candidate_states(stream, self._authentication_key)
                published = _published_superblock_states(stream, self._authentication_key)
                if candidates[0].superblock.sequence != published[0].superblock.sequence:
                    raise ValueError(
                        "newest published PMV superblock is structurally damaged; "
                        "explicit recovery is required before writing"
                    )
                # A reader may safely fall back to an older snapshot.  A
                # writer must not: wrong keys or an untrusted signer could
                # otherwise make it truncate a valid newer commit as though it
                # were merely an uncommitted tail.
                newest = candidates[0]
                try:
                    current = authenticate_snapshot(
                        stream,
                        newest,
                        vault_id=newest.superblock.vault_id,
                        integrity_key=checked_integrity_key,
                        index_root_key=checked_index_root_key,
                        commit_key=checked_commit_key,
                        index_key=checked_index_key,
                        allow_legacy_static_keys=allow_legacy_static_keys,
                        trusted_signing_public_key=trusted_key,
                    )
                except (InvalidTag, OSError, TypeError, ValueError) as exc:
                    raise ValueError(
                        "newest PMV snapshot cannot be authenticated for writing"
                    ) from exc
                if current.state.superblock.sequence != expected_base_sequence:
                    raise ValueError("prepared transaction is based on a stale PMV sequence")

                superblock = current.state.superblock
                next_revision = superblock.sequence + 1
                if any(block.header.object_revision != next_revision for block in indexes):
                    raise ValueError("index block revision does not match the new commit")
                stream.truncate(superblock.committed_file_end)
                stream.seek(superblock.committed_file_end)
                data_offsets: list[int] = []
                for block in data:
                    data_offsets.append(stream.tell())
                    self._write_block(stream, block)
                stream.flush()
                os.fsync(stream.fileno())

                index_offsets: list[int] = []
                for block in indexes:
                    index_offsets.append(stream.tell())
                    self._write_block(stream, block)
                index_tail = stream.tell()
                entry_root_offset = index_offsets[0]
                entry_root_block = indexes[0]
                root_key = (
                    derive_index_page_key(
                        checked_index_root_key,
                        entry_root_block.header.object_id,
                        entry_root_block.header.object_revision,
                        IndexPageType.ENTRY_INDEX,
                    )
                    if checked_index_root_key is not None else checked_index_key
                )
                try:
                    root_plaintext = open_block(
                        superblock.vault_id, root_key, entry_root_block
                    )
                except InvalidTag as exc:
                    raise ValueError(
                        "entry-index root cannot be authenticated for its derived page role"
                    ) from exc
                try:
                    root = decode_entry_index_root(root_plaintext)
                finally:
                    root_plaintext = b""
                expected_leaf_offsets = set(index_offsets[1:])
                if {record.page_offset for record in root.records} != expected_leaf_offsets:
                    raise ValueError("index root does not reference exactly the committed leaf pages")
                for record in root.records:
                    leaf_block = indexes[index_offsets.index(record.page_offset)]
                    leaf_key = (
                        derive_index_page_key(
                            checked_index_root_key,
                            leaf_block.header.object_id,
                            leaf_block.header.object_revision,
                            IndexPageType.ENTRY_INDEX,
                        )
                        if checked_index_root_key is not None else checked_index_key
                    )
                    try:
                        leaf_plaintext = open_block(
                            superblock.vault_id, leaf_key, leaf_block
                        )
                    except InvalidTag as exc:
                        raise ValueError(
                            "entry-index leaf cannot be authenticated for its derived page role"
                        ) from exc
                    try:
                        leaf = decode_entry_index_page(leaf_plaintext)
                    finally:
                        leaf_plaintext = b""
                    if not leaf.records or leaf.next_page_offset != 0:
                        raise ValueError("root directory references an invalid leaf page")
                    if (leaf.records[0].entry_id != record.min_entry_id or
                            leaf.records[-1].entry_id != record.max_entry_id):
                        raise ValueError("index root range does not match its leaf page")
                    if entry_page_digest(leaf) != record.page_digest:
                        raise ValueError("index leaf digest does not match the root directory")
                    new_data_by_offset = dict(zip(data_offsets, data))
                    for entry_record in leaf.records:
                        if entry_record.state.value != 1:
                            continue
                        referenced = new_data_by_offset.get(entry_record.offset)
                        if referenced is None:
                            referenced = _read_block(
                                stream, current.state, entry_record.offset, BlockType.ENTRY
                            )
                        if referenced.header.block_type is not BlockType.ENTRY:
                            raise ValueError("active index record does not reference an entry block")
                        if referenced.header.object_id != entry_record.entry_id:
                            raise ValueError("active index ID does not match its entry block")
                        if referenced.header.object_revision != entry_record.revision:
                            raise ValueError("active index revision does not match its entry block")
                        if _block_length(referenced) != entry_record.length:
                            raise ValueError("active index length does not match its entry block")
                        if encrypted_block_digest(referenced) != entry_record.content_digest:
                            raise ValueError("active index digest does not match its entry block")

                for index_block in indexes:
                    _validate_index_block_role(index_block)
                chosen_commit_id = commit_id or uuid.uuid4()
                vault_root = VaultRoot(
                    entry=RootReference(
                        RootType.ENTRY,
                        entry_root_offset,
                        _block_length(entry_root_block),
                        entry_root_digest(root),
                    )
                )
                vault_root_id = uuid.uuid4()
                vault_root_key = (
                    derive_index_page_key(
                        checked_index_root_key,
                        vault_root_id,
                        next_revision,
                        IndexPageType.VAULT_ROOT,
                    )
                    if checked_index_root_key is not None else checked_index_key
                )
                vault_root_block = seal(
                    superblock.vault_id,
                    vault_root_key,
                    BlockType.INDEX_PAGE,
                    vault_root_id,
                    next_revision,
                    PmvVaultRootCodec.encode(vault_root),
                )
                _validate_index_block_role(vault_root_block)
                # Index/reference validation above performs positional reads on
                # this same stream. Restore the append cursor before publishing
                # PMVR so the compatibility writer remains strictly append-only.
                stream.seek(index_tail)
                vault_root_offset = stream.tell()
                self._write_block(stream, vault_root_block)
                indexes_end = stream.tell()
                unsigned = Commit(
                    vault_id=superblock.vault_id,
                    commit_id=chosen_commit_id,
                    parent_commit_id=current.commit.commit_id if current.commit else None,
                    revision=next_revision,
                    index_root_offset=vault_root_offset,
                    index_root_length=_block_length(vault_root_block),
                    root_digest=PmvVaultRootCodec.logical_digest(vault_root),
                    signing_public_key=bytes(32),
                    signature=bytes(64),
                )
                signed = sign_commit(unsigned, signing_private_key)
                commit_block_key = (
                    derive_commit_block_key(
                        checked_integrity_key, signed.commit_id, signed.revision
                    )
                    if checked_integrity_key is not None else checked_commit_key
                )
                commit_block = seal(
                    superblock.vault_id,
                    commit_block_key,
                    BlockType.COMMIT,
                    signed.commit_id,
                    signed.revision,
                    encode_commit(signed),
                )
                # Validating records from the previous snapshot performs
                # positioned reads on this same locked handle.
                stream.seek(indexes_end)
                commit_offset = indexes_end
                self._write_block(stream, commit_block)
                committed_end = stream.tell()
                stream.flush()
                os.fsync(stream.fileno())

                updated = Superblock(
                    vault_id=superblock.vault_id,
                    sequence=next_revision,
                    latest_commit_offset=commit_offset,
                    latest_index_offset=vault_root_offset,
                    committed_file_end=committed_end,
                    kdf_parameters_offset=superblock.kdf_parameters_offset,
                    feature_flags=superblock.feature_flags,
                )
                target_slot = 1 - current.state.slot
                stream.seek(target_slot * SUPERBLOCK_SIZE)
                _write_all(stream, encode_superblock(updated, self._authentication_key))
                stream.flush()
                os.fsync(stream.fileno())
                published = SnapshotState(target_slot, updated)
                return AuthenticatedSnapshot(published, signed, root, vault_root)

    @staticmethod
    def _write_block(stream: BinaryIO, block: EncodedBlock) -> None:
        _write_all(stream, encode_block_header(block.header))
        _write_all(stream, block.ciphertext)


__all__ = [
    "DATA_START",
    "BlockRef",
    "WriteStage",
    "WriteTransaction",
    "SnapshotState",
    "AuthenticatedSnapshot",
    "authenticate_snapshot",
    "PmvAppendOnlyFile",
]
