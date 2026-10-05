"""Production-facing PMVE vault store composed from the frozen wire codecs.

The store keeps only purpose-separated mutable session keys in memory.  Entry
reads remain targeted through :class:`PmvEntryReader`; no operation loads the
whole PMV file into memory.  Snapshot writes deliberately rebuild the entry
index in this first production slice.  The append transaction is still fully
streaming and crash-safe; page-level COW is a later optimization.
"""

from __future__ import annotations

import copy
import hmac
import io
import math
import os
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .models import Entry
from .pmv_attachment import AttachmentKind, CHUNK_SIZE
from .pmv_append import (
    AuthenticatedSnapshot,
    PmvAppendOnlyFile,
    _block_length,
    _exclusive_os_lock,
    _fsync_parent_directory,
    _process_lock,
    _write_all,
    authenticate_snapshot,
)
from .pmv_commit import Commit, decode_commit, encode_commit, sign_commit
from .pmv_container import (
    DATA_START,
    BlockType,
    EncodedBlock,
    open as open_block,
    seal,
)
from .pmv_entry_codec import decode_entry, encode_entry
from .pmv_entry_index import (
    EntryIndexPage,
    EntryIndexRecord,
    EntryIndexRoot,
    EntryIndexRootRecord,
    EntryIndexState,
    encode_entry_index_page,
    encode_entry_index_root,
)
from .pmv_entry_reader import EntrySummary, PmvEntryReader
from .pmv_integrity import encrypted_block_digest, entry_page_digest, entry_root_digest
from .pmv_tombstone import Tombstone, encode_tombstone
from .pmv_key_schedule import (
    ARGON2_SALT_SIZE,
    IndexPageType,
    derive_commit_block_key,
    derive_entry_generation_key,
    derive_index_page_key,
    derive_metadata_block_key,
    derive_root_keys,
)
from .pmv_kdf_policy import PmvKdfParameters, PmvKdfProfile
from .pmv_login_fast_index import (
    EntryType as LoginEntryType,
    LookupKind,
    Page as LoginPage,
    PageLocation as LoginPageLocation,
    PageRange as LoginPageRange,
    Record as LoginRecord,
    Root as LoginRoot,
    State as LoginState,
    build_pages as build_login_pages,
    build_root as build_login_root,
    decode as decode_login_page,
    decode_root as decode_login_root,
    domain_token,
    encode as encode_login_page,
    encode_root as encode_login_root,
    logical_root_digest as login_root_digest,
    normalize_domain,
    package_token,
    query as query_login_root,
    rp_id_token,
)
from .pmv_compression import choose_codec
from .pmv_object_index import (
    ChunkKey,
    ChunkPage,
    ChunkRecord,
    ExistingPage,
    ObjectKey,
    ObjectPage,
    ObjectRecord,
    RangeRecord,
    RangeRoot,
    chunk_page_digest,
    chunk_root_digest,
    decode_chunk_page,
    decode_chunk_root,
    decode_object_page,
    decode_object_root,
    encode_chunk_page,
    encode_chunk_root,
    encode_object_page,
    encode_object_root,
    object_page_digest,
    object_root_digest,
    plan_chunk_pages,
    plan_object_pages,
)
from .pmv_object_store import (
    StoredBlock,
    import_from as import_object_from,
    open_range_to as open_object_range_to,
    open_to as open_object_to,
    read_manifest as read_object_manifest,
)
from .pmv_vault_header import (
    HEADER_SIZE,
    PRIMARY_OFFSET,
    SECONDARY_OFFSET,
    UnlockedHeader,
    create_header,
    decode_header,
    rewrap_password as rewrap_header_password,
    rewrap_password_with_recovery as rewrap_header_password_with_recovery,
    rewrap_recovery as rewrap_header_recovery,
    rewrap_recovery_with_password as rewrap_header_recovery_with_password,
    unlock_with_password,
    unlock_with_recovery,
    unlock_with_root_key,
)
from .pmv_vault_metadata import decode_metadata, encode_metadata, logical_digest as metadata_digest
from .pmv_vault_root import PmvVaultRootCodec, RootReference, RootType, VaultRoot


_KEY_SIZE = 32
_MAX_WIRE_LONG = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class VaultIdentity:
    vault_id: uuid.UUID
    signing_public_key: bytes
    key_revision: int
    header_revision: int
    sequence: int
    commit_id: uuid.UUID | None
    parent_commit_id: uuid.UUID | None
    root_digest: bytes | None


@dataclass(frozen=True, slots=True)
class _EntryInput:
    entry_id: uuid.UUID
    encoded: bytes
    entry_type: str
    title: str
    favorite: bool
    icon_object_id: uuid.UUID | None
    modified_at_millis: int
    deleted: bool
    source: Entry | Mapping[str, object]


@dataclass(frozen=True, slots=True)
class ObjectImport:
    stream: BinaryIO
    expected_size: int
    object_id: uuid.UUID
    generation: int
    kind: AttachmentKind


@dataclass(frozen=True, slots=True)
class ObjectRef:
    object_id: uuid.UUID
    generation: int
    kind: AttachmentKind
    size: int
    sha256: bytes


@dataclass(frozen=True, slots=True)
class MutationContent:
    metadata: Mapping[str, object]
    entries: Iterable[Entry | Mapping[str, object]]


@dataclass(frozen=True, slots=True)
class MutationResult:
    identity: VaultIdentity
    object_refs: tuple[ObjectRef, ...]


def _exact_bytes(value: object, label: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{label} must be exactly {length} bytes")
    return value


def _read_exact(stream, offset: int, length: int) -> bytes:
    stream.seek(offset)
    raw = stream.read(length)
    if len(raw) != length:
        raise ValueError("PMV file is truncated")
    return raw


class PmvVaultStore:
    """Unlocked PMVE session with password/recovery bootstrap entry points."""

    def __init__(
        self,
        path: Path,
        container: PmvAppendOnlyFile,
        unlocked: UnlockedHeader,
        header_slot: int,
        header_raw: bytes,
    ) -> None:
        self.path = path
        self._container = container
        self._header = unlocked.header
        self._header_slot = header_slot
        self._header_raw = header_raw
        self._vault_root_key = bytearray(unlocked.vault_root_key)
        self._signing_seed = bytearray(unlocked.signing_private_seed)
        derived = derive_root_keys(bytes(self._vault_root_key), self._header.vault_id)
        self._metadata_key = bytearray(derived.metadata_key)
        self._entry_root_key = bytearray(derived.entry_root_key)
        self._attachment_root_key = bytearray(derived.attachment_root_key)
        self._index_key = bytearray(derived.index_key)
        self._search_index_key = bytearray(derived.search_index_key)
        self._integrity_key = bytearray(derived.integrity_key)
        self._sync_auth_key = bytearray(derived.sync_auth_key)
        self._key_wrap_key = bytearray(derived.key_wrap_key)
        del derived
        self._closed = False
        self._refresh_identity()

    @classmethod
    def create(
        cls,
        path: os.PathLike[str] | str,
        password_utf8: bytes,
        recovery_secret: bytes,
        metadata: Mapping[str, object],
        entries: Iterable[Entry | Mapping[str, object]],
    ) -> "PmvVaultStore":
        target = Path(path)
        password = _exact_bytes(password_utf8, "password_utf8")
        recovery = _exact_bytes(recovery_secret, "recovery_secret", _KEY_SIZE)
        vault_id = uuid.uuid4()
        root_buffer = bytearray(os.urandom(_KEY_SIZE))
        seed_buffer = bytearray(os.urandom(_KEY_SIZE))
        salt = os.urandom(ARGON2_SALT_SIZE)
        header_raw = b""
        store: PmvVaultStore | None = None
        created = False
        try:
            header_raw = create_header(
                vault_id=vault_id,
                key_revision=1,
                header_revision=1,
                password_utf8=password,
                recovery_secret=recovery,
                vault_root_key=bytes(root_buffer),
                signing_private_seed=bytes(seed_buffer),
                salt=salt,
            )
            root_keys = derive_root_keys(bytes(root_buffer), vault_id)
            container = PmvAppendOnlyFile.create(target, vault_id, root_keys.integrity_key)
            del root_keys
            created = True
            with target.open("r+b", buffering=0) as stream:
                stream.seek(PRIMARY_OFFSET)
                _write_all(stream, header_raw)
                stream.seek(SECONDARY_OFFSET)
                _write_all(stream, header_raw)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent_directory(target)
            unlocked = unlock_with_password(header_raw, password)
            store = cls(target, container, unlocked, 0, header_raw)
            store.save_full(expected_sequence=0, metadata=metadata, entries=entries)
            return store
        except Exception:
            if store is not None:
                store.close()
            if created:
                target.unlink(missing_ok=True)
            raise
        finally:
            root_buffer[:] = bytes(len(root_buffer))
            seed_buffer[:] = bytes(len(seed_buffer))
            header_raw = b""

    @classmethod
    def open_password(
        cls, path: os.PathLike[str] | str, password_utf8: bytes
    ) -> "PmvVaultStore":
        password = _exact_bytes(password_utf8, "password_utf8")
        return cls._open(path, lambda raw: unlock_with_password(raw, password))

    @classmethod
    def open_recovery(
        cls, path: os.PathLike[str] | str, recovery_secret: bytes
    ) -> "PmvVaultStore":
        recovery = _exact_bytes(recovery_secret, "recovery_secret", _KEY_SIZE)
        return cls._open(path, lambda raw: unlock_with_recovery(raw, recovery))

    @classmethod
    def open_root_key(
        cls, path: os.PathLike[str] | str, vault_root_key: bytes
    ) -> "PmvVaultStore":
        root_key = _exact_bytes(vault_root_key, "vault_root_key", _KEY_SIZE)
        return cls._open(path, lambda raw: unlock_with_root_key(raw, root_key))

    @classmethod
    def _open(cls, path, unlocker) -> "PmvVaultStore":
        target = Path(path)
        if not target.is_file():
            raise FileNotFoundError(target)
        candidates: list[tuple[int, bytes, UnlockedHeader]] = []
        with target.open("rb") as stream:
            for slot, offset in ((0, PRIMARY_OFFSET), (1, SECONDARY_OFFSET)):
                raw = _read_exact(stream, offset, HEADER_SIZE)
                try:
                    candidates.append((slot, raw, unlocker(raw)))
                except (InvalidTag, TypeError, ValueError):
                    continue
        if not candidates:
            raise ValueError("PMV credential or header authentication failed")
        candidates.sort(
            key=lambda item: (
                item[2].header.header_revision,
                item[2].header.key_revision,
                item[0],
            ),
            reverse=True,
        )
        last_error: Exception | None = None
        for slot, raw, unlocked in candidates:
            store: PmvVaultStore | None = None
            try:
                container = PmvAppendOnlyFile(target, unlocked.superblock_authentication_key)
                store = cls(target, container, unlocked, slot, raw)
                store._reject_decryptable_newest_signer_mismatch()
                store._latest_authenticated_snapshot()
                return store
            except (InvalidTag, OSError, TypeError, ValueError) as error:
                last_error = error
                if store is not None:
                    store.close()
        raise ValueError("no header candidate authenticates the PMV head") from last_error

    @property
    def identity(self) -> VaultIdentity:
        self._require_open()
        self._refresh_identity()
        return self._identity

    @property
    def kdf_parameters(self) -> PmvKdfParameters:
        self._require_open()
        return self._header.kdf_parameters

    def copy_root_key(self) -> bytes:
        """Return an isolated RootKey copy for an OS-protected device envelope."""

        self._require_open()
        return bytes(bytearray(self._vault_root_key))

    def copy_header_raw(self) -> bytes:
        """Return an isolated copy of the currently selected authenticated header raw bytes."""

        self._require_open()
        return bytes(self._header_raw)

    def authenticated_ancestor_commit_ids(self) -> frozenset[uuid.UUID]:
        """Return the fully authenticated commit ancestry retained in this file."""

        self._require_open()
        snapshot = self._latest_authenticated_snapshot()
        if snapshot.commit is None:
            return frozenset()
        commits: dict[uuid.UUID, Commit] = {}
        offset = DATA_START
        end = snapshot.state.superblock.committed_file_end
        while offset < end:
            block = self._container.read_block(snapshot.state, offset)
            if block.header.block_type is BlockType.COMMIT:
                key = bytearray(
                    derive_commit_block_key(
                        bytes(self._integrity_key),
                        block.header.object_id,
                        block.header.object_revision,
                    )
                )
                try:
                    plaintext = open_block(self._header.vault_id, key, block)
                finally:
                    key[:] = bytes(len(key))
                try:
                    commit = decode_commit(plaintext)
                finally:
                    plaintext = b""
                if (
                    commit.vault_id != self._header.vault_id
                    or commit.commit_id != block.header.object_id
                    or commit.revision != block.header.object_revision
                    or commit.signing_public_key != self._header.signing_public_key
                    or commit.commit_id in commits
                ):
                    raise ValueError("PMV commit history cannot be authenticated")
                commits[commit.commit_id] = commit
            offset += _block_length(block)
        if offset != end:
            raise ValueError("PMV commit history has an invalid block boundary")
        latest = commits.get(snapshot.commit.commit_id)
        if latest != snapshot.commit:
            raise ValueError("PMV head commit is missing from authenticated history")
        ancestors: set[uuid.UUID] = set()
        child = latest
        while child.parent_commit_id is not None:
            parent_id = child.parent_commit_id
            if parent_id in ancestors:
                raise ValueError("PMV commit history contains a cycle")
            ancestors.add(parent_id)
            parent = commits.get(parent_id)
            if parent is None:
                break
            if parent.revision >= child.revision:
                raise ValueError("PMV commit revisions are not strictly increasing")
            child = parent
        return frozenset(ancestors)

    def list(self) -> tuple[EntrySummary, ...]:
        self._require_open()
        reader = self._reader()
        last_error: Exception | None = None
        for snapshot in self._authenticated_snapshots():
            try:
                metadata = self._read_metadata(snapshot)
                summaries: dict[uuid.UUID, EntrySummary] = {}
                for directory in snapshot.root.records:
                    leaf = reader._read_leaf(snapshot, directory)
                    for record in leaf.records:
                        if record.state is not EntryIndexState.ACTIVE:
                            continue
                        summaries[record.entry_id] = EntrySummary(
                            entry_id=record.entry_id,
                            entry_type=record.entry_type,
                            display_title=record.display_title,
                            favorite=record.favorite,
                            icon_object_id=record.icon_object_id,
                            modified_at_epoch_millis=record.modified_at_epoch_millis,
                            revision=record.revision,
                        )
                ordered_ids = tuple(
                    uuid.UUID(value)
                    for value in metadata["entry_order"] + metadata["trash_order"]
                )
                if set(ordered_ids) != set(summaries) or len(ordered_ids) != len(summaries):
                    raise ValueError("metadata entry order does not match the entry index")
                return tuple(summaries[entry_id] for entry_id in ordered_ids)
            except (InvalidTag, OSError, TypeError, ValueError) as error:
                last_error = error
        raise ValueError("no fully authenticated PMV list snapshot") from last_error

    def read_entry(self, entry_id: uuid.UUID) -> Entry | None:
        self._require_open()
        if not isinstance(entry_id, uuid.UUID):
            raise TypeError("entry_id must be a UUID")
        return self._reader().find_decoded(
            entry_id, lambda raw: decode_entry(raw, expected_entry_id=entry_id)
        )

    def read_entries(self, entry_ids: Iterable[uuid.UUID]) -> dict[uuid.UUID, Entry | None]:
        """Load several entries without re-reading their shared index pages."""
        self._require_open()
        return self._reader().find_many_decoded(
            entry_ids,
            lambda entry_id, raw: decode_entry(raw, expected_entry_id=entry_id),
        )

    def metadata(self) -> dict[str, object]:
        self._require_open()
        last_error: Exception | None = None
        for snapshot in self._authenticated_snapshots():
            try:
                return self._read_metadata(snapshot)
            except (InvalidTag, OSError, TypeError, ValueError) as error:
                last_error = error
        raise ValueError("no fully authenticated PMV metadata snapshot") from last_error

    def sign_device_authorization(
        self,
        value: "pmv_sync_authorization.DeviceAuthorization",
    ) -> "pmv_sync_authorization.DeviceAuthorization":
        """Sign a device authorization record with the vault signing key."""
        from . import pmv_sync_authorization

        self._require_open()
        if value.vault_id != self.identity.vault_id:
            raise ValueError("device authorization belongs to another vault")
        return pmv_sync_authorization.sign_authorization(value, bytes(self._signing_seed))

    def query_domain(self, domain: str) -> tuple[uuid.UUID, ...]:
        """Return active login candidates for a host, exact domain first."""

        self._require_open()
        normalized = normalize_domain(domain)
        labels = normalized.split(".")
        result: list[uuid.UUID] = []
        seen: set[uuid.UUID] = set()
        for index in range(len(labels) - 1):
            candidate = ".".join(labels[index:])
            token = domain_token(bytes(self._search_index_key), candidate)
            for entry_id in self._query_login(LookupKind.DOMAIN, token):
                if entry_id not in seen:
                    seen.add(entry_id)
                    result.append(entry_id)
        return tuple(result)

    def query_package(self, package_name: str) -> tuple[uuid.UUID, ...]:
        self._require_open()
        token = package_token(bytes(self._search_index_key), package_name)
        return self._query_login(LookupKind.PACKAGE, token)

    def query_rp_id(self, rp_id: str) -> tuple[uuid.UUID, ...]:
        self._require_open()
        token = rp_id_token(bytes(self._search_index_key), rp_id)
        return self._query_login(LookupKind.RP_ID, token)

    def import_object(
        self,
        *,
        expected_sequence: int,
        stream: BinaryIO,
        expected_size: int,
        object_id: uuid.UUID,
        generation: int,
        kind: AttachmentKind,
    ) -> VaultIdentity:
        """Stream one object into a new commit without exposing partial index state."""

        self._require_open()
        snapshot = self._snapshot_for_sequence(expected_sequence)
        metadata = self._read_metadata(snapshot)
        entries = self._entries_for_snapshot(snapshot, metadata)
        result = self._save_full(
            expected_sequence=expected_sequence,
            base_snapshot=snapshot,
            object_imports=(ObjectImport(stream, expected_size, object_id, generation, kind),),
            prepare=lambda _refs: MutationContent(metadata, entries),
            enforce_object_closure=False,
        )
        return result.identity

    def open_object(
        self,
        object_id: uuid.UUID,
        generation: int,
        output: BinaryIO,
    ) -> None:
        """Open an object from one fixed authenticated snapshot into ``output``."""

        self._require_open()
        key = ObjectKey(object_id, generation)
        snapshot = self._latest_authenticated_snapshot()
        record, chunk_root = self._object_read_context(snapshot, key)
        open_object_to(
            record,
            self._header.vault_id,
            bytes(self._attachment_root_key),
            self._snapshot_block_reader(snapshot),
            self._chunk_finder(snapshot, chunk_root),
            output,
        )

    def open_object_range(
        self,
        object_id: uuid.UUID,
        generation: int,
        offset: int,
        length: int,
        output: BinaryIO,
    ) -> None:
        """Open a verified object range from one fixed authenticated snapshot."""

        self._require_open()
        key = ObjectKey(object_id, generation)
        snapshot = self._latest_authenticated_snapshot()
        record, chunk_root = self._object_read_context(snapshot, key)
        open_object_range_to(
            record,
            offset,
            length,
            self._header.vault_id,
            bytes(self._attachment_root_key),
            self._snapshot_block_reader(snapshot),
            self._chunk_finder(snapshot, chunk_root),
            output,
        )

    def save_full(
        self,
        *,
        expected_sequence: int,
        metadata: Mapping[str, object],
        entries: Iterable[Entry | Mapping[str, object]],
    ) -> VaultIdentity:
        self._require_open()
        snapshot = self._snapshot_for_sequence(expected_sequence)
        return self._save_full(
            expected_sequence=expected_sequence,
            base_snapshot=snapshot,
            object_imports=(),
            prepare=lambda _refs: MutationContent(metadata, entries),
        ).identity

    def save_merged(
        self, source: PmvVaultStore, *, expected_sequence: int,
        metadata: Mapping[str, object], entries: Iterable[Entry | Mapping[str, object]],
    ) -> VaultIdentity:
        """Atomically copy missing reachable media and commit a divergent merge."""
        from .pmv_media_ref import scan, scan_value, from_store_ref

        self._require_open()
        source._require_open()
        if self._header.vault_id != source._header.vault_id or self.path.resolve() == source.path.resolve():
            raise ValueError("merge source must be another file of the same vault")
        snapshot = self._snapshot_for_sequence(expected_sequence)
        source_snapshot = source._latest_authenticated_snapshot()
        entries = tuple(entries)
        occurrences = list(scan_value(metadata))
        for entry in entries:
            occurrences.extend(scan(entry) if isinstance(entry, Entry) else scan_value(entry.get("fields", {})))
        refs = {}
        for occurrence in occurrences:
            ref = occurrence.ref
            if ref is None:
                continue
            key = ObjectKey(ref.object_id, ref.generation)
            if key in refs and refs[key] != ref:
                raise ValueError("merged media references disagree for the same object generation")
            refs[key] = ref
        object_root = self._read_object_root(snapshot)
        available = {
            record.key for page in (object_root.records if object_root else ())
            for record in self._read_object_page(snapshot, page).records
        }
        imports = []

        class RangeInput(io.RawIOBase):
            def __init__(self, record, chunk_root, size):
                super().__init__()
                self.record, self.size, self.position = record, size, 0
                self.find_chunk = source._chunk_finder(source_snapshot, chunk_root)

            def read(self, size=-1):
                if self.closed:
                    raise ValueError("read from closed merge stream")
                count = min(CHUNK_SIZE, self.size - self.position, size if size >= 0 else CHUNK_SIZE)
                if count == 0:
                    return b""
                with io.BytesIO() as output:
                    open_object_range_to(self.record, self.position, count, source._header.vault_id,
                                         bytes(source._attachment_root_key),
                                         source._snapshot_block_reader(source_snapshot), self.find_chunk, output)
                    result = output.getvalue()
                if len(result) != count:
                    raise ValueError("incomplete merged media range")
                self.position += count
                return result

        try:
            for key, ref in refs.items():
                owner, owner_snapshot = (self, snapshot) if key in available else (source, source_snapshot)
                record, chunk_root = owner._object_read_context(owner_snapshot, key)
                manifest = read_object_manifest(record, owner._header.vault_id, bytes(owner._attachment_root_key),
                                                owner._snapshot_block_reader(owner_snapshot))
                if (manifest.kind != ref.kind or manifest.total_size != ref.size or
                        not hmac.compare_digest(manifest.sha256, ref.sha256)):
                    raise ValueError("merged media does not match its reference")
                if key not in available:
                    imports.append(ObjectImport(RangeInput(record, chunk_root, ref.size), ref.size,
                                                ref.object_id, ref.generation, ref.kind))

            def prepare(imported):
                for actual in imported:
                    if from_store_ref(actual) != refs[ObjectKey(actual.object_id, actual.generation)]:
                        raise ValueError("merged media transfer verification failed")
                if source._latest_authenticated_snapshot().commit.commit_id != source_snapshot.commit.commit_id:
                    raise ValueError("merge source changed during media transfer")
                return MutationContent(metadata, entries)

            return self.apply_mutation(expected_sequence=expected_sequence,
                                       object_imports=imports, prepare=prepare).identity
        finally:
            for request in imports:
                request.stream.close()

    def compact(self) -> VaultIdentity:
        """Stream reachable blocks into a verified replacement without a logical Commit."""
        from .pmv_compact import compact_store
        return compact_store(self)

    def apply_mutation(
        self,
        *,
        expected_sequence: int,
        prepare: Callable[[tuple[ObjectRef, ...]], MutationContent],
        object_imports: Sequence[ObjectImport] = (),
    ) -> MutationResult:
        """Publish entries, metadata, and 0..N streamed objects in one commit.

        ``prepare`` runs after all streams reach their declared EOF and before PMVR/Commit
        publication.  It can embed the supplied object IDs/generations in Entries without a
        second commit.  Any exception or cancellation leaves the old snapshot authoritative.
        The store never closes caller-owned streams; a retry must use newly opened streams because
        a failed attempt may already have consumed part of each old stream.
        """
        self._require_open()
        if type(expected_sequence) is not int or expected_sequence <= 0:
            raise ValueError("VaultMutation requires a committed base sequence")
        if not callable(prepare):
            raise TypeError("prepare must be callable")
        imports = tuple(object_imports)
        if any(not isinstance(item, ObjectImport) for item in imports):
            raise TypeError("object_imports must contain ObjectImport values")
        keys = tuple(ObjectKey(item.object_id, item.generation) for item in imports)
        if len(set(keys)) != len(keys):
            raise ValueError("mutation contains duplicate object generations")
        for item in imports:
            if type(item.expected_size) is not int or item.expected_size < 0:
                raise ValueError("object expected_size must be non-negative")
            if type(item.generation) is not int or item.generation < 0:
                raise ValueError("object generation must be non-negative")
        snapshot = self._snapshot_for_sequence(expected_sequence)
        return self._save_full(
            expected_sequence=expected_sequence,
            base_snapshot=snapshot,
            object_imports=imports,
            prepare=prepare,
        )

    def _save_full(
        self,
        *,
        expected_sequence: int,
        base_snapshot: AuthenticatedSnapshot,
        object_imports: Sequence[ObjectImport],
        prepare: Callable[[tuple[ObjectRef, ...]], MutationContent],
        enforce_object_closure: bool = True,
    ) -> MutationResult:
        """Replace the logical entry set and publish one signed snapshot.

        This first store slice rewrites all Entry/PMEI pages.  The write path is
        nevertheless append-only and uses the container transaction's stale
        sequence check and publication fsync ordering.
        """

        if type(expected_sequence) is not int or not 0 <= expected_sequence <= _MAX_WIRE_LONG:
            raise ValueError("expected_sequence must be between 0 and 2^63 - 1")
        if base_snapshot.state.superblock.sequence != expected_sequence:
            raise ValueError("write transaction base sequence is stale")
        keys = tuple(ObjectKey(item.object_id, item.generation) for item in object_imports)
        # begin_write owns the process/OS writer locks.  All offsets used by
        # PMEI/PMER/PMVR are therefore obtained from append_block, never from a
        # racy preflight file-length calculation.
        with self._container.begin_write(expected_sequence) as transaction:
            if transaction.vault_id != self._header.vault_id:
                raise ValueError("PMV transaction belongs to another vault")
            if transaction.base_snapshot != base_snapshot.state:
                raise ValueError("write transaction base snapshot is stale")
            revision = transaction.next_revision
            object_reference = (
                base_snapshot.vault_root.object_index
                if base_snapshot.vault_root is not None else None
            )
            chunk_reference = (
                base_snapshot.vault_root.chunk_index
                if base_snapshot.vault_root is not None else None
            )
            imported_refs: list[ObjectRef] = []
            object_records, chunk_records, old_object_pages, old_chunk_pages = (
                self._read_all_object_records(base_snapshot)
            )
            existing_keys = {record.key for record in object_records}
            if object_imports:
                if any(key in existing_keys for key in keys):
                    raise ValueError("object generation already exists")
                for request in object_imports:
                    imported = import_object_from(
                        request.stream,
                        request.expected_size,
                        self._header.vault_id,
                        request.object_id,
                        request.generation,
                        request.kind,
                        bytes(self._attachment_root_key),
                        lambda block: self._append_object_block(transaction, block),
                    )
                    object_records = tuple(sorted(
                        object_records + (imported.object_record,), key=lambda record: record.key
                    ))
                    chunk_records = tuple(sorted(
                        chunk_records + imported.chunk_records, key=lambda record: record.key
                    ))
                    imported_refs.append(ObjectRef(
                        request.object_id,
                        request.generation,
                        request.kind,
                        imported.manifest.total_size,
                        bytes(imported.manifest.sha256),
                    ))
            content = prepare(tuple(imported_refs))
            if not isinstance(content, MutationContent):
                raise TypeError("prepare must return MutationContent")
            prepared = self._normalize_entries(content.entries)
            normalized_metadata = self._normalize_metadata(content.metadata, prepared)
            stored_entries = tuple(sorted(prepared, key=lambda item: str(item.entry_id)))
            from .pmv_media_ref import scan as scan_media_refs, scan_value as scan_media_value
            media_occurrences = []
            for entry in stored_entries:
                occurrences = (
                    scan_media_refs(entry.source)
                    if isinstance(entry.source, Entry)
                    else scan_media_value(entry.source.get("fields", {}), "/fields")
                )
                media_occurrences.extend(occurrences)
            media_occurrences.extend(scan_media_value(normalized_metadata))
            from .pmv_media_ref import Classification as MediaClassification
            if enforce_object_closure and any(
                item.classification in (MediaClassification.LEGACY_EXTERNAL, MediaClassification.INLINE)
                for item in media_occurrences
            ):
                raise ValueError("final Entries/metadata may not use external paths or inline media as authority")
            referenced_keys = {
                ObjectKey(item.ref.object_id, item.ref.generation)
                for item in media_occurrences if item.ref is not None
            }
            available_keys = {record.key for record in object_records}
            if enforce_object_closure:
                if not referenced_keys.issubset(available_keys):
                    raise ValueError("final Entries/metadata contain a dangling PMV ObjectRef")
                if not set(keys).issubset(referenced_keys):
                    raise ValueError("mutation imported an orphan object not referenced by final state")
                object_records = tuple(record for record in object_records if record.key in referenced_keys)
                chunk_records = tuple(
                    record for record in chunk_records
                    if ObjectKey(record.key.object_id, record.key.generation) in referenced_keys
                )
            roots_changed = bool(object_imports) or len(object_records) != len(existing_keys)
            if enforce_object_closure and not object_records:
                object_reference = None
                chunk_reference = None
            elif roots_changed:
                object_reference, chunk_reference = self._write_object_indexes(
                    transaction,
                    revision,
                    object_records,
                    chunk_records,
                    old_object_pages,
                    old_chunk_pages,
                )
            entry_records: list[EntryIndexRecord] = []
            for item in stored_entries:
                entry_key = bytearray(
                    derive_entry_generation_key(
                        bytes(self._entry_root_key), item.entry_id, revision
                    )
                )
                try:
                    block = seal(
                        self._header.vault_id,
                        entry_key,
                        BlockType.ENTRY,
                        item.entry_id,
                        revision,
                        item.encoded,
                        codec_id=choose_codec(item.encoded),
                    )
                finally:
                    entry_key[:] = bytes(len(entry_key))
                reference = transaction.append_block(block)
                entry_records.append(
                    EntryIndexRecord(
                        entry_id=item.entry_id,
                        entry_type=item.entry_type,
                        revision=revision,
                        offset=reference.offset,
                        length=reference.length,
                        state=EntryIndexState.ACTIVE,
                        display_title=item.title,
                        favorite=item.favorite,
                        icon_object_id=item.icon_object_id,
                        modified_at_epoch_millis=item.modified_at_millis,
                        content_digest=encrypted_block_digest(block),
                    )
                )

            purge_values = normalized_metadata.get("purge_tombstones", {})
            if not isinstance(purge_values, Mapping):
                raise ValueError("purge_tombstones must be a JSON object")
            active_ids = {item.entry_id for item in stored_entries}
            previous_records = {record.entry_id: record for record in self._reader().all_records()}
            for raw_id, raw_timestamp in purge_values.items():
                entry_id = uuid.UUID(raw_id)
                if entry_id in active_ids:
                    raise ValueError("Entry and purge_tombstones may not overlap")
                if (isinstance(raw_timestamp, bool) or not isinstance(raw_timestamp, (int, float))
                        or not math.isfinite(float(raw_timestamp)) or raw_timestamp < 0):
                    raise ValueError("purge tombstone timestamp must be a non-negative finite number")
                purged_at = min(int(float(raw_timestamp) * 1000), _MAX_WIRE_LONG)
                previous = previous_records.get(entry_id)
                tombstone_plain = encode_tombstone(Tombstone(
                    entry_id,
                    revision,
                    purged_at,
                    previous.content_digest if previous is not None else bytes(32),
                ))
                tombstone_key = bytearray(derive_entry_generation_key(
                    bytes(self._entry_root_key), entry_id, revision
                ))
                try:
                    tombstone_block = seal(
                        self._header.vault_id,
                        tombstone_key,
                        BlockType.TOMBSTONE,
                        entry_id,
                        revision,
                        tombstone_plain,
                    )
                finally:
                    tombstone_key[:] = bytes(len(tombstone_key))
                    tombstone_plain = b""
                tombstone_ref = transaction.append_block(tombstone_block)
                entry_records.append(EntryIndexRecord(
                    entry_id=entry_id,
                    entry_type=previous.entry_type if previous is not None else "tombstone",
                    revision=revision,
                    offset=tombstone_ref.offset,
                    length=tombstone_ref.length,
                    state=EntryIndexState.TOMBSTONE,
                    modified_at_epoch_millis=purged_at,
                    content_digest=encrypted_block_digest(tombstone_block),
                ))

            metadata_plain = encode_metadata(normalized_metadata)
            metadata_block_key = bytearray(
                derive_metadata_block_key(
                    bytes(self._metadata_key), self._header.vault_id, revision
                )
            )
            try:
                metadata_block = seal(
                    self._header.vault_id,
                    metadata_block_key,
                    BlockType.OBJECT_METADATA,
                    self._header.vault_id,
                    revision,
                    metadata_plain,
                    codec_id=choose_codec(metadata_plain),
                )
            finally:
                metadata_block_key[:] = bytes(len(metadata_block_key))
            metadata_reference = transaction.append_block(metadata_block)
            metadata_plain = b""

            login_reference: RootReference | None = None
            login_pages = build_login_pages(self._login_records(stored_entries))
            if login_pages:
                login_locations: list[LoginPageLocation] = []
                for page in login_pages:
                    page_id = uuid.uuid4()
                    page_key = bytearray(
                        derive_index_page_key(
                            bytes(self._index_key),
                            page_id,
                            revision,
                            IndexPageType.LOGIN_INDEX,
                        )
                    )
                    try:
                        page_block = seal(
                            self._header.vault_id,
                            page_key,
                            BlockType.LOGIN_INDEX,
                            page_id,
                            revision,
                            encode_login_page(page),
                        )
                    finally:
                        page_key[:] = bytes(len(page_key))
                    page_ref = transaction.append_block(page_block)
                    login_locations.append(LoginPageLocation(page_ref.offset, page_ref.length))
                login_root = build_login_root(login_pages, login_locations)
                login_root_id = uuid.uuid4()
                login_root_key = bytearray(
                    derive_index_page_key(
                        bytes(self._index_key),
                        login_root_id,
                        revision,
                        IndexPageType.LOGIN_INDEX,
                    )
                )
                try:
                    login_root_block = seal(
                        self._header.vault_id,
                        login_root_key,
                        BlockType.LOGIN_INDEX,
                        login_root_id,
                        revision,
                        encode_login_root(login_root),
                    )
                finally:
                    login_root_key[:] = bytes(len(login_root_key))
                login_root_ref = transaction.append_block(login_root_block)
                login_reference = RootReference(
                    RootType.LOGIN,
                    login_root_ref.offset,
                    login_root_ref.length,
                    login_root_digest(login_root),
                )

            entry_root_records: list[EntryIndexRootRecord] = []
            for page in self._entry_pages(entry_records):
                page_id = uuid.uuid4()
                page_key = bytearray(
                    derive_index_page_key(
                        bytes(self._index_key),
                        page_id,
                        revision,
                        IndexPageType.ENTRY_INDEX,
                    )
                )
                try:
                    page_block = seal(
                        self._header.vault_id,
                        page_key,
                        BlockType.INDEX_PAGE,
                        page_id,
                        revision,
                        encode_entry_index_page(page),
                    )
                finally:
                    page_key[:] = bytes(len(page_key))
                page_reference = transaction.append_block(page_block)
                entry_root_records.append(
                    EntryIndexRootRecord(
                        page.records[0].entry_id,
                        page.records[-1].entry_id,
                        page_reference.offset,
                        entry_page_digest(page),
                    )
                )

            entry_root = EntryIndexRoot(tuple(entry_root_records))
            entry_root_id = uuid.uuid4()
            entry_root_key = bytearray(
                derive_index_page_key(
                    bytes(self._index_key),
                    entry_root_id,
                    revision,
                    IndexPageType.ENTRY_INDEX,
                )
            )
            try:
                entry_root_block = seal(
                    self._header.vault_id,
                    entry_root_key,
                    BlockType.INDEX_PAGE,
                    entry_root_id,
                    revision,
                    encode_entry_index_root(entry_root),
                )
            finally:
                entry_root_key[:] = bytes(len(entry_root_key))
            entry_root_reference = transaction.append_block(entry_root_block)

            vault_root = VaultRoot(
                entry=RootReference(
                    RootType.ENTRY,
                    entry_root_reference.offset,
                    entry_root_reference.length,
                    entry_root_digest(entry_root),
                ),
                login=login_reference,
                object_index=object_reference,
                chunk_index=chunk_reference,
                metadata=RootReference(
                    RootType.METADATA,
                    metadata_reference.offset,
                    metadata_reference.length,
                    metadata_digest(normalized_metadata),
                ),
            )
            vault_root_id = uuid.uuid4()
            vault_root_key = bytearray(
                derive_index_page_key(
                    bytes(self._index_key),
                    vault_root_id,
                    revision,
                    IndexPageType.VAULT_ROOT,
                )
            )
            try:
                vault_root_block = seal(
                    self._header.vault_id,
                    vault_root_key,
                    BlockType.INDEX_PAGE,
                    vault_root_id,
                    revision,
                    PmvVaultRootCodec.encode(vault_root),
                )
            finally:
                vault_root_key[:] = bytes(len(vault_root_key))
            vault_root_reference = transaction.append_block(vault_root_block)

            commit_id = uuid.uuid4()
            unsigned = Commit(
                vault_id=self._header.vault_id,
                commit_id=commit_id,
                parent_commit_id=transaction.parent_commit_id,
                revision=revision,
                index_root_offset=vault_root_reference.offset,
                index_root_length=vault_root_reference.length,
                root_digest=PmvVaultRootCodec.logical_digest(vault_root),
                signing_public_key=bytes(32),
                signature=bytes(64),
            )
            signing_seed = bytearray(self._signing_seed)
            try:
                signing_key = Ed25519PrivateKey.from_private_bytes(bytes(signing_seed))
                signed = sign_commit(unsigned, signing_key)
            finally:
                signing_seed[:] = bytes(len(signing_seed))
            commit_key = bytearray(
                derive_commit_block_key(
                    bytes(self._integrity_key), signed.commit_id, signed.revision
                )
            )
            try:
                commit_block = seal(
                    self._header.vault_id,
                    commit_key,
                    BlockType.COMMIT,
                    signed.commit_id,
                    signed.revision,
                    encode_commit(signed),
                )
            finally:
                commit_key[:] = bytes(len(commit_key))
            transaction.publish(
                index_root_ref=vault_root_reference,
                encrypted_commit=commit_block,
                commit=signed,
                index_root_key=bytes(self._index_key),
                integrity_key=bytes(self._integrity_key),
                trusted_signing_public_key=self._header.signing_public_key,
            )

        self._refresh_identity()
        return MutationResult(self._identity, tuple(imported_refs))

    def rewrap_password(self, old_password_utf8: bytes, new_password_utf8: bytes) -> VaultIdentity:
        self._require_open()
        old_password = _exact_bytes(old_password_utf8, "old_password_utf8")
        new_password = _exact_bytes(new_password_utf8, "new_password_utf8")
        return self._replace_header(
            lambda raw: unlock_with_password(raw, old_password),
            lambda raw, revision: rewrap_header_password(
                raw, old_password, new_password, os.urandom(ARGON2_SALT_SIZE), revision
            ),
            lambda raw: unlock_with_password(raw, new_password),
            "old password or PMV header authentication failed",
        )

    def rewrap_password_profile(
        self,
        password_utf8: bytes,
        target_profile: PmvKdfProfile,
    ) -> VaultIdentity:
        self._require_open()
        password = _exact_bytes(password_utf8, "password_utf8")
        if not isinstance(target_profile, PmvKdfProfile):
            raise TypeError("target_profile must be PmvKdfProfile")
        return self._replace_header(
            lambda raw: unlock_with_password(raw, password),
            lambda raw, revision: rewrap_header_password(
                raw,
                password,
                password,
                os.urandom(ARGON2_SALT_SIZE),
                revision,
                target_parameters=target_profile.parameters,
            ),
            lambda raw: unlock_with_password(raw, password),
            "password or PMV header authentication failed",
        )

    def rotate_recovery(
        self, old_recovery_secret: bytes, new_recovery_secret: bytes
    ) -> VaultIdentity:
        self._require_open()
        old_secret = _exact_bytes(old_recovery_secret, "old_recovery_secret", _KEY_SIZE)
        new_secret = _exact_bytes(new_recovery_secret, "new_recovery_secret", _KEY_SIZE)
        return self._replace_header(
            lambda raw: unlock_with_recovery(raw, old_secret),
            lambda raw, revision: rewrap_header_recovery(
                raw, old_secret, new_secret, revision
            ),
            lambda raw: unlock_with_recovery(raw, new_secret),
            "old recovery secret or PMV header authentication failed",
        )

    def regenerate_recovery_key(
        self, password_utf8: bytes, new_recovery_secret: bytes
    ) -> VaultIdentity:
        """用主密码重新生成恢复密钥（无需旧恢复密钥）；旧恢复密钥立即失效。"""
        self._require_open()
        password = _exact_bytes(password_utf8, "password_utf8")
        secret = _exact_bytes(new_recovery_secret, "new_recovery_secret", _KEY_SIZE)
        return self._replace_header(
            lambda raw: unlock_with_password(raw, password),
            lambda raw, revision: rewrap_header_recovery_with_password(
                raw, password, secret, revision
            ),
            lambda raw: unlock_with_recovery(raw, secret),
            "password or PMV header authentication failed",
        )

    def reset_password_with_recovery(
        self, recovery_secret: bytes, new_password_utf8: bytes
    ) -> VaultIdentity:
        self._require_open()
        recovery = _exact_bytes(recovery_secret, "recovery_secret", _KEY_SIZE)
        new_password = _exact_bytes(new_password_utf8, "new_password_utf8")
        return self._replace_header(
            lambda raw: unlock_with_recovery(raw, recovery),
            lambda raw, revision: rewrap_header_password_with_recovery(
                raw, recovery, new_password, os.urandom(ARGON2_SALT_SIZE), revision
            ),
            lambda raw: unlock_with_password(raw, new_password),
            "recovery secret or PMV header authentication failed",
        )

    def adopt_header(self, raw: bytes) -> VaultIdentity:
        """Replace both header slots with an authenticated header from the same vault.

        用于分叉同步合并：当采用“本端（更新）密钥版本”时，合并文件的密码/恢复密钥
        槽必须替换为本端槽，否则合并后本端新主密码会失效、退回旧密码。被采纳的
        头部必须能认证当前提交链（同一 vault_id、同一根密钥、同一签名身份）。
        """
        self._require_open()
        source = _exact_bytes(raw, "header_raw", HEADER_SIZE)
        unlocked = unlock_with_root_key(source, bytes(self._vault_root_key))
        try:
            if unlocked.header.vault_id != self._header.vault_id:
                raise ValueError("adopted PMV header vault id does not match")
            if not self._unlocked_matches_current_head(unlocked):
                raise ValueError("adopted PMV header cannot authenticate the current head")
        finally:
            del unlocked
        process_lock = _process_lock(self.path)
        with process_lock, _exclusive_os_lock(self.path):
            with self.path.open("r+b", buffering=0) as stream:
                stream.seek(PRIMARY_OFFSET)
                _write_all(stream, source)
                stream.seek(SECONDARY_OFFSET)
                _write_all(stream, source)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent_directory(self.path)
        self._header = decode_header(source)
        self._header_slot = 0
        self._header_raw = source
        self._refresh_identity()
        return self._identity

    def _replace_header(self, unlocker, builder, reopener, failure_message: str) -> VaultIdentity:
        process_lock = _process_lock(self.path)
        with process_lock, _exclusive_os_lock(self.path):
            with self.path.open("r+b", buffering=0) as stream:
                slots = (
                    _read_exact(stream, PRIMARY_OFFSET, HEADER_SIZE),
                    _read_exact(stream, SECONDARY_OFFSET, HEADER_SIZE),
                )
                valid: list[tuple[int, bytes, UnlockedHeader]] = []
                for index, raw in enumerate(slots):
                    try:
                        unlocked = unlocker(raw)
                        if self._unlocked_matches_current_head(unlocked):
                            valid.append((index, raw, unlocked))
                    except (InvalidTag, OSError, TypeError, ValueError):
                        continue
                if not valid:
                    raise ValueError(failure_message)
                source_slot, source_raw, unlocked = max(
                    valid,
                    key=lambda item: (
                        item[2].header.header_revision,
                        item[2].header.key_revision,
                        item[0],
                    ),
                )
                updated = builder(source_raw, unlocked.header.header_revision + 1)
                target_slot = 1 - source_slot
                stream.seek(PRIMARY_OFFSET if target_slot == 0 else SECONDARY_OFFSET)
                _write_all(stream, updated)
                stream.flush()
                os.fsync(stream.fileno())
                # Once the new slot is durable, retire the old-credential slot.
                # A crash before this second fsync still leaves at least one
                # unlockable header; a successful return guarantees that the
                # the old credential is no longer accepted through a stale slot.
                stream.seek(PRIMARY_OFFSET if source_slot == 0 else SECONDARY_OFFSET)
                _write_all(stream, updated)
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_parent_directory(self.path)
        reopened = reopener(updated)
        self._header = reopened.header
        self._header_slot = target_slot
        self._header_raw = updated
        self._refresh_identity()
        return self._identity

    def _unlocked_matches_current_head(self, unlocked: UnlockedHeader) -> bool:
        if unlocked.header.vault_id != self._header.vault_id:
            return False
        if not hmac.compare_digest(unlocked.vault_root_key, bytes(self._vault_root_key)):
            return False
        if not hmac.compare_digest(
            unlocked.superblock_authentication_key, bytes(self._integrity_key)
        ):
            return False
        actual_public = (
            Ed25519PrivateKey.from_private_bytes(unlocked.signing_private_seed)
            .public_key()
            .public_bytes_raw()
        )
        if not hmac.compare_digest(actual_public, self._header.signing_public_key):
            return False
        roots = derive_root_keys(unlocked.vault_root_key, unlocked.header.vault_id)
        container = PmvAppendOnlyFile(self.path, unlocked.superblock_authentication_key)
        with self.path.open("rb") as stream:
            for candidate in container.candidate_states():
                try:
                    snapshot = authenticate_snapshot(
                        stream,
                        candidate,
                        vault_id=unlocked.header.vault_id,
                        integrity_key=roots.integrity_key,
                        index_root_key=roots.index_key,
                        trusted_signing_public_key=unlocked.header.signing_public_key,
                    )
                except (InvalidTag, OSError, TypeError, ValueError):
                    continue
                commit = snapshot.commit
                return (
                    snapshot.state.superblock.sequence == self._identity.sequence
                    and (commit.commit_id if commit else None) == self._identity.commit_id
                    and (commit.root_digest if commit else None) == self._identity.root_digest
                )
        return False

    def close(self) -> None:
        if self._closed:
            return
        for buffer in self._secret_buffers_for_test():
            buffer[:] = bytes(len(buffer))
        self._container._authentication_key = bytes(_KEY_SIZE)
        self._header_raw = b""
        self._closed = True

    def __enter__(self) -> "PmvVaultStore":
        self._require_open()
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()

    def _reader(self) -> PmvEntryReader:
        return PmvEntryReader(
            self._container,
            vault_id=self._header.vault_id,
            integrity_key=bytes(self._integrity_key),
            index_root_key=bytes(self._index_key),
            trusted_signing_public_key=self._header.signing_public_key,
            entry_root_key=bytes(self._entry_root_key),
        )

    @staticmethod
    def _entry_pages(records: Iterable[EntryIndexRecord]) -> tuple[EntryIndexPage, ...]:
        ordered = sorted(records, key=lambda record: str(record.entry_id))
        pages: list[EntryIndexPage] = []
        current: list[EntryIndexRecord] = []
        for record in ordered:
            candidate = current + [record]
            try:
                encode_entry_index_page(EntryIndexPage(tuple(candidate)))
            except ValueError:
                if not current:
                    raise ValueError("entry-index record cannot fit in a PMEI page")
                pages.append(EntryIndexPage(tuple(current)))
                current = [record]
                encode_entry_index_page(EntryIndexPage(tuple(current)))
            else:
                current = candidate
        if current:
            pages.append(EntryIndexPage(tuple(current)))
        return tuple(pages)

    def _latest_authenticated_snapshot(self) -> AuthenticatedSnapshot:
        for snapshot in self._authenticated_snapshots():
            return snapshot
        raise ValueError("no authenticated PMV snapshot")

    def _reject_decryptable_newest_signer_mismatch(self) -> None:
        """Reject a Header whose RootKey opens the head but whose signer differs.

        Corrupt Commit ciphertext is left to normal dual-Superblock recovery.  A
        successfully decrypted Commit, however, gives an unambiguous signing
        identity and must never be downgraded to an older/empty snapshot.
        """

        newest = self._container.candidate_states()[0]
        if newest.superblock.sequence == 0:
            return
        block = self._container.read_block(
            newest, newest.superblock.latest_commit_offset, BlockType.COMMIT
        )
        key = bytearray(
            derive_commit_block_key(
                bytes(self._integrity_key), block.header.object_id, block.header.object_revision
            )
        )
        try:
            try:
                plaintext = open_block(self._header.vault_id, key, block)
            except InvalidTag:
                return
        finally:
            key[:] = bytes(len(key))
        try:
            commit = decode_commit(plaintext)
        finally:
            plaintext = b""
        if not hmac.compare_digest(commit.signing_public_key, self._header.signing_public_key):
            raise ValueError("PMV header signing identity does not match the newest commit")

    def _snapshot_for_sequence(self, expected_sequence: int) -> AuthenticatedSnapshot:
        if type(expected_sequence) is not int or not 0 <= expected_sequence <= _MAX_WIRE_LONG:
            raise ValueError("expected_sequence must be between 0 and 2^63 - 1")
        for snapshot in self._authenticated_snapshots():
            sequence = snapshot.state.superblock.sequence
            if sequence == expected_sequence:
                return snapshot
            if sequence < expected_sequence:
                break
        raise ValueError("write transaction base sequence is stale")

    def _entries_for_snapshot(
        self,
        snapshot: AuthenticatedSnapshot,
        metadata: Mapping[str, object],
    ) -> tuple[Entry, ...]:
        reader = self._reader()
        decoded: dict[uuid.UUID, Entry] = {}
        for directory in snapshot.root.records:
            page = reader._read_leaf(snapshot, directory)
            for record in page.records:
                if record.state is not EntryIndexState.ACTIVE:
                    continue
                plaintext = reader._read_entry(snapshot, record)
                decoded[record.entry_id] = decode_entry(
                    plaintext, expected_entry_id=record.entry_id
                )
                plaintext = b""
        raw_order = metadata.get("entry_order", [])
        raw_trash = metadata.get("trash_order", [])
        if not isinstance(raw_order, list) or not isinstance(raw_trash, list):
            raise ValueError("metadata entry order is invalid")
        ordered = tuple(uuid.UUID(value) for value in raw_order + raw_trash)
        if len(ordered) != len(decoded) or set(ordered) != set(decoded):
            raise ValueError("metadata entry order does not match the entry index")
        return tuple(decoded[entry_id] for entry_id in ordered)

    @staticmethod
    def _append_object_block(transaction, block: EncodedBlock) -> StoredBlock:
        reference = transaction.append_block(block)
        return StoredBlock(reference.offset, reference.length)

    def _open_index_plaintext(
        self,
        snapshot: AuthenticatedSnapshot,
        offset: int,
        page_type: IndexPageType,
        expected_length: int | None = None,
    ) -> bytes:
        if snapshot.commit is None:
            raise ValueError("object index has no authenticated commit")
        block = self._container.read_block(snapshot.state, offset, BlockType.INDEX_PAGE)
        if expected_length is not None and _block_length(block) != expected_length:
            raise ValueError("object index block length does not match its root reference")
        if not 0 < block.header.object_revision <= snapshot.commit.revision:
            raise ValueError("object index block revision is outside the authenticated lineage")
        if block.header.chunk_index != -1 or block.header.flags != 0:
            raise ValueError("object index block has a non-canonical role")
        key = bytearray(
            derive_index_page_key(
                bytes(self._index_key),
                block.header.object_id,
                block.header.object_revision,
                page_type,
            )
        )
        try:
            return open_block(self._header.vault_id, key, block)
        finally:
            key[:] = bytes(len(key))

    def _read_object_root(
        self, snapshot: AuthenticatedSnapshot
    ) -> RangeRoot[ObjectKey] | None:
        reference = snapshot.vault_root.object_index if snapshot.vault_root else None
        if reference is None:
            return None
        plaintext = self._open_index_plaintext(
            snapshot, reference.offset, IndexPageType.OBJECT_INDEX, reference.length
        )
        try:
            root = decode_object_root(plaintext)
        finally:
            plaintext = b""
        if object_root_digest(root) != reference.digest:
            raise ValueError("ObjectIndex root digest does not match the vault root")
        return root

    def _read_chunk_root(
        self, snapshot: AuthenticatedSnapshot
    ) -> RangeRoot[ChunkKey] | None:
        reference = snapshot.vault_root.chunk_index if snapshot.vault_root else None
        if reference is None:
            return None
        plaintext = self._open_index_plaintext(
            snapshot, reference.offset, IndexPageType.CHUNK_INDEX, reference.length
        )
        try:
            root = decode_chunk_root(plaintext)
        finally:
            plaintext = b""
        if chunk_root_digest(root) != reference.digest:
            raise ValueError("ChunkIndex root digest does not match the vault root")
        return root

    def _read_object_page(
        self, snapshot: AuthenticatedSnapshot, selected: RangeRecord[ObjectKey]
    ) -> ObjectPage:
        plaintext = self._open_index_plaintext(
            snapshot, selected.page_offset, IndexPageType.OBJECT_INDEX
        )
        try:
            page = decode_object_page(plaintext)
        finally:
            plaintext = b""
        if not page.records:
            raise ValueError("ObjectIndex root references an empty page")
        if page.records[0].key != selected.min_key or page.records[-1].key != selected.max_key:
            raise ValueError("ObjectIndex page range does not match its root")
        if object_page_digest(page) != selected.page_digest:
            raise ValueError("ObjectIndex page digest does not match its root")
        return page

    def _read_chunk_page(
        self, snapshot: AuthenticatedSnapshot, selected: RangeRecord[ChunkKey]
    ) -> ChunkPage:
        plaintext = self._open_index_plaintext(
            snapshot, selected.page_offset, IndexPageType.CHUNK_INDEX
        )
        try:
            page = decode_chunk_page(plaintext)
        finally:
            plaintext = b""
        if not page.records:
            raise ValueError("ChunkIndex root references an empty page")
        if page.records[0].key != selected.min_key or page.records[-1].key != selected.max_key:
            raise ValueError("ChunkIndex page range does not match its root")
        if chunk_page_digest(page) != selected.page_digest:
            raise ValueError("ChunkIndex page digest does not match its root")
        return page

    def _read_all_object_records(
        self, snapshot: AuthenticatedSnapshot
    ) -> tuple[
        tuple[ObjectRecord, ...],
        tuple[ChunkRecord, ...],
        tuple[ExistingPage[ObjectKey], ...],
        tuple[ExistingPage[ChunkKey], ...],
    ]:
        object_root = self._read_object_root(snapshot)
        chunk_root = self._read_chunk_root(snapshot)
        if object_root is None:
            if chunk_root is not None:
                raise ValueError("ChunkIndex exists without an ObjectIndex")
            return (), (), (), ()
        objects: list[ObjectRecord] = []
        object_pages: list[ExistingPage[ObjectKey]] = []
        for selected in object_root.records:
            page = self._read_object_page(snapshot, selected)
            objects.extend(page.records)
            object_pages.append(
                ExistingPage(
                    selected.min_key,
                    selected.max_key,
                    selected.page_offset,
                    selected.page_digest,
                )
            )
        chunks: list[ChunkRecord] = []
        chunk_pages: list[ExistingPage[ChunkKey]] = []
        if chunk_root is not None:
            for selected in chunk_root.records:
                page = self._read_chunk_page(snapshot, selected)
                chunks.extend(page.records)
                chunk_pages.append(
                    ExistingPage(
                        selected.min_key,
                        selected.max_key,
                        selected.page_offset,
                        selected.page_digest,
                    )
                )
        return tuple(objects), tuple(chunks), tuple(object_pages), tuple(chunk_pages)

    def _write_object_indexes(
        self,
        transaction,
        revision: int,
        object_records: Sequence[ObjectRecord],
        chunk_records: Sequence[ChunkRecord],
        old_object_pages: Sequence[ExistingPage[ObjectKey]],
        old_chunk_pages: Sequence[ExistingPage[ChunkKey]],
    ) -> tuple[RootReference, RootReference | None]:
        object_ranges: list[RangeRecord[ObjectKey]] = []
        for planned in plan_object_pages(object_records, old_object_pages):
            page = planned.page
            if planned.reused_offset is None:
                page_reference = self._append_index_page(
                    transaction,
                    revision,
                    IndexPageType.OBJECT_INDEX,
                    encode_object_page(page),
                )
                offset = page_reference.offset
            else:
                offset = planned.reused_offset
            object_ranges.append(
                RangeRecord(page.records[0].key, page.records[-1].key, offset, planned.digest)
            )
        object_root = RangeRoot(tuple(object_ranges))
        object_root_block = self._append_index_page(
            transaction,
            revision,
            IndexPageType.OBJECT_INDEX,
            encode_object_root(object_root),
        )
        object_reference = RootReference(
            RootType.OBJECT,
            object_root_block.offset,
            object_root_block.length,
            object_root_digest(object_root),
        )

        if not chunk_records:
            return object_reference, None
        chunk_ranges: list[RangeRecord[ChunkKey]] = []
        for planned in plan_chunk_pages(chunk_records, old_chunk_pages):
            page = planned.page
            if planned.reused_offset is None:
                page_reference = self._append_index_page(
                    transaction,
                    revision,
                    IndexPageType.CHUNK_INDEX,
                    encode_chunk_page(page),
                )
                offset = page_reference.offset
            else:
                offset = planned.reused_offset
            chunk_ranges.append(
                RangeRecord(page.records[0].key, page.records[-1].key, offset, planned.digest)
            )
        chunk_root = RangeRoot(tuple(chunk_ranges))
        chunk_root_block = self._append_index_page(
            transaction,
            revision,
            IndexPageType.CHUNK_INDEX,
            encode_chunk_root(chunk_root),
        )
        chunk_reference = RootReference(
            RootType.CHUNK,
            chunk_root_block.offset,
            chunk_root_block.length,
            chunk_root_digest(chunk_root),
        )
        return object_reference, chunk_reference

    def _append_index_page(
        self,
        transaction,
        revision: int,
        page_type: IndexPageType,
        plaintext: bytes,
    ):
        page_id = uuid.uuid4()
        key = bytearray(
            derive_index_page_key(bytes(self._index_key), page_id, revision, page_type)
        )
        try:
            block = seal(
                self._header.vault_id,
                key,
                BlockType.INDEX_PAGE,
                page_id,
                revision,
                plaintext,
            )
        finally:
            key[:] = bytes(len(key))
        return transaction.append_block(block)

    def _object_read_context(
        self, snapshot: AuthenticatedSnapshot, key: ObjectKey
    ) -> tuple[ObjectRecord, RangeRoot[ChunkKey] | None]:
        root = self._read_object_root(snapshot)
        if root is None:
            raise ValueError("object generation does not exist")
        selected = root.find_page(key)
        if selected is None:
            raise ValueError("object generation does not exist")
        record = self._read_object_page(snapshot, selected).find(key)
        if record is None:
            raise ValueError("object generation does not exist")
        return record, self._read_chunk_root(snapshot)

    def _snapshot_block_reader(self, snapshot: AuthenticatedSnapshot):
        def read(offset: int, length: int) -> EncodedBlock:
            block = self._container.read_block(snapshot.state, offset)
            if _block_length(block) != length:
                raise ValueError("object block length does not match its index record")
            return block

        return read

    def _chunk_finder(
        self,
        snapshot: AuthenticatedSnapshot,
        root: RangeRoot[ChunkKey] | None,
    ):
        pages: dict[int, ChunkPage] = {}

        def find(key: ChunkKey) -> ChunkRecord | None:
            if root is None:
                return None
            selected = root.find_page(key)
            if selected is None:
                return None
            page = pages.get(selected.page_offset)
            if page is None:
                page = self._read_chunk_page(snapshot, selected)
                pages[selected.page_offset] = page
            return page.find(key)

        return find

    def _normalize_entries(
        self, entries: Iterable[Entry | Mapping[str, object]]
    ) -> tuple[_EntryInput, ...]:
        if isinstance(entries, (bytes, str, Mapping)):
            raise TypeError("entries must be an iterable of Entry or mapping values")
        result: list[_EntryInput] = []
        seen: set[uuid.UUID] = set()
        for source in entries:
            if not isinstance(source, (Entry, Mapping)):
                raise TypeError("entry must be an Entry or mapping")
            get = source.get if isinstance(source, Mapping) else lambda key, default=None: getattr(source, key, default)
            raw_id = get("id")
            if not isinstance(raw_id, str):
                raise ValueError("Entry ID must be a canonical UUID string")
            try:
                entry_id = uuid.UUID(raw_id)
            except ValueError as error:
                raise ValueError("Entry ID must be a canonical UUID string") from error
            if str(entry_id) != raw_id:
                raise ValueError("Entry ID must use canonical lowercase UUID representation")
            if entry_id in seen:
                raise ValueError("entries contain a duplicate Entry ID")
            seen.add(entry_id)
            encoded = encode_entry(source)
            fields = get("fields", {})
            if not isinstance(fields, Mapping):
                fields = {}
            favorite = get("favorite", fields.get("favorite", False))
            if type(favorite) is not bool:
                favorite = False
            icon_value = get("icon_object_id", fields.get("icon_object_id"))
            try:
                icon_id = uuid.UUID(icon_value) if isinstance(icon_value, str) else None
            except ValueError:
                icon_id = None
            updated = get("updated_at", 0)
            if isinstance(updated, bool) or not isinstance(updated, (int, float)):
                raise ValueError("Entry updated_at must be a finite JSON number")
            numeric_updated = float(updated)
            if not numeric_updated > 0:
                modified = 0
            elif numeric_updated >= _MAX_WIRE_LONG / 1000:
                modified = _MAX_WIRE_LONG
            else:
                modified = int(numeric_updated * 1000)
            entry_type = get("secret_type", "login")
            title = get("title", "")
            if not isinstance(entry_type, str) or not entry_type:
                raise ValueError("Entry secret_type must be a non-empty string")
            if not isinstance(title, str):
                raise ValueError("Entry title must be a string")
            result.append(
                _EntryInput(
                    entry_id=entry_id,
                    encoded=encoded,
                    entry_type=entry_type,
                    title=title,
                    favorite=favorite,
                    icon_object_id=icon_id,
                    modified_at_millis=modified,
                    deleted=get("deleted_at") is not None,
                    source=source,
                )
            )
        return tuple(result)

    def _normalize_metadata(
        self,
        metadata: Mapping[str, object],
        entries: Sequence[_EntryInput],
    ) -> dict[str, object]:
        if not isinstance(metadata, Mapping):
            raise TypeError("metadata must be a mapping")
        value = copy.deepcopy(dict(metadata))
        value["vault_id"] = str(self._header.vault_id)
        value["key_revision"] = self._header.key_revision
        value["entry_order"] = [str(item.entry_id) for item in entries if not item.deleted]
        value["trash_order"] = [str(item.entry_id) for item in entries if item.deleted]
        # Validate before any transaction starts, so malformed metadata never
        # creates an append tail that needs recovery.
        encode_metadata(value)
        return value

    def _login_records(self, entries: Sequence[_EntryInput]) -> tuple[LoginRecord, ...]:
        records: dict[tuple[int, bytes, bytes], LoginRecord] = {}
        search_key = bytes(self._search_index_key)
        for item in entries:
            if item.deleted:
                continue
            source = item.source
            get = source.get if isinstance(source, Mapping) else lambda key, default=None: getattr(source, key, default)
            tokens: list[tuple[LookupKind, bytes, LoginEntryType]] = []
            if item.entry_type == "login":
                fields = get("fields", {})
                url_values: list[str] = []
                raw_url = get("url", "")
                if isinstance(raw_url, str):
                    url_values.append(raw_url)
                if isinstance(fields, Mapping):
                    origin = fields.get("_autofill_origin")
                    if isinstance(origin, Mapping) and origin.get("kind") == "web":
                        host_value = origin.get("host")
                        if isinstance(host_value, str):
                            url_values.append(host_value)
                    modules = fields.get("modules")
                    if isinstance(modules, list):
                        for module in modules:
                            if not isinstance(module, Mapping):
                                continue
                            value = module.get("value")
                            if isinstance(value, Mapping):
                                module_url = value.get("url")
                                if isinstance(module_url, str):
                                    url_values.append(module_url)
                for host in dict.fromkeys(filter(None, (self._domain_from_url(raw) for raw in url_values))):
                    try:
                        tokens.append((LookupKind.DOMAIN, domain_token(search_key, host), LoginEntryType.LOGIN))
                    except ValueError:
                        pass
                package_values: list[str] = []
                for raw in (get("target_app", ""), raw_url):
                    if isinstance(raw, str):
                        package_values.append(raw)
                if isinstance(fields, Mapping):
                    origin = fields.get("_autofill_origin")
                    if isinstance(origin, Mapping) and origin.get("kind") == "android":
                        package_value = origin.get("package")
                        if isinstance(package_value, str):
                            package_values.append(package_value)
                    modules = fields.get("modules")
                    if isinstance(modules, list):
                        for module in modules:
                            if not isinstance(module, Mapping):
                                continue
                            value = module.get("value")
                            if isinstance(value, Mapping):
                                package_value = value.get("target_app")
                                if isinstance(package_value, str):
                                    package_values.append(package_value)
                for target_app in dict.fromkeys(package_values):
                    try:
                        tokens.append((LookupKind.PACKAGE, package_token(search_key, target_app), LoginEntryType.LOGIN))
                    except ValueError:
                        pass
            fields = get("fields", {})
            rp_ids: list[str] = []
            if isinstance(fields, Mapping):
                legacy_rp_id = fields.get("rp_id")
                if (item.entry_type == "passkey" and isinstance(legacy_rp_id, str)
                        and legacy_rp_id.strip()):
                    rp_ids.append(legacy_rp_id.strip())
                modules = fields.get("modules")
                if isinstance(modules, list):
                    for module in modules:
                        if not isinstance(module, Mapping) or module.get("type") != "passkey":
                            continue
                        value = module.get("value")
                        if not isinstance(value, dict):
                            continue
                        from .passkeys import parse_record
                        try:
                            parsed = parse_record(value)
                        except ValueError:
                            continue
                        rp_ids.append(parsed.rp_id)
            for rp_id in dict.fromkeys(rp_ids):
                try:
                    tokens.append((LookupKind.RP_ID, rp_id_token(search_key, rp_id), LoginEntryType.PASSKEY))
                except ValueError:
                    pass
            for kind, token, entry_type in tokens:
                record = LoginRecord(
                    item.entry_id,
                    entry_type,
                    LoginState.ACTIVE,
                    kind,
                    token,
                )
                records[(int(kind), token, item.entry_id.bytes)] = record
        return tuple(records[key] for key in sorted(records))

    @staticmethod
    def _domain_from_url(raw: str) -> str | None:
        value = raw.strip()
        if not value:
            return None
        scheme_match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*):", value)
        explicit_scheme = "//" in value or (
            scheme_match is not None
            and scheme_match.group(1).lower()
            in {"data", "file", "javascript", "mailto", "tel", "urn"}
        )
        candidates = (value,) if explicit_scheme else (value, f"https://{value}")
        for candidate in candidates:
            try:
                parsed = urlsplit(candidate)
                host = parsed.hostname
                # Accessing port rejects malformed/non-numeric/out-of-range ports.
                parsed.port
            except (TypeError, ValueError):
                continue
            if host:
                return host
        return None

    def _authenticated_snapshots(self) -> Iterator[AuthenticatedSnapshot]:
        with self.path.open("rb") as stream:
            for candidate in self._container.candidate_states():
                try:
                    yield authenticate_snapshot(
                        stream,
                        candidate,
                        vault_id=self._header.vault_id,
                        integrity_key=bytes(self._integrity_key),
                        index_root_key=bytes(self._index_key),
                        trusted_signing_public_key=self._header.signing_public_key,
                    )
                except (InvalidTag, OSError, TypeError, ValueError):
                    continue

    def _read_metadata(self, snapshot: AuthenticatedSnapshot) -> dict[str, object]:
        if snapshot.commit is None or snapshot.vault_root is None:
            raise ValueError("initial PMV snapshot has no metadata")
        reference = snapshot.vault_root.metadata
        if reference is None:
            raise ValueError("PMV vault root omits metadata")
        block = self._container.read_block(
            snapshot.state, reference.offset, BlockType.OBJECT_METADATA
        )
        if block.header.object_id != self._header.vault_id:
            raise ValueError("metadata block object ID does not match the vault")
        if block.header.object_revision != snapshot.commit.revision:
            raise ValueError("metadata block revision does not match the commit")
        if _block_length(block) != reference.length:
            raise ValueError("metadata block length does not match the vault root")
        metadata_block_key = bytearray(
            derive_metadata_block_key(
                bytes(self._metadata_key), block.header.object_id, block.header.object_revision
            )
        )
        try:
            plaintext = open_block(self._header.vault_id, metadata_block_key, block)
        finally:
            metadata_block_key[:] = bytes(len(metadata_block_key))
        try:
            decoded = decode_metadata(plaintext, self._header.vault_id)
            if metadata_digest(decoded) != reference.digest:
                raise ValueError("metadata logical digest does not match the vault root")
            return decoded
        finally:
            plaintext = b""

    def _query_login(self, kind: LookupKind, token: bytes) -> tuple[uuid.UUID, ...]:
        snapshot = self._latest_authenticated_snapshot()
        try:
            root = self._read_login_root(snapshot)
            if root is None:
                return ()
            return tuple(
                query_login_root(
                    root,
                    kind,
                    token,
                    lambda selected: self._read_login_page(snapshot, selected),
                )
            )
        except (InvalidTag, OSError, TypeError, ValueError) as error:
            raise ValueError("latest authenticated PMV login-index is damaged") from error

    def _read_login_root(self, snapshot: AuthenticatedSnapshot) -> LoginRoot | None:
        if snapshot.commit is None or snapshot.vault_root is None:
            return None
        reference = snapshot.vault_root.login
        if reference is None:
            return None
        block = self._container.read_block(
            snapshot.state, reference.offset, BlockType.LOGIN_INDEX
        )
        if block.header.object_revision != snapshot.commit.revision:
            raise ValueError("login root revision does not match the commit")
        if _block_length(block) != reference.length:
            raise ValueError("login root length does not match the vault root")
        key = bytearray(
            derive_index_page_key(
                bytes(self._index_key),
                block.header.object_id,
                block.header.object_revision,
                IndexPageType.LOGIN_INDEX,
            )
        )
        try:
            plaintext = open_block(self._header.vault_id, key, block)
        finally:
            key[:] = bytes(len(key))
        try:
            root = decode_login_root(plaintext)
        finally:
            plaintext = b""
        if login_root_digest(root) != reference.digest:
            raise ValueError("login logical root digest does not match the vault root")
        return root

    def _read_login_page(
        self,
        snapshot: AuthenticatedSnapshot,
        selected: LoginPageRange,
    ) -> LoginPage:
        if snapshot.commit is None:
            raise ValueError("login leaf has no authenticated commit")
        block = self._container.read_block(
            snapshot.state, selected.page_offset, BlockType.LOGIN_INDEX
        )
        if block.header.object_revision != snapshot.commit.revision:
            raise ValueError("login leaf revision does not match the commit")
        if _block_length(block) != selected.page_length:
            raise ValueError("login leaf length does not match its root range")
        key = bytearray(
            derive_index_page_key(
                bytes(self._index_key),
                block.header.object_id,
                block.header.object_revision,
                IndexPageType.LOGIN_INDEX,
            )
        )
        try:
            plaintext = open_block(self._header.vault_id, key, block)
        finally:
            key[:] = bytes(len(key))
        try:
            return decode_login_page(plaintext)
        finally:
            plaintext = b""

    def _refresh_identity(self) -> None:
        snapshot = self._latest_authenticated_snapshot()
        commit = snapshot.commit
        self._identity = VaultIdentity(
            vault_id=self._header.vault_id,
            signing_public_key=self._header.signing_public_key,
            key_revision=self._header.key_revision,
            header_revision=self._header.header_revision,
            sequence=snapshot.state.superblock.sequence,
            commit_id=commit.commit_id if commit else None,
            parent_commit_id=commit.parent_commit_id if commit else None,
            root_digest=commit.root_digest if commit else None,
        )

    def _require_open(self) -> None:
        if self._closed:
            raise ValueError("PMV vault session is closed")

    def _secret_buffers_for_test(self) -> Sequence[bytearray]:
        return (
            self._vault_root_key,
            self._signing_seed,
            self._metadata_key,
            self._entry_root_key,
            self._attachment_root_key,
            self._index_key,
            self._search_index_key,
            self._integrity_key,
            self._sync_auth_key,
            self._key_wrap_key,
        )

    def _entry_offset_for_test(self, entry_id: uuid.UUID) -> int:
        snapshot = self._reader().snapshot()
        directory = snapshot.root.find_page(entry_id)
        if directory is None:
            raise KeyError(entry_id)
        leaf = self._reader()._read_leaf(snapshot, directory)
        record = leaf.find(entry_id)
        if record is None:
            raise KeyError(entry_id)
        return record.offset


__all__ = ["PmvVaultStore", "VaultIdentity"]
