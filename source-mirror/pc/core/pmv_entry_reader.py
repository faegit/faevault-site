"""Authenticated, targeted entry reads from the append-only PMV container."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Callable, Iterable, TypeVar

from cryptography.exceptions import InvalidTag

from .pmv_append import (
    AuthenticatedSnapshot,
    PmvAppendOnlyFile,
    _validate_index_block_role,
    authenticate_snapshot,
)
from .pmv_container import BLOCK_HEADER_SIZE, BlockType, open as open_block
from .pmv_entry_index import (
    EntryIndexPage,
    EntryIndexRecord,
    EntryIndexRootRecord,
    EntryIndexState,
    decode_entry_index_page,
)
from .pmv_integrity import encrypted_block_digest, entry_page_digest
from .pmv_key_schedule import (
    IndexPageType,
    derive_entry_generation_key,
    derive_index_page_key,
)
from .pmv_tombstone import decode_tombstone


T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class EntrySummary:
    entry_id: uuid.UUID
    entry_type: str
    display_title: str
    favorite: bool
    icon_object_id: uuid.UUID | None
    modified_at_epoch_millis: int
    revision: int


@dataclass(frozen=True, slots=True)
class Cursor:
    sequence: int
    page_index: int


@dataclass(frozen=True, slots=True)
class ListPage:
    items: tuple[EntrySummary, ...]
    next_cursor: Cursor | None


class PmvEntryReader:
    """Resolve a trusted snapshot, then decrypt only its selected leaf/entry."""

    def __init__(
        self,
        container: PmvAppendOnlyFile,
        *,
        vault_id: uuid.UUID,
        integrity_key: bytes | None,
        index_root_key: bytes | None,
        trusted_signing_public_key: bytes,
        entry_root_key: bytes,
        commit_key: bytes | None = None,
        index_key: bytes | None = None,
        allow_legacy_static_keys: bool = False,
    ) -> None:
        if not isinstance(container, PmvAppendOnlyFile):
            raise TypeError("container must be a PmvAppendOnlyFile")
        if not isinstance(vault_id, uuid.UUID):
            raise TypeError("vault_id must be a UUID")
        self._container = container
        self._vault_id = vault_id
        self._integrity_key = (
            self._exact_key(integrity_key, "integrity_key")
            if integrity_key is not None else None
        )
        self._index_root_key = (
            self._exact_key(index_root_key, "index_root_key")
            if index_root_key is not None else None
        )
        self._commit_key = (
            self._exact_key(commit_key, "commit_key")
            if allow_legacy_static_keys and commit_key is not None else None
        )
        self._index_key = (
            self._exact_key(index_key, "index_key")
            if allow_legacy_static_keys and index_key is not None else None
        )
        self._allow_legacy_static_keys = allow_legacy_static_keys
        if self._integrity_key is None and self._commit_key is None:
            raise ValueError("integrity_key is required for production reads")
        if self._index_root_key is None and self._index_key is None:
            raise ValueError("index_root_key is required for production reads")
        self._trusted_key = self._exact_key(
            trusted_signing_public_key, "trusted_signing_public_key"
        )
        self._entry_root_key = self._exact_key(entry_root_key, "entry_root_key")

        # Fail construction if even the oldest authenticated slot is unusable.
        self._resolve_snapshot()

    def list_page(self, cursor: Cursor | None = None) -> ListPage:
        if cursor is not None and not isinstance(cursor, Cursor):
            raise TypeError("cursor must be a Cursor")
        last_error: Exception | None = None
        for snapshot in self._authenticated_candidates():
            sequence = snapshot.state.superblock.sequence
            if cursor is not None and cursor.sequence != sequence:
                # A first-page read can fall back from a damaged newest leaf to
                # an older authenticated snapshot.  Its cursor remains pinned
                # to that sequence, so skip other candidates until it is found.
                continue
            try:
                if cursor is not None and snapshot.commit is None:
                    raise ValueError("cursor cannot address the initial empty snapshot")
                if not snapshot.root.records:
                    return ListPage((), None)
                page_index = cursor.page_index if cursor is not None else 0
                if not 0 <= page_index < len(snapshot.root.records):
                    raise ValueError("cursor page is outside the entry-index root")
                leaf = self._read_leaf(snapshot, snapshot.root.records[page_index])
                items = tuple(
                    EntrySummary(
                        entry_id=record.entry_id,
                        entry_type=record.entry_type,
                        display_title=record.display_title,
                        favorite=record.favorite,
                        icon_object_id=record.icon_object_id,
                        modified_at_epoch_millis=record.modified_at_epoch_millis,
                        revision=record.revision,
                    )
                    for record in leaf.records
                    if record.state is EntryIndexState.ACTIVE
                )
                next_index = page_index + 1
                next_cursor = (
                    Cursor(sequence, next_index)
                    if next_index < len(snapshot.root.records)
                    else None
                )
                return ListPage(items, next_cursor)
            except (InvalidTag, OSError, TypeError, ValueError) as exc:
                last_error = exc
                if cursor is not None:
                    break
        if cursor is not None:
            raise ValueError("cursor belongs to another committed snapshot") from last_error
        raise ValueError("no fully authenticated entry-index page") from last_error

    def find(self, entry_id: uuid.UUID) -> bytes | None:
        if not isinstance(entry_id, uuid.UUID):
            raise TypeError("entry_id must be a UUID")
        last_error: Exception | None = None
        for snapshot in self._authenticated_candidates():
            try:
                directory = snapshot.root.find_page(entry_id)
                if directory is None:
                    return None
                record = self._read_leaf(snapshot, directory).find(entry_id)
            except (InvalidTag, OSError, TypeError, ValueError) as exc:
                last_error = exc
                continue
            if record is None:
                return None
            if record.state is EntryIndexState.TOMBSTONE:
                try:
                    self._read_tombstone(snapshot, record)
                except (InvalidTag, OSError, TypeError, ValueError) as exc:
                    raise ValueError("latest committed tombstone cannot be authenticated") from exc
                return None
            try:
                return self._read_entry(snapshot, record)
            except (InvalidTag, OSError, TypeError, ValueError) as exc:
                last_error = exc
        if last_error is not None:
            raise ValueError("no fully authenticated entry snapshot") from last_error
        return None

    def find_record(self, entry_id: uuid.UUID) -> EntryIndexRecord | None:
        if not isinstance(entry_id, uuid.UUID):
            raise TypeError("entry_id must be a UUID")
        snapshot = self._resolve_snapshot()
        directory = snapshot.root.find_page(entry_id)
        return None if directory is None else self._read_leaf(snapshot, directory).find(entry_id)

    def all_records(self) -> tuple[EntryIndexRecord, ...]:
        snapshot = self._resolve_snapshot()
        return tuple(
            record
            for directory in snapshot.root.records
            for record in self._read_leaf(snapshot, directory).records
        )

    def find_decoded(self, entry_id: uuid.UUID, decoder: Callable[[bytes], T]) -> T | None:
        if not callable(decoder):
            raise TypeError("decoder must be callable")
        plaintext = self.find(entry_id)
        return None if plaintext is None else decoder(plaintext)

    def find_many_decoded(
        self,
        entry_ids: Iterable[uuid.UUID],
        decoder: Callable[[uuid.UUID, bytes], T],
    ) -> dict[uuid.UUID, T | None]:
        """Reuse one authenticated snapshot and each index leaf for a list load.

        If a page or entry in the newest snapshot is damaged, use the normal
        single-entry reader for that ID so its older-snapshot fallback remains.
        """
        if not callable(decoder):
            raise TypeError("decoder must be callable")
        snapshot = self._resolve_snapshot()
        leaves: dict[int, EntryIndexPage] = {}
        result: dict[uuid.UUID, T | None] = {}
        for entry_id in entry_ids:
            if not isinstance(entry_id, uuid.UUID):
                raise TypeError("entry_id must be a UUID")
            try:
                directory = snapshot.root.find_page(entry_id)
                if directory is None:
                    result[entry_id] = None
                    continue
                page = leaves.get(directory.page_offset)
                if page is None:
                    page = self._read_leaf(snapshot, directory)
                    leaves[directory.page_offset] = page
                record = page.find(entry_id)
                if record is None:
                    result[entry_id] = None
                    continue
                if record.state is EntryIndexState.TOMBSTONE:
                    self._read_tombstone(snapshot, record)
                    result[entry_id] = None
                    continue
                plaintext = self._read_entry(snapshot, record)
            except (InvalidTag, OSError, TypeError, ValueError):
                plaintext = self.find(entry_id)
            result[entry_id] = None if plaintext is None else decoder(entry_id, plaintext)
        return result

    def snapshot(self) -> AuthenticatedSnapshot:
        """Return the newest fully authenticated snapshot (primarily diagnostics)."""

        return self._resolve_snapshot()

    def _resolve_snapshot(self) -> AuthenticatedSnapshot:
        for snapshot in self._authenticated_candidates():
            return snapshot
        raise ValueError("no fully authenticated entry-index snapshot")

    def _authenticated_candidates(self):
        with self._container.path.open("rb") as stream:
            for candidate in self._container.candidate_states():
                try:
                    yield authenticate_snapshot(
                        stream,
                        candidate,
                        vault_id=self._vault_id,
                        integrity_key=self._integrity_key,
                        index_root_key=self._index_root_key,
                        commit_key=self._commit_key,
                        index_key=self._index_key,
                        allow_legacy_static_keys=self._allow_legacy_static_keys,
                        trusted_signing_public_key=self._trusted_key,
                    )
                except (InvalidTag, OSError, TypeError, ValueError):
                    continue

    def _read_leaf(
        self,
        snapshot: AuthenticatedSnapshot,
        directory: EntryIndexRootRecord,
    ) -> EntryIndexPage:
        block = self._container.read_block(
            snapshot.state, directory.page_offset, BlockType.INDEX_PAGE
        )
        if snapshot.commit is None:
            raise ValueError("non-empty index leaf has no authenticated commit")
        _validate_index_block_role(block)
        if block.header.object_revision != snapshot.commit.revision:
            raise ValueError("entry-index leaf revision does not match the commit")
        leaf_key = (
            derive_index_page_key(
                self._index_root_key,
                block.header.object_id,
                block.header.object_revision,
                IndexPageType.ENTRY_INDEX,
            )
            if self._index_root_key is not None else self._index_key
        )
        plaintext = open_block(self._vault_id, leaf_key, block)
        try:
            page = decode_entry_index_page(plaintext)
        finally:
            plaintext = b""
        if page.next_page_offset != 0 or not page.records:
            raise ValueError("entry-index root references an invalid leaf page")
        if (page.records[0].entry_id != directory.min_entry_id or
                page.records[-1].entry_id != directory.max_entry_id):
            raise ValueError("entry-index leaf range does not match its root record")
        if entry_page_digest(page) != directory.page_digest:
            raise ValueError("entry-index leaf digest does not match its root record")
        return page

    def _read_entry(
        self,
        snapshot: AuthenticatedSnapshot,
        record: EntryIndexRecord,
    ) -> bytes:
        indexed_end = record.offset + record.length
        if indexed_end > snapshot.state.superblock.committed_file_end:
            raise ValueError("entry-index record exceeds the committed snapshot")
        block = self._container.read_block(snapshot.state, record.offset, BlockType.ENTRY)
        if BLOCK_HEADER_SIZE + block.header.cipher_size != record.length:
            raise ValueError("entry-index length does not match the entry block")
        if block.header.object_id != record.entry_id:
            raise ValueError("entry-index ID does not match the entry block")
        if block.header.object_revision != record.revision:
            raise ValueError("entry-index revision does not match the entry block")
        if encrypted_block_digest(block) != record.content_digest:
            raise ValueError("entry block digest does not match the entry-index record")
        derived = derive_entry_generation_key(
            self._entry_root_key, record.entry_id, record.revision
        )
        key_buffer = bytearray(derived)
        del derived
        try:
            return open_block(self._vault_id, key_buffer, block)
        finally:
            key_buffer[:] = bytes(len(key_buffer))

    def _read_tombstone(
        self,
        snapshot: AuthenticatedSnapshot,
        record: EntryIndexRecord,
    ) -> None:
        block = self._container.read_block(snapshot.state, record.offset, BlockType.TOMBSTONE)
        if BLOCK_HEADER_SIZE + block.header.cipher_size != record.length:
            raise ValueError("tombstone length does not match the entry-index record")
        if block.header.object_id != record.entry_id or block.header.object_revision != record.revision:
            raise ValueError("tombstone identity does not match the entry-index record")
        if encrypted_block_digest(block) != record.content_digest:
            raise ValueError("tombstone digest does not match the entry-index record")
        key_buffer = bytearray(derive_entry_generation_key(
            self._entry_root_key, record.entry_id, record.revision
        ))
        try:
            plaintext = open_block(self._vault_id, key_buffer, block)
        finally:
            key_buffer[:] = bytes(len(key_buffer))
        tombstone = decode_tombstone(plaintext)
        plaintext = b""
        if tombstone.entry_id != record.entry_id or tombstone.revision != record.revision:
            raise ValueError("tombstone plaintext does not match the entry-index record")

    @staticmethod
    def _exact_key(value: bytes, label: str) -> bytes:
        if type(value) is not bytes:
            raise TypeError(f"{label} must be bytes")
        if len(value) != 32:
            raise ValueError(f"{label} must be exactly 32 bytes")
        return value


__all__ = [
    "EntrySummary",
    "Cursor",
    "ListPage",
    "PmvEntryReader",
]
