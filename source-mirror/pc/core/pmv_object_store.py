"""Callback-based streaming access planner for PMV image and attachment objects.

This module intentionally has no transaction writer.  Import appends invisible blocks through a
callback and returns publishable ObjectIndex/ChunkIndex records only after the complete object and
its manifest have been persisted successfully.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import BinaryIO, Callable
from uuid import UUID

from .pmv_attachment import (
    CHUNK_SIZE,
    AttachmentKind,
    AttachmentManifest,
    ChunkFailure,
    encode_manifest,
    open_manifest,
    seal_from,
    seal_manifest,
)
from .pmv_container import BLOCK_HEADER_SIZE, DATA_START, EncodedBlock, open as open_block
from .pmv_integrity import encrypted_block_digest
from .pmv_key_schedule import derive_attachment_object_key, derive_chunk_key
from .pmv_object_index import ChunkKey, ChunkRecord, ObjectKey, ObjectRecord


@dataclass(frozen=True, slots=True)
class StoredBlock:
    offset: int
    length: int

    def __post_init__(self) -> None:
        if type(self.offset) is not int or self.offset < DATA_START:
            raise ValueError("invalid block offset")
        if type(self.length) is not int or self.length < BLOCK_HEADER_SIZE + 16:
            raise ValueError("invalid block length")


@dataclass(frozen=True, slots=True)
class ImportResult:
    manifest: AttachmentManifest
    object_record: ObjectRecord
    chunk_records: tuple[ChunkRecord, ...]


AppendBlock = Callable[[EncodedBlock], StoredBlock]
ReadBlock = Callable[[int, int], EncodedBlock]
FindChunk = Callable[[ChunkKey], ChunkRecord | None]


def _stored_length(block: EncodedBlock) -> int:
    return BLOCK_HEADER_SIZE + len(block.ciphertext)


def import_from(
    stream: BinaryIO,
    expected_size: int,
    vault_id: UUID,
    object_id: UUID,
    generation: int,
    kind: AttachmentKind,
    attachment_root_key: bytes,
    append: AppendBlock,
) -> ImportResult:
    """Seal chunks one at a time and return records suitable for a later atomic commit."""

    object_key = bytearray(derive_attachment_object_key(attachment_root_key, object_id, generation))
    stored_chunks: list[tuple[StoredBlock, bytes]] = []
    pending_chunk_key: bytearray | None = None
    try:
        def key_for_chunk(index: int) -> bytearray:
            nonlocal pending_chunk_key
            if pending_chunk_key is not None:
                raise RuntimeError("previous chunk key was not cleared")
            pending_chunk_key = bytearray(derive_chunk_key(bytes(object_key), index))
            return pending_chunk_key

        def emit(block: EncodedBlock) -> None:
            nonlocal pending_chunk_key
            try:
                location = append(block)
                if not isinstance(location, StoredBlock):
                    raise TypeError("append must return StoredBlock")
                if location.length != _stored_length(block):
                    raise ValueError("persisted chunk length mismatch")
                stored_chunks.append((location, encrypted_block_digest(block)))
            finally:
                if pending_chunk_key is not None:
                    pending_chunk_key[:] = b"\0" * len(pending_chunk_key)
                    pending_chunk_key = None

        manifest = seal_from(
            stream, expected_size, vault_id, object_id, generation, kind,
            key_for_chunk, emit,
        )
        if len(stored_chunks) != len(manifest.chunks):
            raise RuntimeError("persisted chunk count mismatch")
        chunk_records = tuple(
            ChunkRecord(
                ChunkKey(object_id, generation, index),
                location.offset,
                location.length,
                manifest.chunks[index].sha256,
                cipher_digest,
            )
            for index, (location, cipher_digest) in enumerate(stored_chunks)
        )

        manifest_plain = bytearray(encode_manifest(manifest))
        try:
            manifest_block = seal_manifest(vault_id, bytes(object_key), manifest)
            manifest_location = append(manifest_block)
            if not isinstance(manifest_location, StoredBlock):
                raise TypeError("append must return StoredBlock")
            if manifest_location.length != _stored_length(manifest_block):
                raise ValueError("persisted manifest length mismatch")
            object_record = ObjectRecord(
                ObjectKey(object_id, generation),
                manifest_location.offset,
                manifest_location.length,
                hashlib.sha256(manifest_plain).digest(),
                encrypted_block_digest(manifest_block),
            )
        finally:
            manifest_plain[:] = b"\0" * len(manifest_plain)
        return ImportResult(manifest, object_record, chunk_records)
    finally:
        if pending_chunk_key is not None:
            pending_chunk_key[:] = b"\0" * len(pending_chunk_key)
        object_key[:] = b"\0" * len(object_key)


def read_manifest(
    record: ObjectRecord, vault_id: UUID, attachment_root_key: bytes, read_block: ReadBlock,
) -> AttachmentManifest:
    """Read an authenticated media descriptor without decrypting its chunks."""
    manifest, object_key = _open_manifest_from_index(record, vault_id, attachment_root_key, read_block)
    try:
        return manifest
    finally:
        object_key[:] = b"\0" * len(object_key)


def _open_manifest_from_index(
    record: ObjectRecord,
    vault_id: UUID,
    attachment_root_key: bytes,
    read_block: ReadBlock,
) -> tuple[AttachmentManifest, bytearray]:
    block = read_block(record.manifest_offset, record.manifest_length)
    if _stored_length(block) != record.manifest_length:
        raise ValueError("manifest block length disagrees with ObjectIndex")
    if encrypted_block_digest(block) != record.cipher_digest:
        raise ValueError("manifest ciphertext digest disagrees with ObjectIndex")
    object_key = bytearray(derive_attachment_object_key(
        attachment_root_key, record.key.object_id, record.key.generation,
    ))
    try:
        manifest = open_manifest(vault_id, bytes(object_key), block)
        if manifest.object_id != record.key.object_id or manifest.generation != record.key.generation:
            raise ValueError("manifest key disagrees with ObjectIndex")
        encoded = bytearray(encode_manifest(manifest))
        try:
            if hashlib.sha256(encoded).digest() != record.plain_digest:
                raise ValueError("manifest plaintext digest disagrees with ObjectIndex")
        finally:
            encoded[:] = b"\0" * len(encoded)
        return manifest, object_key
    except BaseException:
        object_key[:] = b"\0" * len(object_key)
        raise


def _open_chunk(
    manifest: AttachmentManifest,
    index: int,
    vault_id: UUID,
    object_key: bytearray,
    read_block: ReadBlock,
    find_chunk: FindChunk,
) -> bytearray:
    manifest_record = manifest.chunks[index]
    try:
        key = ChunkKey(manifest.object_id, manifest.generation, index)
        index_record = find_chunk(key)
        if index_record is None:
            raise ValueError(f"ChunkIndex is missing chunk {index}")
        if index_record.plain_digest != manifest_record.sha256:
            raise ValueError("ChunkIndex digest disagrees with manifest")
        block = read_block(index_record.block_offset, index_record.block_length)
        if _stored_length(block) != index_record.block_length:
            raise ValueError("chunk block length disagrees with ChunkIndex")
        if encrypted_block_digest(block) != index_record.cipher_digest:
            raise ValueError("chunk ciphertext digest disagrees with ChunkIndex")
        header = block.header
        if not (
            header.block_type is manifest.kind.block_type
            and header.object_id == manifest.object_id
            and header.object_revision == manifest.generation
            and header.chunk_index == index
            and header.plain_size == manifest_record.plain_size
        ):
            raise ValueError("chunk header disagrees with manifest")
        chunk_key = bytearray(derive_chunk_key(bytes(object_key), index))
        try:
            plain = bytearray(open_block(vault_id, bytes(chunk_key), block))
        finally:
            chunk_key[:] = b"\0" * len(chunk_key)
        if hashlib.sha256(plain).digest() != manifest_record.sha256:
            plain[:] = b"\0" * len(plain)
            raise ValueError("chunk digest mismatch")
        return plain
    except ChunkFailure:
        raise
    except Exception as exc:
        raise ChunkFailure(index, exc) from exc


def open_to(
    object_record: ObjectRecord,
    vault_id: UUID,
    attachment_root_key: bytes,
    read_block: ReadBlock,
    find_chunk: FindChunk,
    output: BinaryIO,
) -> None:
    manifest, object_key = _open_manifest_from_index(
        object_record, vault_id, attachment_root_key, read_block,
    )
    try:
        whole = hashlib.sha256()
        for record in manifest.chunks:
            plain = _open_chunk(manifest, record.index, vault_id, object_key, read_block, find_chunk)
            try:
                whole.update(plain)
                output.write(plain)
            finally:
                plain[:] = b"\0" * len(plain)
        if whole.digest() != manifest.sha256:
            raise ValueError("attachment digest mismatch")
    finally:
        object_key[:] = b"\0" * len(object_key)


def open_range_to(
    object_record: ObjectRecord,
    offset: int,
    length: int,
    vault_id: UUID,
    attachment_root_key: bytes,
    read_block: ReadBlock,
    find_chunk: FindChunk,
    output: BinaryIO,
) -> None:
    """Read a verified byte range while fetching only intersecting chunks."""

    if type(offset) is not int or type(length) is not int or offset < 0 or length < 0:
        raise ValueError("invalid object range")
    manifest, object_key = _open_manifest_from_index(
        object_record, vault_id, attachment_root_key, read_block,
    )
    try:
        if offset > manifest.total_size or length > manifest.total_size - offset:
            raise ValueError("object range is outside the attachment")
        if length == 0:
            return
        first = offset // CHUNK_SIZE
        last = (offset + length - 1) // CHUNK_SIZE
        for index in range(first, last + 1):
            plain = _open_chunk(manifest, index, vault_id, object_key, read_block, find_chunk)
            try:
                chunk_start = index * CHUNK_SIZE
                start = max(offset, chunk_start) - chunk_start
                end = min(offset + length, chunk_start + len(plain)) - chunk_start
                output.write(plain[start:end])
            finally:
                plain[:] = b"\0" * len(plain)
    finally:
        object_key[:] = b"\0" * len(object_key)


__all__ = [
    "StoredBlock", "ImportResult", "import_from", "open_to", "open_range_to",
]
