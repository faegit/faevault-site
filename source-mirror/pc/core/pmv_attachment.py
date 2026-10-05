"""Canonical streaming PMV image/attachment manifests and chunk blocks."""

from __future__ import annotations

import hashlib
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO, Callable

from .pmv_container import (
    GCM_TAG_SIZE,
    MAX_BLOCK_CIPHER_SIZE,
    BlockType,
    EncodedBlock,
    open as open_block,
    seal,
)
from .pmv_compression import choose_codec


CHUNK_SIZE = 8 * 1024 * 1024
VERSION = 1
HEADER_SIZE = 96
RECORD_SIZE = 48
# Keeps the complete canonical manifest inside one OBJECT_METADATA block.
MAX_CHUNKS = (MAX_BLOCK_CIPHER_SIZE - GCM_TAG_SIZE - HEADER_SIZE) // RECORD_SIZE
MAGIC = b"PMOA"
_HEADER = struct.Struct(">4sI16sqB7xqII32s8x")
_RECORD = struct.Struct(">II32s8x")


def _digest_bytes(value: bytes | bytearray | memoryview, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} must be bytes-like")
    digest = bytes(value)
    if len(digest) != 32:
        raise ValueError(f"{label} must be SHA-256")
    return digest


class AttachmentKind(IntEnum):
    IMAGE = 1
    ATTACHMENT = 2

    @property
    def block_type(self) -> BlockType:
        return BlockType.IMAGE_CHUNK if self is AttachmentKind.IMAGE else BlockType.ATTACHMENT_CHUNK


@dataclass(frozen=True)
class ChunkRecord:
    index: int
    plain_size: int
    sha256: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.index, int) or isinstance(self.index, bool) or self.index < 0:
            raise ValueError("invalid chunk index")
        if not isinstance(self.plain_size, int) or isinstance(self.plain_size, bool) or not 1 <= self.plain_size <= CHUNK_SIZE:
            raise ValueError("invalid chunk size")
        digest = _digest_bytes(self.sha256, "chunk digest")
        object.__setattr__(self, "sha256", digest)


@dataclass(frozen=True)
class AttachmentManifest:
    object_id: uuid.UUID
    generation: int
    kind: AttachmentKind
    total_size: int
    sha256: bytes
    chunks: tuple[ChunkRecord, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.object_id, uuid.UUID):
            raise TypeError("object_id must be a UUID")
        if not isinstance(self.generation, int) or isinstance(self.generation, bool) or not 0 <= self.generation <= 2**63 - 1:
            raise ValueError("invalid attachment generation")
        if not isinstance(self.kind, AttachmentKind):
            raise TypeError("kind must be an AttachmentKind")
        if not isinstance(self.total_size, int) or isinstance(self.total_size, bool) or not 0 <= self.total_size <= 2**63 - 1:
            raise ValueError("invalid attachment size")
        digest = _digest_bytes(self.sha256, "attachment digest")
        chunks = tuple(self.chunks)
        if len(chunks) > MAX_CHUNKS:
            raise ValueError("attachment chunk count exceeds the format limit")
        expected_count = 0 if self.total_size == 0 else (self.total_size - 1) // CHUNK_SIZE + 1
        if len(chunks) != expected_count:
            raise ValueError("attachment size and chunk count disagree")
        total = 0
        for index, chunk in enumerate(chunks):
            if not isinstance(chunk, ChunkRecord) or chunk.index != index:
                raise ValueError("chunks must be contiguous and ordered")
            expected_size = self.total_size - index * CHUNK_SIZE if index == len(chunks) - 1 else CHUNK_SIZE
            if chunk.plain_size != expected_size:
                raise ValueError("chunk size disagrees with attachment size")
            total += chunk.plain_size
        if total != self.total_size:
            raise ValueError("chunk total disagrees with attachment size")
        object.__setattr__(self, "sha256", digest)
        object.__setattr__(self, "chunks", chunks)


class ChunkFailure(ValueError):
    def __init__(self, chunk_index: int, cause: BaseException) -> None:
        self.chunk_index = chunk_index
        super().__init__(f"attachment chunk {chunk_index} verification failed")
        self.__cause__ = cause


def encode_manifest(value: AttachmentManifest) -> bytes:
    if not isinstance(value, AttachmentManifest):
        raise TypeError("value must be an AttachmentManifest")
    output = bytearray(HEADER_SIZE + len(value.chunks) * RECORD_SIZE)
    _HEADER.pack_into(output, 0, MAGIC, VERSION, value.object_id.bytes, value.generation,
                      value.kind.value, value.total_size, CHUNK_SIZE, len(value.chunks), value.sha256)
    offset = HEADER_SIZE
    for chunk in value.chunks:
        _RECORD.pack_into(output, offset, chunk.index, chunk.plain_size, chunk.sha256)
        offset += RECORD_SIZE
    return bytes(output)


def decode_manifest(raw: bytes | bytearray | memoryview) -> AttachmentManifest:
    if not isinstance(raw, (bytes, bytearray, memoryview)):
        raise TypeError("raw must be bytes-like")
    encoded = bytes(raw)
    if len(encoded) < HEADER_SIZE or (len(encoded) - HEADER_SIZE) % RECORD_SIZE:
        raise ValueError("invalid attachment manifest length")
    magic, version, object_bytes, generation, kind_id, total_size, chunk_size, count, digest = _HEADER.unpack_from(encoded)
    if magic != MAGIC or version != VERSION:
        raise ValueError("invalid attachment manifest magic or version")
    if any(encoded[88:96]):
        raise ValueError("attachment manifest reserved fields are non-zero")
    if chunk_size != CHUNK_SIZE:
        raise ValueError("unsupported attachment chunk size")
    if count > MAX_CHUNKS or len(encoded) != HEADER_SIZE + count * RECORD_SIZE:
        raise ValueError("invalid attachment chunk count")
    chunks: list[ChunkRecord] = []
    offset = HEADER_SIZE
    for _ in range(count):
        index, plain_size, chunk_digest = _RECORD.unpack_from(encoded, offset)
        if any(encoded[offset + 40:offset + RECORD_SIZE]):
            raise ValueError("attachment chunk reserved fields are non-zero")
        chunks.append(ChunkRecord(index, plain_size, chunk_digest))
        offset += RECORD_SIZE
    try:
        kind = AttachmentKind(kind_id)
    except ValueError as exc:
        raise ValueError("unknown attachment kind") from exc
    return AttachmentManifest(uuid.UUID(bytes=object_bytes), generation, kind, total_size, digest, tuple(chunks))


def seal_manifest(vault_id: uuid.UUID, key: bytes, value: AttachmentManifest) -> EncodedBlock:
    return seal(vault_id, key, BlockType.OBJECT_METADATA, value.object_id, value.generation,
                encode_manifest(value), chunk_index=-1)


def open_manifest(vault_id: uuid.UUID, key: bytes, block: EncodedBlock) -> AttachmentManifest:
    if block.header.block_type is not BlockType.OBJECT_METADATA or block.header.chunk_index != -1:
        raise ValueError("not an attachment manifest block")
    result = decode_manifest(open_block(vault_id, key, block))
    if result.object_id != block.header.object_id or result.generation != block.header.object_revision:
        raise ValueError("attachment manifest is not bound to its block header")
    return result


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    output = bytearray(size)
    view = memoryview(output)
    offset = 0
    while offset < size:
        part = stream.read(size - offset)
        if not part:
            raise ValueError("attachment stream ended early")
        view[offset:offset + len(part)] = part
        offset += len(part)
    return bytes(output)


def seal_from(
    stream: BinaryIO,
    expected_size: int,
    vault_id: uuid.UUID,
    object_id: uuid.UUID,
    generation: int,
    kind: AttachmentKind,
    key_for_chunk: Callable[[int], bytes],
    emit: Callable[[EncodedBlock], None],
) -> AttachmentManifest:
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        raise ValueError("invalid attachment size")
    count = 0 if expected_size == 0 else (expected_size - 1) // CHUNK_SIZE + 1
    if count > MAX_CHUNKS:
        raise ValueError("attachment chunk count exceeds the format limit")
    whole = hashlib.sha256()
    chunks: list[ChunkRecord] = []
    remaining = expected_size
    index = 0
    while remaining:
        wanted = min(CHUNK_SIZE, remaining)
        plain = _read_exact(stream, wanted)
        whole.update(plain)
        digest = hashlib.sha256(plain).digest()
        emit(seal(vault_id, key_for_chunk(index), kind.block_type, object_id, generation,
                  plain, chunk_index=index, codec_id=choose_codec(plain)))
        chunks.append(ChunkRecord(index, wanted, digest))
        remaining -= wanted
        index += 1
    if stream.read(1):
        raise ValueError("attachment stream is longer than its declared size")
    return AttachmentManifest(object_id, generation, kind, expected_size, whole.digest(), tuple(chunks))


def open_to(
    manifest: AttachmentManifest,
    vault_id: uuid.UUID,
    key_for_chunk: Callable[[int], bytes],
    block_for_chunk: Callable[[int], EncodedBlock],
    output: BinaryIO,
) -> None:
    whole = hashlib.sha256()
    for record in manifest.chunks:
        try:
            block = block_for_chunk(record.index)
            header = block.header
            if not (header.block_type is manifest.kind.block_type and
                    header.object_id == manifest.object_id and
                    header.object_revision == manifest.generation and
                    header.chunk_index == record.index and
                    header.plain_size == record.plain_size):
                raise ValueError("chunk header disagrees with manifest")
            plain = open_block(vault_id, key_for_chunk(record.index), block)
            if not hashlib.sha256(plain).digest() == record.sha256:
                raise ValueError("chunk digest mismatch")
            whole.update(plain)
            output.write(plain)
        except ChunkFailure:
            raise
        except Exception as exc:
            raise ChunkFailure(record.index, exc) from exc
    if whole.digest() != manifest.sha256:
        raise ValueError("attachment digest mismatch")


__all__ = [
    "CHUNK_SIZE", "HEADER_SIZE", "RECORD_SIZE", "MAX_CHUNKS", "AttachmentKind",
    "ChunkRecord", "AttachmentManifest", "ChunkFailure", "encode_manifest", "decode_manifest",
    "seal_manifest", "open_manifest", "seal_from", "open_to",
]
