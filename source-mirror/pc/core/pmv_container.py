"""Binary primitives for the append-only PMV container format.

The wire representation in this module mirrors the Android implementation in
``PmvContainerFormat`` and ``PmvBlockCrypto``.  All multibyte integers use
network (big-endian) byte order.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import pmv_compression


FORMAT_VERSION = 1
SUPERBLOCK_SIZE = 4 * 1024
VAULT_HEADER_SIZE = 4 * 1024
VAULT_HEADER_PRIMARY_OFFSET = SUPERBLOCK_SIZE * 2
VAULT_HEADER_SECONDARY_OFFSET = VAULT_HEADER_PRIMARY_OFFSET + VAULT_HEADER_SIZE
DATA_START = VAULT_HEADER_SECONDARY_OFFSET + VAULT_HEADER_SIZE
BLOCK_HEADER_SIZE = 128
GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
MAX_BLOCK_CIPHER_SIZE = 16 * 1024 * 1024 + GCM_TAG_SIZE

SUPERBLOCK_AUTH_SIZE = 32
SUPERBLOCK_MAGIC = b"PMVS"
BLOCK_MAGIC = b"PMVB"
BLOCK_AAD_DOMAIN = b"PMV Block AAD v1\x00"

_SUPERBLOCK_FIELDS = struct.Struct(">4sI16s6q")
_BLOCK_HEADER_FIELDS = struct.Struct(">4sII16sI16sqiiiiqq12s")
_INT32_MIN = -(2**31)
_INT32_MAX = 2**31 - 1
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def _require_int_range(value: int, minimum: int, maximum: int, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise ValueError(f"{label} is outside its wire-format range")


def _require_uuid(value: uuid.UUID, label: str) -> None:
    if not isinstance(value, uuid.UUID):
        raise TypeError(f"{label} must be a UUID")


def _to_bytes(value: bytes | bytearray | memoryview, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{label} must be bytes-like")
    return bytes(value)


class BlockType(IntEnum):
    ENTRY = 1
    LOGIN_INDEX = 2
    OBJECT_METADATA = 3
    IMAGE_CHUNK = 4
    ATTACHMENT_CHUNK = 5
    INDEX_PAGE = 6
    COMMIT = 7
    TOMBSTONE = 8
    OTHER = 255

    @classmethod
    def from_id(cls, value: int) -> BlockType:
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError("unknown PMV block type") from exc


@dataclass(frozen=True)
class Superblock:
    vault_id: uuid.UUID
    sequence: int
    latest_commit_offset: int
    latest_index_offset: int
    committed_file_end: int
    kdf_parameters_offset: int
    feature_flags: int

    def __post_init__(self) -> None:
        _require_uuid(self.vault_id, "vault_id")
        for label, value in (
            ("sequence", self.sequence),
            ("latest_commit_offset", self.latest_commit_offset),
            ("latest_index_offset", self.latest_index_offset),
            ("committed_file_end", self.committed_file_end),
            ("kdf_parameters_offset", self.kdf_parameters_offset),
            ("feature_flags", self.feature_flags),
        ):
            _require_int_range(value, _INT64_MIN, _INT64_MAX, label)
        if self.sequence < 0:
            raise ValueError("superblock sequence cannot be negative")
        if self.committed_file_end < DATA_START:
            raise ValueError("invalid committed file boundary")
        for label, offset in (
            ("commit", self.latest_commit_offset),
            ("index", self.latest_index_offset),
            ("KDF", self.kdf_parameters_offset),
        ):
            if offset != 0 and not DATA_START <= offset <= self.committed_file_end:
                raise ValueError(f"{label} offset is outside the committed boundary")


@dataclass(frozen=True)
class BlockHeader:
    block_id: uuid.UUID
    block_type: BlockType
    object_id: uuid.UUID
    object_revision: int
    chunk_index: int
    flags: int
    crypto_suite_id: int
    codec_id: int
    plain_size: int
    cipher_size: int
    nonce: bytes

    def __post_init__(self) -> None:
        _require_uuid(self.block_id, "block_id")
        if not isinstance(self.block_type, BlockType):
            raise TypeError("block_type must be a BlockType")
        _require_uuid(self.object_id, "object_id")
        _require_int_range(self.object_revision, _INT64_MIN, _INT64_MAX, "object_revision")
        _require_int_range(self.chunk_index, _INT32_MIN, _INT32_MAX, "chunk_index")
        _require_int_range(self.flags, _INT32_MIN, _INT32_MAX, "flags")
        _require_int_range(self.crypto_suite_id, _INT32_MIN, _INT32_MAX, "crypto_suite_id")
        _require_int_range(self.codec_id, _INT32_MIN, _INT32_MAX, "codec_id")
        _require_int_range(self.plain_size, _INT64_MIN, _INT64_MAX, "plain_size")
        _require_int_range(self.cipher_size, _INT64_MIN, _INT64_MAX, "cipher_size")
        nonce = _to_bytes(self.nonce, "nonce")
        object.__setattr__(self, "nonce", nonce)

        if self.object_revision < 0:
            raise ValueError("object revision cannot be negative")
        if self.chunk_index < -1:
            raise ValueError("invalid chunk index")
        if self.crypto_suite_id <= 0:
            raise ValueError("invalid cryptographic suite")
        if self.codec_id < 0:
            raise ValueError("invalid compression codec")
        if self.plain_size < 0:
            raise ValueError("invalid plaintext size")
        if self.cipher_size < GCM_TAG_SIZE:
            raise ValueError("ciphertext is shorter than its authentication tag")
        if self.cipher_size > MAX_BLOCK_CIPHER_SIZE:
            raise ValueError("block ciphertext exceeds the format limit")
        if len(nonce) != GCM_NONCE_SIZE:
            raise ValueError("GCM nonce must be 96 bits")


@dataclass(frozen=True)
class EncodedBlock:
    header: BlockHeader
    ciphertext: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.header, BlockHeader):
            raise TypeError("header must be a BlockHeader")
        ciphertext = _to_bytes(self.ciphertext, "ciphertext")
        object.__setattr__(self, "ciphertext", ciphertext)
        if self.header.cipher_size != len(ciphertext):
            raise ValueError("block ciphertext length does not match its header")


def _require_authentication_key(key: bytes | bytearray | memoryview) -> bytes:
    raw = _to_bytes(key, "authentication_key")
    if len(raw) < 32:
        raise ValueError("superblock authentication key must be at least 256 bits")
    return raw


def _require_block_key(key: bytes | bytearray | memoryview) -> bytes:
    raw = _to_bytes(key, "key")
    if len(raw) != 32:
        raise ValueError("PMV block key must be 256 bits")
    return raw


def encode_superblock(
    value: Superblock,
    authentication_key: bytes | bytearray | memoryview,
) -> bytes:
    if not isinstance(value, Superblock):
        raise TypeError("value must be a Superblock")
    key = _require_authentication_key(authentication_key)
    output = bytearray(SUPERBLOCK_SIZE)
    _SUPERBLOCK_FIELDS.pack_into(
        output,
        0,
        SUPERBLOCK_MAGIC,
        FORMAT_VERSION,
        value.vault_id.bytes,
        value.sequence,
        value.latest_commit_offset,
        value.latest_index_offset,
        value.committed_file_end,
        value.kdf_parameters_offset,
        value.feature_flags,
    )
    tag_offset = SUPERBLOCK_SIZE - SUPERBLOCK_AUTH_SIZE
    output[tag_offset:] = hmac.new(key, output[:tag_offset], hashlib.sha256).digest()
    return bytes(output)


def decode_superblock(
    raw: bytes | bytearray | memoryview,
    authentication_key: bytes | bytearray | memoryview,
) -> Superblock:
    encoded = _to_bytes(raw, "raw")
    if len(encoded) != SUPERBLOCK_SIZE:
        raise ValueError("invalid superblock size")
    key = _require_authentication_key(authentication_key)
    tag_offset = SUPERBLOCK_SIZE - SUPERBLOCK_AUTH_SIZE
    expected = hmac.new(key, encoded[:tag_offset], hashlib.sha256).digest()
    if not hmac.compare_digest(expected, encoded[tag_offset:]):
        raise ValueError("superblock authentication failed")

    magic, version, vault_bytes, *fields = _SUPERBLOCK_FIELDS.unpack_from(encoded)
    if magic != SUPERBLOCK_MAGIC:
        raise ValueError("invalid superblock magic")
    if version != FORMAT_VERSION:
        raise ValueError("invalid superblock version")
    return Superblock(uuid.UUID(bytes=vault_bytes), *fields)


def select_latest_superblock(
    slot_a: bytes | bytearray | memoryview,
    slot_b: bytes | bytearray | memoryview,
    authentication_key: bytes | bytearray | memoryview,
) -> Superblock | None:
    candidates: list[Superblock] = []
    for raw in (slot_a, slot_b):
        try:
            candidates.append(decode_superblock(raw, authentication_key))
        except Exception:
            continue
    return max(candidates, key=lambda value: value.sequence, default=None)


def encode_block_header(value: BlockHeader) -> bytes:
    if not isinstance(value, BlockHeader):
        raise TypeError("value must be a BlockHeader")
    output = bytearray(BLOCK_HEADER_SIZE)
    _BLOCK_HEADER_FIELDS.pack_into(
        output,
        0,
        BLOCK_MAGIC,
        FORMAT_VERSION,
        BLOCK_HEADER_SIZE,
        value.block_id.bytes,
        value.block_type.value,
        value.object_id.bytes,
        value.object_revision,
        value.chunk_index,
        value.flags,
        value.crypto_suite_id,
        value.codec_id,
        value.plain_size,
        value.cipher_size,
        value.nonce,
    )
    return bytes(output)


def decode_block_header(raw: bytes | bytearray | memoryview) -> BlockHeader:
    encoded = _to_bytes(raw, "raw")
    if len(encoded) != BLOCK_HEADER_SIZE:
        raise ValueError("invalid block header size")
    (
        magic,
        version,
        header_size,
        block_id,
        block_type,
        object_id,
        object_revision,
        chunk_index,
        flags,
        crypto_suite_id,
        codec_id,
        plain_size,
        cipher_size,
        nonce,
    ) = _BLOCK_HEADER_FIELDS.unpack_from(encoded)
    if magic != BLOCK_MAGIC:
        raise ValueError("invalid block magic")
    if version != FORMAT_VERSION:
        raise ValueError("invalid block version")
    if header_size != BLOCK_HEADER_SIZE:
        raise ValueError("invalid block header length")
    result = BlockHeader(
        block_id=uuid.UUID(bytes=block_id),
        block_type=BlockType.from_id(block_type),
        object_id=uuid.UUID(bytes=object_id),
        object_revision=object_revision,
        chunk_index=chunk_index,
        flags=flags,
        crypto_suite_id=crypto_suite_id,
        codec_id=codec_id,
        plain_size=plain_size,
        cipher_size=cipher_size,
        nonce=nonce,
    )
    if any(encoded[_BLOCK_HEADER_FIELDS.size:]):
        raise ValueError("block header reserved fields are non-zero")
    return result


def block_aad(vault_id: uuid.UUID, header: BlockHeader) -> bytes:
    _require_uuid(vault_id, "vault_id")
    if not isinstance(header, BlockHeader):
        raise TypeError("header must be a BlockHeader")
    return BLOCK_AAD_DOMAIN + vault_id.bytes + encode_block_header(header)


def seal(
    vault_id: uuid.UUID,
    key: bytes | bytearray | memoryview,
    block_type: BlockType,
    object_id: uuid.UUID,
    object_revision: int,
    plaintext: bytes | bytearray | memoryview,
    block_id: uuid.UUID | None = None,
    chunk_index: int = -1,
    flags: int = 0,
    codec_id: int = 0,
) -> EncodedBlock:
    _require_uuid(vault_id, "vault_id")
    block_key = _require_block_key(key)
    plain = _to_bytes(plaintext, "plaintext")
    if len(plain) > MAX_BLOCK_CIPHER_SIZE - GCM_TAG_SIZE:
        raise ValueError("block plaintext exceeds the format limit")
    if block_id is None:
        block_id = uuid.uuid4()
    encoded_plain = pmv_compression.encode(codec_id, plain)
    if len(encoded_plain) > MAX_BLOCK_CIPHER_SIZE - GCM_TAG_SIZE:
        raise ValueError("encoded block plaintext exceeds the format limit")
    nonce = os.urandom(GCM_NONCE_SIZE)
    header = BlockHeader(
        block_id=block_id,
        block_type=block_type,
        object_id=object_id,
        object_revision=object_revision,
        chunk_index=chunk_index,
        flags=flags,
        crypto_suite_id=1,
        codec_id=codec_id,
        plain_size=len(plain),
        cipher_size=len(encoded_plain) + GCM_TAG_SIZE,
        nonce=nonce,
    )
    ciphertext = AESGCM(block_key).encrypt(nonce, encoded_plain, block_aad(vault_id, header))
    if len(ciphertext) != header.cipher_size:
        raise RuntimeError("AES-GCM output length does not match its header")
    return EncodedBlock(header, ciphertext)


def open(
    vault_id: uuid.UUID,
    key: bytes | bytearray | memoryview,
    block: EncodedBlock,
) -> bytes:
    _require_uuid(vault_id, "vault_id")
    block_key = _require_block_key(key)
    if not isinstance(block, EncodedBlock):
        raise TypeError("block must be an EncodedBlock")
    if block.header.crypto_suite_id != 1:
        raise ValueError("unsupported PMV cryptographic suite")
    encoded_plaintext = AESGCM(block_key).decrypt(
        block.header.nonce,
        block.ciphertext,
        block_aad(vault_id, block.header),
    )
    try:
        return pmv_compression.decode(
            block.header.codec_id,
            encoded_plaintext,
            block.header.plain_size,
        )
    except BaseException:
        scrub = bytearray(encoded_plaintext)
        scrub[:] = b"\x00" * len(scrub)
        raise


__all__ = [
    "FORMAT_VERSION",
    "SUPERBLOCK_SIZE",
    "VAULT_HEADER_SIZE",
    "VAULT_HEADER_PRIMARY_OFFSET",
    "VAULT_HEADER_SECONDARY_OFFSET",
    "DATA_START",
    "BLOCK_HEADER_SIZE",
    "GCM_NONCE_SIZE",
    "GCM_TAG_SIZE",
    "MAX_BLOCK_CIPHER_SIZE",
    "SUPERBLOCK_AUTH_SIZE",
    "SUPERBLOCK_MAGIC",
    "BLOCK_MAGIC",
    "BLOCK_AAD_DOMAIN",
    "BlockType",
    "Superblock",
    "BlockHeader",
    "EncodedBlock",
    "encode_superblock",
    "decode_superblock",
    "select_latest_superblock",
    "encode_block_header",
    "decode_block_header",
    "block_aad",
    "seal",
    "open",
]
