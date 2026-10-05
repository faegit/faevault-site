"""Canonical PMV commit records and Ed25519 verification.

The fixed-width plaintext produced here is intended to be encrypted inside a
PMV ``COMMIT`` block.  Its representation is shared byte-for-byte with the
Android implementation; all multibyte integers use unsigned big-endian form,
but wire-u64 semantics are deliberately limited to ``0..Long.MAX_VALUE``.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, replace
from typing import ClassVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .pmv_container import (
    BLOCK_HEADER_SIZE,
    DATA_START as _DATA_START,
    GCM_TAG_SIZE,
    MAX_BLOCK_CIPHER_SIZE,
)


COMMIT_MAGIC = b"PMVC"
COMMIT_VERSION = 1
COMMIT_PLAIN_SIZE = 224
ROOT_DIGEST_SIZE = 32
PUBLIC_KEY_SIZE = 32
SIGNATURE_SIZE = 64
COMMIT_SIGNING_DOMAIN = b"pmv/v1/commit\0"

_MIN_BLOCK_LENGTH = BLOCK_HEADER_SIZE + GCM_TAG_SIZE
_MAX_BLOCK_LENGTH = BLOCK_HEADER_SIZE + MAX_BLOCK_CIPHER_SIZE
_MAX_WIRE_LONG = (1 << 63) - 1
_ZERO_UUID_BYTES = bytes(16)
_HEADER = struct.Struct(">4sIII16s16sB7s16sQQQ32s32s64s")

assert _HEADER.size == COMMIT_PLAIN_SIZE


def _require_uuid(value: object, label: str) -> uuid.UUID:
    if not isinstance(value, uuid.UUID):
        raise TypeError(f"{label} must be a UUID")
    return value


def _require_bytes(value: object, label: str, length: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{label} must be bytes")
    if len(value) != length:
        raise ValueError(f"{label} must be exactly {length} bytes")
    return value


def _require_u64(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not 0 <= value <= _MAX_WIRE_LONG:
        raise ValueError(f"{label} must be between 0 and 2^63 - 1")
    return value


@dataclass(frozen=True, slots=True)
class Commit:
    vault_id: uuid.UUID
    commit_id: uuid.UUID
    parent_commit_id: uuid.UUID | None
    revision: int
    index_root_offset: int
    index_root_length: int
    root_digest: bytes
    signing_public_key: bytes
    signature: bytes

    def __post_init__(self) -> None:
        _require_uuid(self.vault_id, "vault_id")
        _require_uuid(self.commit_id, "commit_id")
        if self.vault_id.int == 0 or self.commit_id.int == 0:
            raise ValueError("vault and commit UUIDs must be non-zero")
        if self.parent_commit_id is not None:
            _require_uuid(self.parent_commit_id, "parent_commit_id")
            if self.parent_commit_id.int == 0:
                raise ValueError("parent commit UUID must be non-zero")
            if self.parent_commit_id == self.commit_id:
                raise ValueError("commit cannot be its own parent")
        _require_u64(self.revision, "revision")
        _require_u64(self.index_root_offset, "index_root_offset")
        _require_u64(self.index_root_length, "index_root_length")
        if self.index_root_offset < _DATA_START:
            raise ValueError("index root offset precedes the PMV data area")
        if not _MIN_BLOCK_LENGTH <= self.index_root_length <= _MAX_BLOCK_LENGTH:
            raise ValueError("index root block length is invalid")
        if self.index_root_offset > _MAX_WIRE_LONG - self.index_root_length:
            raise ValueError("index root block range exceeds the cross-runtime signed 64-bit range")
        _require_bytes(self.root_digest, "root_digest", ROOT_DIGEST_SIZE)
        _require_bytes(self.signing_public_key, "signing_public_key", PUBLIC_KEY_SIZE)
        _require_bytes(self.signature, "signature", SIGNATURE_SIZE)


def canonical_signing_bytes(
    vault_id: uuid.UUID,
    commit_id: uuid.UUID,
    parent_commit_id: uuid.UUID | None,
    revision: int,
    root_digest: bytes,
) -> bytes:
    """Return the sole canonical message accepted for a PMV commit signature."""

    checked_vault_id = _require_uuid(vault_id, "vault_id")
    checked_commit_id = _require_uuid(commit_id, "commit_id")
    if checked_vault_id.int == 0 or checked_commit_id.int == 0:
        raise ValueError("vault and commit UUIDs must be non-zero")
    if parent_commit_id is not None:
        checked_parent = _require_uuid(parent_commit_id, "parent_commit_id")
        if checked_parent.int == 0:
            raise ValueError("parent commit UUID must be non-zero")
        if checked_parent == checked_commit_id:
            raise ValueError("commit cannot be its own parent")
        parent_present = b"\x01"
        parent_bytes = checked_parent.bytes
    else:
        parent_present = b"\x00"
        parent_bytes = _ZERO_UUID_BYTES
    checked_revision = _require_u64(revision, "revision")
    checked_digest = _require_bytes(root_digest, "root_digest", ROOT_DIGEST_SIZE)
    return b"".join(
        (
            COMMIT_SIGNING_DOMAIN,
            checked_vault_id.bytes,
            checked_commit_id.bytes,
            parent_present,
            parent_bytes,
            checked_revision.to_bytes(8, "big"),
            checked_digest,
        )
    )


def sign_commit(commit: Commit, private_key: Ed25519PrivateKey) -> Commit:
    """Return ``commit`` signed by ``private_key`` with its public key bound."""

    if not isinstance(commit, Commit):
        raise TypeError("commit must be a Commit")
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key must be an Ed25519PrivateKey")
    message = canonical_signing_bytes(
        commit.vault_id,
        commit.commit_id,
        commit.parent_commit_id,
        commit.revision,
        commit.root_digest,
    )
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return replace(
        commit,
        signing_public_key=public_key,
        signature=private_key.sign(message),
    )


def verify_commit_signature(commit: Commit) -> None:
    """Verify ``commit`` or raise ``ValueError`` for an invalid signature."""

    if not isinstance(commit, Commit):
        raise TypeError("commit must be a Commit")
    message = canonical_signing_bytes(
        commit.vault_id,
        commit.commit_id,
        commit.parent_commit_id,
        commit.revision,
        commit.root_digest,
    )
    try:
        Ed25519PublicKey.from_public_bytes(commit.signing_public_key).verify(
            commit.signature,
            message,
        )
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("commit signature verification failed") from exc


def encode_commit(commit: Commit) -> bytes:
    """Encode a verified commit to its fixed-width canonical plaintext."""

    if not isinstance(commit, Commit):
        raise TypeError("commit must be a Commit")
    verify_commit_signature(commit)
    parent_present = int(commit.parent_commit_id is not None)
    parent_bytes = (
        commit.parent_commit_id.bytes
        if commit.parent_commit_id is not None
        else _ZERO_UUID_BYTES
    )
    return _HEADER.pack(
        COMMIT_MAGIC,
        COMMIT_VERSION,
        COMMIT_PLAIN_SIZE,
        0,
        commit.vault_id.bytes,
        commit.commit_id.bytes,
        parent_present,
        bytes(7),
        parent_bytes,
        commit.revision,
        commit.index_root_offset,
        commit.index_root_length,
        commit.root_digest,
        commit.signing_public_key,
        commit.signature,
    )


def decode_commit(raw: bytes) -> Commit:
    """Decode and authenticate one fixed-width commit plaintext."""

    if type(raw) is not bytes:
        raise TypeError("raw must be bytes")
    if len(raw) != COMMIT_PLAIN_SIZE:
        raise ValueError("commit plaintext size is invalid")
    (
        magic,
        version,
        declared_size,
        flags,
        vault_bytes,
        commit_bytes,
        parent_present,
        reserved,
        parent_bytes,
        revision,
        index_root_offset,
        index_root_length,
        root_digest,
        public_key,
        signature,
    ) = _HEADER.unpack(raw)
    if magic != COMMIT_MAGIC:
        raise ValueError("commit magic is invalid")
    if version != COMMIT_VERSION:
        raise ValueError("commit version is invalid")
    if declared_size != COMMIT_PLAIN_SIZE:
        raise ValueError("commit declared size is invalid")
    if flags != 0 or reserved != bytes(7):
        raise ValueError("commit reserved fields are non-zero")
    if parent_present not in (0, 1):
        raise ValueError("commit parent-present flag is invalid")
    if parent_present == 0 and parent_bytes != _ZERO_UUID_BYTES:
        raise ValueError("parentless commit contains a parent UUID")
    commit = Commit(
        vault_id=uuid.UUID(bytes=vault_bytes),
        commit_id=uuid.UUID(bytes=commit_bytes),
        parent_commit_id=uuid.UUID(bytes=parent_bytes) if parent_present else None,
        revision=revision,
        index_root_offset=index_root_offset,
        index_root_length=index_root_length,
        root_digest=root_digest,
        signing_public_key=public_key,
        signature=signature,
    )
    verify_commit_signature(commit)
    return commit


class PmvCommitCodec:
    """Android-shaped facade for callers that prefer a codec object."""

    PLAIN_SIZE: ClassVar[int] = COMMIT_PLAIN_SIZE
    Commit: ClassVar[type[Commit]] = Commit
    canonical_signing_bytes = staticmethod(canonical_signing_bytes)
    sign = staticmethod(sign_commit)
    verify = staticmethod(verify_commit_signature)
    encode = staticmethod(encode_commit)
    decode = staticmethod(decode_commit)


__all__ = [
    "COMMIT_MAGIC",
    "COMMIT_VERSION",
    "COMMIT_PLAIN_SIZE",
    "ROOT_DIGEST_SIZE",
    "PUBLIC_KEY_SIZE",
    "SIGNATURE_SIZE",
    "COMMIT_SIGNING_DOMAIN",
    "Commit",
    "PmvCommitCodec",
    "canonical_signing_bytes",
    "sign_commit",
    "verify_commit_signature",
    "encode_commit",
    "decode_commit",
]
