"""Canonical authenticated PMV tombstone plaintext."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass


SIZE = 128
FLAG_PURGED = 1
_VERSION = 1
_MAGIC = b"PMVT"
_PREFIX = struct.Struct(">4sII16sqq32sI")
_MAX_SIGNED_LONG = (1 << 63) - 1


@dataclass(frozen=True, slots=True)
class Tombstone:
    entry_id: uuid.UUID
    revision: int
    purged_at_epoch_millis: int
    previous_content_digest: bytes
    flags: int = FLAG_PURGED

    def __post_init__(self) -> None:
        if not isinstance(self.entry_id, uuid.UUID):
            raise TypeError("entry_id must be a UUID")
        for value, name in ((self.revision, "revision"),
                            (self.purged_at_epoch_millis, "purged_at_epoch_millis")):
            if (not isinstance(value, int) or isinstance(value, bool)
                    or not 0 <= value <= _MAX_SIGNED_LONG):
                raise ValueError(f"{name} is outside the signed 64-bit range")
        if not isinstance(self.previous_content_digest, bytes) or len(self.previous_content_digest) != 32:
            raise ValueError("previous_content_digest must be 32 bytes")
        if self.flags != FLAG_PURGED:
            raise ValueError("tombstone flags are invalid")


def encode_tombstone(value: Tombstone) -> bytes:
    if not isinstance(value, Tombstone):
        raise TypeError("value must be a Tombstone")
    prefix = _PREFIX.pack(
        _MAGIC, _VERSION, SIZE, value.entry_id.bytes, value.revision,
        value.purged_at_epoch_millis, value.previous_content_digest, value.flags,
    )
    return prefix + bytes(SIZE - len(prefix))


def decode_tombstone(raw: bytes) -> Tombstone:
    if not isinstance(raw, bytes) or len(raw) != SIZE:
        raise ValueError("tombstone size is invalid")
    magic, version, declared, entry_id, revision, purged_at, digest, flags = _PREFIX.unpack_from(raw)
    if magic != _MAGIC or version != _VERSION or declared != SIZE:
        raise ValueError("tombstone header is invalid")
    if any(raw[_PREFIX.size:]):
        raise ValueError("tombstone reserved bytes are non-zero")
    return Tombstone(uuid.UUID(bytes=entry_id), revision, purged_at, digest, flags)
