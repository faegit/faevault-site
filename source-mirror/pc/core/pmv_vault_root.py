"""Fixed 16 KiB composite PMV vault root shared with Android.

Wire-u64 offsets and lengths use the portable ``0..Long.MAX_VALUE`` subset.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum

from .pmv_container import DATA_START

PAGE_SIZE = 16 * 1024
_MAGIC = b"PMVR"
_VERSION = 1
_HEADER = struct.Struct(">4sIIIqq")
_REF = struct.Struct(">BB6sqq32sq")
_DOMAIN = b"pmv/v1/vault-root\0"
_MAX_WIRE_LONG = (1 << 63) - 1


def _require_wire_long(value: object, label: str, *, minimum: int) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not minimum <= value <= _MAX_WIRE_LONG:
        raise ValueError(f"{label} must be between {minimum} and 2^63 - 1")
    return value


class RootType(IntEnum):
    ENTRY = 1
    LOGIN = 2
    OBJECT = 3
    CHUNK = 4
    METADATA = 5


@dataclass(frozen=True, slots=True)
class RootReference:
    type: RootType
    offset: int
    length: int
    digest: bytes
    def __post_init__(self) -> None:
        if not isinstance(self.type, RootType):
            raise ValueError("invalid vault-root reference")
        checked_offset = _require_wire_long(self.offset, "offset", minimum=DATA_START)
        checked_length = _require_wire_long(self.length, "length", minimum=1)
        if checked_offset > _MAX_WIRE_LONG - checked_length:
            raise ValueError("vault-root reference range exceeds the cross-runtime signed 64-bit range")
        if type(self.digest) is not bytes or len(self.digest) != 32:
            raise ValueError("vault-root digest must be 32 bytes")


@dataclass(frozen=True, slots=True)
class VaultRoot:
    entry: RootReference
    login: RootReference | None = None
    object_index: RootReference | None = None
    chunk_index: RootReference | None = None
    metadata: RootReference | None = None
    def __post_init__(self) -> None:
        expected = (RootType.ENTRY, RootType.LOGIN, RootType.OBJECT, RootType.CHUNK, RootType.METADATA)
        for value, kind in zip(self.references(), expected):
            if kind is RootType.ENTRY and value is None:
                raise ValueError("entry root is required")
            if value is not None and value.type is not kind:
                raise ValueError("vault-root reference type mismatch")
    def references(self):
        return (self.entry, self.login, self.object_index, self.chunk_index, self.metadata)


def encode_vault_root(root: VaultRoot) -> bytes:
    output = bytearray(PAGE_SIZE)
    _HEADER.pack_into(output, 0, _MAGIC, _VERSION, PAGE_SIZE, 5, 0, 0)
    position = _HEADER.size
    for kind, value in zip(RootType, root.references()):
        _REF.pack_into(output, position, int(value is not None), int(kind), bytes(6),
                       value.offset if value else 0, value.length if value else 0,
                       value.digest if value else bytes(32), 0)
        position += _REF.size
    return bytes(output)


def decode_vault_root(raw: bytes) -> VaultRoot:
    if type(raw) is not bytes or len(raw) != PAGE_SIZE:
        raise ValueError("invalid vault-root page size")
    magic, version, size, count, r1, r2 = _HEADER.unpack_from(raw)
    if (magic, version, size, count, r1, r2) != (_MAGIC, _VERSION, PAGE_SIZE, 5, 0, 0):
        raise ValueError("invalid vault-root header")
    refs = []
    position = _HEADER.size
    for expected in RootType:
        present, kind, reserved, offset, length, digest, tail = _REF.unpack_from(raw, position)
        position += _REF.size
        if present not in (0, 1) or kind != int(expected) or reserved != bytes(6) or tail != 0:
            raise ValueError("invalid vault-root reference")
        if not present:
            if offset != 0 or length != 0 or digest != bytes(32):
                raise ValueError("absent vault-root reference is not canonical zero")
            refs.append(None)
        else:
            refs.append(RootReference(expected, offset, length, digest))
    if any(raw[position:]):
        raise ValueError("vault-root trailing reserved bytes are non-zero")
    if refs[0] is None:
        raise ValueError("entry root is required")
    return VaultRoot(refs[0], refs[1], refs[2], refs[3], refs[4])


def logical_root_digest(root: VaultRoot) -> bytes:
    canonical = bytearray(_DOMAIN)
    for kind, value in zip(RootType, root.references()):
        canonical += struct.pack(">BBq32s", int(kind), int(value is not None),
                                 value.length if value else 0, value.digest if value else bytes(32))
    return hashlib.sha256(canonical).digest()


class PmvVaultRootCodec:
    PAGE_SIZE = PAGE_SIZE
    RootType = RootType
    Reference = RootReference
    Root = VaultRoot
    encode = staticmethod(encode_vault_root)
    decode = staticmethod(decode_vault_root)
    logical_digest = staticmethod(logical_root_digest)
