from __future__ import annotations

import struct
import uuid
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.pmv_commit import (
    COMMIT_PLAIN_SIZE,
    Commit,
    canonical_signing_bytes,
    decode_commit,
    encode_commit,
    sign_commit,
    verify_commit_signature,
)
from core.pmv_container import DATA_START


VAULT_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
COMMIT_ID = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")
PARENT_ID = uuid.UUID("ffeeddcc-bbaa-9988-7766-554433221100")
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def _unsigned(parent: uuid.UUID | None = PARENT_ID) -> Commit:
    return Commit(
        vault_id=VAULT_ID,
        commit_id=COMMIT_ID,
        parent_commit_id=parent,
        revision=0x0102030405060708,
        index_root_offset=DATA_START,
        index_root_length=16_528,
        root_digest=bytes(range(32)),
        signing_public_key=bytes(32),
        signature=bytes(64),
    )


def _signed(parent: uuid.UUID | None = PARENT_ID) -> Commit:
    return sign_commit(_unsigned(parent), PRIVATE_KEY)


def test_canonical_signing_bytes_exact_layout_with_parent() -> None:
    actual = canonical_signing_bytes(
        VAULT_ID,
        COMMIT_ID,
        PARENT_ID,
        0x0102030405060708,
        bytes(range(32)),
    )
    assert actual == (
        b"pmv/v1/commit\0"
        + VAULT_ID.bytes
        + COMMIT_ID.bytes
        + b"\x01"
        + PARENT_ID.bytes
        + bytes.fromhex("0102030405060708")
        + bytes(range(32))
    )


def test_canonical_signing_bytes_exact_layout_without_parent() -> None:
    actual = canonical_signing_bytes(VAULT_ID, COMMIT_ID, None, 0, bytes(32))
    assert actual == (
        b"pmv/v1/commit\0"
        + VAULT_ID.bytes
        + COMMIT_ID.bytes
        + b"\x00"
        + bytes(16)
        + bytes(8)
        + bytes(32)
    )


@pytest.mark.parametrize("parent", [PARENT_ID, None])
def test_commit_round_trip_and_signature(parent: uuid.UUID | None) -> None:
    commit = _signed(parent)
    encoded = encode_commit(commit)
    assert len(encoded) == COMMIT_PLAIN_SIZE
    assert encoded[:16] == b"PMVC" + struct.pack(">III", 1, COMMIT_PLAIN_SIZE, 0)
    assert decode_commit(encoded) == commit
    verify_commit_signature(commit)


@pytest.mark.parametrize(
    ("offset", "replacement", "message"),
    [
        (0, b"BAD!", "magic"),
        (4, struct.pack(">I", 2), "version"),
        (8, struct.pack(">I", 223), "declared size"),
        (12, struct.pack(">I", 1), "reserved"),
        (49, b"\x01", "reserved"),
    ],
)
def test_decode_rejects_invalid_header_fields(
    offset: int, replacement: bytes, message: str
) -> None:
    encoded = bytearray(encode_commit(_signed()))
    encoded[offset : offset + len(replacement)] = replacement
    with pytest.raises(ValueError, match=message):
        decode_commit(bytes(encoded))


def test_decode_rejects_invalid_parent_encoding() -> None:
    encoded = bytearray(encode_commit(_signed(None)))
    encoded[48] = 2
    with pytest.raises(ValueError, match="parent-present"):
        decode_commit(bytes(encoded))

    encoded = bytearray(encode_commit(_signed(None)))
    encoded[56] = 1
    with pytest.raises(ValueError, match="parentless"):
        decode_commit(bytes(encoded))


@pytest.mark.parametrize(
    "offset",
    [
        16,   # vault UUID
        32,   # commit UUID
        56,   # parent UUID
        72,   # revision
        96,   # root digest
        128,  # public key
        160,  # signature
    ],
)
def test_decode_rejects_tampering(offset: int) -> None:
    encoded = bytearray(encode_commit(_signed()))
    encoded[offset] ^= 1
    with pytest.raises(ValueError):
        decode_commit(bytes(encoded))


def test_index_location_is_integrity_checked_even_though_not_signed() -> None:
    encoded = bytearray(encode_commit(_signed()))
    encoded[88:96] = (1).to_bytes(8, "big")
    with pytest.raises(ValueError, match="block length"):
        decode_commit(bytes(encoded))


def test_rejects_wrong_plaintext_length_and_types() -> None:
    with pytest.raises(ValueError, match="size"):
        decode_commit(bytes(COMMIT_PLAIN_SIZE - 1))
    with pytest.raises(TypeError, match="bytes"):
        decode_commit(bytearray(COMMIT_PLAIN_SIZE))  # type: ignore[arg-type]


def test_commit_rejects_self_parent_and_invalid_unsigned_ranges() -> None:
    with pytest.raises(ValueError, match="own parent"):
        replace(_unsigned(), parent_commit_id=COMMIT_ID)
    with pytest.raises(ValueError, match=r"2\^63"):
        canonical_signing_bytes(VAULT_ID, COMMIT_ID, None, -1, bytes(32))
    with pytest.raises(ValueError, match=r"2\^63"):
        canonical_signing_bytes(VAULT_ID, COMMIT_ID, None, 1 << 63, bytes(32))
    with pytest.raises(TypeError, match="integer"):
        canonical_signing_bytes(VAULT_ID, COMMIT_ID, None, True, bytes(32))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("revision", 1 << 63),
        ("index_root_offset", 1 << 63),
        ("index_root_length", 1 << 63),
        ("revision", True),
        ("index_root_offset", True),
        ("index_root_length", True),
    ],
)
def test_commit_rejects_values_android_long_cannot_represent(field: str, value: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(_unsigned(), **{field: value})


def test_encode_refuses_unsigned_commit() -> None:
    with pytest.raises(ValueError, match="signature verification"):
        encode_commit(_unsigned())
