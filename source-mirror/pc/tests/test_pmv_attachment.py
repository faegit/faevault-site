import io
import uuid

import pytest

from core.pmv_attachment import (
    CHUNK_SIZE, AttachmentKind, AttachmentManifest, ChunkFailure, ChunkRecord,
    decode_manifest, encode_manifest, open_to, seal_from,
)
from core.pmv_container import EncodedBlock


VAULT_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
OBJECT_ID = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")


def key(index: int) -> bytes:
    return bytes((value + index) & 0xFF for value in range(32))


def test_multichunk_stream_round_trip_and_canonical_layout():
    plain = bytes(value & 0xFF for value in range(CHUNK_SIZE + 17))
    blocks = []
    manifest = seal_from(io.BytesIO(plain), len(plain), VAULT_ID, OBJECT_ID, 7,
                         AttachmentKind.ATTACHMENT, key, blocks.append)
    assert len(blocks) == 2
    encoded = encode_manifest(manifest)
    assert encoded[:4] == b"PMOA"
    assert encode_manifest(decode_manifest(encoded)) == encoded
    output = io.BytesIO()
    open_to(manifest, VAULT_ID, key, blocks.__getitem__, output)
    assert output.getvalue() == plain


def test_tamper_reports_exact_chunk_and_does_not_fetch_later_data():
    blocks = []
    plain = bytes(CHUNK_SIZE + 2)
    manifest = seal_from(io.BytesIO(plain), len(plain), VAULT_ID, OBJECT_ID, 1,
                         AttachmentKind.IMAGE, key, blocks.append)
    damaged = bytearray(blocks[1].ciphertext)
    damaged[0] ^= 1
    blocks[1] = EncodedBlock(blocks[1].header, damaged)
    requested = []
    with pytest.raises(ChunkFailure) as caught:
        open_to(manifest, VAULT_ID, key, lambda index: (requested.append(index), blocks[index])[1], io.BytesIO())
    assert caught.value.chunk_index == 1
    assert requested == [0, 1]


def test_rejects_out_of_order_bounds_and_reserved_bytes():
    digest = bytes(32)
    with pytest.raises(ValueError):
        AttachmentManifest(OBJECT_ID, 0, AttachmentKind.IMAGE, 1, digest,
                           (ChunkRecord(1, 1, digest),))
    valid = AttachmentManifest(OBJECT_ID, 0, AttachmentKind.IMAGE, 1, digest,
                               (ChunkRecord(0, 1, digest),))
    encoded = bytearray(encode_manifest(valid))
    encoded[88] = 1
    with pytest.raises(ValueError):
        decode_manifest(encoded)


def test_android_and_pc_manifest_bytes_are_fixed_big_endian():
    manifest = AttachmentManifest(OBJECT_ID, 7, AttachmentKind.ATTACHMENT, 1, bytes(range(32)),
                                  (ChunkRecord(0, 1, bytes(reversed(range(32)))),))
    encoded = encode_manifest(manifest)
    assert encoded.hex() == (
        "504d4f4100000001102132435465768798a9bacbdcedfe0f0000000000000007"
        "020000000000000000000000000000010080000000000001"
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        "0000000000000000"
        "00000000000000011f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
        "0000000000000000"
    )


def test_ten_gib_manifest_does_not_allocate_attachment_contents():
    total = 10 * 1024 * 1024 * 1024
    count = (total - 1) // CHUNK_SIZE + 1
    chunks = tuple(ChunkRecord(index, total - index * CHUNK_SIZE if index == count - 1 else CHUNK_SIZE,
                               bytes(32)) for index in range(count))
    encoded = encode_manifest(AttachmentManifest(OBJECT_ID, 2, AttachmentKind.ATTACHMENT,
                                                 total, bytes(32), chunks))
    assert len(encoded) == 96 + count * 48
