from __future__ import annotations

import json
import hashlib
from pathlib import Path
from uuid import UUID

import pytest

from core import pmv_compression, pmv_container


def _vector() -> dict:
    root = Path(__file__).resolve().parents[2] / "vault_android" / "spec" / "interop" / "pmv_next" / "v1"
    return json.loads((root / "compression.json").read_text(encoding="utf-8"))["cases"][0]


def test_shared_zstd_frame_is_byte_exact_and_round_trips() -> None:
    case = _vector()
    plain = case["inputs"]["unitUtf8"].encode() * case["inputs"]["repeat"]
    compressed = pmv_compression.compress_zstd_frame(plain)
    assert len(plain) == case["expected"]["plainSize"]
    assert compressed.hex() == case["expected"]["compressedHex"]
    assert pmv_compression.validate_single_zstd_frame(compressed) == len(plain)
    assert pmv_compression.decode(1, compressed, len(plain)) == plain


def test_adaptive_policy_and_strict_rejections() -> None:
    compressible = b"A" * 8192
    incompressible = b"".join(hashlib.sha256(index.to_bytes(4, "big")).digest() for index in range(128))
    assert pmv_compression.choose_codec(compressible) == pmv_compression.CODEC_ZSTD_FRAME_V1
    assert pmv_compression.choose_codec(incompressible) == pmv_compression.CODEC_NONE
    encoded = pmv_compression.compress_zstd_frame(compressible)
    for invalid in (encoded[:-1], encoded + b"\0", encoded + encoded):
        with pytest.raises(ValueError):
            pmv_compression.decode(1, invalid, len(compressible))
    with pytest.raises(ValueError):
        pmv_compression.decode(1, encoded, len(compressible) - 1)
    with pytest.raises(ValueError):
        pmv_compression.decode(9, encoded, len(compressible))


def test_block_aead_binds_codec_and_uncompressed_size() -> None:
    vault_id = UUID("11111111-2222-3333-4444-555555555555")
    object_id = UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    key = bytes(range(32))
    plain = b"compress me" * 4096
    block = pmv_container.seal(
        vault_id, key, pmv_container.BlockType.ATTACHMENT_CHUNK,
        object_id, 3, plain, chunk_index=0,
        codec_id=pmv_compression.CODEC_ZSTD_FRAME_V1,
    )
    assert block.header.plain_size == len(plain)
    assert block.header.cipher_size < len(plain)
    assert pmv_container.open(vault_id, key, block) == plain
    tampered = pmv_container.EncodedBlock(
        pmv_container.BlockHeader(
            **{**block.header.__dict__, "codec_id": pmv_compression.CODEC_NONE}
        ),
        block.ciphertext,
    )
    with pytest.raises(Exception):
        pmv_container.open(vault_id, key, tampered)
