"""Strict PMV block compression codecs shared with Android.

Each compressed block contains exactly one standard Zstandard frame.  Dictionaries, checksums,
concatenated frames and trailing bytes are forbidden.  The caller supplies the authenticated
uncompressed size from the PMV Block Header, so decompression is always bounded.
"""

from __future__ import annotations

import zstandard


CODEC_NONE = 0
CODEC_ZSTD_FRAME_V1 = 1
ZSTD_LEVEL = 3
SAMPLE_BYTES = 1024 * 1024
MIN_INPUT_BYTES = 4096
MIN_SAVINGS_PERCENT = 10
MAX_PLAIN_BYTES = 16 * 1024 * 1024
_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def compress_zstd_frame(plain: bytes) -> bytes:
    if not isinstance(plain, bytes):
        raise TypeError("plain must be bytes")
    if len(plain) > MAX_PLAIN_BYTES:
        raise ValueError("compression input exceeds the PMV block limit")
    return zstandard.ZstdCompressor(
        level=ZSTD_LEVEL,
        write_content_size=True,
        write_checksum=False,
        write_dict_id=False,
    ).compress(plain)


def choose_codec(plain: bytes) -> int:
    if not isinstance(plain, bytes):
        raise TypeError("plain must be bytes")
    if len(plain) < MIN_INPUT_BYTES:
        return CODEC_NONE
    sample = plain[:SAMPLE_BYTES]
    compressed = compress_zstd_frame(sample)
    return (
        CODEC_ZSTD_FRAME_V1
        if len(compressed) * 100 <= len(sample) * (100 - MIN_SAVINGS_PERCENT)
        else CODEC_NONE
    )


def encode(codec_id: int, plain: bytes) -> bytes:
    if codec_id == CODEC_NONE:
        return plain
    if codec_id == CODEC_ZSTD_FRAME_V1:
        return compress_zstd_frame(plain)
    raise ValueError("unsupported PMV compression codec")


def decode(codec_id: int, encoded: bytes, expected_plain_size: int) -> bytes:
    if type(expected_plain_size) is not int or not 0 <= expected_plain_size <= MAX_PLAIN_BYTES:
        raise ValueError("invalid decompressed PMV block size")
    if codec_id == CODEC_NONE:
        if len(encoded) != expected_plain_size:
            raise ValueError("uncompressed PMV block length mismatch")
        return encoded
    if codec_id != CODEC_ZSTD_FRAME_V1:
        raise ValueError("unsupported PMV compression codec")
    declared = validate_single_zstd_frame(encoded)
    if declared != expected_plain_size:
        raise ValueError("Zstandard content size disagrees with PMV Block Header")
    plain = zstandard.ZstdDecompressor().decompress(
        encoded,
        max_output_size=expected_plain_size,
        allow_extra_data=False,
    )
    if len(plain) != expected_plain_size:
        raise ValueError("Zstandard output length mismatch")
    return plain


def validate_single_zstd_frame(encoded: bytes) -> int:
    """Return the declared content size after proving the input is one complete frame."""
    if not isinstance(encoded, bytes) or len(encoded) < 6 or encoded[:4] != _ZSTD_MAGIC:
        raise ValueError("invalid Zstandard frame magic")
    index = 4
    descriptor = encoded[index]
    index += 1
    if descriptor & 0x18:
        raise ValueError("reserved Zstandard frame header bits are set")
    content_size_flag = descriptor >> 6
    single_segment = bool(descriptor & 0x20)
    checksum = bool(descriptor & 0x04)
    dictionary_flag = descriptor & 0x03
    if not single_segment:
        index = _advance(index, 1, len(encoded), "window descriptor")
    dictionary_size = (0, 1, 2, 4)[dictionary_flag]
    if dictionary_size:
        raise ValueError("Zstandard dictionaries are not allowed")
    index = _advance(index, dictionary_size, len(encoded), "dictionary id")
    content_size_bytes = (1 if single_segment else 0, 2, 4, 8)[content_size_flag]
    if content_size_bytes == 0:
        raise ValueError("Zstandard frame must declare content size")
    end = _advance(index, content_size_bytes, len(encoded), "content size")
    declared = int.from_bytes(encoded[index:end], "little")
    if content_size_bytes == 2:
        declared += 256
    index = end
    while True:
        end = _advance(index, 3, len(encoded), "block header")
        header = int.from_bytes(encoded[index:end], "little")
        index = end
        last_block = bool(header & 1)
        block_type = (header >> 1) & 0x03
        block_size = header >> 3
        if block_type == 3:
            raise ValueError("reserved Zstandard block type")
        payload_size = 1 if block_type == 1 else block_size
        index = _advance(index, payload_size, len(encoded), "block payload")
        if last_block:
            break
    if checksum:
        raise ValueError("Zstandard frame checksum is not allowed")
    if index != len(encoded):
        raise ValueError("concatenated or trailing Zstandard data is not allowed")
    return declared


def _advance(index: int, count: int, total: int, label: str) -> int:
    end = index + count
    if count < 0 or end < index or end > total:
        raise ValueError(f"truncated Zstandard {label}")
    return end


__all__ = [
    "CODEC_NONE", "CODEC_ZSTD_FRAME_V1", "ZSTD_LEVEL", "SAMPLE_BYTES",
    "MIN_INPUT_BYTES", "MIN_SAVINGS_PERCENT", "MAX_PLAIN_BYTES",
    "compress_zstd_frame", "choose_codec", "encode", "decode",
    "validate_single_zstd_frame",
]
