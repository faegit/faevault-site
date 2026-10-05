"""PMVE recovery-key encoding primitives for the stable PMRK1 wire format."""

from __future__ import annotations

import hashlib
import os
import re

SECRET_SIZE = 32
RECOVERY_PREFIX = "PMRK1"
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_INDEX = {char: index for index, char in enumerate(_CROCKFORD)}


class RecoveryKeyError(ValueError):
    pass


def _encode_crockford(value: bytes, width: int) -> str:
    number = int.from_bytes(value, "big")
    chars = ["0"] * width
    for index in range(width - 1, -1, -1):
        chars[index] = _CROCKFORD[number & 31]
        number >>= 5
    if number:
        raise ValueError("value does not fit Crockford width")
    return "".join(chars)


def _decode_crockford(text: str, byte_length: int) -> bytes:
    number = 0
    for char in text:
        try:
            digit = _CROCKFORD_INDEX[char]
        except KeyError as exc:
            raise RecoveryKeyError("恢复密钥包含无效字符") from exc
        number = (number << 5) | digit
    if number >= 1 << (byte_length * 8):
        raise RecoveryKeyError("恢复密钥长度或前导位无效")
    return number.to_bytes(byte_length, "big")


def _checksum(secret: bytes) -> str:
    digest = hashlib.sha256(b"PMRK1\0" + secret).digest()
    value = (int.from_bytes(digest[:3], "big") >> 4).to_bytes(3, "big")
    return _encode_crockford(value, 5)[1:]


def encode(secret: bytes) -> str:
    if type(secret) is not bytes or len(secret) != SECRET_SIZE:
        raise RecoveryKeyError("恢复密钥必须是 256 位")
    body = _encode_crockford(secret, 52) + _checksum(secret)
    groups = "-".join(body[index : index + 4] for index in range(0, len(body), 4))
    return f"{RECOVERY_PREFIX}-{groups}"


def decode(text: str) -> bytes:
    compact = re.sub(r"[-\s]", "", str(text or "")).upper()
    if not compact.startswith(RECOVERY_PREFIX):
        raise RecoveryKeyError("恢复密钥版本无效")
    encoded = compact[len(RECOVERY_PREFIX) :]
    if len(encoded) != 56:
        raise RecoveryKeyError("恢复密钥长度无效")
    secret = _decode_crockford(encoded[:52], SECRET_SIZE)
    if encoded[52:] != _checksum(secret):
        raise RecoveryKeyError("恢复密钥校验码不正确")
    return secret


def generate() -> tuple[bytes, str]:
    secret = os.urandom(SECRET_SIZE)
    return secret, encode(secret)


def fingerprint(secret: bytes) -> str:
    if type(secret) is not bytes or len(secret) != SECRET_SIZE:
        raise RecoveryKeyError("恢复密钥必须是 256 位")
    digest = hashlib.sha256(b"PMRK1 fingerprint\0" + secret).digest()
    return _encode_crockford(digest, 52)[:6]
