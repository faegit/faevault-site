"""新一代 .pmbak 备份加密（V2 布局），与安卓端 ``storage/PmvBackupCrypto.kt`` 逐字节对齐。

布局::

    PMXB(4) | VERSION(1)=2 | KDF_ID(1)=1 | MEMORY_KIB(4 BE) | ITERATIONS(4 BE)
    | PARALLELISM(4 BE) | SALT(16) | NONCE(12) | CIPHERTEXT + GCM TAG(16)

- KDF: Argon2id v1.3（复用 :func:`pmv_key_schedule.derive_password_kek`：m=64MiB, t=3, p=1, salt=16B）
- AEAD: AES-256-GCM，AAD 绑定 MAGIC/版本/KDF 参数/salt（域前缀 ``PMV backup v2\\0``）
- 导出口令以 UTF-8 编码输入，密钥使用后立即填零

跨端契约见 ``spec/VAULT_FORMAT.md`` §7。
"""

from __future__ import annotations

import os
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import crypto
from .pmv_key_schedule import (
    ARGON2_ITERATIONS,
    ARGON2_LANES,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_SALT_SIZE,
    derive_password_kek,
)

MAGIC: Final = b"PMXB"
VERSION_V2: Final = 2
KDF_ID_ARGON2ID: Final = 1

_NONCE_SIZE: Final = 12
_GCM_TAG_BITS: Final = 128
_HEADER_SIZE: Final = 4 + 1 + 1 + 4 + 4 + 4 + ARGON2_SALT_SIZE + _NONCE_SIZE
_MIN_ENCRYPTED: Final = _HEADER_SIZE + _GCM_TAG_BITS // 8

_AAD_DOMAIN: Final = b"PMV backup v2\x00"


def _uint32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _read_uint32be(data: bytes, off: int) -> int:
    return int.from_bytes(data[off : off + 4], "big")


def _aad(salt: bytes) -> bytes:
    """域分离 AAD：绑定 MAGIC、版本、KDF 枚举与参数、salt，防止参数/盐被替换。"""
    return (
        _AAD_DOMAIN
        + MAGIC
        + bytes((VERSION_V2, KDF_ID_ARGON2ID))
        + _uint32be(ARGON2_MEMORY_COST_KIB)
        + _uint32be(ARGON2_ITERATIONS)
        + _uint32be(ARGON2_LANES)
        + salt
    )


def encrypt_v2(plaintext: bytes, password_utf8: bytes) -> bytes:
    """新格式加密打包，返回完整 PMXB v2 文件字节。

    ``password_utf8`` 为调用方提供的原始 UTF-8 字节序列（不做归一化或裁剪）。
    """
    if not isinstance(plaintext, (bytes, bytearray, memoryview)):
        raise TypeError("plaintext must be bytes-like")
    salt = os.urandom(ARGON2_SALT_SIZE)
    nonce = os.urandom(_NONCE_SIZE)
    key = derive_password_kek(bytes(password_utf8), salt)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), _aad(salt))
    finally:
        key = b"\x00" * len(key)
    return MAGIC + bytes((VERSION_V2, KDF_ID_ARGON2ID)) + (
        _uint32be(ARGON2_MEMORY_COST_KIB)
        + _uint32be(ARGON2_ITERATIONS)
        + _uint32be(ARGON2_LANES)
        + salt
        + nonce
        + ciphertext
    )


def decrypt_v2(raw: bytes, password_utf8: bytes) -> bytes:
    """新格式解密。头部不符/版本不支持/KDF 参数不符 → ``ValueError``；tag 校验失败 → :class:`crypto.DecryptError`。"""
    if type(raw) is not bytes:
        raise ValueError("raw must be bytes")
    if len(raw) < _MIN_ENCRYPTED:
        raise ValueError("文件头不匹配或数据过短")
    if raw[:4] != MAGIC:
        raise ValueError("不是有效的加密备份文件")
    if raw[4] != VERSION_V2:
        raise ValueError(f"不支持的备份版本: {raw[4]}")
    if raw[5] != KDF_ID_ARGON2ID:
        raise ValueError(f"不支持的备份 KDF: {raw[5]}")
    off = 6
    memory_kib = _read_uint32be(raw, off)
    off += 4
    iterations = _read_uint32be(raw, off)
    off += 4
    parallelism = _read_uint32be(raw, off)
    off += 4
    if (memory_kib, iterations, parallelism) != (
        ARGON2_MEMORY_COST_KIB,
        ARGON2_ITERATIONS,
        ARGON2_LANES,
    ):
        raise ValueError("不支持的备份 KDF 参数")
    salt = raw[off : off + ARGON2_SALT_SIZE]
    off += ARGON2_SALT_SIZE
    nonce = raw[off : off + _NONCE_SIZE]
    off += _NONCE_SIZE
    ciphertext = raw[off:]
    key = derive_password_kek(bytes(password_utf8), salt)
    try:
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, _aad(salt))
        except Exception as exc:  # InvalidTag 等
            raise crypto.DecryptError("备份口令错误或备份文件已损坏") from exc
    finally:
        key = b"\x00" * len(key)
        salt = b"\x00" * len(salt)