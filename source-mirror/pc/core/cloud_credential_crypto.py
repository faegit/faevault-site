"""Vault-bound, cross-platform encryption for individual cloud credential fields."""

from __future__ import annotations

import struct
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_SIZE = 32
NONCE_SIZE = 12
FORMAT_VERSION = 1
AAD_DOMAIN = b"pmv/cloud-credential\0"
CLOUD_CREDENTIAL_INFO = b"pmv/v1/cloud-credentials"


def derive_cloud_credential_key(key_wrap_key: bytes) -> bytes:
    if type(key_wrap_key) is not bytes or len(key_wrap_key) != KEY_SIZE:
        raise ValueError("key_wrap_key must be exactly 32 bytes")
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=bytes(KEY_SIZE),
        info=CLOUD_CREDENTIAL_INFO,
    ).derive(key_wrap_key)


def field_aad(vault_id: UUID, provider: str, field: str, field_version: int) -> bytes:
    if not isinstance(vault_id, UUID):
        raise TypeError("vault_id must be a UUID")
    if not provider or not field or "\0" in provider or "\0" in field:
        raise ValueError("provider and field must be non-empty and contain no NUL")
    if type(field_version) is not int or field_version <= 0:
        raise ValueError("field_version must be positive")
    return (
        AAD_DOMAIN + struct.pack(">I", FORMAT_VERSION) + vault_id.bytes
        + provider.encode("utf-8") + b"\0" + field.encode("utf-8") + b"\0"
        + struct.pack(">I", field_version)
    )


def seal_field(key: bytes, vault_id: UUID, provider: str, field: str,
               field_version: int, plaintext_utf8: bytes, nonce: bytes) -> bytes:
    if type(key) is not bytes or len(key) != KEY_SIZE:
        raise ValueError("cloud credential key must be exactly 32 bytes")
    if type(plaintext_utf8) is not bytes:
        raise TypeError("plaintext_utf8 must be bytes")
    if type(nonce) is not bytes or len(nonce) != NONCE_SIZE:
        raise ValueError("nonce must be exactly 12 bytes")
    return nonce + AESGCM(key).encrypt(
        nonce, plaintext_utf8, field_aad(vault_id, provider, field, field_version)
    )


def open_field(key: bytes, vault_id: UUID, provider: str, field: str,
               field_version: int, packed: bytes) -> bytes:
    if type(key) is not bytes or len(key) != KEY_SIZE:
        raise ValueError("cloud credential key must be exactly 32 bytes")
    if type(packed) is not bytes or len(packed) < NONCE_SIZE + 16:
        raise ValueError("invalid encrypted cloud credential field")
    nonce, ciphertext = packed[:NONCE_SIZE], packed[NONCE_SIZE:]
    return AESGCM(key).decrypt(
        nonce, ciphertext, field_aad(vault_id, provider, field, field_version)
    )
