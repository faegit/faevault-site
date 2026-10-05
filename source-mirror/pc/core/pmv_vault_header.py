"""Fixed 4 KiB PMV v1 bootstrap header and RootKey envelopes.

The two PMVH slots occupy 8192/12288 after the 0/4096 superblock slots;
encrypted blocks begin at the shared 16 KiB data boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
import struct
from typing import Callable
from uuid import UUID

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core.pmv_container import (
    VAULT_HEADER_PRIMARY_OFFSET,
    VAULT_HEADER_SECONDARY_OFFSET,
    VAULT_HEADER_SIZE,
)
from core.pmv_key_schedule import (
    ARGON2_SALT_SIZE,
    KEY_SIZE,
    derive_password_kek,
    derive_root_keys,
)
from core.pmv_kdf_policy import PmvKdfParameters, PmvKdfPolicy, PmvKdfProfile

HEADER_SIZE = VAULT_HEADER_SIZE
VERSION = 1
SUITE_1 = 1
PASSWORD_KDF_ARGON2ID = 1
RECOVERY_KDF_HKDF_SHA256 = 2
SIGNING_KDF_KEY_WRAP = 3
PRIMARY_OFFSET = VAULT_HEADER_PRIMARY_OFFSET
SECONDARY_OFFSET = VAULT_HEADER_SECONDARY_OFFSET

_MAGIC = b"PMVH"
_AAD_DOMAIN = b"pmv/v1/vault-header-envelope\0"
_RECOVERY_INFO = b"pmv/v1/recovery-kek"
_AUTH_SIZE = 32
_AUTH_OFFSET = HEADER_SIZE - _AUTH_SIZE
_NONCE_SIZE = 12
_ENVELOPE_CIPHER_SIZE = KEY_SIZE + 16
_ENVELOPE_SIZE = _NONCE_SIZE + _ENVELOPE_CIPHER_SIZE
_PASSWORD_ENVELOPE_OFFSET = 112
_RECOVERY_ENVELOPE_OFFSET = _PASSWORD_ENVELOPE_OFFSET + _ENVELOPE_SIZE
_SIGNING_ENVELOPE_OFFSET = _RECOVERY_ENVELOPE_OFFSET + _ENVELOPE_SIZE
_RESERVED_OFFSET = _SIGNING_ENVELOPE_OFFSET + _ENVELOPE_SIZE


@dataclass(frozen=True, slots=True)
class Envelope:
    nonce: bytes
    ciphertext: bytes

    def __post_init__(self) -> None:
        _bytes(self.nonce, "nonce", _NONCE_SIZE)
        _bytes(self.ciphertext, "ciphertext", _ENVELOPE_CIPHER_SIZE)


@dataclass(frozen=True, slots=True)
class Header:
    vault_id: UUID
    key_revision: int
    header_revision: int
    kdf_parameters: PmvKdfParameters
    salt: bytes
    signing_public_key: bytes
    password_envelope: Envelope
    recovery_envelope: Envelope
    signing_seed_envelope: Envelope

    def __post_init__(self) -> None:
        if not isinstance(self.vault_id, UUID):
            raise TypeError("vault_id must be a UUID")
        _revision(self.key_revision, "key_revision")
        _revision(self.header_revision, "header_revision")
        PmvKdfPolicy.validate(self.kdf_parameters)
        _bytes(self.salt, "salt", ARGON2_SALT_SIZE)
        public = _bytes(self.signing_public_key, "signing_public_key", 32)
        if not any(public):
            raise ValueError("invalid Ed25519 public key")


@dataclass(frozen=True, slots=True)
class Nonces:
    password: bytes
    recovery: bytes
    signing_seed: bytes

    def __post_init__(self) -> None:
        _bytes(self.password, "password nonce", _NONCE_SIZE)
        _bytes(self.recovery, "recovery nonce", _NONCE_SIZE)
        _bytes(self.signing_seed, "signing seed nonce", _NONCE_SIZE)

    @classmethod
    def random(cls) -> "Nonces":
        return cls(os.urandom(_NONCE_SIZE), os.urandom(_NONCE_SIZE), os.urandom(_NONCE_SIZE))


@dataclass(frozen=True, slots=True)
class UnlockedHeader:
    header: Header
    vault_root_key: bytes
    signing_private_seed: bytes
    superblock_authentication_key: bytes


def create_header(
    *,
    vault_id: UUID,
    key_revision: int,
    header_revision: int,
    password_utf8: bytes,
    recovery_secret: bytes,
    vault_root_key: bytes,
    signing_private_seed: bytes,
    salt: bytes,
    nonces: Nonces | None = None,
    kdf_parameters: PmvKdfParameters = PmvKdfProfile.STANDARD.parameters,
) -> bytes:
    recovery = _bytes(recovery_secret, "recovery_secret", KEY_SIZE)
    root = _bytes(vault_root_key, "vault_root_key", KEY_SIZE)
    seed = _bytes(signing_private_seed, "signing_private_seed", 32)
    checked_salt = _bytes(salt, "salt", ARGON2_SALT_SIZE)
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    chosen_nonces = nonces or Nonces.random()
    PmvKdfPolicy.validate(kdf_parameters)
    password_kek = derive_password_kek(_bytes(password_utf8, "password_utf8"), checked_salt, kdf_parameters)
    recovery_kek = derive_recovery_kek(recovery, vault_id)
    root_keys = derive_root_keys(root, vault_id)
    header = Header(
        vault_id=vault_id,
        key_revision=key_revision,
        header_revision=header_revision,
        kdf_parameters=kdf_parameters,
        salt=checked_salt,
        signing_public_key=public_key,
        password_envelope=_seal(password_kek, chosen_nonces.password, root, _aad(vault_id, key_revision, public_key, 1, checked_salt, kdf_parameters)),
        recovery_envelope=_seal(recovery_kek, chosen_nonces.recovery, root, _aad(vault_id, key_revision, public_key, 2, vault_id.bytes)),
        signing_seed_envelope=_seal(root_keys.key_wrap_key, chosen_nonces.signing_seed, seed, _aad(vault_id, key_revision, public_key, 3, vault_id.bytes)),
    )
    return _encode_authenticated(header, root_keys.integrity_key)


def decode_header(raw: bytes) -> Header:
    value = _bytes(raw, "raw", HEADER_SIZE)
    if value[:4] != _MAGIC:
        raise ValueError("invalid PMVH magic")
    version, size, suite = struct.unpack_from(">III", value, 4)
    if version != VERSION:
        raise ValueError("unsupported PMVH version")
    if size != HEADER_SIZE:
        raise ValueError("invalid PMVH header size")
    if suite != SUITE_1:
        raise ValueError("unsupported PMVH crypto suite")
    vault_id = UUID(bytes=value[16:32])
    key_revision, header_revision = struct.unpack_from(">QQ", value, 32)
    kdf_id, memory, iterations, lanes = struct.unpack_from(">IIII", value, 48)
    if kdf_id != PASSWORD_KDF_ARGON2ID:
        raise ValueError("unsupported PMVH password KDF")
    kdf_parameters = PmvKdfParameters(memory, iterations, lanes)
    PmvKdfPolicy.validate(kdf_parameters)
    salt = value[64:80]
    public_key = value[80:112]
    if not any(public_key):
        raise ValueError("invalid Ed25519 public key")
    if any(value[_RESERVED_OFFSET:_AUTH_OFFSET]):
        raise ValueError("PMVH reserved bytes must be zero")
    return Header(
        vault_id=vault_id,
        key_revision=key_revision,
        header_revision=header_revision,
        kdf_parameters=kdf_parameters,
        salt=salt,
        signing_public_key=public_key,
        password_envelope=_read_envelope(value, _PASSWORD_ENVELOPE_OFFSET),
        recovery_envelope=_read_envelope(value, _RECOVERY_ENVELOPE_OFFSET),
        signing_seed_envelope=_read_envelope(value, _SIGNING_ENVELOPE_OFFSET),
    )


def unlock_with_password(raw: bytes, password_utf8: bytes) -> UnlockedHeader:
    header = decode_header(raw)
    kek = derive_password_kek(_bytes(password_utf8, "password_utf8"), header.salt, header.kdf_parameters)
    return _unlock(raw, header, kek, 1)


def unlock_with_recovery(raw: bytes, recovery_secret: bytes) -> UnlockedHeader:
    header = decode_header(raw)
    kek = derive_recovery_kek(_bytes(recovery_secret, "recovery_secret", KEY_SIZE), header.vault_id)
    return _unlock(raw, header, kek, 2)


def unlock_with_root_key(raw: bytes, vault_root_key: bytes) -> UnlockedHeader:
    """Authenticate a complete header and unwrap its signing seed from a held RootKey."""
    header = decode_header(raw)
    root = bytes(bytearray(_bytes(vault_root_key, "vault_root_key", KEY_SIZE)))
    return _unlock_with_verified_root(raw, header, root)


def rewrap_password(
    raw: bytes,
    old_password_utf8: bytes,
    new_password_utf8: bytes,
    new_salt: bytes,
    new_header_revision: int,
    new_nonce: bytes | None = None,
    *,
    target_parameters: PmvKdfParameters | None = None,
) -> bytes:
    unlocked = unlock_with_password(raw, old_password_utf8)
    if new_header_revision <= unlocked.header.header_revision:
        raise ValueError("header revision must increase")
    checked_salt = _bytes(new_salt, "new_salt", ARGON2_SALT_SIZE)
    nonce = _bytes(new_nonce if new_nonce is not None else os.urandom(_NONCE_SIZE), "new_nonce", _NONCE_SIZE)
    old = unlocked.header
    parameters = target_parameters or old.kdf_parameters
    PmvKdfPolicy.validate(parameters)
    kek = derive_password_kek(_bytes(new_password_utf8, "new_password_utf8"), checked_salt, parameters)
    updated = Header(
        vault_id=old.vault_id,
        key_revision=old.key_revision,
        header_revision=new_header_revision,
        kdf_parameters=parameters,
        salt=checked_salt,
        signing_public_key=old.signing_public_key,
        password_envelope=_seal(kek, nonce, unlocked.vault_root_key, _aad(old.vault_id, old.key_revision, old.signing_public_key, 1, checked_salt, parameters)),
        recovery_envelope=old.recovery_envelope,
        signing_seed_envelope=old.signing_seed_envelope,
    )
    return _encode_authenticated(updated, unlocked.superblock_authentication_key)


def rewrap_recovery(
    raw: bytes,
    old_recovery_secret: bytes,
    new_recovery_secret: bytes,
    new_header_revision: int,
    new_nonce: bytes | None = None,
) -> bytes:
    """Rotate recovery credentials without changing the RootKey, signer, or password slot."""
    unlocked = unlock_with_recovery(raw, old_recovery_secret)
    if new_header_revision <= unlocked.header.header_revision:
        raise ValueError("header revision must increase")
    secret = _bytes(new_recovery_secret, "new_recovery_secret", KEY_SIZE)
    nonce = _bytes(new_nonce if new_nonce is not None else os.urandom(_NONCE_SIZE), "new_nonce", _NONCE_SIZE)
    old = unlocked.header
    recovery_kek = derive_recovery_kek(secret, old.vault_id)
    updated = Header(
        vault_id=old.vault_id,
        key_revision=old.key_revision,
        header_revision=new_header_revision,
        kdf_parameters=old.kdf_parameters,
        salt=old.salt,
        signing_public_key=old.signing_public_key,
        password_envelope=old.password_envelope,
        recovery_envelope=_seal(
            recovery_kek,
            nonce,
            unlocked.vault_root_key,
            _aad(old.vault_id, old.key_revision, old.signing_public_key, 2, old.vault_id.bytes),
        ),
        signing_seed_envelope=old.signing_seed_envelope,
    )
    return _encode_authenticated(updated, unlocked.superblock_authentication_key)


def rewrap_recovery_with_password(
    raw: bytes,
    password_utf8: bytes,
    new_recovery_secret: bytes,
    new_header_revision: int,
    new_nonce: bytes | None = None,
) -> bytes:
    """Rotate recovery credentials using the master password (no old recovery key needed)."""
    unlocked = unlock_with_password(raw, password_utf8)
    if new_header_revision <= unlocked.header.header_revision:
        raise ValueError("header revision must increase")
    secret = _bytes(new_recovery_secret, "new_recovery_secret", KEY_SIZE)
    nonce = _bytes(new_nonce if new_nonce is not None else os.urandom(_NONCE_SIZE), "new_nonce", _NONCE_SIZE)
    old = unlocked.header
    recovery_kek = derive_recovery_kek(secret, old.vault_id)
    updated = Header(
        vault_id=old.vault_id,
        key_revision=old.key_revision,
        header_revision=new_header_revision,
        kdf_parameters=old.kdf_parameters,
        salt=old.salt,
        signing_public_key=old.signing_public_key,
        password_envelope=old.password_envelope,
        recovery_envelope=_seal(
            recovery_kek,
            nonce,
            unlocked.vault_root_key,
            _aad(old.vault_id, old.key_revision, old.signing_public_key, 2, old.vault_id.bytes),
        ),
        signing_seed_envelope=old.signing_seed_envelope,
    )
    return _encode_authenticated(updated, unlocked.superblock_authentication_key)


def rewrap_password_with_recovery(
    raw: bytes,
    recovery_secret: bytes,
    new_password_utf8: bytes,
    new_salt: bytes,
    new_header_revision: int,
    new_nonce: bytes | None = None,
    *,
    target_parameters: PmvKdfParameters | None = None,
) -> bytes:
    """Install a new password envelope after authenticating with recovery."""
    unlocked = unlock_with_recovery(raw, recovery_secret)
    if new_header_revision <= unlocked.header.header_revision:
        raise ValueError("header revision must increase")
    checked_salt = _bytes(new_salt, "new_salt", ARGON2_SALT_SIZE)
    nonce = _bytes(new_nonce if new_nonce is not None else os.urandom(_NONCE_SIZE), "new_nonce", _NONCE_SIZE)
    old = unlocked.header
    parameters = target_parameters or old.kdf_parameters
    PmvKdfPolicy.validate(parameters)
    kek = derive_password_kek(_bytes(new_password_utf8, "new_password_utf8"), checked_salt, parameters)
    updated = Header(
        vault_id=old.vault_id,
        key_revision=old.key_revision,
        header_revision=new_header_revision,
        kdf_parameters=parameters,
        salt=checked_salt,
        signing_public_key=old.signing_public_key,
        password_envelope=_seal(
            kek,
            nonce,
            unlocked.vault_root_key,
            _aad(old.vault_id, old.key_revision, old.signing_public_key, 1, checked_salt, parameters),
        ),
        recovery_envelope=old.recovery_envelope,
        signing_seed_envelope=old.signing_seed_envelope,
    )
    return _encode_authenticated(updated, unlocked.superblock_authentication_key)


def unlock_candidates_with_password(slot_a: bytes, slot_b: bytes, password_utf8: bytes) -> list[UnlockedHeader]:
    return _unlock_candidates(slot_a, slot_b, lambda value: unlock_with_password(value, password_utf8))


def unlock_candidates_with_recovery(slot_a: bytes, slot_b: bytes, recovery_secret: bytes) -> list[UnlockedHeader]:
    return _unlock_candidates(slot_a, slot_b, lambda value: unlock_with_recovery(value, recovery_secret))


def unlock_candidates_with_root_key(slot_a: bytes, slot_b: bytes, vault_root_key: bytes) -> list[UnlockedHeader]:
    return _unlock_candidates(slot_a, slot_b, lambda value: unlock_with_root_key(value, vault_root_key))


def select_latest_with_password(slot_a: bytes, slot_b: bytes, password_utf8: bytes) -> UnlockedHeader | None:
    candidates = unlock_candidates_with_password(slot_a, slot_b, password_utf8)
    return candidates[0] if candidates else None


def select_latest_with_recovery(slot_a: bytes, slot_b: bytes, recovery_secret: bytes) -> UnlockedHeader | None:
    candidates = unlock_candidates_with_recovery(slot_a, slot_b, recovery_secret)
    return candidates[0] if candidates else None


def derive_recovery_kek(recovery_secret: bytes, vault_id: UUID) -> bytes:
    secret = _bytes(recovery_secret, "recovery_secret", KEY_SIZE)
    if not isinstance(vault_id, UUID):
        raise TypeError("vault_id must be a UUID")
    return HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=vault_id.bytes, info=_RECOVERY_INFO).derive(secret)


def _unlock(raw: bytes, header: Header, kek: bytes, slot: int) -> UnlockedHeader:
    envelope = header.password_envelope if slot == 1 else header.recovery_envelope
    salt = header.salt if slot == 1 else header.vault_id.bytes
    try:
        root = AESGCM(kek).decrypt(
            envelope.nonce,
            envelope.ciphertext,
            _aad(
                header.vault_id,
                header.key_revision,
                header.signing_public_key,
                slot,
                salt,
                header.kdf_parameters if slot == 1 else None,
            ),
        )
    except Exception as error:
        raise ValueError("PMVH credential or envelope authentication failed") from error
    return _unlock_with_verified_root(raw, header, root)


def _unlock_with_verified_root(raw: bytes, header: Header, root: bytes) -> UnlockedHeader:
    root_keys = derive_root_keys(root, header.vault_id)
    expected_auth = hmac.new(root_keys.integrity_key, raw[:_AUTH_OFFSET], hashlib.sha256).digest()
    if not hmac.compare_digest(expected_auth, raw[_AUTH_OFFSET:]):
        raise ValueError("PMVH authentication failed")
    try:
        seed = AESGCM(root_keys.key_wrap_key).decrypt(
            header.signing_seed_envelope.nonce,
            header.signing_seed_envelope.ciphertext,
            _aad(header.vault_id, header.key_revision, header.signing_public_key, 3, header.vault_id.bytes),
        )
    except Exception as error:
        raise ValueError("PMVH signing envelope authentication failed") from error
    public_key = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
    if not hmac.compare_digest(public_key, header.signing_public_key):
        raise ValueError("PMVH signing seed does not match public key")
    return UnlockedHeader(header, root, seed, root_keys.integrity_key)


def _unlock_candidates(slot_a: bytes, slot_b: bytes, unlocker: Callable[[bytes], UnlockedHeader]) -> list[UnlockedHeader]:
    candidates: list[UnlockedHeader] = []
    for slot in (slot_a, slot_b):
        try:
            candidates.append(unlocker(slot))
        except (TypeError, ValueError):
            pass
    candidates.sort(key=lambda item: (item.header.header_revision, item.header.key_revision), reverse=True)
    return candidates


def _encode_authenticated(header: Header, integrity_key: bytes) -> bytes:
    key = _bytes(integrity_key, "integrity_key", KEY_SIZE)
    output = bytearray(HEADER_SIZE)
    params = header.kdf_parameters
    struct.pack_into(">4sIII16sQQIIII16s32s", output, 0, _MAGIC, VERSION, HEADER_SIZE, SUITE_1, header.vault_id.bytes,
                     header.key_revision, header.header_revision, PASSWORD_KDF_ARGON2ID, params.memory_kib,
                     params.iterations, params.parallelism, header.salt, header.signing_public_key)
    _write_envelope(output, _PASSWORD_ENVELOPE_OFFSET, header.password_envelope)
    _write_envelope(output, _RECOVERY_ENVELOPE_OFFSET, header.recovery_envelope)
    _write_envelope(output, _SIGNING_ENVELOPE_OFFSET, header.signing_seed_envelope)
    output[_AUTH_OFFSET:] = hmac.new(key, output[:_AUTH_OFFSET], hashlib.sha256).digest()
    return bytes(output)


def _aad(
    vault_id: UUID,
    key_revision: int,
    public_key: bytes,
    slot: int,
    salt: bytes,
    password_parameters: PmvKdfParameters | None = None,
) -> bytes:
    if slot == 1:
        parameters = password_parameters or PmvKdfProfile.STANDARD.parameters
        PmvKdfPolicy.validate(parameters)
        kdf_id, params = PASSWORD_KDF_ARGON2ID, (
            parameters.memory_kib,
            parameters.iterations,
            parameters.parallelism,
        )
    elif slot == 2:
        kdf_id, params = RECOVERY_KDF_HKDF_SHA256, (0, 0, 0)
    elif slot == 3:
        kdf_id, params = SIGNING_KDF_KEY_WRAP, (0, 0, 0)
    else:
        raise ValueError("unknown PMVH slot")
    return _AAD_DOMAIN + struct.pack(">4sII16sIIIII16sQ32s", _MAGIC, VERSION, SUITE_1, vault_id.bytes, slot, kdf_id,
                                     *params, _bytes(salt, "KDF salt", 16), _revision(key_revision, "key_revision"),
                                     _bytes(public_key, "public_key", 32))


def _seal(key: bytes, nonce: bytes, plain: bytes, aad: bytes) -> Envelope:
    checked_key = _bytes(key, "key", KEY_SIZE)
    checked_nonce = _bytes(nonce, "nonce", _NONCE_SIZE)
    checked_plain = _bytes(plain, "plain", KEY_SIZE)
    return Envelope(checked_nonce, AESGCM(checked_key).encrypt(checked_nonce, checked_plain, aad))


def _read_envelope(raw: bytes, offset: int) -> Envelope:
    return Envelope(raw[offset:offset + _NONCE_SIZE], raw[offset + _NONCE_SIZE:offset + _ENVELOPE_SIZE])


def _write_envelope(output: bytearray, offset: int, envelope: Envelope) -> None:
    output[offset:offset + _NONCE_SIZE] = envelope.nonce
    output[offset + _NONCE_SIZE:offset + _ENVELOPE_SIZE] = envelope.ciphertext


def _bytes(value: object, name: str, length: int | None = None) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{name} must be bytes")
    if length is not None and len(value) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return value


def _revision(value: object, name: str) -> int:
    if type(value) is not int or value < 0 or value > (1 << 63) - 1:
        raise ValueError(f"{name} must be a non-negative signed 64-bit integer")
    return value
