"""Vault-signed device authorization and replay-safe challenge-response."""

from __future__ import annotations

import os
import struct
import threading
import time
import uuid
from dataclasses import dataclass, replace
from enum import IntEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


AUTH_SIZE = 256
CHALLENGE_SIZE = 256
SIGNATURE_SIZE = 64
PUBLIC_KEY_SIZE = 32
NONCE_SIZE = 32
DIGEST_SIZE = 32
MAX_PENDING_CHALLENGES = 1_024
PERMISSION_READ = 1
PERMISSION_WRITE = 2
PERMISSION_AUTHORIZE = 4
DEFINED_PERMISSION_MASK = PERMISSION_READ | PERMISSION_WRITE | PERMISSION_AUTHORIZE
_MAX_WIRE_PERMISSIONS = (1 << 32) - 1
_MAX_LONG = (1 << 63) - 1
_AUTH_DOMAIN = b"pmv/v1/device-authorization\0"
_CHALLENGE_DOMAIN = b"pmv/v1/device-challenge\0"
_AUTH = struct.Struct(">4sII16s16s32sIqqqq")
_CHALLENGE = struct.Struct(">4sII16s16s32s32sB7s16s32s16sq")


class Operation(IntEnum):
    READ = 1
    WRITE = 2
    AUTHORIZE = 3

    @property
    def permission(self) -> int:
        return {Operation.READ: PERMISSION_READ, Operation.WRITE: PERMISSION_WRITE,
                Operation.AUTHORIZE: PERMISSION_AUTHORIZE}[self]


def _long(value: object, label: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_LONG:
        raise ValueError(f"{label} is outside the signed 64-bit range")


@dataclass(frozen=True, slots=True)
class DeviceAuthorization:
    vault_id: uuid.UUID
    device_id: uuid.UUID
    device_public_key: bytes
    permissions: int
    issued_at_epoch_millis: int
    expires_at_epoch_millis: int
    revoked_at_epoch_millis: int
    epoch: int
    signature: bytes = bytes(SIGNATURE_SIZE)

    def __post_init__(self) -> None:
        if not isinstance(self.vault_id, uuid.UUID) or not isinstance(self.device_id, uuid.UUID):
            raise TypeError("vault_id and device_id must be UUID values")
        if not isinstance(self.device_public_key, bytes) or len(self.device_public_key) != PUBLIC_KEY_SIZE:
            raise ValueError("device_public_key must be 32 bytes")
        if (not isinstance(self.permissions, int) or isinstance(self.permissions, bool)
                or not 0 < self.permissions <= _MAX_WIRE_PERMISSIONS):
            raise ValueError("device permissions are invalid")
        if not self.granted_permissions:
            raise ValueError("device authorization grants no defined permission")
        for value, label in ((self.issued_at_epoch_millis, "issued_at"),
                             (self.expires_at_epoch_millis, "expires_at"),
                             (self.revoked_at_epoch_millis, "revoked_at"), (self.epoch, "epoch")):
            _long(value, label)
        if self.expires_at_epoch_millis and self.expires_at_epoch_millis < self.issued_at_epoch_millis:
            raise ValueError("authorization expiry precedes issuance")
        if self.revoked_at_epoch_millis and self.revoked_at_epoch_millis < self.issued_at_epoch_millis:
            raise ValueError("authorization revocation precedes issuance")
        if not isinstance(self.signature, bytes) or len(self.signature) != SIGNATURE_SIZE:
            raise ValueError("authorization signature must be 64 bytes")

    @property
    def granted_permissions(self) -> int:
        """Only the permission bits that map to a real operation.

        ``permissions`` keeps the exact value found on the wire so that encoding a
        decoded record reproduces the original bytes and its signature keeps
        verifying. Records written by codecs that accepted undefined bits (bit3 and
        above) therefore stay readable forever: the bits survive the round-trip and
        remain covered by the signature, but they can never grant an operation,
        because every authorization decision reads this projection instead.
        """
        return self.permissions & DEFINED_PERMISSION_MASK

    def allows(self, operation: Operation) -> bool:
        return bool(self.granted_permissions & operation.permission)

    def active_at(self, now_millis: int) -> bool:
        _long(now_millis, "now_millis")
        return self.revoked_at_epoch_millis == 0 and (
            self.expires_at_epoch_millis == 0 or now_millis <= self.expires_at_epoch_millis
        )


def _auth_prefix(value: DeviceAuthorization) -> bytes:
    return _AUTH.pack(
        b"PMDA", 1, AUTH_SIZE, value.vault_id.bytes, value.device_id.bytes,
        value.device_public_key, value.permissions, value.issued_at_epoch_millis,
        value.expires_at_epoch_millis, value.revoked_at_epoch_millis, value.epoch,
    )


def authorization_signing_bytes(value: DeviceAuthorization) -> bytes:
    return _AUTH_DOMAIN + _auth_prefix(value)


def sign_authorization(value: DeviceAuthorization, vault_private_seed: bytes) -> DeviceAuthorization:
    if not isinstance(vault_private_seed, bytes) or len(vault_private_seed) != 32:
        raise ValueError("vault_private_seed must be 32 bytes")
    signature = Ed25519PrivateKey.from_private_bytes(vault_private_seed).sign(
        authorization_signing_bytes(value)
    )
    return replace(value, signature=signature)


def verify_authorization(value: DeviceAuthorization, trusted_vault_public_key: bytes) -> bool:
    try:
        if not isinstance(trusted_vault_public_key, bytes) or len(trusted_vault_public_key) != 32:
            return False
        Ed25519PublicKey.from_public_bytes(trusted_vault_public_key).verify(
            value.signature, authorization_signing_bytes(value)
        )
        return True
    except (TypeError, ValueError):
        return False
    except Exception:
        return False


def encode_authorization(value: DeviceAuthorization) -> bytes:
    return _auth_prefix(value) + value.signature + bytes(AUTH_SIZE - _AUTH.size - SIGNATURE_SIZE)


def decode_authorization(raw: bytes) -> DeviceAuthorization:
    if not isinstance(raw, bytes) or len(raw) != AUTH_SIZE:
        raise ValueError("device authorization size is invalid")
    fields = _AUTH.unpack_from(raw)
    if fields[:3] != (b"PMDA", 1, AUTH_SIZE):
        raise ValueError("device authorization header is invalid")
    signature_end = _AUTH.size + SIGNATURE_SIZE
    if any(raw[signature_end:]):
        raise ValueError("device authorization reserved bytes are non-zero")
    if fields[6] <= 0 or fields[6] > _MAX_WIRE_PERMISSIONS or not (fields[6] & DEFINED_PERMISSION_MASK):
        raise ValueError(f"device permissions are invalid: {fields[6]}")
    return DeviceAuthorization(
        uuid.UUID(bytes=fields[3]), uuid.UUID(bytes=fields[4]), fields[5], fields[6],
        fields[7], fields[8], fields[9], fields[10], raw[_AUTH.size:signature_end],
    )


@dataclass(frozen=True, slots=True)
class Challenge:
    vault_id: uuid.UUID
    device_id: uuid.UUID
    server_nonce: bytes
    client_nonce: bytes
    operation: Operation
    requested_commit_id: uuid.UUID | None
    request_digest: bytes
    session_id: uuid.UUID
    expires_at_epoch_millis: int

    def __post_init__(self) -> None:
        if not all(isinstance(value, uuid.UUID) for value in (self.vault_id, self.device_id, self.session_id)):
            raise TypeError("challenge UUID fields are invalid")
        if not isinstance(self.server_nonce, bytes) or len(self.server_nonce) != NONCE_SIZE:
            raise ValueError("server_nonce must be 32 bytes")
        if not isinstance(self.client_nonce, bytes) or len(self.client_nonce) != NONCE_SIZE:
            raise ValueError("client_nonce must be 32 bytes")
        if not isinstance(self.operation, Operation):
            raise ValueError("challenge operation is invalid")
        if self.requested_commit_id is not None and not isinstance(self.requested_commit_id, uuid.UUID):
            raise TypeError("requested_commit_id must be a UUID or None")
        if not isinstance(self.request_digest, bytes) or len(self.request_digest) != DIGEST_SIZE:
            raise ValueError("request_digest must be 32 bytes")
        _long(self.expires_at_epoch_millis, "expires_at_epoch_millis")


def encode_challenge(value: Challenge) -> bytes:
    prefix = _CHALLENGE.pack(
        b"PMCH", 1, CHALLENGE_SIZE, value.vault_id.bytes, value.device_id.bytes,
        value.server_nonce, value.client_nonce, int(value.operation), bytes(7),
        (value.requested_commit_id or uuid.UUID(int=0)).bytes, value.request_digest,
        value.session_id.bytes, value.expires_at_epoch_millis,
    )
    return prefix + bytes(CHALLENGE_SIZE - len(prefix))


def decode_challenge(raw: bytes) -> Challenge:
    if not isinstance(raw, bytes) or len(raw) != CHALLENGE_SIZE:
        raise ValueError("device challenge size is invalid")
    fields = _CHALLENGE.unpack_from(raw)
    if fields[:3] != (b"PMCH", 1, CHALLENGE_SIZE) or any(fields[8]) or any(raw[_CHALLENGE.size:]):
        raise ValueError("device challenge encoding is non-canonical")
    commit = uuid.UUID(bytes=fields[9])
    return Challenge(
        uuid.UUID(bytes=fields[3]), uuid.UUID(bytes=fields[4]), fields[5], fields[6],
        Operation(fields[7]), None if commit.int == 0 else commit, fields[10],
        uuid.UUID(bytes=fields[11]), fields[12],
    )


def challenge_signing_bytes(value: Challenge) -> bytes:
    return _CHALLENGE_DOMAIN + encode_challenge(value)


def sign_challenge(value: Challenge, device_private_seed: bytes) -> bytes:
    if not isinstance(device_private_seed, bytes) or len(device_private_seed) != 32:
        raise ValueError("device_private_seed must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(device_private_seed).sign(challenge_signing_bytes(value))


def verify_challenge(value: Challenge, signature: bytes, device_public_key: bytes) -> bool:
    try:
        if not isinstance(signature, bytes) or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(device_public_key).verify(signature, challenge_signing_bytes(value))
        return True
    except Exception:
        return False


class AuthorizationRegistry:
    """Thread-safe monotonic authorization state and single-use challenge registry."""

    def __init__(self, vault_id: uuid.UUID, trusted_vault_public_key: bytes) -> None:
        self.vault_id = vault_id
        self.trusted_key = bytes(trusted_vault_public_key)
        self._authorizations: dict[uuid.UUID, DeviceAuthorization] = {}
        self._transient: dict[uuid.UUID, DeviceAuthorization] = {}
        self._pending: dict[uuid.UUID, Challenge] = {}
        self._lock = threading.RLock()

    def install(self, authorization: DeviceAuthorization, *, transient: bool = False) -> None:
        """Install a vault-signed authorization record.

        Persistent and transient grants keep **separate epoch namespaces**. A transient
        grant is minted with ``epoch = now_millis`` so that it looks recent, but that
        value is ~10^12 while persistent epochs are a small counter; sharing one
        sequence would make every transient grant permanently outrank — and therefore
        block — each later persistent grant for the same device. Ordering is therefore
        only enforced among persistent records, and a transient record's epoch carries
        no ordering meaning at all.

        Both namespaces are still verified against the vault key individually, and a
        device is authorized when *either* namespace grants the operation, so
        separating them can never authorize more than the vault itself signed.
        """
        if authorization.vault_id != self.vault_id or not verify_authorization(authorization, self.trusted_key):
            raise ValueError("device authorization is not signed by the trusted vault")
        with self._lock:
            if transient:
                self._transient[authorization.device_id] = authorization
                return
            current = self._authorizations.get(authorization.device_id)
            if current is not None and authorization.epoch <= current.epoch:
                raise ValueError("device authorization epoch is stale")
            self._authorizations[authorization.device_id] = authorization

    def _granting(
        self, device_id: uuid.UUID, operation: Operation, now_millis: int,
    ) -> DeviceAuthorization | None:
        """The record that authorizes ``operation`` right now, or ``None``.

        Transient grants are checked first: they are the narrower, session-scoped
        intent behind an export/transfer approval. Callers must verify a device
        signature against the returned record's own public key.
        """
        transient = self._transient.get(device_id)
        if transient is not None and transient.active_at(now_millis) and transient.allows(operation):
            return transient
        persistent = self._authorizations.get(device_id)
        if persistent is not None and persistent.active_at(now_millis) and persistent.allows(operation):
            return persistent
        return None

    def _prune_transient(self, now_millis: int) -> None:
        self._transient = {
            device_id: record for device_id, record in self._transient.items()
            if record.active_at(now_millis)
        }

    def issue(self, device_id: uuid.UUID, operation: Operation, client_nonce: bytes,
              requested_commit_id: uuid.UUID | None = None, request_digest: bytes = bytes(32),
              now_millis: int | None = None, ttl_millis: int = 30_000) -> Challenge:
        now = int(time.time() * 1000) if now_millis is None else now_millis
        _long(now, "now_millis")
        if not 1 <= ttl_millis <= 300_000:
            raise ValueError("challenge TTL is invalid")
        if not isinstance(client_nonce, bytes) or len(client_nonce) != NONCE_SIZE:
            raise ValueError("client_nonce must be 32 bytes")
        if not isinstance(request_digest, bytes) or len(request_digest) != DIGEST_SIZE:
            raise ValueError("request_digest must be 32 bytes")
        with self._lock:
            self._prune_transient(now)
            if self._granting(device_id, operation, now) is None:
                raise PermissionError("device is not active or lacks permission")
            self._pending = {
                session_id: challenge for session_id, challenge in self._pending.items()
                if challenge.expires_at_epoch_millis >= now
            }
            if len(self._pending) >= MAX_PENDING_CHALLENGES:
                raise RuntimeError("too many pending device challenges")
            challenge = Challenge(
                self.vault_id, device_id, os.urandom(NONCE_SIZE), bytes(client_nonce), operation,
                requested_commit_id, bytes(request_digest), uuid.uuid4(), now + ttl_millis,
            )
            self._pending[challenge.session_id] = challenge
            return challenge

    def consume(self, challenge: Challenge, signature: bytes, now_millis: int | None = None) -> None:
        now = int(time.time() * 1000) if now_millis is None else now_millis
        _long(now, "now_millis")
        with self._lock:
            expected = self._pending.pop(challenge.session_id, None)
            if expected != challenge:
                raise ValueError("challenge is unknown or already consumed")
            if now > challenge.expires_at_epoch_millis:
                raise ValueError("challenge has expired")
            auth = self._granting(challenge.device_id, challenge.operation, now)
            if auth is None:
                raise PermissionError("device was revoked or lacks permission")
            if not verify_challenge(challenge, signature, auth.device_public_key):
                raise ValueError("device challenge signature is invalid")

    def is_authorized(self, device_id: uuid.UUID, operation: Operation, now_millis: int | None = None) -> bool:
        """Connection-level check: device is active, not revoked, and has operation permission."""
        now = int(time.time() * 1000) if now_millis is None else now_millis
        _long(now, "now_millis")
        with self._lock:
            return self._granting(device_id, operation, now) is not None
