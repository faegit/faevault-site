"""Typed, identity-bound device envelope payload for PMVE RootKeys.

The encoded value is plaintext only until the platform device protector (DPAPI
on Windows) seals it. The authenticated PMVE header is re-opened before use to
enforce the vault, signer, and key revision binding.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
from pathlib import Path
import struct
from uuid import UUID

from .pmv_vault_header import (
    HEADER_SIZE,
    PRIMARY_OFFSET,
    SECONDARY_OFFSET,
    unlock_with_root_key,
)


DEVICE_ENVELOPE_MAGIC = b"PMVEROOT"
DEVICE_ENVELOPE_VERSION = 1
_KEY_SIZE = 32
_MAX_WIRE_LONG = (1 << 63) - 1
_FORMAT = ">8sB16sq32s32s"
DEVICE_ENVELOPE_SIZE = struct.calcsize(_FORMAT)


class DeviceEnvelopeError(ValueError):
    """The device-protected PMVE payload is malformed or unusable."""


class DeviceEnvelopeBindingError(DeviceEnvelopeError):
    """The protected RootKey is not bound to the current PMVE identity."""


@dataclass(frozen=True, slots=True)
class PmvEDeviceIdentity:
    vault_id: UUID
    signing_public_key: bytes
    key_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.vault_id, UUID):
            raise TypeError("vault_id must be a UUID")
        signing_key = _exact_bytes(self.signing_public_key, "signing_public_key", _KEY_SIZE)
        if not any(signing_key):
            raise ValueError("signing_public_key must not be all zero")
        object.__setattr__(self, "signing_public_key", signing_key)
        if isinstance(self.key_revision, bool) or not isinstance(self.key_revision, int):
            raise TypeError("key_revision must be an integer")
        if self.key_revision < 0 or self.key_revision > _MAX_WIRE_LONG:
            raise ValueError("key_revision is outside the signed 64-bit wire range")


class PmvEDeviceEnvelope:
    """Decoded RootKey material whose mutable secret can be explicitly cleared."""

    __slots__ = ("identity", "_root_key")

    def __init__(self, identity: PmvEDeviceIdentity, root_key: bytes | bytearray | memoryview) -> None:
        if not isinstance(identity, PmvEDeviceIdentity):
            raise TypeError("identity must be a PmvEDeviceIdentity")
        self.identity = identity
        self._root_key = bytearray(_exact_view(root_key, "root_key", _KEY_SIZE))

    def copy_root_key(self) -> bytes:
        return bytes(self._root_key)

    def copy_root_key_buffer(self) -> bytearray:
        """Return a caller-owned mutable copy that can be cleared in ``finally``."""

        return bytearray(self._root_key)

    def clear(self) -> None:
        self._root_key[:] = bytes(len(self._root_key))


def encode_device_envelope(
    root_key: bytes | bytearray | memoryview,
    identity: PmvEDeviceIdentity,
) -> bytearray:
    """Encode a RootKey and its PMVE identity for subsequent OS protection."""

    if not isinstance(identity, PmvEDeviceIdentity):
        raise TypeError("identity must be a PmvEDeviceIdentity")
    root = _exact_view(root_key, "root_key", _KEY_SIZE)
    output = bytearray(DEVICE_ENVELOPE_SIZE)
    output[:8] = DEVICE_ENVELOPE_MAGIC
    output[8] = DEVICE_ENVELOPE_VERSION
    output[9:25] = identity.vault_id.bytes
    struct.pack_into(">q", output, 25, identity.key_revision)
    output[33:65] = identity.signing_public_key
    output[65:97] = root
    return output


def decode_device_envelope(raw: bytes | bytearray | memoryview) -> PmvEDeviceEnvelope:
    """Strictly decode the typed PMVE payload after OS unprotection."""

    value = _exact_view(raw, "device_envelope")
    if len(value) != DEVICE_ENVELOPE_SIZE:
        raise DeviceEnvelopeError("invalid PMVE device envelope size")
    if bytes(value[:8]) != DEVICE_ENVELOPE_MAGIC:
        raise DeviceEnvelopeError("invalid PMVE device envelope magic")
    version = value[8]
    if version != DEVICE_ENVELOPE_VERSION:
        raise DeviceEnvelopeError("unsupported PMVE device envelope version")
    try:
        identity = PmvEDeviceIdentity(
            UUID(bytes=bytes(value[9:25])),
            bytes(value[33:65]),
            struct.unpack_from(">q", value, 25)[0],
        )
        return PmvEDeviceEnvelope(identity, value[65:97])
    except (TypeError, ValueError) as exc:
        raise DeviceEnvelopeError("invalid PMVE device envelope fields") from exc


def validate_device_envelope(
    envelope: PmvEDeviceEnvelope,
    current_identity: PmvEDeviceIdentity,
) -> None:
    """Reject stale or transplanted device material before opening a session."""

    if envelope.identity.vault_id != current_identity.vault_id:
        raise DeviceEnvelopeBindingError("PMVE device envelope vault identity changed")
    if not hmac.compare_digest(
        envelope.identity.signing_public_key,
        current_identity.signing_public_key,
    ):
        raise DeviceEnvelopeBindingError("PMVE device envelope signing identity changed")
    if envelope.identity.key_revision != current_identity.key_revision:
        raise DeviceEnvelopeBindingError("PMVE device envelope key revision changed")


def authenticated_vault_identity(
    vault_path: Path | str,
    root_key: bytes | bytearray | memoryview,
) -> PmvEDeviceIdentity:
    """Read the newest PMVE header that authenticates with the supplied RootKey."""

    root_buffer = bytearray(_exact_view(root_key, "root_key", _KEY_SIZE))
    candidates = []
    try:
        with Path(vault_path).open("rb") as stream:
            for slot, offset in ((0, PRIMARY_OFFSET), (1, SECONDARY_OFFSET)):
                stream.seek(offset)
                raw = stream.read(HEADER_SIZE)
                if len(raw) != HEADER_SIZE:
                    continue
                try:
                    unlocked = unlock_with_root_key(raw, bytes(root_buffer))
                except (TypeError, ValueError):
                    continue
                header = unlocked.header
                candidates.append((
                    header.header_revision,
                    header.key_revision,
                    slot,
                    header,
                ))
                del unlocked
        if not candidates:
            raise DeviceEnvelopeBindingError(
                "RootKey does not authenticate either PMVE vault header"
            )
        _, _, _, header = max(candidates, key=lambda item: item[:3])
        return PmvEDeviceIdentity(
            vault_id=header.vault_id,
            signing_public_key=header.signing_public_key,
            key_revision=header.key_revision,
        )
    finally:
        root_buffer[:] = bytes(len(root_buffer))


def _exact_bytes(
    value: bytes | bytearray | memoryview,
    name: str,
    length: int | None = None,
) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    checked = bytes(value)
    if length is not None and len(checked) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return checked


def _exact_view(
    value: bytes | bytearray | memoryview,
    name: str,
    length: int | None = None,
) -> memoryview:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError(f"{name} must be bytes-like")
    checked = memoryview(value).cast("B")
    if length is not None and len(checked) != length:
        raise ValueError(f"{name} must be exactly {length} bytes")
    return checked


__all__ = [
    "DEVICE_ENVELOPE_MAGIC",
    "DEVICE_ENVELOPE_SIZE",
    "DEVICE_ENVELOPE_VERSION",
    "DeviceEnvelopeBindingError",
    "DeviceEnvelopeError",
    "PmvEDeviceEnvelope",
    "PmvEDeviceIdentity",
    "authenticated_vault_identity",
    "decode_device_envelope",
    "encode_device_envelope",
    "validate_device_envelope",
]
