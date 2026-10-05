from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest

from core import biometric
from core.storage import Vault
from core.pmve_device_envelope import (
    DEVICE_ENVELOPE_MAGIC,
    DeviceEnvelopeBindingError,
    DeviceEnvelopeError,
    PmvEDeviceIdentity,
    decode_device_envelope,
    encode_device_envelope,
    validate_device_envelope,
)


VAULT_ID = UUID("00112233-4455-6677-8899-aabbccddeeff")
SIGNING_PUBLIC_KEY = bytes(range(32))
ROOT_KEY = bytes(reversed(range(32)))
IDENTITY = PmvEDeviceIdentity(
    vault_id=VAULT_ID,
    signing_public_key=SIGNING_PUBLIC_KEY,
    key_revision=7,
)


def test_pmve_device_envelope_round_trips_typed_root_key_and_identity() -> None:
    encoded = encode_device_envelope(ROOT_KEY, IDENTITY)

    envelope = decode_device_envelope(encoded)
    try:
        assert bytes(encoded).startswith(DEVICE_ENVELOPE_MAGIC)
        assert envelope.identity == IDENTITY
        assert envelope.copy_root_key() == ROOT_KEY
    finally:
        envelope.clear()

    assert envelope.copy_root_key() == bytes(32)


def test_pmve_device_identity_uses_signed_long_key_revision_boundary() -> None:
    assert PmvEDeviceIdentity(VAULT_ID, SIGNING_PUBLIC_KEY, (1 << 63) - 1).key_revision == (
        1 << 63
    ) - 1
    with pytest.raises(ValueError, match="signed 64-bit"):
        PmvEDeviceIdentity(VAULT_ID, SIGNING_PUBLIC_KEY, 1 << 63)


@pytest.mark.parametrize(
    "current",
    [
        PmvEDeviceIdentity(UUID(int=2), SIGNING_PUBLIC_KEY, 7),
        PmvEDeviceIdentity(VAULT_ID, bytes([9]) * 32, 7),
        PmvEDeviceIdentity(VAULT_ID, SIGNING_PUBLIC_KEY, 8),
    ],
)
def test_pmve_device_envelope_rejects_changed_vault_signer_or_key_revision(current) -> None:
    envelope = decode_device_envelope(encode_device_envelope(ROOT_KEY, IDENTITY))
    try:
        with pytest.raises(DeviceEnvelopeBindingError):
            validate_device_envelope(envelope, current)
    finally:
        envelope.clear()


def test_pmve_device_envelope_rejects_unknown_payload() -> None:
    with pytest.raises(DeviceEnvelopeError):
        decode_device_envelope(b"UNKNOWN!" + ROOT_KEY)


def test_enable_pmve_writes_a_typed_identity_bound_envelope(monkeypatch, tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + bytes(32))
    monkeypatch.setattr(biometric, "_authenticated_pmve_identity", lambda _path, _root: IDENTITY)
    monkeypatch.setattr(biometric, "_protect", lambda value: bytes(value))

    assert biometric.enable_pmve(path, ROOT_KEY)

    envelope = decode_device_envelope(biometric.hello_path(path).read_bytes())
    try:
        assert envelope.identity == IDENTITY
        assert envelope.copy_root_key() == ROOT_KEY
    finally:
        envelope.clear()


def test_enable_pmve_rejects_a_root_key_when_the_current_commit_is_corrupt(monkeypatch, tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + bytes(32))
    protected = []
    monkeypatch.setattr(
        Vault,
        "open_with_root_key",
        lambda *_args: (_ for _ in ()).throw(ValueError("corrupt Commit/PMVR")),
    )
    monkeypatch.setattr(biometric, "_protect", lambda value: protected.append(value) or b"protected")

    assert not biometric.enable_pmve(path, ROOT_KEY)
    assert protected == []
    assert not biometric.hello_path(path).exists()


def test_enable_for_vault_uses_root_key_accessor_for_pmve(monkeypatch, tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    calls = []
    vault = SimpleNamespace(
        path=path,
        device_unlock_key_format="pmve-root-key",
        root_key_for_device_unlock=lambda: calls.append("root") or ROOT_KEY,
    )
    monkeypatch.setattr(
        biometric,
        "enable_pmve",
        lambda actual_path, root_key: calls.append((actual_path, bytes(root_key))) or True,
    )

    assert biometric.enable_for_vault(vault)
    assert calls == ["root", (path, ROOT_KEY)]


def test_malformed_binding_is_deleted_and_requires_registration(monkeypatch, tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + bytes(32))
    biometric.hello_path(path).write_bytes(b"protected-invalid")
    monkeypatch.setattr(biometric, "verify", lambda: True)
    monkeypatch.setattr(biometric, "_unprotect", lambda _blob: b"INVALID!" + ROOT_KEY)

    with pytest.raises(DeviceEnvelopeBindingError, match="重新登记"):
        biometric.unlock_pmve(path)

    assert not biometric.hello_path(path).exists()


def test_stale_pmve_binding_is_deleted_and_requires_registration(monkeypatch, tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + bytes(32))
    biometric.hello_path(path).write_bytes(b"protected")
    monkeypatch.setattr(biometric, "verify", lambda: True)
    monkeypatch.setattr(
        biometric,
        "_unprotect",
        lambda _blob: bytes(encode_device_envelope(ROOT_KEY, IDENTITY)),
    )
    monkeypatch.setattr(
        biometric,
        "authenticated_vault_identity",
        lambda _path, _root: PmvEDeviceIdentity(VAULT_ID, SIGNING_PUBLIC_KEY, 8),
    )

    with pytest.raises(DeviceEnvelopeBindingError, match="revision"):
        biometric.unlock_pmve(path)

    assert not biometric.hello_path(path).exists()


def test_open_vault_uses_root_key_api_and_clears_temporary_material(monkeypatch, tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + bytes(32))
    biometric.hello_path(path).write_bytes(b"protected")
    encoded = encode_device_envelope(ROOT_KEY, IDENTITY)
    monkeypatch.setattr(biometric, "verify", lambda: True)
    monkeypatch.setattr(biometric, "_unprotect", lambda _blob: bytes(encoded))
    monkeypatch.setattr(biometric, "authenticated_vault_identity", lambda _path, _root: IDENTITY)

    opened_with = []

    class FakeVault:
        @classmethod
        def open_with_root_key(cls, opened_path, root_key):
            opened_with.append((opened_path, root_key))
            return SimpleNamespace(path=opened_path)

    result = biometric.open_vault(path, vault_type=FakeVault)

    assert result.path == path
    assert opened_with == [(path, ROOT_KEY)]
