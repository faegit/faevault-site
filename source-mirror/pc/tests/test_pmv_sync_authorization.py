from __future__ import annotations

import uuid
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core.pmv_sync_authorization import *


def _public(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def test_registry_enforces_permission_expiry_revocation_epoch_and_replay() -> None:
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    authorization = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ | PERMISSION_WRITE,
        1000, 10_000, 0, 1,
    ), vault_seed)
    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    registry.install(authorization)
    challenge = registry.issue(device_id, Operation.WRITE, bytes(32), now_millis=2000)
    signature = sign_challenge(challenge, device_seed)
    registry.consume(challenge, signature, now_millis=2001)
    with pytest.raises(ValueError, match="consumed"):
        registry.consume(challenge, signature, now_millis=2002)

    with pytest.raises(ValueError, match="stale"):
        registry.install(authorization)
    revoked = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), authorization.permissions,
        1000, 10_000, 3000, 2,
    ), vault_seed)
    registry.install(revoked)
    with pytest.raises(PermissionError, match="active"):
        registry.issue(device_id, Operation.READ, bytes(32), now_millis=4000)


def test_context_binding_rejects_wrong_operation_vault_and_signature() -> None:
    seed = bytes(range(32, 64))
    challenge = Challenge(
        uuid.uuid4(), uuid.uuid4(), bytes(range(32)), bytes(range(32, 64)), Operation.READ,
        None, bytes(32), uuid.uuid4(), 5000,
    )
    signature = sign_challenge(challenge, seed)
    assert verify_challenge(challenge, signature, _public(seed))
    assert not verify_challenge(replace(challenge, operation=Operation.WRITE), signature, _public(seed))
    assert not verify_challenge(replace(challenge, vault_id=uuid.uuid4()), signature, _public(seed))
    assert not verify_challenge(challenge, bytes(64), _public(seed))


def test_registry_rejects_malformed_boundary_inputs() -> None:
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    authorization = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ,
        1000, 10_000, 0, 1,
    ), vault_seed)
    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    registry.install(authorization)
    with pytest.raises(ValueError, match="client_nonce"):
        registry.issue(device_id, Operation.READ, bytes(31), now_millis=2000)
    with pytest.raises(ValueError, match="request_digest"):
        registry.issue(
            device_id, Operation.READ, bytes(32), request_digest=bytes(31), now_millis=2000,
        )


def test_undefined_permission_bits_stay_readable_but_never_grant() -> None:
    """Records written under the pre-strict 4-bit mask must stay decodable and
    byte-exact, while bit3 grants nothing. Regression for the registry-wide
    decode failure that blocked every device on a shared vault."""
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    legacy = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), 15, 1000, 10_000, 0, 1,
    ), vault_seed)
    assert legacy.permissions == 15
    assert legacy.granted_permissions == DEFINED_PERMISSION_MASK

    raw = encode_authorization(legacy)
    decoded = decode_authorization(raw)
    assert decoded.permissions == 15
    assert encode_authorization(decoded) == raw
    assert verify_authorization(decoded, _public(vault_seed))

    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    registry.install(decoded)
    for operation in Operation:
        assert registry.is_authorized(device_id, operation, now_millis=2000)
    challenge = registry.issue(device_id, Operation.AUTHORIZE, bytes(32), now_millis=2000)
    registry.consume(challenge, sign_challenge(challenge, device_seed), now_millis=2001)


def test_transient_grant_does_not_consume_the_persistent_epoch() -> None:
    """Transient grants are minted with epoch=now_millis (~10^12) while persistent
    epochs are a small counter. Sharing one sequence let a transient grant outrank —
    and therefore permanently block — every later persistent grant for that device."""
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    now = 1_700_000_000_000
    registry = AuthorizationRegistry(vault_id, _public(vault_seed))

    transient = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ,
        now, now + 300_000, 0, now,
    ), vault_seed)
    registry.install(transient, transient=True)
    assert registry.is_authorized(device_id, Operation.READ, now_millis=now)

    # 随后签发的持久授权（世代号=计数器）必须仍能装入。
    persistent = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ | PERMISSION_WRITE,
        now, 0, 0, 1,
    ), vault_seed)
    registry.install(persistent)

    # 持久授权授予的写权限必须可用（此前会被判为世代号过期）。
    assert registry.is_authorized(device_id, Operation.WRITE, now_millis=now)
    challenge = registry.issue(device_id, Operation.WRITE, bytes(32), now_millis=now)
    registry.consume(challenge, sign_challenge(challenge, device_seed), now_millis=now + 1)

    # 持久侧的单调性仍然生效。
    with pytest.raises(ValueError, match="stale"):
        registry.install(persistent)


def test_expired_transient_grant_does_not_authorize() -> None:
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    now = 1_700_000_000_000
    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    registry.install(sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ,
        now, now + 1_000, 0, now,
    ), vault_seed), transient=True)
    assert registry.is_authorized(device_id, Operation.READ, now_millis=now)
    assert not registry.is_authorized(device_id, Operation.READ, now_millis=now + 2_000)
    with pytest.raises(PermissionError, match="lacks permission"):
        registry.issue(device_id, Operation.READ, bytes(32), now_millis=now + 2_000)


def test_transient_grant_cannot_widen_beyond_its_signature() -> None:
    """瞬时授权只读，因此不能凭并集语义获得持久授权之外的能力。"""
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    now = 1_700_000_000_000
    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    registry.install(sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ, now, 0, 0, now,
    ), vault_seed), transient=True)
    assert registry.is_authorized(device_id, Operation.READ, now_millis=now)
    assert not registry.is_authorized(device_id, Operation.WRITE, now_millis=now)
    assert not registry.is_authorized(device_id, Operation.AUTHORIZE, now_millis=now)


def test_transient_grant_is_still_signature_gated() -> None:
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    forged = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ, 1_000, 0, 0, 1_000,
    ), bytes(range(64, 96)))
    with pytest.raises(ValueError, match="not signed"):
        registry.install(forged, transient=True)


def test_bit3_alone_is_not_an_authorization() -> None:
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    for permissions in (0, 8, 16, 0xFFFFFFF8):
        with pytest.raises(ValueError, match="permissions|permission"):
            DeviceAuthorization(
                vault_id, device_id, bytes(32), permissions, 1000, 0, 0, 1,
            )


def test_permission_projection_cannot_widen_authority() -> None:
    vault_id, device_id = uuid.uuid4(), uuid.uuid4()
    vault_seed, device_seed = bytes(range(32)), bytes(range(32, 64))
    read_only = sign_authorization(DeviceAuthorization(
        vault_id, device_id, _public(device_seed), PERMISSION_READ | 0b1111_1000, 1000, 0, 0, 1,
    ), vault_seed)
    assert read_only.granted_permissions == PERMISSION_READ
    assert read_only.allows(Operation.READ)
    assert not read_only.allows(Operation.WRITE)
    assert not read_only.allows(Operation.AUTHORIZE)

    registry = AuthorizationRegistry(vault_id, _public(vault_seed))
    registry.install(read_only)
    with pytest.raises(PermissionError, match="lacks permission"):
        registry.issue(device_id, Operation.WRITE, bytes(32), now_millis=2000)
