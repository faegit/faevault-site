"""Mirror of the Android PmvDeviceRegistryTest for the PC metadata registry codec."""

import base64
import dataclasses
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import pmv_device_registry, pmv_sync_authorization


VAULT_ID = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
VAULT_SEED = bytes((index * 3 + 1) & 0xFF for index in range(32))
VAULT_PUBLIC = Ed25519PrivateKey.from_private_bytes(VAULT_SEED).public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def _record(device_id, epoch, revoked_at=0, permissions=None):
    permissions = permissions or (
        pmv_sync_authorization.PERMISSION_READ
        | pmv_sync_authorization.PERMISSION_WRITE
        | pmv_sync_authorization.PERMISSION_AUTHORIZE
    )
    return pmv_sync_authorization.sign_authorization(
        pmv_sync_authorization.DeviceAuthorization(
            vault_id=VAULT_ID,
            device_id=device_id,
            device_public_key=bytes((index * 7 + device_id.int) & 0xFF for index in range(32)),
            permissions=permissions,
            issued_at_epoch_millis=1000,
            expires_at_epoch_millis=0,
            revoked_at_epoch_millis=revoked_at,
            epoch=epoch,
        ),
        VAULT_SEED,
    )


def test_round_trip_preserves_unknown_fields_and_signature():
    metadata = {"schema": "pmv-vault-metadata", "future_field": "kept"}
    records = [_record(uuid.uuid4(), 1), _record(uuid.uuid4(), 2)]
    updated = pmv_device_registry.with_registry(metadata, records)
    assert updated["future_field"] == "kept"
    decoded = pmv_device_registry.decode(updated)
    assert len(decoded) == len(records)
    pmv_device_registry.verify_all(decoded, VAULT_PUBLIC)


def test_signature_verification_rejects_forged_records():
    forged = dataclasses.replace(_record(uuid.uuid4(), 1), signature=bytes(64))
    with pytest.raises(ValueError):
        pmv_device_registry.verify_all([forged], VAULT_PUBLIC)


def test_epoch_must_be_monotonic_and_latest_wins():
    device = uuid.uuid4()
    old = _record(device, 1)
    newer = _record(device, 2, revoked_at=5000)
    decoded = pmv_device_registry.decode(pmv_device_registry.with_registry({}, [old, newer]))
    assert len(decoded) == 1
    assert decoded[0].epoch == 2
    assert decoded[0].revoked_at_epoch_millis == 5000
    # 手工构造乱序元数据必须失败关闭
    manual = {
        pmv_device_registry.METADATA_FIELD: [
            base64.b64encode(pmv_sync_authorization.encode_authorization(newer)).decode("ascii"),
            base64.b64encode(pmv_sync_authorization.encode_authorization(old)).decode("ascii"),
        ],
    }
    with pytest.raises(ValueError):
        pmv_device_registry.decode(manual)


def test_legacy_undefined_permission_bits_do_not_break_the_registry():
    """Regression: a record carrying permissions=15 (signed by a pre-strict codec)
    used to raise inside decode_authorization, which aborted the whole registry and
    left every device on a shared vault unable to authenticate. The record is
    authentic, so it must decode, verify, and stay byte-exact through a re-encode."""
    device = uuid.uuid4()
    legacy = _record(device, 1, permissions=15)
    other = _record(uuid.uuid4(), 1)
    metadata = pmv_device_registry.with_registry({}, [legacy, other])

    decoded = pmv_device_registry.decode(metadata)
    assert len(decoded) == 2
    verified = pmv_device_registry.verify_all(decoded, VAULT_PUBLIC)
    assert len(verified) == 2
    latest = pmv_device_registry.latest(verified, device)
    assert latest is not None
    assert latest.permissions == 15
    assert latest.granted_permissions == pmv_sync_authorization.DEFINED_PERMISSION_MASK
    # Re-encoding must reproduce the original bytes so signatures keep verifying.
    assert pmv_device_registry.encode(verified) == pmv_device_registry.encode(decoded)
    assert pmv_device_registry.decode(metadata) == verified


def test_invalid_values_fail_closed_like_android():
    # 结构错误（字段不是数组）仍按原语义报错。
    with pytest.raises(ValueError):
        pmv_device_registry.decode({pmv_device_registry.METADATA_FIELD: "not-array"})
    # 损坏记录可能代表撤销授权，不能跳过后继续使用较旧授权。
    with pytest.raises(ValueError):
        pmv_device_registry.decode({pmv_device_registry.METADATA_FIELD: ["!!!invalid base64!!!"]})
    good = pmv_device_registry.encode([_record(uuid.uuid4(), 1)])
    mixed = {pmv_device_registry.METADATA_FIELD: ["!!!invalid base64!!!", good[0]]}
    with pytest.raises(ValueError):
        pmv_device_registry.decode(mixed)
    assert pmv_device_registry.decode({}) == []
