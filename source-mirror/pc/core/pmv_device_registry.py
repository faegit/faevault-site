"""PMVE metadata device authorization registry (mirror of the Android codec).

Stored in the vault-signed metadata under the ``device_authorizations`` field as
an array of base64-encoded 256-byte ``DeviceAuthorization`` records, sorted by
``(device_id, epoch)``. Any holder of the vault signing key may authorize/revoke
devices; sync peers only trust records verified against the vault public key and
enforce "authentication before data".
"""

from __future__ import annotations

import base64
from typing import Any, Mapping
from uuid import UUID

from . import pmv_sync_authorization


METADATA_FIELD = "device_authorizations"


def encode(records: list[pmv_sync_authorization.DeviceAuthorization]) -> list[str]:
    ordered = sorted(records, key=lambda record: (str(record.device_id), record.epoch))
    return [
        base64.b64encode(pmv_sync_authorization.encode_authorization(record)).decode("ascii")
        for record in ordered
    ]


def decode(metadata: Mapping[str, Any]) -> list[pmv_sync_authorization.DeviceAuthorization]:
    raw = metadata.get(METADATA_FIELD)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError("device_authorizations must be an array")
    records: list[pmv_sync_authorization.DeviceAuthorization] = []
    for index, value in enumerate(raw):
        if not isinstance(value, str):
            raise ValueError(f"device_authorizations[{index}] must be a string")
        try:
            raw_bytes = base64.b64decode(value, validate=True)
        except Exception as error:
            raise ValueError(f"device_authorizations[{index}] base64 is invalid") from error
        try:
            record = pmv_sync_authorization.decode_authorization(raw_bytes)
        except Exception as error:
            raise ValueError(f"device_authorizations[{index}] cannot be decoded") from error
        records.append(record)
    by_device: dict[UUID, pmv_sync_authorization.DeviceAuthorization] = {}
    previous_device: UUID | None = None
    previous_epoch = -1
    for record in records:
        if previous_device is not None:
            if previous_device != record.device_id and str(previous_device) > str(record.device_id):
                raise ValueError("device_authorizations order is not canonical")
            if previous_device == record.device_id and record.epoch <= previous_epoch:
                raise ValueError("device_authorizations epochs must strictly increase per device")
        previous_device = record.device_id
        previous_epoch = record.epoch
        current = by_device.get(record.device_id)
        if current is not None and record.epoch <= current.epoch:
            raise ValueError("device_authorizations epochs must strictly increase per device")
        by_device[record.device_id] = record
    return list(by_device.values())


def verify_all(
    records: list[pmv_sync_authorization.DeviceAuthorization],
    vault_public_key: bytes,
) -> list[pmv_sync_authorization.DeviceAuthorization]:
    for record in records:
        if not pmv_sync_authorization.verify_authorization(record, vault_public_key):
            raise ValueError(f"device authorization is not signed by the trusted vault: {record.device_id}")
    return records


def with_registry(
    metadata: Mapping[str, Any],
    records: list[pmv_sync_authorization.DeviceAuthorization],
) -> dict[str, Any]:
    updated = dict(metadata)
    if records:
        updated[METADATA_FIELD] = encode(records)
    else:
        updated.pop(METADATA_FIELD, None)
    return updated


def latest(
    records: list[pmv_sync_authorization.DeviceAuthorization],
    device_id: UUID,
) -> pmv_sync_authorization.DeviceAuthorization | None:
    candidates = [record for record in records if record.device_id == device_id]
    return max(candidates, key=lambda record: record.epoch) if candidates else None
