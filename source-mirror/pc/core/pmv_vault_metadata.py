"""PMV-next top-level vault metadata canonical JSON codec.

Entry bodies, trash entry bodies, and media plaintext deliberately do not belong
in this block.  The neutral mapping API keeps unknown future top-level fields
losslessly round-trippable until a production store adapter is introduced.
"""

from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from uuid import UUID

from .pmv_container import BlockType
from .pmv_entry_codec import _canonical_json


SCHEMA = "pmv-vault-metadata"
VERSION = 1
MAX_PLAIN_SIZE = 16 * 1024 * 1024
BLOCK_TYPE = BlockType.OBJECT_METADATA
DIGEST_DOMAIN = b"PMV Vault Metadata Logical Digest v1\x00"

_REQUIRED_FIELDS = {
    "schema",
    "version",
    "vault_id",
    "entry_order",
    "trash_order",
    "sync_meta",
    "key_revision",
    "export_epoch",
    "purge_tombstones",
}
_FORBIDDEN_TOP_LEVEL = {"entries", "trash", "media", "attachments", "images"}
_FORBIDDEN_SECRET_FIELDS = {
    "password",
    "secret",
    "private_key",
    "private_key_pkcs8",
    "media_plaintext",
    "content_bytes",
}


def _canonical_uuid(value: object, name: str) -> UUID:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError(f"{name} must be a UUID") from error
    if str(parsed) != value:
        raise ValueError(f"{name} must use canonical lowercase UUID representation")
    return parsed


def _non_negative_number(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise ValueError(f"{name} must be a finite non-negative JSON number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{name} must be a finite non-negative JSON number")
    try:
        number = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"{name} must be a finite non-negative JSON number") from error
    if not number.is_finite() or number < 0:
        raise ValueError(f"{name} must be a finite non-negative JSON number")


def _uuid_order(value: object, name: str) -> set[UUID]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a JSON array")
    parsed = [_canonical_uuid(item, f"{name}[{index}]") for index, item in enumerate(value)]
    if len(parsed) != len(set(parsed)):
        raise ValueError(f"{name} must not contain duplicate UUIDs")
    return set(parsed)


def _reject_secret_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError("Vault Metadata object keys must be strings")
            if key in _FORBIDDEN_SECRET_FIELDS:
                raise ValueError(f"Vault Metadata must not contain secret or media plaintext field: {key}")
            _reject_secret_fields(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_fields(child)


def _validate(metadata: Mapping[str, Any]) -> None:
    if not all(isinstance(key, str) for key in metadata):
        raise ValueError("Vault Metadata object keys must be strings")
    if not _REQUIRED_FIELDS.issubset(metadata):
        raise ValueError("Vault Metadata is missing required fields")
    if (
        metadata["schema"] != SCHEMA
        or isinstance(metadata["version"], bool)
        or not isinstance(metadata["version"], int)
        or metadata["version"] != VERSION
    ):
        raise ValueError("Vault Metadata schema or version is invalid")
    _canonical_uuid(metadata["vault_id"], "vault_id")
    entry_ids = _uuid_order(metadata["entry_order"], "entry_order")
    trash_ids = _uuid_order(metadata["trash_order"], "trash_order")
    if entry_ids & trash_ids:
        raise ValueError("entry_order and trash_order must not overlap")

    sync_meta = metadata["sync_meta"]
    if not isinstance(sync_meta, Mapping):
        raise ValueError("sync_meta must be a JSON object")
    _canonical_uuid(sync_meta.get("device_id"), "sync_meta.device_id")

    key_revision = metadata["key_revision"]
    if isinstance(key_revision, bool) or not isinstance(key_revision, int) or not 0 <= key_revision < (1 << 63):
        raise ValueError("key_revision must be an integer in 0..2^63-1")
    if metadata["export_epoch"] is not None:
        _non_negative_number(metadata["export_epoch"], "export_epoch")

    purges = metadata["purge_tombstones"]
    if not isinstance(purges, Mapping):
        raise ValueError("purge_tombstones must be a JSON object")
    for entry_id, timestamp in purges.items():
        _canonical_uuid(entry_id, "purge_tombstones key")
        _non_negative_number(timestamp, f"purge_tombstones[{entry_id}]")

    if _FORBIDDEN_TOP_LEVEL & set(metadata):
        raise ValueError("Vault Metadata must not contain entry or media content")
    _reject_secret_fields(metadata)


def encode_metadata(metadata: Mapping[str, Any]) -> bytes:
    _validate(metadata)
    try:
        encoded = _canonical_json(metadata).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("Vault Metadata contains a value that is not valid JSON") from error
    if len(encoded) > MAX_PLAIN_SIZE:
        raise ValueError("Vault Metadata exceeds the single-block limit")
    return encoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Vault Metadata contains duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_metadata(raw: bytes, expected_vault_id: UUID | None = None) -> dict[str, Any]:
    if len(raw) > MAX_PLAIN_SIZE:
        raise ValueError("Vault Metadata exceeds the single-block limit")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Vault Metadata is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Vault Metadata must be a JSON object")
    _validate(value)
    vault_id = _canonical_uuid(value["vault_id"], "vault_id")
    if expected_vault_id is not None and vault_id != expected_vault_id:
        raise ValueError("Vault Metadata vault_id does not match the block object ID")
    return value


def logical_digest(metadata: Mapping[str, Any]) -> bytes:
    return hashlib.sha256(DIGEST_DOMAIN + encode_metadata(metadata)).digest()


__all__ = [
    "BLOCK_TYPE",
    "DIGEST_DOMAIN",
    "MAX_PLAIN_SIZE",
    "SCHEMA",
    "VERSION",
    "decode_metadata",
    "encode_metadata",
    "logical_digest",
]
