"""Lossless, passkey-aware module merging for synchronization."""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from . import passkeys


_KEY_BUNDLE_FIELDS = frozenset({"user_id", "credential_id", "private_key", "public_key"})
_BOOLEAN_FIELDS = ("discoverable", "backup_eligible", "backup_state")
_TIMESTAMP_FIELDS = frozenset({"created_at", "last_used_at"})
_MERGE_SPECIAL_FIELDS = _KEY_BUNDLE_FIELDS | _TIMESTAMP_FIELDS | frozenset(
    {
        "rp_id",
        "counter_mode",
        "sign_count",
        "schema_version",
        "key_mode",
        "device_binding",
    }
)
_CONFLICT_GROUP_KEY = "passkeyConflictGroupId"
_CONFLICT_STATUS_KEY = "passkeyConflictStatus"
_INVALID_MODULE_SET = "invalid passkey module set"


@dataclass(frozen=True)
class PasskeyMergeResult:
    modules: list[dict] = field(repr=False)
    has_key_conflict: bool = False
    metadata_conflicts: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ModuleRecord:
    module: dict[str, Any] = field(repr=False)
    parsed: passkeys.ValidatedPasskey = field(repr=False)
    identity: tuple[str, bytes] = field(repr=False)
    key_identity: str


def merge_module_sets(local_modules: list[dict], remote_modules: list[dict]) -> PasskeyMergeResult:
    """Merge two passkey-only module sets without mutating either input.

    Invalid module wrappers or records are rejected with one redacted error.
    Output order is stable by decoded credential identity and key identity; only
    hard-conflict group identifiers are random.
    """
    try:
        records = _read_module_set(local_modules) + _read_module_set(remote_modules)
        by_identity: dict[tuple[str, bytes], dict[str, list[_ModuleRecord]]] = {}
        for record in records:
            by_identity.setdefault(record.identity, {}).setdefault(record.key_identity, []).append(record)

        output: list[dict] = []
        conflicts: set[str] = set()
        has_key_conflict = False
        for identity in sorted(by_identity, key=lambda item: (item[0], item[1])):
            key_groups = by_identity[identity]
            variants = [
                _merge_same_key(key_groups[key_identity], conflicts)
                for key_identity in sorted(key_groups)
            ]
            if len(variants) > 1:
                has_key_conflict = True
                group_id = uuid.uuid4().hex
                for variant in variants:
                    config = variant["config"]
                    config[_CONFLICT_GROUP_KEY] = group_id
                    config[_CONFLICT_STATUS_KEY] = "key_mismatch"
            output.extend(variants)

        _ensure_distinct_ids(output)
        return PasskeyMergeResult(
            modules=output,
            has_key_conflict=has_key_conflict,
            metadata_conflicts=tuple(sorted(conflicts)),
        )
    except passkeys.PasskeyError:
        raise passkeys.PasskeyError(_INVALID_MODULE_SET) from None
    except Exception:
        raise passkeys.PasskeyError(_INVALID_MODULE_SET) from None


def _read_module_set(value: Any) -> list[_ModuleRecord]:
    if type(value) is not list:
        raise passkeys.PasskeyError(_INVALID_MODULE_SET)
    return [_read_module(module) for module in value]


def _read_module(value: Any) -> _ModuleRecord:
    module = _safe_clone(value)
    if type(module) is not dict or module.get("type") != "passkey":
        raise passkeys.PasskeyError(_INVALID_MODULE_SET)
    config = module.get("config", {})
    if type(config) is not dict:
        raise passkeys.PasskeyError(_INVALID_MODULE_SET)
    module["config"] = config
    record = module.get("value")
    if type(record) is not dict:
        raise passkeys.PasskeyError(_INVALID_MODULE_SET)
    parsed = passkeys.parse_record(record)
    identity = (_normalized_rp_identity(parsed.rp_id), parsed.credential_id_bytes)
    return _ModuleRecord(
        module=module,
        parsed=parsed,
        identity=identity,
        key_identity=_key_identity(parsed),
    )


def _key_identity(parsed: passkeys.ValidatedPasskey) -> str:
    if parsed.schema_version == 2:
        carrier = "legacy"
    elif parsed.key_mode == "syncable":
        carrier = "syncable"
    else:
        binding = parsed.value.get("device_binding") or {}
        carrier = "device:{device_id}:{binding_id}:{key_generation}".format(**binding)
    return f"{parsed.key_identity}:{carrier}"


def _normalized_rp_identity(value: str) -> str:
    try:
        if type(value) is not str or not value:
            raise ValueError
        normalized = value[:-1] if value.endswith(".") else value
        if not normalized or normalized.endswith("."):
            raise ValueError
        passkeys._validated_rp_id(normalized)
        return normalized.encode("idna").decode("ascii").lower()
    except Exception:
        raise passkeys.PasskeyError(_INVALID_MODULE_SET) from None


def _merge_same_key(records: list[_ModuleRecord], conflicts: set[str]) -> dict[str, Any]:
    preferred = max(records, key=_source_rank)
    result = _safe_clone(preferred.module)
    result_config = result["config"]

    for record in records:
        if record is preferred:
            continue
        _merge_mapping(
            result,
            record.module,
            conflicts=conflicts,
            prefix="module.",
            skip={"id", "type", "value", "config"},
        )
        _merge_mapping(
            result_config,
            record.module["config"],
            conflicts=conflicts,
            prefix="config.",
            skip={_CONFLICT_GROUP_KEY, _CONFLICT_STATUS_KEY},
        )

    result_value = result["value"]
    for record in records:
        if record is preferred:
            continue
        _merge_mapping(
            result_value,
            record.module["value"],
            conflicts=conflicts,
            prefix="",
            skip=_MERGE_SPECIAL_FIELDS | frozenset(_BOOLEAN_FIELDS),
        )

    _merge_counter(result_value)
    _merge_timestamps(result_value, records)
    _merge_booleans(result_value, records)
    passkeys.parse_record(result_value)
    return result


def _source_rank(record: _ModuleRecord) -> tuple[datetime, datetime, str]:
    value = record.module["value"]
    return (
        _timestamp(value.get("last_used_at")),
        _timestamp(value.get("created_at")),
        json.dumps(record.module, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
    )


def _merge_counter(
    result: dict[str, Any],
) -> None:
    result["sign_count"] = "0"
    result["counter_mode"] = "synced_zero"


def _merge_timestamps(result: dict[str, Any], records: list[_ModuleRecord]) -> None:
    created = [
        record.module["value"].get("created_at")
        for record in records
        if _nonempty(record.module["value"].get("created_at"))
    ]
    if created:
        result["created_at"] = min(created, key=_timestamp)

    last_used = [
        record.module["value"].get("last_used_at")
        for record in records
        if _nonempty(record.module["value"].get("last_used_at"))
    ]
    if last_used:
        result["last_used_at"] = max(last_used, key=_timestamp)
    elif any("last_used_at" in record.module["value"] for record in records):
        result["last_used_at"] = ""


def _merge_booleans(result: dict[str, Any], records: list[_ModuleRecord]) -> None:
    for key in _BOOLEAN_FIELDS:
        values = [
            record.module["value"].get(key)
            for record in records
            if key in record.module["value"]
        ]
        if not values:
            continue
        result[key] = "true" if "true" in values else "false"


def _merge_mapping(
    preferred: dict[str, Any],
    other: dict[str, Any],
    *,
    conflicts: set[str],
    prefix: str,
    skip: set[str] | frozenset[str],
) -> None:
    for key in sorted(other):
        if key in skip:
            continue
        path = f"{prefix}{key}"
        if key not in preferred or not _nonempty(preferred[key]):
            if _nonempty(other[key]) or key not in preferred:
                preferred[key] = _safe_clone(other[key])
            continue
        if not _nonempty(other[key]) or preferred[key] == other[key]:
            continue
        if type(preferred[key]) is dict and type(other[key]) is dict:
            _merge_mapping(
                preferred[key],
                other[key],
                conflicts=conflicts,
                prefix=f"{path}.",
                skip=frozenset(),
            )
            continue
        conflicts.add(path)


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    normalized = value.replace("t", "T").replace("z", "Z")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    return datetime.fromisoformat(normalized)


def _nonempty(value: Any) -> bool:
    return value != "" and value != [] and value != {}


def _ensure_distinct_ids(modules: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for index, module in enumerate(modules):
        module_id = module.get("id")
        if isinstance(module_id, str) and module_id and module_id not in seen:
            seen.add(module_id)
            continue
        parsed = passkeys.parse_record(module["value"])
        record_value = parsed.value
        nonce = 0
        while True:
            digest = hashlib.sha256(
                (
                    parsed.rp_id + "\0"
                    + record_value["credential_id"] + "\0"
                    + record_value["public_key"] + "\0"
                    + str(index) + "\0" + str(nonce)
                ).encode("utf-8")
            ).hexdigest()[:32]
            if digest not in seen:
                module["id"] = digest
                seen.add(digest)
                break
            nonce += 1


def _safe_clone(value: Any, active: set[int] | None = None) -> Any:
    if active is None:
        active = set()
    value_type = type(value)
    if value_type is dict:
        container_id = id(value)
        if container_id in active:
            raise passkeys.PasskeyError(_INVALID_MODULE_SET)
        active.add(container_id)
        try:
            result: dict[str, Any] = {}
            for key, child in value.items():
                if type(key) is not str:
                    raise passkeys.PasskeyError(_INVALID_MODULE_SET)
                result[key] = _safe_clone(child, active)
            return result
        finally:
            active.remove(container_id)
    if value_type is list:
        container_id = id(value)
        if container_id in active:
            raise passkeys.PasskeyError(_INVALID_MODULE_SET)
        active.add(container_id)
        try:
            return [_safe_clone(child, active) for child in value]
        finally:
            active.remove(container_id)
    if value_type in (str, int, bool) or value is None:
        return value
    if value_type is float and math.isfinite(value):
        return value
    raise passkeys.PasskeyError(_INVALID_MODULE_SET)
