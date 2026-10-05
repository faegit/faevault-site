"""PMV next single-entry canonical JSON codec.

The wire shape uses the PMV-next canonical JSON profile shared with Android:
object keys sort by unsigned UTF-8 bytes, arrays retain order, and numbers use
plain decimal without exponent or insignificant trailing zeroes.
"""

from __future__ import annotations

import json
import math
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping
from uuid import UUID

from .models import Entry


MAX_ENTRY_PLAIN_SIZE = 16 * 1024 * 1024

_WIRE_FIELDS = (
    "title",
    "username",
    "password",
    "url",
    "target_app",
    "notes",
    "tags",
    "id",
    "created_at",
    "updated_at",
    "secret_type",
    "fields",
    "deleted_at",
    "leak_check_revision",
    "leak_pwned_count",
    "leak_common_weak",
    "leak_checked_at",
)

_DEFAULTS: dict[str, Any] = {
    "title": "",
    "username": "",
    "password": "",
    "url": "",
    "target_app": "",
    "notes": "",
    "tags": [],
    "id": "",
    "created_at": 0.0,
    "updated_at": 0.0,
    "secret_type": "login",
    "fields": {},
    "deleted_at": None,
    "leak_check_revision": None,
    "leak_pwned_count": None,
    "leak_common_weak": False,
    "leak_checked_at": None,
}


def _canonical_uuid(value: object) -> UUID:
    if not isinstance(value, str):
        raise ValueError("Entry ID must be a UUID string")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        raise ValueError("Entry ID must be a UUID") from error
    if str(parsed) != value.lower():
        raise ValueError("Entry ID must use canonical UUID representation")
    return parsed


def _wire_mapping(entry: Entry | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(entry, Mapping):
        source = entry
        get = lambda name: source.get(name, _DEFAULTS[name])
    else:
        get = lambda name: getattr(entry, name, _DEFAULTS[name])
    result = {name: get(name) for name in _WIRE_FIELDS}
    _canonical_uuid(result["id"])
    return result


def _canonical_number(value: int | float | Decimal) -> str:
    if isinstance(value, bool):
        raise ValueError("boolean is not a JSON number")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    try:
        number = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError) as error:
        raise ValueError("invalid JSON number") from error
    if not number.is_finite():
        raise ValueError("non-finite JSON number")
    if number == 0:
        return "0"
    plain = format(number, "f")
    if "." in plain:
        plain = plain.rstrip("0").rstrip(".")
    return plain


def _canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, (int, float, Decimal)):
        return _canonical_number(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("JSON object keys must be strings")
        ordered = sorted(value, key=lambda key: key.encode("utf-8"))
        return "{" + ",".join(
            f"{_canonical_json(key)}:{_canonical_json(value[key])}" for key in ordered
        ) + "}"
    raise ValueError(f"unsupported JSON value: {type(value).__name__}")


def encode_entry(entry: Entry | Mapping[str, Any]) -> bytes:
    """Encode one entry to the exact compact UTF-8 shape emitted on Android."""

    value = _wire_mapping(entry)
    for name in ("created_at", "updated_at", "deleted_at", "leak_check_revision", "leak_checked_at"):
        number = value[name]
        if number is not None and (not isinstance(number, (int, float)) or isinstance(number, bool) or not math.isfinite(number)):
            raise ValueError(f"{name} must be a finite JSON number or null")
    try:
        encoded = _canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("Entry contains a value that is not valid JSON") from error
    if len(encoded) > MAX_ENTRY_PLAIN_SIZE:
        raise ValueError("Entry payload exceeds the single-block limit")
    return encoded


def decode_entry(raw: bytes, expected_entry_id: UUID | None = None) -> Entry:
    """Decode one Android-compatible entry, ignoring unknown top-level keys."""

    if len(raw) > MAX_ENTRY_PLAIN_SIZE:
        raise ValueError("Entry payload exceeds the single-block limit")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Entry payload is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ValueError("Entry payload must be a JSON object")
    merged = {name: value.get(name, _DEFAULTS[name]) for name in _WIRE_FIELDS}
    parsed_id = _canonical_uuid(merged["id"])
    if expected_entry_id is not None and parsed_id != expected_entry_id:
        raise ValueError("Entry payload ID does not match the block object ID")
    if not isinstance(merged["fields"], dict):
        raise ValueError("Entry fields must be a JSON object")
    if not isinstance(merged["tags"], list) or not all(isinstance(item, str) for item in merged["tags"]):
        raise ValueError("Entry tags must be a JSON string array")
    for name in ("title", "username", "password", "url", "target_app", "notes", "secret_type"):
        if not isinstance(merged[name], str):
            raise ValueError(f"Entry {name} must be a JSON string")
    for name in ("created_at", "updated_at"):
        if not isinstance(merged[name], (int, float)) or isinstance(merged[name], bool):
            raise ValueError(f"Entry {name} must be a JSON number")
    for name in ("deleted_at", "leak_check_revision", "leak_checked_at"):
        if merged[name] is not None and (
            not isinstance(merged[name], (int, float)) or isinstance(merged[name], bool)
        ):
            raise ValueError(f"Entry {name} must be a JSON number or null")
    if merged["leak_pwned_count"] is not None and (
        not isinstance(merged["leak_pwned_count"], int) or isinstance(merged["leak_pwned_count"], bool)
    ):
        raise ValueError("Entry leak_pwned_count must be a JSON integer or null")
    if not isinstance(merged["leak_common_weak"], bool):
        raise ValueError("Entry leak_common_weak must be a JSON boolean")
    return Entry(**merged)


__all__ = ["MAX_ENTRY_PLAIN_SIZE", "decode_entry", "encode_entry"]
