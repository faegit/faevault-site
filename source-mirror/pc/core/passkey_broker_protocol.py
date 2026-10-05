"""Strict framing and message validation for the native Passkey broker."""

from __future__ import annotations

import base64
import json
import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any, Mapping


PROTOCOL_VERSION = 1
MAX_FRAME = 1024 * 1024
MAX_TEXT = 4096
MESSAGE_TYPES = frozenset(
    {"hello", "status", "list", "make", "get", "commit-use", "reconcile", "cancel"}
)
SENSITIVE_FIELDS = frozenset(
    {
        "masterPassword", "password", "recoveryKey", "rootKey", "syncKey",
        "accessToken", "refreshToken", "command", "environment", "vaultPath",
    }
)
_COMMON = frozenset({"v", "type", "requestId", "deadlineMs"})
_FIELDS = {
    "hello": _COMMON | {"challenge", "processId", "packageFamilyName"},
    "status": _COMMON,
    "list": _COMMON | {"rpId", "allowCredentialIds"},
    "make": _COMMON | {"record"},
    "get": _COMMON | {"rpId", "credentialId"},
    "commit-use": _COMMON | {"rpId", "credentialId", "lastUsedAt", "signCount"},
    "reconcile": _COMMON | {"credentials"},
    "cancel": _COMMON | {"targetRequestId"},
}


class ProtocolError(ValueError):
    """A peer sent malformed, oversized, expired, or forbidden input."""


@dataclass(frozen=True)
class Request:
    type: str
    request_id: uuid.UUID
    deadline_ms: int
    payload: Mapping[str, Any]


def encode_frame(message: Mapping[str, Any]) -> bytes:
    _validate_json_value(message)
    payload = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if not payload or len(payload) > MAX_FRAME:
        raise ProtocolError("invalid frame size")
    return struct.pack("<I", len(payload)) + payload


def decode_frame(data: bytes) -> dict[str, Any]:
    if len(data) < 4:
        raise ProtocolError("incomplete frame")
    (size,) = struct.unpack_from("<I", data)
    if size < 2 or size > MAX_FRAME or len(data) != size + 4:
        raise ProtocolError("invalid frame size")
    try:
        message = json.loads(data[4:].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("message must be an object")
    _validate_json_value(message)
    return message


def decode_request(data: bytes, *, now_ms: int | None = None) -> Request:
    message = decode_frame(data)
    if message.get("v") != PROTOCOL_VERSION:
        raise ProtocolError("unsupported protocol version")
    message_type = message.get("type")
    if message_type not in MESSAGE_TYPES:
        raise ProtocolError("unsupported message type")
    unknown = set(message) - _FIELDS[message_type]
    forbidden = set(message) & SENSITIVE_FIELDS
    if unknown or forbidden:
        raise ProtocolError("forbidden or unknown field")
    try:
        request_id = uuid.UUID(str(message["requestId"]))
        deadline_ms = int(message["deadlineMs"])
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise ProtocolError("invalid request metadata") from exc
    current = int(time.time() * 1000) if now_ms is None else now_ms
    if deadline_ms <= current or deadline_ms > current + 120_000:
        raise ProtocolError("invalid request deadline")
    payload = {key: value for key, value in message.items() if key not in _COMMON}
    return Request(message_type, request_id, deadline_ms, payload)


def b64u_decode(value: object, *, maximum: int = 65536) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        raise ProtocolError("invalid Base64URL value")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise ProtocolError("invalid Base64URL value") from exc
    if len(decoded) > maximum or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode() != value:
        raise ProtocolError("invalid Base64URL value")
    return decoded


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    if depth > 12:
        raise ProtocolError("message nesting is too deep")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise ProtocolError("floating point values are forbidden")
    if isinstance(value, str):
        if len(value) > MAX_TEXT:
            raise ProtocolError("text value is too long")
        return
    if isinstance(value, list):
        if len(value) > 1024:
            raise ProtocolError("array is too large")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 128:
            raise ProtocolError("object is too large")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 64:
                raise ProtocolError("invalid object key")
            if key in SENSITIVE_FIELDS:
                raise ProtocolError("sensitive field is forbidden")
            _validate_json_value(item, depth=depth + 1)
        return
    raise ProtocolError("unsupported JSON value")
