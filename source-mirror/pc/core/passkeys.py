"""Validation for Android-created Passkey records synchronized to the PC vault."""

from __future__ import annotations

import base64
import codecs
import hashlib
import ipaddress
import math
import re
import secrets
import sys
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa


class PasskeyError(ValueError):
    pass


class _PasskeyValidationError(PasskeyError):
    """An expected, secret-free validation failure."""


_COMMON_REQUIRED_RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "rp_id",
        "rp_name",
        "user_id",
        "user_name",
        "user_display_name",
        "credential_id",
        "public_key",
        "algorithm",
        "transports",
        "aaguid",
        "discoverable",
        "backup_eligible",
        "backup_state",
        "counter_mode",
        "sign_count",
        "created_at",
        "last_used_at",
    }
)
_REQUIRED_RECORD_FIELDS = _COMMON_REQUIRED_RECORD_FIELDS
_V2_BOOLEAN_FIELDS = ("discoverable", "backup_eligible", "backup_state")
_V2_OPTIONAL_TEXT_FIELDS = ("rp_name", "user_name", "user_display_name", "last_used_at")
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_BASE64URL_UNPADDED_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_ASCII_DOMAIN_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$")
_INVALID_RECORD_ERROR = "invalid passkey record"
_INVALID_JSON_ERROR = "invalid passkey record JSON data"
_INVALID_RP_ID_ERROR = "invalid passkey RP ID"
_NFKC_DOMAIN_DELIMITERS = frozenset("./\\:@#?[]")
_MAX_JSON_DEPTH = 128
_MAX_JSON_INTEGER_DECIMAL_DIGITS = 4300


@dataclass(frozen=True)
class ValidatedPasskey:
    """Typed, validated passkey data with the secret-bearing record hidden from repr."""

    _value: Mapping[str, Any] = field(repr=False)
    rp_id: str
    credential_id_bytes: bytes = field(repr=False)
    public_key_bytes: bytes = field(repr=False)
    key_identity: str
    sign_count: int
    schema_version: int
    key_mode: str
    device_id: str | None = None

    @property
    def value(self) -> dict[str, Any]:
        return _thaw_value(self._value)

    @property
    def identity(self) -> tuple[str, bytes]:
        return self.rp_id, self.credential_id_bytes

    def __repr__(self) -> str:
        return "ValidatedPasskey(<redacted>)"


def validate_record(value: dict) -> dict[str, Any]:
    """Validate a synced passkey record without rewriting key-bearing strings."""
    return _run_public_boundary(_validate_record, value)


def _validate_record(value: dict) -> dict[str, Any]:
    if type(value) is not dict:
        raise _PasskeyValidationError(_INVALID_JSON_ERROR)
    rp_id = _validated_rp_id(value.get("rp_id"))
    result = _thaw_value(_freeze_value(value))
    schema_text = result.get("schema_version")
    if schema_text is None:
        raise _PasskeyValidationError("incomplete passkey record")
    if schema_text not in ("2", "3"):
        raise _PasskeyValidationError("unsupported passkey schema version")
    schema_version = int(schema_text)
    for key in _REQUIRED_RECORD_FIELDS:
        if key not in result:
            raise _PasskeyValidationError("incomplete passkey record")

    result["rp_id"] = rp_id

    credential_id = _unb64u(result["credential_id"], maximum=1024, label="credential id")
    if not 16 <= len(credential_id) <= 1024:
        raise _PasskeyValidationError("invalid credential ID length")
    _unb64u(result["user_id"], maximum=1024, label="user ID")
    public_key_bytes = _unb64u(result["public_key"], maximum=4096, label="public key")
    algorithm_text = result.get("algorithm")
    supported_algorithms = {"-7", "-257", "-8"}
    if algorithm_text not in supported_algorithms:
        raise _PasskeyValidationError("unsupported passkey algorithm")
    algorithm = int(algorithm_text)
    cose_public_key = _parse_cose_public_key(public_key_bytes, algorithm)

    key_mode = result.get("key_mode")
    if schema_version == 2:
        if key_mode is not None or "private_key_envelope" in result or "device_binding" in result:
            raise _PasskeyValidationError("invalid passkey private-key carrier")
        private_key_bytes = _unb64u_unpadded(
            result.get("private_key"),
            minimum=16,
            maximum=16_384,
            label="passkey private key",
        )
        _validate_private_key(private_key_bytes, cose_public_key, algorithm)
        key_mode = "syncable"
        result["key_mode"] = "syncable"
    elif key_mode == "syncable":
        if result.get("private_key_envelope") is not None:
            raise _PasskeyValidationError("passkey private-key envelope is no longer supported")
        if "device_binding" in result and result["device_binding"] is not None:
            raise _PasskeyValidationError("invalid passkey private-key carrier")
        private_key_bytes = _unb64u_unpadded(
            result.get("private_key"),
            minimum=16,
            maximum=16_384,
            label="passkey private key",
        )
        _validate_private_key(private_key_bytes, cose_public_key, algorithm)
    elif key_mode == "device_bound":
        _validate_device_binding(result.get("device_binding"))
        if "private_key" in result:
            raise _PasskeyValidationError("invalid passkey private-key carrier")
        if "private_key_envelope" in result and result["private_key_envelope"] is not None:
            raise _PasskeyValidationError("invalid passkey private-key carrier")
    else:
        raise _PasskeyValidationError("unsupported passkey key mode")

    if result.get("transports") != "internal":
        raise _PasskeyValidationError("unsupported passkey transport")

    if result.get("counter_mode") != "synced_zero":
        raise _PasskeyValidationError("invalid passkey counter mode")
    sign_count = _signature_counter(result.get("sign_count"))
    if sign_count != 0:
        raise _PasskeyValidationError("synced_zero counter mode requires a zero signature counter")

    _validate_v2_metadata(result)
    if schema_version == 3:
        if result["key_mode"] == "syncable" and result["backup_eligible"] != "true":
            raise _PasskeyValidationError("invalid passkey backup metadata")
        if result["key_mode"] == "device_bound" and (result["backup_eligible"] != "false" or result["backup_state"] != "false"):
            raise _PasskeyValidationError("invalid passkey backup metadata")
    created_at = result.get("created_at")
    if not isinstance(created_at, str) or not created_at:
        raise _PasskeyValidationError("created at must be an RFC3339 timestamp")
    _validate_timestamp(result.get("created_at"), label="created at", allow_empty=False)
    _validate_timestamp(result.get("last_used_at"), label="last used at", allow_empty=True)

    result["sign_count"] = str(sign_count)
    result["algorithm"] = str(algorithm)
    result["transports"] = "internal"
    result["counter_mode"] = "synced_zero"
    return result


def parse_record(value: dict) -> ValidatedPasskey:
    """Return a typed view while retaining the validated record's source encodings."""
    return _run_public_boundary(_parse_record, value)


def normalized_rp_id(value: object) -> str:
    """Public, redacted boundary for RP ID normalization used by providers."""
    candidate = value[:-1] if isinstance(value, str) and value.endswith(".") else value
    return _run_public_boundary(_validated_rp_id, candidate).lower()


def decode_user_id(value: object) -> bytes:
    """Decode a validated opaque user handle without exposing the private helper."""
    return _run_public_boundary(
        lambda item: _unb64u(item, maximum=1024, label="user ID"), value
    )


def _parse_record(value: dict) -> ValidatedPasskey:
    validated = _validate_record(value)
    credential_id_bytes = _unb64u(validated["credential_id"], maximum=1024, label="credential id")
    public_key_bytes = _unb64u(validated["public_key"], maximum=4096, label="public key")
    schema_version = int(validated["schema_version"])
    key_mode = validated.get("key_mode", "syncable")
    device_id = None
    if key_mode == "device_bound":
        device_id = validated["device_binding"]["device_id"]
    return ValidatedPasskey(
        _value=_freeze_value(validated),
        rp_id=validated["rp_id"],
        credential_id_bytes=credential_id_bytes,
        public_key_bytes=public_key_bytes,
        key_identity=hashlib.sha256(public_key_bytes).hexdigest(),
        sign_count=int(validated["sign_count"]),
        schema_version=schema_version,
        key_mode=key_mode,
        device_id=device_id,
    )


def _run_public_boundary(operation, value):
    error_message: str | None = None
    try:
        return operation(value)
    except _PasskeyValidationError as exc:
        if len(exc.args) == 1 and type(exc.args[0]) is str:
            error_message = exc.args[0]
        else:
            error_message = _INVALID_RECORD_ERROR
    except Exception:
        error_message = _INVALID_RECORD_ERROR
    raise PasskeyError(error_message) from None


def _unb64u(value: str, *, maximum: int = 4096, label: str = "base64url value") -> bytes:
    if not isinstance(value, str) or not value:
        raise _PasskeyValidationError(f"invalid {label} base64url value")
    maximum_encoded = ((maximum + 2) // 3) * 4
    if len(value) > maximum_encoded:
        raise _PasskeyValidationError(f"{label} is too large")
    if not _BASE64URL_RE.fullmatch(value):
        raise _PasskeyValidationError(f"invalid {label} base64url value")
    padding = len(value) - len(value.rstrip("="))
    if (padding and len(value) % 4) or (not padding and len(value) % 4 == 1):
        raise _PasskeyValidationError(f"invalid {label} base64url value")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise _PasskeyValidationError(f"invalid {label} base64url value") from exc
    canonical = base64.urlsafe_b64encode(decoded).decode()
    if not padding:
        canonical = canonical.rstrip("=")
    if not secrets.compare_digest(canonical, value):
        raise _PasskeyValidationError(f"invalid {label} base64url value")
    if len(decoded) > maximum:
        raise _PasskeyValidationError(f"{label} is too large")
    return decoded


def _unb64u_unpadded(
    value: Any,
    *,
    minimum: int,
    maximum: int,
    label: str,
) -> bytes:
    if not isinstance(value, str) or not _BASE64URL_UNPADDED_RE.fullmatch(value):
        raise _PasskeyValidationError(f"invalid {label} base64url value")
    decoded = _unb64u(value, maximum=maximum, label=label)
    if len(decoded) < minimum:
        raise _PasskeyValidationError(f"invalid {label} length")
    return decoded


def _canonical_uuid(value: Any, *, label: str) -> str:
    if not isinstance(value, str):
        raise _PasskeyValidationError(f"invalid {label}")
    try:
        canonical = str(UUID(value))
    except (AttributeError, ValueError):
        raise _PasskeyValidationError(f"invalid {label}") from None
    if not secrets.compare_digest(canonical, value.lower()):
        raise _PasskeyValidationError(f"invalid {label}")
    return canonical


def _positive_decimal(value: Any, *, label: str) -> int:
    if not isinstance(value, str) or not value or not value.isascii() or not value.isdigit():
        raise _PasskeyValidationError(f"invalid {label}")
    parsed = int(value)
    if parsed <= 0 or str(parsed) != value:
        raise _PasskeyValidationError(f"invalid {label}")
    return parsed


def _validate_device_binding(value: Any) -> dict[str, Any]:
    if type(value) is not dict or value.get("provider") != "android_keystore":
        raise _PasskeyValidationError("invalid passkey device binding")
    _canonical_uuid(value.get("device_id"), label="passkey device ID")
    binding = _unb64u_unpadded(value.get("binding_id"), minimum=16, maximum=64, label="passkey binding ID")
    if not 16 <= len(binding) <= 64:
        raise _PasskeyValidationError("invalid passkey binding ID length")
    _positive_decimal(value.get("key_generation"), label="passkey key generation")
    return value


def _validate_private_key(private_bytes: bytes, cose: dict[int, Any], algorithm: int) -> None:
    try:
        private_key = serialization.load_der_private_key(private_bytes, password=None)
        if algorithm == -7:
            if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(
                private_key.curve, ec.SECP256R1
            ):
                raise ValueError
            numbers = private_key.public_key().public_numbers()
            if numbers.x.to_bytes(32, "big") != cose.get(-2) or numbers.y.to_bytes(32, "big") != cose.get(-3):
                raise ValueError
        elif algorithm == -257:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError
            numbers = private_key.public_key().public_numbers()
            if numbers.n != int.from_bytes(cose.get(-1, b""), "big") or numbers.e != int.from_bytes(
                cose.get(-2, b""), "big"
            ):
                raise ValueError
        elif algorithm == -8:
            if not isinstance(private_key, ed25519.Ed25519PrivateKey):
                raise ValueError
            raw_public = private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if raw_public != cose.get(-2):
                raise ValueError
        else:
            raise ValueError
    except (TypeError, ValueError):
        raise _PasskeyValidationError("passkey private key does not match public key") from None


def _parse_cose_public_key(value: bytes, algorithm: int) -> dict[int, Any]:
    try:
        reader = _CborReader(value)
        map_length = reader.read_map_length()
        if map_length > 16:
            raise ValueError
        result: dict[int, Any] = {}
        previous_key_order: tuple[int, bytes] | None = None
        for _ in range(map_length):
            key_start = reader.offset
            key = reader.read_item()
            key_bytes = value[key_start : reader.offset]
            key_order = len(key_bytes), key_bytes
            if not isinstance(key, int) or key in result:
                raise ValueError
            if previous_key_order is not None and key_order <= previous_key_order:
                raise ValueError
            previous_key_order = key_order
            item = reader.read_item()
            if not isinstance(item, (int, bytes)):
                raise ValueError
            result[key] = item
        if reader.offset != len(value):
            raise ValueError
    except (IndexError, ValueError):
        raise _PasskeyValidationError("malformed or non-deterministic COSE CBOR key") from None

    if result.get(3) != algorithm:
        raise _PasskeyValidationError("unsupported COSE key algorithm")
    if algorithm == -7:
        if result.get(1) != 2:
            raise _PasskeyValidationError("unsupported COSE key type")
        if result.get(-1) != 1:
            raise _PasskeyValidationError("unsupported COSE key curve")
        x = result.get(-2)
        y = result.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise _PasskeyValidationError("invalid COSE public key coordinates")
        try:
            ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"),
                int.from_bytes(y, "big"),
                ec.SECP256R1(),
            ).public_key()
        except ValueError as exc:
            raise _PasskeyValidationError("invalid COSE public key point") from exc
    elif algorithm == -257:
        if result.get(1) != 3:
            raise _PasskeyValidationError("unsupported COSE key type")
        modulus = result.get(-1)
        exponent = result.get(-2)
        if (
            not isinstance(modulus, bytes)
            or not isinstance(exponent, bytes)
            or len(modulus) not in range(256, 513)
            or not 1 <= len(exponent) <= 8
            or modulus[0] == 0
            or exponent[0] == 0
        ):
            raise _PasskeyValidationError("invalid COSE RSA public key")
        try:
            rsa.RSAPublicNumbers(
                int.from_bytes(exponent, "big"),
                int.from_bytes(modulus, "big"),
            ).public_key()
        except ValueError as exc:
            raise _PasskeyValidationError("invalid COSE RSA public key") from exc
    elif algorithm == -8:
        if result.get(1) != 1:
            raise _PasskeyValidationError("unsupported COSE key type")
        if result.get(-1) != 6:
            raise _PasskeyValidationError("unsupported COSE key curve")
        public_bytes = result.get(-2)
        if not isinstance(public_bytes, bytes) or len(public_bytes) != 32:
            raise _PasskeyValidationError("invalid COSE Ed25519 public key")
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)
        except ValueError as exc:
            raise _PasskeyValidationError("invalid COSE Ed25519 public key") from exc
    else:
        raise _PasskeyValidationError("unsupported COSE key algorithm")
    return result


class _CborReader:
    def __init__(self, value: bytes):
        self.value = value
        self.offset = 0

    def read_map_length(self) -> int:
        major, argument = self._head()
        if major != 5:
            raise ValueError
        return argument

    def read_item(self) -> int | bytes:
        major, argument = self._head()
        if major == 0:
            return argument
        if major == 1:
            return -1 - argument
        if major == 2:
            end = self.offset + argument
            if end > len(self.value):
                raise ValueError
            item = self.value[self.offset : end]
            self.offset = end
            return item
        raise ValueError

    def _head(self) -> tuple[int, int]:
        if self.offset >= len(self.value):
            raise ValueError
        initial = self.value[self.offset]
        self.offset += 1
        major = initial >> 5
        additional = initial & 0x1F
        if additional < 24:
            return major, additional
        byte_count = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if byte_count is None or self.offset + byte_count > len(self.value):
            raise ValueError
        encoded = self.value[self.offset : self.offset + byte_count]
        self.offset += byte_count
        argument = int.from_bytes(encoded, "big")
        minimum = {1: 24, 2: 0x100, 4: 0x10000, 8: 0x100000000}[byte_count]
        if argument < minimum:
            raise ValueError
        return major, argument


def _signature_counter(value: Any) -> int:
    if isinstance(value, bool):
        raise _PasskeyValidationError("invalid signature counter")
    if isinstance(value, str) and value.isascii() and value.isdigit():
        if len(value) > 10 or (len(value) == 10 and value > "4294967295"):
            raise _PasskeyValidationError("invalid signature counter")
        count = int(value)
    else:
        raise _PasskeyValidationError("invalid signature counter")
    if not 0 <= count <= 0xFFFFFFFF:
        raise _PasskeyValidationError("invalid signature counter")
    return count


def _freeze_value(value: Any) -> Any:
    return _copy_json_graph(value, freeze=True)


def _thaw_value(value: Any) -> Any:
    return _copy_json_graph(value, freeze=False)


def _copy_json_graph(value: Any, *, freeze: bool) -> Any:
    """Copy a JSON graph iteratively so attacker-controlled depth cannot recurse."""
    root: list[Any] = [None]
    active_containers: set[int] = set()
    stack: list[tuple[str, Any, int, Any, Any, Any]] = [("enter", value, 0, root, 0, None)]

    while stack:
        action, source, depth, parent, slot, state = stack.pop()
        if action == "exit":
            kind, mutable = state
            active_containers.remove(id(source))
            if freeze:
                copied = MappingProxyType(mutable) if kind == "dict" else tuple(mutable)
            else:
                copied = mutable
            parent[slot] = copied
            continue

        value_type = type(source)
        if freeze:
            is_dict = value_type is dict
            is_list = value_type is list
        else:
            is_dict = isinstance(source, MappingProxyType)
            is_list = value_type is tuple

        if is_dict or is_list:
            if depth > _MAX_JSON_DEPTH:
                raise ValueError
            container_id = id(source)
            if container_id in active_containers:
                raise _PasskeyValidationError(_INVALID_JSON_ERROR)
            active_containers.add(container_id)

            if is_dict:
                mutable: Any = {}
                items = list(source.items())
                for key, _ in items:
                    if type(key) is not str:
                        raise _PasskeyValidationError(_INVALID_JSON_ERROR)
                stack.append(("exit", source, depth, parent, slot, ("dict", mutable)))
                for key, item in reversed(items):
                    stack.append(("enter", item, depth + 1, mutable, key, None))
            else:
                mutable = [None] * len(source)
                stack.append(("exit", source, depth, parent, slot, ("list", mutable)))
                for index in range(len(source) - 1, -1, -1):
                    stack.append(("enter", source[index], depth + 1, mutable, index, None))
            continue

        if value_type in (str, bool) or source is None:
            parent[slot] = source
            continue
        if value_type is int:
            if not _integer_is_safely_bounded(source):
                raise ValueError
            parent[slot] = source
            continue
        if value_type is float and math.isfinite(source):
            parent[slot] = source
            continue
        raise _PasskeyValidationError(_INVALID_JSON_ERROR)

    return root[0]


def _integer_is_safely_bounded(value: int) -> bool:
    configured_limit = getattr(sys, "get_int_max_str_digits", lambda: 0)()
    digit_limit = min(
        configured_limit or _MAX_JSON_INTEGER_DECIMAL_DIGITS,
        _MAX_JSON_INTEGER_DECIMAL_DIGITS,
    )
    return abs(value) < 10**digit_limit


def _validate_v2_metadata(value: dict[str, Any]) -> None:
    aaguid = value.get("aaguid")
    if not isinstance(aaguid, str) or not aaguid.strip():
        raise _PasskeyValidationError("invalid passkey AAGUID")
    try:
        UUID(aaguid)
    except (AttributeError, ValueError):
        raise _PasskeyValidationError("invalid passkey AAGUID") from None
    for key in _V2_OPTIONAL_TEXT_FIELDS:
        if key in value and not isinstance(value[key], str):
            raise _PasskeyValidationError(f"invalid passkey text metadata: {key}")
    for key in _V2_BOOLEAN_FIELDS:
        if value.get(key) not in ("true", "false"):
            raise _PasskeyValidationError(f"invalid passkey boolean metadata: {key}")
    if value["backup_state"] == "true" and value["backup_eligible"] != "true":
        raise _PasskeyValidationError("invalid passkey backup metadata")


def _validate_timestamp(value: Any, *, label: str, allow_empty: bool) -> None:
    if value is None:
        return
    if value == "" and allow_empty:
        return
    if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
        raise _PasskeyValidationError(f"{label} must be an RFC3339 timestamp")
    normalized = value.replace("t", "T").replace("z", "Z")
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise _PasskeyValidationError(f"{label} must be an RFC3339 timestamp") from exc


def _validated_rp_id(value: Any) -> str:
    try:
        if type(value) is not str:
            raise ValueError
        if not value or len(value) > 253 or value != value.strip() or "." not in value or value.startswith(".") or value.endswith("."):
            raise ValueError
        for character in value:
            if character.isspace() or unicodedata.category(character).startswith("C"):
                raise ValueError

        ascii_labels: list[str] = []
        for label in value.split("."):
            if not label:
                raise ValueError
            normalized_label = "".join(_normalize_rp_id_character(character) for character in label)
            if any(character.isspace() or character in _NFKC_DOMAIN_DELIMITERS for character in normalized_label):
                raise ValueError
            if not _rp_id_label_characters_are_valid(normalized_label):
                raise ValueError
            ascii_label = _encode_rp_id_label(label)
            if not ascii_label or "." in ascii_label or len(ascii_label) > 63 or not _ASCII_DOMAIN_LABEL_RE.fullmatch(ascii_label):
                raise ValueError
            ascii_labels.append(ascii_label)

        ascii_name = ".".join(ascii_labels)
        if len(ascii_name) > 253 or ascii_labels[-1].isdigit():
            raise ValueError
        if _rp_id_is_ip_address(ascii_name):
            raise ValueError
    except Exception:
        raise _PasskeyValidationError(_INVALID_RP_ID_ERROR) from None
    return value


def _normalize_rp_id_character(character: str) -> str:
    return unicodedata.normalize("NFKC", character)


def _rp_id_label_characters_are_valid(label: str) -> bool:
    for index, character in enumerate(label):
        if character == "-" or unicodedata.category(character)[0] in "LMN":
            continue
        if character == "\u00b7":
            between_l_characters = index and index + 1 < len(label) and label[index - 1].lower() == label[index + 1].lower() == "l"
            if between_l_characters:
                continue
        elif character == "\u0375":
            if index + 1 < len(label) and unicodedata.name(label[index + 1], "").startswith("GREEK "):
                continue
        elif character in "\u05f3\u05f4":
            if index and unicodedata.name(label[index - 1], "").startswith("HEBREW "):
                continue
        elif character == "\u30fb":
            if any(unicodedata.name(item, "").startswith(("HIRAGANA ", "KATAKANA ", "CJK UNIFIED IDEOGRAPH-")) for item in label):
                continue
        return False
    return True


def _encode_rp_id_label(label: str) -> str:
    ascii_label = codecs.encode(label, "idna").decode("ascii")
    if ascii_label.lower().startswith("xn--"):
        decoded_label = codecs.decode(ascii_label.encode("ascii"), "idna")
        if codecs.encode(decoded_label, "idna").decode("ascii").lower() != ascii_label.lower():
            raise UnicodeError
    return ascii_label


def _rp_id_is_ip_address(ascii_name: str) -> bool:
    try:
        ipaddress.ip_address(ascii_name)
    except ValueError:
        return False
    return True
