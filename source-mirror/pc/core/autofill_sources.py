"""Stable autofill source policies and cross-client link wire codec."""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from .models import Entry


AUTOFILL_LINKS_KEY = "autofill_links"

AUTOFILL_ROLES = (
    "username",
    "email",
    "password",
    "one_time_code",
    "full_name",
    "phone",
    "country",
    "region",
    "city",
    "street_address",
    "postal_code",
    "cardholder",
    "card_number",
    "card_expiry",
    "card_cvv",
    "id_number",
    "api_key",
    "api_secret",
    "host",
    "port",
    "database",
    "ssid",
    "wifi_password",
    "recovery_answer",
    "custom_text",
    "custom_secret",
)

# This is the single metadata source for the runtime verification floor.
SENSITIVE_ROLES = frozenset(
    {
        "password",
        "card_cvv",
        "id_number",
        "api_key",
        "api_secret",
        "wifi_password",
        "recovery_answer",
        "custom_secret",
    }
)

_ROLE_SET = frozenset(AUTOFILL_ROLES)


def parse_role(value: object) -> str | None:
    """Return an exact known wire role, without trimming or case folding."""
    return value if type(value) is str and value in _ROLE_SET else None


def enforce_verification(role: str, requested: bool) -> bool:
    return requested or role in SENSITIVE_ROLES


@dataclass(frozen=True)
class FieldPolicy:
    role: str
    internal_default: bool
    external_default: bool
    requires_verification: bool


def _policy(role: str) -> FieldPolicy:
    sensitive = role in SENSITIVE_ROLES
    return FieldPolicy(role, True, not sensitive, sensitive)


_TOP_LEVEL_POLICIES = {
    "username": _policy("username"),
    "password": _policy("password"),
    # Android stores the built-in card, Wi-Fi, API, and server editors directly
    # in Entry.fields.  These explicit mappings keep those values selectable by
    # a PC login without relying on a client-specific module projection.
    "full_name": _policy("full_name"),
    "id_number": _policy("id_number"),
    "cardholder": _policy("cardholder"),
    "card_number": _policy("card_number"),
    "expiry": _policy("card_expiry"),
    "cvv": _policy("card_cvv"),
    "ssid": _policy("ssid"),
    "wifi_password": _policy("wifi_password"),
    "admin_password": _policy("wifi_password"),
    "api_key": _policy("api_key"),
    "api_secret": _policy("api_secret"),
    "server_host": _policy("host"),
    "server_port": _policy("port"),
    "server_user": _policy("username"),
    "server_pass": _policy("password"),
}

_MODULE_POLICIES = {
    ("login_account", "username"): _policy("username"),
    ("login_account", "password"): _policy("password"),
    ("address", "country"): _policy("country"),
    ("address", "region"): _policy("region"),
    ("address", "city"): _policy("city"),
    ("address", "address"): _policy("street_address"),
    ("address", "postal_code"): _policy("postal_code"),
    ("card_document", "full_name"): _policy("full_name"),
    ("card_document", "id_number"): _policy("id_number"),
    ("card_document", "cardholder"): _policy("cardholder"),
    ("card_document", "card_number"): _policy("card_number"),
    ("card_document", "expiry"): _policy("card_expiry"),
    ("card_document", "cvv"): _policy("card_cvv"),
    ("api_credential", "api_key"): _policy("api_key"),
    ("api_credential", "api_secret"): _policy("api_secret"),
    ("wifi", "ssid"): _policy("ssid"),
    ("wifi", "wifi_password"): _policy("wifi_password"),
    ("wifi", "admin_password"): _policy("wifi_password"),
    ("server_connection", "host"): _policy("host"),
    ("server_connection", "port"): _policy("port"),
    ("server_connection", "username"): _policy("username"),
    ("server_connection", "password"): _policy("password"),
    ("ssh", "host"): _policy("host"),
    ("ssh", "port"): _policy("port"),
    ("ssh", "username"): _policy("username"),
    ("ssh", "password"): _policy("password"),
    ("database", "host"): _policy("host"),
    ("database", "port"): _policy("port"),
    ("database", "database"): _policy("database"),
    ("database", "username"): _policy("username"),
    ("database", "password"): _policy("password"),
    ("recovery", "answer"): _policy("recovery_answer"),
    ("otp", "@computed/one_time_code"): _policy("one_time_code"),
    ("text", "value"): _policy("custom_text"),
    ("password", "value"): _policy("custom_secret"),
}


def policy_for_top_level(source_key: str) -> FieldPolicy | None:
    return _TOP_LEVEL_POLICIES.get(source_key)


def policy_for_field(module_type: str, source_key: str) -> FieldPolicy | None:
    return _MODULE_POLICIES.get((module_type, source_key))


@dataclass(frozen=True)
class AutofillFieldRef:
    module_id: str | None
    source_key: str
    role: str
    requires_verification: bool


@dataclass(frozen=True)
class AutofillLink:
    id: str
    source_entry_id: str
    fields: tuple[AutofillFieldRef, ...]

    def __post_init__(self) -> None:
        try:
            normalized = tuple(self.fields)
        except TypeError as exc:
            raise TypeError("AutofillLink.fields must be an iterable of AutofillFieldRef") from exc
        if not all(isinstance(field, AutofillFieldRef) for field in normalized):
            raise TypeError("AutofillLink.fields must contain only AutofillFieldRef values")
        object.__setattr__(self, "fields", normalized)


def decode_links(fields_or_raw: object) -> tuple[AutofillLink, ...]:
    """Decode links from an Entry fields mapping or the raw wire array.

    Malformed links and references are dropped independently. The function is
    deliberately total: arbitrary persisted input produces a tuple, not an
    exception.
    """
    raw = fields_or_raw.get(AUTOFILL_LINKS_KEY) if isinstance(fields_or_raw, dict) else fields_or_raw
    if not isinstance(raw, list):
        return ()

    decoded: list[AutofillLink] = []
    for value in raw:
        link = _decode_link(value)
        if link is not None:
            decoded.append(link)

    original_ids = {link.id for link in decoded}
    seen_ids: set[str] = set()
    occurrences: dict[str, int] = {}
    normalized: list[AutofillLink] = []
    for index, link in enumerate(decoded):
        occurrence = occurrences.get(link.id, 0)
        occurrences[link.id] = occurrence + 1
        if occurrence == 0:
            seen_ids.add(link.id)
            normalized.append(link)
        else:
            replacement = _deterministic_replacement_id(
                link, index, occurrence, original_ids, seen_ids
            )
            normalized.append(
                AutofillLink(replacement, link.source_entry_id, link.fields)
            )
    return tuple(normalized)


def _decode_link(value: object) -> AutofillLink | None:
    if not isinstance(value, dict):
        return None
    link_id = _nonblank_string(value.get("id"))
    source_entry_id = _nonblank_string(value.get("source_entry_id"))
    raw_fields = value.get("fields")
    if link_id is None or source_entry_id is None or not isinstance(raw_fields, list):
        return None
    fields = tuple(ref for raw in raw_fields if (ref := _decode_ref(raw)) is not None)
    if not fields:
        return None
    return AutofillLink(link_id, source_entry_id, fields)


def _decode_ref(value: object) -> AutofillFieldRef | None:
    if not isinstance(value, dict) or "module_id" not in value:
        return None
    raw_module_id = value["module_id"]
    if raw_module_id is None:
        module_id = None
    else:
        module_id = _nonblank_string(raw_module_id)
        if module_id is None:
            return None
    source_key = _nonblank_string(value.get("source_key"))
    role = parse_role(value.get("role"))
    requested = value.get("requires_verification")
    if source_key is None or role is None or type(requested) is not bool:
        return None
    return AutofillFieldRef(
        module_id, source_key, role, enforce_verification(role, requested)
    )


def encode_links(links: Iterable[AutofillLink]) -> list[dict[str, Any]]:
    """Normalize link objects and return their canonical wire representation."""
    raw = []
    try:
        for link in links:
            try:
                raw.append(_encode_raw_link(link))
            except (TypeError, AttributeError):
                continue
    except (TypeError, AttributeError):
        pass
    return [_encode_raw_link(link) for link in decode_links(raw)]


def encode_links_into_fields(fields: dict, links: Iterable[AutofillLink]) -> dict:
    """Return a copied fields mapping containing normalized links."""
    preserved = dict(fields) if isinstance(fields, dict) else {}
    encoded = encode_links(links)
    if encoded:
        preserved[AUTOFILL_LINKS_KEY] = encoded
    else:
        preserved.pop(AUTOFILL_LINKS_KEY, None)
    return preserved


def _encode_raw_link(link: AutofillLink) -> dict[str, Any]:
    raw_fields = link.fields if isinstance(link.fields, (list, tuple)) else ()
    encoded_fields = []
    for ref in raw_fields:
        try:
            encoded_fields.append(_encode_raw_ref(ref))
        except (TypeError, AttributeError):
            continue
    return {
        "id": link.id,
        "source_entry_id": link.source_entry_id,
        "fields": encoded_fields,
    }


def _encode_raw_ref(ref: AutofillFieldRef) -> dict[str, Any]:
    requested = ref.requires_verification
    verification = (
        enforce_verification(ref.role, requested)
        if parse_role(ref.role) is not None and type(requested) is bool
        else requested
    )
    return {
        "module_id": ref.module_id,
        "source_key": ref.source_key,
        "role": ref.role,
        "requires_verification": verification,
    }


def _deterministic_replacement_id(
    link: AutofillLink,
    index: int,
    occurrence: int,
    original_ids: set[str],
    seen_ids: set[str],
) -> str:
    salt = 0
    while True:
        parts = [
            "faevault-autofill-link-id-repair-v1|",
            _seed_part(link.id),
            _seed_part(link.source_entry_id),
            f"{index}|{occurrence}|{salt}|",
        ]
        for field in link.fields:
            parts.extend(
                (
                    _seed_part(field.module_id),
                    _seed_part(field.source_key),
                    _seed_part(field.role),
                    "1|" if field.requires_verification else "0|",
                )
            )
        digest = bytearray(hashlib.md5(_java_utf8_bytes("".join(parts))).digest())
        digest[6] = (digest[6] & 0x0F) | 0x30
        digest[8] = (digest[8] & 0x3F) | 0x80
        candidate = str(uuid.UUID(bytes=bytes(digest)))
        if candidate not in original_ids and candidate not in seen_ids:
            seen_ids.add(candidate)
            return candidate
        salt += 1


def _seed_part(value: str | None) -> str:
    if value is None:
        return "null|"
    # Java String.length counts UTF-16 code units, not Unicode code points.
    java_length = len(value.encode("utf-16-le", errors="surrogatepass")) // 2
    return f"{java_length}:{value}|"


def _java_utf8_bytes(value: str) -> bytes:
    encoded = bytearray()
    index = 0
    while index < len(value):
        code_point = ord(value[index])
        if 0xD800 <= code_point <= 0xDBFF:
            if index + 1 < len(value):
                low = ord(value[index + 1])
                if 0xDC00 <= low <= 0xDFFF:
                    combined = 0x10000 + ((code_point - 0xD800) << 10) + (low - 0xDC00)
                    encoded.extend(chr(combined).encode("utf-8"))
                    index += 2
                    continue
            encoded.append(0x3F)
        elif 0xDC00 <= code_point <= 0xDFFF:
            encoded.append(0x3F)
        else:
            encoded.extend(value[index].encode("utf-8"))
        index += 1
    return bytes(encoded)


def _nonblank_string(value: object) -> str | None:
    return value if type(value) is str and value.strip() else None


def matching_words(value: str) -> frozenset[str]:
    """Unicode whole words, with underscores treated as word separators."""
    return frozenset(re.findall(r"[^\W_]+", str(value or "").casefold()))


def shares_matching_word(left: str, right: str) -> bool:
    return bool(matching_words(left) & matching_words(right))


def entry_matching_text(entry: Entry) -> str:
    """Non-secret names and explicit app/website bindings for suggestions."""
    values = [entry.title, entry.target_app.removesuffix(".exe")]
    urls = [entry.url]
    raw_modules = entry.fields.get("modules", [])
    for module in raw_modules if isinstance(raw_modules, list) else ():
        if not isinstance(module, dict) or module.get("sensitive"):
            continue
        value = module.get("value")
        if not isinstance(value, str):
            continue
        kind = module.get("type")
        if kind == "target_app":
            values.append(value)
        elif kind == "url" or (kind == "text" and value.lower().startswith(("https://", "http://"))):
            urls.append(value)
    for value in urls:
        try:
            host = urlsplit(value).hostname or ""
            try:
                host = host.encode("ascii").decode("idna")
            except UnicodeError:
                pass
            values.append(host)
        except ValueError:
            continue
    return " ".join(values)
