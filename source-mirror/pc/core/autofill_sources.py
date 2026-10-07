"""Stable autofill source policies and cross-client link wire codec."""

from __future__ import annotations

import hashlib
import re
import uuid
import unicodedata
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


GENERIC_MATCH_WORDS = frozenset({"www", "com", "org", "net", "edu", "gov", "co", "app", "apps", "android", "auth", "login", "account", "accounts", "my", "git", "password", "mail", "email", "exe", "账号", "账户", "登录", "邮箱", "密码", "认证", "应用", "网页", "浏览器"})
AUTOFILL_BINDINGS_KEY = "_autofill_bindings"


def matching_words(value: str) -> frozenset[str]:
    text = unicodedata.normalize("NFKC", str(value or ""))
    raw_words = re.findall(r"[^\W_]+", text.casefold())
    text = re.sub(r"([\u3400-\u9fff]+)", r" \1 ", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text).casefold()
    return frozenset(word for word in [*raw_words, *re.findall(r"[^\W_]+", text)]
                     if len(word) >= 2 and word not in GENERIC_MATCH_WORDS)


def shares_matching_word(left: str, right: str) -> bool:
    left_words, right_words = matching_words(left), matching_words(right)
    if left_words & right_words:
        return True
    # Camel splitting also joins a brand such as WeChat for its flat spelling.
    def joined(value):
        text = unicodedata.normalize("NFKC", str(value or ""))
        text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
        text = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", text).casefold()
        return "".join(w for w in re.findall(r"[^\W_]+", text) if (w not in GENERIC_MATCH_WORDS or w == "git") and not re.search(r"[\u3400-\u9fff]", w))
    def compact(value):
        return "".join(re.findall(r"[^\W_]+", unicodedata.normalize("NFKC", str(value or "")).casefold()))
    if left_words and right_words and compact(left) == compact(right):
        return True
    if joined(left) and joined(left) == joined(right):
        return True
    return any(len(short) >= 2 and re.fullmatch(r"[\u3400-\u9fff]+", short)
               and short in long for a in left_words for b in right_words
               for short, long in [(a, b), (b, a)])


def entry_bindings(entry: Entry) -> tuple[dict, ...]:
    raw = entry.fields.get(AUTOFILL_BINDINGS_KEY, [])
    return tuple(item for item in raw if isinstance(item, dict)) if isinstance(raw, list) else ()


def entry_binding_values(entry: Entry, kind: str) -> tuple[str, ...]:
    values = [entry.url if kind == "web" else entry.target_app]
    raw_modules = entry.fields.get("modules", [])
    for module in raw_modules if isinstance(raw_modules, list) else ():
        if not isinstance(module, dict) or module.get("sensitive"):
            continue
        value = module.get("value")
        if isinstance(value, str) and (module.get("type") == ("url" if kind == "web" else "target_app")
                or (kind == "web" and module.get("type") == "text" and value.lower().startswith(("https://", "http://")))):
            values.append(value)
    return tuple(value for value in values if isinstance(value, str) and value.strip())


def with_linked_sources(vault, entries: Iterable[Entry]) -> list[Entry]:
    """Load only explicitly referenced sources, never unrelated categories."""
    by_id = {entry.id: entry for entry in entries}
    source_ids = {link.source_entry_id for entry in by_id.values() for link in entry.autofill_links()}
    for source_id in source_ids - by_id.keys():
        source = vault.read_entry(source_id)
        if source is not None:
            by_id[source_id] = source
    return list(by_id.values())


def entry_is_fillable(entry: Entry, entries=None) -> bool:
    from .autofill_resolver import resolve_snapshot
    return bool(resolve_snapshot(entry, entries or [entry]).values)


def entry_has_password(entry: Entry, entries=None) -> bool:
    from .autofill_resolver import resolve_snapshot
    return bool(resolve_snapshot(entry, entries or [entry]).get("password"))


def entry_matching_text(entry: Entry) -> str:
    values = [entry.title, *(v.removesuffix(".exe") for v in entry_binding_values(entry, "windows"))]
    urls = list(entry_binding_values(entry, "web"))
    for binding in entry_bindings(entry):
        if binding.get("kind") == "web":
            urls.append(str(binding.get("origin") or "https://" + str(binding.get("host") or "")))
        elif binding.get("kind") == "windows":
            values.append(str(binding.get("process") or "").removesuffix(".exe"))
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
