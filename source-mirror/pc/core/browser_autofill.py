"""Security boundary and wire protocol for PC browser autofill."""

from __future__ import annotations

import ipaddress
import json
import struct
from dataclasses import dataclass
from io import BufferedIOBase
from typing import Any
from urllib.parse import urlsplit

from .models import Entry, SecretType
from .public_suffix import registrable_domain
from .autofill_sources import matching_words, shares_matching_word, entry_matching_text, entry_binding_values, entry_bindings, entry_is_fillable, parse_role

PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1024 * 1024
HOST_NAME = "app.fae.vault.autofill"
CHROMIUM_EXTENSION_ID = "mkgodfefjfbgipnanaimcaopapmccaeb"
FIREFOX_EXTENSION_ID = "vault-autofill@fae.local"
MAX_REQUEST_ID = 128
MAX_ORIGIN = 2048
MAX_TITLE = 256
MAX_USERNAME = 512
MAX_PASSWORD = 4096
class ProtocolError(ValueError):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable


@dataclass(frozen=True)
class BrowserRequest:
    request_id: str
    action: str
    origin: str | None = None
    credential_id: str | None = None
    title: str = ""
    username: str = ""
    password: str = ""
    master_password: str = ""
    query: str = ""
    manual_selection: bool = False
    field_key: str = ""
    field_role: str = ""


def _is_authorizable_ip(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Permit explicit authorization for unicast IP origins, including VPN and link-local ranges."""
    return address.is_loopback or not (address.is_unspecified or address.is_multicast or address.is_reserved)


def normalize_origin(raw: object, *, allow_ip: bool = False) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_ORIGIN:
        raise ProtocolError("INVALID_ORIGIN", "无法确认网页来源")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise ProtocolError("INVALID_ORIGIN", "网页来源格式无效") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ProtocolError("INVALID_ORIGIN", "仅支持 HTTPS 网页")
    if parsed.username is not None or parsed.password is not None:
        raise ProtocolError("INVALID_ORIGIN", "网页来源不能包含用户信息")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ProtocolError("INVALID_ORIGIN", "必须提供网页 Origin，而不是完整地址")
    host = parsed.hostname.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ProtocolError("INVALID_ORIGIN", "网页域名无效") from exc
    if host == "localhost" or len(host) > 253:
        raise ProtocolError("INVALID_ORIGIN", "网页域名无效")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or any(not label or len(label) > 63 for label in host.split(".")):
            raise ProtocolError("INVALID_ORIGIN", "网页域名无效")
        normalized_host = host
    else:
        if not allow_ip or not _is_authorizable_ip(address):
            raise ProtocolError(
                "INVALID_ORIGIN",
                "此 IP 地址需要先获得明确授权",
            )
        normalized_host = f"[{host}]" if address.version == 6 else host
    if port is not None and not 1 <= port <= 65535:
        raise ProtocolError("INVALID_ORIGIN", "网页端口无效")
    return f"https://{normalized_host}" + (f":{port}" if port not in (None, 443) else "")


def is_ip_origin(origin: str) -> bool:
    try:
        normalized = normalize_origin(origin, allow_ip=True)
        ipaddress.ip_address(urlsplit(normalized).hostname or "")
    except (ProtocolError, ValueError):
        return False
    return True


def normalize_excluded_host(raw: object) -> str:
    """Normalize a user-entered website exclusion to an IDNA host."""
    text = str(raw or "").strip()
    if not text:
        return ""
    candidate = text if "://" in text else f"https://{text}"
    try:
        parsed = urlsplit(candidate)
        host = (parsed.hostname or "").rstrip(".").lower().encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""
    if not host or parsed.username is not None or parsed.password is not None:
        return ""
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        pass
    if "." not in host or len(host) > 253 or any(not label or len(label) > 63 for label in host.split(".")):
        return ""
    return host


def origin_is_excluded(origin: str, excluded_hosts: object) -> bool:
    host = (urlsplit(origin).hostname or "").rstrip(".").lower()
    normalized = {
        value
        for raw in (excluded_hosts if isinstance(excluded_hosts, (list, tuple, set)) else ())
        if (value := normalize_excluded_host(raw))
    }
    return any(host == blocked or host.endswith(f".{blocked}") for blocked in normalized)


def entry_origin(entry: Entry, *, allow_ip: bool = False) -> str | None:
    raw = str(entry.url or "").strip()
    if not raw:
        return None
    try:
        parsed = urlsplit(raw)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return normalize_origin(origin, allow_ip=allow_ip)
    except (ProtocolError, ValueError):
        return None


def entry_origins(entry: Entry) -> tuple[str, ...]:
    result = []
    for raw in entry_binding_values(entry, "web"):
        try:
            parsed = urlsplit(raw if "://" in raw else "https://" + raw)
            result.append(normalize_origin(f"{parsed.scheme}://{parsed.netloc}", allow_ip=True))
        except (ProtocolError, ValueError):
            pass
    for binding in entry_bindings(entry):
        if binding.get("kind") != "web":
            continue
        raw = binding.get("origin") or "https://" + str(binding.get("host") or "")
        try:
            result.append(normalize_origin(raw, allow_ip=True))
        except ProtocolError:
            pass
    return tuple(dict.fromkeys(result))


def browser_match_reason(entry: Entry, origin: str) -> str | None:
    normalized = normalize_origin(origin, allow_ip=True)
    for binding in entry_bindings(entry):
        if binding.get("kind") != "web":
            continue
        try:
            remembered = normalize_origin(binding.get("origin") or "https://" + str(binding.get("host") or ""), allow_ip=True)
        except ProtocolError:
            continue
        if remembered == normalized:
            return "confirmed"
    origins = entry_origins(entry)
    if normalized in origins:
        return "exact"
    if is_ip_origin(normalized):
        return None
    host = urlsplit(normalized).hostname or ""
    related_origins = list(origins)
    for raw in entry_binding_values(entry, "web"):
        try:
            parsed = urlsplit(raw if "://" in raw else "https://" + raw)
            if parsed.scheme == "http" and parsed.hostname:
                related_origins.append("https://" + parsed.netloc)
        except ValueError:
            pass
    for stored in related_origins:
        other = urlsplit(stored).hostname or ""
        site = registrable_domain(host)
        if site is not None and site == registrable_domain(other):
            return "same_site"
    try:
        readable = host.encode("ascii").decode("idna")
    except UnicodeError:
        readable = host
    return "name" if shares_matching_word(entry_matching_text(entry), ".".join(readable.split(".")[:-1])) else None


def matching_entries(
    entries: list[Entry], origin: str, *, limit: int = 20, allow_ip: bool = False
) -> list[Entry]:
    normalized = normalize_origin(origin, allow_ip=allow_ip)
    matches = [
        entry
        for entry in entries
        if entry.secret_type == SecretType.LOGIN
        and entry.deleted_at is None
        and entry_is_fillable(entry, entries)
        and browser_match_reason(entry, normalized) in {"confirmed", "exact"}
    ]
    matches.sort(key=lambda item: (item.title.lower(), item.username.lower(), item.id))
    return matches[: max(0, min(int(limit), 20))]


def word_matching_entries(entries: list[Entry], origin: str, *, limit: int = 20) -> list[Entry]:
    """Low confidence suggestions only; never a source authorization check."""
    normalized = normalize_origin(origin, allow_ip=True)
    if is_ip_origin(normalized):
        return []
    host = urlsplit(normalized).hostname or ""
    try:
        host = host.encode("ascii").decode("idna")
    except UnicodeError:
        pass
    # The final DNS label is a suffix, not a useful account-name word.
    words = matching_words(".".join(host.split(".")[:-1])) - {"www", "com", "org", "net", "edu", "gov", "co"}
    if not words:
        return []
    matches = [entry for entry in entries if entry.secret_type == SecretType.LOGIN
               and entry.deleted_at is None and entry_is_fillable(entry, entries)
               and browser_match_reason(entry, normalized) in {"same_site", "name"}]
    matches.sort(key=lambda entry: (entry.title.casefold(), entry.username.casefold(), entry.id))
    return matches[:max(0, min(int(limit), 20))]


def parse_request(value: object) -> BrowserRequest:
    if not isinstance(value, dict):
        raise ProtocolError("INVALID_REQUEST", "请求必须是 JSON 对象")
    if value.get("version") != PROTOCOL_VERSION:
        raise ProtocolError("UNSUPPORTED_VERSION", "不支持的协议版本")
    request_id = value.get("requestId")
    if not isinstance(request_id, str) or not request_id or len(request_id) > MAX_REQUEST_ID:
        raise ProtocolError("INVALID_REQUEST", "请求标识无效")
    action = value.get("action")
    if action not in {"status", "unlock", "list", "get", "save", "authorize", "lock", "map_field"}:
        raise ProtocolError("UNSUPPORTED_ACTION", "不支持的操作")
    origin = normalize_origin(value.get("origin"), allow_ip=True) if action in {"list", "get", "save", "authorize", "map_field"} else None
    credential_id = None
    if action in {"get", "map_field"}:
        credential_id = _bounded_text(value.get("credentialId"), "凭据标识", 128, required=True)
    title = username = password = ""
    if action == "save":
        title = _bounded_text(value.get("title", ""), "标题", MAX_TITLE).strip()
        username = _bounded_text(value.get("username", ""), "用户名", MAX_USERNAME).strip()
        password = _bounded_text(value.get("password"), "密码", MAX_PASSWORD, required=True)
    master_password = ""
    if action == "unlock":
        master_password = _bounded_text(value.get("masterPassword"), "主密码", 128, required=True)
    query = _bounded_text(value.get("query", ""), "搜索", 80)
    manual = value.get("manualSelection", False)
    if type(manual) is not bool:
        raise ProtocolError("INVALID_REQUEST", "选择状态无效")
    key = _bounded_text(value.get("fieldKey", ""), "字段", 256, required=action == "map_field")
    role = _bounded_text(value.get("fieldRole", ""), "角色", 64)
    if role and parse_role(role) is None:
        raise ProtocolError("INVALID_REQUEST", "字段角色无效")
    return BrowserRequest(request_id, action, origin, credential_id, title, username, password, master_password, query, manual, key, role)


def success(request_id: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"version": PROTOCOL_VERSION, "requestId": request_id, "ok": True, "result": result or {}}


def failure(request_id: str, error: ProtocolError) -> dict[str, Any]:
    return {
        "version": PROTOCOL_VERSION,
        "requestId": request_id,
        "ok": False,
        "error": {"code": error.code, "message": error.message, "retryable": error.retryable},
    }


def read_message(stream: BufferedIOBase) -> dict[str, Any] | None:
    header = _read_exact(stream, 4)
    if header == b"":
        return None
    if len(header) != 4:
        raise ProtocolError("INVALID_REQUEST", "消息头不完整")
    length = struct.unpack("<I", header)[0]
    if length <= 0 or length > MAX_MESSAGE_BYTES:
        raise ProtocolError("INVALID_REQUEST", "消息长度无效")
    payload = _read_exact(stream, length)
    if len(payload) != length:
        raise ProtocolError("INVALID_REQUEST", "消息内容不完整")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("INVALID_REQUEST", "消息不是有效 JSON") from exc
    if not isinstance(value, dict):
        raise ProtocolError("INVALID_REQUEST", "消息必须是 JSON 对象")
    return value


def write_message(stream: BufferedIOBase, value: dict[str, Any]) -> None:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError("INTERNAL_ERROR", "响应内容过大")
    stream.write(struct.pack("<I", len(payload)))
    stream.write(payload)
    stream.flush()


def _read_exact(stream: BufferedIOBase, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            break
        result.extend(part)
    return bytes(result)


def _bounded_text(value: object, label: str, maximum: int, *, required: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (required and not value):
        raise ProtocolError("INVALID_REQUEST", f"{label}无效")
    if "\x00" in value:
        raise ProtocolError("INVALID_REQUEST", f"{label}无效")
    return value
