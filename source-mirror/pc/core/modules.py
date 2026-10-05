"""Reusable entry-module contract shared with the Android client."""

from __future__ import annotations

import copy
import datetime as _datetime
import uuid
from typing import Any, Iterable

from core import autofill_sources


MODULES_KEY = "modules"

TEXT = "text"
PASSWORD = "password"
MULTILINE = "multiline"
URL = "url"
DATE = "date"
BOOLEAN = "boolean"
DATETIME = "datetime"
IMAGES = "images"
ATTACHMENTS = "attachments"
LOGIN_ACCOUNT = "login_account"
TARGET_APP = "target_app"
API_CREDENTIAL = "api_credential"
WIFI = "wifi"
SERVER_CONNECTION = "server_connection"
SSH = "ssh"
DATABASE = "database"
OTP = "otp"
CARD_DOCUMENT = "card_document"
ADDRESS = "address"
RECOVERY = "recovery"
PASSKEY = "passkey"

CATALOG: dict[str, dict[str, Any]] = {
    TEXT: {"title": "文本", "group": "通用", "default": ""},
    PASSWORD: {"title": "密码", "group": "通用", "default": "", "sensitive": True, "locked": True},
    MULTILINE: {"title": "Markdown", "group": "通用", "default": ""},
    BOOLEAN: {"title": "布尔值", "group": "通用", "default": False},
    DATETIME: {"title": "日期时间", "group": "通用", "default": "", "default_config": {"mode": "datetime"}},
    IMAGES: {"title": "图片", "group": "通用", "default": []},
    ATTACHMENTS: {"title": "附件", "group": "通用", "default": [], "sensitive": True},
    LOGIN_ACCOUNT: {
        "title": "登录", "group": "账号与网络", "default": {"username": "", "password": ""},
        "sensitive_fields": ("password",),
    },
    TARGET_APP: {"title": "关联程序", "group": "账号与网络", "default": ""},
    API_CREDENTIAL: {
        "title": "API凭证", "group": "账号与网络",
        "default": {"api_key": "", "api_secret": ""},
        "sensitive_fields": ("api_key", "api_secret"),
    },
    WIFI: {
        "title": "Wi-Fi", "group": "账号与网络",
        "default": {"ssid": "", "wifi_password": "", "security_type": "无加密", "router_admin_url": "", "admin_password": ""},
        "sensitive_fields": ("wifi_password", "admin_password"),
    },
    SERVER_CONNECTION: {
        "title": "服务器", "group": "账号与网络",
        "default": {"host": "", "port": "", "username": "", "password": ""},
        "sensitive_fields": ("password",),
    },
    SSH: {
        "title": "SSH", "group": "账号与网络",
        "default": {"host": "", "port": "", "username": "", "password": "", "private_key": "", "fingerprint": ""},
        "sensitive_fields": ("password", "private_key"),
    },
    DATABASE: {
        "title": "数据库连接", "group": "账号与网络",
        "default": {"engine": "MySQL", "host": "", "port": "", "database": "", "username": "", "password": ""},
        "sensitive_fields": ("password",),
    },
    OTP: {
        "title": "动态码", "group": "账号与网络",
        "default": {"secret": "", "issuer": "", "label": "", "algorithm": "SHA1", "digits": "6", "period": "30", "type": "totp", "counter": "0", "otp_domains": ""},
        "sensitive_fields": ("secret",),
        "field_order": ("secret", "issuer", "label", "algorithm", "digits", "period", "type", "counter", "otp_domains"),
    },
    CARD_DOCUMENT: {
        "title": "卡证", "group": "身份与金融",
        "default": {},
        "sensitive_fields": ("card_number", "cvv", "withdrawal_password", "id_number"),
        "field_order": ("card_type", "cardholder", "card_number", "bank", "bank_branch", "expiry", "cvv", "withdrawal_password", "images"),
    },
    ADDRESS: {
        "title": "地址", "group": "身份与金融",
        "default": {"country": "", "region": "", "city": "", "address": "", "postal_code": ""},
    },
    RECOVERY: {
        "title": "恢复信息", "group": "身份与金融",
        "default": {"question": "", "answer": ""},
        "sensitive_fields": ("answer",),
    },
    PASSKEY: {
        "title": "通行密钥", "group": "账号与网络",
        "default": {
            "schema_version": "2",
            "rp_id": "", "rp_name": "", "user_id": "", "user_name": "", "user_display_name": "",
            "credential_id": "", "private_key": "", "public_key": "",
            "algorithm": "-7", "transports": "internal",
            "aaguid": "", "discoverable": "true",
            "backup_eligible": "true", "backup_state": "true",
            "counter_mode": "synced_zero", "sign_count": "0",
            "created_at": "", "last_used_at": "",
        },
        "sensitive_fields": ("user_id", "credential_id", "private_key"),
        "locked": True,
    },
}

GROUPS = ("通用", "账号与网络", "身份与金融")

# 已精简的遗留通用类型：加载时自动映射为 TEXT。
_LEGACY_TYPES = {URL: TEXT, DATE: TEXT}

CARD_BANK = "bank_card"
CARD_ID_CARD = "id_card"
CARD_CUSTOM = "custom"

CARD_TYPE_LABELS = {
    CARD_BANK: "银行卡",
    CARD_ID_CARD: "身份证",
    CARD_CUSTOM: "其他卡证",
}
CARD_DOCUMENT_FIELDS = ("card_type", "full_name", "id_number", "issue_date", "expiry_date", "issuing_authority")
CARD_FIELDS = {
    CARD_BANK: ("card_type", "cardholder", "card_number", "bank", "bank_branch", "expiry", "cvv", "withdrawal_password"),
    CARD_ID_CARD: CARD_DOCUMENT_FIELDS,
    CARD_CUSTOM: ("card_type", "card_name", "card_number", "expiry", "notes"),
}


def card_value_for_type(value: dict[str, Any], requested_type: str) -> dict[str, Any]:
    card_type = requested_type if requested_type in CARD_TYPE_LABELS else CARD_CUSTOM
    result: dict[str, Any] = {key: "" for key in CARD_FIELDS[card_type]}
    result["card_type"] = card_type
    result["images"] = []
    if isinstance(value, dict):
        result.update(copy.deepcopy(value))
    result["card_type"] = card_type
    if not isinstance(result.get("images"), list):
        result["images"] = []
    return result


# 卡证默认值由 card_value_for_type 生成（与 Android 端 catalog 一致）。
CATALOG[CARD_DOCUMENT]["default"] = card_value_for_type({}, CARD_BANK)


def valid_datetime_value(mode: str, value: str) -> bool:
    if not value:
        return True
    try:
        if mode == "date":
            return _datetime.date.fromisoformat(value).isoformat() == value
        if mode == "time":
            return _datetime.time.fromisoformat(value).strftime("%H:%M") == value
        if mode == "datetime":
            return _datetime.datetime.fromisoformat(value).strftime("%Y-%m-%dT%H:%M") == value
    except ValueError:
        pass
    return False


def _new_id() -> str:
    return uuid.uuid4().hex


def _resolve_type(module_type: str) -> str:
    return _LEGACY_TYPES.get(module_type, module_type)


def mandatory_sensitive_fields(module_type: str) -> set[str]:
    return set(CATALOG.get(module_type, {}).get("sensitive_fields", ()))


def default_autofill_role(module_type: str) -> str | None:
    return CATALOG.get(_resolve_type(module_type), {}).get("autofill_role")


def autofill_role_options(module_type: str, *, sensitive: bool = False) -> tuple[str, ...]:
    module_type = _resolve_type(module_type)
    if module_type == TEXT:
        return tuple(
            role for role in autofill_sources.AUTOFILL_ROLES
            if sensitive or role not in autofill_sources.SENSITIVE_ROLES
        )
    if module_type == PASSWORD:
        return (
            "password", "card_cvv", "id_number", "api_key", "api_secret",
            "wifi_password", "recovery_answer", "custom_secret",
        )
    if module_type == DATETIME:
        return ("card_expiry", "custom_text")
    return ()


def configured_autofill_role(module: dict) -> str | None:
    config = module.get("config") if isinstance(module, dict) else None
    return autofill_sources.parse_role(config.get("autofill_role")) if isinstance(config, dict) else None


def with_autofill_role(module: dict, role: str | None) -> dict:
    if role is not None and autofill_sources.parse_role(role) is None:
        raise ValueError("unknown autofill role")
    result = copy.deepcopy(module)
    config = result.get("config") if isinstance(result.get("config"), dict) else {}
    result["config"] = config
    if role is None:
        config.pop("autofill_role", None)
    else:
        config["autofill_role"] = role
    return result


def compact_compound_value(value: dict[str, Any]) -> dict[str, Any]:
    """Drop empty text placeholders while preserving meaningful defaults and unknown data."""
    return {
        key: item
        for key, item in value.items()
        if not isinstance(item, str) or item.strip()
    }


def new_module(module_type: str, *, required: bool = False) -> dict:
    module_type = _resolve_type(module_type)
    spec = CATALOG.get(module_type, {})
    module = {
        "id": _new_id(),
        "type": module_type,
        "title": str(spec.get("title") or "未知模块"),
        "sensitive": bool(spec.get("sensitive", False)),
        "required": bool(required),
        "config": copy.deepcopy(spec.get("default_config", {})),
        "value": copy.deepcopy(spec.get("default", "")),
    }
    if module_type == CARD_DOCUMENT:
        module["value"] = card_value_for_type({}, CARD_BANK)
    return module


def normalize_modules(value: Any) -> list[dict]:
    if not isinstance(value, list):
        return []
    result: list[dict] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict):
            continue
        module = copy.deepcopy(raw)
        module_type = _resolve_type(str(module.get("type") or "unknown"))
        module_id = str(module.get("id") or "")
        if not module_id or module_id in seen:
            module_id = _new_id()
        seen.add(module_id)
        spec = CATALOG.get(module_type, {})
        module["id"] = module_id
        module["type"] = module_type
        module["title"] = str(module.get("title") or spec.get("title") or "未知模块")
        module["required"] = bool(module.get("required", False))
        module["config"] = module.get("config") if isinstance(module.get("config"), dict) else {}
        if module_type == DATETIME and module["config"].get("mode") not in {"date", "time", "datetime"}:
            module["config"]["mode"] = "datetime"
        module["sensitive"] = bool(module.get("sensitive", spec.get("sensitive", False)))
        if spec.get("locked"):
            module["sensitive"] = True
        if "value" not in module:
            module["value"] = copy.deepcopy(spec.get("default", ""))
        if module_type == BOOLEAN:
            raw_boolean = module.get("value")
            module["value"] = raw_boolean if type(raw_boolean) is bool else str(raw_boolean).lower() == "true"
        elif module_type == CARD_DOCUMENT:
            raw_card = module.get("value") if isinstance(module.get("value"), dict) else {}
            requested = str(raw_card.get("card_type") or CARD_BANK)
            module["value"] = card_value_for_type(raw_card, requested)
        result.append(module)
    return result


def modules_from_fields(fields: dict | None) -> list[dict]:
    return normalize_modules(fields.get(MODULES_KEY)) if isinstance(fields, dict) else []


def detail_modules(fields: dict | None, secret_type: str) -> list[dict]:
    """Return add-on modules, excluding the first module consumed by a specialized detail view."""
    all_modules = modules_from_fields(fields)
    consumed_types: set[str]
    if secret_type == "login":
        consumed_types = {TARGET_APP, OTP}
    elif secret_type == "otp":
        consumed_types = {OTP}
    elif secret_type == "secure_note":
        consumed_types = {MULTILINE}
    elif secret_type == "server":
        consumed_types = {SERVER_CONNECTION}
    else:
        consumed_types = set()
    if not consumed_types:
        return all_modules
    result: list[dict] = []
    consumed: set[str] = set()
    for module in all_modules:
        module_type = str(module.get("type") or "")
        if module_type in consumed_types and module_type not in consumed:
            consumed.add(module_type)
            continue
        result.append(module)
    return result


def target_app_value(fields: dict | None) -> str:
    """Read a package/process binding from the reusable target-app module."""
    for module in modules_from_fields(fields):
        if module.get("type") == TARGET_APP:
            value = module.get("value")
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def ordered_value(module: dict) -> dict:
    """按模块定义顺序重排 value 字段，未知键保持原相对顺序附加到尾部。

    与 Android 端 EntryModules.orderedValue 一致：PMVE canonical 排序会使
    落盘后的模块 value 变为字典序，渲染前需恢复定义顺序。
    """
    value = module.get("value")
    if not isinstance(value, dict):
        return value
    module_type = str(module.get("type") or "")
    if module_type == CARD_DOCUMENT:
        card_type = str(value.get("card_type") or CARD_BANK)
        order = (*CARD_FIELDS.get(card_type, CARD_FIELDS[CARD_CUSTOM]), "images")
    else:
        order = CATALOG.get(module_type, {}).get("field_order")
    if not order:
        return value
    out: dict[str, Any] = {}
    for key in order:
        if key in value:
            out[key] = value[key]
    for key, item in value.items():
        if key not in out:
            out[key] = item
    return out


def fields_with_modules(fields: dict | None, value: Iterable[dict]) -> dict:
    result = dict(fields) if isinstance(fields, dict) else {}
    result[MODULES_KEY] = normalize_modules(list(value))
    return result


_SEARCH_MAX_DEPTH = 64
_SEARCH_MAX_NODES = 10_000
_SEARCH_MAX_CONTAINER_ITEMS = 1_000
_SEARCH_MAX_TEXT_CHARS = 100_000


def _plain_strings(value: Any) -> Iterable[str]:
    """Yield searchable text without recursing through hostile module data."""
    stack: list[tuple[bool, Any, int]] = [(False, value, 0)]
    active: set[int] = set()
    nodes = 0
    text_chars = 0

    while stack:
        leaving, current, depth = stack.pop()
        if leaving:
            active.discard(id(current))
            continue

        nodes += 1
        if nodes > _SEARCH_MAX_NODES or depth > _SEARCH_MAX_DEPTH:
            continue

        current_type = type(current)
        if current_type is str:
            if not current or len(current) > _SEARCH_MAX_TEXT_CHARS - text_chars:
                continue
            text_chars += len(current)
            yield current
            continue

        if current_type is dict:
            if len(current) > _SEARCH_MAX_CONTAINER_ITEMS or id(current) in active:
                continue
            active.add(id(current))
            stack.append((True, current, depth))
            for child in reversed(tuple(current.values())):
                stack.append((False, child, depth + 1))
            continue

        if current_type in (list, tuple):
            if len(current) > _SEARCH_MAX_CONTAINER_ITEMS or id(current) in active:
                continue
            active.add(id(current))
            stack.append((True, current, depth))
            for child in reversed(current):
                stack.append((False, child, depth + 1))


def searchable_values(module: dict) -> list[str]:
    """Return non-sensitive text only; malformed data defaults to protection."""
    module_type = str(module.get("type") or "")
    if bool(module.get("sensitive")) or module_type in {IMAGES, ATTACHMENTS}:
        return []
    value = module.get("value")
    if not isinstance(value, dict):
        return list(_plain_strings(value))
    config = module.get("config") if isinstance(module.get("config"), dict) else {}
    sensitive = mandatory_sensitive_fields(module_type)
    extra = config.get("sensitiveFields")
    if isinstance(extra, list):
        sensitive.update(str(key) for key in extra)
    return [
        text
        for key, child in value.items()
        if key not in sensitive and key not in {"images", "card_type"}
        for text in _plain_strings(child)
    ]


def preset_modules(secret_type: str) -> list[dict]:
    if secret_type == "secure_note":
        return [new_module(MULTILINE, required=True)]
    if secret_type == "server":
        return [new_module(SERVER_CONNECTION, required=True)]
    return []


def has_sensitive_modules(fields: dict | None) -> bool:
    for module in modules_from_fields(fields):
        module_type = str(module.get("type") or "")
        if bool(module.get("sensitive")) or mandatory_sensitive_fields(module_type):
            return True
        config = module.get("config")
        if isinstance(config, dict) and config.get("sensitiveFields"):
            return True
    return False


# Wi-Fi 加密类型统一标准文本（与 Android 端保持一致的规范化值，落盘/展示/二维码都用它）。
# 每一项即标准全名，不做聚合/简化简写。
WIFI_SECURITY_OPTIONS = (
    "无加密",
    "WEP",
    "WPA-Personal",
    "WPA2-Personal",
    "WPA2/WPA3-Personal",
    "WPA3-Personal",
    "WPA-Enterprise",
    "WPA2-Enterprise",
    "WPA3-Enterprise",
)

# 从外部来源（系统 netsh / 二维码 T 字段 / 旧数据）读取到的原始值 → 精确标准文本。
# 大小写不敏感；netsh 常见取值含 WPA2-Personal、WPA3-Personal、Open 等。
_WIFI_SECURITY_NORMALIZE = {
    "": "无加密",
    "NOPASS": "无加密",
    "OPEN": "无加密",
    "开放网络": "无加密",
    "WEP": "WEP",
    "WPA": "WPA-Personal",
    "WPAPSK": "WPA-Personal",
    "WPA-PERSONAL": "WPA-Personal",
    "WPA-TKIP": "WPA-Personal",
    "WPA/WPA2": "WPA2-Personal",
    "WPA2": "WPA2-Personal",
    "WPA2PSK": "WPA2-Personal",
    "WPA2-PERSONAL": "WPA2-Personal",
    "WPA2-PSK": "WPA2-Personal",
    "WPA2-AES": "WPA2-Personal",
    "WPA2/WPA3": "WPA2/WPA3-Personal",
    "WPA-WPA3": "WPA2/WPA3-Personal",
    "WPA3": "WPA3-Personal",
    "SAE": "WPA3-Personal",
    "WPA3-PERSONAL": "WPA3-Personal",
    "WPA3-SAE": "WPA3-Personal",
    "混合加密": "WPA2/WPA3-Personal",
    "WPA-ENTERPRISE": "WPA-Enterprise",
    "WPA-EAP": "WPA-Enterprise",
    "WPA2-ENTERPRISE": "WPA2-Enterprise",
    "WPA2-EAP": "WPA2-Enterprise",
    "WPA3-ENTERPRISE": "WPA3-Enterprise",
    "WPA3-EAP": "WPA3-Enterprise",
}

# 未知值需向上兼容保留原样，但落盘前会先尝试归一化以确保跨端枚举一致。
def normalize_wifi_security(value: str) -> str:
    """把任意来源的 Wi-Fi 加密类型映射到统一标准文本；未知值原样返回。"""
    if value is None:
        return "无加密"
    text = str(value).strip()
    if not text:
        return "无加密"
    return _WIFI_SECURITY_NORMALIZE.get(text.upper(), text)


def wifi_qr_auth_token(security: str, has_password: bool) -> str:
    """分享 Wi-Fi 二维码的 T 字段：WPA 族统一聚合为 WPA（规范通配语义），WEP 精确保留。

    密码非空时拒绝 nopass（规范里 nopass 不应携带密码），兜底提升为 WPA。
    """
    norm = normalize_wifi_security(security)
    if norm == "WEP":
        return "WEP"
    if norm == "无加密":
        return "nopass" if not has_password else "WPA"
    return "WPA"
