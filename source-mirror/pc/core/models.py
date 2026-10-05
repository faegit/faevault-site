"""密码条目数据模型。"""

from __future__ import annotations

import calendar
import copy
import datetime as _dt
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field

from . import modules as entry_modules
from . import otp


def monotonic_timestamp(previous: float, now: float | None = None) -> float:
    """Return a local LWW timestamp that cannot move an imported revision backwards."""
    current = time.time() if now is None else float(now)
    return max(current, float(previous or 0.0) + 0.001)


def _timestamp_seconds(value: object, *, default: float | None) -> float | None:
    """Normalize legacy numeric strings and ISO-8601 timestamps to Unix seconds."""
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    if not isinstance(value, str):
        return default
    try:
        parsed = _dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return default


class SecretType:
    LOGIN = "login"
    CARD_DOCUMENT = "card_document"
    WIFI = "wifi"
    API_KEY = "api_key"
    OTP = "otp"
    SECURE_NOTE = "secure_note"
    SERVER = "server"
    CUSTOM = "custom"
    PASSKEY = "passkey"

    # ALL 是可持久化的跨端类型；Passkey 只能由 Credential Manager 创建。
    ALL = [LOGIN, WIFI, CARD_DOCUMENT, API_KEY, OTP, SECURE_NOTE, SERVER, CUSTOM, PASSKEY]
    CREATABLE = [LOGIN, WIFI, CARD_DOCUMENT, API_KEY, OTP, SECURE_NOTE, SERVER, CUSTOM]
    NAV_TYPES = ALL
    LABELS = {
        LOGIN: "登录",
        CARD_DOCUMENT: "卡证",
        WIFI: "Wi-Fi",
        API_KEY: "API凭证",
        OTP: "动态码",
        SECURE_NOTE: "安全笔记",
        SERVER: "服务器",
        CUSTOM: "自定义",
        PASSKEY: "通行密钥",
    }
_KNOWN_FIELDS: frozenset[str] | None = None


def _get_known_fields() -> frozenset[str]:
    global _KNOWN_FIELDS
    if _KNOWN_FIELDS is None:
        _KNOWN_FIELDS = frozenset(Entry.__dataclass_fields__)
    return _KNOWN_FIELDS


_HAYSTACK_SKIP_KEYS = frozenset(("card_images_b64", "id_images_b64", entry_modules.MODULES_KEY))


@dataclass
class Entry:
    title: str = ""
    username: str = ""
    password: str = ""
    url: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    target_app: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    secret_type: str = field(default=SecretType.LOGIN)
    fields: dict = field(default_factory=dict)
    deleted_at: float | None = None
    leak_check_revision: float | None = None
    leak_pwned_count: int | None = None
    leak_common_weak: bool = False
    leak_checked_at: float | None = None

    # 缓存搜索用 haystack 和排序键，惰性生成
    _haystack: str = field(default="", repr=False, compare=False)
    _title_lower: str = field(default="", repr=False, compare=False)

    def __post_init__(self) -> None:
        self.title = str(self.title or "")
        self.username = str(self.username or "")
        self.password = str(self.password or "")
        self.url = str(self.url or "")
        self.notes = str(self.notes or "")

        if self.tags is None:
            self.tags = []
        elif isinstance(self.tags, str):
            self.tags = [self.tags]
        else:
            try:
                self.tags = [str(t) for t in self.tags if t is not None]
            except Exception:
                self.tags = []

        self.target_app = str(self.target_app or "")

        if not self.id:
            self.id = str(uuid.uuid4())
        else:
            self.id = str(self.id)

        now = time.time()
        for attr in ("created_at", "updated_at"):
            setattr(self, attr, _timestamp_seconds(getattr(self, attr), default=now))

        self.deleted_at = _timestamp_seconds(self.deleted_at, default=None)
        self.leak_check_revision = _timestamp_seconds(self.leak_check_revision, default=None)
        try:
            self.leak_pwned_count = None if self.leak_pwned_count is None else max(0, int(self.leak_pwned_count))
        except (TypeError, ValueError):
            self.leak_pwned_count = None
        self.leak_common_weak = bool(self.leak_common_weak)
        self.leak_checked_at = _timestamp_seconds(self.leak_checked_at, default=None)

        if not isinstance(self.fields, dict):
            self.fields = {}

        # 旧版 Android 将 Passkey 模块错误地放在 login 条目中。加载时升级为独立类型，
        # 后续保存即可把修正后的类型同步回两端。
        has_passkey = any(
            module.get("type") == entry_modules.PASSKEY
            for module in entry_modules.modules_from_fields(self.fields)
        )
        if self.secret_type == SecretType.LOGIN and has_passkey:
            self.secret_type = SecretType.PASSKEY
        elif self.secret_type not in SecretType.ALL:
            self.secret_type = SecretType.LOGIN

        self._haystack = ""
        self._title_lower = self.title.lower()

    def _build_haystack(self) -> str:
        if self._haystack:
            return self._haystack
        legacy_extra = [str(v) for k, v in self.fields.items() if k not in _HAYSTACK_SKIP_KEYS and v]
        module_extra = [
            text
            for module in entry_modules.modules_from_fields(self.fields)
            for text in entry_modules.searchable_values(module)
        ]
        extra = " ".join([*legacy_extra, *module_extra])
        parts = [
            self.title or "",
            self.username or "",
            self.url or "",
            self.notes or "",
            " ".join(self.tags or []),
            self.target_app,
            extra,
        ]
        self._haystack = " ".join(parts).lower()
        return self._haystack

    def invalidate_haystack(self) -> None:
        self._haystack = ""

    def get_field(self, key: str, default: str = "") -> str:
        return str(self.fields.get(key, default) or default)

    def _otp_module_value(self) -> dict | None:
        for module in entry_modules.modules_from_fields(self.fields):
            if module.get("type") == entry_modules.OTP and isinstance(module.get("value"), dict):
                return module["value"]
        return None

    def get_otp_field(self, key: str, default: str = "") -> str:
        """读取 OTP 字段：内嵌 OTP 模块 value 优先，顶层 fields 兜底（与 Android 端一致）。"""
        value = self._otp_module_value()
        if value is not None and key in value and value[key] is not None:
            return str(value[key])
        return self.get_field(key, default)

    def otp_fields(self) -> dict:
        """返回用于生成动态码的 OTP 字段（模块 value 或顶层 fields）。"""
        module_value = self._otp_module_value()
        return otp.normalize_fields(module_value if module_value is not None else self.fields)

    def has_otp(self) -> bool:
        return bool(self.otp_fields().get("secret"))

    def otp_binding_id(self) -> str:
        """顶层 bound_otp_id：指向一个独立 OTP 条目（外部绑定）。"""
        return self.get_field("bound_otp_id")

    def autofill_links(self):
        """Decode stored autofill links without mutating or migrating this entry."""
        from .autofill_sources import decode_links

        return decode_links(self.fields)

    def migrate_autofill_links(self) -> None:
        """Explicitly migrate the legacy OTP binding into the link wire format."""
        from .autofill_sources import (
            AutofillFieldRef,
            AutofillLink,
            encode_links_into_fields,
        )

        if "bound_otp_id" not in self.fields:
            return

        legacy = self.fields.get("bound_otp_id")
        preserved = dict(self.fields)
        preserved.pop("bound_otp_id", None)
        if type(legacy) is str and legacy.strip():
            links = self.autofill_links()
            equivalent = any(
                link.source_entry_id == legacy
                and any(
                    ref.module_id is None
                    and ref.source_key == "@computed/one_time_code"
                    and ref.role == "one_time_code"
                    for ref in link.fields
                )
                for link in links
            )
            if not equivalent:
                links = links + (
                    AutofillLink(
                        id=str(uuid.uuid4()),
                        source_entry_id=legacy,
                        fields=(
                            AutofillFieldRef(
                                module_id=None,
                                source_key="@computed/one_time_code",
                                role="one_time_code",
                                requires_verification=False,
                            ),
                        ),
                    ),
                )
            preserved = encode_links_into_fields(preserved, links)

        if preserved != self.fields:
            self.fields = preserved
            self.invalidate_haystack()

    def otp_domains(self) -> list[str]:
        """关联域名：内嵌 OTP 模块 value 优先，顶层兜底。"""
        return otp.parse_otp_domains(self.get_otp_field("otp_domains"))

    @property
    def display_secret(self) -> str:
        if self.secret_type == SecretType.LOGIN:
            return self.username
        if self.secret_type == SecretType.CARD_DOCUMENT:
            last4 = self.get_field("card_number_last4")
            if not last4:
                digits = re.sub(r"\D", "", self.get_field("card_number"))
                last4 = digits[-4:] if len(digits) >= 4 else ""
            if last4:
                return f"**** {last4}"
            holder = self.get_field("cardholder") or self.get_field("full_name")
            if holder:
                return holder
            id_last = re.sub(r"\s", "", self.get_field("id_number"))[-4:]
            return f"**** {id_last}" if id_last else ""
        if self.secret_type == SecretType.WIFI:
            return self.get_field("ssid")
        if self.secret_type == SecretType.API_KEY:
            return self.get_field("service") or self.username
        if self.secret_type == SecretType.OTP:
            return self.get_field("label") or self.get_field("issuer") or self.username
        if self.secret_type == SecretType.SERVER:
            host = self.get_field("server_host")
            user = self.get_field("server_user")
            if host or user:
                return host or user
            for module in entry_modules.modules_from_fields(self.fields):
                if module.get("type") == entry_modules.SERVER_CONNECTION:
                    value = module.get("value")
                    if isinstance(value, dict):
                        return str(value.get("host") or value.get("username") or "")
        if self.secret_type == SecretType.SECURE_NOTE:
            return ""
        if self.secret_type == SecretType.CUSTOM:
            return f"{len(entry_modules.modules_from_fields(self.fields))} 个模块"
        if self.secret_type == SecretType.PASSKEY:
            return self.username or self.url
        return self.username

    def touch(self) -> None:
        self.updated_at = monotonic_timestamp(self.updated_at)
        self.invalidate_haystack()

    def matches(self, query: str) -> bool:
        if not query:
            return True
        return query.lower() in self._build_haystack()

    def dedup_key(self) -> tuple[str, str, str]:
        return (
            self.secret_type,
            (self.title or "").strip().lower(),
            (self.username or "").strip().lower(),
        )

    def content_equals(self, other: "Entry") -> bool:
        """与 ``other`` 的所有可编辑字段（含名称、用户名）是否完全一致，用于判断编辑是否产生实质变化。"""
        return self.title == other.title and self.username == other.username and self.same_content(other)

    def same_content(self, other: "Entry") -> bool:
        return (
            self.secret_type == other.secret_type
            and self.password == other.password
            and self.url == other.url
            and self.notes == other.notes
            and set(self.tags or []) == set(other.tags or [])
            and self.target_app == other.target_app
            and self.fields == other.fields
        )

    def same_except_password(self, other: "Entry") -> bool:
        """除密码和标签外，其他字段均相同（用于识别密码冲突型重复）。"""
        return self.secret_type == other.secret_type and self.url == other.url and self.notes == other.notes and self.fields == other.fields

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("_haystack", None)
        d.pop("_title_lower", None)
        return d

    def __getstate__(self) -> dict:
        """复制/序列化 Entry 时剥离 Vault 会话回引用。

        ``Vault._lazy`` 会给条目挂上 ``entry.vault``（运行时回引用），而已解锁的
        Vault 会话刻意不可 pickle（见 ``Vault.__getstate__``）。若不剥离，
        ``copy.deepcopy(entry)``（例如打开编辑弹窗）会连带复制整个已解锁会话并抛错。
        """
        state = dict(self.__dict__)
        state.pop("vault", None)
        return state

    def __setstate__(self, state: dict) -> None:
        self.__dict__.update(state)

    @classmethod
    def from_dict(cls, data: dict) -> "Entry":
        known = _get_known_fields()
        return cls(**{k: v for k, v in data.items() if k in known})

    # --- Expiry helpers ---
    def get_expiry_date(self) -> _dt.date | None:
        """尝试从条目字段解析到期日期，优先使用 `expiry_date`，兼容多种常见格式。"""
        module_expiry = ""
        for module in entry_modules.modules_from_fields(self.fields):
            if module.get("type") != entry_modules.CARD_DOCUMENT:
                continue
            value = module.get("value")
            if isinstance(value, dict):
                module_expiry = str(value.get("expiry_date") or value.get("expiry") or "")
                if module_expiry:
                    break
        s = (self.get_field("expiry_date") or self.get_field("expiry") or module_expiry).strip()
        if not s:
            return None
        # 尝试 ISO
        try:
            return _dt.date.fromisoformat(s)
        except Exception:
            pass
        # 完整日期格式
        for f in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%Y%m%d"):
            try:
                return _dt.datetime.strptime(s, f).date()
            except Exception:
                continue
        # 银行卡有效期 MM/YY（2位年份）：用当前年份的后两位与卡面年份的差值，
        # 直接换算为完整年份，不做世纪判断。取该月最后一天为到期日。
        m = re.match(r"^(\d{1,2})/(\d{2})$", s)
        if m:
            month, yy = int(m.group(1)), int(m.group(2))
            if 1 <= month <= 12:
                today = _dt.date.today()
                year = today.year + (yy - today.year % 100)
                last_day = calendar.monthrange(year, month)[1]
                return _dt.date(year, month, last_day)
        # 仅含年月（4位年份），视为该月最后一天到期
        for f in ("%Y-%m", "%Y/%m", "%m/%Y"):
            try:
                dt = _dt.datetime.strptime(s, f)
                last_day = calendar.monthrange(dt.year, dt.month)[1]
                return dt.date().replace(day=last_day)
            except Exception:
                continue
        # 通过正则提取 YYYY-MM-DD
        try:
            m = re.search(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})", s)
            if m:
                return _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except Exception:
            pass
        return None

    def expiry_status(self, days_threshold: int = 30) -> str | None:
        """返回过期状态：'expired' / 'expiring_soon' / None。"""
        d = self.get_expiry_date()
        if not d:
            return None
        today = _dt.date.today()
        if d < today:
            return "expired"
        delta = (d - today).days
        if delta <= days_threshold:
            return "expiring_soon"
        return None

    def expiry_date_str(self) -> str | None:
        d = self.get_expiry_date()
        if not d:
            return None
        return d.strftime("%Y-%m-%d")


class LazyEntry:
    """延迟解密代理——外观与 :class:`Entry` 一致，但 password/notes/fields
    在首次访问时才从独立的加密 payload 中解密，避免敏感信息常驻内存。"""

    _META = frozenset(
        {
            "id",
            "title",
            "username",
            "url",
            "secret_type",
            "tags",
            "target_app",
            "created_at",
            "updated_at",
            "deleted_at",
            "display_secret",
            "leak_check_revision",
            "leak_pwned_count",
            "leak_common_weak",
            "leak_checked_at",
        }
    )
    _SENSITIVE = frozenset({"password", "notes", "fields"})

    __slots__ = ("_meta", "_payload", "_key", "_aad", "_decrypted", "_haystack", "_title_lower")

    def __init__(self, meta: dict, encrypted_payload: tuple[bytes, bytes], key: bytes, aad: bytes | None = None):
        object.__setattr__(self, "_meta", dict(meta))
        object.__setattr__(self, "_payload", encrypted_payload)
        object.__setattr__(self, "_key", key)
        object.__setattr__(self, "_aad", aad)
        object.__setattr__(self, "_decrypted", None)
        t = meta.get("title", "")
        object.__setattr__(self, "_title_lower", t.lower() if t else "")
        object.__setattr__(self, "_haystack", "")

    def _ensure(self) -> None:
        if self._decrypted is None:
            from .crypto import AESGCM
            if isinstance(self._payload, dict):
                payload = copy.deepcopy(self._payload)
            else:
                nonce, ciphertext = self._payload
                raw = AESGCM(self._key).decrypt(nonce, ciphertext, self._aad)
                payload = json.loads(raw.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("entry payload must be a JSON object")
            object.__setattr__(self, "_decrypted", payload)

    def __getattr__(self, name: str):
        if name in self._META:
            v = self._meta.get(name)
            if v is not None:
                return v
            if name == "tags":
                return []
            if name == "target_app":
                return ""
            if name == "deleted_at":
                return None
            if name in ("leak_check_revision", "leak_pwned_count", "leak_checked_at"):
                return None
            if name == "leak_common_weak":
                return False
            return ""
        if name in self._SENSITIVE:
            self._ensure()
            v = self._decrypted.get(name)
            if name == "fields":
                return v if isinstance(v, dict) else {}
            return v if v else ""
        raise AttributeError(f"LazyEntry has no attribute {name!r}")

    def __setattr__(self, name: str, value):
        if name in self._META:
            self._meta[name] = value
            if name == "title":
                object.__setattr__(self, "_title_lower", (value or "").lower())
        elif name in self._SENSITIVE:
            self._ensure()
            self._decrypted[name] = value
        else:
            object.__setattr__(self, name, value)

    def touch(self) -> None:
        self._meta["updated_at"] = monotonic_timestamp(self._meta.get("updated_at", 0.0))
        object.__setattr__(self, "_haystack", "")

    def invalidate_haystack(self) -> None:
        object.__setattr__(self, "_haystack", "")

    def release_sensitive(self) -> None:
        """Drop decrypted payload/search caches while keeping list metadata available."""
        decrypted = self._decrypted
        if isinstance(decrypted, dict):
            decrypted.clear()
        object.__setattr__(self, "_decrypted", None)
        object.__setattr__(self, "_haystack", "")

    def _build_haystack(self) -> str:
        if self._haystack:
            return self._haystack
        parts = [
            self.title or "",
            self.username or "",
            self.url or "",
            " ".join(self.tags or []),
            self.target_app,
        ]
        if self._decrypted is not None:
            parts.append(self.notes or "")
            extra = " ".join(str(v) for k, v in self.fields.items() if k not in _HAYSTACK_SKIP_KEYS and v)
            if extra:
                parts.append(extra)
        h = " ".join(parts).lower()
        object.__setattr__(self, "_haystack", h)
        return h

    def matches(self, query: str) -> bool:
        if not query:
            return True
        return query.lower() in self._build_haystack()

    def get_field(self, key: str, default: str = "") -> str:
        return str(self.fields.get(key, default) or default)

    @property
    def display_secret(self) -> str:
        return self._meta.get("display_secret", "")

    def content_equals(self, other) -> bool:
        return self.title == other.title and self.username == other.username and self.same_content(other)

    def same_content(self, other) -> bool:
        return (
            self.secret_type == other.secret_type
            and self.password == other.password
            and self.url == other.url
            and self.notes == other.notes
            and set(self.tags or []) == set(other.tags or [])
            and self.target_app == other.target_app
            and self.fields == other.fields
        )

    def same_except_password(self, other) -> bool:
        return self.secret_type == other.secret_type and self.url == other.url and self.notes == other.notes and self.fields == other.fields

    def dedup_key(self) -> tuple[str, str, str]:
        return (
            self.secret_type,
            (self.title or "").strip().lower(),
            (self.username or "").strip().lower(),
        )

    def to_dict(self) -> dict:
        self._ensure()
        return {**self._meta, **self._decrypted}

    def get_expiry_date(self) -> _dt.date | None:
        return Entry.get_expiry_date(self)

    def expiry_status(self, days_threshold: int = 30) -> str | None:
        return Entry.expiry_status(self, days_threshold)

    def expiry_date_str(self) -> str | None:
        return Entry.expiry_date_str(self)
