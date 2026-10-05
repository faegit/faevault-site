"""导入来源：浏览器（Chromium 内核）、CSV、系统 Wi-Fi 配置。

浏览器导入仅在 Windows 上读取**当前用户自己**的凭据库：
Chromium 把密码用 AES-256-GCM 加密存放在 SQLite，密钥写在 ``Local State``
里并用 Windows DPAPI 保护。先用 DPAPI 解出主密钥，再逐条解密。

Wi-Fi 导入通过 ``netsh wlan show profile ... key=clear`` 读取当前用户已保存
的无线网络明文密码，仅支持 Windows。
"""

from __future__ import annotations

import base64
import csv
import io
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import modules, otp
from .log import get, redact
from .models import Entry, SecretType

_log = get("importers")

# ---- 已知的 Chromium 浏览器与其用户数据目录 ----
_LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", ""))
_APPDATA = Path(os.environ.get("APPDATA", ""))

CHROMIUM_BROWSERS: dict[str, Path] = {
    "Chrome": _LOCALAPPDATA / "Google/Chrome/User Data",
    "Edge": _LOCALAPPDATA / "Microsoft/Edge/User Data",
    "Brave": _LOCALAPPDATA / "BraveSoftware/Brave-Browser/User Data",
    "Chromium": _LOCALAPPDATA / "Chromium/User Data",
    "Vivaldi": _LOCALAPPDATA / "Vivaldi/User Data",
    "Yandex": _LOCALAPPDATA / "Yandex/YandexBrowser/User Data",
    # Opera 系列把配置放在 Roaming 下，且凭据库直接位于配置根目录（无 Default 子目录）
    "Opera": _APPDATA / "Opera Software/Opera Stable",
    "Opera GX": _APPDATA / "Opera Software/Opera GX Stable",
}


@dataclass
class ImportResult:
    entries: list[Entry]
    source: str
    error: str = ""
    warning: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


def available_browsers() -> list[str]:
    return [name for name, base in CHROMIUM_BROWSERS.items() if (base / "Local State").exists()]


def _master_key(user_data: Path) -> bytes:
    import win32crypt  # 延迟导入，非 Windows 环境不报错

    local_state = json.loads((user_data / "Local State").read_text(encoding="utf-8"))
    enc_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    enc_key = enc_key[5:]  # 去掉 "DPAPI" 前缀
    return win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]


class _AppBound(Exception):
    """Chrome 127+ 的 app-bound 加密（v20），需要 SYSTEM 权限才能解。"""


def _decrypt_value(blob: bytes, key: bytes) -> str:
    if not blob:
        return ""
    prefix = blob[:3]
    if prefix in (b"v20", b"v24"):
        raise _AppBound()
    try:
        if prefix in (b"v10", b"v11"):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce, payload = blob[3:15], blob[15:]
            return AESGCM(key).decrypt(nonce, payload, None).decode("utf-8", "replace")
        # 旧版直接 DPAPI 加密
        import win32crypt

        return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1].decode("utf-8", "replace")
    except Exception:
        return ""


def _profiles(user_data: Path) -> list[Path]:
    # 标准 Chromium：User Data 下的 Default / Profile N；Opera 系列：凭据库直接在配置根目录
    candidates = [user_data / "Default", user_data]
    candidates += sorted(user_data.glob("Profile *"))
    return [p for p in candidates if (p / "Login Data").exists()]


def import_browser(name: str) -> ImportResult:
    _log.info("浏览器导入：%s", name)
    base = CHROMIUM_BROWSERS.get(name)
    if not base or not (base / "Local State").exists():
        _log.warning("未找到 %s 的用户数据目录", name)
        return ImportResult([], name, f"未找到 {name} 的数据")
    try:
        key = _master_key(base)
    except Exception as exc:
        _log.error("无法获取 %s 主密钥：%s", name, exc)
        return ImportResult([], name, f"无法获取 {name} 主密钥：{exc}")

    entries: list[Entry] = []
    app_bound = 0
    for profile in _profiles(base):
        login_db = profile / "Login Data"
        # 浏览器运行时会锁定数据库，复制一份再读
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "Login Data"
            try:
                shutil.copy2(login_db, copy)
                conn = sqlite3.connect(copy)
                rows = conn.execute("SELECT origin_url, username_value, password_value FROM logins").fetchall()
                conn.close()
            except Exception:
                continue
            for url, username, pw_blob in rows:
                try:
                    password = _decrypt_value(pw_blob, key)
                except _AppBound:
                    app_bound += 1
                    continue
                if not username and not password:
                    continue
                entries.append(
                    Entry(
                        title=_title_from_url(url),
                        username=username,
                        password=password,
                        url=url,
                        tags=[name],
                    )
                )

    warning = ""
    if app_bound:
        warning = (
            f"{name} 有 {app_bound} 条采用新版 app-bound 加密（Chrome 127+），"
            "第三方程序无法直接解密。请改用浏览器内置导出："
            "设置 → 密码 → 导出密码，再用「从 CSV 导入」。"
        )
        _log.warning("%s：%d 条 app-bound 加密无法解密", name, app_bound)
    _log.info("浏览器导入完成：%s，解析 %d 条", name, len(entries))
    if not entries and app_bound:
        return ImportResult([], name, warning)
    return ImportResult(entries, name, warning=warning)


def _title_from_url(url: str) -> str:
    if not url:
        return "未命名"
    host = url.split("//", 1)[-1].split("/", 1)[0]
    host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host or url


# ---------- CSV ----------
# 兼容主流浏览器导出列：name,url,username,password,note
_CSV_ALIASES = {
    "title": ["name", "title", "account", "login_name"],
    "url": ["url", "website", "login_uri", "origin_url", "uri"],
    "username": ["username", "user", "login", "email", "login_username"],
    "password": ["password", "pass", "login_password"],
    "notes": ["note", "notes", "comment", "extra"],
    "tags": ["tags", "folder", "group", "grouping"],
    "otp_uri": ["otpauth", "otp_auth", "otpauth_uri", "otp uri"],
    "otp_secret": ["login_totp", "totp", "totp_secret", "otp secret"],
    "secret_type": ["type", "secret_type", "entry_type"],
}
_OTP_CSV_KEYS = ("secret", "algorithm", "digits", "period", "issuer", "label", "counter")
_CSV_LEAK_KEYS = (
    "leak_check_revision",
    "leak_pwned_count",
    "leak_common_weak",
    "leak_checked_at",
)
_CSV_TYPE_VALUES = {
    "": SecretType.LOGIN,
    SecretType.LOGIN: SecretType.LOGIN,
    SecretType.CARD_DOCUMENT: SecretType.CARD_DOCUMENT,
    SecretType.WIFI: SecretType.WIFI,
    SecretType.API_KEY: SecretType.API_KEY,
    SecretType.OTP: SecretType.OTP,
    SecretType.SECURE_NOTE: SecretType.SECURE_NOTE,
    SecretType.SERVER: SecretType.SERVER,
    SecretType.CUSTOM: SecretType.CUSTOM,
    "安全笔记": SecretType.SECURE_NOTE,
    "服务器": SecretType.SERVER,
    "自定义": SecretType.CUSTOM,
    "login_password": SecretType.LOGIN,
    "password": SecretType.LOGIN,
    "wifi_password": SecretType.WIFI,
    "wi-fi": SecretType.WIFI,
    "api": SecretType.API_KEY,
    "key": SecretType.API_KEY,
    "secret": SecretType.API_KEY,
    "apikey": SecretType.API_KEY,
    "api-key": SecretType.API_KEY,
    "totp": SecretType.OTP,
    "hotp": SecretType.OTP,
}


def _row_lower(row: dict) -> dict[str, str]:
    return {str(k).lower().strip(): str(v).strip() for k, v in row.items() if k and v not in (None, "")}


def _pick_lower(lower: dict[str, str], keys: list[str]) -> str:
    for k in keys:
        if k in lower and lower[k]:
            return lower[k]
    return ""


def _csv_secret_type(value: str) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "_")
    return _CSV_TYPE_VALUES.get(normalized, SecretType.LOGIN)


def _fields_for_secret_type(secret_type: str, fields: dict, *, title: str, username: str, password: str) -> dict:
    out = dict(fields)
    if secret_type == SecretType.WIFI:
        if password and not out.get("wifi_password"):
            out["wifi_password"] = password
        if title and not out.get("ssid"):
            out["ssid"] = title
    elif secret_type == SecretType.API_KEY:
        if password and not out.get("api_key"):
            out["api_key"] = password
        if username and not out.get("service"):
            out["service"] = username
    return out


def import_password_manager(path: str | Path) -> ImportResult:
    """自动识别受支持的密码管理器 CSV 或 Bitwarden 未加密 JSON。"""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as exc:
        return ImportResult([], path.name, f"无法读取文件：{exc}")
    if text.lstrip().startswith("{"):
        return _import_bitwarden_json(text, path.name)
    return _import_csv_text(text, path.name)


def import_csv(path: str | Path) -> ImportResult:
    """兼容旧调用；CSV 仍由统一密码管理器导入器解析。"""
    path = Path(path)
    _log.info("CSV 导入：%s", path)
    try:
        text = path.read_text(encoding="utf-8-sig")
    except Exception as exc:
        _log.error("无法读取 CSV 文件：%s", exc)
        return ImportResult([], path.name, f"无法读取文件：{exc}")

    return _import_csv_text(text, path.name)


def _detect_csv_source(fieldnames: list[str]) -> str:
    header = {str(value).strip().lower() for value in fieldnames}
    if {"folder", "favorite", "login_uri", "login_username", "login_password"} <= header:
        return "Bitwarden CSV"
    if {"url", "username", "password", "extra", "name", "grouping", "fav"} <= header:
        return "LastPass CSV"
    if "otpauth" in header and "archived" in header:
        return "1Password CSV"
    if "group" in header and "title" in header:
        return "KeePass CSV"
    if "httprealm" in header or "formactionorigin" in header:
        return "Firefox CSV"
    if {"name", "url", "username", "password"} <= header:
        return "Chromium CSV"
    return "Vault CSV"


def _import_csv_text(text: str, source_name: str) -> ImportResult:
    csv.field_size_limit(2**31 - 1)
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        return ImportResult([], source_name, "CSV 没有表头")

    source = _detect_csv_source(reader.fieldnames)

    entries: list[Entry] = []
    for row in reader:
        lower = _row_lower(row)
        title = _pick_lower(lower, _CSV_ALIASES["title"])
        url = _pick_lower(lower, _CSV_ALIASES["url"])
        username = _pick_lower(lower, _CSV_ALIASES["username"])
        password = _pick_lower(lower, _CSV_ALIASES["password"])
        notes = _pick_lower(lower, _CSV_ALIASES["notes"])
        fields = _fields_from_csv(lower)
        raw_custom_fields = lower.get("fields", "")
        if raw_custom_fields and not fields:
            fields["imported_custom_fields"] = raw_custom_fields
            if raw_custom_fields not in notes:
                notes = "\n\n".join(filter(None, (notes, f"导入的其他字段：\n{raw_custom_fields}")))
        otp_uri = _pick_lower(lower, _CSV_ALIASES["otp_uri"])
        otp_secret = _pick_lower(lower, _CSV_ALIASES["otp_secret"])
        if otp_uri:
            fields["otp_uri"] = otp_uri
        if otp_secret:
            fields["otp_secret"] = otp_secret
        secret_type = _csv_secret_type(_pick_lower(lower, _CSV_ALIASES["secret_type"]))
        otp_fields = _otp_fields_from_csv(lower, fields, url=url, notes=notes)
        if secret_type == SecretType.OTP or (url.lower().startswith("otpauth://") and otp_fields.get("secret")):
            secret_type = SecretType.OTP
            fields = otp.normalize_fields({**fields, **otp_fields})
            title = title or fields.get("issuer") or fields.get("label") or "动态码"
        else:
            fields = _fields_for_secret_type(
                secret_type,
                fields,
                title=title,
                username=username,
                password=password,
            )

        tag_text = _pick_lower(lower, _CSV_ALIASES["tags"])
        tags = [part.strip() for part in re.split(r"[;,|，]", tag_text) if part.strip()]

        known_columns = {alias for aliases in _CSV_ALIASES.values() for alias in aliases}
        known_columns.update(_OTP_CSV_KEYS)
        known_columns.update(_CSV_LEAK_KEYS)
        known_columns.update({"fields", "otp_type", "otp.type"})
        for key, value in lower.items():
            if key not in known_columns and value and key not in fields:
                fields[key] = value

        if not (title or url or username or fields.get("secret")):
            continue
        entry = Entry(
            title=title or _title_from_url(url),
            username=username,
            password=password if secret_type == SecretType.LOGIN else "",
            url=url,
            notes=notes,
            secret_type=secret_type,
            fields=fields,
            # 所有类型均保留标签，包括 Passkey；标签不影响密钥材料。
            tags=tags,
        )
        _apply_csv_leak_cache(entry, lower)
        entries.append(entry)
    if not entries:
        _log.warning("CSV 未解析到有效条目：%s", source_name)
        return ImportResult([], source, "未解析到有效条目（请确认是密码管理器导出文件）")
    _log.info("CSV 导入成功：%d 条", len(entries))
    return ImportResult(entries, source)


def _import_bitwarden_json(text: str, source_name: str) -> ImportResult:
    try:
        root = json.loads(text)
    except Exception as exc:
        return ImportResult([], source_name, f"JSON 文件格式无效：{exc}")
    if not isinstance(root, dict):
        return ImportResult([], source_name, "JSON 顶层格式无效")
    if root.get("encrypted") is True:
        return ImportResult([], "Bitwarden JSON", "暂不支持 Bitwarden 加密 JSON，请导出未加密 JSON")
    folders = {
        str(folder.get("id")): str(folder.get("name"))
        for folder in root.get("folders", [])
        if isinstance(folder, dict) and folder.get("id") and folder.get("name")
    }
    entries: list[Entry] = []
    skipped = 0
    type_map = {1: SecretType.LOGIN, 2: SecretType.SECURE_NOTE, 3: SecretType.CARD_DOCUMENT, 4: SecretType.CARD_DOCUMENT}
    card_keys = {"number": "card_number", "cardholderName": "cardholder", "expMonth": "expiry_month", "expYear": "expiry_year", "code": "cvv"}
    for item in root.get("items", []):
        if not isinstance(item, dict):
            skipped += 1
            continue
        login = item.get("login") if isinstance(item.get("login"), dict) else {}
        card = item.get("card") if isinstance(item.get("card"), dict) else {}
        identity = item.get("identity") if isinstance(item.get("identity"), dict) else {}
        secret_type = type_map.get(item.get("type"), SecretType.LOGIN)
        fields: dict[str, str] = {}
        if login.get("totp"):
            fields["otp_secret"] = str(login["totp"])
        for key, value in card.items():
            if value not in (None, ""):
                fields[card_keys.get(key, key)] = str(value)
        for key, value in identity.items():
            if value not in (None, ""):
                fields[key] = str(value)
        custom_lines = []
        for index, custom in enumerate(item.get("fields", []), 1):
            if not isinstance(custom, dict) or custom.get("value") in (None, ""):
                continue
            name = str(custom.get("name") or f"custom_{index}")
            key = re.sub(r"[^a-z0-9_\u4e00-\u9fff]+", "_", name.lower()).strip("_") or f"custom_{index}"
            base, suffix = key, 2
            while key in fields:
                key, suffix = f"{base}_{suffix}", suffix + 1
            fields[key] = str(custom["value"])
            custom_lines.append(f"{name}: {custom['value']}")
        uris = login.get("uris") if isinstance(login.get("uris"), list) else []
        url = str(uris[0].get("uri", "")) if uris and isinstance(uris[0], dict) else ""
        notes = "\n\n".join(filter(None, (str(item.get("notes") or ""), "\n".join(custom_lines))))
        tags = [folders[str(item.get("folderId"))]] if str(item.get("folderId")) in folders else []
        entries.append(Entry(
            title=str(item.get("name") or "") or _title_from_url(url),
            username=str(login.get("username") or ""),
            password=str(login.get("password") or "") if secret_type == SecretType.LOGIN else "",
            url=url,
            notes=notes,
            # 所有类型均保留标签，包括 Passkey；标签不影响密钥材料。
            tags=tags,
            secret_type=secret_type,
            fields=fields,
        ))
    if not entries:
        return ImportResult([], "Bitwarden JSON", "Bitwarden JSON 中未找到条目")
    warning = f"已跳过 {skipped} 条无法识别的数据" if skipped else ""
    return ImportResult(entries, "Bitwarden JSON", warning=warning)


def _fields_from_csv(lower: dict[str, str]) -> dict:
    raw = lower.get("fields", "")
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _csv_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _csv_float(value: str) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _csv_bool(value: str) -> bool:
    return str(value or "").strip().lower() in {"true", "1", "yes", "y", "是"}


def _apply_csv_leak_cache(entry: Entry, lower: dict[str, str]) -> None:
    pwned_count = _csv_int(lower.get("leak_pwned_count", ""))
    common_weak = _csv_bool(lower.get("leak_common_weak", ""))
    if pwned_count is None and not common_weak:
        return
    entry.leak_pwned_count = pwned_count
    entry.leak_common_weak = common_weak
    entry.leak_checked_at = _csv_float(lower.get("leak_checked_at", "")) or entry.updated_at
    entry.leak_check_revision = entry.updated_at


def _otp_fields_from_csv(lower: dict[str, str], fields: dict, *, url: str, notes: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in _OTP_CSV_KEYS:
        value = lower.get(key)
        if value not in (None, ""):
            out[key] = str(value).strip()
    typ = lower.get("otp_type") or lower.get("otp.type") or fields.get("type")
    if not typ and lower.get("type") in ("totp", "hotp"):
        typ = lower.get("type")
    if typ:
        out["type"] = str(typ).strip()
    for candidate in (url, notes, lower.get("otpauth", "")):
        parsed = otp.parse_otpauth_uri(candidate)
        if parsed:
            out = {**parsed, **out}
            break
    if fields.get("secret"):
        out = {**{k: str(v) for k, v in fields.items() if k in otp.OTP_FIELD_KEYS}, **out}
    return out


# ---------- Wi-Fi（系统已保存的无线网络） ----------
# netsh 的输出受系统语言影响，同时兼容中英文字段名
_WIFI_PROFILE_RE = re.compile(r"(?:All User Profile|Group Policy Profile|用户配置文件|所有用户配置文件|组策略配置文件)\s*[:：]\s*(.+)")
_WIFI_SSID_RE = re.compile(r"(?:SSID name|SSID 名称)\s*[:：]\s*\"(.*)\"")
_WIFI_AUTH_RE = re.compile(r"(?:Authentication|身份验证)\s*[:：]\s*(.+)")
_WIFI_KEY_RE = re.compile(r"(?:Key Content|关键内容)\s*[:：]\s*(.+)")


def _netsh(args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["netsh", *args],
            capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return ""
    raw = result.stdout or b""
    # netsh 输出编码取决于控制台代码页：新版终端默认 UTF-8，旧版为本地 OEM 代码页（如 GBK）
    for enc in ("utf-8", "oem"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "ignore")


def available_wifi_profiles() -> list[str]:
    """返回当前 Windows 用户已保存的 Wi-Fi 配置名称列表。"""
    output = _netsh(["wlan", "show", "profiles"])
    names: list[str] = []
    for line in output.splitlines():
        m = _WIFI_PROFILE_RE.search(line)
        if m:
            name = m.group(1).strip()
            if name and name not in names:
                names.append(name)
    return names


def import_wifi(names: list[str]) -> ImportResult:
    """从系统已保存的 Wi-Fi 配置中读取 SSID 与明文密码，生成 Wi-Fi 类型条目。"""
    _log.info("Wi-Fi 导入：%d 个配置", len(names))
    entries: list[Entry] = []
    failed: list[str] = []
    for name in names:
        output = _netsh(["wlan", "show", "profile", f"name={name}", "key=clear"])
        ssid_match = _WIFI_SSID_RE.search(output)
        ssid = ssid_match.group(1).strip() if ssid_match else name
        auth_match = _WIFI_AUTH_RE.search(output)
        auth = auth_match.group(1).strip() if auth_match else ""
        key_match = _WIFI_KEY_RE.search(output)
        key = key_match.group(1).strip() if key_match else ""
        if not key:
            failed.append(name)
            continue
        entries.append(
            Entry(
                title=name,
                secret_type=SecretType.WIFI,
                fields={"ssid": ssid or name, "wifi_password": key, "security_type": modules.normalize_wifi_security(auth)},
            )
        )

    warning = ""
    if failed:
        warning = f"以下 {len(failed)} 个网络未读取到密码（可能是 802.1X 企业认证或未保存密码），已跳过：\n" + "、".join(failed)
        _log.warning("Wi-Fi 导入：%d 个配置无密码：%s", len(failed), [redact(n) for n in failed])
    _log.info("Wi-Fi 导入完成：%d 条", len(entries))
    if not entries:
        return ImportResult([], "Wi-Fi", warning or "未读取到任何已保存的 Wi-Fi 密码")
    return ImportResult(entries, "Wi-Fi", warning=warning)


_PLAINTEXT_FIELD_SECRET_KEYS = frozenset({"private_key", "public_key", "credential_id"})
_PLAINTEXT_EXPORT_MAX_DEPTH = 64
_PLAINTEXT_EXPORT_MAX_NODES = 10_000
_PLAINTEXT_EXPORT_MAX_CONTAINER_ITEMS = 1_000
_PLAINTEXT_EXPORT_ERROR = "无法安全导出 CSV：字段数据无效"


class PlaintextExportError(ValueError):
    """Raised when plaintext export input cannot be handled safely."""


class _PlaintextExportRejected(Exception):
    pass


@dataclass
class _PlaintextTraversal:
    nodes: int = 0

    def visit(self, depth: int) -> None:
        if depth > _PLAINTEXT_EXPORT_MAX_DEPTH:
            raise _PlaintextExportRejected()
        self.nodes += 1
        if self.nodes > _PLAINTEXT_EXPORT_MAX_NODES:
            raise _PlaintextExportRejected()


def _check_plaintext_container(value) -> None:
    if len(value) > _PLAINTEXT_EXPORT_MAX_CONTAINER_ITEMS:
        raise _PlaintextExportRejected()


def _plaintext_modules_value(value, *, depth: int, traversal: _PlaintextTraversal, active: set[int]) -> list:
    traversal.visit(depth)
    if type(value) not in (list, tuple):
        raise _PlaintextExportRejected()
    _check_plaintext_container(value)
    identity = id(value)
    if identity in active:
        raise _PlaintextExportRejected()
    active.add(identity)
    try:
        result = []
        for module in value:
            if type(module) is not dict:
                raise _PlaintextExportRejected()
            module_type = module.get("type")
            if type(module_type) is not str or not module_type:
                raise _PlaintextExportRejected()
            sanitized = _plaintext_field_value(
                module,
                depth=depth + 1,
                traversal=traversal,
                active=active,
            )
            if module_type != modules.PASSKEY:
                result.append(sanitized)
        return result
    finally:
        active.remove(identity)


def _plaintext_field_value(value, *, depth: int, traversal: _PlaintextTraversal, active: set[int]):
    traversal.visit(depth)
    value_type = type(value)
    if value is None or value_type in (str, bool, int):
        return value
    if value_type is float:
        if not math.isfinite(value):
            raise _PlaintextExportRejected()
        return value
    if value_type is dict:
        _check_plaintext_container(value)
        identity = id(value)
        if identity in active:
            raise _PlaintextExportRejected()
        active.add(identity)
        try:
            result = {}
            for key, nested_value in value.items():
                if type(key) is not str:
                    raise _PlaintextExportRejected()
                if key in _PLAINTEXT_FIELD_SECRET_KEYS:
                    continue
                if key == modules.MODULES_KEY:
                    safe_modules = _plaintext_modules_value(
                        nested_value,
                        depth=depth + 1,
                        traversal=traversal,
                        active=active,
                    )
                    if safe_modules:
                        result[key] = safe_modules
                    continue
                result[key] = _plaintext_field_value(
                    nested_value,
                    depth=depth + 1,
                    traversal=traversal,
                    active=active,
                )
            return result
        finally:
            active.remove(identity)
    if value_type in (list, tuple):
        _check_plaintext_container(value)
        identity = id(value)
        if identity in active:
            raise _PlaintextExportRejected()
        active.add(identity)
        try:
            return [
                _plaintext_field_value(
                    item,
                    depth=depth + 1,
                    traversal=traversal,
                    active=active,
                )
                for item in value
            ]
        finally:
            active.remove(identity)
    raise _PlaintextExportRejected()


def fields_for_plaintext_export(fields: dict) -> dict:
    """Return a sanitized copy of fields for defense-in-depth plaintext export."""
    try:
        if type(fields) is not dict:
            raise _PlaintextExportRejected()
        return _plaintext_field_value(
            fields,
            depth=0,
            traversal=_PlaintextTraversal(),
            active=set(),
        )
    except PlaintextExportError:
        raise
    except Exception:
        raise PlaintextExportError(_PLAINTEXT_EXPORT_ERROR) from None


# 与 Android CsvExporter 对齐的导出列。列名与 Android 一致；其中 card_expiry 对应字段 key "expiry"。
_ANDROID_CSV_HEADERS = [
    "type", "title", "username", "password", "url", "notes", "tags",
    "card_number", "card_expiry", "cvv", "cardholder", "bank",
    "id_number", "full_name",
    "ssid", "wifi_password", "security_type",
    "service", "api_key", "api_secret", "base_url",
    *_CSV_LEAK_KEYS,
]

# 已知扩展字段列（column -> fields key）
_ANDROID_CSV_FIELD_COLUMNS = (
    ("card_number", "card_number"),
    ("card_expiry", "expiry"),
    ("cvv", "cvv"),
    ("cardholder", "cardholder"),
    ("bank", "bank"),
    ("id_number", "id_number"),
    ("full_name", "full_name"),
    ("ssid", "ssid"),
    ("wifi_password", "wifi_password"),
    ("security_type", "security_type"),
    ("service", "service"),
    ("api_key", "api_key"),
    ("api_secret", "api_secret"),
    ("base_url", "base_url"),
)


def _csv_field(fields: dict, key: str) -> str:
    """Android getStringField 语义：仅导出标量扩展字段，非标量输出空串。"""
    value = fields.get(key)
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return ""


def _csv_export_payload(entries: list[Entry]) -> bytes:
    try:
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(_ANDROID_CSV_HEADERS)
        for entry in entries:
            # 防御性校验整棵 fields（拒绝过深/循环/畸形结构，剔除 Passkey 私密键），
            # 但导出只读取上面固定的已知列，fields 整体不再序列化进 CSV。
            export_fields = fields_for_plaintext_export(entry.fields)
            writer.writerow(
                [
                    entry.secret_type,
                    entry.title,
                    entry.username,
                    entry.password,
                    entry.url,
                    entry.notes,
                    ";".join(entry.tags),
                    *[_csv_field(export_fields, key) for _, key in _ANDROID_CSV_FIELD_COLUMNS],
                    entry.leak_check_revision or "",
                    "" if entry.leak_pwned_count is None else entry.leak_pwned_count,
                    str(entry.leak_common_weak).lower(),
                    entry.leak_checked_at or "",
                ]
            )
        return stream.getvalue().encode("utf-8-sig")
    except PlaintextExportError:
        raise
    except Exception:
        raise PlaintextExportError(_PLAINTEXT_EXPORT_ERROR) from None
