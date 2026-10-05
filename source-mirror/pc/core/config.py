"""数据库目录内唯一的本地配置通道。

配置整体由随机 AES-256-GCM 密钥加密，密钥再由当前 Windows 用户的 DPAPI
保护。文件包含版本、nonce、AAD 约束下的密文及 DPAPI 包裹密钥，但不包含可独立
解密配置的明文密钥。旧明文 ``config.json`` 会在首次成功加载时原地迁移。
"""

from __future__ import annotations

import hmac
import builtins
import json
import os
import re
import tempfile
import threading
import time
import base64
from contextlib import contextmanager
from functools import lru_cache
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .log import get
from .storage import default_vault_path, vault_dir

_log = get("config")

_INVALID_NAME_CHARS = re.compile(r'[\\/:*?"<>|]+')
_CONFIG_FORMAT = "FAEVaultConfig"
_CONFIG_VERSION = 1
_CONFIG_AAD = b"FAEVault/config/v1"
_DPAPI_ENTROPY = b"FAEVault/config-key/v1"


class ConfigIntegrityError(RuntimeError):
    """配置存在但认证失败或格式损坏；调用方必须使用安全默认值。"""


def _protect_key(secret: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("加密配置需要 Windows 用户密钥保护")
    import win32crypt

    return bytes(win32crypt.CryptProtectData(secret, None, _DPAPI_ENTROPY, None, None, 0))


def _unprotect_key(protected: bytes) -> bytes:
    if os.name != "nt":
        raise RuntimeError("加密配置需要 Windows 用户密钥保护")
    import win32crypt

    return bytes(win32crypt.CryptUnprotectData(protected, _DPAPI_ENTROPY, None, None, 0)[1])

# 账户回收站保留期（ACCOUNT_LIFECYCLE.md §8），与安卓端一致
ACCOUNT_RETENTION_DAYS = 30

# 与安卓端设置保持一致的默认值和范围。
DEFAULT_THEME_MODE = "light"
DEFAULT_LANGUAGE_MODE = "auto"
DEFAULT_LOCK_ENABLED = False
DEFAULT_LOCK_SECONDS = 60
MIN_LOCK_SECONDS = 30
MAX_LOCK_SECONDS = 3600
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 60
MIN_CLIPBOARD_CLEAR_SECONDS = 0
MAX_CLIPBOARD_CLEAR_SECONDS = 600
DEFAULT_REQUIRE_MASTER_FOR_SENSITIVE = False
DEFAULT_LEAK_CHECK_ENABLED = True
DEFAULT_LEAK_RECHECK_DAYS = 5
DEFAULT_RECYCLE_BIN_RETENTION_DAYS = 30
DEFAULT_BACKGROUND_HIDE = False
DEFAULT_LIST_PANE_RATIO = 40
#: 截屏保护默认开启（即「允许截屏」默认关闭）：保险库内容不应默认出现在截图/录屏/投屏里。
DEFAULT_SCREEN_CAPTURE_ALLOWED = False


def _config_path() -> Path:
    return default_vault_path().with_name("config.json")


_config_cache: dict | None = None
_config_dirty: bool = False
_config_integrity_failed: bool = False

# 写配置时串行化（browser_host 等常驻进程与主程序并发写同一个 config.json）。
_config_write_lock = threading.RLock()

# ── 账户（保险库）隔离层 ───────────────────────────────────────────────
# 除账户注册表 / 云同步 / 压缩状态等全局键外，所有设置按当前账户
# （current_user）落入 account_settings[账户名] 子字典；切换账户后互不覆盖，
# 与安卓端「全部设置项按账户隔离」保持一致。云同步偏好已由 cloud_sync_prefs
# 以 vault_id 后缀隔离，仍走全局键。
_GLOBAL_CONFIG_KEYS = frozenset(
    {
        "current_user",
        "users",
        "trashed_accounts",
        "account_settings",
        "pmve_compact_state",
        "list_pane_ratio",
        "clipboard_cleanup",
    }
)


def _is_global_key(key: str) -> bool:
    if key in _GLOBAL_CONFIG_KEYS:
        return True
    if key.startswith("cloud_auto"):
        return True
    return False


def _write_key(data: dict, key: str, value) -> None:
    """按当前账户写入设置；全局键或尚无活动账户时写入顶层（兼容旧明文迁移）。

    账户名取自即将写入的同一份 data（而非全局缓存），保证与后续 get 读取到的
    命名空间一致，避免 set 与 get 看到不同的“当前账户”。
    """
    name = data.get("current_user")
    if _is_global_key(key) or not name:
        data[key] = value
        return
    table = data.get("account_settings")
    if not isinstance(table, dict):
        table = {}
    acct = table.get(name)
    if not isinstance(acct, dict):
        acct = {}
    acct[key] = value
    table[name] = acct
    data["account_settings"] = table


def _read_key(data: dict, key: str, default=None):
    name = data.get("current_user")
    if name and not _is_global_key(key):
        table = data.get("account_settings")
        if isinstance(table, dict):
            acct = table.get(name)
            if isinstance(acct, dict) and key in acct:
                return acct[key]
    return data.get(key, default)


def _configuration_revision(path: Path) -> bytes | None:
    """Return a content revision suitable for compare-and-swap writes."""
    try:
        return sha256(path.read_bytes()).digest()
    except FileNotFoundError:
        return None


@contextmanager
def _interprocess_config_lock():
    """Serialize config updates made by the UI and long-running helper processes."""
    path = _config_path().with_name("config.json.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        if os.name == "nt":
            import msvcrt
            while True:
                try:
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.02)
        else:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


def _mark_integrity_failed() -> None:
    global _config_cache, _config_integrity_failed
    _config_cache = {}
    _config_integrity_failed = True


def _require_writable() -> None:
    if _config_integrity_failed:
        raise ConfigIntegrityError("配置文件验证失败，必须先显式恢复或重置")


def _decode_envelope(data: dict) -> dict:
    if data.get("format") != _CONFIG_FORMAT or data.get("version") != _CONFIG_VERSION:
        raise ConfigIntegrityError("配置文件格式不受支持")
    try:
        wrapped = base64.b64decode(data["protected_key"], validate=True)
        nonce = base64.b64decode(data["nonce"], validate=True)
        ciphertext = base64.b64decode(data["ciphertext"], validate=True)
        key = bytearray(_unprotect_key(wrapped))
        if len(key) != 32 or len(nonce) != 12:
            raise ValueError("invalid key or nonce length")
        try:
            plain = AESGCM(bytes(key)).decrypt(nonce, ciphertext, _CONFIG_AAD)
        finally:
            key[:] = b"\0" * len(key)
        decoded = json.loads(plain.decode("utf-8"))
        if not isinstance(decoded, dict):
            raise ValueError("payload is not an object")
        return decoded
    except ConfigIntegrityError:
        raise
    except Exception as error:
        raise ConfigIntegrityError("配置文件完整性验证失败") from error


def _encode_envelope(data: dict, previous: dict | None = None) -> str:
    key = bytearray(os.urandom(32))
    wrapped: bytes
    if isinstance(previous, dict) and previous.get("format") == _CONFIG_FORMAT:
        try:
            wrapped = base64.b64decode(previous["protected_key"], validate=True)
            restored = _unprotect_key(wrapped)
            if len(restored) != 32:
                raise ValueError("invalid key")
            key[:] = restored
        except Exception as error:
            raise ConfigIntegrityError("现有配置密钥无法验证") from error
    else:
        wrapped = _protect_key(bytes(key))
    try:
        nonce = os.urandom(12)
        plain = json.dumps(data, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = AESGCM(bytes(key)).encrypt(nonce, plain, _CONFIG_AAD)
    finally:
        key[:] = b"\0" * len(key)
    envelope = {
        "format": _CONFIG_FORMAT,
        "version": _CONFIG_VERSION,
        "protected_key": base64.b64encode(wrapped).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _load_uncached() -> dict:
    # PC 端只加载数据库位置的配置文件；缺失/损坏时按无配置处理，不恢复备份。
    path = _config_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("format") == _CONFIG_FORMAT:
                return _decode_envelope(data)
            if isinstance(data, dict):
                if {"protected_key", "nonce", "ciphertext"} & data.keys():
                    raise ConfigIntegrityError("加密配置封装被修改")
                # Legacy plaintext is accepted once and immediately replaced atomically.
                _save_uncached(data)
                return data
            raise ConfigIntegrityError("配置文件内容不是设置对象")
        except ConfigIntegrityError:
            _mark_integrity_failed()
            _log.error("配置文件完整性验证失败，已使用安全默认设置")
        except Exception:
            _mark_integrity_failed()
            _log.exception("配置文件无法读取，已使用安全默认设置")
    return {}


def load() -> dict:
    global _config_cache
    if _config_cache is None:
        _config_cache = _load_uncached()
    return _config_cache


def _save_uncached(data: dict, *, expected_revision: bytes | None = None, check_revision: bool = False) -> None:
    _require_writable()
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    if path.exists():
        try:
            candidate = json.loads(path.read_text(encoding="utf-8"))
            previous = candidate if isinstance(candidate, dict) else None
        except Exception:
            previous = None
    payload = _encode_envelope(data, previous)
    # 原子写入：先写临时文件再替换，避免写入中断留下半截/空配置导致设置丢失。
    descriptor, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if check_revision and not hmac.compare_digest(
            _configuration_revision(path) or b"", expected_revision or b""
        ):
            raise ConfigIntegrityError("配置文件已被其他进程修改，请重试")
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def save(data: dict) -> None:
    global _config_cache, _config_dirty
    with _config_write_lock, _interprocess_config_lock():
        _require_writable()
        # 与磁盘当前状态合并后落盘：browser_host 等常驻进程用启动时的
        # 旧缓存整体写回时，不覆盖主程序随后保存的新设置。
        disk = _load_uncached()
        _require_writable()
        revision = _configuration_revision(_config_path())
        merged = {**disk, **data}
        _config_cache = merged
        _config_dirty = True
        _save_uncached(merged, expected_revision=revision, check_revision=True)
        _config_dirty = False


def get(key: str, default=None):
    return _read_key(load(), key, default)


def screen_capture_allowed() -> bool:
    """Read the positive setting, including the previous inverse key.

    默认禁止截屏：保险库内容不应在截图、录屏、投屏中默认可见。用户显式保存过的
    取值（新键或旧的反向键）一律沿用，不因改默认值而改变。
    """
    data = load()
    allowed = _read_key(data, "screen_capture_allowed", None)
    if allowed is not None:
        return bool(allowed)
    protect = _read_key(data, "screen_capture_protect", None)
    if protect is not None:
        return not bool(protect)
    return DEFAULT_SCREEN_CAPTURE_ALLOWED


def set(key: str, value) -> None:
    global _config_cache, _config_dirty
    with _config_write_lock, _interprocess_config_lock():
        _require_writable()
        # 每次写入都基于磁盘最新状态，避免用本进程缓存的旧值回写。
        data = _load_uncached()
        _require_writable()
        revision = _configuration_revision(_config_path())
        _write_key(data, key, value)
        _config_cache = data
        _config_dirty = True
        _save_uncached(data, expected_revision=revision, check_revision=True)
        _config_dirty = False


def set_many(values: dict[str, object]) -> None:
    """Persist several settings atomically with one encrypted fsync.

    Settings controls often change together (and spin boxes can emit rapidly).
    Repeating the full read/decrypt/encrypt/fsync cycle for every field stalls the
    Qt event loop, so callers that already hold a coherent snapshot use this batch
    entry point instead.
    """
    global _config_cache, _config_dirty
    if not values:
        return
    with _config_write_lock, _interprocess_config_lock():
        _require_writable()
        data = _load_uncached()
        _require_writable()
        revision = _configuration_revision(_config_path())
        changed = False
        for key, value in values.items():
            if _read_key(data, key, object()) != value:
                _write_key(data, key, value)
                changed = True
        _config_cache = data
        if not changed:
            return
        _config_dirty = True
        _save_uncached(data, expected_revision=revision, check_revision=True)
        _config_dirty = False


def stage_many(values: dict[str, object]) -> None:
    """Expose pending UI values through ``get`` before their debounced disk write."""
    global _config_cache
    if not values:
        return
    data = load()
    for key, value in values.items():
        _write_key(data, key, value)
    _config_cache = data


def flush() -> None:
    global _config_dirty, _config_cache
    if _config_dirty and _config_cache is not None:
        _require_writable()
        _save_uncached(_config_cache)
        _config_dirty = False


def invalidate_cache() -> None:
    global _config_cache, _config_dirty
    _config_cache = None
    _config_dirty = False


def reset_corrupt_config() -> None:
    """Explicitly discard an unreadable config; normal setters must never do this implicitly."""
    global _config_cache, _config_dirty, _config_integrity_failed
    with _config_write_lock, _interprocess_config_lock():
        path = _config_path()
        if path.exists():
            path.unlink()
        _config_cache = {}
        _config_dirty = False
        _config_integrity_failed = False
        _save_uncached({})


def recover_corrupt_config(data: dict) -> None:
    """Explicitly replace an unreadable config with caller-supplied recovered settings."""
    reset_corrupt_config()
    save(data)


_THEME_MODES = frozenset({"light", "dark", "auto", "brand_blue"})


def _migrate_theme_mode(mode: str) -> str:
    """旧版“品牌蓝”主题已并入浅色，读取时统一迁移。"""
    return "light" if mode == "brand_blue" else mode


def theme_mode() -> str:
    """返回主题模式；优先当前账户设置，否则旧版 dark 布尔配置，最后默认。"""
    name = load().get("current_user")
    if name:
        table = load().get("account_settings")
        if isinstance(table, dict):
            acct = table.get(name)
            if isinstance(acct, dict):
                mode = acct.get("theme_mode")
                if mode in _THEME_MODES:
                    return _migrate_theme_mode(mode)
    data = load()
    mode = data.get("theme_mode")
    if mode in _THEME_MODES:
        return _migrate_theme_mode(mode)
    if "dark" in data:
        return "dark" if bool(data["dark"]) else "light"
    return DEFAULT_THEME_MODE


def language_mode() -> str:
    """返回界面语言；优先当前账户设置，旧配置和未知值统一回退到跟随系统。"""
    name = load().get("current_user")
    if name:
        table = load().get("account_settings")
        if isinstance(table, dict):
            acct = table.get(name)
            if isinstance(acct, dict):
                mode = acct.get("language_mode")
                if mode in {"auto", "zh-Hans", "en"}:
                    return mode
    mode = get("language_mode", DEFAULT_LANGUAGE_MODE)
    return mode if mode in {"auto", "zh-Hans", "en"} else DEFAULT_LANGUAGE_MODE


def lock_seconds() -> int:
    """返回自动锁定秒数，优先当前账户设置，兼容旧版 lock_minutes 配置。"""
    name = load().get("current_user")
    if name:
        table = load().get("account_settings")
        if isinstance(table, dict):
            acct = table.get(name)
            if isinstance(acct, dict) and "lock_seconds" in acct:
                try:
                    seconds = int(acct["lock_seconds"])
                except (TypeError, ValueError):
                    seconds = DEFAULT_LOCK_SECONDS
                return max(MIN_LOCK_SECONDS, min(MAX_LOCK_SECONDS, seconds))
    data = load()
    value = data.get("lock_seconds")
    if value is None and "lock_minutes" in data:
        try:
            value = int(data["lock_minutes"]) * 60
        except (TypeError, ValueError):
            value = DEFAULT_LOCK_SECONDS
    try:
        seconds = int(DEFAULT_LOCK_SECONDS if value is None else value)
    except (TypeError, ValueError):
        seconds = DEFAULT_LOCK_SECONDS
    return max(MIN_LOCK_SECONDS, min(MAX_LOCK_SECONDS, seconds))


# ---------- 多用户 ----------
def _valid_vault_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(4) == b"PMVS"
    except OSError:
        return False


def _name_from_vault_file(path: Path) -> str:
    # 命名统一：文件名去掉后缀即为账户名，不再处理 vault_ 前缀。
    return path.stem.strip() or "默认账户"


def _recover_users_from_vault_files(data: dict) -> list[dict]:
    # 若主程序或 browser_host 已有较新的注册表，直接复用，不做无谓重建。
    existing = data.get("users")
    if isinstance(existing, list) and existing:
        return existing

    trashed = data.get("trashed_accounts")
    trashed_names = {str(name) for name in trashed.keys()} if isinstance(trashed, dict) else builtins.set()
    candidates = [
        path for path in vault_dir().glob("*.pmv")
        if path.is_file() and _valid_vault_file(path)
    ]
    candidates.sort(key=lambda path: path.stat().st_mtime, reverse=True)

    users: list[dict] = []
    used_names: set[str] = builtins.set()
    for path in candidates:
        base_name = _name_from_vault_file(path)
        if base_name in trashed_names:
            continue
        name = base_name
        index = 2
        while name in used_names:
            name = f"{base_name}-{index}"
            index += 1
        used_names.add(name)
        users.append({"name": name, "file": path.name})

    if users:
        data["users"] = users
        if data.get("current_user") not in used_names:
            data["current_user"] = users[0]["name"]
        save(data)
        _log.warning("用户注册表为空，已从现有保险库文件恢复 %d 个账户", len(users))
    return users


def list_users(include_trashed: bool = False) -> list[dict]:
    """已注册用户列表，每项形如 {"name": "FAE", "file": "FAE.pmv"}。

    默认隐藏处于回收站中的账户（``include_trashed=False``，对应 ACCOUNT_LIFECYCLE
    的「Trashed 状态从所有可见入口消失」）；需要枚举全部账户（如分配唯一文件名、
    清理过期账户）时传 ``include_trashed=True``。
    """
    data = _load_uncached()
    if _config_integrity_failed:
        # A damaged settings file must not trigger a second source of settings
        # or an automatic write while its contents cannot be authenticated.
        return []
    users = data.get("users", [])
    users = users if isinstance(users, list) else []
    if not users:
        users = _recover_users_from_vault_files(data)
    if include_trashed:
        return users
    trashed = trashed_accounts()
    return [u for u in users if u.get("name") not in trashed]


def unique_vault_filename(name: str) -> str:
    """为新用户生成一个不与现有库文件冲突的文件名。"""
    taken = {u.get("file") for u in list_users(include_trashed=True)}
    base = _INVALID_NAME_CHARS.sub("_", name).strip() or "user"
    filename = f"{base}.pmv"
    n = 2
    while filename in taken:
        filename = f"{base}-{n}.pmv"
        n += 1
    return filename


def register_user(name: str, filename: str) -> dict:
    data = _load_uncached()
    raw_users = data.get("users")
    users = list(raw_users) if isinstance(raw_users, list) else []
    record = {"name": name, "file": filename}
    users.append(record)
    set("users", users)
    return record


def rename_user(old_name: str, new_name: str) -> dict:
    """重命名账户的显示名（文件与库内容不变），同步 current_user 与回收站映射。"""
    name = str(new_name or "").strip()
    if not name or _INVALID_NAME_CHARS.search(name):
        raise ValueError("账户名不合法")
    data = _load_uncached()
    users = data.get("users")
    if not isinstance(users, list):
        raise ValueError("账户不存在")
    target = next((u for u in users if u.get("name") == old_name), None)
    if target is None:
        raise ValueError("账户不存在")
    if any(u.get("name") == name for u in users):
        raise ValueError("账户名已存在")
    target["name"] = name
    if data.get("current_user") == old_name:
        data["current_user"] = name
    trashed = data.get("trashed_accounts")
    if isinstance(trashed, dict) and old_name in trashed:
        trashed[name] = trashed.pop(old_name)
    # 账户重命名同步迁移其设置命名空间，避免设置随显示名变化而丢失。
    table = data.get("account_settings")
    if isinstance(table, dict) and old_name in table:
        table[name] = table.pop(old_name)
        data["account_settings"] = table
    save(data)
    return target


# ---------- PMVE 自动压缩进度 ----------


def compact_state() -> dict[str, dict]:
    """按库文件名记录最近一次自动压缩的提交序号/文件大小/时间。"""
    state = get("pmve_compact_state", {})
    return state if isinstance(state, dict) else {}


def record_compact(filename: str, revision: int, size: int) -> None:
    """记录一次自动压缩：本次压缩后的提交序号与文件字节数，用于下次阈值判断。"""
    state = dict(compact_state())
    state[filename] = {"revision": int(revision), "size": int(size), "at": time.time()}
    set("pmve_compact_state", state)


def record_import(filename: str) -> None:
    """记录一次导入：导入完成后进入冷却期，冷却期内不自动压缩。"""
    state = dict(compact_state())
    entry = state.get(filename, {})
    entry = dict(entry) if isinstance(entry, dict) else {}
    entry["imported_at"] = time.time()
    state[filename] = entry
    set("pmve_compact_state", state)


def user_vault_path(record: dict) -> Path:
    return vault_dir() / record["file"]


def _user_record(name: str, *, include_trashed: bool = True) -> dict | None:
    for u in list_users(include_trashed=include_trashed):
        if u.get("name") == name:
            return u
    return None


# ---------- 账户回收站（ACCOUNT_LIFECYCLE.md）----------
# 账户层软删除：删除仅写入回收站标记（账户名 → 删除时刻的 UTC 毫秒），
# 不动任何 .pmv / 恢复密钥 / 生物识别绑定；30 天内可恢复，逾期才物理清理。
# 该标记是设备本地偏好，不写入 .pmv，因此不参与文件级同步（见规范 §6）。


def trashed_accounts() -> dict[str, int]:
    """回收站映射：账户名 → 删除时刻的 UTC 毫秒时间戳。"""
    data = get("trashed_accounts", {})
    if not isinstance(data, dict):
        return {}
    result: dict[str, int] = {}
    for name, ts in data.items():
        try:
            result[str(name)] = int(ts)
        except (TypeError, ValueError):
            continue
    return result


def is_account_trashed(name: str) -> bool:
    return name in trashed_accounts()


def trash_account(name: str) -> None:
    """软删除账户：写入回收站标记，不触碰文件 / 密钥。

    当前账户被删除时清空 ``current_user``（ACCOUNT_LIFECYCLE §2）。
    """
    data = _load_uncached()
    trashed = data.get("trashed_accounts")
    if not isinstance(trashed, dict):
        trashed = {}
    trashed[name] = int(time.time() * 1000)
    data["trashed_accounts"] = trashed
    if data.get("current_user") == name:
        data["current_user"] = None
    save(data)
    _log.info("账户「%s」已移入回收站", name)


def restore_account(name: str) -> bool:
    """恢复账户（Trashed → Active）：移除回收站标记即可，无需主密码。"""
    data = _load_uncached()
    trashed = data.get("trashed_accounts")
    if not isinstance(trashed, dict) or name not in trashed:
        return False
    del trashed[name]
    data["trashed_accounts"] = trashed
    save(data)
    _log.info("账户「%s」已从回收站恢复", name)
    return True


def purge_account(name: str) -> None:
    """物理删除账户（Trashed → Purged，不可逆，ACCOUNT_LIFECYCLE §4）。

    按规范顺序清理：生物识别绑定 → 库文件(.pmv/.bak/.tmp) →
    回收站标记 / 注册表项 → current_user。
    """
    from . import biometric  # 延迟导入避免循环依赖

    record = _user_record(name)
    if record is not None:
        path = user_vault_path(record)
        biometric.disable(path)
        for p in (path, path.with_suffix(path.suffix + ".bak"), path.with_suffix(path.suffix + ".tmp")):
            try:
                p.unlink()
            except OSError:
                pass
    data = _load_uncached()
    users = data.get("users")
    if isinstance(users, list):
        data["users"] = [u for u in users if u.get("name") != name]
    trashed = data.get("trashed_accounts")
    if isinstance(trashed, dict):
        trashed.pop(name, None)
        data["trashed_accounts"] = trashed
    if data.get("current_user") == name:
        data["current_user"] = None
    table = data.get("account_settings")
    if isinstance(table, dict) and name in table:
        del table[name]
        data["account_settings"] = table
    save(data)
    _log.warning("账户「%s」已彻底删除（不可恢复）", name)


def purge_expired_accounts() -> list[str]:
    """启动期清理：彻底删除回收站中超过保留期的账户，返回被清理的账户名列表。"""
    trashed = trashed_accounts()
    if not trashed:
        return []
    cutoff = time.time() * 1000 - ACCOUNT_RETENTION_DAYS * 86400 * 1000
    expired = [name for name, ts in trashed.items() if ts <= cutoff]
    for name in expired:
        purge_account(name)
    if expired:
        _log.info("启动清理：彻底删除 %d 个过期账户", len(expired))
    return expired


def get_current_user() -> str | None:
    # 直接读取顶层键，避免经由 get() 的账户命名空间层形成递归。
    return load().get("current_user")


def set_current_user(name: str | None) -> None:
    set("current_user", name)


# ── 锁定状态签名（防篡改）───────────────────────────────────

_LOCKOUT_SALT = b"PM-Lockout-v1"
_LOCKOUT_N = 2**12


def _lockout_key() -> bytes:
    return _derive_lockout_key(str(vault_dir()))


@lru_cache(maxsize=4)
def _derive_lockout_key(directory: str) -> bytes:
    return Scrypt(salt=_LOCKOUT_SALT, length=32, n=_LOCKOUT_N, r=8, p=1).derive(directory.encode())


def _lockout_sig(key: str, value) -> str:
    return hmac.new(_lockout_key(), f"{key}:{value}".encode(), sha256).hexdigest()


def get_lockout(key: str, default=0):
    """返回 (value, is_valid)。is_valid=False 表示签名不匹配（被篡改）。

    优先读取当前账户命名空间；仅当账户层无该键时才回退到顶层（兼容旧数据）。
    数据中无签名时视为有效（从未写入过），防止首次启动误判为篡改。
    """
    data = load()
    name = load().get("current_user")
    if name and not _is_global_key(key):
        table = data.get("account_settings")
        if isinstance(table, dict):
            acct = table.get(name)
            if isinstance(acct, dict) and (key in acct or f"{key}_sig" in acct):
                value = acct.get(key, default)
                sig = acct.get(f"{key}_sig")
                if sig is None:
                    return value, True
                return value, hmac.compare_digest(sig, _lockout_sig(key, value))
    value = data.get(key, default)
    sig = data.get(f"{key}_sig")
    if sig is None:
        return value, True
    return value, hmac.compare_digest(sig, _lockout_sig(key, value))


def set_lockout(key: str, value) -> None:
    with _config_write_lock:
        data = _load_uncached()
        _write_key(data, key, value)
        _write_key(data, f"{key}_sig", _lockout_sig(key, value))
        save(data)


def browser_private_origins() -> tuple[list[str], bool]:
    """Return exact private-IP origins and whether their local signature is valid."""
    key = "browser_autofill_private_origins"
    data = load()
    raw = data.get(key, [])
    if not isinstance(raw, list):
        return [], False
    values = list(dict.fromkeys(value for value in raw if isinstance(value, str)))[:64]
    signature = data.get(f"{key}_sig")
    if signature is None:
        return ([], True) if not values else ([], False)
    if not hmac.compare_digest(str(signature), _lockout_sig(key, raw)):
        return [], False
    return values, True


def set_browser_private_origins(origins: list[str]) -> None:
    values = list(dict.fromkeys(value for value in origins if isinstance(value, str)))[:64]
    set_lockout("browser_autofill_private_origins", values)


# ── 主密码解锁失败锁定（语义对齐安卓 security.LockoutPref）────
# 安卓规则（LockoutPref）：
#   MAX_ATTEMPTS = 5，LOCKOUT_SECONDS = 30
#   recordFailure: count = min(fail+1, MAX)；remaining = MAX - count
#     remaining>0 → retryDelay = 2**(count-1) * 250ms
#     else        → rounds += 1；cooldown = LOCKOUT_SECONDS * rounds * 1000ms；
#                   清零 fail_count，记录 rounds 与 lockout_until
#   clear(): fail_count=0, rounds=0, lockout_until=0

PASSWORD_MAX_ATTEMPTS = 5
PASSWORD_LOCKOUT_SECONDS = 30


def record_password_failure() -> tuple[int, float, bool, int]:
    """记录一次主密码解锁失败。

    返回 (new_fail_count, retry_delay_seconds, entered_cooldown, cooldown_seconds)，
    语义与安卓 ``LockoutPref.recordFailure`` 完全一致。
    """
    with _config_write_lock:
        count0 = max(0, int(get_lockout("fail_count")[0] or 0))
        rounds0 = max(0, int(get_lockout("lockout_rounds")[0] or 0))
        count = min(count0 + 1, PASSWORD_MAX_ATTEMPTS)
        remaining = PASSWORD_MAX_ATTEMPTS - count
        now = time.time()
        if remaining > 0:
            delay = 2.0 ** (count - 1) * 0.25
            set_lockout("fail_count", count)
            set_lockout("next_attempt_at", now + delay)
            return count, delay, False, 0
        new_rounds = rounds0 + 1
        cooldown = PASSWORD_LOCKOUT_SECONDS * new_rounds
        set_lockout("fail_count", 0)
        set_lockout("lockout_rounds", new_rounds)
        set_lockout("lockout_until", now + cooldown)
        set_lockout("next_attempt_at", 0)
        return 0, 0.0, True, cooldown


def password_cooling_remaining() -> float:
    """距冷却结束的剩余秒数；未冷却返回 0。"""
    until = max(float(get_lockout("lockout_until")[0] or 0),
                float(get_lockout("next_attempt_at")[0] or 0))
    return max(0.0, until - time.time())


def clear_password_lockout() -> None:
    """解锁成功后清空全部失败锁定状态（含 rounds，与安卓 clear 对齐）。"""
    with _config_write_lock:
        set_lockout("fail_count", 0)
        set_lockout("lockout_rounds", 0)
        set_lockout("lockout_until", 0)
        set_lockout("next_attempt_at", 0)
