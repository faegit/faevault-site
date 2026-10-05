"""密码泄露检测：离线弱密码字典 + 在线 Pwned Passwords（k-匿名）查询。

两层与安卓端一致：
- 离线：与 ``data/common_passwords.txt`` 中收录的高频泄露/弱密码精确匹配，零网络、合隐私。
- 在线：将密码 SHA-1 哈希前 5 位作为前缀发给 Pwned Passwords API，服务器返回该前缀下
  所有哈希后缀及出现次数，本地比对后缀。全程不暴露完整哈希。
"""

from __future__ import annotations

import hashlib
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import config
from .models import SecretType

_API_URL = "https://api.pwnedpasswords.com/range/"
_DICT_PATH = Path(__file__).resolve().parent / "data" / "common_passwords.txt"

_lock = threading.Lock()
_cache: frozenset[str] | None = None


@dataclass(frozen=True)
class LeakCheckResult:
    entry_id: str
    revision: float
    common_weak: bool
    pwned_count: int
    checked_at: float


def _load_dict() -> frozenset[str]:
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        if _cache is not None:
            return _cache
        words: set[str] = set()
        try:
            with _DICT_PATH.open("r", encoding="utf-8") as f:
                for raw in f:
                    s = raw.strip()
                    if s and not s.startswith("#"):
                        words.add(s)
        except OSError:
            pass
        _cache = frozenset(words)
        return _cache


def is_common_weak(password: str) -> bool:
    """离线检测：密码是否命中本地高频泄露/弱密码字典。"""
    if not password:
        return False
    return password in _load_dict()


def entry_secret(entry) -> str:
    """取条目中可参与泄露检测的密码字段（仅含密码语义的类型有值）。"""
    if entry.secret_type == SecretType.LOGIN:
        return entry.password or ""
    if entry.secret_type == SecretType.WIFI:
        return entry.get_field("wifi_password")
    if entry.secret_type == SecretType.API_KEY:
        return entry.get_field("api_key")
    return ""


def is_entry_leaked(entry) -> bool:
    """返回条目的泄露状态，优先使用与当前版本匹配的持久化检测结果。"""
    if not check_enabled():
        return False
    if has_current_check(entry):
        return bool(entry.leak_common_weak or entry.leak_pwned_count > 0)
    return is_common_weak(entry_secret(entry))


def is_entry_leaked_cached(entry) -> bool:
    """只使用当前版本缓存判断泄露状态；用于列表刷新等高频 UI 路径。"""
    if not check_enabled() or not has_current_check(entry):
        return False
    return bool(entry.leak_common_weak or entry.leak_pwned_count > 0)


def has_current_check(entry) -> bool:
    revision = getattr(entry, "leak_check_revision", None)
    count = getattr(entry, "leak_pwned_count", None)
    return revision is not None and count is not None and revision == entry.updated_at


def needs_leak_check(
    entry,
    *,
    recheck_days: int | None = None,
    force: bool = False,
    now: float | None = None,
) -> bool:
    """Return whether this entry should run the Android-compatible leak pipeline."""
    if not check_enabled():
        return False
    if force:
        # 强制重检（手动触发）：仅需非空密码即可，与旧逻辑一致。
        return bool(entry_secret(entry))
    if recheck_days is None:
        try:
            recheck_days = int(config.get("leak_recheck_days", 5))
        except (TypeError, ValueError):
            recheck_days = 5
    recheck_days = max(0, min(30, recheck_days))
    if recheck_days == 0:
        # 关闭周期重检：无需解密即可直接跳过。
        return False
    # 已有与当前版本匹配的持久化检测结果时，仅凭元信息即可判定（无需解密密码）。
    # 这避免了列表刷新/分类切换等高频路径上对每个条目反复解密密码的开销。
    if has_current_check(entry):
        checked_at = getattr(entry, "leak_checked_at", None)
        if checked_at is None:
            return bool(entry_secret(entry))
        current_time = time.time() if now is None else now
        if current_time - checked_at >= recheck_days * 86400:
            return bool(entry_secret(entry))
        return False
    # 无当前检测：需要检测，但先确认有密码可检测。
    return bool(entry_secret(entry))


def needs_online_check(
    entry,
    *,
    interval_days: int | None = None,
    now: float | None = None,
) -> bool:
    """Backward-compatible name for the full leak-check scheduler predicate."""
    return needs_leak_check(entry, recheck_days=interval_days, now=now)


def make_check_result(entry, *, pwned_count: int, checked_at: float | None = None) -> LeakCheckResult:
    """为条目当前版本构造可持久化结果；网络失败（负数）不得调用。"""
    if pwned_count < 0:
        raise ValueError("network failures cannot be cached as leak check results")
    return LeakCheckResult(
        entry_id=entry.id,
        revision=entry.updated_at,
        common_weak=is_common_weak(entry_secret(entry)),
        pwned_count=pwned_count,
        checked_at=time.time() if checked_at is None else checked_at,
    )


def check_enabled() -> bool:
    """泄露检测总开关是否开启。关闭时不检测、不提示、不置顶。"""
    return bool(config.get("leak_check_enabled", True))


def online_check_enabled() -> bool:
    """在线查询是否开启（设置项，默认开启）。"""
    return check_enabled() and bool(config.get("leak_online_check", True))


def pwned_count(password: str, *, timeout: float = 8.0) -> int:
    """在线查询密码在已知泄露中出现的次数。

    :return: 出现次数；0 表示未发现；网络异常/超时返回 -1。
    """
    if not password:
        return 0
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    req = urllib.request.Request(
        f"{_API_URL}{prefix}",
        headers={
            "User-Agent": "FAEVault/1.0",
            "Add-Padding": "true",  # 防止基于响应长度的侧信道
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return -1
            body = resp.read().decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return -1

    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            try:
                return int(parts[1].strip())
            except ValueError:
                return 0
    return 0


def audit_snapshots(
    snapshots: list[tuple[str, float, str]],
    *,
    query: Callable[[str], int] | None = None,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> list[LeakCheckResult]:
    """检测条目快照，相同密码仅联网一次，失败结果不进入缓存。"""
    query = query or pwned_count
    use_online = online_check_enabled()
    results: list[LeakCheckResult] = []
    counts: dict[str, int] = {}
    total = len(snapshots)
    for index, (entry_id, revision, password) in enumerate(snapshots, start=1):
        if should_stop is not None and should_stop():
            break
        try:
            if password not in counts:
                counts[password] = query(password) if use_online else 0
            count = counts[password]
            if count < 0:
                continue
            results.append(
                LeakCheckResult(
                    entry_id=entry_id,
                    revision=revision,
                    common_weak=is_common_weak(password),
                    pwned_count=count,
                    checked_at=time.time(),
                )
            )
        finally:
            if on_progress is not None:
                on_progress(index, total)
    return results
