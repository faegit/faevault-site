"""Local password-health analysis shared by the desktop security center."""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Callable, Iterable

from zxcvbn import zxcvbn

from . import leak, modules
from .models import Entry, SecretType

HIGH = "high"
IMPROVEMENT = "improvement"
HEALTHY = "healthy"
ALL = "all"


@dataclass(frozen=True)
class Finding:
    key: str
    label: str
    high_risk: bool
    icon: str
    description: str
    recommendation: str


FINDINGS = (
    Finding("leaked", "公开泄露", True, "security", "联网记录确认该密码出现在公开泄露数据中。", "立即更换，并避免在其他账户继续使用。"),
    Finding("duplicate", "重复密码", True, modules.PASSWORD, "至少两个条目正在使用完全相同的密码。", "为每个账户设置不同的随机密码。"),
    Finding("weak", "强度极低", True, "security", "密码包含容易猜测的词语、序列或变体，强度评分很低。", "改用至少 12 位且难以猜测的随机密码。"),
    Finding("pattern", "常见/初始密码", True, modules.RECOVERY, "密码命中常见弱密码字典，或包含明显序列、默认词和重复模式。", "更换为与常见词、设备默认值无关的随机密码。"),
    Finding("near_duplicate", "相似密码", False, modules.LOGIN_ACCOUNT, "多个密码仅在大小写、连续数字或首尾符号上存在变化。", "不要用简单变体区分账户，改用彼此独立的密码。"),
    Finding("too_short", "长度不足 12 位", False, modules.TEXT, "密码长度少于建议的 12 位。", "在不复用旧密码的前提下增加长度。"),
    Finding("account_info", "包含账户信息", False, modules.LOGIN_ACCOUNT, "密码包含用户名、条目名称或网站名称中的明显片段。", "移除可从账户资料推测出的内容。"),
    Finding("long_unchanged", "条目超过 180 天未更新", False, modules.TEXT, "该条目超过 180 天没有更新；这不等同于密码一定未更换。", "确认密码仍然有效且未泄露，必要时更换。"),
)
FINDING_BY_KEY = {finding.key: finding for finding in FINDINGS}
_PASSWORD_FIELDS = frozenset(("password", "wifi_password", "withdrawal_password", "api_key", "api_secret"))
_SEQUENCES = ("1234", "4321", "abcd", "qwerty", "password", "admin", "letmein", "welcome")
_LONG_UNCHANGED_DAYS = 180
_SCANNABLE_TYPES = {SecretType.LOGIN, SecretType.WIFI}


@dataclass(frozen=True)
class HealthReport:
    total: int
    findings: dict[str, tuple[Entry, ...]]
    high_risk: tuple[Entry, ...]
    improvement: tuple[Entry, ...]
    healthy: tuple[Entry, ...]

    def entries_for(self, key: str) -> tuple[Entry, ...]:
        if key == HIGH:
            return self.high_risk
        if key == IMPROVEMENT:
            return self.improvement
        if key == HEALTHY:
            return self.healthy
        if key == ALL:
            return _distinct((*self.high_risk, *self.improvement))
        return self.findings.get(key, ())

    def issues_for(self, entry_id: str) -> tuple[Finding, ...]:
        return tuple(
            finding for finding in FINDINGS
            if any(entry.id == entry_id for entry in self.findings.get(finding.key, ()))
        )


EMPTY_REPORT = HealthReport(0, {finding.key: () for finding in FINDINGS}, (), (), ())


@dataclass(frozen=True)
class _EntryAnalysis:
    entry: Entry
    fingerprint: str
    secret_hashes: frozenset[str]
    near_hashes: frozenset[str]
    leaked: bool
    weak: bool
    common_pattern: bool
    too_short: bool
    account_info: bool
    long_unchanged: bool


_cache_lock = threading.Lock()
_entry_cache: dict[str, _EntryAnalysis] = {}
_report_cache_key: str | None = None
_report_cache: HealthReport | None = None


def analyze(
    entries: Iterable[Entry],
    *,
    logical_revision: str = "",
    force: bool = False,
    now: float | None = None,
    common_password_check: Callable[[str], bool] = leak.is_common_weak,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> HealthReport:
    """Analyze entries without retaining plaintext password collections.

    Only LOGIN and WIFI entry types are scanned (matching Android's PasswordHealth).
    """
    global _report_cache, _report_cache_key
    current = time.time() if now is None else now
    day = int(current // 86400)
    active = [
        entry for entry in entries
        if getattr(entry, "deleted_at", None) is None
        and getattr(entry, "secret_type", None) in _SCANNABLE_TYPES
    ]
    report_key = f"{logical_revision}:{day}" if logical_revision else None
    with _cache_lock:
        if not force and report_key and report_key == _report_cache_key and _report_cache is not None:
            return _report_cache
        if force:
            _entry_cache.clear()

    analyzed: list[_EntryAnalysis] = []
    active_ids: set[str] = set()
    for index, entry in enumerate(active, 1):
        if should_stop and should_stop():
            return EMPTY_REPORT
        active_ids.add(entry.id)
        try:
            fingerprint = _entry_fingerprint(entry, day)
            with _cache_lock:
                cached = _entry_cache.get(entry.id)
            result = replace(cached, entry=entry) if cached and cached.fingerprint == fingerprint else _analyze_entry(
                entry, fingerprint, day, common_password_check
            )
        finally:
            _release(entry)
        with _cache_lock:
            _entry_cache[entry.id] = result
        if result.secret_hashes:
            analyzed.append(result)
        if on_progress:
            on_progress(index, len(active))

    with _cache_lock:
        for stale_id in set(_entry_cache) - active_ids:
            _entry_cache.pop(stale_id, None)

    exact_entries: dict[str, set[str]] = defaultdict(set)
    near_entries: dict[str, set[str]] = defaultdict(set)
    for result in analyzed:
        for digest in result.secret_hashes:
            exact_entries[digest].add(result.entry.id)
        for digest in result.near_hashes:
            near_entries[digest].add(result.entry.id)

    found: dict[str, list[Entry]] = {finding.key: [] for finding in FINDINGS}
    for result in analyzed:
        entry = result.entry
        if result.leaked:
            found["leaked"].append(entry)
        if any(len(exact_entries[digest]) > 1 for digest in result.secret_hashes):
            found["duplicate"].append(entry)
        if result.weak:
            found["weak"].append(entry)
        if result.common_pattern:
            found["pattern"].append(entry)
        if any(len(near_entries[digest]) > 1 for digest in result.near_hashes):
            found["near_duplicate"].append(entry)
        if result.too_short:
            found["too_short"].append(entry)
        if result.account_info:
            found["account_info"].append(entry)
        if result.long_unchanged:
            found["long_unchanged"].append(entry)

    high_ids = {entry.id for finding in FINDINGS if finding.high_risk for entry in found[finding.key]}
    improvement_ids = {
        entry.id for finding in FINDINGS if not finding.high_risk for entry in found[finding.key]
    } - high_ids
    password_entries = tuple(result.entry for result in analyzed)
    report = HealthReport(
        total=len(password_entries),
        findings={key: tuple(value) for key, value in found.items()},
        high_risk=tuple(entry for entry in password_entries if entry.id in high_ids),
        improvement=tuple(entry for entry in password_entries if entry.id in improvement_ids),
        healthy=tuple(entry for entry in password_entries if entry.id not in high_ids | improvement_ids),
    )
    if report_key:
        with _cache_lock:
            _report_cache_key = report_key
            _report_cache = report
    return report


def clear_cache() -> None:
    global _report_cache, _report_cache_key
    with _cache_lock:
        _entry_cache.clear()
        _report_cache = None
        _report_cache_key = None


def _analyze_entry(
    entry: Entry,
    fingerprint: str,
    day: int,
    common_password_check: Callable[[str], bool],
) -> _EntryAnalysis:
    hashes: set[str] = set()
    near_hashes: set[str] = set()
    weak = common = short = account = False
    for secret in _entry_secrets(entry):
        hashes.add(_digest(secret))
        signature = _near_signature(secret)
        if signature:
            near_hashes.add(_digest(signature))
        weak = weak or _extremely_weak(secret)
        common = common or _common_pattern(secret) or common_password_check(secret)
        short = short or len(secret) < 12
        account = account or _contains_account_info(entry, secret)
    return _EntryAnalysis(
        entry=entry,
        fingerprint=fingerprint,
        secret_hashes=frozenset(hashes),
        near_hashes=frozenset(near_hashes),
        leaked=bool(
            leak.has_current_check(entry) and int(getattr(entry, "leak_pwned_count", 0) or 0) > 0
        ),
        weak=weak,
        common_pattern=common or bool(getattr(entry, "leak_common_weak", False)),
        too_short=short,
        account_info=account,
        long_unchanged=bool(entry.updated_at and day - int(entry.updated_at // 86400) >= _LONG_UNCHANGED_DAYS),
    )


def _entry_secrets(entry: Entry):
    seen: set[str] = set()
    base = leak.entry_secret(entry)
    if base:
        seen.add(base)
        yield base
    for module in modules.modules_from_fields(entry.fields):
        module_type = str(module.get("type") or "")
        value = module.get("value")
        if module_type == modules.PASSWORD and isinstance(value, str) and value and value not in seen:
            seen.add(value)
            yield value
        elif isinstance(value, dict):
            for key, raw in value.items():
                if key in _PASSWORD_FIELDS and isinstance(raw, str) and raw and raw not in seen:
                    seen.add(raw)
                    yield raw


def _entry_fingerprint(entry: Entry, day: int) -> str:
    digest = hashlib.sha256()
    for value in (*_entry_secrets(entry), entry.username, entry.title, entry.url, str(entry.updated_at), str(day)):
        digest.update(str(value).encode("utf-8"))
        digest.update(b"\0")
    for module in modules.modules_from_fields(entry.fields):
        digest.update(str(module.get("type") or "").encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _extremely_weak(password: str) -> bool:
    """Use the same zxcvbn score threshold as Android, with bounded work."""
    return zxcvbn(password, max_length=72)["score"] <= 1


def _common_pattern(password: str) -> bool:
    value = password.lower()
    if any(pattern in value for pattern in _SEQUENCES) or (len(value) >= 4 and len(set(value)) <= 2):
        return True
    return any(len(value) % size == 0 and len(set(_chunks(value, size))) == 1 for size in range(1, len(value) // 2 + 1))


def _near_signature(password: str) -> str:
    """Android-compatible near-duplicate signature: lowercase, digits→#, trim non-alnum/#."""
    value = re.sub(r"\d{2,}", "#", password.lower())
    # Trim leading/trailing characters that are not alphanumeric or '#'
    start = 0
    while start < len(value) and not (value[start].isalnum() or value[start] == "#"):
        start += 1
    end = len(value)
    while end > start and not (value[end - 1].isalnum() or value[end - 1] == "#"):
        end -= 1
    value = value[start:end]
    return value if len(value) >= 5 else ""


def _contains_account_info(entry: Entry, password: str) -> bool:
    value = password.lower()
    host = re.sub(r"^[a-z]+://", "", entry.url.lower()).split("/", 1)[0].split(".", 1)[0]
    candidates = (entry.username.split("@", 1)[0], entry.title, host)
    return any(candidate.strip().lower() in value for candidate in candidates if len(candidate.strip()) >= 4)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _chunks(value: str, size: int):
    return (value[index:index + size] for index in range(0, len(value), size))


def _distinct(entries: Iterable[Entry]) -> tuple[Entry, ...]:
    result: list[Entry] = []
    seen: set[str] = set()
    for entry in entries:
        if entry.id not in seen:
            seen.add(entry.id)
            result.append(entry)
    return tuple(result)


def _release(entry: Entry) -> None:
    release = getattr(entry, "release_sensitive", None)
    if callable(release):
        release()
