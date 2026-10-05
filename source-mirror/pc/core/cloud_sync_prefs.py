"""Per-vault automatic cloud-sync preferences, mirroring the Android AutoCloudSyncPrefs.

Scheduler state (per-target enabled / interval / timestamps / failure counter /
status) plus the stored ``sync_last_*`` record and the WebDAV preview cache all
live in the encrypted config under a per-vault SHA-256 suffix, so every vault
keeps an independent association, scheduler and stored status.  This module owns
the key scheme so the UI and scheduler never hand-roll preference names.

Key layout (Android ``{name}_{suffix}``, PC prefix ``cloud_auto_``):

- ``cloud_auto_target_<suffix>``              current auto target ("drive"/"webdav")
- ``cloud_auto_<target>_enabled_<suffix>``    per-target auto-sync switch
- ``cloud_auto_<target>_interval_<suffix>``   interval in minutes (validated)
- ``cloud_auto_<target>_enabled_at_<suffix>`` first-enable timestamp
- ``cloud_auto_<target>_last_success_<suffix>`` last successful run timestamp
- ``cloud_auto_<target>_failures_<suffix>``   consecutive-failure counter
- ``cloud_auto_<target>_status_<suffix>``     per-target status text
- ``cloud_auto_<target>_last_attempt_<suffix>`` last scheduled attempt timestamp
- ``cloud_sync_enabled_<suffix>``             master cloud-sync feature toggle
- ``cloud_auto_sync_last_success_<suffix>``   stored status: last success (CloudSyncStoredStatus)
- ``cloud_auto_sync_last_target_<suffix>``    stored status: last target
- ``cloud_auto_sync_last_error_<suffix>``     stored status: last error message
- ``cloud_auto_webdav_preview_etag_<suffix>`` WebDAV preview cache ETag
- ``cloud_auto_webdav_preview_size_<suffix>`` WebDAV preview cache size
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from . import config

INTERVALS = (15, 30, 60, 180, 360, 1440, 10080)
INTERVAL_LABELS = ("15分钟", "30分钟", "1小时", "3小时", "6小时", "每天", "每周")
DEFAULT_INTERVAL_MINUTES = 60
STATUS_NEVER = "尚未执行自动同步"
TARGETS = ("drive", "webdav")


@dataclass(frozen=True)
class AutoSyncSettings:
    enabled: bool
    target: str
    interval_minutes: int
    enabled_at: float
    last_success: float
    failures: int
    status: str


@dataclass(frozen=True)
class CloudSyncStoredStatus:
    last_success_at: float = 0.0
    target: str = ""
    error: str = ""


@dataclass(frozen=True)
class WebDavPreviewCache:
    etag: str = ""
    size: int = -1


def suffix(vault_id: str) -> str:
    """Per-vault key suffix: first 24 hex chars of SHA-256, same as Android."""
    return sha256(str(vault_id).encode("utf-8")).hexdigest()[:24]


def key(vault_id: str, name: str) -> str:
    return f"cloud_auto_{name}_{suffix(vault_id)}"


def master_key(vault_id: str) -> str:
    """Master cloud-sync feature toggle (controls the Sync-menu entry visibility)."""
    return f"cloud_sync_enabled_{suffix(vault_id)}"


def is_due(enabled_at: float, last_success: float, interval_minutes: int, now: float) -> bool:
    interval = interval_minutes if interval_minutes in INTERVALS else DEFAULT_INTERVAL_MINUTES
    base = max(float(enabled_at or 0.0), float(last_success or 0.0))
    return base <= 0.0 or now >= base + interval * 60


def _bool(value) -> bool:
    return bool(value)


def _float(value, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value, default: int = DEFAULT_INTERVAL_MINUTES) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def load(vault_id: str) -> AutoSyncSettings:
    """Read the current scheduler settings for one vault (Android AutoCloudSyncPrefs.load)."""
    target = str(config.get(key(vault_id, "target"), "") or "")
    if target not in TARGETS:
        target = ""
    enabled = _bool(config.get(key(vault_id, f"{target}_enabled" if target else "enabled"), False))
    interval = _int(config.get(key(vault_id, f"{target}_interval" if target else "interval"), DEFAULT_INTERVAL_MINUTES))
    if interval not in INTERVALS:
        interval = DEFAULT_INTERVAL_MINUTES
    enabled_at = _float(config.get(key(vault_id, f"{target}_enabled_at" if target else "enabled_at")))
    last_success = _float(config.get(key(vault_id, f"{target}_last_success" if target else "last_success")))
    failures = _int(config.get(key(vault_id, f"{target}_failures" if target else "failures"), 0))
    status = str(config.get(key(vault_id, f"{target}_status" if target else "status"), STATUS_NEVER) or STATUS_NEVER)
    return AutoSyncSettings(enabled, target, interval, enabled_at, last_success, failures, status)


def save(vault_id: str, enabled: bool, target: str, interval_minutes: int) -> None:
    """Persist the auto-sync switch for one target (Android AutoCloudSyncPrefs.save)."""
    if target not in TARGETS:
        raise ValueError(f"unsupported auto-sync target: {target}")
    interval = interval_minutes if interval_minutes in INTERVALS else DEFAULT_INTERVAL_MINUTES
    was_enabled = _bool(config.get(key(vault_id, f"{target}_enabled"), False))
    config.set(key(vault_id, "target"), target)
    config.set(key(vault_id, f"{target}_enabled"), bool(enabled))
    config.set(key(vault_id, f"{target}_interval"), interval)
    if enabled and not was_enabled:
        now = __import__("time").time()
        config.set(key(vault_id, f"{target}_enabled_at"), now)
    # Compatibility master switch: on when any target is enabled.
    other = "webdav" if target == "drive" else "drive"
    any_enabled = enabled or _bool(config.get(key(vault_id, f"{other}_enabled"), False))
    config.set(key(vault_id, "enabled"), any_enabled)


def success(vault_id: str, status: str, target: str = "") -> None:
    """Record a successful auto-sync run (Android AutoCloudSyncPrefs.success)."""
    target = target if target in TARGETS else load(vault_id).target
    now = __import__("time").time()
    config.set(key(vault_id, f"{target}_last_success"), now)
    config.set(key(vault_id, f"{target}_failures"), 0)
    config.set(key(vault_id, f"{target}_status"), status)
    config.set(key(vault_id, "sync_last_success"), now)
    config.set(key(vault_id, "sync_last_target"), target)
    config.set(key(vault_id, "sync_last_error"), None)


def record_failure(vault_id: str, target: str, message: str) -> None:
    """Store the last failure without touching the counter (Android recordFailure)."""
    config.set(key(vault_id, "sync_last_target"), target)
    config.set(key(vault_id, "sync_last_error"), message)


def skipped(vault_id: str, status: str) -> None:
    """Record a skipped pass (Android AutoCloudSyncPrefs.skipped)."""
    target = load(vault_id).target
    config.set(key(vault_id, f"{target}_status" if target else "status"), status)


def failure(vault_id: str, status: str, target: str = "") -> int:
    """Increment the failure counter; auto-disable the target after 3 consecutive failures."""
    target = target if target in TARGETS else load(vault_id).target
    count = _int(config.get(key(vault_id, f"{target}_failures"), 0), 0) + 1
    config.set(key(vault_id, f"{target}_failures"), count)
    config.set(key(vault_id, f"{target}_status"), status)
    if count >= 3:
        config.set(key(vault_id, f"{target}_enabled"), False)
    return count


def load_sync_status(vault_id: str) -> CloudSyncStoredStatus:
    """Read the stored sync status record (Android CloudSyncStoredStatus)."""
    return CloudSyncStoredStatus(
        last_success_at=_float(config.get(key(vault_id, "sync_last_success"))),
        target=str(config.get(key(vault_id, "sync_last_target"), "") or ""),
        error=str(config.get(key(vault_id, "sync_last_error"), "") or ""),
    )


def save_webdav_preview_cache(vault_id: str, etag: str, size: int) -> None:
    config.set(key(vault_id, "webdav_preview_etag"), etag)
    config.set(key(vault_id, "webdav_preview_size"), int(size))


def load_webdav_preview_cache(vault_id: str) -> WebDavPreviewCache:
    return WebDavPreviewCache(
        etag=str(config.get(key(vault_id, "webdav_preview_etag"), "") or ""),
        size=_int(config.get(key(vault_id, "webdav_preview_size"), -1), -1),
    )


def master_enabled(vault_id: str) -> bool:
    return _bool(config.get(master_key(vault_id), False))


def set_master_enabled(vault_id: str, enabled: bool) -> None:
    config.set(master_key(vault_id), bool(enabled))