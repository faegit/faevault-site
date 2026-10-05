"""Safe, narrowly-scoped cleanup helpers for desktop vault maintenance."""

from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


STALE_TEMP_SECONDS = 24 * 60 * 60
_SYSTEM_TEMP_PREFIXES = (
    "vault-sync-",
    "vault-paste-",
    "vault-cloud-pmve-",
    "vault-webdav-pull-",
    "vault-webdav-readback-",
)
# 媒体导入的暂存文件前缀，见 core/media_files.py（mkstemp 落盘，异常终止会留下孤儿）。
_MEDIA_TEMP_PREFIXES = ("import-", "bytes-")


@dataclass(frozen=True, slots=True)
class CleanupReport:
    removed_files: int = 0
    freed_bytes: int = 0


def media_root() -> Path:
    """本机所有保险库的媒体根目录（与应用数据目录同源）。"""
    return Path(os.environ.get("APPDATA", Path.home())) / "vault" / "media"


def _iter_files(pattern: str, *, root: Path, recursive: bool = False, prefix: str = ""):
    """Yield matching files, skipping entries the OS refuses to stat（Windows 独占占用）。"""
    try:
        matches = root.rglob(pattern) if recursive else root.glob(pattern)
        for path in matches:
            try:
                if path.is_file() and path.name.startswith(prefix):
                    yield path
            except OSError:
                continue
    except OSError:
        return


def clean_stale_temp_files(vault_path: Path, *, now: float | None = None) -> CleanupReport:
    """Remove only stale temporary files created by FAEVault.

    覆盖系统临时目录的传输/粘贴中转文件、库目录下未完成的写入临时文件，以及媒体
    目录中超过 24 小时的导入暂存孤儿（对齐安卓端 CacheCleaner.cleanStaleMediaStaging）。
    近期暂存媒体可能仍被「恢复的编辑草稿」引用，因此只回收过期的。
    """

    now = time.time() if now is None else float(now)
    vault_path = Path(vault_path)
    candidates: set[Path] = set()
    temp_root = Path(tempfile.gettempdir())
    for prefix in _SYSTEM_TEMP_PREFIXES:
        candidates.update(_iter_files(f"{prefix}*", root=temp_root))
    if vault_path.parent.is_dir():
        candidates.update(
            _iter_files(f".{vault_path.name}.*.tmp", root=vault_path.parent)
        )
    root = media_root()
    if root.is_dir():
        candidates.update(
            _iter_files("*.tmp", root=root, recursive=True, prefix=_MEDIA_TEMP_PREFIXES)
        )

    removed = 0
    freed = 0
    for path in candidates:
        try:
            stat = path.stat()
            if now - stat.st_mtime < STALE_TEMP_SECONDS:
                continue
            path.unlink()
        except (FileNotFoundError, PermissionError, OSError):
            continue
        removed += 1
        freed += stat.st_size
    return CleanupReport(removed_files=removed, freed_bytes=freed)
