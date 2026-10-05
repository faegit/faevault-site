"""统一日志配置。

控制台输出 INFO 及以上级别；日志文件使用大小轮转（默认 512 KB × 4 份 ≈ 2 MB 上限），
启动时同步清理超过保留天数的旧备份文件。
调用 setup() 一次即可，所有模块通过 get(name) 获取各自的 logger。
"""

from __future__ import annotations

import logging
import sys
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FMT = "[%(asctime)s] %(levelname)-7s %(name)s: %(message)s"
_DATE = "%H:%M:%S"
_ROOT = "faevault"

_MAX_BYTES = 512 * 1024  # 单文件上限 512 KB
_BACKUP_COUNT = 3  # 保留 3 份备份，连当前文件共 4 份 ≈ 2 MB
_MAX_AGE_DAYS = 30  # 超过 30 天的备份文件直接删除


def setup(
    level: int = logging.DEBUG,
    log_file: Path | None = None,
    max_bytes: int = _MAX_BYTES,
    backup_count: int = _BACKUP_COUNT,
    max_age_days: int = _MAX_AGE_DAYS,
    *,
    console: bool = True,
) -> None:
    root = logging.getLogger(_ROOT)
    if root.handlers:
        return
    root.setLevel(logging.DEBUG)

    if console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_handler.setFormatter(logging.Formatter(_FMT, _DATE))
        root.addHandler(console_handler)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        _purge_old_backups(log_file, max_age_days)
        fh = RotatingFileHandler(
            log_file,
            encoding="utf-8",
            maxBytes=max_bytes,
            backupCount=backup_count,
        )
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(_FMT, _DATE))
        root.addHandler(fh)

    root.debug(
        "日志系统初始化完成，文件：%s（轮转 %d KB × %d 份）",
        log_file or "（未启用）",
        max_bytes // 1024,
        backup_count + 1,
    )


def _purge_old_backups(log_file: Path, max_age_days: int) -> None:
    """删除超龄的轮转备份文件（.1 .2 .3 …），避免手动轮转残留占用空间。"""
    if max_age_days <= 0 or not log_file.parent.exists():
        return
    cutoff = time.time() - max_age_days * 86400
    removed = 0
    for f in log_file.parent.glob(log_file.name + ".*"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except OSError:
            pass
    if removed:
        logging.getLogger(_ROOT).debug("清理 %d 个超龄日志备份文件", removed)


def get(name: str) -> logging.Logger:
    return logging.getLogger(f"{_ROOT}.{name}")


def redact(text: str, keep: int = 1) -> str:
    """脱敏日志中的用户自定义文本（条目标题、标签、SSID 等），仅保留首尾各 keep 个字符。"""
    if not text:
        return ""
    if len(text) <= keep * 2:
        return "*" * len(text)
    return text[:keep] + "*" * (len(text) - keep * 2) + text[-keep:]
