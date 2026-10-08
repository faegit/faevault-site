"""加密备份：把整个密码库导出为单个可跨设备携带的加密文件，再导入。

与主库相互独立——备份用**单独的导出密码**加密。备份使用 Argon2id +
AES-256-GCM（带 AAD），与安卓端 `storage/PmvBackupCrypto.kt` 逐字节对齐。文件格式::

    V2: MAGIC(4) | VERSION(1)=2 | KDF_ID(1) | MEMORY_KIB(4 BE) | ITERATIONS(4 BE)
        | PARALLELISM(4 BE) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG

外层 PMXB 加密版本保持 v2；加密 JSON 载荷版本为 v3，并继续读取载荷 v2。
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from . import pmv_backup
from . import passkeys
from . import modules
from .log import get
from .models import Entry

_log = get("backup")

MAGIC = b"PMXB"
FORMAT_VERSION = 3
SUPPORTED_PAYLOAD_VERSIONS = frozenset({2, 3})
SUFFIX = ".pmbak"
MAX_BACKUP_BYTES = 128 * 1024 * 1024


def is_strong_passphrase(password: str) -> bool:
    """Match Android's policy for portable backups containing syncable Passkeys."""
    if len(password) < 14:
        return False
    categories = (
        any(char.islower() for char in password),
        any(char.isupper() for char in password),
        any(char.isdigit() for char in password),
        any(
            not char.islower() and not char.isupper() and not char.isdigit()
            for char in password
        ),
    )
    return sum(categories) >= 3


@dataclass
class BackupPayload:
    """解密后的备份内容。``device_id`` 是库谱系标识（SYNC_V2 §7.5），用于导入端判断
    是否同一份库；第三方导出或早期备份没有该字段，``device_id`` 为空、``export_epoch`` 为 0。"""

    entries: list[Entry] = field(default_factory=list)
    export_epoch: float = 0.0
    device_id: str = ""
    key_revision: int = 0
    purge_tombstones: dict[str, float] = field(default_factory=dict)
    autofill_exclusions: dict = field(default_factory=dict)
    deletion_baseline: dict | None = None


def export_encrypted(
    entries: list[Entry],
    path: str | Path,
    password: str,
    device_id: str = "",
    key_revision: int = 0,
    purge_tombstones: dict[str, float] | None = None,
    autofill_exclusions: dict | None = None,
    deletion_baseline: dict | None = None,
) -> None:
    _log.info("加密导出 %d 条 → %s", len(entries), path)
    if contains_syncable_passkeys(entries) and not is_strong_passphrase(password):
        raise ValueError(
            "包含可同步 Passkey 的备份口令至少需要 14 位，并包含大小写字母、数字、符号中的至少三类"
        )
    sync_meta: dict[str, object] = {"device_id": device_id} if device_id else {}
    if key_revision:
        sync_meta["key_revision"] = key_revision
    payload = {
        "version": FORMAT_VERSION,
        "entries": [e.to_dict() for e in entries],
        "purge_tombstones": dict(purge_tombstones or {}),
        "export_epoch": time.time(),
        "sync_meta": sync_meta,
    }
    if autofill_exclusions is not None:
        from .autofill_exclusions import normalize
        payload["autofill_exclusions"] = normalize(autofill_exclusions)
    from .deletion_baseline import baseline
    payload["deletion_baseline"] = baseline(deletion_baseline)
    plaintext = bytearray(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    try:
        data = pmv_backup.encrypt_v2(plaintext, password.encode("utf-8"))
        Path(path).write_bytes(data)
    finally:
        plaintext[:] = b"\x00" * len(plaintext)
        plaintext.clear()
    _log.debug("加密导出完成，文件大小 %d 字节", len(data))


def _decrypt_payload(path: str | Path, password: str) -> dict:
    _log.info("加密导入 ← %s", path)
    source = Path(path)
    if source.stat().st_size > MAX_BACKUP_BYTES:
        raise crypto.DecryptError("加密备份文件过大")
    raw = source.read_bytes()
    try:
        plaintext = bytearray(pmv_backup.decrypt_v2(raw, password.encode("utf-8")))
    except (crypto.DecryptError, ValueError) as exc:
        # decrypt_v2 的 ValueError（结构损坏/参数不符）统一归为"不是有效备份"
        if isinstance(exc, crypto.DecryptError):
            raise
        raise crypto.DecryptError("不是有效的加密备份文件") from exc
    try:
        decoded = json.loads(plaintext.decode("utf-8"))
        if type(decoded) is not dict:
            raise crypto.DecryptError("不是有效的加密备份文件")
        version = decoded.get("version", 2)
        if type(version) is not int or version not in SUPPORTED_PAYLOAD_VERSIONS:
            raise crypto.DecryptError("不支持的加密备份版本")
        return decoded
    finally:
        plaintext[:] = b"\x00" * len(plaintext)
        plaintext.clear()


def import_encrypted(path: str | Path, password: str) -> list[Entry]:
    return import_encrypted_with_meta(path, password).entries


def import_encrypted_with_meta(path: str | Path, password: str) -> BackupPayload:
    """解密备份并返回 :class:`BackupPayload`（含谱系 ``device_id`` 与 ``export_epoch``）。"""
    data = _decrypt_payload(path, password)
    entries = [Entry.from_dict(e) for e in data.get("entries", [])]
    try:
        export_epoch = float(data.get("export_epoch") or 0.0)
    except (TypeError, ValueError):
        export_epoch = 0.0
    meta = data.get("sync_meta") if isinstance(data.get("sync_meta"), dict) else {}
    device_id = str(meta.get("device_id") or "")
    key_revision = int(meta.get("key_revision") or 0)
    purges = {
        str(k): float(v)
        for k, v in (data.get("purge_tombstones", {}) or {}).items()
        if k
    }
    contains_syncable_passkeys(entries)
    _log.info("加密导入成功：%d 条（export_epoch=%s, device_id=%s）", len(entries), export_epoch, device_id[:8] or "∅")
    return BackupPayload(
        entries=entries,
        export_epoch=export_epoch,
        device_id=device_id,
        key_revision=key_revision,
        purge_tombstones=purges,
        autofill_exclusions=data.get("autofill_exclusions", {}),
        deletion_baseline=data.get("deletion_baseline"),
    )


def contains_syncable_passkeys(entries: list[Entry]) -> bool:
    found = False
    for entry in entries:
        for module in modules.modules_from_fields(entry.fields):
            if module.get("type") != modules.PASSKEY:
                continue
            value = module.get("value")
            if type(value) is not dict or value.get("schema_version") != "3":
                continue
            try:
                parsed = passkeys.parse_record(value)
            except passkeys.PasskeyError as exc:
                raise ValueError("Invalid Passkey v3 record in backup") from exc
            if parsed.key_mode == "syncable":
                found = True
    return found
