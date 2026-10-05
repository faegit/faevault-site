"""PC 本地定期备份：周期策略、卷标识校验与原子覆盖备份。

备份只覆盖目标目录中的同名 .pmv 文件，不做同步；目录不可用或卷标识不符时
抛 [BackupWaitingDevice]，调用方置为“等待设备状态”并稍后重试，不报错。
"""

from __future__ import annotations

import os
import shutil
import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


INTERVALS: dict[str, int] = {
    "realtime": 0,
    "hourly": 3600,
    "daily": 86400,
    "weekly": 604800,
    "monthly": 2592000,
}
ORDER = ["realtime", "hourly", "daily", "weekly", "monthly"]
LABELS = {
    "realtime": "实时",
    "hourly": "每小时",
    "daily": "每天",
    "weekly": "每周",
    "monthly": "每月",
}


class BackupWaitingDevice(Exception):
    """备份目标目录不可用或卷标识不符：等待设备状态，不视为失败。"""


class BackupInsufficientSpace(Exception):
    """目标卷剩余空间不足，拒绝本次备份。"""


BUFFER_SIZE = 8 * 1024 * 1024  # 8 MiB 流式缓冲，绝不整文件读入内存
PARTIAL_SUFFIX = ".backup-partial"
MANIFEST_SUFFIX = ".manifest.json"
DEVICE_MARKER_NAME = "FAEVault.device.json"
DEVICE_MARKER_MAX_BYTES = 4096


class BindingState(str, Enum):
    KNOWN = "known"
    SUSPECTED_ORIGINAL = "suspected_original"
    IDENTITY_ANOMALY = "identity_anomaly"
    NEW_DEVICE = "new_device"


class MarkerState(str, Enum):
    MISSING = "missing"
    VALID = "valid"
    INVALID = "invalid"


@dataclass(frozen=True)
class DeviceMarker:
    state: MarkerState
    device_uuid: str = ""


def _canonical_uuid(value: str | None) -> str:
    try:
        return str(uuid.UUID(str(value).strip())) if value else ""
    except (ValueError, AttributeError, TypeError):
        return ""


def evaluate_binding(
    stored_device_uuid: str | None,
    stored_access_id: str | None,
    observed_device_uuid: str | None,
    observed_access_id: str | None,
) -> BindingState:
    stored_uuid = _canonical_uuid(stored_device_uuid)
    observed_uuid = _canonical_uuid(observed_device_uuid)
    uuid_matches = bool(stored_uuid and stored_uuid == observed_uuid)
    access_matches = bool(
        stored_access_id
        and observed_access_id
        and stored_access_id.strip() == observed_access_id.strip()
    )
    if uuid_matches and access_matches:
        return BindingState.KNOWN
    if uuid_matches:
        return BindingState.SUSPECTED_ORIGINAL
    if access_matches:
        return BindingState.IDENTITY_ANOMALY
    return BindingState.NEW_DEVICE


def read_device_marker(directory: str | Path) -> DeviceMarker:
    path = Path(directory) / DEVICE_MARKER_NAME
    try:
        if not path.exists():
            return DeviceMarker(MarkerState.MISSING)
        if not path.is_file() or path.stat().st_size > DEVICE_MARKER_MAX_BYTES:
            return DeviceMarker(MarkerState.INVALID)
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return DeviceMarker(MarkerState.INVALID)
        marker_uuid = _canonical_uuid(data.get("deviceUuid"))
        if data.get("version") != 1 or not marker_uuid:
            return DeviceMarker(MarkerState.INVALID)
        return DeviceMarker(MarkerState.VALID, marker_uuid)
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        return DeviceMarker(MarkerState.INVALID)


def create_device_marker(directory: str | Path) -> DeviceMarker:
    """仅供用户确认后的绑定流程调用；既有损坏标记绝不覆盖。"""
    existing = read_device_marker(directory)
    if existing.state is not MarkerState.MISSING:
        return existing
    path = Path(directory) / DEVICE_MARKER_NAME
    marker_uuid = str(uuid.uuid4())
    try:
        with path.open("x", encoding="utf-8", newline="\n") as output:
            json.dump({"version": 1, "deviceUuid": marker_uuid}, output, separators=(",", ":"))
            output.flush()
            os.fsync(output.fileno())
    except FileExistsError:
        pass
    except OSError:
        return DeviceMarker(MarkerState.INVALID)
    return read_device_marker(directory)


def interval_seconds(key: str) -> int:
    if key not in INTERVALS:
        raise ValueError(f"无效的备份周期: {key}")
    return INTERVALS[key]


def should_run(
    now: float,
    last_backup_at: float,
    key: str,
    *,
    force: bool = False,
) -> bool:
    seconds = interval_seconds(key)
    if force:
        return True
    if seconds == 0:
        return True
    return now - last_backup_at >= seconds


@dataclass(frozen=True)
class DeviceFingerprint:
    """复合设备指纹：物理盘序列号 / 分区 GUID / 文件系统 UUID / 卷标 / 容量 / 型号。"""

    disk_serial: str = ""
    volume_guid: str = ""
    fs_uuid: str = ""
    label: str = ""
    capacity_bytes: int = 0
    model: str = ""

    @property
    def stable_components(self) -> list[str]:
        return [part for part in (self.disk_serial, self.volume_guid, self.fs_uuid) if part]

    def identity_key(self) -> str:
        """稳定分量组合成唯一键；没有任何稳定分量时返回空串（调用方必须拒绝备份）。"""
        stable = self.stable_components
        if not stable:
            return ""
        return "|".join(stable + [self.label, str(self.capacity_bytes), self.model])

    def display_id(self) -> str:
        raw = "|".join(self.stable_components)
        digest = hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:6].upper()
        kind = "HDD" if self.model else "VOL"
        return f"{kind}-{digest}"

    def display_name(self) -> str:
        return self.label or (self.model or "备份设备")

    def to_dict(self) -> dict[str, object]:
        return {
            "identity": self.identity_key(),
            "id": self.display_id(),
            "name": self.display_name(),
            "model": self.model,
            "capacity": self.capacity_bytes,
        }


def _windows_volume_info(root: str) -> tuple[str, str, str]:
    """返回 (volume GUID, 文件系统卷序列号, 卷标)。"""
    try:
        import ctypes
        from ctypes import wintypes

        volume_name = ctypes.create_unicode_buffer(261)
        serial = wintypes.DWORD()
        max_component = wintypes.DWORD()
        flags = wintypes.DWORD()
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            volume_name,
            261,
            ctypes.byref(serial),
            ctypes.byref(max_component),
            ctypes.byref(flags),
            None,
            0,
        )
        fs_uuid = f"{serial.value:08x}" if ok else ""
        label = volume_name.value or ""
        guid_buf = ctypes.create_unicode_buffer(64)
        volume_guid = ""
        if ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(root, guid_buf, 64):
            volume_guid = guid_buf.value
        return volume_guid, fs_uuid, label
    except Exception:
        return "", "", ""


def _volume_disk_number(root: str) -> int | None:
    """通过 IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS 获取磁盘号。"""
    try:
        import ctypes
        from ctypes import wintypes

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ_WRITE = 0x1 | 0x2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        handle = ctypes.windll.kernel32.CreateFileW(
            ctypes.c_wchar_p(root.rstrip("\\/") + "\\"),
            GENERIC_READ,
            FILE_SHARE_READ_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if not handle or handle == INVALID_HANDLE_VALUE:
            return None
        try:
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
            out = ctypes.create_string_buffer(128)
            returned = wintypes.DWORD()
            ok = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None,
                0,
                out,
                len(out),
                ctypes.byref(returned),
                None,
            )
            if ok and returned.value >= 8:
                return int.from_bytes(out.raw[8:12], "little")
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        pass
    return None


def _physical_drive_info(disk_number: int) -> tuple[str, str]:
    """通过 IOCTL_STORAGE_QUERY_PROPERTY 获取物理盘序列号与型号。"""
    try:
        import ctypes
        from ctypes import wintypes

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ_WRITE = 0x1 | 0x2
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        handle = ctypes.windll.kernel32.CreateFileW(
            ctypes.c_wchar_p(f"\\\\.\\PhysicalDrive{disk_number}"),
            GENERIC_READ,
            FILE_SHARE_READ_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )
        if not handle or handle == INVALID_HANDLE_VALUE:
            return "", ""
        try:
            IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
            query = ctypes.create_string_buffer(12)
            ctypes.memset(query, 0, 12)
            ctypes.memmove(query, ctypes.c_uint(0), 4)  # StorageDeviceProperty
            ctypes.memmove(ctypes.byref(query, 4), ctypes.c_uint(0), 4)  # PropertyStandardQuery
            out = ctypes.create_string_buffer(1024)
            returned = wintypes.DWORD()
            ok = ctypes.windll.kernel32.DeviceIoControl(
                handle,
                IOCTL_STORAGE_QUERY_PROPERTY,
                query,
                len(query),
                out,
                len(out),
                ctypes.byref(returned),
                None,
            )
            if not ok or returned.value < 40:
                return "", ""
            raw = out.raw
            vendor_offset = int.from_bytes(raw[16:20], "little")
            product_offset = int.from_bytes(raw[20:24], "little")
            serial_offset = int.from_bytes(raw[28:32], "little")

            def read_cstr(offset: int) -> str:
                if offset <= 0 or offset >= len(raw):
                    return ""
                end = raw.find(b"\x00", offset)
                if end < 0:
                    end = len(raw)
                return raw[offset:end].decode("utf-8", "replace").strip()

            serial = read_cstr(serial_offset)
            vendor = read_cstr(vendor_offset)
            product = read_cstr(product_offset)
            model = " ".join(part for part in (vendor, product) if part)
            return serial, model
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return "", ""


def _volume_capacity(root: str) -> int:
    try:
        import ctypes

        free = ctypes.c_ulonglong()
        total = ctypes.c_ulonglong()
        avail = ctypes.c_ulonglong()
        if ctypes.windll.kernel32.GetDiskFreeSpaceExW(
            ctypes.c_wchar_p(root),
            ctypes.byref(free),
            ctypes.byref(total),
            ctypes.byref(avail),
        ):
            return int(total.value)
    except Exception:
        pass
    return 0


def device_fingerprint(directory: str) -> DeviceFingerprint | None:
    """收集目录所在卷的复合指纹；目录不存在返回 None。"""
    path = Path(directory)
    if not path.is_dir():
        return None
    if os.name == "nt":
        root = os.path.splitdrive(os.path.abspath(str(path)))[0] or str(path)
        root = root.rstrip("\\/") + "\\"
        volume_guid, fs_uuid, label = _windows_volume_info(root)
        capacity = _volume_capacity(root)
        disk_number = _volume_disk_number(root)
        serial, model = _physical_drive_info(disk_number) if disk_number is not None else ("", "")
        return DeviceFingerprint(
            disk_serial=serial,
            volume_guid=volume_guid,
            fs_uuid=fs_uuid,
            label=label,
            capacity_bytes=capacity,
            model=model,
        )
    try:
        stat = os.stat(path)
        return DeviceFingerprint(fs_uuid=f"dev:{stat.st_dev}", capacity_bytes=0)
    except OSError:
        return None


def volume_identity(directory: str) -> str:
    """目录所在卷的复合身份键；无稳定分量或目录不可用时返回空串（调用方必须拒绝备份）。"""
    fingerprint = device_fingerprint(directory)
    return fingerprint.identity_key() if fingerprint is not None else ""


def storage_access_id(directory: str | Path) -> str:
    """PC 端 SAF ID 等价物：稳定卷 ID + 用户授权的卷内目录位置。"""
    path = Path(directory)
    fingerprint = device_fingerprint(str(path))
    if fingerprint is None:
        return ""
    if os.name == "nt":
        absolute = os.path.abspath(str(path))
        drive, _ = os.path.splitdrive(absolute)
        if not drive:
            return ""
        relative = os.path.relpath(absolute, drive + "\\").replace("\\", "/").strip("/").lower()
        volume = fingerprint.volume_guid or fingerprint.fs_uuid or fingerprint.disk_serial
        return f"win:{volume.strip().lower()}|dir:{relative}" if volume else ""
    try:
        stat = path.stat()
        return f"posix:dev:{stat.st_dev}|dir:{path.resolve().as_posix()}"
    except OSError:
        return ""


def binding_state_for_directory(
    directory: str | Path,
    stored_device_uuid: str | None,
    stored_access_id: str | None,
) -> tuple[BindingState, DeviceMarker, str]:
    access_id = storage_access_id(directory)
    marker = read_device_marker(directory)
    observed_uuid = marker.device_uuid if marker.state is MarkerState.VALID else None
    return (
        evaluate_binding(stored_device_uuid, stored_access_id, observed_uuid, access_id),
        marker,
        access_id,
    )


@dataclass(frozen=True)
class BackupPlan:
    source: Path
    target_dir: Path
    final: Path
    partial: Path
    manifest: Path
    source_size: int
    free_bytes: int

    @property
    def target_name(self) -> str:
        return self.final.name


def build_backup_plan(vault_path: str | Path, backup_dir: str | Path) -> BackupPlan:
    source = Path(vault_path)
    target_dir = Path(backup_dir)
    if not source.is_file():
        raise FileNotFoundError(f"保险库文件不存在: {source}")
    if not target_dir.is_dir():
        raise BackupWaitingDevice("备份目录不可用，等待设备状态")
    final = target_dir / source.name
    partial = target_dir / f"{source.name}{PARTIAL_SUFFIX}"
    manifest = target_dir / f"{source.name}{MANIFEST_SUFFIX}"
    source_size = source.stat().st_size
    free_bytes = shutil.disk_usage(target_dir).free
    if source_size > free_bytes:
        raise BackupInsufficientSpace(
            f"目标卷剩余空间不足：需要 {source_size} 字节，可用 {free_bytes} 字节"
        )
    return BackupPlan(
        source=source,
        target_dir=target_dir,
        final=final,
        partial=partial,
        manifest=manifest,
        source_size=source_size,
        free_bytes=free_bytes,
    )


@dataclass
class BackupJournal:
    """本地进度日志：崩溃后从未完成文件续传，而非整项重来。"""

    source: str = ""
    source_size: int = 0
    target_name: str = ""
    started_at: float = 0.0

    def matches(self, plan: BackupPlan) -> bool:
        return (
            self.source == str(plan.source)
            and self.source_size == plan.source_size
            and self.target_name == plan.target_name
        )

    @staticmethod
    def load(path: Path) -> "BackupJournal":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return BackupJournal(
                source=str(data.get("source", "")),
                source_size=int(data.get("source_size", 0)),
                target_name=str(data.get("target_name", "")),
                started_at=float(data.get("started_at", 0.0)),
            )
        except Exception:
            return BackupJournal()

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        tmp.write_text(
            json.dumps(
                {
                    "source": self.source,
                    "source_size": self.source_size,
                    "target_name": self.target_name,
                    "started_at": self.started_at,
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        os.replace(tmp, path)


def _hash_stream(digest: hashlib._Hash, stream, length: int) -> None:
    remaining = length
    while remaining > 0:
        chunk = stream.read(min(BUFFER_SIZE, remaining))
        if not chunk:
            raise OSError("文件提前结束，无法完成校验")
        digest.update(chunk)
        remaining -= len(chunk)


@dataclass(frozen=True)
class BackupResult:
    final: Path
    sha256: str
    size: int
    resumed: bool
    manifest: Path


def perform_backup(
    vault_path: str | Path,
    backup_dir: str | Path,
    *,
    journal_path: str | Path | None = None,
    resume: bool = True,
) -> BackupResult:
    """流式备份：临时文件 → 哈希校验 → 原子改名，支持崩溃后从未完成文件续传。

    流程：扫描来源 → 确认目标卷身份（由调用方）→ 检查剩余空间 → 生成计划 →
    复制为 .backup-partial（8 MiB 流式 + SHA-256）→ 回读校验 → 原子 rename →
    生成备份清单与进度记录。全程不把整个文件读入内存。
    """
    plan = build_backup_plan(vault_path, backup_dir)
    journal_path = Path(journal_path) if journal_path is not None else None
    journal = BackupJournal.load(journal_path) if journal_path is not None else BackupJournal()
    resumed = False
    start_offset = 0
    digest = hashlib.sha256()

    if resume and plan.partial.exists():
        partial_size = plan.partial.stat().st_size
        if journal.matches(plan) and 0 < partial_size <= plan.source_size:
            resumed = True
            start_offset = partial_size
            with plan.partial.open("rb") as prefix:
                _hash_stream(digest, prefix, partial_size)

    if journal_path is not None and not journal.matches(plan):
        journal = BackupJournal(
            source=str(plan.source),
            source_size=plan.source_size,
            target_name=plan.target_name,
            started_at=time.time(),
        )
        journal.save(journal_path)

    with plan.source.open("rb") as source:
        source.seek(start_offset)
        with plan.partial.open("ab" if resumed else "wb") as output:
            while True:
                chunk = source.read(BUFFER_SIZE)
                if not chunk:
                    break
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())

    # 回读目标（partial）重新校验哈希与大小，杜绝半个文件伪装成完整备份
    verify_digest = hashlib.sha256()
    with plan.partial.open("rb") as target:
        _hash_stream(verify_digest, target, plan.source_size)
    if verify_digest.hexdigest() != digest.hexdigest():
        raise OSError("备份回读校验失败，目标文件已保留为 .backup-partial")

    # Keep four previous verified snapshots beside the current one. Rotating only
    # after the new partial passes verification avoids archiving a failed copy.
    if plan.final.exists():
        for generation in range(4, 1, -1):
            older = plan.target_dir / f"{plan.target_name}.history.{generation - 1}"
            newer = plan.target_dir / f"{plan.target_name}.history.{generation}"
            if older.exists():
                os.replace(older, newer)
        os.replace(plan.final, plan.target_dir / f"{plan.target_name}.history.1")
    os.replace(plan.partial, plan.final)
    manifest = {
        "file": plan.target_name,
        "size": plan.source_size,
        "sha256": digest.hexdigest(),
        "created_at": time.time(),
        "source": str(plan.source),
        "resumed": resumed,
    }
    plan.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return BackupResult(
        final=plan.final,
        sha256=digest.hexdigest(),
        size=plan.source_size,
        resumed=resumed,
        manifest=plan.manifest,
    )
