"""PMVE-only vault facade and persistence integration."""

from __future__ import annotations

import copy
import hashlib
import os
import shutil
import time
import uuid
from collections import defaultdict
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from . import crypto, media_files, recovery_key
from .log import get, redact
from .models import Entry, SecretType, monotonic_timestamp
from .pmv_append import _fsync_parent_directory
from .pmv_vault_store import PmvVaultStore
from .pinyin import pinyin_sort_key

_log = get("storage")

PMVE_MAGIC = b"PMVS"
MAX_VAULT_BYTES = 1024 * 1024 * 1024
MAX_SYNC_BYTES = 10 * 1024 * 1024 * 1024
MAX_ENTRY_COUNT = 100_000

_ENTRY_META_KEYS = frozenset(
    {
        "id",
        "title",
        "username",
        "url",
        "target_app",
        "secret_type",
        "tags",
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


class ExternalVaultChange(RuntimeError):
    """The encrypted vault changed after this in-memory session opened it."""


class StaleEntryChange(RuntimeError):
    """An entry changed after an editor took its snapshot."""


def _file_revision(path: Path) -> bytes | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.digest()
    except FileNotFoundError:
        return None


@contextmanager
def _vault_write_lock(path: Path, timeout: float = 5.0):
    """Serialize vault writes between the desktop app and native host."""
    lock_path = path.with_suffix(path.suffix + ".write.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    if handle.tell() == 0:
        handle.write(b"\0")
        handle.flush()
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        deadline = time.monotonic() + timeout
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    handle.close()
                    raise TimeoutError("保险库正在被其他进程写入")
                time.sleep(0.05)
        try:
            yield
        finally:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            handle.close()
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def vault_dir() -> Path:
    base = Path(os.environ.get("APPDATA", Path.home())) / "vault"
    base.mkdir(parents=True, exist_ok=True)
    return base


def default_vault_path() -> Path:
    return vault_dir() / "vault.pmv"


def _make_entry_meta(entry: Entry) -> dict:
    """从 Entry 提取用于索引的元信息字段。"""
    return {
        "id": entry.id,
        "title": entry.title,
        "username": entry.username,
        "url": entry.url,
        "target_app": entry.target_app,
        "secret_type": entry.secret_type,
        "tags": entry.tags,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "deleted_at": entry.deleted_at,
        "display_secret": entry.display_secret,
        "leak_check_revision": entry.leak_check_revision,
        "leak_pwned_count": entry.leak_pwned_count,
        "leak_common_weak": entry.leak_common_weak,
        "leak_checked_at": entry.leak_checked_at,
    }


def _make_entry_payload(entry: Entry) -> dict:
    """敏感字段——password / notes / fields 独立加密。"""
    return {
        "password": entry.password,
        "notes": entry.notes,
        "fields": entry.fields,
    }


def _replace_with_retry(src: Path, dst: Path) -> None:
    """Replace a vault file, tolerating brief Windows file locks from AV/indexers."""
    delays = (0.02, 0.05, 0.1, 0.2)
    for delay in delays:
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            time.sleep(delay)
    os.replace(src, dst)


# ── Vault ────────────────────────────────────────────────────────


@dataclass
class SameServiceGroup:
    """按域名/包名分组的同服务条目组。"""
    service_key: str
    entries: list


@dataclass(frozen=True, slots=True)
class PmvEIdentity:
    vault_id: uuid.UUID
    signing_public_key: bytes
    key_revision: int
    header_revision: int
    sequence: int
    commit_id: uuid.UUID | None
    parent_commit_id: uuid.UUID | None
    root_digest: bytes | None
    authenticated_ancestor_commit_ids: frozenset[uuid.UUID] = frozenset()


class VaultLineage(str, Enum):
    SAME = "SAME"
    FAST_FORWARD = "FAST_FORWARD"
    REMOTE_STALE = "REMOTE_STALE"
    DIVERGED = "DIVERGED"
    DIFFERENT = "DIFFERENT"
    INVALID = "INVALID"


def _read_logical_key_revision(metadata: Mapping[str, object]) -> int:
    """Match Android's PMVE payload rule: sync field first, then top-level fallback."""
    sync_meta = metadata["sync_meta"]
    if not isinstance(sync_meta, Mapping):
        raise ValueError("sync_meta must be a JSON object")
    value = sync_meta["key_revision"] if "key_revision" in sync_meta else metadata["key_revision"]
    if type(value) is not int or not 0 <= value <= (1 << 31) - 1:
        raise ValueError("key_revision must be a non-negative 32-bit integer")
    return value


def remote_key_version_newer(
    local_rev: int,
    local_time: float,
    remote_rev: int,
    remote_time: float,
) -> bool:
    """密钥/密码版本自动收敛决策：返回 True 表示远端版本更新、应采用远端。

    优先按“密钥更新时间”（key_updated_at）比较；时间缺失/相等时退回 key_revision
    计数；仍相等则保留本端（确定性行为，不弹人工选择）。
    """
    if local_time > 0.0 and remote_time > 0.0 and local_time != remote_time:
        return remote_time > local_time
    if local_time <= 0.0 and remote_time > 0.0:
        return True
    if remote_time <= 0.0 and local_time > 0.0:
        return False
    if remote_rev != local_rev:
        return remote_rev > local_rev
    return False


def pmve_key_convergence_kind(vault: "Vault", remote_path: Path) -> str:
    """PMVE 同步前后密钥/主密码自动收敛检测。

    返回 "NONE"（两端密钥版本一致，无需提示）、"KEY_ONLY"（仅恢复密钥等密钥槽
    更新，弹红色提示即可）或 "PASSWORD"（主密码槽更新，确认后必须锁定并用新
    密码重新解锁）。判断依据：sync_meta 的密钥版本/更新时间是否一致，以及两端
    密码槽是否变化。
    """
    local_rev, local_time = vault.read_sync_key_meta(vault.path)
    remote_rev, remote_time = vault.read_sync_key_meta(Path(remote_path))
    if local_rev == remote_rev and local_time == remote_time:
        return "NONE"
    from .pmv_vault_header import decode_header

    def password_envelope(path: Path) -> bytes:
        store = PmvVaultStore.open_root_key(path, vault.root_key_for_device_unlock())
        try:
            return decode_header(store.copy_header_raw()).password_envelope
        finally:
            store.close()

    local_env = password_envelope(vault.path)
    remote_env = password_envelope(Path(remote_path))
    if local_env != remote_env:
        return "PASSWORD"
    return "KEY_ONLY"


class Vault:
    def __init__(self, path: Path, password: str | bytearray | crypto.SecureString):
        self.path = Path(path)
        if isinstance(password, crypto.SecureString):
            self._password = password.clone()
        elif type(password) is bytearray:
            self._password = crypto.SecureString.from_utf8(password)
        else:
            password_utf8 = bytearray(password.encode("utf-8"))
            try:
                self._password = crypto.SecureString.from_utf8(password_utf8)
            finally:
                password_utf8[:] = b"\x00" * len(password_utf8)
        # 索引元信息 — 常驻内存，包含列表／搜索所需字段
        self._entry_meta: dict[str, dict] = {}
        self._trash_meta: dict[str, dict] = {}
        self._entry_order: list[str] = []
        self._trash_order: list[str] = []
        # PMVE payloads are materialized only for entries read or edited in this session.
        self._payloads: dict[str, dict] = {}
        # 已实例化的 Entry 对象缓存：search/entries 每次调用都会重建全部对象并深拷贝，
        # 在条目数较大时（分类切换等高频路径）成为主要开销。元信息与载荷已常驻内存，
        # 故缓存对象本身；任何写操作都经由 save()，在 save() 中统一失效。
        self._entry_cache: dict[str, tuple[dict, dict, "Entry"]] = {}
        self._purge_tombstones: dict[str, float] = {}
        self.device_id: str = ""
        self.key_revision: int = 0
        # 主密码/恢复密钥最近一次变更时刻（UTC 秒）。分叉同步时据此自动收敛：
        # 只保留更新时间最新的密钥/密码版本，旧端自动替换。
        self.key_updated_at: float = 0.0
        self.export_epoch: float = 0.0
        self._disk_revision: bytes | None = None
        self._vault_id = ""
        self._pmve_store: PmvVaultStore | None = None
        self._pmve_metadata: dict[str, object] = {}
        self._pmve_sequence: int = 0
        self._device_unlock_key_format = "pmve-root-key"

    # ── 兼容属性 ────────────────────────────────────────────────

    @property
    def entries(self) -> list[Entry]:
        if self._pmve_store is not None:
            missing = [eid for eid in self._entry_order if eid not in self._payloads]
            if missing:
                loaded = self._pmve_store.read_entries(uuid.UUID(eid) for eid in missing)
                for eid in missing:
                    decoded = loaded.get(uuid.UUID(eid))
                    if decoded is None:
                        raise crypto.DecryptError("PMVE 索引引用了不存在的条目")
                    self._entry_meta[eid] = _make_entry_meta(decoded)
                    self._payloads[eid] = _make_entry_payload(decoded)
        return [self._lazy(eid) for eid in self._entry_order]

    @entries.setter
    def entries(self, val: list) -> None:
        self._entry_order = [e.id for e in val]
        for e in val:
            self._entry_meta[e.id] = _make_entry_meta(e)
            self._set_payload(e)

    @property
    def trash(self) -> list[Entry]:
        return [self._lazy(eid) for eid in self._trash_order]

    @trash.setter
    def trash(self, val: list) -> None:
        self._trash_order = [e.id for e in val]
        for e in val:
            self._trash_meta[e.id] = _make_entry_meta(e)
            self._set_payload(e)

    def _lazy(self, eid: str) -> Entry:
        eid = str(eid)
        payload = self._payloads.get(eid)
        if payload is None and self._pmve_store is not None:
            try:
                decoded = self._pmve_store.read_entry(uuid.UUID(eid))
            except (TypeError, ValueError):
                decoded = None
            if decoded is None:
                raise crypto.DecryptError("PMVE 索引引用了不存在的条目")
            target = self._trash_meta if eid in self._trash_order else self._entry_meta
            target[eid] = _make_entry_meta(decoded)
            payload = _make_entry_payload(decoded)
            self._payloads[eid] = payload
            meta = target[eid]
        else:
            meta = self._entry_meta.get(eid) or self._trash_meta.get(eid) or {}
        cached = self._entry_cache.get(eid)
        if cached is not None and cached[0] is payload and cached[1] is meta:
            return cached[2]
        entry = Entry.from_dict(copy.deepcopy({**meta, **(payload or {})}))
        entry.vault = self
        self._entry_cache[eid] = (payload, meta, entry)
        return entry

    def _encrypt_payload(self, entry_id: str, data: dict):
        del entry_id
        return copy.deepcopy(data)

    def _set_payload(self, entry: Entry) -> None:
        if entry.id in self._payloads:
            return
        self._payloads[entry.id] = self._encrypt_payload(entry.id, _make_entry_payload(entry))

    # ── 生命周期 ────────────────────────────────────────────────

    @classmethod
    def create(
        cls,
        path: Path,
        password: str,
        recovery_secret: bytes | None = None,
    ) -> "Vault":
        if recovery_secret is None:
            recovery_secret, _ = recovery_key.generate()
        return cls.create_pmve(path, password, recovery_secret)

    @classmethod
    def create_pmve(cls, path: Path, password: str, recovery_secret: bytes) -> "Vault":
        """Create a new PMVE vault."""

        password_utf8 = bytearray(password.encode("utf-8"))
        try:
            return cls.create_pmve_with_password_buffer(path, password_utf8, recovery_secret)
        finally:
            password_utf8[:] = b"\x00" * len(password_utf8)

    @classmethod
    def create_pmve_with_password_buffer(
        cls,
        path: Path,
        password_utf8: bytearray,
        recovery_secret: bytes,
    ) -> "Vault":
        """Create PMVE from caller-owned mutable UTF-8 bytes."""

        device_id = str(uuid.uuid4())
        metadata = {
            "schema": "pmv-vault-metadata",
            "version": 1,
            "vault_id": str(uuid.UUID(int=0)),
            "entry_order": [],
            "trash_order": [],
            "sync_meta": {"device_id": device_id, "key_revision": 1},
            "key_revision": 1,
            "export_epoch": None,
            "purge_tombstones": {},
        }
        session_password = crypto.SecureString.from_utf8(password_utf8)
        try:
            store = PmvVaultStore.create(path, bytes(password_utf8), bytes(recovery_secret), metadata, ())
            vault = cls._open_pmve_store(Path(path), session_password, store)
            vault.key_updated_at = time.time()
            return vault
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("无法创建 PMVE 保险库") from exc
        finally:
            session_password.clear()

    @staticmethod
    def _backup_path(path: Path) -> Path:
        return path.with_suffix(path.suffix + ".bak")


    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        password_utf8 = bytearray(password.encode("utf-8"))
        try:
            return cls.open_with_password_buffer(path, password_utf8)
        finally:
            password_utf8[:] = b"\x00" * len(password_utf8)

    @classmethod
    def open_with_password_buffer(cls, path: Path, password_utf8: bytearray) -> "Vault":
        path = Path(path)
        _log.info("尝试解锁：%s", path)
        with path.open("rb") as handle:
            magic = handle.read(4)
        if magic != PMVE_MAGIC:
            raise crypto.DecryptError("此保险库格式已不再支持，请使用 PMVE 文件")
        session_password = crypto.SecureString.from_utf8(password_utf8)
        try:
            store = PmvVaultStore.open_password(path, bytes(password_utf8))
            return cls._open_pmve_store(path, session_password, store)
        except (TypeError, ValueError) as exc:
            _log.warning("解锁失败：主密码错误或 PMVE 库文件已损坏")
            raise crypto.DecryptError("主密码错误或 PMVE 库文件已损坏") from exc
        finally:
            session_password.clear()



    @classmethod
    def open_with_recovery_key(cls, path: Path, recovery_secret: bytes) -> "Vault":
        path = Path(path)
        with path.open("rb") as handle:
            magic = handle.read(4)
        if magic != PMVE_MAGIC:
            raise crypto.DecryptError("此保险库格式已不再支持，请使用 PMVE 文件")
        try:
            store = PmvVaultStore.open_recovery(path, bytes(recovery_secret))
            return cls._open_pmve_store(path, "", store)
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("恢复密钥错误或 PMVE 库文件已损坏") from exc

    @classmethod
    def open_with_root_key(cls, path: Path, root_key: bytes) -> "Vault":
        """Open PMVE using a RootKey recovered from an OS-protected envelope."""

        path = Path(path)
        with path.open("rb") as handle:
            if handle.read(4) != PMVE_MAGIC:
                raise crypto.DecryptError("RootKey 解锁仅适用于 PMVE 保险库")
        try:
            store = PmvVaultStore.open_root_key(path, bytes(root_key))
            return cls._open_pmve_store(path, "", store)
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("Windows Hello RootKey 已失效或 PMVE 库文件已损坏") from exc

    def root_key_for_device_unlock(self) -> bytes:
        if self._pmve_store is None:
            raise ValueError("PMVE RootKey 会话不可用")
        return self._pmve_store.copy_root_key()

    @property
    def kdf_parameters(self):
        if self._pmve_store is None:
            raise ValueError("PMVE KDF 会话不可用")
        return self._pmve_store.kdf_parameters

    def rewrap_kdf_profile(self, target_profile) -> None:
        """Rewrap the password slot without retaining a plaintext password copy."""
        from .pmv_kdf_policy import PmvKdfProfile

        if self._pmve_store is None or self._password.is_empty():
            raise crypto.DecryptError("KDF 升级需要由主密码解锁的 PMVE 会话")
        if not isinstance(target_profile, PmvKdfProfile):
            raise TypeError("target_profile must be PmvKdfProfile")
        with self._password.bytes() as password_utf8:
            self._pmve_store.rewrap_password_profile(bytes(password_utf8), target_profile)

    @staticmethod
    def _coerce_media_ref(value):
        from .pmv_media_ref import MediaRef, from_external_string, from_json

        if isinstance(value, MediaRef):
            return value
        if isinstance(value, str):
            return from_external_string(value)
        return from_json(value)

    def open_media_object(self, ref, output) -> None:
        """Stream one authenticated PMVE object without exposing the private Store."""

        if self._pmve_store is None:
            raise ValueError("只有 PMVE 保险库支持 ObjectStore 媒体读取")
        canonical = self._coerce_media_ref(ref)
        self._pmve_store.open_object(
            canonical.object_id, canonical.generation, output
        )

    def open_media_range(self, ref, offset: int, length: int, output) -> None:
        """Stream one verified byte range from a canonical PMVE media reference."""

        if self._pmve_store is None:
            raise ValueError("只有 PMVE 保险库支持 ObjectStore 媒体范围读取")
        canonical = self._coerce_media_ref(ref)
        self._pmve_store.open_object_range(
            canonical.object_id, canonical.generation, offset, length, output
        )

    def atomic_import_media_mutation(
        self,
        transform_plan,
        *,
        expected_sequence: int,
        metadata=None,
        target_entry: Entry | None = None,
        expected_entry_revision: int | None = None,
        expected_entry_updated_at: float | None = None,
    ):
        """Import plan streams and publish its target Entry/metadata in one PMVE commit."""

        from .pmv_media_ref import TransformPlan, from_store_ref
        from .pmv_vault_store import MutationContent

        if self._pmve_store is None:
            raise ValueError("只有 PMVE 保险库支持原子媒体导入")
        if not isinstance(transform_plan, TransformPlan):
            raise TypeError("transform_plan 必须是 PMVE TransformPlan")
        if type(expected_sequence) is not int or expected_sequence != self._pmve_sequence:
            raise ExternalVaultChange("PMVE 媒体导入基线已过期，请刷新后重试")
        final_target = target_entry or transform_plan.original
        if not isinstance(final_target, Entry) or final_target.id != transform_plan.original.id:
            raise ValueError("媒体导入 target_entry 必须与 TransformPlan 使用同一 Entry ID")
        effective_plan = TransformPlan(
            final_target,
            transform_plan.object_imports,
            transform_plan.paths,
            transform_plan.path_import_indexes,
        )
        target_id = final_target.id
        existing_ids = self._entry_order + self._trash_order
        current_entries = {
            entry_id: Entry.from_dict(self._lazy(entry_id).to_dict())
            for entry_id in existing_ids
        }
        if target_id in current_entries:
            if expected_entry_revision is None and expected_entry_updated_at is None:
                raise ExternalVaultChange(
                    "更新已有媒体 Entry 必须提供 expected revision/updated_at"
                )
            if expected_entry_revision is not None:
                revisions = {
                    str(summary.entry_id): summary.revision
                    for summary in self._pmve_store.list()
                }
                if revisions.get(target_id) != expected_entry_revision:
                    raise ExternalVaultChange("媒体 Entry revision 已变化，请刷新后重试")
            if (
                expected_entry_updated_at is not None
                and float(current_entries[target_id].updated_at)
                != float(expected_entry_updated_at)
            ):
                raise ExternalVaultChange("媒体 Entry 已被更新，请刷新后重试")
        else:
            if expected_entry_revision is not None or expected_entry_updated_at is not None:
                raise ValueError("新建媒体 Entry 不应提供 expected revision/updated_at")
            if target_id in self._purge_tombstones:
                raise ValueError("新建媒体 Entry ID 与 purge tombstone 碰撞")
        entry_order = [entry_id for entry_id in self._entry_order if entry_id != target_id]
        trash_order = [entry_id for entry_id in self._trash_order if entry_id != target_id]
        destination_order = trash_order if final_target.deleted_at is not None else entry_order
        original_order = self._trash_order if target_id in self._trash_order else self._entry_order
        if target_id in original_order:
            insertion = min(original_order.index(target_id), len(destination_order))
            destination_order.insert(insertion, target_id)
        else:
            destination_order.append(target_id)
        ordered_ids = entry_order + trash_order
        metadata_seed = copy.deepcopy(
            self._pmve_metadata if metadata is None else metadata
        )
        if metadata is not None:
            from .autofill_exclusions import FIELD, merge as merge_exclusions
            if FIELD in self._pmve_metadata or FIELD in metadata_seed:
                metadata_seed[FIELD] = merge_exclusions(self._pmve_metadata.get(FIELD), metadata_seed.get(FIELD))
        metadata_seed["entry_order"] = list(entry_order)
        metadata_seed["trash_order"] = list(trash_order)

        def prepare(object_refs):
            transformed = effective_plan.transform(object_refs)
            if transformed.id != target_id:
                raise ValueError("媒体导入不得更改 Entry ID")
            current = current_entries.get(target_id)
            if current is not None:
                from . import leak

                old_secret = leak.entry_secret(current)
                new_secret = leak.entry_secret(transformed)
                old_cache_current = leak.has_current_check(current)
                content_changed = (
                    not transformed.content_equals(current)
                    or transformed.deleted_at != current.deleted_at
                )
                transformed.created_at = current.created_at
                transformed.updated_at = current.updated_at
                if content_changed:
                    transformed.touch()
                    if old_secret and old_secret == new_secret and old_cache_current:
                        transformed.leak_check_revision = transformed.updated_at
                        transformed.leak_pwned_count = current.leak_pwned_count
                        transformed.leak_common_weak = current.leak_common_weak
                        transformed.leak_checked_at = current.leak_checked_at
                    elif old_secret != new_secret:
                        transformed.leak_check_revision = None
                        transformed.leak_pwned_count = None
                        transformed.leak_common_weak = False
                        transformed.leak_checked_at = None
                else:
                    transformed.leak_check_revision = current.leak_check_revision
                    transformed.leak_pwned_count = current.leak_pwned_count
                    transformed.leak_common_weak = current.leak_common_weak
                    transformed.leak_checked_at = current.leak_checked_at
            final_entries = tuple(
                transformed if entry_id == target_id else current_entries[entry_id]
                for entry_id in ordered_ids
            )
            return MutationContent(metadata_seed, final_entries)

        try:
            result = self._pmve_store.apply_mutation(
                expected_sequence=expected_sequence,
                object_imports=transform_plan.object_imports,
                prepare=prepare,
            )
        except ValueError as exc:
            if "stale" in str(exc).lower():
                raise ExternalVaultChange(
                    "PMVE 媒体导入期间保险库已被其他进程修改"
                ) from exc
            raise
        committed = self._pmve_store.read_entry(uuid.UUID(target_id))
        if committed is None:
            raise crypto.DecryptError("PMVE 媒体提交后目标 Entry 不存在")
        self._entry_order = entry_order
        self._trash_order = trash_order
        self._entry_meta.pop(target_id, None)
        self._trash_meta.pop(target_id, None)
        target_metadata = self._trash_meta if target_id in trash_order else self._entry_meta
        target_metadata[target_id] = _make_entry_meta(committed)
        self._payloads[target_id] = _make_entry_payload(committed)
        self._pmve_metadata = self._pmve_store.metadata()
        self._pmve_sequence = result.identity.sequence
        self._disk_revision = result.identity.root_digest
        return tuple(from_store_ref(value) for value in result.object_refs)

    def import_media_mutation(
        self,
        transform_plan,
        *,
        expected_sequence: int,
        metadata=None,
        target_entry: Entry | None = None,
        expected_entry_revision: int | None = None,
        expected_entry_updated_at: float | None = None,
    ):
        """Public alias for the atomic PMVE media mutation facade."""

        return self.atomic_import_media_mutation(
            transform_plan,
            expected_sequence=expected_sequence,
            metadata=metadata,
            target_entry=target_entry,
            expected_entry_revision=expected_entry_revision,
            expected_entry_updated_at=expected_entry_updated_at,
        )

    @property
    def pmve_identity(self) -> PmvEIdentity:
        if self._pmve_store is None:
            raise ValueError("只有 PMVE 保险库具有 PMVE Identity")
        identity = self._pmve_store.identity
        return PmvEIdentity(
            identity.vault_id,
            identity.signing_public_key,
            identity.key_revision,
            identity.header_revision,
            identity.sequence,
            identity.commit_id,
            identity.parent_commit_id,
            identity.root_digest,
            self._pmve_store.authenticated_ancestor_commit_ids(),
        )

    def authenticate_external_file(self, path: Path) -> PmvEIdentity:
        """Fully authenticate an external PMVE Header, Commit and PMVR using this RootKey."""

        if self._pmve_store is None:
            raise crypto.DecryptError("PMVE 外部文件认证需要已解锁的 PMVE 会话")
        external = Path(path)
        try:
            if external.stat().st_size > MAX_SYNC_BYTES:
                raise crypto.DecryptError("外部 PMVE 文件超过 10 GB 安全限制")
        except OSError as exc:
            raise crypto.DecryptError("无法读取外部 PMVE 文件") from exc
        candidate: PmvVaultStore | None = None
        try:
            candidate = PmvVaultStore.open_root_key(
                external, self.root_key_for_device_unlock()
            )
            identity = candidate.identity
            # Force authentication of PMVR children used by production reads.
            candidate.metadata()
            candidate.list()
            return PmvEIdentity(
                identity.vault_id,
                identity.signing_public_key,
                identity.key_revision,
                identity.header_revision,
                identity.sequence,
                identity.commit_id,
                identity.parent_commit_id,
                identity.root_digest,
                candidate.authenticated_ancestor_commit_ids(),
            )
        except (OSError, TypeError, ValueError) as exc:
            raise crypto.DecryptError("外部 PMVE Header/Commit/PMVR 认证失败") from exc
        finally:
            if candidate is not None:
                candidate.close()

    @staticmethod
    def classify_lineage(
        local: PmvEIdentity | None,
        remote: PmvEIdentity | None,
    ) -> VaultLineage:
        if not isinstance(local, PmvEIdentity) or not isinstance(remote, PmvEIdentity):
            return VaultLineage.INVALID

        def valid(identity: PmvEIdentity) -> bool:
            return (
                isinstance(identity.vault_id, uuid.UUID)
                and type(identity.signing_public_key) is bytes
                and len(identity.signing_public_key) == 32
                and type(identity.key_revision) is int
                and identity.key_revision >= 1
                and type(identity.header_revision) is int
                and identity.header_revision >= 1
                and type(identity.sequence) is int
                and identity.sequence >= 1
                and isinstance(identity.commit_id, uuid.UUID)
                and (
                    identity.parent_commit_id is None
                    or isinstance(identity.parent_commit_id, uuid.UUID)
                )
                and type(identity.root_digest) is bytes
                and len(identity.root_digest) == 32
                and isinstance(identity.authenticated_ancestor_commit_ids, frozenset)
                and all(
                    isinstance(commit_id, uuid.UUID)
                    for commit_id in identity.authenticated_ancestor_commit_ids
                )
            )

        if not valid(local) or not valid(remote):
            return VaultLineage.INVALID
        if (
            local.vault_id != remote.vault_id
            or local.signing_public_key != remote.signing_public_key
        ):
            return VaultLineage.DIFFERENT
        if (
            local.sequence == remote.sequence
            and local.commit_id == remote.commit_id
            and local.root_digest == remote.root_digest
        ):
            return VaultLineage.SAME
        if (
            local.commit_id in remote.authenticated_ancestor_commit_ids
            or remote.parent_commit_id == local.commit_id
        ):
            return VaultLineage.FAST_FORWARD
        if (
            remote.commit_id in local.authenticated_ancestor_commit_ids
            or local.parent_commit_id == remote.commit_id
        ):
            return VaultLineage.REMOTE_STALE
        return VaultLineage.DIVERGED

    def replace_authenticated_file(self, candidate_path: Path, *, force: bool = False) -> PmvEIdentity:
        """Atomically adopt one fully authenticated PMVE file.

        ``force=True`` 用于用户显式“下载覆盖”：仍要求远端与本地为同一保险库且签名
        可认证，但跳过谱系快速前进约束（覆盖可能丢弃本地较新的提交，调用方负责确认）。
        """

        if self._pmve_store is None:
            raise crypto.DecryptError("仅 PMVE 支持认证整库替换")
        candidate_path = Path(candidate_path)
        remote_identity = self.authenticate_external_file(candidate_path)
        local_identity = self.pmve_identity
        lineage = self.classify_lineage(local_identity, remote_identity)
        if lineage is VaultLineage.SAME:
            return local_identity
        if not force and lineage is not VaultLineage.FAST_FORWARD:
            raise ExternalVaultChange(f"PMVE 谱系不允许整库替换：{lineage.value}")

        root_key = bytearray(self.root_key_for_device_unlock())
        stage = self.path.with_suffix(self.path.suffix + ".sync-replace.tmp")
        rollback = self.path.with_suffix(self.path.suffix + ".sync-rollback.tmp")
        backup = self.path.with_suffix(self.path.suffix + ".sync.bak")
        replaced = False

        def copy_durable(source: Path, target: Path) -> None:
            with source.open("rb") as input_handle, target.open("wb") as output_handle:
                shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
                output_handle.flush()
                os.fsync(output_handle.fileno())

        try:
            copy_durable(candidate_path, stage)
            if self.authenticate_external_file(stage) != remote_identity:
                raise crypto.DecryptError("PMVE 替换暂存文件复验不一致")
            with _vault_write_lock(self.path):
                if self.pmve_identity != local_identity:
                    raise ExternalVaultChange("本地 PMVE 在替换前发生并发修改")
                copy_durable(self.path, backup)
                self._pmve_store.close()
                self._pmve_store = None
                _replace_with_retry(stage, self.path)
                replaced = True
                _fsync_parent_directory(self.path)
                reopened = Vault.open_with_root_key(self.path, bytes(root_key))
                if reopened.pmve_identity != remote_identity:
                    reopened.close()
                    raise crypto.DecryptError("PMVE 替换后身份复验失败")
                self._password.clear()
                self.__dict__.clear()
                self.__dict__.update(reopened.__dict__)
            return self.pmve_identity
        except Exception:
            if replaced and backup.exists():
                copy_durable(backup, rollback)
                _replace_with_retry(rollback, self.path)
                _fsync_parent_directory(self.path)
                restored = Vault.open_with_root_key(self.path, bytes(root_key))
                self.__dict__.clear()
                self.__dict__.update(restored.__dict__)
            elif self._pmve_store is None:
                restored = Vault.open_with_root_key(self.path, bytes(root_key))
                self.__dict__.clear()
                self.__dict__.update(restored.__dict__)
            raise
        finally:
            root_key[:] = bytes(len(root_key))
            stage.unlink(missing_ok=True)
            rollback.unlink(missing_ok=True)

    def merge_and_adopt_authenticated_file(
        self,
        candidate_path: Path,
        *,
        adopt_local: bool = True,
    ) -> PmvEIdentity:
        """PMVE 分叉合并采纳：以远端 Head 为基线提交合并内容（条目 LWW + 注册表 union），
        原子安装为本地库；随后推送同一文件即可让远端快速前进。"""
        if self._pmve_store is None:
            raise crypto.DecryptError("仅 PMVE 支持分叉合并")
        from . import pmv_device_registry
        from .sync import ConflictChoice, merge_with_purges

        candidate_path = Path(candidate_path)
        local_identity = self.pmve_identity
        root_key = self.root_key_for_device_unlock()
        remote_store = PmvVaultStore.open_root_key(candidate_path, root_key)
        try:
            remote_identity = self.authenticate_external_file(candidate_path)
            if remote_identity.vault_id != local_identity.vault_id:
                raise ExternalVaultChange("远端不是同一份 PMVE 保险库")
            if self.classify_lineage(local_identity, remote_identity) is not VaultLineage.DIVERGED:
                raise ExternalVaultChange("仅 DIVERGED 关系允许合并采纳")

            def load_payload(store) -> tuple[list[Entry], dict]:
                metadata = store.metadata()
                entries: list[Entry] = []
                for summary in store.list():
                    entry = store.read_entry(summary.entry_id)
                    if entry is not None:
                        entries.append(entry)
                return entries, metadata

            local_entries, local_metadata = load_payload(self._pmve_store)
            remote_entries, remote_metadata = load_payload(remote_store)
            merged_entries, _stats, merged_purges = merge_with_purges(
                local_entries,
                remote_entries,
                local_metadata.get("purge_tombstones", {}),
                remote_metadata.get("purge_tombstones", {}),
                on_conflict=lambda _local, _remote: ConflictChoice.KEEP_BOTH,
            )

            def registry_of(metadata: dict):
                return pmv_device_registry.decode(metadata)

            def union(first, second):
                by_device: dict = {}
                for record in list(first) + list(second):
                    current = by_device.get(record.device_id)
                    if current is None or record.epoch > current.epoch:
                        by_device[record.device_id] = record
                return sorted(
                    by_device.values(),
                    key=lambda record: (str(record.device_id), record.epoch),
                )

            def key_meta(metadata: dict) -> tuple[int, float]:
                sync_meta = metadata.get("sync_meta", {})
                return (
                    _read_logical_key_revision(metadata),
                    float(sync_meta.get("key_updated_at", 0.0) or 0.0),
                )

            # 自动收敛：按密钥更新时间/版本选择最新端，写入合并文件，旧端随后被替换。
            local_rev, local_time = key_meta(local_metadata)
            remote_rev, remote_time = key_meta(remote_metadata)
            adopt_remote = remote_key_version_newer(
                local_rev, local_time, remote_rev, remote_time
            )
            merged_metadata = copy.deepcopy(remote_metadata)
            from .device_activity import FIELD as ACTIVITY_FIELD, merge as merge_activity, stamp, current_device_id
            merged_metadata[ACTIVITY_FIELD] = merge_activity(local_metadata.get(ACTIVITY_FIELD), remote_metadata.get(ACTIVITY_FIELD))
            merged_metadata = stamp(merged_metadata, current_device_id(self))
            if merged_metadata[ACTIVITY_FIELD].get("version", 1) == 1:
                merged_metadata[ACTIVITY_FIELD]["last_writer"]["parent_commit_id"] = str(remote_store.identity.commit_id)
            from .autofill_exclusions import FIELD, merge as merge_exclusions
            if FIELD in local_metadata or FIELD in remote_metadata:
                merged_metadata[FIELD] = merge_exclusions(local_metadata.get(FIELD), remote_metadata.get(FIELD))
            sync_meta = merged_metadata.get("sync_meta")
            if not isinstance(sync_meta, dict):
                sync_meta = {}
            sync_meta["key_revision"] = remote_rev if adopt_remote else local_rev
            chosen_time = remote_time if adopt_remote else local_time
            if chosen_time:
                sync_meta["key_updated_at"] = float(chosen_time)
            merged_metadata["sync_meta"] = sync_meta
            merged_metadata["purge_tombstones"] = merged_purges
            merged_metadata.pop("passkey_keyset", None)
            merged_registry = union(registry_of(local_metadata), registry_of(remote_metadata))
            merged_metadata = pmv_device_registry.with_registry(
                merged_metadata,
                pmv_device_registry.verify_all(merged_registry, remote_identity.signing_public_key),
            )
            remote_store.save_merged(
                self._pmve_store,
                expected_sequence=remote_identity.sequence,
                metadata=merged_metadata,
                entries=merged_entries,
            )
            if not adopt_remote:
                # 采用本端（更新）密钥版本：合并文件头部必须替换为本端密码/恢复密钥槽，
                # 否则合并后本端新主密码会失效、退回旧密码。
                remote_store.adopt_header(self._pmve_store.copy_header_raw())
        finally:
            remote_store.close()
        merged_identity = self.authenticate_external_file(candidate_path)

        # 云同步先把合并结果发布并回读认证，确认远端提交后才安装本地。
        # 这样 CAS 竞争或“提交结果未知”不会提前撕裂当前本地会话。
        if not adopt_local:
            return merged_identity

        stage = self.path.with_suffix(self.path.suffix + ".merge.tmp")
        rollback = self.path.with_suffix(self.path.suffix + ".merge-rollback.tmp")
        backup = self.path.with_suffix(self.path.suffix + ".merge.bak")
        replaced = False

        def copy_durable(source: Path, target: Path) -> None:
            with source.open("rb") as input_handle, target.open("wb") as output_handle:
                shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
                output_handle.flush()
                os.fsync(output_handle.fileno())

        try:
            copy_durable(candidate_path, stage)
            if self.authenticate_external_file(stage) != merged_identity:
                raise crypto.DecryptError("PMVE 合并暂存文件复验不一致")
            with _vault_write_lock(self.path):
                if self.pmve_identity != local_identity:
                    raise ExternalVaultChange("本地 PMVE 在合并前发生并发修改")
                copy_durable(self.path, backup)
                self._pmve_store.close()
                self._pmve_store = None
                _replace_with_retry(stage, self.path)
                replaced = True
                _fsync_parent_directory(self.path)
                reopened = Vault.open_with_root_key(self.path, root_key)
                if reopened.pmve_identity != merged_identity:
                    reopened.close()
                    raise crypto.DecryptError("PMVE 合并后身份复验失败")
                self._password.clear()
                self.__dict__.clear()
                self.__dict__.update(reopened.__dict__)
            return self.pmve_identity
        except Exception:
            if replaced and backup.exists():
                copy_durable(backup, rollback)
                _replace_with_retry(rollback, self.path)
                _fsync_parent_directory(self.path)
                restored = Vault.open_with_root_key(self.path, root_key)
                self.__dict__.clear()
                self.__dict__.update(restored.__dict__)
            elif self._pmve_store is None:
                restored = Vault.open_with_root_key(self.path, root_key)
                self.__dict__.clear()
                self.__dict__.update(restored.__dict__)
            raise
        finally:
            stage.unlink(missing_ok=True)
            rollback.unlink(missing_ok=True)

    @property
    def device_unlock_key_format(self) -> str:
        """Identify the OS-protected PMVE RootKey payload."""

        return self._device_unlock_key_format

    @property
    def metadata(self) -> dict:
        """Copy of authenticated vault metadata; available after unlock only."""
        if self._pmve_store is None:
            raise crypto.DecryptError("PMVE Store 会话不可用")
        return copy.deepcopy(self._pmve_store.metadata())

    @property
    def vault_identity(self):
        """PMVE 库的签名身份（vault_id + signing key）。"""
        if self._pmve_store is not None:
            return self._pmve_store.identity
        return None

    @classmethod
    def _open_pmve_store(
        cls,
        path: Path,
        password: str | bytearray | crypto.SecureString,
        store: PmvVaultStore,
    ) -> "Vault":
        """Adapt one authenticated PMVE Store snapshot to the application facade."""

        try:
            identity = store.identity
            metadata = store.metadata()
            summaries = store.list()
            entry_order = [str(value) for value in metadata.get("entry_order", [])]
            trash_order = [str(value) for value in metadata.get("trash_order", [])]
            summary_ids = {str(summary.entry_id) for summary in summaries}
            if set(entry_order + trash_order) != summary_ids:
                raise ValueError("PMVE 元数据顺序与条目集合不一致")

            vault = cls(path, password)
            vault._device_unlock_key_format = "pmve-root-key"
            vault._vault_id = str(identity.vault_id)
            vault._pmve_store = store
            vault._pmve_metadata = copy.deepcopy(metadata)
            vault._pmve_sequence = identity.sequence
            vault._entry_order = entry_order
            vault._trash_order = trash_order
            trash_ids = set(trash_order)
            for summary in summaries:
                entry_id = str(summary.entry_id)
                target = vault._trash_meta if entry_id in set(trash_order) else vault._entry_meta
                target[entry_id] = {
                    "id": entry_id,
                    "title": summary.display_title,
                    "secret_type": summary.entry_type,
                    "updated_at": summary.modified_at_epoch_millis / 1000.0,
                    "deleted_at": 0.0 if entry_id in trash_ids else None,
                }
            sync_meta = metadata.get("sync_meta", {})
            vault.device_id = str(sync_meta.get("device_id") or "") if isinstance(sync_meta, dict) else ""
            # 逻辑密钥版本以 sync_meta.key_revision 为准（主密码/恢复密钥每次变更 +1），
            # 回退顶层 key_revision；头部 identity.key_revision 是固定格式代次，不能用于显示。
            # 与 Android 的空值合并语义一致：sync_meta 显式写 0 时保留 0，不做 or 回退。
            vault.key_revision = _read_logical_key_revision(metadata)
            vault.key_updated_at = float(
                sync_meta.get("key_updated_at", 0.0) if isinstance(sync_meta, dict) else 0.0
            ) if isinstance(sync_meta, dict) else 0.0
            try:
                vault.export_epoch = float(metadata.get("export_epoch") or 0.0)
            except (TypeError, ValueError):
                vault.export_epoch = 0.0
            vault._purge_tombstones = {
                str(key): float(value)
                for key, value in (metadata.get("purge_tombstones", {}) or {}).items()
            }
            vault._disk_revision = identity.root_digest
            return vault
        except Exception:
            store.close()
            raise

    def query_login_domain(self, domain: str) -> tuple[str, ...]:
        """Query the authoritative PMVE LoginFastIndex."""
        if self._pmve_store is None:
            raise crypto.DecryptError("PMVE Store 会话不可用")
        try:
            return tuple(str(value) for value in self._pmve_store.query_domain(domain))
        except ValueError:
            # LoginFastIndex is the sole autofill candidate source. Unsupported
            # lookup values, including IP literals, must not trigger a full-vault scan.
            return ()

    def query_login_package(self, package_name: str) -> tuple[str, ...]:
        """Query application candidates through the authoritative PMVE LoginFastIndex."""
        if self._pmve_store is None:
            raise crypto.DecryptError("PMVE Store 会话不可用")
        try:
            return tuple(str(value) for value in self._pmve_store.query_package(package_name))
        except ValueError:
            return ()

    def read_entry(self, entry_id: str) -> Entry | None:
        """Decrypt one PMVE entry without materializing the full vault."""
        if self._pmve_store is not None:
            try:
                return self._pmve_store.read_entry(uuid.UUID(entry_id))
            except (TypeError, ValueError):
                return None
        if entry_id not in self._entry_order and entry_id not in self._trash_order:
            return None
        return self._lazy(entry_id)

    def list_entry_ids(self, secret_type: str | None = None) -> tuple[str, ...]:
        """Enumerate active EntryIndex ids, optionally filtered by entry type.

        This exposes only authenticated summary metadata.  Callers still have to
        opt in to decrypting individual entries through :meth:`read_entry`.
        """
        return tuple(
            entry_id
            for entry_id in self._entry_order
            if secret_type is None or self._entry_meta[entry_id].get("secret_type") == secret_type
        )

    def ensure_device_authorized(self) -> None:
        """PMVE 设备自注册（惰性，同步前调用）：为本机生成/恢复设备身份并确保在授权清单中。"""
        if self._pmve_store is None:
            return
        from . import device_identity, pmv_device_registry, pmv_sync_authorization

        store = self._pmve_store
        identity = store.identity
        vault_id = identity.vault_id
        device_id, seed = device_identity.load_or_create(vault_id)
        public_key = device_identity.device_public_key(seed)
        now = int(time.time() * 1000)
        metadata = store.metadata()
        records = pmv_device_registry.decode(metadata)
        existing = pmv_device_registry.latest(records, device_id)
        if existing is not None and existing.active_at(now):
            return
        signed = store.sign_device_authorization(
            pmv_sync_authorization.DeviceAuthorization(
                vault_id=vault_id,
                device_id=device_id,
                device_public_key=public_key,
                permissions=(
                    pmv_sync_authorization.PERMISSION_READ
                    | pmv_sync_authorization.PERMISSION_WRITE
                    | pmv_sync_authorization.PERMISSION_AUTHORIZE
                ),
                issued_at_epoch_millis=now,
                expires_at_epoch_millis=0,
                revoked_at_epoch_millis=0,
                epoch=(existing.epoch if existing is not None else 0) + 1,
            )
        )
        updated_records = [
            record for record in records if record.device_id != device_id
        ] + [signed]
        updated = pmv_device_registry.with_registry(
            metadata,
            pmv_device_registry.verify_all(updated_records, identity.signing_public_key),
        )
        entries: list[Entry] = []
        for summary in store.list():
            entry = store.read_entry(summary.entry_id)
            if entry is not None:
                entries.append(entry)
        from .device_activity import stamp, FIELD as ACTIVITY_FIELD
        updated = stamp(updated, device_id)
        if updated[ACTIVITY_FIELD].get("version", 1) == 1:
            updated[ACTIVITY_FIELD]["last_writer"]["parent_commit_id"] = str(store.identity.commit_id)
        store.save_full(
            expected_sequence=identity.sequence,
            metadata=updated,
            entries=entries,
        )
        self._pmve_metadata = copy.deepcopy(updated)
        self._pmve_sequence = store.identity.sequence




    @property
    def autofill_exclusions(self) -> dict:
        from .autofill_exclusions import FIELD, normalize
        return normalize(self._pmve_metadata.get(FIELD))

    def replace_autofill_exclusions(self, values: dict) -> None:
        from .autofill_exclusions import FIELD, normalize
        old = copy.deepcopy(self._pmve_metadata)
        self._pmve_metadata[FIELD] = normalize(values)
        try:
            self.save()
        except Exception:
            self._pmve_metadata = old
            raise

    def set_autofill_exclusions(self, category: str, values: list[str]) -> None:
        from .autofill_exclusions import update
        updated = update(self.autofill_exclusions, category, values)
        if updated != self.autofill_exclusions:
            self.replace_autofill_exclusions(updated)

    def save(self, with_lock: bool = True) -> None:
        del with_lock  # PmvVaultStore owns its cross-process write lock.
        # 任何写操作都经过 save()：失效已缓存的 Entry 对象，避免返回陈旧实例。
        self._entry_cache.clear()
        _log.debug("保存 PMVE 库（%d 条）→ %s", len(self._entry_order), self.path)
        if not self.device_id:
            self.device_id = str(uuid.uuid4())
        self.export_epoch = time.time()
        self._save_pmve()


    def _save_pmve(self) -> None:
        store = self._pmve_store
        if store is None:
            raise crypto.DecryptError("PMVE Store 会话不可用")

        from .device_activity import stamp, current_device_id, FIELD as ACTIVITY_FIELD
        metadata = stamp(self._pmve_metadata, current_device_id(self))
        metadata.pop("deletion_baseline", None)
        metadata.pop("_deletion_known_members_v1", None)
        if metadata[ACTIVITY_FIELD].get("version", 1) == 1:
            metadata[ACTIVITY_FIELD]["last_writer"]["parent_commit_id"] = str(store.identity.commit_id)
        metadata.setdefault("schema", "pmv-vault-metadata")
        metadata.setdefault("version", 1)
        metadata["vault_id"] = self._vault_id
        metadata["entry_order"] = [self._canonical_uuid_text(value) for value in self._entry_order]
        metadata["trash_order"] = [self._canonical_uuid_text(value) for value in self._trash_order]
        sync_meta = metadata.get("sync_meta")
        if not isinstance(sync_meta, dict):
            sync_meta = {}
        sync_meta["device_id"] = self._canonical_uuid_text(self.device_id)
        sync_meta["key_revision"] = int(self.key_revision or 0)
        if self.key_updated_at:
            sync_meta["key_updated_at"] = float(self.key_updated_at)
        metadata["sync_meta"] = sync_meta
        metadata["key_revision"] = self.key_revision
        metadata["export_epoch"] = self.export_epoch
        metadata["purge_tombstones"] = {
            self._canonical_uuid_text(key): float(value)
            for key, value in self._purge_tombstones.items()
        }

        entries: list[Entry] = []
        for entry_id in self._entry_order + self._trash_order:
            entry = self._lazy(entry_id)
            entry.id = self._canonical_uuid_text(entry.id)
            entries.append(entry)
        try:
            identity = store.save_full(
                expected_sequence=self._pmve_sequence,
                metadata=metadata,
                entries=entries,
            )
        except ValueError as exc:
            if "stale" in str(exc).lower():
                raise ExternalVaultChange("保险库已被其他进程修改，请刷新后重试") from exc
            raise
        self._pmve_metadata = store.metadata()
        self._pmve_sequence = identity.sequence
        self._disk_revision = identity.root_digest

    @staticmethod
    def _canonical_uuid_text(value: object) -> str:
        try:
            return str(uuid.UUID(str(value)))
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError("PMVE 条目和设备 ID 必须是 UUID") from exc

    def maybe_auto_compact(self) -> bool:
        """PMVE 自动压缩：提交数与文件增长达到阈值时回收历史 Block 垃圾空间。

        阈值与安卓端 AutoCompactPolicy 保持一致；压缩后签名身份与内容摘要不变。
        返回 True 表示本次执行了压缩。任何失败由调用方捕获，不影响正常使用。
        """
        if self._pmve_store is None:
            return False
        if not self.path.exists():
            return False
        from . import config as _config
        from .pmv_compact import should_auto_compact

        state = _config.compact_state().get(self.path.name, {})
        last_rev = int(state.get("revision", 0) or 0)
        last_size = int(state.get("size", 0) or 0)
        last_at = float(state.get("at", 0) or 0)
        last_import_at = float(state.get("imported_at", 0) or 0)
        size = self.path.stat().st_size
        if not should_auto_compact(
            self._pmve_sequence, last_rev, size, last_size, last_at, last_import_at
        ):
            return False
        identity = self._pmve_store.compact()
        _config.record_compact(self.path.name, identity.sequence, self.path.stat().st_size)
        self._pmve_sequence = identity.sequence
        self._disk_revision = identity.root_digest
        return True

    def compact_now(self) -> tuple[int, int]:
        """Force one authenticated PMVE compaction and return sizes before/after."""
        if self._pmve_store is None or not self.path.exists():
            raise ValueError("当前保险库不支持数据库压缩")
        from . import config as _config

        size_before = self.path.stat().st_size
        identity = self._pmve_store.compact()
        size_after = self.path.stat().st_size
        _config.record_compact(self.path.name, identity.sequence, size_after)
        self._pmve_sequence = identity.sequence
        self._disk_revision = identity.root_digest
        return size_before, size_after

    def compact_before_sync(self) -> bool:
        """云端同步上传前压缩一次：存在实际历史垃圾时回收 Block 垃圾空间。

        与 maybe_auto_compact 不同，不受 24 小时间隔与导入冷却限制——
        云同步上传本身就是低频率操作，上传前压缩可减小云端体积，同时
        压缩后签名身份与内容摘要保持不变。返回 True 表示执行了压缩。
        失败由调用方捕获，不影响同步流程。
        """
        if self._pmve_store is None:
            return False
        if not self.path.exists():
            return False
        from . import config as _config
        from .pmv_compact import should_auto_compact

        state = _config.compact_state().get(self.path.name, {})
        last_rev = int(state.get("revision", 0) or 0)
        last_size = int(state.get("size", 0) or 0)
        size = self.path.stat().st_size
        if not should_auto_compact(self._pmve_sequence, last_rev, size, last_size):
            return False
        identity = self._pmve_store.compact()
        _config.record_compact(self.path.name, identity.sequence, self.path.stat().st_size)
        self._pmve_sequence = identity.sequence
        self._disk_revision = identity.root_digest
        return True

    def compact_after_purge(self) -> bool:
        """清空回收站后立即压缩：不受自动压缩门槛限制，直接回收追加写垃圾空间。

        对齐安卓端 compactAfterTrashPurge——仅在批量清空回收站后调用。逐条彻底删除
        不压缩，避免每次删除都重写整个库文件。返回 True 表示执行了压缩。
        """
        if self._pmve_store is None or not self.path.exists():
            return False
        self.compact_now()
        return True

    def maybe_compact_after_large_media(self) -> bool:
        """媒体提交后机会式压缩：距上次压缩够久且文件增长够大时回收死空间。

        对齐安卓端 compactAfterLargeMediaCommit——使用独立于 ``maybe_auto_compact``
        的阈值（最短间隔 + 最小增长），不看提交数，避免「新增 55MB 后文件显示
        109MB」的追加速写虚胖。返回 True 表示执行了压缩。
        """
        if self._pmve_store is None:
            return False
        if not self.path.exists():
            return False
        from . import config as _config
        from .pmv_compact import MEDIA_COMPACT_MIN_GROWTH, MEDIA_COMPACT_MIN_INTERVAL_SECONDS

        state = _config.compact_state().get(self.path.name, {})
        last_at = float(state.get("at", 0) or 0)
        last_size = int(state.get("size", 0) or 0)
        if time.time() - last_at < MEDIA_COMPACT_MIN_INTERVAL_SECONDS:
            return False
        if self.path.stat().st_size - last_size < MEDIA_COMPACT_MIN_GROWTH:
            return False
        self.compact_now()
        return True

    def reopen(self) -> "Vault":
        """Open a fresh session from disk using the in-memory protected password."""
        if self._password.is_empty():
            reopened = Vault.open_with_root_key(self.path, self.root_key_for_device_unlock())
        else:
            with self._password.bytes() as password_utf8:
                store = PmvVaultStore.open_password(self.path, bytes(password_utf8))
                reopened = Vault._open_pmve_store(self.path, self._password, store)
        self.close()
        return reopened

    def close(self) -> None:
        """Best-effort clearing of decrypted session material."""
        if self._pmve_store is not None:
            self._pmve_store.close()
            self._pmve_store = None
        for payload in self._payloads.values():
            if isinstance(payload, dict):
                payload.clear()
        self._payloads.clear()
        self._entry_cache.clear()
        self._password.clear()
        media_files.remove_vault_context(self)

    def has_external_change(self) -> bool:
        if self._pmve_store is not None:
            try:
                return self._pmve_store.identity.sequence != self._pmve_sequence
            except (OSError, TypeError, ValueError):
                return True
        return self._disk_revision is not None and _file_revision(self.path) != self._disk_revision

    def verify_password(self, password: str) -> bool:
        if self._password is not None and not self._password.is_empty():
            if self._password.matches(password):
                return True
        # 设备密钥（Windows Hello）/恢复密钥解锁的会话不持有主密码，
        # 或会话内密码状态异常（长期运行被清除/损坏）——回退到真实打开校验。
        try:
            probe = Vault.open(self.path, password)
            probe.close()
            return True
        except Exception:
            return False

    def change_password(self, new_password: str) -> None:
        _log.info("修改 PMVE 主密码")
        if self._pmve_store is None or self._password.is_empty():
            raise crypto.DecryptError("PMVE 修改主密码需要由当前主密码解锁的会话")
        new_password_utf8 = bytearray(new_password.encode("utf-8"))
        try:
            with self._password.bytes() as old_password_utf8:
                identity = self._pmve_store.rewrap_password(
                    bytes(old_password_utf8), bytes(new_password_utf8)
                )
            self._password.clear()
            self._password = crypto.SecureString.from_utf8(new_password_utf8)
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("PMVE 主密码修改失败") from exc
        finally:
            new_password_utf8[:] = b"\x00" * len(new_password_utf8)
        self.key_revision = max(int(self.key_revision or 0) + 1, int(identity.key_revision or 0))
        self._pmve_metadata["key_revision"] = self.key_revision
        self.key_updated_at = time.time()
        self.save()


    def reset_password_with_recovery(
        self, recovery_secret: bytes, new_password: str
    ) -> None:
        if self._pmve_store is None:
            raise crypto.DecryptError("PMVE Store 会话不可用")
        new_password_utf8 = bytearray(new_password.encode("utf-8"))
        try:
            identity = self._pmve_store.reset_password_with_recovery(
                bytes(recovery_secret), bytes(new_password_utf8)
            )
            self._password.clear()
            self._password = crypto.SecureString.from_utf8(new_password_utf8)
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("恢复密钥错误或 PMVE 密码重置失败") from exc
        finally:
            new_password_utf8[:] = b"\x00" * len(new_password_utf8)
        self.key_revision = max(int(self.key_revision or 0) + 1, int(identity.key_revision or 0))
        self._pmve_metadata["key_revision"] = self.key_revision
        self.key_updated_at = time.time()
        self.save()


    def regenerate_recovery_key(
        self,
        recovery_secret: bytes,
        *,
        old_recovery_secret: bytes | None = None,
    ) -> None:
        if self._pmve_store is None or old_recovery_secret is None:
            raise crypto.DecryptError("PMVE 轮换恢复密钥需要验证旧恢复密钥")
        try:
            identity = self._pmve_store.rotate_recovery(
                bytes(old_recovery_secret), bytes(recovery_secret)
            )
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("PMVE 恢复密钥轮换失败") from exc
        self.key_revision = max(int(self.key_revision or 0) + 1, int(identity.key_revision or 0))
        self._pmve_metadata["key_revision"] = self.key_revision
        self.key_updated_at = time.time()
        self.save()

    def regenerate_recovery_key_with_password(
        self, password_utf8: str, new_recovery_secret: bytes
    ) -> None:
        """用主密码重新生成恢复密钥（无需旧恢复密钥）；旧密钥立即失效。"""
        if self._pmve_store is None:
            raise crypto.DecryptError("PMVE Store 会话不可用")
        try:
            identity = self._pmve_store.regenerate_recovery_key(
                bytes(password_utf8, "utf-8"), bytes(new_recovery_secret)
            )
        except (TypeError, ValueError) as exc:
            raise crypto.DecryptError("PMVE 恢复密钥重新生成失败") from exc
        self.key_revision = max(int(self.key_revision or 0) + 1, int(identity.key_revision or 0))
        self._pmve_metadata["key_revision"] = self.key_revision
        self.key_updated_at = time.time()
        self.save()






    # ── 条目操作 ────────────────────────────────────────────────

    def add(self, entry: Entry) -> None:
        entry.id = self._canonical_uuid_text(entry.id)
        _log.info("新增条目：「%s」（类型=%s）", redact(entry.title), entry.secret_type)
        self._entry_meta[entry.id] = _make_entry_meta(entry)
        self._entry_order.append(entry.id)
        self._payloads[entry.id] = self._encrypt_payload(entry.id, _make_entry_payload(entry))
        self.save()

    def update(self, entry: Entry) -> None:
        _log.info("更新条目：「%s」（id=%s）", redact(entry.title), entry.id[:8])
        for i, eid in enumerate(self._entry_order):
            if eid == entry.id:
                cur = self._lazy(eid)
                if float(entry.updated_at) != float(cur.updated_at):
                    raise StaleEntryChange("条目已在其他窗口更新，请重新打开后编辑")
                from . import leak

                old_secret = leak.entry_secret(cur)
                new_secret = leak.entry_secret(entry)
                old_cache_current = leak.has_current_check(cur)
                if entry.content_equals(cur):
                    entry.updated_at = cur.updated_at
                    return
                else:
                    entry.touch()
                    if old_secret and old_secret == new_secret and old_cache_current:
                        entry.leak_check_revision = entry.updated_at
                        entry.leak_pwned_count = cur.leak_pwned_count
                        entry.leak_common_weak = cur.leak_common_weak
                        entry.leak_checked_at = cur.leak_checked_at
                    elif old_secret != new_secret:
                        entry.leak_check_revision = None
                        entry.leak_pwned_count = None
                        entry.leak_common_weak = False
                        entry.leak_checked_at = None
                self._entry_meta[eid] = _make_entry_meta(entry)
                self._payloads[eid] = self._encrypt_payload(entry.id, _make_entry_payload(entry))
                break
        self.save()

    def apply_leak_checks(self, results: list) -> int:
        """批量保存后台泄露检测结果，忽略检测期间已发生变化的条目。"""
        applied = 0
        for result in results:
            meta = self._entry_meta.get(result.entry_id)
            if meta is None or meta.get("updated_at") != result.revision:
                continue
            meta["leak_check_revision"] = result.revision
            meta["leak_pwned_count"] = max(0, int(result.pwned_count))
            meta["leak_common_weak"] = bool(result.common_weak)
            meta["leak_checked_at"] = float(result.checked_at)
            applied += 1
        if applied:
            self.save()
        return applied

    def delete(self, entry_id: str) -> None:
        meta = self._entry_meta.get(entry_id)
        title = meta["title"] if meta else entry_id[:8]
        _log.info("删除条目：「%s」（移入回收站）", redact(title))
        self._entry_order = [eid for eid in self._entry_order if eid != entry_id]
        self._entry_meta.pop(entry_id, None)
        if meta is not None:
            changed_at = monotonic_timestamp(meta.get("updated_at", 0.0))
            meta["deleted_at"] = changed_at
            meta["updated_at"] = changed_at
            self._trash_meta[entry_id] = meta
            self._trash_order.append(entry_id)
        self.save()

    def restore(self, entry_id: str) -> None:
        meta = self._trash_meta.get(entry_id)
        if meta is None:
            return
        _log.info("从回收站恢复条目：「%s」", redact(meta.get("title", "")))
        self._trash_order = [eid for eid in self._trash_order if eid != entry_id]
        self._trash_meta.pop(entry_id, None)
        meta["deleted_at"] = None
        meta["updated_at"] = monotonic_timestamp(meta.get("updated_at", 0.0))
        self._entry_meta[entry_id] = meta
        self._entry_order.append(entry_id)
        self.save()

    def restore_many(self, entry_ids: list[str]) -> int:
        ids = set(entry_ids)
        if not ids:
            return 0
        count = 0
        for eid in list(self._trash_order):
            if eid in ids:
                meta = self._trash_meta.get(eid)
                if meta is not None:
                    meta["deleted_at"] = None
                    meta["updated_at"] = monotonic_timestamp(meta.get("updated_at", 0.0))
                    self._entry_meta[eid] = meta
                    self._entry_order.append(eid)
                    count += 1
        self._trash_order = [eid for eid in self._trash_order if eid not in ids]
        for eid in ids:
            self._trash_meta.pop(eid, None)
        if count:
            self.save()
        return count

    def purge(self, entry_id: str) -> None:
        meta = self._trash_meta.get(entry_id)
        if meta is None:
            return
        _log.info("彻底删除回收站条目：「%s」", redact(meta.get("title", "")))
        self._record_purge(entry_id)
        self._trash_order = [eid for eid in self._trash_order if eid != entry_id]
        self._trash_meta.pop(entry_id, None)
        self._payloads.pop(entry_id, None)
        self.save()

    def purge_many(self, entry_ids: list[str]) -> int:
        ids = set(entry_ids)
        if not ids:
            return 0
        before = len(self._trash_order)
        for eid in ids:
            if eid in self._trash_meta:
                self._record_purge(eid)
        self._trash_order = [eid for eid in self._trash_order if eid not in ids]
        for eid in ids:
            self._trash_meta.pop(eid, None)
            self._payloads.pop(eid, None)
        purged = before - len(self._trash_order)
        if purged:
            self.save()
        return purged

    def purge_all(self) -> None:
        if not self._trash_order:
            return
        _log.info("清空回收站（%d 条）", len(self._trash_order))
        for eid in self._trash_order:
            self._record_purge(eid)
            self._payloads.pop(eid, None)
        self._trash_order = []
        self._trash_meta = {}
        self.save()

    def purge_expired(self, retention_days: int) -> None:
        if not self._trash_order:
            return
        cutoff = time.time() - retention_days * 86400
        remaining = [eid for eid in self._trash_order if (self._trash_meta[eid].get("deleted_at") or 0) >= cutoff]
        if len(remaining) == len(self._trash_order):
            return
        _log.info("自动清理回收站：移除 %d 条过期条目", len(self._trash_order) - len(remaining))
        purged = set(self._trash_order) - set(remaining)
        for eid in purged:
            self._record_purge(eid)
            self._trash_meta.pop(eid, None)
            self._payloads.pop(eid, None)
        self._trash_order = remaining
        self.save()

    def _record_purge(self, entry_id: str, purged_at: float | None = None) -> None:
        meta = self._trash_meta.get(str(entry_id)) or self._entry_meta.get(str(entry_id)) or {}
        previous_revision = float(meta.get("updated_at", 0.0) or 0.0)
        candidate = monotonic_timestamp(previous_revision, purged_at)
        self._purge_tombstones[str(entry_id)] = max(
            candidate,
            float(self._purge_tombstones.get(str(entry_id), 0.0)),
        )

    def rename_tag(self, old: str, new: str) -> int:
        affected = 0
        for eid in self._entry_order:
            meta = self._entry_meta.get(eid)
            if meta is None or old not in meta.get("tags", []):
                continue
            renamed: list[str] = []
            for t in meta["tags"]:
                t = new if t == old else t
                if t not in renamed:
                    renamed.append(t)
            meta["tags"] = renamed
            meta["updated_at"] = monotonic_timestamp(meta.get("updated_at", 0.0))
            # Also update payload (tags could be in both, but tags are in meta now)
            affected += 1
        if affected:
            _log.info("重命名标签「%s」→「%s」，影响 %d 条", redact(old), redact(new), affected)
            self.save()
        return affected

    def merge(self, incoming: list[Entry], resolver) -> dict:
        from . import sync

        _log.info("开始合并 %d 条外部记录", len(incoming))
        by_key: dict[tuple, Entry] = {}
        for eid in self._entry_order:
            e = self._lazy(eid)
            by_key[e.dedup_key()] = e
        stats = dict(
            added=0,
            overwritten=0,
            kept_both=0,
            skipped=0,
            identical=0,
            passkey_conflicts=0,
            cancelled=False,
        )
        changed = False
        for inc in incoming:
            key = inc.dedup_key()
            cur = by_key.get(key)
            if cur is None:
                self._payloads[inc.id] = self._encrypt_payload(inc.id, _make_entry_payload(inc))
                self._entry_meta[inc.id] = _make_entry_meta(inc)
                self._entry_order.append(inc.id)
                by_key[key] = inc
                stats["added"] += 1
                changed = True
                continue
            original_cur_fields = copy.deepcopy(cur.fields)
            cur, inc, passkey_conflict = sync.merge_passkeys_for_entries(cur, inc)
            stats["passkey_conflicts"] += int(passkey_conflict)
            passkeys_changed = cur.fields != original_cur_fields
            if cur.same_content(inc):
                if passkeys_changed:
                    self._entry_meta[cur.id] = _make_entry_meta(cur)
                    self._payloads[cur.id] = self._encrypt_payload(cur.id, _make_entry_payload(cur))
                    by_key[key] = cur
                    changed = True
                if self._apply_imported_leak_cache(cur, inc):
                    stats["overwritten"] += 1
                    changed = True
                else:
                    stats["identical"] += 1
                continue
            action = resolver(cur, inc)
            if action == "cancel":
                if passkeys_changed:
                    self._entry_meta[cur.id] = _make_entry_meta(cur)
                    self._payloads[cur.id] = self._encrypt_payload(cur.id, _make_entry_payload(cur))
                    by_key[key] = cur
                    changed = True
                stats["cancelled"] = True
                break
            if action == "overwrite":
                inc.id, inc.created_at = cur.id, cur.created_at
                inc.touch()
                self._entry_meta[inc.id] = _make_entry_meta(inc)
                self._payloads[inc.id] = self._encrypt_payload(inc.id, _make_entry_payload(inc))
                stats["overwritten"] += 1
                changed = True
            elif action == "keep_both":
                self._payloads[inc.id] = self._encrypt_payload(inc.id, _make_entry_payload(inc))
                self._entry_meta[inc.id] = _make_entry_meta(inc)
                self._entry_order.append(inc.id)
                stats["kept_both"] += 1
                changed = True
            else:
                if passkeys_changed:
                    self._entry_meta[cur.id] = _make_entry_meta(cur)
                    self._payloads[cur.id] = self._encrypt_payload(cur.id, _make_entry_payload(cur))
                    by_key[key] = cur
                    changed = True
                stats["skipped"] += 1
        if changed:
            self.save()
        _log.info(
            "合并完成：新增 %d，覆盖 %d，保留副本 %d，跳过 %d，重复 %d，已取消=%s",
            stats["added"],
            stats["overwritten"],
            stats["kept_both"],
            stats["skipped"],
            stats["identical"],
            stats["cancelled"],
        )
        return stats

    def _apply_imported_leak_cache(self, current: Entry, incoming: Entry) -> bool:
        incoming_has_cache = incoming.leak_pwned_count is not None or bool(incoming.leak_common_weak)
        if not incoming_has_cache:
            return False
        meta = self._entry_meta.get(current.id)
        if meta is None:
            return False
        same_cache = (
            meta.get("leak_pwned_count") == incoming.leak_pwned_count
            and bool(meta.get("leak_common_weak", False)) == bool(incoming.leak_common_weak)
            and meta.get("leak_checked_at") == incoming.leak_checked_at
            and meta.get("leak_check_revision") == meta.get("updated_at")
        )
        if same_cache:
            return False
        meta["leak_pwned_count"] = incoming.leak_pwned_count
        meta["leak_common_weak"] = bool(incoming.leak_common_weak)
        meta["leak_checked_at"] = incoming.leak_checked_at or time.time()
        meta["leak_check_revision"] = meta.get("updated_at")
        return True

    # ── 多端同步 ────────────────────────────────────────────────

    def _all_with_tombstones(self) -> list:
        return [self._lazy(eid) for eid in self._entry_order] + [self._lazy(eid) for eid in self._trash_order]

    def _split_tombstones(self, merged: list) -> None:
        entries = [e for e in merged if e.deleted_at is None]
        trash = [e for e in merged if e.deleted_at is not None]
        self._entry_meta = {}
        self._trash_meta = {}
        self._payloads = {}
        self._entry_order = [e.id for e in entries]
        self._trash_order = [e.id for e in trash]
        for e in entries + trash:
            self._entry_meta[e.id] = _make_entry_meta(e)
            self._payloads[e.id] = self._encrypt_payload(e.id, _make_entry_payload(e))

    def sync_merge(
        self,
        incoming: list[Entry],
        remote_export_epoch: float | None,
        on_conflict=None,
        incoming_purge_tombstones: dict[str, float] | None = None,
        incoming_autofill_exclusions: dict | None = None,
    ) -> dict:
        from . import sync

        _log.info("Sync 合并 %d 条远端记录（remote_epoch=%s）", len(incoming), remote_export_epoch)
        calibrated = sync.calibrate(incoming, remote_export_epoch, time.time())
        merged, stats, purges = sync.merge_with_purges(
            self._all_with_tombstones(),
            calibrated,
            self._purge_tombstones,
            incoming_purge_tombstones,
            on_conflict,
        )
        self._purge_tombstones = purges
        self._split_tombstones(merged)
        if incoming_autofill_exclusions is not None:
            from .autofill_exclusions import FIELD, merge as merge_exclusions
            self._pmve_metadata[FIELD] = merge_exclusions(self.autofill_exclusions, incoming_autofill_exclusions)
        self._pmve_metadata.pop("passkey_keyset", None)
        self.save()
        _log.info(
            "Sync 合并完成：新增 %d，取远端 %d，留本地 %d，重复 %d，保留双份 %d，冲突 %d",
            stats["added"],
            stats["remote_wins"],
            stats["local_wins"],
            stats["identical"],
            stats["kept_both"],
            stats["conflicts"],
        )
        return stats

    def read_sync_key_meta(self, source: Path | bytes) -> tuple[int, float]:
        if isinstance(source, bytes):
            raise crypto.DecryptError("PMVE 同步只接受认证文件路径")
        path = Path(source)
        if not path.is_file():
            raise crypto.DecryptError("远端 PMVE 文件不存在")
        with path.open("rb") as handle:
            if handle.read(4) != PMVE_MAGIC:
                raise crypto.DecryptError("远端保险库格式已不再支持")
        self.authenticate_external_file(path)
        return self._pmve_sync_key_meta(path)


    def _pmve_sync_key_meta(self, path: Path) -> tuple[int, float]:
        from .pmv_vault_store import PmvVaultStore

        root_key = bytearray(self.root_key_for_device_unlock())
        try:
            store = PmvVaultStore.open_root_key(path, bytes(root_key))
            try:
                metadata = store.metadata()
                sync_meta = metadata.get("sync_meta", {})
                return (
                    _read_logical_key_revision(metadata),
                    float(sync_meta.get("key_updated_at", 0.0) or 0.0),
                )
            finally:
                store.close()
        finally:
            root_key[:] = bytes(len(root_key))



    def scan_duplicates(self) -> dict:
        groups: dict[tuple, list] = defaultdict(list)
        for eid in self._entry_order:
            e = self._lazy(eid)
            if e.secret_type != SecretType.LOGIN:
                continue
            groups[e.dedup_key()].append(e)
        exact = pw_conflict = 0
        for dupes in groups.values():
            if len(dupes) <= 1:
                continue
            first = dupes[0]
            if all(first.same_except_password(e) for e in dupes[1:]):
                if len({e.password for e in dupes}) == 1:
                    exact += 1
                else:
                    pw_conflict += 1
            else:
                exact += 1
        return {"exact": exact, "pw_conflict": pw_conflict}

    def duplicate_groups(self) -> list[list[Entry]]:
        groups: dict[tuple, list[Entry]] = defaultdict(list)
        for eid in self._entry_order:
            entry = self._lazy(eid)
            if entry.secret_type != SecretType.LOGIN:
                continue
            groups[entry.dedup_key()].append(entry)
        return sorted(
            (sorted(items, key=lambda entry: entry.updated_at, reverse=True) for items in groups.values() if len(items) > 1),
            key=len,
            reverse=True,
        )

    def dedup_entries(self, pw_resolver=None) -> dict:
        groups: dict[tuple, list] = defaultdict(list)
        for eid in self._entry_order:
            e = self._lazy(eid)
            if e.secret_type != SecretType.LOGIN:
                continue
            groups[e.dedup_key()].append(e)
        dup_groups = {k: v for k, v in groups.items() if len(v) > 1}
        if not dup_groups:
            _log.info("去重扫描完成：未发现重复条目")
            return {"exact_merged": 0, "pw_resolved": 0, "pw_skipped": 0}
        stats = {"exact_merged": 0, "pw_resolved": 0, "pw_skipped": 0}
        to_remove: set[tuple] = set()
        replacements: list[Entry] = []
        for key, dupes in dup_groups.items():
            first = dupes[0]
            same_fields = all(first.same_except_password(e) for e in dupes[1:])
            passwords = {e.password for e in dupes}
            if not same_fields or len(passwords) == 1:
                merged = self._merge_group(dupes)
                to_remove.add(key)
                replacements.append(merged)
                stats["exact_merged"] += 1
            else:
                if pw_resolver is None:
                    stats["pw_skipped"] += 1
                    continue
                chosen = pw_resolver(dupes)
                if chosen is None:
                    stats["pw_skipped"] += 1
                    continue
                merged = self._merge_group(dupes, password=chosen.password)
                to_remove.add(key)
                replacements.append(merged)
                stats["pw_resolved"] += 1
        if to_remove:
            self._entry_order = [
                eid
                for eid in self._entry_order
                if (
                    self._entry_meta.get(eid, {}).get("secret_type", SecretType.LOGIN),
                    (self._entry_meta.get(eid, {}).get("title", "").strip().lower()),
                    (self._entry_meta.get(eid, {}).get("username", "").strip().lower()),
                )
                not in to_remove
            ] + [r.id for r in replacements]
            for e in replacements:
                self._entry_meta[e.id] = _make_entry_meta(e)
                self._payloads[e.id] = self._encrypt_payload(e.id, _make_entry_payload(e))
            self.save()
        _log.info(
            "去重完成：自动合并 %d，手动解决 %d，跳过 %d",
            stats["exact_merged"],
            stats["pw_resolved"],
            stats["pw_skipped"],
        )
        return stats

    def _merge_group(self, dupes: list, password: str | None = None) -> Entry:
        dupes_sorted = sorted(dupes, key=lambda e: e.updated_at, reverse=True)
        winner = Entry.from_dict(copy.copy(dupes_sorted[0]).to_dict())
        seen: set[str] = set()
        merged_tags: list[str] = []
        for e in dupes_sorted:
            for t in e.tags:
                if t and t not in seen:
                    merged_tags.append(t)
                    seen.add(t)
        merged_fields: dict = {}
        for e in reversed(dupes_sorted):
            merged_fields.update(e.fields)
        winner.tags = merged_tags
        winner.fields = merged_fields
        winner.created_at = min(e.created_at for e in dupes)
        winner.updated_at = max(e.updated_at for e in dupes)
        winner.id = min(dupes, key=lambda e: e.created_at).id
        if password is not None:
            winner.password = password
        winner.invalidate_haystack()
        return winner

    def merge_entries_manual(
        self,
        entries: list[Entry],
        *,
        resolved_title: str = "",
        resolved_username: str = "",
        resolved_password: str = "",
    ) -> Entry:
        """手动合并：由用户指定 title/username/password，其他字段自动合并。

        与 ``_merge_group`` 的区别在于 title/username/password 按用户指定值写入，
        而非自动取最新条目的值。URL / target_app 取首个非空值。
        """
        sorted_entries = sorted(entries, key=lambda e: e.updated_at, reverse=True)
        winner = Entry.from_dict(copy.copy(sorted_entries[0]).to_dict())
        seen: set[str] = set()
        merged_tags: list[str] = []
        for e in sorted_entries:
            for t in e.tags:
                if t and t not in seen:
                    merged_tags.append(t)
                    seen.add(t)
        merged_fields: dict = {}
        for e in reversed(sorted_entries):
            merged_fields.update(e.fields)
        winner.title = resolved_title if resolved_title else winner.title
        winner.username = resolved_username if resolved_username else (
            next((e.username for e in entries if e.username), winner.username)
        )
        winner.password = resolved_password
        winner.url = next((e.url for e in entries if e.url), winner.url)
        winner.target_app = next((e.target_app for e in entries if e.target_app), winner.target_app)
        winner.tags = merged_tags
        winner.fields = merged_fields
        winner.created_at = min(e.created_at for e in entries)
        winner.updated_at = time.time()
        winner.id = min(entries, key=lambda e: e.created_at).id
        winner.invalidate_haystack()
        return winner

    def scan_same_service(self) -> list[SameServiceGroup]:
        """按域名 / 包名分组，返回有 2+ 条目的同服务组。

        逻辑与 Android ``VaultOps.scanSameService`` 对齐：
        从 URL 提取域名 → 回退 target_app → 回退 title。
        """
        from urllib.parse import urlparse

        def _service_domain(entry: Entry) -> str:
            url = (entry.url or "").strip()
            if url:
                try:
                    parsed = urlparse(url)
                    domain = (parsed.hostname or "").removeprefix("www.").lower()
                    if domain:
                        return domain
                except Exception:
                    pass
            app = (entry.target_app or "").strip().lower()
            if app:
                return app
            return (entry.title or "").strip().lower()

        alive = [
            e for eid in self._entry_order
            for e in [self._lazy(eid)]
            if e.deleted_at is None and e.secret_type == SecretType.LOGIN
        ]
        groups: dict[str, list] = {}
        for e in alive:
            key = _service_domain(e)
            if not key:
                continue
            groups.setdefault(key, []).append(e)

        result = [
            SameServiceGroup(key, sorted(entries, key=lambda x: x.updated_at, reverse=True))
            for key, entries in groups.items()
            if len(entries) > 1
        ]
        result.sort(key=lambda g: len(g.entries), reverse=True)
        return result

    def search(self, query: str) -> list[Entry]:
        items = []
        for eid in self._entry_order:
            entry = self._lazy(eid)
            if entry.matches(query):
                items.append(entry)
        items.sort(key=lambda e: pinyin_sort_key(e.title))
        return items

    def __getstate__(self):
        """Unlocked vault sessions deliberately cannot serialize their master password."""
        raise TypeError("unlocked Vault sessions cannot be pickled")

    def __setstate__(self, state):
        """Unpickle by re-opening."""
        reopened = Vault.open(Path(state["path"]), state["password"])
        self.__dict__.update(reopened.__dict__)
