"""云端同步的控制器层：状态、后台任务与重型认证均与 UI 分离。

视图（``ui/app.py`` 的 ``_open_cloud_sync``）只负责呈现与交互确认；
本模块负责所有云端读写、合并、覆盖、下载与远端 PMVE 认证，全部在
``QThread`` 中执行。检测或同步期间主线程只处理信号，不做重活，
因此窗口操作不会因“正在检测”等后台行为而卡顿。
"""

from __future__ import annotations

import datetime
import time
import email.utils
import enum
import os
import tempfile
from pathlib import Path

from PySide6.QtCore import QMetaMethod, QObject, QThread, Signal
from shiboken6 import isValid

from core import auto_cloud_sync, cloud, crypto, remote_update, cloud_sync_prefs
from core.storage import Vault, VaultLineage
from . import i18n


def authenticated_writer_line(store) -> str:
    from core.device_activity import verified_last_writer
    profile = verified_last_writer(store)
    name = profile.get("name") if profile else None
    return i18n.tr("最近写入设备：{name}").format(name=name or i18n.tr("未知设备"))


class RemoteMetadataWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, target, connection, parent=None):
        super().__init__(parent)
        self.target, self.connection = target, connection

    def run(self):
        try:
            if self.target == "drive":
                metadata = cloud.cloud_drive_metadata(self.connection)
            else:
                client = cloud.WebDavClient(self.connection)
                # Deliberately HEAD only: unsupported metadata never falls back to a download.
                _, headers, response = client._request("HEAD", url=self.connection.file_url, retry=True, stream=True)
                try:
                    modified = email.utils.parsedate_to_datetime(headers["Last-Modified"]).timestamp() if headers.get("Last-Modified") else 0.0
                    metadata = cloud.RemoteMetadata(True, int(headers.get("Content-Length", "-1")), modified, cloud._strong_etag(headers))
                finally:
                    response.close()
            if not metadata.exists:
                raise cloud.CloudError("远端文件已删除")
            self.completed.emit(metadata)
        except Exception as exc:
            self.failed.emit(str(exc))


class CloudSyncPhase(enum.Enum):
    """单个同步目标的阶段（对齐安卓 CloudSyncPhase）。"""

    IDLE = "idle"
    RUNNING = "running"
    FAILED = "failed"


_PREVIEW_TITLES = {
    VaultLineage.SAME: "双方内容一致",
    VaultLineage.FAST_FORWARD: "远端有新版本，可拉取",
    VaultLineage.REMOTE_STALE: "本地有新版本，可上传",
    VaultLineage.DIVERGED: "双方均有修改，可自动合并",
    VaultLineage.DIFFERENT: "远端不是同一份保险库",
    VaultLineage.INVALID: "远端数据无法验证",
}


def _preview_detail(
    lineage,
    *,
    local_seq: int,
    remote_seq: int,
    local_key: int,
    remote_key: int,
    local_active: int,
    local_trash: int,
    checked: str | None = None,
) -> str:
    """按谱系生成结构化预览摘要（第一行是结论，其后是提交/条目明细）。"""
    lines = [
        _PREVIEW_TITLES.get(lineage, "等待检测"),
        f"本地提交 #{local_seq}（密钥 v{local_key}） · 远端提交 #{remote_seq}（密钥 v{remote_key}）",
        f"本地 {local_active} 项（回收站 {local_trash}）",
    ]
    if checked:
        lines.append(f"最近检测：{checked}")
    return "\n".join(lines)


def cloud_sync_user_message(error: Exception | str, *, local_saved: bool = False) -> str:
    """将云端异常收敛为用户可执行的提示，不暴露 PMV/Identity/CAS 等内部词汇。"""
    text = str(error).lower()
    if "decrypt" in text or "主密码不匹配" in text:
        detail = "远端数据无法用当前账户验证，请确认关联的是同一份保险库"
    elif "不是同一" in text or "different" in text:
        detail = "远端文件不属于当前账户，本次同步已停止"
    elif any(word in text for word in ("identity", "签名", "身份", "谱系", "逻辑内容不一致")):
        detail = "远端文件未通过安全检查，本次同步已停止"
    elif any(word in text for word in ("conflict", "cas", "409", "其他设备更新", "发生变化")):
        detail = "同步期间另一台设备更新了远端数据，请稍后重试"
    elif any(word in text for word in ("timeout", "timed out", "超时")):
        detail = "云端响应超时，请检查网络后重试"
    elif "certificate" in text or "证书" in text:
        detail = "云端身份验证失败，请检查服务器证书或重新关联"
    elif any(word in text for word in ("401", "403", "unauthorized", "forbidden")):
        detail = "云端登录信息已失效，请重新关联"
    elif "不存在" in text or "已删除" in text:
        detail = "关联的云端文件已不存在，请重新关联"
    else:
        detail = "暂时无法完成云端同步，请检查网络和云端空间后重试"
    if local_saved:
        return f"本地已保存合并结果，但未能上传到云端。{detail}"
    return detail


class CloudWorker(QThread):
    """WebDAV 云端操作：连接 / 检测 / 上传 / 下载。"""

    completed = Signal(str, object)
    failed = Signal(str)

    def __init__(self, action: str, connection: cloud.WebDavConfig, payload=None, parent=None):
        super().__init__(parent)
        self.action = action
        self.connection = connection
        self.payload = payload

    def _file_payload(self) -> tuple[Path, cloud.RemoteFileSnapshot | None]:
        """Normalise the upload payload.

        ``push_file``/``overwrite_file`` are constructed both as a bare ``Path``
        (explicit overwrite) and as a ``(path, expected)`` pair (CAS upload), so
        unpack whichever shape the caller used.
        """
        if isinstance(self.payload, Path):
            return self.payload, None
        path, expected = self.payload
        return Path(path), expected

    def run(self) -> None:
        try:
            client = cloud.WebDavClient(self.connection)
            if self.action == "connect":
                client.test()
                # 关联只需知道远端有没有数据，不能整库下载：PMVE 是 file-only，
                # download_if_exists 会拒绝 PMVS 文件，导致「远端已有数据」的
                # 合并/覆盖/下载三选一对话框永远无法出现。
                result = client.metadata(verify_size=True)
            elif self.action == "inspect":
                result = client.metadata(verify_size=True)
            elif self.action in {"overwrite", "push"}:
                if isinstance(self.payload, Path):
                    if self.payload.stat().st_size > cloud.MAX_DOWNLOAD_BYTES:
                        raise cloud.CloudError("本地保险库超过 128 MB 安全限制")
                    upload_data = self.payload.read_bytes()
                else:
                    path, expected = self.payload
                    if path.stat().st_size > cloud.MAX_DOWNLOAD_BYTES:
                        raise cloud.CloudError("本地保险库超过 128 MB 安全限制")
                    upload_data = path.read_bytes()
                if self.action == "overwrite":
                    client.upload_overwrite(upload_data)
                else:
                    client.upload_if_unchanged(upload_data, expected)
                result = client.download_snapshot()
            elif self.action == "pull":
                result = client.download_if_exists()
            elif self.action == "pull_file":
                descriptor, name = tempfile.mkstemp(prefix="vault-webdav-pull-", suffix=".pmv")
                os.close(descriptor)
                temp_path = Path(name)
                try:
                    result = client.download_to_if_exists(temp_path)
                except Exception:
                    temp_path.unlink(missing_ok=True)
                    raise
            elif self.action in {"push_file", "overwrite_file"}:
                local_path, expected = self._file_payload()
                if local_path.stat().st_size > cloud.MAX_CLOUD_VAULT_BYTES:
                    raise cloud.CloudError("本地保险库超过 1 GB 安全限制")
                client.upload_file_if_unchanged(
                    local_path, expected, force=self.action == "overwrite_file"
                )
                descriptor, name = tempfile.mkstemp(prefix="vault-webdav-readback-", suffix=".pmv")
                os.close(descriptor)
                readback = Path(name)
                try:
                    result = client.download_to_if_exists(readback)
                except Exception:
                    readback.unlink(missing_ok=True)
                    raise
            else:
                raise cloud.CloudError("未知云端操作")
            self.completed.emit(self.action, result)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class CloudDriveWorker(QThread):
    """云端硬盘操作：检测 / 拉取 / 写入 / 上传。"""

    completed = Signal(str, object)
    failed = Signal(str)

    def __init__(self, action: str, target: Path, payload=None, parent=None):
        super().__init__(parent)
        self.action = action
        self.target = target
        self.payload = payload

    def _file_payload(self) -> tuple[Path, cloud.RemoteFileSnapshot | None]:
        """Normalise the upload payload: bare ``Path`` or ``(path, expected)``."""
        if isinstance(self.payload, Path):
            return self.payload, None
        path, expected = self.payload
        return Path(path), expected

    def run(self) -> None:
        try:
            if self.action == "inspect":
                result = cloud.cloud_drive_metadata(self.target)
            elif self.action == "pull":
                result = cloud.read_cloud_drive(self.target, allow_missing=True)
            elif self.action in {"overwrite", "push"}:
                if isinstance(self.payload, Path):
                    local_path, expected = self.payload, None
                else:
                    local_path, expected = self.payload
                if local_path.stat().st_size > cloud.MAX_DOWNLOAD_BYTES:
                    raise cloud.CloudError("本地保险库超过 128 MB 安全限制")
                data = local_path.read_bytes()
                cloud.write_cloud_drive(
                    self.target,
                    data,
                    expected=expected,
                    force=self.action == "overwrite",
                )
                result = cloud.read_cloud_drive(self.target)
            elif self.action == "pull_file":
                # Keep the downloaded copy off the cloud/removable drive. A sidecar
                # beside the remote vault can be picked up by its sync client.
                descriptor, name = tempfile.mkstemp(prefix="vault-cloud-drive-download-", suffix=".pmv")
                os.close(descriptor)
                temp_path = Path(name)
                try:
                    result = cloud.read_cloud_drive_to(self.target, temp_path, allow_missing=True)
                    if result is None:
                        temp_path.unlink(missing_ok=True)
                except Exception:
                    temp_path.unlink(missing_ok=True)
                    raise
            elif self.action in {"push_file", "overwrite_file"}:
                local_path, expected = self._file_payload()
                if local_path.stat().st_size > cloud.MAX_CLOUD_VAULT_BYTES:
                    raise cloud.CloudError("本地保险库超过 1 GB 安全限制")
                revision = cloud.write_cloud_drive_file(
                    self.target,
                    local_path,
                    expected=expected,
                    force=self.action == "overwrite_file",
                )
                after = self.target.stat()
                result = cloud.RemoteFileSnapshot(
                    self.target, revision, True, after.st_mtime, after.st_size
                )
            else:
                raise cloud.CloudError("未知云端硬盘操作")
            self.completed.emit(self.action, result)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))


class InteractiveCloudSyncWorker(QThread):
    """完整的手动云端合并，状态渲染永不参与线程内逻辑。"""

    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, vault_path: Path, password: crypto.SecureString, target: str, payload, *, allow_missing: bool, parent=None):
        super().__init__(parent)
        self.vault_path = vault_path
        self.password = password
        self.target = target
        self.payload = payload
        self.allow_missing = allow_missing

    def run(self) -> None:
        try:
            with self.password.bytes() as password:
                if self.target == "drive":
                    result = auto_cloud_sync.sync_drive_manual(
                        self.vault_path, password, self.payload, allow_missing=self.allow_missing
                    )
                    metadata = cloud.cloud_drive_metadata(self.payload)
                elif self.target == "webdav":
                    result = auto_cloud_sync.sync_webdav(
                        self.vault_path, password, self.payload, allow_missing=self.allow_missing
                    )
                    metadata = None
                else:
                    raise cloud.CloudError("手动同步目标无效")
                refreshed = Vault.open_with_password_buffer(self.vault_path, password) if result.changed else None
            self.completed.emit((result, refreshed, metadata))
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(str(exc))
        finally:
            self.password.clear()


class RemotePreviewWorker(QThread):
    """在后台认证远端 PMVE 文件并生成检测预览文本，主线程不参与任何解密。"""

    previewReady = Signal(str, object, int, int)
    failed = Signal(str)

    def __init__(
        self,
        vault_path: Path,
        password: crypto.SecureString,
        remote_path: Path,
        *,
        local_identity,
        parent=None,
    ):
        super().__init__(parent)
        self.vault_path = vault_path
        self.password = password
        self.remote_path = remote_path
        self.local_identity = local_identity

    def run(self) -> None:
        try:
            with self.password.bytes() as password:
                vault = Vault.open_with_password_buffer(self.vault_path, password)
            try:
                remote_identity = vault.authenticate_external_file(self.remote_path)
                lineage = vault.classify_lineage(self.local_identity, remote_identity)
                local_key_rev, _ = vault.read_sync_key_meta(vault.path)
                remote_key_rev, _ = vault.read_sync_key_meta(self.remote_path)
                text = _preview_detail(
                    lineage,
                    local_seq=self.local_identity.sequence if self.local_identity else 0,
                    remote_seq=remote_identity.sequence,
                    local_key=local_key_rev,
                    remote_key=remote_key_rev,
                    local_active=len(vault.entries),
                    local_trash=len(vault.trash),
                    checked=datetime.datetime.now().strftime("%H:%M:%S"),
                )
                from core.pmv_vault_store import PmvVaultStore
                remote_store = PmvVaultStore.open_root_key(self.remote_path, vault.root_key_for_device_unlock())
                try:
                    text += "\n" + authenticated_writer_line(remote_store)
                finally:
                    remote_store.close()
                # 透传已认证的远端身份与计数，供控制器缓存复用（跳过下次整库下载/解密）。
                self.previewReady.emit(text, remote_identity, len(vault.entries), remote_key_rev)
            finally:
                vault.close()
                self.remote_path.unlink(missing_ok=True)
        except Exception as exc:  # noqa: BLE001
            self.remote_path.unlink(missing_ok=True)
            self.failed.emit(f"远端 PMVE 无法认证或已损坏\n{exc}")
        finally:
            self.password.clear()


class RemoteVerifyWorker(QThread):
    """在后台认证一个已下载的远端文件并返回其 PMVE Identity。"""

    verified = Signal(object)
    failed = Signal(str)

    def __init__(self, vault_path: Path, password: crypto.SecureString, remote_path: Path, parent=None):
        super().__init__(parent)
        self.vault_path = vault_path
        self.password = password
        self.remote_path = remote_path

    def run(self) -> None:
        try:
            with self.password.bytes() as password:
                vault = Vault.open_with_password_buffer(self.vault_path, password)
            try:
                identity = vault.authenticate_external_file(self.remote_path)
            finally:
                vault.close()
                self.remote_path.unlink(missing_ok=True)
            self.verified.emit(identity)
        except Exception as exc:  # noqa: BLE001
            self.remote_path.unlink(missing_ok=True)
            self.failed.emit(str(exc))
        finally:
            self.password.clear()


class DownloadReplaceWorker(QThread):
    """在后台用已下载的远端文件整体替换本地 PMVE 文件（含认证与落盘）。"""

    replaced = Signal(object)
    failed = Signal(str)

    def __init__(self, vault_path: Path, password: crypto.SecureString, remote_path: Path, *, force: bool, parent=None):
        super().__init__(parent)
        self.vault_path = vault_path
        self.password = password
        self.remote_path = remote_path
        self.force = force

    def run(self) -> None:
        try:
            with self.password.bytes() as password:
                vault = Vault.open_with_password_buffer(self.vault_path, password)
            try:
                identity = vault.replace_authenticated_file(self.remote_path, force=self.force)
                vault.acknowledge_deletion_checkpoint()
            finally:
                vault.close()
                self.remote_path.unlink(missing_ok=True)
            with self.password.bytes() as password:
                refreshed = Vault.open_with_password_buffer(self.vault_path, password)
            if self.isInterruptionRequested():
                refreshed.close()
            else:
                self.replaced.emit(refreshed)
        except Exception as exc:  # noqa: BLE001
            self.remote_path.unlink(missing_ok=True)
            self.failed.emit(str(exc))
        finally:
            self.password.clear()


class CloudSettingsWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)

    def __init__(self, vault_id, vault_uuid, root_key, parent=None):
        super().__init__(parent)
        self.vault_id, self.vault_uuid, self.root_key = vault_id, vault_uuid, root_key

    def run(self):
        try:
            drive = cloud.load_cloud_drive(self.vault_id)
            revision = cloud.load_cloud_drive_revision(self.vault_id)
            logical = cloud.load_cloud_drive_logical_revision(self.vault_id)
            webdav = cloud.load_webdav(self.vault_id, vault_uuid=self.vault_uuid, root_key=bytes(self.root_key))
            health = "ok" if drive and drive.is_file() else ("missing" if drive else "")
            self.completed.emit((drive, revision, logical, webdav, health))
        except Exception as exc:
            self.failed.emit(str(exc))
        finally:
            self.root_key[:] = bytes(len(self.root_key))


class CloudSyncController(QObject):
    """云端同步状态机：持有全部状态，任何重活都在后台线程执行。

    信号约定：
    - ``stateChanged``：连接 / 健康状态变化，视图刷新控件；
    - ``busyChanged(target, busy)``：目标忙碌变化；
    - ``previewChanged(target, text)``：检测预览文本；
    - ``message(title, text, kind)``：需要弹出提示；
    - ``askExistingRemote(title, callback)``：远端已有数据，视图弹选择后回调 mode；
    - ``vaultReplaced(vault)``：同步已用新的保险库对象替换本地（视图负责关旧库与 reload）；
    - ``localVaultReplaced``：下载覆盖已替换磁盘文件，视图需重新打开本地保险库。
    """

    DRIVE = "drive"
    WEBDAV = "webdav"

    stateChanged = Signal()
    settled = Signal()
    busyChanged = Signal(str, bool)
    previewChanged = Signal(str, str)
    remoteUpdateFound = Signal(str)
    message = Signal(str, str, str)
    askExistingRemote = Signal(str, object)
    vaultReplaced = Signal(object)
    localVaultReplaced = Signal()

    def __init__(
        self,
        vault: Vault,
        *,
        vault_path: Path,
        password: crypto.SecureString,
        cloud_vault_id: str,
        parent: QObject | None = None,
    ):
        super().__init__(parent)
        self._vault = vault
        self._vault_path = Path(vault_path)
        self._password = password
        self._cloud_vault_id = cloud_vault_id
        self.drive_path: Path | None = None
        self.drive_revision: str | None = None
        self.drive_logical_revision: str | None = None
        self.drive_health = ""
        self.webdav_config: cloud.WebDavConfig | None = None
        self.webdav_health = ""
        self._busy_targets: set[str] = set()
        # 阶段状态机（对齐安卓 CloudSyncPhase）：每个目标独立记录阶段、阶段文案、
        # 进度（0..1 或 None=不确定）与最近一次成功时间/结果。
        self._phase: dict[str, CloudSyncPhase] = {
            self.DRIVE: CloudSyncPhase.IDLE,
            self.WEBDAV: CloudSyncPhase.IDLE,
        }
        self._phase_message: dict[str, str] = {}
        self._progress: dict[str, float | None] = {}
        self._last_success: dict[str, float] = {}
        self._last_result: dict[str, tuple[int, bool]] = {}
        # 远端身份缓存：target -> (revision_key, remote_identity, entry_count, remote_key_rev)。
        # 远端未发生变化时复用上次整库解密得到的身份，跳过下载与解密（与安卓“先比 ETag 再决定
        # 是否下载全量”的探测一致），从而消除“检测很慢”的重复开销。
        self._remote_cache: dict[str, tuple[str, object, int, int]] = {}
        self._remote_writer_lines = {}
        self._workers: list[QThread] = []
        self._remote_checks = {}
        self._remote_checked_at = {}
        self._remote_associations = {}
        self._overwrite_update_inputs = {}
        self._remote_epochs = {"drive": 0, "webdav": 0}
        self._closed = False
        self.loading = False
        self.loaded = False
        self.previews = {}
        self.last_notice = None
        self._notice_target = None
        self.notices = {}
        self.pending_question = None
        self.previewChanged.connect(self._remember_preview)
        self.message.connect(self._remember_notice)
        self.askExistingRemote.connect(self._remember_question)

    def _update_association(self, target):
        connection = self.drive_path if target == self.DRIVE else self.webdav_config
        return remote_update.association_fingerprint(target, connection) if connection is not None else ""

    def remote_update_state(self, target):
        association = self._update_association(target)
        if not association or not remote_update.enabled(self._cloud_vault_id, target):
            return remote_update.UpdateState()
        return remote_update.load(self._cloud_vault_id, target, association)

    def set_remote_detection(self, target, enabled):
        self._remote_epochs[target] += 1
        remote_update.set_enabled(self._cloud_vault_id, target, enabled)
        self._remote_checked_at.pop(target, None)
        self.stateChanged.emit()
        if enabled:
            self.check_remote_updates()

    def snooze_remote_update(self, target):
        # History is persisted when shown, so Later retains the card without repeating a toast.
        self.stateChanged.emit()

    def acknowledge_remote_update(self, target, version, consumed_version=""):
        if not version:
            return
        association = self._update_association(target)
        if not association:
            return
        state = self.remote_update_state(target)
        state, _ = remote_update.reduce(state, {"type": "acknowledge", "version": version, "consumed_version": consumed_version})
        remote_update.save(self._cloud_vault_id, target, association, state)
        self.stateChanged.emit()

    def check_remote_updates(self):
        # A queued page-open timer can outlive the session QObject during teardown.
        if self._closed or not isValid(self):
            return
        parent = self.parent()
        if (self._closed or not self.loaded or getattr(parent, "_locked", False)
                or not cloud_sync_prefs.master_enabled(self._cloud_vault_id) or self.start_block_reason()):
            return
        now = time.monotonic()
        for target in (self.DRIVE, self.WEBDAV):
            association = self._update_association(target)
            if association != self._remote_associations.get(target):
                self._remote_epochs[target] += 1
                self._remote_associations[target] = association
                self._remote_checked_at.pop(target, None)
            if (not association or not remote_update.enabled(self._cloud_vault_id, target)
                    or target in self._remote_checks
                    or now - self._remote_checked_at.get(target, -remote_update.INTERVAL_SECONDS) < remote_update.INTERVAL_SECONDS):
                continue
            self._remote_checked_at[target] = now
            epoch = self._remote_epochs[target]
            worker = RemoteMetadataWorker(target, self.drive_path if target == self.DRIVE else self.webdav_config, self)
            self._remote_checks[target] = worker
            worker.completed.connect(lambda meta, t=target, a=association, e=epoch: self._remote_observed(t, a, e, meta))
            worker.failed.connect(lambda msg, t=target, a=association, e=epoch: self._remote_check_failed(t, a, e, msg))
            worker.finished.connect(lambda t=target: self._remote_checks.pop(t, None))
            self._start(worker)
        self.stateChanged.emit()

    def _remote_result_current(self, target, association, epoch):
        return (not self._closed and isValid(self) and not getattr(self.parent(), "_locked", False)
                and cloud_sync_prefs.master_enabled(self._cloud_vault_id)
                and remote_update.enabled(self._cloud_vault_id, target)
                and self._remote_epochs[target] == epoch and self._update_association(target) == association)

    def _remote_observed(self, target, association, epoch, metadata):
        if not self._remote_result_current(target, association, epoch):
            return
        version = remote_update.metadata_version(target, metadata)
        if not version:
            return
        previous = self.remote_update_state(target)
        state, notify = remote_update.reduce(previous,
                                            {"type": "observe", "version": version, "now": int(time.time() * 1000)})
        if state.pending and state.pending != previous.pending:
            self._remote_cache.pop(target, None)
            self.previews.pop(target, None)
            self.previewChanged.emit(target, "远端版本已变化，请重新验证设备信息")
        remote_update.save(self._cloud_vault_id, target, association, state)
        setattr(self, f"{target}_health", "ok")
        self.stateChanged.emit()
        if notify:
            self.remoteUpdateFound.emit(target)

    def _remote_check_failed(self, target, association, epoch, message):
        if self._remote_result_current(target, association, epoch):
            setattr(self, f"{target}_health", "missing" if "404" in message or "已删除" in message else "failed")
            self._set_phase(target, CloudSyncPhase.FAILED, message=cloud_sync_user_message(message))
            self.stateChanged.emit()

    def _remember_preview(self, target, text):
        self.previews[target] = text

    def _remember_notice(self, title, text, kind):
        self.last_notice = (title, text, kind)
        self.notices[self._notice_target] = self.last_notice

    def notice_for(self, target):
        return self.notices.get(target) or self.notices.get(None)

    def _notify(self, target, title, text, kind):
        self._notice_target = target
        try:
            self.message.emit(title, text, kind)
        finally:
            self._notice_target = None
        self.stateChanged.emit()

    def _remember_question(self, title, callback):
        self.pending_question = (title, callback)

    def answer_question(self, mode):
        question, self.pending_question = self.pending_question, None
        if question and not self._closed:
            question[1](mode)

    def can_start(self, target):
        return not self.start_block_reason()

    def start_block_reason(self) -> str:
        """当前不能开始云端操作的原因；空串表示可以开始。

        纯查询、无副作用：它还兼作界面上的忙碌指示（``sync_pages`` 用它算按钮可用性），
        所以不能在这里弹提示。
        """
        if self._closed:
            return "云端同步会话已结束"
        if self.loading:
            return "正在加载同步设置，请稍候"
        if self.any_busy:
            return "已有云端任务正在进行，请等待完成"
        parent = self.parent()
        if getattr(parent, "_auto_sync_workers", {}):
            return "后台自动同步正在进行，请稍候"
        if parent is not None:
            for other in parent.findChildren(CloudSyncController):
                if other is not self and other._workers:
                    return "上一次云端会话尚未结束，请稍候"
        return ""

    def _refuse_start(self, target) -> None:
        """操作被 ``can_start`` 挡下时给出原因。

        原先各入口只是 ``return``，界面上表现为「点了没反应」，分不清是后台在忙还是按钮坏了。
        """
        reason = self.start_block_reason()
        if reason:
            self._notify(target, "无法开始", reason, "warn")


    @property
    def _live_vault(self) -> Vault:
        """始终返回当前活动保险库：对话框常驻期间主窗口可能因外部变更而重开库，
        旧引用会进入 close 状态（_pmve_store 为 None），直接读取 pmve_identity 会抛错。
        优先取父窗口的实时 vault，避免持有过期引用。"""
        parent = self.parent()
        live = getattr(parent, "vault", None)
        return live if live is not None else self._vault

    # ---------- 只读状态 ----------

    @property
    def drive_connected(self) -> bool:
        return self.drive_path is not None

    @property
    def webdav_connected(self) -> bool:
        return self.webdav_config is not None

    @property
    def any_busy(self) -> bool:
        return self.loading or bool(self._busy_targets) or bool(self._remote_checks)

    def is_busy(self, target: str) -> bool:
        return target in self._busy_targets

    # ---------- 阶段状态（对齐安卓 CloudSyncPhase） ----------

    def phase_of(self, target: str) -> CloudSyncPhase:
        return self._phase.get(target, CloudSyncPhase.IDLE)

    def status_state(self, target: str) -> str:
        """供视图着色的阶段标识：running / failed / idle。"""
        return self.phase_of(target).value

    def status_text(self, target: str) -> str:
        """状态行文案（对齐安卓 CloudSyncStatusLine）。"""
        phase = self.phase_of(target)
        source = "云端硬盘" if target == self.DRIVE else "WebDAV"
        if phase is CloudSyncPhase.RUNNING:
            return self._phase_message.get(target) or f"正在同步到 {source}…"
        if phase is CloudSyncPhase.FAILED:
            return self._phase_message.get(target) or f"{source}同步失败 · 请重试"
        last = self._last_success.get(target, 0.0)
        if last:
            stamp = datetime.datetime.fromtimestamp(last).strftime("%m-%d %H:%M")
            text = f"已同步并通过安全校验 · {stamp}"
            changed, uploaded = self._last_result.get(target, (0, False))
            if changed:
                text += " · 本地已更新"
            if uploaded:
                text += " · 已更新云端"
            return text
        return "尚未同步"

    def progress_of(self, target: str) -> float | None:
        return self._progress.get(target)

    def _set_phase(
        self,
        target: str,
        phase: CloudSyncPhase,
        *,
        message: str | None = None,
        progress: float | None = None,
    ) -> None:
        self._phase[target] = phase
        self._phase_message[target] = (message or "") if message is not None else self._phase_message.get(target, "")
        self._progress[target] = progress
        if phase is CloudSyncPhase.RUNNING:
            self.notices.pop(target, None)
            self.notices.pop(None, None)
            if message:
                self.previewChanged.emit(target, message)
        self.stateChanged.emit()

    def _mark_success(self, target: str, *, changed: int = 0, uploaded: bool = False) -> None:
        self._last_success[target] = datetime.datetime.now().timestamp()
        self._last_result[target] = (changed, uploaded)

    # ---------- 内部工具 ----------

    def _fresh_secret(self) -> crypto.SecureString:
        # 每个后台线程使用独立密码副本，线程结束后自行 clear，互不干扰。
        return self._password.clone()

    def _set_busy(self, target: str, busy: bool) -> None:
        if self.is_busy(target) == busy:
            return
        if busy:
            self._busy_targets.add(target)
        else:
            self._busy_targets.discard(target)
        self.busyChanged.emit(target, busy)
        self.stateChanged.emit()

    def _start(self, worker: QThread) -> None:
        if self._closed:
            worker.deleteLater()
            return
        self._workers.append(worker)
        worker.finished.connect(lambda w=worker: self._worker_finished(w))
        worker.start()

    def _worker_finished(self, worker):
        if worker in self._workers:
            self._workers.remove(worker)
        worker.deleteLater()
        if not self._closed:
            self.stateChanged.emit()
        if not self._workers:
            self.settled.emit()
            if self._closed:
                self.deleteLater()

    def cancel_active_operations(self, timeout_ms: int = 0) -> None:
        """End the session without blocking the UI or terminating a file write."""
        if self._closed:
            return
        self._closed = True
        self.pending_question = None
        self._password.clear()
        for worker in tuple(self._workers):
            worker.requestInterruption()
            # Disconnect the pipeline, retaining finished cleanup. An in-flight
            # atomic operation finishes normally but can no longer update a view.
            for name in ("completed", "failed", "previewReady", "verified", "replaced"):
                signal = getattr(worker, name, None)
                if signal is not None and worker.isSignalConnected(QMetaMethod.fromSignal(signal)):
                    signal.disconnect()
            if isinstance(worker, InteractiveCloudSyncWorker):
                worker.completed.connect(lambda payload: payload[1].close() if payload[1] is not None else None)
            elif isinstance(worker, DownloadReplaceWorker):
                worker.replaced.connect(lambda refreshed: refreshed.close())
            elif isinstance(worker, (CloudWorker, CloudDriveWorker)):
                worker.completed.connect(self._discard_download)
        self._busy_targets.clear()
        self.loading = False
        self.stateChanged.emit()
        if not self._workers:
            self.settled.emit()
            self.deleteLater()

    @staticmethod
    def _discard_download(action, snapshot):
        if action in {"pull_file", "push_file", "overwrite_file"}:
            path = getattr(snapshot, "path", None)
            if path is not None:
                name = Path(path).name
                if name.startswith(("vault-cloud-drive-download-", "vault-webdav-")) or ".download-" in name:
                    Path(path).unlink(missing_ok=True)

    def load_async(self):
        if self._closed or not isValid(self) or self.loaded or self.loading:
            return
        self.loading = True
        self.stateChanged.emit()
        try:
            worker = CloudSettingsWorker(self._cloud_vault_id, self._live_vault.pmve_identity.vault_id,
                                         bytearray(self._live_vault.root_key_for_device_unlock()), self)
            worker.completed.connect(self._settings_loaded)
            worker.failed.connect(self._settings_failed)
            self._start(worker)
        except Exception as exc:
            self._settings_failed(str(exc))

    def _settings_loaded(self, values):
        if self._closed:
            return
        self.drive_path, self.drive_revision, self.drive_logical_revision, self.webdav_config, self.drive_health = values
        self.webdav_health = "ok" if self.webdav_config else ""
        self.loading = False
        self.loaded = True
        self.check_remote_updates()
        self.previewChanged.emit(self.DRIVE, "已加载关联设置，点击同步或重新检测" if self.drive_path else "尚未关联云端硬盘")
        self.previewChanged.emit(self.WEBDAV, "已加载关联设置，点击同步或重新检测" if self.webdav_config else "尚未关联 WebDAV")
        self.stateChanged.emit()

    def _settings_failed(self, message):
        if self._closed:
            return
        self.loading = False
        self._notify(None, "无法加载同步设置", cloud_sync_user_message(message), "error")
        self.stateChanged.emit()

    @staticmethod
    def _has_data(snapshot) -> bool:
        return bool(
            snapshot
            and (
                (hasattr(snapshot, "data") and snapshot.data)
                or (getattr(snapshot, "exists", False) and getattr(snapshot, "size", -1) > 0)
            )
        )

    def _preview_remote_metadata(self, metadata: cloud.RemoteMetadata, source: str) -> str:
        del source
        checked = datetime.datetime.now().strftime("%H:%M:%S")
        if not metadata.exists or metadata.size == 0:
            return f"远端文件不存在\n最近检测：{checked}"
        return (
            f"远端文件存在（旧格式）\n远端大小：{metadata.size / 1024:.1f} KB\n"
            f"不使用文件时间判断，点击同步按内容合并 · 最近检测：{checked}"
        )

    def load(self) -> None:
        """从本机配置加载已保存的云端关联。"""
        self.drive_path = cloud.load_cloud_drive(self._cloud_vault_id)
        self.drive_revision = cloud.load_cloud_drive_revision(self._cloud_vault_id)
        self.drive_logical_revision = cloud.load_cloud_drive_logical_revision(self._cloud_vault_id)
        root_key = bytearray(self._live_vault.root_key_for_device_unlock())
        try:
            self.webdav_config = cloud.load_webdav(
                self._cloud_vault_id,
                vault_uuid=self._live_vault.pmve_identity.vault_id,
                root_key=bytes(root_key),
            )
        finally:
            root_key[:] = bytes(len(root_key))
        self.drive_health = "ok" if self.drive_path and self.drive_path.is_file() else ("missing" if self.drive_path else "")
        self.webdav_health = "ok" if self.webdav_config else ""
        self.loaded = True
        self.stateChanged.emit()

    # ---------- 检测（预览） ----------

    @staticmethod
    def _remote_revision_key(target: str, meta) -> str:
        """远端“版本指纹”，用于判断内容是否变化（与安卓先比版本再决定下载一致）。

        WebDAV 优先用强 ETag；无强 ETag 退回到 大小+Last-Modified（与 cloud.py 的
        ``_same_version`` 一致）。云端硬盘用 大小+mtime，因为本地文件没有 HTTP ETag。
        """
        if target == CloudSyncController.DRIVE:
            return f"d:{getattr(meta, 'size', -1)}:{getattr(meta, 'modified_at', 0.0)}"
        rev = getattr(meta, "revision", None)
        if rev:
            return rev
        return f"w:{getattr(meta, 'size', -1)}:{getattr(meta, 'modified_at', 0.0)}"

    def _remote_cache_hit(self, target: str, meta) -> bool:
        cached = self._remote_cache.get(target)
        return bool(cached) and cached[0] == self._remote_revision_key(target, meta)

    def _preview_from_remote(self, target: str, remote_identity, entry_count: int, remote_key_rev: int) -> str:
        """用已缓存的远端身份生成检测预览文本（不下载、不解密）。"""
        live = self._live_vault
        lineage = Vault.classify_lineage(live.pmve_identity, remote_identity)
        local_key_rev, _ = live.read_sync_key_meta(live.path)
        text = _preview_detail(
            lineage,
            local_seq=live.pmve_identity.sequence,
            remote_seq=remote_identity.sequence,
            local_key=local_key_rev,
            remote_key=remote_key_rev,
            local_active=len(live.entries),
            local_trash=len(live.trash),
            checked=datetime.datetime.now().strftime("%H:%M:%S"),
        )
        verified = self._remote_writer_lines.get(target)
        if verified and verified[0] == remote_identity.root_digest:
            text += "\n" + verified[1]
        else:
            text += "\n" + i18n.tr("最近写入设备：{name}").format(name=i18n.tr("未知设备"))
        return text

    def inspect_drive(self) -> None:
        if not self.can_start(self.DRIVE):
            self._refuse_start(self.DRIVE)
            return
        if self.drive_path is None:
            self.previewChanged.emit(self.DRIVE, "尚未关联云端硬盘")
            return
        self.previewChanged.emit(self.DRIVE, "正在检测云端保险库数据…")
        self._set_phase(self.DRIVE, CloudSyncPhase.RUNNING, message="正在检测云端保险库数据…")
        self._set_busy(self.DRIVE, True)
        worker = CloudDriveWorker("inspect", self.drive_path, parent=self)
        worker.completed.connect(lambda _action, result: self._drive_inspected(result))
        worker.failed.connect(lambda msg: self._preview_failed(self.DRIVE, msg))
        self._start(worker)

    def inspect_webdav(self) -> None:
        if not self.can_start(self.WEBDAV):
            self._refuse_start(self.WEBDAV)
            return
        if self.webdav_config is None:
            self.previewChanged.emit(self.WEBDAV, "尚未关联 WebDAV")
            return
        self.previewChanged.emit(self.WEBDAV, "正在检测 WebDAV 远端数据…")
        self._set_phase(self.WEBDAV, CloudSyncPhase.RUNNING, message="正在检测 WebDAV 远端数据…")
        self._set_busy(self.WEBDAV, True)
        worker = CloudWorker("inspect", self.webdav_config, None, parent=self)
        worker.completed.connect(lambda _action, result: self._webdav_inspected(result))
        worker.failed.connect(lambda msg: self._preview_failed(self.WEBDAV, msg))
        self._start(worker)

    def _drive_inspected(self, metadata) -> None:
        if self._closed:
            return
        try:
            if metadata.exists and metadata.size > 0:
                # 远端自上次检测未变化：复用已认证身份，跳过整库下载与解密。
                if self._remote_cache_hit(self.DRIVE, metadata):
                    cached = self._remote_cache[self.DRIVE]
                    self.previewChanged.emit(self.DRIVE, self._preview_from_remote(self.DRIVE, *cached[1:]))
                    self.drive_health = "ok"
                    self._set_busy(self.DRIVE, False)
                    return
                self.previewChanged.emit(self.DRIVE, "正在认证远端 PMVE 数据…")
                self._pull_and_preview(self.DRIVE, "云端硬盘")
                return
            self.previewChanged.emit(self.DRIVE, self._preview_remote_metadata(metadata, "云端硬盘"))
            self.drive_health = "missing" if not metadata.exists else "ok"
        except Exception as exc:  # noqa: BLE001
            self.drive_health = "failed"
            self.previewChanged.emit(self.DRIVE, f"远端检测失败\n{exc}")
        self._set_busy(self.DRIVE, False)

    def _webdav_inspected(self, metadata) -> None:
        if self._closed:
            return
        try:
            source = self.webdav_config.label if self.webdav_config else "WebDAV"
            if metadata.exists and metadata.size > 0:
                # 远端自上次检测未变化：复用已认证身份，跳过整库下载与解密。
                if self._remote_cache_hit(self.WEBDAV, metadata):
                    cached = self._remote_cache[self.WEBDAV]
                    self.previewChanged.emit(self.WEBDAV, self._preview_from_remote(self.WEBDAV, *cached[1:]))
                    self.webdav_health = "ok"
                    self._set_busy(self.WEBDAV, False)
                    return
                self.previewChanged.emit(self.WEBDAV, "正在认证远端 PMVE 数据…")
                self._pull_and_preview(self.WEBDAV, source)
                return
            self.previewChanged.emit(self.WEBDAV, self._preview_remote_metadata(metadata, source))
            self.webdav_health = "missing" if not metadata.exists else "ok"
        except Exception as exc:  # noqa: BLE001
            self.webdav_health = "failed"
            self.previewChanged.emit(self.WEBDAV, f"远端检测失败\n{exc}")
        self._set_busy(self.WEBDAV, False)

    def _pull_and_preview(self, target: str, source: str) -> None:
        if target == self.DRIVE and self.drive_path is None:
            worker = None
        elif target == self.WEBDAV and self.webdav_config is None:
            worker = None
        elif target == self.DRIVE:
            worker = CloudDriveWorker("pull_file", self.drive_path, parent=self)
        else:
            worker = CloudWorker("pull_file", self.webdav_config, None, parent=self)
        if worker is None:
            # 检测期间关联被清掉：这里若不收尾，busy 会永远为真，
            # 界面上就是「一直正在检测…且按钮全灰」。
            self._preview_failed(target, "关联已失效，请重新关联后再检测")
            return
        worker.completed.connect(lambda _action, result: self._preview_pulled(target, source, result))
        worker.failed.connect(lambda msg: self._preview_failed(target, msg))
        self._start(worker)

    def _preview_pulled(self, target: str, source: str, snapshot) -> None:
        if self._closed:
            self._discard_download("pull_file", snapshot)
            return
        if snapshot is None or not snapshot.exists or not getattr(snapshot, "path", None):
            self.previewChanged.emit(target, "远端文件不存在或为空")
            setattr(self, f"{target}_health", "missing")
            self._set_busy(target, False)
            return
        # 用实际下载文件的版本指纹作为缓存键，与 inspect 阶段的元数据指纹保持一致。
        revision_key = self._remote_revision_key(target, snapshot)
        worker = RemotePreviewWorker(
            self._vault_path,
            self._fresh_secret(),
            Path(snapshot.path),
            local_identity=self._live_vault.pmve_identity,
            parent=self,
        )
        worker.previewReady.connect(
            lambda text, identity, entry_count, remote_key_rev, t=target, k=revision_key: self._preview_ready(
                t, text, identity, entry_count, remote_key_rev, k
            )
        )
        worker.failed.connect(lambda msg, t=target: self._preview_failed(t, msg))
        self._start(worker)

    def _preview_ready(self, target: str, text: str, remote_identity, entry_count: int, remote_key_rev: int, revision_key: str) -> None:
        if self._closed:
            return
        self._remote_cache[target] = (revision_key, remote_identity, entry_count, remote_key_rev)
        prefix = i18n.tr("最近写入设备：{name}").split("{name}")[0]
        writer_line = next((line for line in text.splitlines() if line.startswith(prefix)), None)
        if writer_line is not None:
            self._remote_writer_lines[target] = (remote_identity.root_digest, writer_line)
        setattr(self, f"{target}_health", "ok")
        self.previewChanged.emit(target, text)
        self._set_phase(target, CloudSyncPhase.IDLE, message="")
        self._set_busy(target, False)

    def _preview_failed(self, target: str, message: str) -> None:
        if self._closed:
            return
        setattr(self, f"{target}_health", "failed")
        detail = cloud_sync_user_message(message)
        self.previewChanged.emit(target, f"远端检测失败\n{detail}")
        self._set_phase(target, CloudSyncPhase.FAILED, message=detail)
        self._set_busy(target, False)

    # ---------- 手动同步 ----------

    def sync_drive(self, target: Path, *, associated: bool) -> None:
        if not self.can_start(self.DRIVE):
            self._refuse_start(self.DRIVE)
            return
        self.previewChanged.emit(self.DRIVE, "正在后台同步，窗口可继续操作…")
        self._set_phase(self.DRIVE, CloudSyncPhase.RUNNING, message="正在同步到云端硬盘…")
        worker = InteractiveCloudSyncWorker(
            self._vault_path,
            self._fresh_secret(),
            "drive",
            target,
            allow_missing=associated,
            parent=self,
        )
        worker.completed.connect(lambda payload: self._sync_ok(target, self.DRIVE, associated, payload))
        worker.failed.connect(lambda msg: self._sync_failed(self.DRIVE, associated, msg))
        self._set_busy(self.DRIVE, True)
        self._start(worker)

    def sync_webdav(self, connection: cloud.WebDavConfig, *, associated: bool) -> None:
        if not self.can_start(self.WEBDAV):
            self._refuse_start(self.WEBDAV)
            return
        self.previewChanged.emit(self.WEBDAV, "正在后台同步，窗口可继续操作…")
        self._set_phase(self.WEBDAV, CloudSyncPhase.RUNNING, message="正在同步到 WebDAV…")
        worker = InteractiveCloudSyncWorker(
            self._vault_path,
            self._fresh_secret(),
            "webdav",
            connection,
            allow_missing=associated,
            parent=self,
        )
        worker.completed.connect(lambda payload: self._sync_ok(connection, self.WEBDAV, associated, payload))
        worker.failed.connect(lambda msg: self._sync_failed(self.WEBDAV, associated, msg))
        self._set_busy(self.WEBDAV, True)
        self._start(worker)

    def _sync_ok(self, target_ref, target: str, associated: bool, payload) -> None:
        result, refreshed, metadata = payload
        if self._closed:
            if refreshed is not None:
                refreshed.close()
            return
        notice = ""
        if target == self.DRIVE:
            if associated:
                self.drive_path = Path(target_ref)
            if metadata is not None:
                self.drive_revision = metadata.revision
                cloud.save_cloud_drive(self._cloud_vault_id, self.drive_path)
                cloud.save_cloud_drive_sync(self._cloud_vault_id, revision=metadata.revision)
        else:
            if associated:
                root_key = bytearray(self._live_vault.root_key_for_device_unlock())
                try:
                    cloud.save_webdav(
                        self._cloud_vault_id, target_ref,
                        vault_uuid=self._live_vault.pmve_identity.vault_id,
                        root_key=bytes(root_key),
                    )
                finally:
                    root_key[:] = bytes(len(root_key))
                self.webdav_config = target_ref
        self.acknowledge_remote_update(target, result.stats.get("remote_update_version", ""),
                                       result.stats.get("remote_update_consumed_version", ""))
        if refreshed is not None:
            self._vault = refreshed
            # 视图负责关闭旧库并刷新列表；即使刷新失败也不阻塞同步状态。
            try:
                self.vaultReplaced.emit(refreshed)
            except Exception as exc:  # noqa: BLE001
                notice = f"\n主界面刷新失败：{exc}"
        setattr(self, f"{target}_health", "ok")
        self._mark_success(target, changed=1 if result.changed else 0, uploaded=bool(result.uploaded))
        self._set_phase(target, CloudSyncPhase.IDLE, message="")
        self._set_busy(target, False)
        message = (
            "已同步并通过安全校验 · 云端已更新"
            if result.uploaded
            else "已同步并通过安全校验 · 已保存云端的新内容"
            if result.changed
            else "已同步并通过安全校验 · 双方内容一致"
        )
        self.previewChanged.emit(target, message + notice)
        source = "云端硬盘" if target == self.DRIVE else "WebDAV"
        self._notify(target, f"{source}同步完成", message + notice, "success" if not notice else "warn")

    def _sync_failed(self, target: str, associated: bool, message: str) -> None:
        if self._closed:
            return
        if not associated:
            setattr(self, f"{target}_health", "failed")
        detail = cloud_sync_user_message(message)
        self._set_phase(target, CloudSyncPhase.FAILED, message=detail)
        self._set_busy(target, False)
        self.previewChanged.emit(target, f"同步未完成\n{detail}")
        source = "云端硬盘" if target == self.DRIVE else "WebDAV"
        self._notify(target, f"{source}同步未完成", detail, "error")

    # ---------- 上传覆盖 ----------

    def overwrite_drive(self, target: Path, *, associated: bool) -> None:
        if not self.can_start(self.DRIVE):
            self._refuse_start(self.DRIVE)
            return
        self._overwrite_update_inputs[self.DRIVE] = (self._update_association(self.DRIVE), self._remote_epochs[self.DRIVE], self.remote_update_state(self.DRIVE).pending)
        self._vault.save()
        worker = CloudDriveWorker("overwrite_file", target, self._vault.path, parent=self)
        worker.completed.connect(lambda _action, snap: self._overwrite_pulled(self.DRIVE, target, associated, snap))
        worker.failed.connect(lambda msg: self._overwrite_failed(self.DRIVE, associated, msg))
        self._set_phase(self.DRIVE, CloudSyncPhase.RUNNING, message="正在上传覆盖云端…")
        self._set_busy(self.DRIVE, True)
        self._start(worker)

    def overwrite_webdav(self, connection: cloud.WebDavConfig, *, associated: bool) -> None:
        if not self.can_start(self.WEBDAV):
            self._refuse_start(self.WEBDAV)
            return
        self._overwrite_update_inputs[self.WEBDAV] = (self._update_association(self.WEBDAV), self._remote_epochs[self.WEBDAV], self.remote_update_state(self.WEBDAV).pending)
        self._vault.save()
        worker = CloudWorker("overwrite_file", connection, (self._vault.path, None), parent=self)
        worker.completed.connect(lambda _action, snap: self._overwrite_pulled(self.WEBDAV, connection, associated, snap))
        worker.failed.connect(lambda msg: self._overwrite_failed(self.WEBDAV, associated, msg))
        self._set_phase(self.WEBDAV, CloudSyncPhase.RUNNING, message="正在上传覆盖云端…")
        self._set_busy(self.WEBDAV, True)
        self._start(worker)

    def _overwrite_pulled(self, target: str, target_ref, associated: bool, snapshot) -> None:
        if self._closed:
            self._discard_download("pull_file", snapshot)
            return
        if snapshot is None or not snapshot.exists or not getattr(snapshot, "path", None):
            self._overwrite_failed(target, associated, "上传后远端文件不存在")
            return
        # 回读文件在后台认证，避免主线程卡在 PMVE 解密上。
        worker = RemoteVerifyWorker(
            self._vault_path,
            self._fresh_secret(),
            Path(snapshot.path),
            parent=self,
        )
        worker.verified.connect(
            lambda identity: self._overwrite_verified(target, target_ref, associated, snapshot, identity)
        )
        worker.failed.connect(lambda msg: self._overwrite_failed(target, associated, msg))
        self._start(worker)

    def _overwrite_verified(self, target: str, target_ref, associated: bool, snapshot, identity) -> None:
        if self._closed:
            return
        try:
            if self._vault.classify_lineage(self._live_vault.pmve_identity, identity) is not VaultLineage.SAME:
                raise cloud.CloudError("PMVE 上传后回读 Identity 不一致")
            if target == self.DRIVE:
                if associated:
                    self.drive_path = Path(target_ref)
                self.drive_revision = snapshot.revision
                cloud.save_cloud_drive(self._cloud_vault_id, self.drive_path)
                cloud.save_cloud_drive_sync(self._cloud_vault_id, revision=snapshot.revision)
            else:
                if associated:
                    root_key = bytearray(self._live_vault.root_key_for_device_unlock())
                    try:
                        cloud.save_webdav(
                            self._cloud_vault_id, target_ref,
                            vault_uuid=self._live_vault.pmve_identity.vault_id,
                            root_key=bytes(root_key),
                        )
                    finally:
                        root_key[:] = bytes(len(root_key))
                    self.webdav_config = target_ref
            setattr(self, f"{target}_health", "ok")
            association, epoch, pending = self._overwrite_update_inputs.pop(target, ("", -1, ""))
            consumed = pending if association == self._update_association(target) and epoch == self._remote_epochs[target] else ""
            self.acknowledge_remote_update(target, remote_update.metadata_version(target, snapshot), consumed)
            self._mark_success(target, changed=1, uploaded=True)
            self._set_phase(target, CloudSyncPhase.IDLE, message="")
            self._set_busy(target, False)
            self._notify(target, "上传完成", "远端文件已覆盖并通过回读校验。", "success")
            self.inspect_drive() if target == self.DRIVE else self.inspect_webdav()
        except Exception as exc:  # noqa: BLE001
            self._overwrite_failed(target, associated, str(exc))

    def _overwrite_failed(self, target: str, associated: bool, message: str) -> None:
        self._overwrite_update_inputs.pop(target, None)
        if self._closed:
            return
        if not associated:
            setattr(self, f"{target}_health", "failed")
        detail = cloud_sync_user_message(message)
        self._set_phase(target, CloudSyncPhase.FAILED, message=detail)
        self._set_busy(target, False)
        source = "云端硬盘" if target == self.DRIVE else "WebDAV"
        self._notify(target, f"写入{source}失败", detail, "error")

    # ---------- 下载覆盖 ----------

    def download_drive(self, target: Path) -> None:
        if not self.can_start(self.DRIVE):
            self._refuse_start(self.DRIVE)
            return
        self._set_phase(self.DRIVE, CloudSyncPhase.RUNNING, message="正在下载覆盖本地…")
        self._set_busy(self.DRIVE, True)
        worker = CloudDriveWorker("pull_file", target, parent=self)
        worker.completed.connect(lambda _action, snap: self._download_pulled(self.DRIVE, target, snap))
        worker.failed.connect(lambda msg: self._download_failed(self.DRIVE, msg))
        self._start(worker)

    def download_webdav(self, connection: cloud.WebDavConfig) -> None:
        if not self.can_start(self.WEBDAV):
            self._refuse_start(self.WEBDAV)
            return
        self._set_phase(self.WEBDAV, CloudSyncPhase.RUNNING, message="正在下载覆盖本地…")
        self._set_busy(self.WEBDAV, True)
        worker = CloudWorker("pull_file", connection, None, parent=self)
        worker.completed.connect(lambda _action, snap: self._download_pulled(self.WEBDAV, connection, snap))
        worker.failed.connect(lambda msg: self._download_failed(self.WEBDAV, msg))
        self._start(worker)

    def _download_pulled(self, target: str, target_ref, snapshot) -> None:
        if self._closed:
            self._discard_download("pull_file", snapshot)
            return
        if snapshot is None or not snapshot.exists or not getattr(snapshot, "path", None):
            self._download_failed(target, "云端保险库文件不存在或为空")
            return
        worker = DownloadReplaceWorker(
            self._vault_path,
            self._fresh_secret(),
            Path(snapshot.path),
            force=True,
            parent=self,
        )
        worker.replaced.connect(lambda refreshed: self._download_replaced(target, target_ref, snapshot, refreshed))
        worker.failed.connect(lambda msg: self._download_failed(target, msg))
        self._start(worker)

    def _download_replaced(self, target: str, target_ref, snapshot, refreshed) -> None:
        if self._closed:
            refreshed.close()
            return
        try:
            if target == self.DRIVE:
                self.drive_revision = snapshot.revision
                cloud.save_cloud_drive(self._cloud_vault_id, Path(target_ref))
                cloud.save_cloud_drive_sync(self._cloud_vault_id, revision=snapshot.revision)
            setattr(self, f"{target}_health", "ok")
            self.acknowledge_remote_update(target, remote_update.metadata_version(target, snapshot))
            self._mark_success(target)
            self._set_phase(target, CloudSyncPhase.IDLE, message="")
            self._set_busy(target, False)
            self._vault = refreshed
            self.vaultReplaced.emit(refreshed)
            source = "云端硬盘" if target == self.DRIVE else "WebDAV"
            self._notify(target,
                "下载完成",
                "本地保险库已被远端 PMVE 版本覆盖，并已保留 .sync.bak 备份。",
                "success",
            )
            self.inspect_drive() if target == self.DRIVE else self.inspect_webdav()
        except Exception as exc:  # noqa: BLE001
            self._download_failed(target, str(exc))

    def _download_failed(self, target: str, message: str) -> None:
        if self._closed:
            return
        setattr(self, f"{target}_health", "failed")
        detail = cloud_sync_user_message(message)
        self._set_phase(target, CloudSyncPhase.FAILED, message=detail)
        self._set_busy(target, False)
        self._notify(target, "下载覆盖失败", f"本地数据已保留：{detail}", "error")

    # ---------- 关联 ----------

    def associate_drive(self, target: Path) -> None:
        """目标文件已由视图解析，控制器负责检测远端并决定后续动作。"""
        if not self.can_start(self.DRIVE):
            self._refuse_start(self.DRIVE)
            return
        self._set_phase(self.DRIVE, CloudSyncPhase.RUNNING, message="正在连接云端硬盘…")
        self._set_busy(self.DRIVE, True)
        worker = CloudDriveWorker("inspect", target, parent=self)
        worker.completed.connect(lambda _action, result: self._drive_associate_inspected(target, result))
        worker.failed.connect(lambda msg: self._drive_associate_failed(msg))
        self._start(worker)

    def _drive_associate_inspected(self, target: Path, snapshot) -> None:
        if self._closed:
            return
        self._set_busy(self.DRIVE, False)
        if self._has_data(snapshot):
            self.askExistingRemote.emit(
                "云端已有保险库数据",
                lambda mode: self._drive_continue_association(target, mode),
            )
        else:
            self.sync_drive(target, associated=True)

    def _drive_continue_association(self, target: Path, mode: str | None) -> None:
        if mode == "merge":
            self.sync_drive(target, associated=True)
        elif mode == "overwrite":
            self.overwrite_drive(target, associated=True)
        elif mode == "download":
            self.download_drive(target)

    def _drive_associate_failed(self, message: str) -> None:
        if self._closed:
            return
        detail = cloud_sync_user_message(message)
        self._set_phase(self.DRIVE, CloudSyncPhase.FAILED, message=detail)
        self._set_busy(self.DRIVE, False)
        self._notify(self.DRIVE, "关联失败", detail, "error")

    def associate_webdav(self, connection: cloud.WebDavConfig) -> None:
        """连接已由视图构建，控制器负责测试远端并决定后续动作。"""
        if not self.can_start(self.WEBDAV):
            self._refuse_start(self.WEBDAV)
            return
        self._set_phase(self.WEBDAV, CloudSyncPhase.RUNNING, message="正在连接 WebDAV…")
        self._set_busy(self.WEBDAV, True)
        worker = CloudWorker("connect", connection, None, parent=self)
        worker.completed.connect(lambda _action, result: self._webdav_associate_tested(connection, result))
        worker.failed.connect(lambda msg: self._webdav_associate_failed(msg))
        self._start(worker)

    def _webdav_associate_tested(self, connection: cloud.WebDavConfig, snapshot) -> None:
        if self._closed:
            return
        self._set_busy(self.WEBDAV, False)
        if self._has_data(snapshot):
            self.askExistingRemote.emit(
                "远端已有保险库数据",
                lambda mode: self._webdav_continue_association(connection, mode),
            )
        else:
            self.sync_webdav(connection, associated=True)

    def _webdav_continue_association(self, connection: cloud.WebDavConfig, mode: str | None) -> None:
        if mode == "merge":
            self.sync_webdav(connection, associated=True)
        elif mode == "overwrite":
            self.overwrite_webdav(connection, associated=True)
        elif mode == "download":
            self.download_webdav(connection)

    def _webdav_associate_failed(self, message: str) -> None:
        if self._closed:
            return
        detail = cloud_sync_user_message(message)
        self._set_phase(self.WEBDAV, CloudSyncPhase.FAILED, message=detail)
        self._set_busy(self.WEBDAV, False)
        self._notify(self.WEBDAV, "连接失败", detail, "error")

    # ---------- 取消关联 ----------

    def clear_drive(self) -> None:
        if not self.can_start(self.DRIVE):
            self._refuse_start(self.DRIVE)
            return
        self.set_remote_detection(self.DRIVE, False)
        cloud.clear_cloud_drive(self._cloud_vault_id)
        self.drive_path = None
        self.drive_revision = None
        self.drive_logical_revision = None
        self.drive_health = ""
        self._remote_cache.pop(self.DRIVE, None)
        self._phase[self.DRIVE] = CloudSyncPhase.IDLE
        self._phase_message[self.DRIVE] = ""
        self._last_success.pop(self.DRIVE, None)
        self._last_result.pop(self.DRIVE, None)
        self.previewChanged.emit(self.DRIVE, "尚未关联云端硬盘")
        self._notify(self.DRIVE, "已取消关联", "已取消云端硬盘关联，本地和云端文件均已保留。", "success")
        self.stateChanged.emit()

    def clear_webdav(self) -> None:
        if not self.can_start(self.WEBDAV):
            self._refuse_start(self.WEBDAV)
            return
        self.set_remote_detection(self.WEBDAV, False)
        cloud.clear_webdav(self._cloud_vault_id)
        self.webdav_config = None
        self.webdav_health = ""
        self._remote_cache.pop(self.WEBDAV, None)
        self._phase[self.WEBDAV] = CloudSyncPhase.IDLE
        self._phase_message[self.WEBDAV] = ""
        self._last_success.pop(self.WEBDAV, None)
        self._last_result.pop(self.WEBDAV, None)
        self.previewChanged.emit(self.WEBDAV, "尚未关联 WebDAV")
        self._notify(self.WEBDAV, "已取消关联", "已取消 WebDAV 关联，本地和远端文件均已保留。", "success")
        self.stateChanged.emit()
