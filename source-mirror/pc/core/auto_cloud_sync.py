"""Headless cloud synchronization used by the unlocked-session scheduler."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import cloud
from .cloud_sync_prefs import INTERVALS as INTERVAL_MINUTES  # noqa: F401 - compatibility export
from .cloud_sync_prefs import is_due  # noqa: F401 - compatibility export
from .storage import Vault, VaultLineage


@dataclass(frozen=True)
class AutoSyncResult:
    target: str
    uploaded: bool
    changed: bool
    stats: dict












def _acknowledged_result(target, uploaded, changed, stats, snapshot) -> AutoSyncResult:
    from .remote_update import metadata_version
    acknowledged = dict(stats)
    token = metadata_version(target, snapshot)
    if token:
        acknowledged["remote_update_version"] = token
    return AutoSyncResult(target, uploaded, changed, acknowledged)


def _sync_pmve_files(
    vault: Vault,
    target: str,
    download,
    upload,
    *,
    allow_missing: bool = False,
) -> AutoSyncResult:
    """Reconcile one PMVE file using authenticated Commit ancestry and CAS retries."""

    cas_retries = 0
    for attempt in range(3):
        descriptor, name = tempfile.mkstemp(prefix="vault-cloud-pmve-", suffix=".pmv")
        os.close(descriptor)
        temporary = Path(name)
        try:
            snapshot = download(temporary)
            if snapshot is None:
                if not allow_missing:
                    raise cloud.CloudError("关联的云端文件已删除，同步已暂停")
                snapshot = cloud.RemoteFileSnapshot(temporary, None, False, 0.0, 0)
                lineage = VaultLineage.REMOTE_STALE
            else:
                try:
                    remote_identity = vault.authenticate_external_file(snapshot.path)
                except Exception as exc:
                    raise cloud.CloudError("远端 PMVE 身份或签名认证失败") from exc
                lineage = vault.classify_lineage(vault.pmve_identity, remote_identity)

            stats = {"lineage": lineage.value, "cas_retries": cas_retries}
            from .remote_update import metadata_version
            consumed_version = metadata_version(target, snapshot)
            if consumed_version:
                stats["remote_update_consumed_version"] = consumed_version
            if lineage is VaultLineage.SAME:
                return _acknowledged_result(target, False, False, stats, snapshot)
            if lineage is VaultLineage.FAST_FORWARD:
                vault.replace_authenticated_file(snapshot.path)
                # Re-opened identity must still equal the authenticated snapshot Head.
                if vault.classify_lineage(vault.pmve_identity, remote_identity) is not VaultLineage.SAME:
                    raise cloud.CloudError("PMVE 本地安装后 Identity 复验失败")
                return _acknowledged_result(target, False, True, stats, snapshot)
            if lineage is VaultLineage.REMOTE_STALE:
                try:
                    vault.compact_before_sync()
                except Exception:
                    pass
                try:
                    upload(vault.path, snapshot)
                except cloud.CloudConflict:
                    # A timed-out/failed publish may nevertheless have committed.  Read
                    # back before retrying so an unknown result is classified safely.
                    committed = download(temporary)
                    if committed is not None:
                        try:
                            committed_identity = vault.authenticate_external_file(committed.path)
                        except Exception:
                            committed_identity = None
                        if Vault.classify_lineage(vault.pmve_identity, committed_identity) is VaultLineage.SAME:
                            stats["cas_retries"] = cas_retries
                            return _acknowledged_result(target, True, False, stats, committed)
                    cas_retries += 1
                    if attempt == 2:
                        raise cloud.CloudConflict("PMVE CAS 连续竞争，请稍后重试")
                    continue
                verified = download(temporary)
                if verified is None:
                    raise cloud.CloudError("PMVE 上传后远端文件消失")
                try:
                    verified_identity = vault.authenticate_external_file(verified.path)
                except Exception as exc:
                    raise cloud.CloudError("PMVE 上传后文件身份认证失败") from exc
                if vault.classify_lineage(vault.pmve_identity, verified_identity) is not VaultLineage.SAME:
                    raise cloud.CloudError("PMVE 上传后回读 Identity 不一致")
                stats["cas_retries"] = cas_retries
                return _acknowledged_result(target, True, False, stats, verified)
            if lineage is VaultLineage.DIVERGED:
                # 自动收敛：以远端 Head 为基线提交合并内容（条目 LWW + 密钥版本/注册表
                # union），原子采纳为本地库，再上传同一文件让远端快速前进。
                merged_identity = vault.merge_and_adopt_authenticated_file(
                    snapshot.path,
                    adopt_local=False,
                )
                try:
                    upload(snapshot.path, snapshot)
                except cloud.CloudConflict:
                    committed = download(temporary)
                    if committed is not None:
                        try:
                            committed_identity = vault.authenticate_external_file(committed.path)
                        except Exception:
                            committed_identity = None
                        if Vault.classify_lineage(merged_identity, committed_identity) is VaultLineage.SAME:
                            installed = vault.replace_authenticated_file(snapshot.path, force=True)
                            if Vault.classify_lineage(installed, committed_identity) is not VaultLineage.SAME:
                                raise cloud.CloudError("PMVE 合并本地安装后 Identity 复验失败")
                            stats["cas_retries"] = cas_retries
                            return _acknowledged_result(target, True, True, stats, committed)
                    # 合并期间远端又被更新：重拉最新远端并以新 Head 再合并，
                    # 合并与密钥收敛是确定性的，有界重试后仍冲突才失败。
                    cas_retries += 1
                    if attempt == 2:
                        raise cloud.CloudConflict("PMVE CAS 连续竞争，请稍后重试")
                    continue
                verified = download(temporary)
                if verified is None:
                    raise cloud.CloudError("PMVE 合并上传后远端文件消失")
                try:
                    verified_identity = vault.authenticate_external_file(verified.path)
                except Exception as exc:
                    raise cloud.CloudError("PMVE 合并上传后文件身份认证失败") from exc
                if Vault.classify_lineage(merged_identity, verified_identity) is not VaultLineage.SAME:
                    raise cloud.CloudError("PMVE 合并上传后回读 Identity 不一致")
                # 远端已确认精确提交后，才原子安装到当前会话。
                installed = vault.replace_authenticated_file(snapshot.path, force=True)
                if Vault.classify_lineage(installed, verified_identity) is not VaultLineage.SAME:
                    raise cloud.CloudError("PMVE 合并本地安装后 Identity 复验失败")
                stats["cas_retries"] = cas_retries
                return _acknowledged_result(target, True, True, stats, verified)
            if lineage is VaultLineage.DIFFERENT:
                raise cloud.CloudError("远端 PMVE 不是同一保险库或签名者")
            raise cloud.CloudError("远端 PMVE Identity 无效")
        finally:
            temporary.unlink(missing_ok=True)
    raise cloud.CloudConflict("PMVE CAS 连续竞争，请稍后重试")


def _open_with_password(vault_path: Path, password: str | bytearray) -> Vault:
    return (
        Vault.open_with_password_buffer(vault_path, password)
        if type(password) is bytearray
        else Vault.open(vault_path, password)
    )


def sync_drive(vault_path: Path, password: str | bytearray, target: Path) -> AutoSyncResult:
    vault = _open_with_password(vault_path, password)
    try:
        if not cloud.cloud_drive_metadata(target).exists:
            raise cloud.CloudError("关联的云端文件已删除，自动同步已暂停")
        return _sync_pmve_files(
            vault,
            "drive",
            lambda temporary: cloud.read_cloud_drive_to(target, temporary, allow_missing=True),
            lambda source, expected: cloud.write_cloud_drive_file(target, source, expected=expected),
            # Desktop sync-folder writes compare the downloaded content hash
            # again immediately before atomic replacement, matching Android's
            # identity-before-write fallback when a provider has no ETag CAS.
        )
    finally:
        vault.close()


def sync_webdav(
    vault_path: Path,
    password: str | bytearray,
    connection: cloud.WebDavConfig,
    *,
    allow_missing: bool = False,
) -> AutoSyncResult:
    """Reconcile one WebDAV file.

    ``allow_missing`` 由交互式手动同步传入：远端文件不存在时按新建处理，
    自动同步则保持 False，让缺失触发"云端文件已删除，同步已暂停"。
    """
    vault = _open_with_password(vault_path, password)
    try:
        client = cloud.WebDavClient(connection)
        return _sync_pmve_files(
            vault,
            "webdav",
            client.download_to_if_exists,
            client.upload_file_if_unchanged,
            allow_missing=allow_missing,
            # Android supports WebDAV providers without a strong ETag by
            # re-reading the remote file before publish.  WebDavClient applies
            # the equivalent content check for desktop below.
        )
    finally:
        vault.close()


def sync_drive_manual(
    vault_path: Path,
    password: str | bytearray,
    target: Path,
    *,
    allow_missing: bool = False,
) -> AutoSyncResult:
    """Run the complete interactive drive reconciliation away from the UI thread."""

    vault = _open_with_password(vault_path, password)
    try:
        return _sync_pmve_files(
            vault,
            "drive",
            lambda temporary: cloud.read_cloud_drive_to(target, temporary, allow_missing=True),
            lambda source, expected: cloud.write_cloud_drive_file(target, source, expected=expected),
            allow_missing=allow_missing,
            # A desktop sync folder has no server ETag, but its writer still checks
            # the file revision immediately before atomic replacement.
        )
    finally:
        vault.close()
