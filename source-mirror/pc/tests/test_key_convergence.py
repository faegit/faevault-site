"""同库同步自动收敛：密钥/密码版本按更新时间自动选择，不再人工选择。"""

import shutil
import uuid
from pathlib import Path

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import pmv_device_registry, pmv_sync_authorization
from core.pmv_vault_store import PmvVaultStore
from core.storage import Vault, _read_logical_key_revision, remote_key_version_newer


PASSWORD = "correct horse battery staple"
RECOVERY = bytes(range(32))
NEW_PASSWORD = "new correct horse battery staple"


@pytest.mark.parametrize(
    ("sync_value", "expected"),
    [(3, 3), (0, 0)],
)
def test_logical_key_revision_prefers_sync_metadata(sync_value, expected):
    assert _read_logical_key_revision(
        {"key_revision": 9, "sync_meta": {"key_revision": sync_value}}
    ) == expected


def test_logical_key_revision_falls_back_only_when_sync_field_is_absent():
    assert _read_logical_key_revision({"key_revision": 4, "sync_meta": {}}) == 4


@pytest.mark.parametrize("bad_value", [None, True, -1, 1.5, "2", 1 << 31])
def test_logical_key_revision_rejects_values_android_rejects(bad_value):
    with pytest.raises(ValueError):
        _read_logical_key_revision(
            {"key_revision": 4, "sync_meta": {"key_revision": bad_value}}
        )


def test_sync_key_meta_reads_logical_revision_not_header_revision(tmp_path):
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.change_password(NEW_PASSWORD)
    assert vault.key_revision == 2
    assert vault.pmve_identity.key_revision == 1
    revision, updated_at = vault.read_sync_key_meta(path)
    assert revision == 2
    assert updated_at > 0
    vault.close()


def _public_key(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def test_remote_key_version_newer_prefers_update_time():
    # 时间优先：远端更新时间更新 → True，即使远端版本号更低。
    assert remote_key_version_newer(5, 100.0, 3, 200.0)
    assert not remote_key_version_newer(3, 200.0, 5, 100.0)
    # 时间缺失/相等 → 退回版本号。
    assert remote_key_version_newer(1, 0.0, 2, 0.0)
    assert not remote_key_version_newer(2, 0.0, 1, 0.0)
    # 一端缺少时间戳、另一端已盖章 → 有盖章的一端更新。
    assert remote_key_version_newer(1, 0.0, 1, 200.0)
    assert not remote_key_version_newer(1, 200.0, 1, 0.0)
    # 完全相等 → 保留本端（确定性）。
    assert not remote_key_version_newer(2, 300.0, 2, 300.0)
    assert not remote_key_version_newer(2, 0.0, 2, 0.0)


def test_pmve_change_password_stamps_key_updated_at(tmp_path):
    path = tmp_path / "v.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    # 创建保险库即生成恢复密钥，应盖章创建时间（不再显示“未知时间”）。
    assert vault.key_updated_at > 0.0
    created = vault.key_updated_at
    vault.change_password(NEW_PASSWORD)
    # 改密后更新时间应前进。
    assert vault.key_updated_at > created
    vault.close()

    reopened = Vault.open(path, NEW_PASSWORD)
    try:
        assert reopened.key_updated_at > 0.0
        _rev, updated = reopened.read_sync_key_meta(path)
        assert updated > 0.0
    finally:
        reopened.close()


def test_regenerate_recovery_key_with_password_invalidates_old(tmp_path):
    # 设置页“重新生成恢复密钥”使用主密码授权轮换，无需旧恢复密钥，
    # 且旧恢复密钥立即失效、主密码保持不变（与安卓端一致）。
    new_recovery = bytes(range(32, 64))
    path = tmp_path / "v.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.close()

    reopened = Vault.open(path, PASSWORD)
    try:
        assert reopened.key_revision == 1
        reopened.regenerate_recovery_key_with_password(PASSWORD, new_recovery)
        assert reopened.key_revision == 2
    finally:
        reopened.close()

    # 旧恢复密钥已失效。
    with pytest.raises(Exception):
        Vault.open_with_recovery_key(path, RECOVERY)
    # 新恢复密钥可解锁。
    recovered = Vault.open_with_recovery_key(path, new_recovery)
    assert recovered.key_revision == 2
    recovered.close()
    # 主密码未变，仍可解锁。
    by_password = Vault.open(path, PASSWORD)
    assert by_password.key_revision == 2
    by_password.close()



def _enroll_with_key_time(base, out, device_id, seed, key_updated_at) -> None:
    shutil.copy2(base, out)
    store = PmvVaultStore.open_password(out, PASSWORD.encode("utf-8"))
    try:
        identity = store.identity
        authorization = store.sign_device_authorization(
            pmv_sync_authorization.DeviceAuthorization(
                vault_id=identity.vault_id,
                device_id=device_id,
                device_public_key=_public_key(seed),
                permissions=(
                    pmv_sync_authorization.PERMISSION_READ
                    | pmv_sync_authorization.PERMISSION_WRITE
                    | pmv_sync_authorization.PERMISSION_AUTHORIZE
                ),
                issued_at_epoch_millis=100,
                expires_at_epoch_millis=0,
                revoked_at_epoch_millis=0,
                epoch=1,
            )
        )
        metadata = pmv_device_registry.with_registry(store.metadata(), [authorization])
        sync_meta = metadata.get("sync_meta")
        if not isinstance(sync_meta, dict):
            sync_meta = {}
        sync_meta["key_updated_at"] = float(key_updated_at)
        metadata["sync_meta"] = sync_meta
        entries = []
        for summary in store.list():
            entry = store.read_entry(summary.entry_id)
            if entry is not None:
                entries.append(entry)
        store.save_full(
            expected_sequence=identity.sequence,
            metadata=metadata,
            entries=entries,
        )
    finally:
        store.close()


def test_pmve_merge_adopt_keeps_newer_key_version(tmp_path) -> None:
    def make_base(name: str, vault_int: int, device_int: int) -> Path:
        base = tmp_path / name
        store = PmvVaultStore.create(
            base,
            PASSWORD.encode("utf-8"),
            RECOVERY,
            {
                "schema": "pmv-vault-metadata",
                "version": 1,
                "vault_id": str(uuid.UUID(int=vault_int)),
                "entry_order": [],
                "trash_order": [],
                "sync_meta": {"device_id": str(uuid.UUID(int=device_int)), "key_revision": 1},
                "key_revision": 1,
                "export_epoch": None,
                "purge_tombstones": {},
            },
            (),
        )
        store.close()
        return base

    # 方向一：候选端（a）时间更新 → 合并结果采用 a 的时间。
    base1 = make_base("base1.pmv", 1, 2)
    file_a = tmp_path / "a.pmv"
    file_b = tmp_path / "b.pmv"
    _enroll_with_key_time(base1, file_a, uuid.UUID(int=3), bytes(range(32)), 200.0)
    _enroll_with_key_time(base1, file_b, uuid.UUID(int=4), bytes((i * 5 + 3) & 0xFF for i in range(32)), 50.0)
    vault_b = Vault.open(file_b, PASSWORD)
    try:
        vault_b.merge_and_adopt_authenticated_file(file_a)
        sync_meta = vault_b._pmve_store.metadata().get("sync_meta", {})
        assert float(sync_meta.get("key_updated_at", 0.0) or 0.0) == 200.0
    finally:
        vault_b.close()

    # 方向二：候选端（c）时间更旧 → 合并结果应保留本端（d）的较新时间。
    base2 = make_base("base2.pmv", 11, 12)
    file_c = tmp_path / "c.pmv"
    file_d = tmp_path / "d.pmv"
    _enroll_with_key_time(base2, file_c, uuid.UUID(int=13), bytes(range(32)), 50.0)
    _enroll_with_key_time(base2, file_d, uuid.UUID(int=14), bytes((i * 5 + 3) & 0xFF for i in range(32)), 200.0)
    vault_d = Vault.open(file_d, PASSWORD)
    try:
        vault_d.merge_and_adopt_authenticated_file(file_c)
        sync_meta = vault_d._pmve_store.metadata().get("sync_meta", {})
        assert float(sync_meta.get("key_updated_at", 0.0) or 0.0) == 200.0
    finally:
        vault_d.close()


def _make_password_diverged_pair(tmp_path: Path, name: str):
    """创建一对分叉 PMVE：一端改主密码（密钥版本更新），另一端仅新增条目。"""
    from core.models import Entry

    base = tmp_path / f"{name}-base.pmv"
    file_new = tmp_path / f"{name}-new.pmv"
    file_old = tmp_path / f"{name}-old.pmv"
    vault = Vault.create_pmve(base, PASSWORD, RECOVERY)
    vault.close()
    shutil.copy2(base, file_new)
    shutil.copy2(base, file_old)

    changed = Vault.open(file_new, PASSWORD)
    try:
        changed.change_password(NEW_PASSWORD)
    finally:
        changed.close()

    untouched = Vault.open(file_old, PASSWORD)
    try:
        untouched.add(Entry(title="b-entry", password="secret"))
    finally:
        untouched.close()
    return file_new, file_old


def test_pmve_merge_adopt_keeps_newest_password_slot(tmp_path) -> None:
    """分叉合并后，合并文件的密码槽必须来自密钥版本最新的一端：
    新密码可解锁、旧密码失效（方向一候选端更新；方向二本端更新）。"""
    import pytest
    from core import crypto

    # 方向一：候选端（new）密码更新 → 合并结果应可用新密码打开、旧密码失效。
    file_new, file_old = _make_password_diverged_pair(tmp_path, "case1")
    vault = Vault.open(file_old, PASSWORD)
    try:
        vault.merge_and_adopt_authenticated_file(file_new)
    finally:
        vault.close()
    with pytest.raises(crypto.DecryptError):
        Vault.open(file_old, PASSWORD)
    reopened = Vault.open(file_old, NEW_PASSWORD)
    try:
        assert any(entry.title == "b-entry" for entry in reopened.entries)
    finally:
        reopened.close()

    # 方向二：候选端（old）密码更旧、本端（new）更新 → 合并后仍保留本端新密码槽。
    file_new, file_old = _make_password_diverged_pair(tmp_path, "case2")
    vault = Vault.open(file_new, NEW_PASSWORD)
    try:
        vault.merge_and_adopt_authenticated_file(file_old)
    finally:
        vault.close()
    with pytest.raises(crypto.DecryptError):
        Vault.open(file_new, PASSWORD)
    reopened = Vault.open(file_new, NEW_PASSWORD)
    try:
        assert any(entry.title == "b-entry" for entry in reopened.entries)
    finally:
        reopened.close()


def test_pmve_key_convergence_kind_detects_password_change(tmp_path) -> None:
    """pmve_key_convergence_kind：密码槽变化 → PASSWORD；仅恢复密钥变化 → KEY_ONLY。"""
    from core.storage import pmve_key_convergence_kind

    file_new, file_old = _make_password_diverged_pair(tmp_path, "kind")
    vault = Vault.open(file_old, PASSWORD)
    try:
        assert pmve_key_convergence_kind(vault, file_new) == "PASSWORD"
        # 自身对自身：无收敛
        assert pmve_key_convergence_kind(vault, file_old) == "NONE"
    finally:
        vault.close()
