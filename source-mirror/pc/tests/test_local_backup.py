"""PC 本地备份策略与原子覆盖测试。"""

import hashlib
import json
import os
import types

import pytest

from core.local_backup import (
    BindingState,
    BackupInsufficientSpace,
    BackupWaitingDevice,
    BackupJournal,
    DEVICE_MARKER_NAME,
    MarkerState,
    PARTIAL_SUFFIX,
    binding_state_for_directory,
    create_device_marker,
    device_fingerprint,
    evaluate_binding,
    interval_seconds,
    perform_backup,
    should_run,
    storage_access_id,
    volume_identity,
)


DEVICE_UUID = "123e4567-e89b-12d3-a456-426614174000"
OTHER_UUID = "123e4567-e89b-12d3-a456-426614174001"


def test_two_identifier_binding_state_matrix() -> None:
    assert evaluate_binding(DEVICE_UUID, "access:a", DEVICE_UUID, "access:a") is BindingState.KNOWN
    assert evaluate_binding(DEVICE_UUID, "access:a", DEVICE_UUID, "access:b") is BindingState.SUSPECTED_ORIGINAL
    assert evaluate_binding(DEVICE_UUID, "access:a", None, "access:a") is BindingState.IDENTITY_ANOMALY
    assert evaluate_binding(DEVICE_UUID, "access:a", OTHER_UUID, "access:a") is BindingState.IDENTITY_ANOMALY
    assert evaluate_binding(DEVICE_UUID, "access:a", OTHER_UUID, "access:b") is BindingState.NEW_DEVICE


def test_device_marker_is_created_once_and_reused(tmp_path) -> None:
    first = create_device_marker(tmp_path)
    second = create_device_marker(tmp_path)
    assert first.state is MarkerState.VALID
    assert second == first
    assert (tmp_path / DEVICE_MARKER_NAME).exists()


def test_invalid_device_marker_is_never_overwritten(tmp_path) -> None:
    marker = tmp_path / DEVICE_MARKER_NAME
    marker.write_text('{"version":1,"deviceUuid":"not-a-uuid"}', encoding="utf-8")
    result = create_device_marker(tmp_path)
    assert result.state is MarkerState.INVALID
    assert "not-a-uuid" in marker.read_text(encoding="utf-8")


def test_directory_binding_reads_marker_and_access_identity(tmp_path) -> None:
    marker = create_device_marker(tmp_path)
    access_id = storage_access_id(tmp_path)
    state, observed, observed_access = binding_state_for_directory(
        tmp_path,
        marker.device_uuid,
        access_id,
    )
    assert state is BindingState.KNOWN
    assert observed == marker
    assert observed_access == access_id


def test_should_run_gates_by_interval_and_force(tmp_path) -> None:
    now = 200_000.0
    assert should_run(now, 0.0, "daily")
    assert not should_run(now, now - interval_seconds("daily") + 1, "daily")
    assert should_run(now, now - interval_seconds("daily"), "daily")
    assert should_run(now, now - 1, "daily", force=True)
    assert should_run(now, now, "realtime")


def test_invalid_interval_rejected() -> None:
    with pytest.raises(ValueError):
        interval_seconds("fortnightly")


def test_volume_identity_is_stable_for_existing_directory(tmp_path) -> None:
    first = volume_identity(str(tmp_path))
    second = volume_identity(str(tmp_path))
    assert first != ""
    assert first == second


def test_volume_identity_missing_directory_returns_empty() -> None:
    assert volume_identity(str(__import__("pathlib").Path("Z:/definitely-not-exists-xyz"))) == ""


def test_device_fingerprint_identity_never_relies_on_drive_letter(tmp_path) -> None:
    fp = device_fingerprint(str(tmp_path))
    assert fp is not None
    # 身份键必须来自稳定分量（物理盘序列号/分区 GUID/文件系统 UUID），不能是盘符
    assert fp.identity_key() != ""
    assert "|" in fp.identity_key()
    assert "Z:" not in fp.identity_key()
    assert fp.display_id().startswith(("HDD-", "VOL-"))


def test_perform_backup_copies_atomically_and_cleans_tmp(tmp_path) -> None:
    vault = tmp_path / "vault.pmv"
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    vault.write_bytes(b"encrypted-vault-bytes")
    result = perform_backup(vault, backup_dir)
    assert result.final.name == "vault.pmv"
    assert result.final.read_bytes() == b"encrypted-vault-bytes"
    leftovers = [p for p in backup_dir.iterdir() if p.name.endswith(PARTIAL_SUFFIX)]
    assert leftovers == []
    manifest = backup_dir / "vault.pmv.manifest.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["sha256"] == hashlib.sha256(b"encrypted-vault-bytes").hexdigest()
    assert data["size"] == len(b"encrypted-vault-bytes")


def test_perform_backup_missing_directory_waits(tmp_path) -> None:
    vault = tmp_path / "vault.pmv"
    vault.write_bytes(b"data")
    missing = tmp_path / "not-there"
    with pytest.raises(BackupWaitingDevice):
        perform_backup(vault, missing)


def test_perform_backup_overwrites_existing_snapshot(tmp_path) -> None:
    vault = tmp_path / "vault.pmv"
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    vault.write_bytes(b"v1")
    perform_backup(vault, backup_dir)
    vault.write_bytes(b"v2")
    perform_backup(vault, backup_dir)
    assert (backup_dir / "vault.pmv").read_bytes() == b"v2"


def test_perform_backup_keeps_four_previous_snapshots(tmp_path) -> None:
    vault = tmp_path / "vault.pmv"
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    for version in range(1, 8):
        vault.write_bytes(f"v{version}".encode())
        perform_backup(vault, backup_dir)
    assert (backup_dir / "vault.pmv").read_bytes() == b"v7"
    for generation in range(1, 5):
        assert (backup_dir / f"vault.pmv.history.{generation}").read_bytes() == f"v{7-generation}".encode()
    assert not (backup_dir / "vault.pmv.history.5").exists()


def test_perform_backup_resumes_from_partial_after_crash(tmp_path) -> None:
    vault = tmp_path / "vault.pmv"
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    payload = os.urandom(2 * 1024 * 1024 + 123)
    vault.write_bytes(payload)
    journal_file = tmp_path / ".local_backup_journal.json"
    plan_partial = backup_dir / f"vault.pmv{PARTIAL_SUFFIX}"
    # 模拟崩溃：只复制了前一半
    half = len(payload) // 2
    plan_partial.write_bytes(payload[:half])
    BackupJournal(
        source=str(vault),
        source_size=len(payload),
        target_name="vault.pmv",
        started_at=1.0,
    ).save(journal_file)
    result = perform_backup(
        vault,
        backup_dir,
        journal_path=journal_file,
        resume=True,
    )
    assert result.resumed is True
    assert (backup_dir / "vault.pmv").read_bytes() == payload
    assert not plan_partial.exists()
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


def test_perform_backup_rejects_insufficient_space(tmp_path, monkeypatch) -> None:
    vault = tmp_path / "vault.pmv"
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    vault.write_bytes(b"x" * 1024)
    monkeypatch.setattr(
        "core.local_backup.shutil.disk_usage",
        lambda _path: types.SimpleNamespace(free=512),
    )
    with pytest.raises(BackupInsufficientSpace):
        perform_backup(vault, backup_dir)
