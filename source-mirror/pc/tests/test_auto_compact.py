from __future__ import annotations

import os
import time
import uuid

import pytest

from core import config
from core import maintenance
from core.maintenance import STALE_TEMP_SECONDS, clean_stale_temp_files
from core.models import Entry
from core.pmv_compact import should_auto_compact
from core.storage import Vault


PASSWORD = "auto compact 密码"
RECOVERY = bytes(range(32))


def _entry() -> Entry:
    return Entry(
        id=str(uuid.uuid4()),
        title="Auto Compact",
        username="alice",
        password="secret",
        url="https://example.com/login",
        target_app="com.example.app",
        notes="note",
        tags=[],
        created_at=1.0,
        updated_at=2.0,
        deleted_at=None,
    )


def test_should_compact_when_commits_and_growth_met() -> None:
    assert should_auto_compact(
        current_revision=500,
        last_compact_revision=100,
        file_size=8 * 1024 * 1024,
        last_compact_size=3 * 1024 * 1024,
        last_compact_at=0.0,
        now=1_800_000_000.0,
    )


def test_should_skip_when_commits_too_few() -> None:
    assert not should_auto_compact(
        current_revision=300,
        last_compact_revision=150,
        file_size=8 * 1024 * 1024,
        last_compact_size=3 * 1024 * 1024,
        last_compact_at=0.0,
        now=1_800_000_000.0,
    )


def test_should_skip_when_file_did_not_grow() -> None:
    assert not should_auto_compact(
        current_revision=500,
        last_compact_revision=100,
        file_size=3_200_000,
        last_compact_size=3_000_000,
        last_compact_at=0.0,
        now=1_800_000_000.0,
    )


def test_should_skip_tiny_vault() -> None:
    assert not should_auto_compact(
        current_revision=500,
        last_compact_revision=0,
        file_size=64 * 1024,
        last_compact_size=0,
        last_compact_at=0.0,
        now=1_800_000_000.0,
    )


def test_should_skip_recent_compact() -> None:
    assert not should_auto_compact(
        current_revision=900,
        last_compact_revision=500,
        file_size=9 * 1024 * 1024,
        last_compact_size=3 * 1024 * 1024,
        last_compact_at=1_800_000_000.0 - 60 * 60,
        now=1_800_000_000.0,
    )


def test_should_skip_within_import_cooldown() -> None:
    assert not should_auto_compact(
        current_revision=500,
        last_compact_revision=0,
        file_size=8 * 1024 * 1024,
        last_compact_size=0,
        last_compact_at=0.0,
        last_import_at=1_800_000_000.0 - 60 * 60,
        now=1_800_000_000.0,
    )
    assert should_auto_compact(
        current_revision=500,
        last_compact_revision=0,
        file_size=8 * 1024 * 1024,
        last_compact_size=0,
        last_compact_at=0.0,
        last_import_at=1_800_000_000.0 - 2 * 24 * 60 * 60,
        now=1_800_000_000.0,
    )


def test_maybe_auto_compact_runs_and_records_state(tmp_path, monkeypatch) -> None:
    """策略命中时执行一次压缩并记录进度；身份不变、文件不损坏。"""
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    identity = vault.pmve_identity
    size_before = path.stat().st_size
    recorded: dict[str, dict] = {}
    monkeypatch.setattr(config, "compact_state", lambda: {})
    monkeypatch.setattr(config, "record_compact", lambda name, rev, size: recorded.update({name: {"revision": rev, "size": size}}))
    monkeypatch.setattr("core.pmv_compact.should_auto_compact", lambda *a, **k: True)

    assert vault.maybe_auto_compact() is True
    assert path.name in recorded
    assert vault.pmve_identity == identity
    assert path.stat().st_size <= size_before
    assert vault.entries[0].title == "Auto Compact"
    vault.close()


def test_maybe_auto_compact_skips_without_policy_hit(tmp_path, monkeypatch) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    monkeypatch.setattr(config, "compact_state", lambda: {})
    monkeypatch.setattr("core.pmv_compact.should_auto_compact", lambda *a, **k: False)

    assert vault.maybe_auto_compact() is False
    vault.close()


def test_maybe_auto_compact_ignores_legacy_format(tmp_path) -> None:
    path = tmp_path / "vault.pmv"
    vault = Vault.create(path, PASSWORD)
    vault.entries = [_entry()]
    vault.save()
    assert vault.maybe_auto_compact() is False
    vault.close()


def test_compact_preserves_authenticated_commit_lineage(tmp_path) -> None:
    """压缩只回收数据块，祖先 COMMIT 块必须保留（避免同步端“缺少父提交”）。"""
    from core.pmv_container import BlockType, DATA_START, BLOCK_HEADER_SIZE
    from core.pmv_vault_store import PmvVaultStore

    def _full_metadata() -> dict:
        return {
            "schema": "pmv-vault-metadata",
            "version": 1,
            "vault_id": str(uuid.UUID(int=1)),
            "entry_order": [],
            "trash_order": [],
            "sync_meta": {"device_id": str(uuid.uuid4())},
            "key_revision": 1,
            "export_epoch": None,
            "purge_tombstones": {},
        }

    path = tmp_path / "lineage.pmv"
    store = PmvVaultStore.create(path, PASSWORD.encode(), RECOVERY, _full_metadata(), [])
    e = _entry()
    store.save_full(expected_sequence=1, metadata=_full_metadata(), entries=[e])
    store.save_full(expected_sequence=2, metadata=_full_metadata(), entries=[e])
    identity = store.identity
    store.compact()
    assert store.identity == identity
    store.close()

    reopened = PmvVaultStore.open_password(path, PASSWORD.encode())
    container = reopened._container
    snapshot = reopened._latest_authenticated_snapshot()
    commit_blocks = 0
    offset = DATA_START
    while offset < snapshot.state.superblock.committed_file_end:
        block = container.read_block(snapshot.state, offset)
        if block.header.block_type is BlockType.COMMIT:
            commit_blocks += 1
        offset += BLOCK_HEADER_SIZE + block.header.cipher_size
    reopened.close()
    # create + 2 次 saveFull = 3 个提交，压缩后应全部保留
    assert commit_blocks == 3


def test_manual_compact_runs_without_auto_policy(tmp_path, monkeypatch) -> None:
    path = tmp_path / "manual.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    before = path.stat().st_size
    monkeypatch.setattr(config, "record_compact", lambda *args: None)

    reported_before, reported_after = vault.compact_now()

    assert reported_before == before
    assert reported_after == path.stat().st_size
    assert vault.entries[0].title == "Auto Compact"
    vault.close()


def test_compact_before_sync_runs_and_preserves_identity(tmp_path, monkeypatch) -> None:
    """云同步前压缩：策略命中即执行，身份不变，且不受 24h 间隔/导入冷却限制。"""
    path = tmp_path / "sync.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    identity = vault.pmve_identity
    size_before = path.stat().st_size
    recorded: dict[str, dict] = {}
    monkeypatch.setattr(config, "compact_state", lambda: {})
    monkeypatch.setattr(config, "record_compact", lambda name, rev, size: recorded.update({name: {"revision": rev, "size": size}}))
    monkeypatch.setattr("core.pmv_compact.should_auto_compact", lambda *a, **k: True)

    assert vault.compact_before_sync() is True
    assert path.name in recorded
    assert vault.pmve_identity == identity
    assert path.stat().st_size <= size_before
    assert vault.entries[0].title == "Auto Compact"
    vault.close()


def test_compact_before_sync_skips_without_policy_hit(tmp_path, monkeypatch) -> None:
    path = tmp_path / "sync.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    monkeypatch.setattr(config, "compact_state", lambda: {})
    monkeypatch.setattr("core.pmv_compact.should_auto_compact", lambda *a, **k: False)

    assert vault.compact_before_sync() is False
    vault.close()


def test_compact_before_sync_ignores_legacy_format(tmp_path) -> None:
    path = tmp_path / "sync.pmv"
    vault = Vault.create(path, PASSWORD)
    vault.entries = [_entry()]
    vault.save()
    assert vault.compact_before_sync() is False
    vault.close()


def test_cleanup_removes_only_stale_faevault_temp_files(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(maintenance.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(maintenance, "media_root", lambda: tmp_path / "no-media")
    vault_path = tmp_path / "vault_demo.pmv"
    stale = tmp_path / f".{vault_path.name}.merge.tmp"
    recent = tmp_path / f".{vault_path.name}.upload.tmp"
    unrelated = tmp_path / "unrelated.tmp"
    for path in (stale, recent, unrelated):
        path.write_bytes(b"1234")
    now = time.time()
    old = now - STALE_TEMP_SECONDS - 1
    os.utime(stale, (old, old))

    report = clean_stale_temp_files(vault_path, now=now)

    assert report.removed_files == 1
    assert report.freed_bytes == 4
    assert not stale.exists()
    assert recent.exists()
    assert unrelated.exists()


def test_cleanup_reclaims_stale_media_import_staging(tmp_path, monkeypatch) -> None:
    """媒体目录里超过 24 小时的导入暂存孤儿要回收，近期暂存与其它文件保留。"""
    monkeypatch.setattr(maintenance.tempfile, "gettempdir", lambda: str(tmp_path / "no-temp"))
    media = tmp_path / "media"
    images = media / "vault-id" / "images"
    images.mkdir(parents=True)
    monkeypatch.setattr(maintenance, "media_root", lambda: media)
    vault_path = tmp_path / "vault_demo.pmv"

    stale_import = images / "import-abcd.tmp"
    stale_bytes = images / "bytes-efgh.tmp"
    recent_import = images / "import-recent.tmp"
    committed = images / "import-abcd.vmed"
    for path in (stale_import, stale_bytes, recent_import, committed):
        path.write_bytes(b"1234")
    now = time.time()
    old = now - STALE_TEMP_SECONDS - 1
    for path in (stale_import, stale_bytes):
        os.utime(path, (old, old))

    report = clean_stale_temp_files(vault_path, now=now)

    assert report.removed_files == 2
    assert not stale_import.exists()
    assert not stale_bytes.exists()
    assert recent_import.exists()
    assert committed.exists()


def test_compact_after_purge_runs_without_policy_and_preserves_identity(tmp_path, monkeypatch) -> None:
    """清空回收站后立即压缩：不看策略门槛，身份与内容不变。"""
    path = tmp_path / "purged.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    entry = _entry()
    vault.entries = [entry]
    vault.save()
    vault.delete(entry.id)
    vault.purge_all()
    identity = vault.pmve_identity
    size_before = path.stat().st_size
    monkeypatch.setattr(config, "record_compact", lambda *args: None)

    assert vault.compact_after_purge() is True

    assert vault.pmve_identity == identity
    assert path.stat().st_size <= size_before
    assert vault.entries == []
    vault.close()


def test_compact_after_purge_returns_false_when_nothing_to_compact(tmp_path) -> None:
    path = tmp_path / "empty.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = []
    vault.save()
    vault.close()
    vault._pmve_store = None

    assert vault.compact_after_purge() is False


def _media_state(monkeypatch, *, last_at: float, last_size: int) -> None:
    monkeypatch.setattr(
        config,
        "compact_state",
        lambda: {"media.pmv": {"at": last_at, "size": last_size}},
    )
    monkeypatch.setattr(config, "record_compact", lambda *args: None)


def test_maybe_compact_after_large_media_runs_when_growth_and_interval_met(
    tmp_path, monkeypatch
) -> None:
    """媒体提交后压缩使用独立阈值：最短间隔 + 最小增长，不看提交数。"""
    path = tmp_path / "media.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    identity = vault.pmve_identity
    _media_state(monkeypatch, last_at=time.time() - 3600, last_size=0)
    # 真实媒体增长阈值是 32MB，测试里降到 1 字节，只验证阈值逻辑本身。
    monkeypatch.setattr("core.pmv_compact.MEDIA_COMPACT_MIN_GROWTH", 1)

    assert vault.maybe_compact_after_large_media() is True

    assert vault.pmve_identity == identity
    assert vault.entries[0].title == "Auto Compact"
    vault.close()


def test_maybe_compact_after_large_media_skips_too_soon(tmp_path, monkeypatch) -> None:
    path = tmp_path / "media.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    _media_state(monkeypatch, last_at=time.time(), last_size=0)

    assert vault.maybe_compact_after_large_media() is False
    vault.close()


def test_maybe_compact_after_large_media_skips_without_growth(tmp_path, monkeypatch) -> None:
    path = tmp_path / "media.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    vault.entries = [_entry()]
    vault.save()
    _media_state(monkeypatch, last_at=time.time() - 3600, last_size=path.stat().st_size + 1)

    assert vault.maybe_compact_after_large_media() is False
    vault.close()


def test_maybe_compact_after_large_media_ignores_legacy_format(tmp_path) -> None:
    """媒体压缩同样要求 PMVE store；纯 Legacy 库不做压缩。"""
    path = tmp_path / "legacy-media.pmv"
    vault = Vault.create(path, PASSWORD)
    vault.entries = [_entry()]
    vault.save()
    vault._pmve_store = None
    assert vault.maybe_compact_after_large_media() is False
    vault.close()


def test_purge_expired_removes_stale_trash_entries(tmp_path) -> None:
    """过期回收站清理是解锁后台维护的一部分，必须真的生效。"""
    path = tmp_path / "expired.pmv"
    vault = Vault.create_pmve(path, PASSWORD, RECOVERY)
    stale = _entry()
    fresh = Entry.from_dict({**_entry().to_dict(), "id": str(uuid.uuid4())})
    vault.entries = [stale, fresh]
    vault.save()
    vault.delete(stale.id)
    vault.delete(fresh.id)
    vault._trash_meta[stale.id]["deleted_at"] = time.time() - 40 * 86400

    vault.purge_expired(30)

    remaining = [item.id for item in vault.trash]
    assert stale.id not in remaining
    assert fresh.id in remaining
    vault.close()
