"""核心逻辑的单元测试（不依赖 GUI）。"""

import copy
import csv
import json
import time
from pathlib import Path

import pytest

from core import backup, config, crypto, importers, leak, modules, otp, pmv_backup, sync, utils
from core.models import Entry, SecretType
from core.storage import ExternalVaultChange, StaleEntryChange, Vault


# ---------- config ----------
def test_lockout_key_is_derived_once_per_vault_directory(monkeypatch, tmp_path):
    derived = []

    class CountingScrypt:
        def __init__(self, **_kwargs):
            pass

        def derive(self, data):
            derived.append(data)
            return config.sha256(data).digest()

    directory = [tmp_path / "first"]
    monkeypatch.setattr(config, "vault_dir", lambda: directory[0])
    monkeypatch.setattr(config, "Scrypt", CountingScrypt)
    first = config._lockout_sig("lockout_until", 123)
    for _ in range(5):
        assert config._lockout_sig("lockout_until", 123) == first
    assert derived == [str(directory[0]).encode()]
    directory[0] = tmp_path / "second"
    assert config._lockout_sig("lockout_until", 123) != first
    assert derived[-1] == str(directory[0]).encode()
    assert len(derived) == 2


def test_defaults_match_android():
    assert config.DEFAULT_THEME_MODE == "light"
    assert config.DEFAULT_LOCK_ENABLED is False
    assert config.DEFAULT_LOCK_SECONDS == 60
    assert (config.MIN_LOCK_SECONDS, config.MAX_LOCK_SECONDS) == (30, 3600)
    assert config.DEFAULT_CLIPBOARD_CLEAR_SECONDS == 60
    assert (config.MIN_CLIPBOARD_CLEAR_SECONDS, config.MAX_CLIPBOARD_CLEAR_SECONDS) == (0, 600)
    assert config.DEFAULT_REQUIRE_MASTER_FOR_SENSITIVE is False
    assert config.DEFAULT_LEAK_CHECK_ENABLED is True
    assert config.DEFAULT_LEAK_RECHECK_DAYS == 5
    assert config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS == 30
    assert config.DEFAULT_BACKGROUND_HIDE is False


def test_list_pane_ratio_is_global_and_defaults_to_forty_percent(monkeypatch):
    from contextlib import nullcontext

    saved = []
    monkeypatch.setattr(config, "_config_cache", {})
    monkeypatch.setattr(config, "_load_uncached", lambda: {"current_user": "FAE"})
    monkeypatch.setattr(config, "_configuration_revision", lambda _path: b"revision")
    monkeypatch.setattr(config, "_interprocess_config_lock", lambda: nullcontext())
    monkeypatch.setattr(config, "_save_uncached", lambda data, **_kwargs: saved.append(data.copy()))

    assert config.DEFAULT_LIST_PANE_RATIO == 40
    config.set("list_pane_ratio", 45)

    assert saved[0]["list_pane_ratio"] == 45
    assert "list_pane_ratio" not in saved[0].get("account_settings", {}).get("FAE", {})


def test_config_defaults_and_legacy_lock_migration(monkeypatch):
    monkeypatch.setattr(config, "_config_cache", {})
    assert config.theme_mode() == "light"
    assert config.DEFAULT_LOCK_ENABLED is False
    assert config.lock_seconds() == 60

    monkeypatch.setattr(config, "_config_cache", {"dark": False, "lock_minutes": 5})
    assert config.theme_mode() == "light"
    assert config.lock_seconds() == 300

    monkeypatch.setattr(config, "_config_cache", {"lock_seconds": 99999})
    assert config.lock_seconds() == 3600


def test_theme_mode_recognizes_all_modes_and_falls_back_to_light(monkeypatch):
    for mode in ("auto", "light", "dark"):
        monkeypatch.setattr(config, "_config_cache", {"theme_mode": mode})
        assert config.theme_mode() == mode

    # 旧版“品牌蓝”已并入浅色，历史配置读取时迁移
    monkeypatch.setattr(config, "_config_cache", {"theme_mode": "brand_blue"})
    assert config.theme_mode() == "light"

    monkeypatch.setattr(config, "_config_cache", {"theme_mode": "unknown"})
    assert config.theme_mode() == "light"


def test_private_browser_origins_are_signed_and_tamper_evident(monkeypatch):
    monkeypatch.setattr(config, "_config_cache", {})
    monkeypatch.setattr(config, "_load_uncached", lambda: {})
    monkeypatch.setattr(config, "_save_uncached", lambda _data, **_kwargs: None)
    origin = "https://192.168.1.10:8443"

    config.set_browser_private_origins([origin, origin])
    assert config.browser_private_origins() == ([origin], True)

    config.load()["browser_autofill_private_origins"].append("https://10.0.0.1")
    assert config.browser_private_origins() == ([], False)


def test_config_set_many_persists_settings_in_one_write(monkeypatch):
    from contextlib import nullcontext

    saved = []
    monkeypatch.setattr(config, "_config_cache", {})
    monkeypatch.setattr(config, "_load_uncached", lambda: {"current_user": "FAE"})
    monkeypatch.setattr(config, "_configuration_revision", lambda _path: b"revision")
    monkeypatch.setattr(config, "_interprocess_config_lock", lambda: nullcontext())
    monkeypatch.setattr(config, "_save_uncached", lambda data, **_kwargs: saved.append(data.copy()))

    config.set_many({"lock_enabled": True, "lock_seconds": 90, "theme_mode": "dark"})

    assert len(saved) == 1
    account = saved[0]["account_settings"]["FAE"]
    assert account == {"lock_enabled": True, "lock_seconds": 90, "theme_mode": "dark"}


def test_stale_process_does_not_clobber_settings_written_later(monkeypatch, tmp_path):
    """常驻进程（browser_host）用启动时的旧缓存写回时，不得覆盖主程序随后保存的设置。

    browser_host 是长驻进程，其 _config_cache 在启动时加载后长期不变；
    主程序随后把 cloud_sync_enabled / lock_enabled 写入磁盘。若 browser_host
    再执行 set_lockout / set_current_user 而沿用旧缓存整体回写，新设置会被清掉。
    修复后每次写入都基于磁盘最新状态，回归测试验证这一点。
    """
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from core import config as cfg
    import importlib

    cfg = importlib.reload(cfg)

    # 主程序先保存两处设置（模拟用户在设置里打开云同步与自动锁定）
    cfg.set("cloud_sync_enabled_demo", True)
    cfg.set("lock_enabled", True)

    # 模拟 browser_host 的陈旧缓存：不含这两处新设置
    monkeypatch.setattr(cfg, "_config_cache", {
        "cloud_sync_enabled_demo": False,
        "lock_enabled": False,
    })

    # browser_host 执行它常用的写操作
    cfg.set_current_user("FAE")
    cfg.set_lockout("fail_count", 3)

    # 新设置必须还在磁盘上
    assert cfg.get("cloud_sync_enabled_demo") is True
    assert cfg.get("lock_enabled") is True
    assert cfg.get_current_user() == "FAE"
    assert cfg.get_lockout("fail_count") == (3, True)


def test_corrupt_or_empty_config_is_not_recovered_from_backup(monkeypatch, tmp_path):
    """PC 端只加载数据库位置的 config.json，不再从 .bak 恢复配置。"""
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from core import config as cfg
    import importlib

    cfg = importlib.reload(cfg)

    cfg.set("lock_enabled", False)
    cfg.set("lock_seconds", 60)
    config_path = tmp_path / "vault" / "config.json"
    assert config_path.exists()
    # 保存不再生成备份文件
    assert not (tmp_path / "vault" / "config.json.bak").exists()

    backup_path = config_path.with_name("config.json.bak")
    backup_path.write_text('{"theme_mode":"dark","lock_enabled":true}', encoding="utf-8")
    for broken in ("{broken json", "", "[]"):
        config_path.write_text(broken, encoding="utf-8")
        cfg.invalidate_cache()
        # 配置损坏只从唯一设置文件读取，退回默认值；不读取旁边的备份。
        assert cfg.get("lock_enabled", "missing") == "missing"
        assert cfg.theme_mode() == cfg.DEFAULT_THEME_MODE
        assert cfg.screen_capture_allowed() is cfg.DEFAULT_SCREEN_CAPTURE_ALLOWED
        assert cfg.screen_capture_allowed() is False
        assert cfg.list_users() == []
        assert backup_path.read_text(encoding="utf-8").startswith('{"theme_mode"')


def test_config_is_encrypted_roundtrips_and_rejects_tampering(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from core import config as cfg
    import importlib

    cfg = importlib.reload(cfg)
    monkeypatch.setattr(cfg, "_protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr(cfg, "_unprotect_key", lambda value: value.removeprefix(b"protected:"))
    settings = {
        "theme_mode": "dark", "lock_seconds": 90, "lock_enabled": True,
        "users": [{"name": "FAE", "file": "FAE.pmv"}],
        "current_user": "FAE", "nested": {"all": [1, "two", False]},
    }
    cfg.save(settings)

    path = cfg._config_path()
    raw = path.read_text(encoding="utf-8")
    assert "FAE.pmv" not in raw
    assert json.loads(raw)["format"] == "FAEVaultConfig"
    cfg.invalidate_cache()
    assert cfg.load() == settings

    envelope = json.loads(raw)
    ciphertext = bytearray(__import__("base64").b64decode(envelope["ciphertext"]))
    ciphertext[-1] ^= 1
    envelope["ciphertext"] = __import__("base64").b64encode(ciphertext).decode()
    path.write_text(json.dumps(envelope), encoding="utf-8")
    cfg.invalidate_cache()
    assert cfg.load() == {}
    with pytest.raises(cfg.ConfigIntegrityError):
        cfg.set("theme_mode", "light")
    assert json.loads(path.read_text(encoding="utf-8"))["ciphertext"] == envelope["ciphertext"]

    cfg.recover_corrupt_config({"theme_mode": "light"})
    assert cfg.get("theme_mode") == "light"


def test_config_compare_and_swap_rejects_unlocked_external_change(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from core import config as cfg
    import importlib

    cfg = importlib.reload(cfg)
    monkeypatch.setattr(cfg, "_protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr(cfg, "_unprotect_key", lambda value: value.removeprefix(b"protected:"))
    cfg.set("first", 1)
    original_revision = cfg._configuration_revision(cfg._config_path())
    cfg.set("second", 2)
    with pytest.raises(cfg.ConfigIntegrityError):
        cfg._save_uncached({"stale": True}, expected_revision=original_revision, check_revision=True)
    cfg.invalidate_cache()
    assert cfg.load() == {"first": 1, "second": 2}


def test_plaintext_config_is_atomically_migrated(monkeypatch, tmp_path):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from core import config as cfg
    import importlib

    cfg = importlib.reload(cfg)
    monkeypatch.setattr(cfg, "_protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr(cfg, "_unprotect_key", lambda value: value.removeprefix(b"protected:"))
    path = cfg._config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"theme_mode":"light","language_mode":"zh-Hans"}', encoding="utf-8")

    assert cfg.load()["theme_mode"] == "light"
    migrated = json.loads(path.read_text(encoding="utf-8"))
    assert migrated["format"] == "FAEVaultConfig"
    assert not list(path.parent.glob("config.json.*.tmp"))


# ---------- models ----------
def test_entry_serialization_roundtrip():
    e = Entry(title="A", username="u", password="p", tags=["x", "y"])
    again = Entry.from_dict(e.to_dict())
    assert again.id == e.id and again.tags == ["x", "y"]


def test_entry_deepcopy_drops_uncopyable_vault_backref():
    """Vault._lazy 会给条目挂上 entry.vault；深度复制条目（如打开编辑弹窗）不得连带复制会话。"""

    class _Uncopyable:
        def __getstate__(self):
            raise TypeError("unlocked Vault sessions cannot be pickled")

    e = Entry(title="A", password="p")
    e.vault = _Uncopyable()

    clone = copy.deepcopy(e)

    assert clone.title == "A" and clone.password == "p"
    assert not hasattr(clone, "vault")
    assert e.vault is not None


def test_entry_from_dict_sanitizes_fields():
    data = {
        "title": None,
        "username": 123,
        "password": None,
        "url": None,
        "notes": None,
        "tags": None,
        "created_at": "invalid",
        "updated_at": None,
        "id": None,
    }
    e = Entry.from_dict(data)
    assert e.title == ""
    assert e.username == "123"
    assert e.password == ""
    assert e.url == ""
    assert e.notes == ""
    assert e.tags == []
    assert isinstance(e.id, str) and e.id


def test_entry_from_dict_accepts_cross_platform_timestamp_representations():
    e = Entry.from_dict(
        {
            "created_at": "2026-07-26T10:00:00+08:00",
            "updated_at": "1785031200.5",
            "deleted_at": "2026-07-26T02:00:00Z",
            "leak_check_revision": "1785031200.5",
            "leak_checked_at": "2026-07-26T02:00:00Z",
        }
    )

    assert e.created_at == pytest.approx(1785031200.0)
    assert e.updated_at == pytest.approx(1785031200.5)
    assert e.deleted_at == pytest.approx(1785031200.0)
    assert e.leak_check_revision == pytest.approx(1785031200.5)
    assert e.leak_checked_at == pytest.approx(1785031200.0)
    assert isinstance(e.to_dict()["created_at"], float)


def test_entry_matches():
    e = Entry(title="GitHub", username="alice", tags=["work"])
    assert e.matches("git") and e.matches("WORK") and not e.matches("zzz")
    assert e.matches("")  # 空查询匹配所有


def test_entry_accepts_otp_type_and_display_secret():
    e = Entry(
        title="GitHub",
        secret_type=SecretType.OTP,
        username="fallback",
        fields={"issuer": "GitHub", "label": "alice@example.com", "secret": "JBSWY3DPEHPK3PXP"},
    )
    assert e.secret_type == SecretType.OTP
    assert e.display_secret == "alice@example.com"


def test_otp_algorithm_matches_rfc_vector():
    # RFC 4226 Appendix D: secret "12345678901234567890", counter 0 -> 755224.
    assert otp.generate_hotp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", 0) == "755224"


def test_otp_parse_uri_normalizes_string_fields():
    fields = otp.parse_otpauth_uri("otpauth://totp/GitHub:alice%40example.com?secret=jbsw y3dp ehpk3pxp&issuer=GitHub&algorithm=SHA256&digits=8&period=45")
    assert fields == {
        "type": "totp",
        "secret": "JBSWY3DPEHPK3PXP",
        "algorithm": "SHA256",
        "digits": "8",
        "period": "45",
        "issuer": "GitHub",
        "label": "alice@example.com",
        "counter": "0",
    }


def test_otp_parse_uri_rejects_invalid_parameters():
    base = "otpauth://totp/Account?secret=JBSWY3DPEHPK3PXP"
    assert otp.parse_otpauth_uri("otpauth://totp/Account?secret=INVALID01") == {}
    assert otp.parse_otpauth_uri(f"{base}&algorithm=MD5") == {}
    assert otp.parse_otpauth_uri(f"{base}&digits=9") == {}
    assert otp.parse_otpauth_uri(f"{base}&period=0") == {}
    assert otp.parse_otpauth_uri("otpauth://hotp/Account?secret=JBSWY3DPEHPK3PXP") == {}
    assert otp.parse_otpauth_uri("otpauth://hotp/Account?secret=JBSWY3DPEHPK3PXP&counter=-1") == {}


# ---------- storage ----------
def test_vault_persist_and_reopen(tmp_path: Path):
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "master")
    v.add(Entry(title="Site", username="u", password="p"))
    reopened = Vault.open(p, "master")
    assert [e.title for e in reopened.entries] == ["Site"]


def test_vault_list_materializes_missing_entries_in_one_batch(tmp_path: Path, monkeypatch):
    path = tmp_path / "batch.pmv"
    created = Vault.create(path, "master")
    created.add(Entry(title="First", password="one"))
    created.add(Entry(title="Second", password="two"))
    created.close()
    reopened = Vault.open(path, "master")
    calls = []
    original = reopened._pmve_store.read_entries

    def tracked(entry_ids):
        ids = tuple(entry_ids)
        calls.append(ids)
        return original(ids)

    monkeypatch.setattr(reopened._pmve_store, "read_entries", tracked)
    assert [entry.title for entry in reopened.entries] == ["First", "Second"]
    assert len(calls) == 1 and len(calls[0]) == 2
    assert [entry.title for entry in reopened.entries] == ["First", "Second"]
    assert len(calls) == 1
    reopened.close()


def test_stale_entry_and_external_vault_changes_are_rejected(tmp_path: Path):
    path = tmp_path / "conflict.pmv"
    first = Vault.create(path, "master")
    first.add(Entry(id="00000000-0000-0000-0000-000000000001", title="Original", username="u", password="p"))
    stale_entry = Entry.from_dict(first.entries[0].to_dict())
    second = Vault.open(path, "master")
    changed = Entry.from_dict(second.entries[0].to_dict())
    changed.title = "Newer"
    second.update(changed)

    with pytest.raises(ExternalVaultChange):
        first.add(Entry(title="must not overwrite"))

    refreshed = first.reopen()
    stale_entry.title = "Stale"
    with pytest.raises(StaleEntryChange):
        refreshed.update(stale_entry)


def test_v2_roundtrip_preserves_android_target_package(tmp_path: Path):
    path = tmp_path / "target-app.pmv"
    vault = Vault.create(path, "master")
    vault.add(Entry(title="Android app", target_app="com.example.android"))

    reopened = Vault.open(path, "master")
    assert reopened.entries[0].target_app == "com.example.android"
    reopened.save()

    assert Vault.open(path, "master").entries[0].target_app == "com.example.android"


def test_leak_check_cache_persists_and_skips_unchanged_entry(tmp_path: Path):
    p = tmp_path / "v.pmv"
    vault = Vault.create(p, "master")
    entry = Entry(title="Site", username="u", password="unique-password")
    vault.add(entry)

    assert leak.needs_online_check(vault.entries[0])
    result = leak.make_check_result(vault.entries[0], pwned_count=0)
    assert vault.apply_leak_checks([result]) == 1

    reopened = Vault.open(p, "master")
    checked = reopened.entries[0]
    assert not leak.needs_online_check(checked)
    assert not leak.is_entry_leaked(checked)

    unchanged = Entry.from_dict(checked.to_dict())
    reopened.update(unchanged)
    assert not leak.needs_online_check(reopened.entries[0])


def test_leak_check_cache_marks_breached_entry(tmp_path: Path):
    p = tmp_path / "v.pmv"
    vault = Vault.create(p, "master")
    vault.add(Entry(title="Site", password="compromised-password"))

    result = leak.make_check_result(vault.entries[0], pwned_count=42)
    vault.apply_leak_checks([result])

    assert leak.is_entry_leaked(vault.entries[0])


def test_cached_leak_status_does_not_fallback_to_dictionary():
    entry = Entry(title="Site", password="password")

    assert leak.is_entry_leaked(entry)
    assert not leak.is_entry_leaked_cached(entry)


def test_leak_check_disabled_hides_cached_badges_and_skips_detection(monkeypatch):
    entry = Entry(title="Site", password="compromised-password", updated_at=100.0)
    entry.leak_check_revision = 100.0
    entry.leak_pwned_count = 42
    entry.leak_common_weak = True
    entry.leak_checked_at = 123.0

    monkeypatch.setattr(config, "_config_cache", {"leak_check_enabled": False})

    assert not leak.check_enabled()
    assert not leak.is_entry_leaked(entry)
    assert not leak.needs_leak_check(entry, force=True)
    assert not leak.online_check_enabled()


def test_secret_change_invalidates_leak_cache_and_rejects_stale_result(tmp_path: Path):
    p = tmp_path / "v.pmv"
    vault = Vault.create(p, "master")
    vault.add(Entry(title="Before", password="unique-password"))
    stale_result = leak.make_check_result(vault.entries[0], pwned_count=0)
    vault.apply_leak_checks([stale_result])

    changed = Entry.from_dict(vault.entries[0].to_dict())
    changed.password = "changed-password"
    vault.update(changed)

    assert leak.needs_online_check(vault.entries[0])
    assert vault.apply_leak_checks([stale_result]) == 0
    assert leak.needs_online_check(vault.entries[0])


def test_non_secret_edit_carries_current_leak_cache_to_new_revision(tmp_path: Path):
    p = tmp_path / "v.pmv"
    vault = Vault.create(p, "master")
    vault.add(Entry(title="Before", password="unique-password"))
    result = leak.make_check_result(vault.entries[0], pwned_count=0, checked_at=123.0)
    vault.apply_leak_checks([result])

    changed = Entry.from_dict(vault.entries[0].to_dict())
    changed.title = "After"
    vault.update(changed)

    updated = vault.entries[0]
    assert updated.updated_at != result.revision
    assert updated.leak_check_revision == updated.updated_at
    assert updated.leak_pwned_count == 0
    assert updated.leak_checked_at == 123.0
    assert not leak.needs_online_check(updated, now=123.0 + 5 * 86400 - 1)


def test_unchanged_edit_preserves_revision_and_does_not_rewrite_vault(tmp_path: Path):
    p = tmp_path / "v.pmv"
    vault = Vault.create(p, "master")
    vault.add(Entry(title="Unchanged", username="user", password="secret"))
    before = Entry.from_dict(vault.entries[0].to_dict())
    before_bytes = p.read_bytes()

    vault.update(Entry.from_dict(before.to_dict()))

    assert vault.entries[0].updated_at == before.updated_at
    assert p.read_bytes() == before_bytes


def test_secret_change_clears_leak_cache(tmp_path: Path):
    p = tmp_path / "v.pmv"
    vault = Vault.create(p, "master")
    vault.add(Entry(title="Site", password="old-password"))
    vault.apply_leak_checks([leak.make_check_result(vault.entries[0], pwned_count=0)])

    changed = Entry.from_dict(vault.entries[0].to_dict())
    changed.password = "new-password"
    vault.update(changed)

    updated = vault.entries[0]
    assert updated.leak_check_revision is None
    assert updated.leak_pwned_count is None
    assert updated.leak_common_weak is False
    assert updated.leak_checked_at is None
    assert leak.needs_online_check(updated)


def test_leak_audit_deduplicates_passwords_and_does_not_cache_failures():
    calls = []

    def query(password: str) -> int:
        calls.append(password)
        return -1 if password == "offline" else 0

    results = leak.audit_snapshots(
        [
            ("first", 1.0, "same-password"),
            ("second", 2.0, "same-password"),
            ("third", 3.0, "offline"),
        ],
        query=query,
    )

    assert calls == ["same-password", "offline"]
    assert [result.entry_id for result in results] == ["first", "second"]


def test_leak_audit_when_online_disabled_writes_safe_cache_without_query(monkeypatch):
    monkeypatch.setattr(config, "_config_cache", {"leak_online_check": False})
    calls = []

    results = leak.audit_snapshots(
        [("first", 1.0, "same-password"), ("second", 2.0, "same-password")],
        query=lambda password: calls.append(password) or 99,
    )

    assert calls == []
    assert [(result.entry_id, result.pwned_count) for result in results] == [
        ("first", 0),
        ("second", 0),
    ]


def test_leak_audit_reports_progress(monkeypatch):
    monkeypatch.setattr(config, "_config_cache", {"leak_online_check": False})
    progress = []

    leak.audit_snapshots(
        [("first", 1.0, "a"), ("second", 2.0, "b")],
        on_progress=lambda done, total: progress.append((done, total)),
    )

    assert progress == [(1, 2), (2, 2)]


def test_leak_check_expires_on_configured_interval_but_zero_disables_expiry():
    checked_at = 1_700_000_000.0
    entry = Entry(title="Site", password="unique-password", updated_at=100.0)
    result = leak.make_check_result(entry, pwned_count=0, checked_at=checked_at)
    entry.leak_check_revision = result.revision
    entry.leak_pwned_count = result.pwned_count
    entry.leak_common_weak = result.common_weak
    entry.leak_checked_at = result.checked_at

    assert not leak.needs_online_check(entry, interval_days=5, now=checked_at + 5 * 86400 - 1)
    assert leak.needs_online_check(entry, interval_days=5, now=checked_at + 5 * 86400)
    assert not leak.needs_online_check(entry, interval_days=0, now=checked_at + 30 * 86400)

    entry.updated_at += 1
    assert not leak.needs_online_check(entry, interval_days=0, now=checked_at + 30 * 86400)


def test_needs_leak_check_force_ignores_zero_recheck_days_but_requires_secret():
    entry = Entry(title="Site", password="unique-password")
    assert not leak.needs_leak_check(entry, recheck_days=0)
    assert leak.needs_leak_check(entry, recheck_days=0, force=True)
    assert not leak.needs_leak_check(Entry(title="Empty"), recheck_days=5, force=True)


def test_entry_secret_matches_android_supported_types_only():
    assert leak.entry_secret(Entry(secret_type=SecretType.LOGIN, password="pw")) == "pw"
    assert leak.entry_secret(Entry(secret_type=SecretType.WIFI, fields={"wifi_password": "wifi-pw"})) == "wifi-pw"
    assert leak.entry_secret(Entry(secret_type=SecretType.API_KEY, fields={"api_key": "api-token"})) == "api-token"
    assert leak.entry_secret(Entry(secret_type=SecretType.CARD_DOCUMENT, fields={"cvv": "123"})) == ""


def test_only_current_card_document_type_is_registered():
    assert "credit_card" not in SecretType.ALL
    assert "id_card" not in SecretType.ALL
    assert "card_document" in SecretType.ALL
    assert "card_document" in SecretType.CREATABLE
    assert SecretType.LABELS[SecretType.CARD_DOCUMENT] == "卡证"


def test_vault_wrong_master(tmp_path: Path):
    p = tmp_path / "v.pmv"
    Vault.create(p, "master").add(Entry(title="x"))
    with pytest.raises(crypto.DecryptError):
        Vault.open(p, "nope")


def test_change_password(tmp_path: Path):
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "old")
    v.add(Entry(title="x", password="secret", notes="private", fields={"token": "value"}))
    assert v.verify_password("old") and not v.verify_password("bad")
    v.change_password("new")
    reopened = Vault.open(p, "new")
    assert reopened.entries[0].title == "x"
    assert reopened.entries[0].password == "secret"
    assert reopened.entries[0].notes == "private"
    assert reopened.entries[0].fields == {"token": "value"}
    with pytest.raises(crypto.DecryptError):
        Vault.open(p, "old")


# ---------- utils ----------
def test_generate_password_length_and_classes():
    pw = utils.generate_password(20, upper=True, lower=True, digits=True, symbols=True)
    assert len(pw) == 20
    assert any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)


def test_strength_monotonic():
    weak, _ = utils.strength("abc")
    strong, _ = utils.strength(utils.generate_password(24))
    assert strong > weak


# ---------- CSV import/export ----------
def _write_archive_csv_fixture(entries, path: Path) -> None:
    """Exercise the CSV payload embedded inside encrypted archives."""
    path.write_bytes(importers._csv_export_payload([entry for entry in entries if entry.deleted_at is None]))


def test_csv_roundtrip(tmp_path: Path):
    entries = [Entry(title="GitHub", username="a", password="p", url="https://g.com")]
    path = tmp_path / "out.csv"
    _write_archive_csv_fixture(entries, path)
    result = importers.import_csv(path)
    assert result.ok and result.entries[0].password == "p"


def test_csv_roundtrip_preserves_leak_cache(tmp_path: Path):
    entry = Entry(title="Leaked", username="alice", password="secret")
    entry.leak_pwned_count = 42
    entry.leak_common_weak = True
    entry.leak_checked_at = 1_700_000_000.0
    entry.leak_check_revision = entry.updated_at
    path = tmp_path / "leaked.csv"

    _write_archive_csv_fixture([entry], path)
    result = importers.import_csv(path)

    assert result.ok
    out = result.entries[0]
    assert out.leak_pwned_count == 42
    assert out.leak_common_weak is True
    assert out.leak_checked_at == 1_700_000_000.0
    assert out.leak_check_revision == out.updated_at


def test_csv_import_defaults_missing_type_to_login(tmp_path: Path):
    path = tmp_path / "login.csv"
    path.write_text(
        "name,url,username,password,note\nExample,https://example.com,alice,secret,hi\n",
        encoding="utf-8",
    )

    result = importers.import_csv(path)

    assert result.ok
    entry = result.entries[0]
    assert entry.secret_type == SecretType.LOGIN
    assert entry.password == "secret"


def test_chrome_csv_name_column_imports_as_login_title_only(tmp_path: Path):
    path = tmp_path / "chrome.csv"
    path.write_text(
        "name,url,username,password,note\nExample,https://example.com/login,alice,secret,from chrome\n",
        encoding="utf-8",
    )

    result = importers.import_csv(path)

    assert result.ok
    entry = result.entries[0]
    assert entry.secret_type == SecretType.LOGIN
    assert entry.title == "Example"
    assert entry.password == "secret"
    assert "full_name" not in entry.fields


def test_csv_import_uses_english_type_values(tmp_path: Path):
    path = tmp_path / "typed.csv"
    path.write_text(
        "type,name,username,password,fields,secret,issuer,label\n"
        "login,Site,alice,pw,{},,,\n"
        'card_document,Bank,,,{"card_type":"bank_card"},,,\n'
        'card_document,ID,,,{"card_type":"id_card"},,,\n'
        'card_document,Other,,,{"card_type":"custom"},,,\n'
        "wifi,Home,,wifi-pw,{},,,\n"
        "api_key,GitHub,GitHub,ghp_token,{},,,\n"
        "otp,,,,{},JBSWY3DPEHPK3PXP,GitHub,alice@example.com\n",
        encoding="utf-8",
    )

    result = importers.import_csv(path)

    assert result.ok
    by_type = {entry.secret_type: entry for entry in result.entries}
    assert set(by_type) == {
        SecretType.LOGIN,
        SecretType.CARD_DOCUMENT,
        SecretType.WIFI,
        SecretType.API_KEY,
        SecretType.OTP,
    }
    card_entries = [e for e in result.entries if e.secret_type == SecretType.CARD_DOCUMENT]
    assert [entry.fields["card_type"] for entry in card_entries] == [
        modules.CARD_BANK,
        modules.CARD_ID_CARD,
        modules.CARD_CUSTOM,
    ]
    assert by_type[SecretType.WIFI].get_field("wifi_password") == "wifi-pw"
    assert by_type[SecretType.API_KEY].get_field("api_key") == "ghp_token"
    assert by_type[SecretType.OTP].fields["secret"] == "JBSWY3DPEHPK3PXP"


def test_csv_import_does_not_guess_deleted_card_types_as_current_cards(tmp_path: Path):
    path = tmp_path / "deleted-card-types.csv"
    path.write_text(
        "type,name\n"
        "credit_card,Credit\n"
        "passport,Passport\n"
        "driving_license,Driving\n"
        "驾照,Driving CN\n"
        "membership_card,Member\n"
        "会员卡,Member CN\n",
        encoding="utf-8",
    )

    result = importers.import_csv(path)

    assert result.ok
    assert {entry.secret_type for entry in result.entries} == {SecretType.LOGIN}


def test_csv_export_writes_english_type_labels(tmp_path: Path):
    entries = [
        Entry(title="Login", secret_type=SecretType.LOGIN, password="pw"),
        Entry(title="Card", secret_type=SecretType.CARD_DOCUMENT, fields={"cardholder": "Alice", "expiry": "12/28"}),
        Entry(title="ID", secret_type=SecretType.CARD_DOCUMENT, fields={"full_name": "Alice"}),
        Entry(title="Wi-Fi", secret_type=SecretType.WIFI, fields={"wifi_password": "wifi-pw"}),
        Entry(title="Key", secret_type=SecretType.API_KEY, fields={"api_key": "token"}),
        Entry(title="OTP", secret_type=SecretType.OTP, fields={"secret": "JBSWY3DPEHPK3PXP"}),
    ]
    path = tmp_path / "types.csv"

    _write_archive_csv_fixture(entries, path)
    rows = list(csv.DictReader(path.read_text(encoding="utf-8-sig").splitlines()))

    assert [row["type"] for row in rows] == [
        "login",
        "card_document",
        "card_document",
        "wifi",
        "api_key",
        "otp",
    ]
    assert [row["title"] for row in rows] == ["Login", "Card", "ID", "Wi-Fi", "Key", "OTP"]
    assert rows[1]["cardholder"] == "Alice"
    assert rows[1]["card_expiry"] == "12/28"
    assert rows[2]["full_name"] == "Alice"
    assert rows[3]["wifi_password"] == "wifi-pw"
    assert rows[4]["api_key"] == "token"


def test_csv_export_excludes_deleted_entries(tmp_path: Path):
    entries = [
        Entry(title="Alive", password="pw"),
        Entry(title="Deleted", password="gone", deleted_at=1_700_000_000.0),
    ]
    path = tmp_path / "active.csv"

    _write_archive_csv_fixture(entries, path)
    rows = list(csv.DictReader(path.read_text(encoding="utf-8-sig").splitlines()))

    assert [row["title"] for row in rows] == ["Alive"]


def test_csv_otp_export_aligned_with_android_omits_secret(tmp_path: Path):
    fields = {
        "secret": "JBSWY3DPEHPK3PXP",
        "algorithm": "SHA256",
        "digits": "8",
        "period": "45",
        "issuer": "GitHub",
        "label": "alice@example.com",
        "type": "totp",
        "counter": "0",
        "android_extra": "kept",
    }
    entries = [Entry(title="GitHub", secret_type=SecretType.OTP, fields=fields)]
    path = tmp_path / "otp.csv"
    _write_archive_csv_fixture(entries, path)
    text = path.read_text(encoding="utf-8-sig")
    row = next(csv.DictReader(text.splitlines()))
    assert row["type"] == "otp"
    assert row["title"] == "GitHub"
    assert "JBSWY3DPEHPK3PXP" not in text


def test_csv_otpauth_uri_import(tmp_path: Path):
    path = tmp_path / "otp_uri.csv"
    path.write_text(
        "name,url,username,password,note\nGitHub,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,,,\n",
        encoding="utf-8",
    )
    result = importers.import_csv(path)
    assert result.ok
    entry = result.entries[0]
    assert entry.secret_type == SecretType.OTP
    assert entry.fields["issuer"] == "GitHub"


def test_csv_chrome_aliases(tmp_path: Path):
    path = tmp_path / "c.csv"
    path.write_text(
        "name,url,username,password,note\nEx,https://x.com,user,pw,hi\n",
        encoding="utf-8",
    )
    r = importers.import_csv(path)
    assert r.ok and r.entries[0].username == "user" and r.entries[0].notes == "hi"


def test_csv_empty_is_error(tmp_path: Path):
    path = tmp_path / "e.csv"
    path.write_text("name,url\n", encoding="utf-8")
    assert not importers.import_csv(path).ok


def test_password_manager_csv_variants(tmp_path: Path):
    samples = {
        "bitwarden.csv": (
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
            'Work,0,login,GitHub,primary,"team: platform",0,https://github.com,alice,secret,JBSWY3DPEHPK3PXP\n'
        ),
        "lastpass.csv": (
            "url,username,password,extra,name,grouping,fav\n"
            "https://mail.example,bob,pw2,memo,Mail,Personal,0\n"
        ),
        "onepassword.csv": (
            "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
            "Example,https://example.com,user,pw,otpauth://totp/Example:user?secret=ABC123,0,0,personal,hello\n"
        ),
        "keepass.csv": "Group,Title,Username,Password,URL,Notes\nWork,Portal,alice,pw,https://portal.example,note\n",
    }
    results = {}
    for filename, content in samples.items():
        path = tmp_path / filename
        path.write_text(content, encoding="utf-8")
        results[filename] = importers.import_password_manager(path)

    bitwarden = results["bitwarden.csv"].entries[0]
    assert results["bitwarden.csv"].source == "Bitwarden CSV"
    assert bitwarden.tags == ["Work"]
    assert bitwarden.fields["otp_secret"] == "JBSWY3DPEHPK3PXP"
    assert "team: platform" in bitwarden.notes
    assert results["lastpass.csv"].source == "LastPass CSV"
    assert results["lastpass.csv"].entries[0].tags == ["Personal"]
    assert results["lastpass.csv"].entries[0].notes == "memo"
    assert results["onepassword.csv"].entries[0].fields["otp_uri"].startswith("otpauth://")
    assert results["keepass.csv"].entries[0].tags == ["Work"]


def test_bitwarden_json_import(tmp_path: Path):
    path = tmp_path / "bitwarden.json"
    path.write_text(
        json.dumps({
            "encrypted": False,
            "folders": [{"id": "folder-1", "name": "Work"}],
            "items": [{
                "type": 1,
                "folderId": "folder-1",
                "name": "GitHub",
                "notes": "primary",
                "login": {
                    "username": "alice", "password": "secret", "totp": "ABC123",
                    "uris": [{"uri": "https://github.com"}],
                },
                "fields": [{"name": "team", "value": "platform"}],
            }],
        }),
        encoding="utf-8",
    )

    result = importers.import_password_manager(path)
    entry = result.entries[0]

    assert result.source == "Bitwarden JSON"
    assert entry.tags == ["Work"]
    assert entry.username == "alice" and entry.password == "secret"
    assert entry.fields["otp_secret"] == "ABC123"
    assert entry.fields["team"] == "platform"


# ---------- 加密备份 ----------
def test_backup_roundtrip(tmp_path: Path):
    entries = [Entry(title="A", username="u", password="p", tags=["x"])]
    path = tmp_path / ("b" + backup.SUFFIX)
    backup.export_encrypted(entries, path, "backup-pw")
    out = backup.import_encrypted(path, "backup-pw")
    assert out[0].title == "A" and out[0].password == "p"


def test_backup_otp_fields_roundtrip(tmp_path: Path):
    fields = {"secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": "6", "unknown": "x"}
    path = tmp_path / ("otp" + backup.SUFFIX)
    backup.export_encrypted([Entry(title="OTP", secret_type=SecretType.OTP, fields=fields)], path, "pw")
    out = backup.import_encrypted(path, "pw")[0]
    assert out.secret_type == SecretType.OTP
    assert out.fields == fields


def test_backup_wrong_password(tmp_path: Path):
    path = tmp_path / ("b" + backup.SUFFIX)
    backup.export_encrypted([Entry(title="A")], path, "right")
    with pytest.raises(crypto.DecryptError):
        backup.import_encrypted(path, "wrong")


def test_backup_export_writes_v2_format(tmp_path: Path):
    """导出文件应为 V2 布局：VERSION=2、KDF_ID=1（Argon2id）。"""
    path = tmp_path / ("b" + backup.SUFFIX)
    backup.export_encrypted([Entry(title="A")], path, "pw")
    raw = path.read_bytes()
    assert raw[:4] == backup.MAGIC
    assert raw[4] == pmv_backup.VERSION_V2
    assert raw[5] == pmv_backup.KDF_ID_ARGON2ID
    # 头长 46 + tag 16
    assert len(raw) >= 46 + 16


# ---------- 跨账户库合并护栏（SYNC_V2 §7.5）----------
def test_backup_carries_lineage(tmp_path: Path):
    """导出携带库谱系 device_id，导入端能取回（BackupPayload 往返）。"""
    path = tmp_path / ("b" + backup.SUFFIX)
    backup.export_encrypted([Entry(title="A", password="p")], path, "pw", device_id="lineage-123")
    payload = backup.import_encrypted_with_meta(path, "pw")
    assert payload.device_id == "lineage-123"
    assert payload.export_epoch > 0
    assert payload.entries[0].title == "A"


def test_backup_v1_without_lineage_compatible(tmp_path: Path):
    """老备份缺谱系信息时反序列化不报错，device_id 为空。"""
    path = tmp_path / ("b" + backup.SUFFIX)
    backup.export_encrypted([Entry(title="A")], path, "pw")  # 不传 device_id
    payload = backup.import_encrypted_with_meta(path, "pw")
    assert payload.device_id == ""


def test_same_lineage_logic():
    assert sync.same_lineage("abc", "abc") is True
    assert sync.same_lineage("abc", "xyz") is False
    assert sync.same_lineage("", "abc") is False  # 本地缺谱系
    assert sync.same_lineage("abc", "") is False  # 远端缺谱系
    assert sync.same_lineage("", "") is False  # 两端都缺
    assert sync.same_lineage(None, None) is False


def test_pmv_export_import_lineage_roundtrip(tmp_path: Path):
    """主库 .pmv 落盘后再读回，device_id 谱系稳定（同一份库自我同步应静默）。"""
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "m")
    v.add(Entry(title="A", password="p"))
    v.close()
    reopened = Vault.open(p, "m")
    device_id = reopened.device_id
    assert device_id and device_id == v.device_id
    assert sync.same_lineage(v.device_id, device_id)
    reopened.close()


# ---------- 合并与冲突 ----------
def test_merge_add_identical_conflict(tmp_path: Path):
    v = Vault.create(tmp_path / "v.pmv", "m")
    v.add(Entry(title="GitHub", username="alice", password="p1"))
    v.add(Entry(title="GitHub", username="carol", password="old"))
    incoming = [
        Entry(title="GitHub", username="alice", password="p1"),  # identical
        Entry(title="New", username="dan", password="x"),  # new
        Entry(title="GitHub", username="carol", password="new"),  # conflict
    ]
    stats = v.merge(incoming, lambda old, inc: "overwrite")
    assert stats["identical"] == 1
    assert stats["added"] == 1
    assert stats["overwritten"] == 1
    carol = next(e for e in v.entries if e.username == "carol")
    assert carol.password == "new"


def test_merge_identical_entries_does_not_save(tmp_path: Path, monkeypatch):
    v = Vault.create(tmp_path / "v.pmv", "m")
    entry = Entry(title="GitHub", username="alice", password="p1")
    v.add(entry)
    calls = []

    monkeypatch.setattr(v, "save", lambda: calls.append("save"))

    stats = v.merge([Entry(title="GitHub", username="alice", password="p1")], lambda old, inc: "skip")

    assert stats["identical"] == 1
    assert calls == []


def test_merge_identical_entry_imports_leak_cache(tmp_path: Path):
    v = Vault.create(tmp_path / "v.pmv", "m")
    v.add(Entry(title="GitHub", username="alice", password="p1"))
    incoming = Entry(title="GitHub", username="alice", password="p1")
    incoming.leak_pwned_count = 42
    incoming.leak_common_weak = True
    incoming.leak_checked_at = 1_700_000_000.0

    stats = v.merge([incoming], lambda old, inc: "skip")

    assert stats["identical"] == 0
    assert stats["overwritten"] == 1
    merged = v.entries[0]
    assert merged.leak_pwned_count == 42
    assert merged.leak_common_weak is True
    assert merged.leak_checked_at == 1_700_000_000.0
    assert merged.leak_check_revision == merged.updated_at


def test_merge_keep_both_and_skip(tmp_path: Path):
    v = Vault.create(tmp_path / "v.pmv", "m")
    v.add(Entry(title="S", username="u", password="a"))
    v.merge([Entry(title="S", username="u", password="b")], lambda o, i: "keep_both")
    assert len([e for e in v.entries if e.dedup_key() == (SecretType.LOGIN, "s", "u")]) == 2

    v2 = Vault.create(tmp_path / "v2.pmv", "m")
    v2.add(Entry(title="S", username="u", password="a"))
    v2.merge([Entry(title="S", username="u", password="b")], lambda o, i: "skip")
    assert next(e for e in v2.entries).password == "a"


def test_dedup_never_groups_login_and_passkey(tmp_path: Path):
    vault = Vault.create(tmp_path / "typed-dedup.pmv", "m")
    vault.add(Entry(title="PayPal", username="user@example.com", password="pw"))
    vault.add(Entry(title="PayPal", username="user@example.com", secret_type=SecretType.PASSKEY))

    assert vault.duplicate_groups() == []
    assert vault.dedup_entries() == {"exact_merged": 0, "pw_resolved": 0, "pw_skipped": 0}
    assert len(vault.entries) == 2


def test_duplicate_maintenance_only_scans_and_merges_login_entries(tmp_path: Path):
    vault = Vault.create(tmp_path / "login-only-dedup.pmv", "m")
    vault.add(Entry(title="Login", username="user", password="pw"))
    vault.add(Entry(title="Login", username="user", password="pw"))
    for index, secret_type in enumerate(t for t in SecretType.ALL if t != SecretType.LOGIN):
        vault.add(Entry(title=f"Same {index}", username="user", password="pw", secret_type=secret_type))
        vault.add(Entry(title=f"Same {index}", username="user", password="pw", secret_type=secret_type))

    assert vault.scan_duplicates() == {"exact": 1, "pw_conflict": 0}
    groups = vault.duplicate_groups()
    assert len(groups) == 1
    assert all(entry.secret_type == SecretType.LOGIN for entry in groups[0])

    assert vault.dedup_entries() == {"exact_merged": 1, "pw_resolved": 0, "pw_skipped": 0}
    assert len([entry for entry in vault.entries if entry.secret_type == SecretType.LOGIN]) == 1
    for secret_type in (t for t in SecretType.ALL if t != SecretType.LOGIN):
        assert len([entry for entry in vault.entries if entry.secret_type == secret_type]) == 2


def test_same_service_only_groups_login_entries(tmp_path: Path):
    vault = Vault.create(tmp_path / "same-service-types.pmv", "m")
    vault.add(Entry(title="PayPal personal", url="https://paypal.com/login"))
    vault.add(Entry(title="PayPal work", url="https://www.paypal.com/home"))
    vault.add(Entry(title="PayPal passkey", url="https://paypal.com", secret_type=SecretType.PASSKEY))
    vault.add(Entry(title="PayPal card", url="https://paypal.com", secret_type=SecretType.CARD_DOCUMENT))

    groups = vault.scan_same_service()

    assert len(groups) == 1
    assert {entry.title for entry in groups[0].entries} == {"PayPal personal", "PayPal work"}


# ---------- Sync v2（多端双向同步）----------
_FIXTURES = Path(__file__).resolve().parents[2] / "vault_android" / "spec" / "sync_v2_fixtures.json"
_SYNC_FIXTURE_CASES = json.loads(_FIXTURES.read_text("utf-8"))["fixtures"] if _FIXTURES.exists() else []


def _entry(d: dict) -> Entry:
    """把 fixture 里的简化记录转成 Entry（content 映射到 notes）。"""
    return Entry(
        id=d["id"],
        notes=d.get("content", ""),
        created_at=d["createdAt"],
        updated_at=d["updatedAt"],
        deleted_at=d.get("deletedAt"),
    )


@pytest.mark.skipif(not _FIXTURES.exists(), reason="缺少跨端测试向量 sync_v2_fixtures.json")
@pytest.mark.parametrize("fixture", _SYNC_FIXTURE_CASES, ids=lambda f: f["name"])
def test_sync_merge_fixtures(fixture):
    local = [_entry(e) for e in fixture["local"]["entries"]]
    incoming = [_entry(e) for e in fixture["incoming"]]
    choice = {
        "KEEP_LOCAL": sync.ConflictChoice.KEEP_LOCAL,
        "KEEP_REMOTE": sync.ConflictChoice.KEEP_REMOTE,
        "KEEP_BOTH": sync.ConflictChoice.KEEP_BOTH,
    }.get(fixture["onConflict"])
    on_conflict = (lambda l, r: choice) if choice else None

    merged, _ = sync.merge(local, incoming, on_conflict)

    if "expected" in fixture:
        got = {e.id: e for e in merged}
        exp = {e["id"]: e for e in fixture["expected"]["entries"]}
        assert got.keys() == exp.keys()
        for eid, ed in exp.items():
            e = got[eid]
            assert e.notes == ed["content"]
            assert e.updated_at == ed["updatedAt"]
            assert e.deleted_at == ed["deletedAt"]
    else:  # expected_constraint（KEEP_BOTH 生成随机 id）
        c = fixture["expected_constraint"]
        assert len(merged) == c["entries_count"]
        by_content = {e.notes: e for e in merged}
        for want in c["entries_contains"]:
            e = by_content[want["content"]]
            if want["id"] != "*ANY_NEW_UUID*":
                assert e.id == want["id"]
            else:
                assert e.id not in {x["id"] for x in fixture["incoming"]}
                assert e.updated_at == want["updatedAt"]


@pytest.mark.skipif(not _FIXTURES.exists(), reason="缺少跨端测试向量 sync_v2_fixtures.json")
def test_sync_export_epoch_does_not_rewrite_entry_timestamps():
    spec = json.loads(_FIXTURES.read_text("utf-8"))["clock_skew_test"]
    raw = [_entry({**r, "content": ""}) for r in spec["incoming_raw"]]
    calibrated = sync.calibrate(raw, spec["header_exportEpoch"], spec["local_now"])
    for got, original in zip(calibrated, raw):
        assert got.created_at == original.created_at
        assert got.updated_at == original.updated_at
        assert got.deleted_at == original.deleted_at


def test_sync_merge_compares_raw_per_entry_updated_at():
    local = [Entry(id="a", title="Local", password="old", updated_at=1_700_000_040.0)]
    incoming = [Entry(id="a", title="Remote", password="new", updated_at=1_700_000_000.0)]

    calibrated = sync.calibrate(incoming, export_epoch=1_700_000_000.0, local_now=1_700_000_050.0)
    merged, stats = sync.merge(local, calibrated)

    assert merged[0].title == "Local"
    assert merged[0].password == "old"
    assert merged[0].updated_at == 1_700_000_040.0
    assert stats["local_wins"] == 1


def test_sync_calibration_does_not_treat_old_export_age_as_clock_skew():
    local = [Entry(id="a", title="Android", password="local", updated_at=1_700_000_500.0)]
    incoming = [Entry(id="a", title="PC", password="remote", updated_at=1_700_000_000.0)]

    calibrated = sync.calibrate(incoming, export_epoch=1_700_000_000.0, local_now=1_700_000_600.0)
    merged, stats = sync.merge(local, calibrated)

    assert merged[0].title == "Android"
    assert merged[0].password == "local"
    assert merged[0].updated_at == 1_700_000_500.0
    assert stats["local_wins"] == 1


def test_sync_same_second_title_or_username_change_is_conflict_not_identical():
    local = [Entry(id="a", title="Old", username="alice", password="pw", updated_at=100.0)]
    incoming = [Entry(id="a", title="New", username="alice", password="pw", updated_at=100.0)]

    merged, stats = sync.merge(
        local,
        incoming,
        lambda _local, _remote: sync.ConflictChoice.KEEP_REMOTE,
    )

    assert merged[0].title == "New"
    assert stats["conflicts"] == 1
    assert stats["remote_wins"] == 1


def test_sync_preserves_android_package_when_newer_pc_revision_is_blank():
    local = Entry(id="shared", title="PC edit", updated_at=200.0, target_app="")
    remote = Entry(id="shared", title="Android edit", updated_at=100.0, target_app="com.example.android")

    merged, stats = sync.merge([local], [remote])

    assert merged[0].title == "PC edit"
    assert merged[0].target_app == "com.example.android"
    assert stats["local_wins"] == 1


def test_sync_preserves_target_app_module_fallback():
    local = Entry(id="shared", title="PC edit", updated_at=200.0)
    remote = Entry(
        id="shared",
        title="Android edit",
        updated_at=100.0,
        fields=modules.fields_with_modules(
            {}, [{"type": modules.TARGET_APP, "value": "com.example.module"}],
        ),
    )

    merged, _, _ = sync.merge_with_purges([local], [remote])

    assert merged[0].target_app == "com.example.module"


def test_sync_coalesces_different_ids_when_only_android_package_differs():
    local = Entry(id="pc-id", title="Example", username="alice", password="secret", updated_at=100.0)
    remote = Entry(
        id="android-id",
        title="Example",
        username="alice",
        password="secret",
        updated_at=200.0,
        target_app="com.example.app",
    )

    merged, stats, purges = sync.merge_with_purges([local], [remote])

    assert len(merged) == 1
    assert merged[0].id == "pc-id"
    assert merged[0].target_app == "com.example.app"
    assert purges["android-id"] > remote.updated_at
    assert stats["coalesced"] == 1


def test_sync_does_not_coalesce_two_intentional_duplicates_without_package():
    local = Entry(id="one", title="Example", username="alice", password="secret")
    remote = Entry(id="two", title="Example", username="alice", password="secret")

    merged, stats, purges = sync.merge_with_purges([local], [remote])

    assert {entry.id for entry in merged} == {"one", "two"}
    assert stats["coalesced"] == 0
    assert purges == {}


def test_sync_same_second_delete_state_difference_is_conflict_not_identical():
    local = [Entry(id="a", title="A", password="pw", updated_at=100.0, deleted_at=100.0)]
    incoming = [Entry(id="a", title="A", password="pw", updated_at=100.0, deleted_at=None)]

    merged, stats = sync.merge(
        local,
        incoming,
        lambda _local, _remote: sync.ConflictChoice.KEEP_REMOTE,
    )

    assert merged[0].deleted_at is None
    assert stats["conflicts"] == 1
    assert stats["remote_wins"] == 1
    assert stats["identical"] == 0


def test_sync_merge_roundtrip_tombstones(tmp_path: Path):
    """端到端：本地删除产生墓碑，远端较新编辑 → 复活；落盘后重开保持。"""
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "m")
    e = Entry(title="A", username="u", password="p")
    v.add(e)
    v.delete(e.id)
    assert len(v.entries) == 0 and len(v.trash) == 1

    remote = Entry(id=e.id, title="A", username="u", password="edited", created_at=e.created_at, updated_at=v.trash[0].updated_at + 100)
    v.sync_merge([remote], remote_export_epoch=None, on_conflict=None)
    assert len(v.entries) == 1 and len(v.trash) == 0
    assert v.entries[0].password == "edited"

    reopened = Vault.open(p, "m")
    assert reopened.device_id == v.device_id
    assert reopened.entries[0].password == "edited"


def test_recycle_delete_and_restore_update_updated_at(tmp_path: Path):
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "m")
    e = Entry(title="A", username="u", password="p", updated_at=1234)
    v.add(e)

    v.delete(e.id)
    deleted_updated_at = v.trash[0].updated_at
    assert deleted_updated_at > 1234
    v.restore(e.id)

    assert len(v.entries) == 1
    assert v.entries[0].updated_at >= deleted_updated_at
    assert v.entries[0].deleted_at is None


def test_local_mutations_stay_newer_than_future_imported_timestamp(tmp_path: Path):
    future = time.time() + 86_400.0

    touched = Entry(title="Touch", updated_at=future)
    touched.touch()
    assert touched.updated_at > future

    p = tmp_path / "future.pmv"
    v = Vault.create(p, "m")
    imported = Entry(title="Imported", username="u", password="p", updated_at=future)
    v.add(imported)

    v.delete(imported.id)
    deleted_revision = v.trash[0].updated_at
    assert deleted_revision > future
    assert v.trash[0].deleted_at == deleted_revision

    v.restore(imported.id)
    assert v.entries[0].updated_at > deleted_revision

    v.delete(imported.id)
    deleted_revision = v.trash[0].updated_at
    v.purge(imported.id)
    assert v._purge_tombstones[imported.id] > deleted_revision


def test_recycle_batch_restore_updates_updated_at_and_purge_records_tombstone(tmp_path: Path):
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "m")
    a = Entry(title="A", username="u", password="p", updated_at=111)
    b = Entry(title="B", username="u", password="p", updated_at=222)
    c = Entry(title="C", username="u", password="p", updated_at=333)
    for entry in (a, b, c):
        v.add(entry)
        v.delete(entry.id)

    assert v.restore_many([a.id, b.id]) == 2
    restored = {entry.id: entry for entry in v.entries}
    assert restored[a.id].updated_at > 111
    assert restored[b.id].updated_at > 222
    assert restored[a.id].deleted_at is None
    assert restored[b.id].deleted_at is None

    assert v.purge_many([c.id]) == 1
    assert c.id not in {entry.id for entry in v.trash}
    assert c.id in v._purge_tombstones


def test_sync_purge_tombstone_removes_older_local_entry(tmp_path: Path):
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "m")
    e = Entry(id="00000000-0000-0000-0000-000000000001", title="A", username="u", password="p", updated_at=100.0)
    v.add(e)

    stats = v.sync_merge(
        [],
        remote_export_epoch=None,
        incoming_purge_tombstones={e.id: 200.0},
    )

    assert len(v.entries) == 0
    assert len(v.trash) == 0
    assert v._purge_tombstones[e.id] == 200.0
    assert stats["purged"] == 1


def test_sync_newer_entry_suppresses_older_purge_tombstone(tmp_path: Path):
    p = tmp_path / "v.pmv"
    v = Vault.create(p, "m")
    e = Entry(id="00000000-0000-0000-0000-000000000001", title="A", username="u", password="p", updated_at=300.0)
    v.add(e)

    stats = v.sync_merge(
        [],
        remote_export_epoch=None,
        incoming_purge_tombstones={e.id: 200.0},
    )

    assert len(v.entries) == 1
    assert "a" not in v._purge_tombstones
    assert stats["purge_skipped"] == 1


# ---------- 账户回收站（ACCOUNT_LIFECYCLE）----------
@pytest.fixture
def _isolated_config(tmp_path, monkeypatch):
    """把 config 的存储与库目录隔离到 tmp_path，避免污染真实用户配置。"""
    monkeypatch.setenv("APPDATA", str(tmp_path))
    import importlib

    from core import config as _config

    importlib.reload(_config)
    return _config


def _seed_account(config, name: str) -> Path:
    filename = config.unique_vault_filename(name)
    path = config.vault_dir() / filename
    Vault.create(path, "pw")
    config.register_user(name, filename)
    config.set_current_user(name)
    return path


def test_empty_user_registry_recovers_existing_vault_files(_isolated_config):
    config = _isolated_config
    first = config.vault_dir() / "FAE.pmv"
    second = config.vault_dir() / "Bob.pmv"
    Vault.create(first, "pw")
    time.sleep(0.01)
    Vault.create(second, "pw")
    (config.vault_dir() / "ignored.pmv").write_bytes(b"not-a-vault")
    config.save({"users": [], "current_user": None, "trashed_accounts": {}})

    users = config.list_users(include_trashed=True)

    assert [user["name"] for user in users] == ["Bob", "FAE"]
    assert [user["file"] for user in users] == ["Bob.pmv", "FAE.pmv"]
    assert config.get_current_user() == "Bob"


def test_user_registry_recovery_does_not_restore_trashed_accounts(_isolated_config):
    config = _isolated_config
    Vault.create(config.vault_dir() / "FAE.pmv", "pw")
    config.save({
        "users": [],
        "current_user": None,
        "trashed_accounts": {"FAE": int(time.time() * 1000)},
    })

    assert config.list_users(include_trashed=True) == []
    assert config.get_current_user() is None


def test_register_user_preserves_trashed_records(_isolated_config):
    config = _isolated_config
    _seed_account(config, "FAE")
    config.trash_account("FAE")

    config.register_user("Bob", "Bob.pmv")

    assert [user["name"] for user in config.list_users(include_trashed=True)] == ["FAE", "Bob"]


def test_trash_hides_account_but_keeps_file(_isolated_config):
    config = _isolated_config
    path = _seed_account(config, "FAE")
    config.trash_account("FAE")

    assert config.is_account_trashed("FAE")
    assert [u["name"] for u in config.list_users()] == []  # 默认隐藏
    assert [u["name"] for u in config.list_users(include_trashed=True)] == ["FAE"]
    assert path.exists()  # 文件不动
    assert config.get_current_user() is None  # 当前账户被清空


def test_restore_account(_isolated_config):
    config = _isolated_config
    _seed_account(config, "Bob")
    config.trash_account("Bob")
    assert config.restore_account("Bob") is True
    assert not config.is_account_trashed("Bob")
    assert [u["name"] for u in config.list_users()] == ["Bob"]
    assert config.restore_account("Bob") is False  # 已不在回收站


def test_purge_expired_removes_files_and_record(_isolated_config):
    config = _isolated_config
    path = _seed_account(config, "Carol")
    bak = path.with_suffix(path.suffix + ".bak")
    bak.write_bytes(b"x")
    config.trash_account("Carol")

    # 未到期不清理
    assert config.purge_expired_accounts() == []
    assert path.exists()

    # 把删除时刻提前到超过保留期
    data = config.load()
    data["trashed_accounts"]["Carol"] -= (config.ACCOUNT_RETENTION_DAYS + 1) * 86400 * 1000
    config.save(data)

    assert config.purge_expired_accounts() == ["Carol"]
    assert not path.exists()
    assert not bak.exists()
    assert config.list_users(include_trashed=True) == []
    assert "Carol" not in config.trashed_accounts()
