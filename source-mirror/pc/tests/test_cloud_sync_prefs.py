from core import cloud_sync_prefs as prefs


def _cfg(tmp_path, monkeypatch):
    from core import config as cfg

    monkeypatch.setattr(cfg, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(cfg, "_config_cache", None)
    return cfg


def test_intervals_and_defaults():
    assert prefs.INTERVALS == (15, 30, 60, 180, 360, 1440, 10080)
    assert prefs.DEFAULT_INTERVAL_MINUTES == 60
    assert prefs.TARGETS == ("drive", "webdav")


def test_suffix_matches_android_scheme():
    assert len(prefs.suffix("vault-a")) == 24
    assert all(c in "0123456789abcdef" for c in prefs.suffix("vault-a"))
    assert prefs.suffix("vault-a") != prefs.suffix("vault-b")
    assert prefs.suffix("vault-a") == prefs.suffix("vault-a")


def test_master_toggle_roundtrip(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    assert prefs.master_enabled(vid) is False
    prefs.set_master_enabled(vid, True)
    assert prefs.master_enabled(vid) is True
    prefs.set_master_enabled(vid, False)
    assert prefs.master_enabled(vid) is False


def test_load_defaults_when_unset(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    settings = prefs.load("vault-a")
    assert settings.target == ""
    assert settings.enabled is False
    assert settings.interval_minutes == prefs.DEFAULT_INTERVAL_MINUTES
    assert settings.status == prefs.STATUS_NEVER


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "drive", 30)
    settings = prefs.load(vid)
    assert settings.target == "drive"
    assert settings.enabled is True
    assert settings.interval_minutes == 30
    assert settings.enabled_at > 0.0
    assert settings.last_success == 0.0


def test_save_keeps_enabled_at_on_reenable(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "drive", 60)
    first = prefs.load(vid).enabled_at
    prefs.save(vid, True, "drive", 60)
    assert prefs.load(vid).enabled_at == first


def test_save_validates_interval_and_target(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "drive", 999)
    assert prefs.load(vid).interval_minutes == prefs.DEFAULT_INTERVAL_MINUTES
    try:
        prefs.save(vid, True, "bogus", 60)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for unsupported target")


def test_success_records_status_and_clears_error(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "drive", 60)
    prefs.record_failure(vid, "drive", "boom")
    prefs.success(vid, "自动同步完成", "drive")
    settings = prefs.load(vid)
    assert settings.last_success > 0.0
    assert settings.failures == 0
    assert settings.status == "自动同步完成"
    status = prefs.load_sync_status(vid)
    assert status.target == "drive"
    assert status.last_success_at > 0.0
    assert status.error == ""


def test_failure_autodisables_after_three(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "drive", 60)
    for i in range(3):
        count = prefs.failure(vid, f"本次自动同步已跳过：失败{i + 1}", "drive")
    assert count == 3
    assert prefs.load(vid).enabled is False
    assert prefs.load_sync_status(vid).error == ""  # record_failure not called
    prefs.record_failure(vid, "drive", "boom")
    assert prefs.load_sync_status(vid).error == "boom"


def test_non_severe_failure_keeps_enabled(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "webdav", 60)
    count = prefs.failure(vid, "本次自动同步已跳过：超时", "webdav")
    assert count == 1
    assert prefs.load(vid).enabled is True


def test_skipped_status_writes_to_current_target(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    prefs.save(vid, True, "webdav", 60)
    prefs.skipped(vid, "自动同步目标未关联，已暂停")
    assert prefs.load(vid).status == "自动同步目标未关联，已暂停"


def test_is_due_semantics():
    now = 1_000_000.0
    # 未设置任何时间 → 到期
    assert prefs.is_due(0.0, 0.0, 60, now) is True
    # 距最近成功未到间隔 → 未到期
    assert prefs.is_due(now - 3600, now - 600, 60, now) is False
    assert prefs.is_due(now - 3600, now - 3601, 60, now) is True
    # 非法间隔回退默认 60
    assert prefs.is_due(now - 3600, now - 120, 9999, now) is False
    assert prefs.is_due(now - 3600, now - 3601, 9999, now) is True


def test_webdav_preview_cache_roundtrip(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    vid = "vault-a"
    assert prefs.load_webdav_preview_cache(vid) == prefs.WebDavPreviewCache()
    prefs.save_webdav_preview_cache(vid, "etag-1", 4096)
    cache = prefs.load_webdav_preview_cache(vid)
    assert cache.etag == "etag-1"
    assert cache.size == 4096


def test_per_vault_isolation(tmp_path, monkeypatch):
    _cfg(tmp_path, monkeypatch)
    prefs.save("vault-a", True, "drive", 60)
    prefs.save("vault-b", True, "webdav", 30)
    assert prefs.load("vault-a").target == "drive"
    assert prefs.load("vault-b").target == "webdav"
    assert prefs.master_enabled("vault-a") is False
