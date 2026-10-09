import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from core import config
from ui.cloud_preferences import SettingsPreferenceWriter
from ui.settings_page import SettingsPage


@pytest.fixture
def application():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def encrypted_config(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(config, "_config_cache", None)
    monkeypatch.setattr(config, "_config_integrity_failed", False)
    monkeypatch.setattr(config, "_staged_settings", {})
    monkeypatch.setattr(config, "_staged_settings_generations", {})
    monkeypatch.setattr(config, "_staged_cloud_auto", {})
    monkeypatch.setattr(config, "_staged_cloud_auto_generations", {})
    monkeypatch.setattr(config, "_protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr(config, "_unprotect_key", lambda value: value.removeprefix(b"protected:"))
    config.save({"current_user": "alice", "account_settings": {
        "alice": {"theme_mode": "light", "lock_seconds": 60},
        "bob": {"theme_mode": "dark", "lock_seconds": 120},
    }})
    return config


def spin(application, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(.002)
    assert predicate()


def test_account_capture_overlay_and_encrypted_roundtrip(encrypted_config):
    values = {"theme_mode": "dark", "language_mode": "en", "lock_seconds": 90,
              "lock_enabled": True, "silent_start": True}
    config.stage_settings_many("alice", values)
    assert config.theme_mode() == "dark"
    assert config.language_mode() == "en"
    assert config.lock_seconds() == 90
    config.set("current_user", "bob")
    assert config.theme_mode() == "dark"
    assert config.lock_seconds() == 120
    assert config.get("silent_start") is True  # Global setting retains its scope.
    config.stage_settings_many("bob", {"lock_seconds": 300})
    config.persist_settings_many("alice", values)
    config.reconcile_settings_many("alice", values)
    assert config.lock_seconds() == 300
    disk = config._load_uncached()
    assert disk["current_user"] == "bob"
    assert disk["account_settings"]["alice"]["lock_seconds"] == 90
    assert disk["account_settings"]["bob"]["lock_seconds"] == 120
    assert disk["silent_start"] is True
    config.persist_settings_many("bob", {"lock_seconds": 300})
    config.reconcile_settings_many("bob", {"lock_seconds": 300})
    config.invalidate_cache()
    assert config.lock_seconds() == 300


@pytest.mark.parametrize("key,value", [
    ("require_master_for_sensitive", False), ("screen_capture_allowed", True),
    ("webdav_password", "secret"), ("master_password", "secret"),
    ("lock_seconds", "secret"), ("lock_enabled", 1),
])
def test_allowlist_excludes_security_grants_and_passwords(key, value):
    with pytest.raises(ValueError):
        config.stage_settings_many("alice", {key: value})
    with pytest.raises(ValueError):
        config.persist_settings_many("alice", {key: value})


@pytest.mark.parametrize("batch", [False, True])
def test_direct_same_scope_change_supersedes_queued_snapshot(encrypted_config, batch):
    config.stage_settings_many("alice", {"lock_enabled": True, "lock_seconds": 90})
    config.set("current_user", "bob")
    config.set("lock_seconds", 180)
    assert config._staged_settings[("alice", "lock_seconds")] == 90
    config.set("current_user", "alice")
    if batch:
        config.set_many({"lock_enabled": False})
    else:
        config.set("lock_enabled", False)
    config.persist_settings_many("alice", {"lock_enabled": True, "lock_seconds": 90})
    config.reconcile_settings_many("alice", {"lock_enabled": True, "lock_seconds": 90})
    assert config.get("lock_enabled") is False
    assert config.lock_seconds() == 90
    assert config._load_uncached()["account_settings"]["bob"]["lock_seconds"] == 180


def test_account_removed_before_late_write_is_not_recreated(encrypted_config):
    config.stage_settings_many("alice", {"lock_seconds": 90})
    config.set("current_user", "bob")
    config.set("account_settings", {"bob": {"lock_seconds": 120}})
    with pytest.raises(ValueError, match="no longer exists"):
        config.persist_settings_many("alice", {"lock_seconds": 90})
    assert "alice" not in config._load_uncached()["account_settings"]


def test_rename_atomically_migrates_pending_settings_and_supersedes_old_jobs(encrypted_config):
    config.set("users", [{"name": "alice", "file": "alice.pmv"}, {"name": "bob", "file": "bob.pmv"}])
    values = {"theme_mode": "dark", "lock_seconds": 300}
    tokens = config.stage_settings_many("alice", values)
    config.rename_user("alice", "renamed")
    config.persist_settings_many("alice", values, generations=tokens)
    config.reconcile_settings_many("alice", values, tokens)
    assert config.get_current_user() == "renamed"
    assert config.lock_seconds() == 300
    disk = config._load_uncached()
    assert "alice" not in disk["account_settings"]
    assert disk["account_settings"]["renamed"]["theme_mode"] == "dark"


def test_settings_close_handoff_and_timer_responsive_during_slow_fsync(application, encrypted_config, monkeypatch):
    started, release, completed = threading.Event(), threading.Event(), threading.Event()
    original = config._save_uncached
    calls = []

    def slow_save(data, **kwargs):
        calls.append(data)
        started.set()
        assert release.wait(3)
        original(data, **kwargs)
        completed.set()

    monkeypatch.setattr(config, "_save_uncached", slow_save)
    writer = SettingsPreferenceWriter()
    page = SimpleNamespace(
        _pending_config_saves={}, _pending_config_generations={}, _settings_account="alice", _preference_writer=writer,
        _config_save_timer=QTimer(), _window=SimpleNamespace(
            apply_lock_settings=lambda: None, apply_privacy_settings=lambda: None,
            apply_native_autofill_settings=lambda: None),
    )
    page._flush_config_saves = lambda: SettingsPage._flush_config_saves(page)
    pulses = []
    timer = QTimer()
    timer.setInterval(5)
    timer.timeout.connect(lambda: pulses.append(time.perf_counter()))
    timer.start()
    start = time.perf_counter()
    for seconds in (60, 90, 120, 180, 300):
        SettingsPage._queue_config_save(page, "lock_seconds", seconds)
    SettingsPage._queue_config_save(page, "background_hide", True)
    SettingsPage._queue_config_save(page, "theme_mode", "dark")
    staging = time.perf_counter() - start
    assert config.lock_seconds() == 300
    assert config.theme_mode() == "dark"
    close_start = time.perf_counter()
    SettingsPage._save_all(page)
    close_elapsed = time.perf_counter() - close_start
    try:
        spin(application, started.is_set)
        spin(application, lambda: len(pulses) >= 10)
        assert not completed.is_set()
        assert len(calls) == 1
        assert page._pending_config_saves == {}
        print(f"settings staging burst {staging * 1000:.2f} ms, close handoff {close_elapsed * 1000:.2f} ms; {len(pulses)} UI timer pulses during blocked fsync")
    finally:
        release.set()
        spin(application, completed.is_set)
        timer.stop()
        page._config_save_timer.stop()
        writer.deleteLater()


def test_common_settings_batch_baseline_and_background_handoff(application, encrypted_config, monkeypatch):
    original = config._save_uncached
    writes = []

    def delayed_save(data, **kwargs):
        time.sleep(.02)
        original(data, **kwargs)
        writes.append(1)

    monkeypatch.setattr(config, "_save_uncached", delayed_save)
    values = {"theme_mode": "dark", "language_mode": "en", "lock_enabled": True,
              "lock_seconds": 300, "clipboard_clear_seconds": 30,
              "background_hide": True, "silent_start": True}
    config.stage_many(values)
    start = time.perf_counter()
    config.set_many(values)  # Former settings timer/close callback.
    baseline = time.perf_counter() - start
    config.set_many({"theme_mode": "light", "lock_seconds": 60})
    writer = SettingsPreferenceWriter()
    writes.clear()
    config.stage_settings_many("alice", values)
    start = time.perf_counter()
    writer.submit("alice", values)
    handoff = time.perf_counter() - start
    spin(application, lambda: bool(writes))
    assert len(writes) == 1
    print(f"7 common settings, 20ms synthetic persistence delay: former UI flush {baseline * 1000:.2f} ms; background handoff {handoff * 1000:.2f} ms")
    writer.deleteLater()


@pytest.mark.parametrize("kind", ["cloud", "account"])
def test_aba_edits_survive_delayed_older_ui_completions(application, encrypted_config, monkeypatch, kind):
    from ui.cloud_preferences import CloudPreferenceWriter

    first_done, second_done, third_started, release, third_done = [threading.Event() for _ in range(5)]
    calls = []
    if kind == "cloud":
        key, a, b = "cloud_auto_enabled_drive_a", True, False
        original = config.persist_cloud_auto_many
        writer = CloudPreferenceWriter()

        def stage(value):
            writer.stage({key: value})
            writer.flush()

        def wrapped(values, **kwargs):
            persist(values, kwargs)

        monkeypatch.setattr(config, "persist_cloud_auto_many", wrapped)
        read_disk = lambda: config._load_uncached().get(key)
    else:
        key, a, b = "theme_mode", "dark", "light"
        original = config.persist_settings_many
        writer = SettingsPreferenceWriter()

        def stage(value):
            tokens = config.stage_settings_many("alice", {key: value})
            writer.submit("alice", {key: value}, tokens)

        def wrapped(account, values, **kwargs):
            persist(values, kwargs, account)

        monkeypatch.setattr(config, "persist_settings_many", wrapped)
        read_disk = lambda: config._load_uncached()["account_settings"]["alice"][key]

    def persist(values, kwargs, account=None):
        calls.append(values[key])
        number = len(calls)
        if number == 3:
            third_started.set()
            assert release.wait(3)
        if kind == "cloud":
            original(values, **kwargs)
        else:
            original(account, values, **kwargs)
        (first_done, second_done, third_done)[number - 1].set()

    try:
        stage(a)
        assert first_done.wait(3)  # Deliberately do not dispatch queued Qt completions.
        stage(b)
        assert second_done.wait(3)
        assert read_disk() == b
        stage(a)
        assert third_started.wait(3)
        application.processEvents()  # A1 completion must not clear the A3 overlay.
        assert config.get(key) == a
        release.set()
        spin(application, third_done.is_set)
        assert read_disk() == a
        assert calls == [a, b, a]
    finally:
        release.set()
        writer.deleteLater()
