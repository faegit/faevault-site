import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from core import config
from ui.cloud_preferences import CloudPreferenceWriter


@pytest.fixture
def application():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def encrypted_config(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(config, "_config_cache", None)
    monkeypatch.setattr(config, "_config_integrity_failed", False)
    monkeypatch.setattr(config, "_staged_cloud_auto", {})
    monkeypatch.setattr(config, "_staged_cloud_auto_generations", {})
    monkeypatch.setattr(config, "_protect_key", lambda key: b"protected:" + key)
    monkeypatch.setattr(config, "_unprotect_key", lambda value: value.removeprefix(b"protected:"))
    config.save({"current_user": "alice", "account_settings": {"alice": {"theme_mode": "dark"}}})
    return config


def spin(application, predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        application.processEvents()
        time.sleep(.002)
    assert predicate()


def test_background_disk_merge_preserves_newer_cache_and_account(encrypted_config):
    config.stage_cloud_auto_many({"cloud_auto_interval_drive_a": 15})
    old = {"cloud_auto_interval_drive_a": 15}
    config.stage_cloud_auto_many({"cloud_auto_interval_drive_a": 60})
    config.set("current_user", "bob")
    config.set_many({"theme_mode": "light"})
    assert config.get("cloud_auto_interval_drive_a") == 60
    config.persist_cloud_auto_many(old)
    assert config.get("cloud_auto_interval_drive_a") == 60
    assert config.get("current_user") == "bob"
    disk = config._load_uncached()
    assert disk["cloud_auto_interval_drive_a"] == 15
    assert disk["current_user"] == "bob"
    assert disk["account_settings"]["alice"]["theme_mode"] == "dark"
    config.persist_cloud_auto_many({"cloud_auto_interval_drive_a": 60})
    config.reconcile_cloud_auto_many({"cloud_auto_interval_drive_a": 60})
    config.invalidate_cache()
    assert config.get("cloud_auto_interval_drive_a") == 60


@pytest.mark.parametrize("values", [{"theme_mode": 1}, {"cloud_auto_password": "secret"}])
def test_writer_rejects_account_settings_and_secret_values(values):
    with pytest.raises(ValueError):
        config.persist_cloud_auto_many(values)


@pytest.mark.parametrize("batch", [False, True])
def test_explicit_disable_supersedes_queued_enable(encrypted_config, batch):
    values = {"cloud_auto_enabled_drive_a": True}
    config.stage_cloud_auto_many(values)
    if batch:
        config.set_many({"cloud_auto_enabled_drive_a": False})
    else:
        config.set("cloud_auto_enabled_drive_a", False)
    config.persist_cloud_auto_many(values)
    config.reconcile_cloud_auto_many(values)
    assert config.get("cloud_auto_enabled_drive_a") is False
    assert config._load_uncached()["cloud_auto_enabled_drive_a"] is False


def test_app_writer_is_reused_by_reopened_pages(application):
    from ui.cloud_preferences import cloud_preference_writer
    assert cloud_preference_writer() is cloud_preference_writer()


def test_background_save_failure_is_reported_on_ui_thread(application, encrypted_config, monkeypatch):
    from PySide6.QtCore import QThread

    def fail(values, **kwargs):
        raise OSError("synthetic disk failure")

    monkeypatch.setattr(config, "persist_cloud_auto_many", fail)
    writer = CloudPreferenceWriter()
    failures = []
    writer.failed.connect(lambda error: failures.append((error, QThread.currentThread())))
    writer.stage({"cloud_auto_interval_drive_a": 180})
    writer.flush()
    spin(application, lambda: bool(failures))
    assert failures == [("synthetic disk failure", application.thread())]
    writer.deleteLater()


def test_slider_burst_coalesces_and_close_flush_keeps_event_loop_alive(application, encrypted_config, monkeypatch):
    started, release, done = threading.Event(), threading.Event(), threading.Event()
    writes = []
    original = config._save_uncached

    def slow_fsync(data, **kwargs):
        writes.append(dict(data))
        started.set()
        assert release.wait(3)
        original(data, **kwargs)
        done.set()

    monkeypatch.setattr(config, "_save_uncached", slow_fsync)
    writer = CloudPreferenceWriter()
    timer = QTimer()
    pulses = []
    timer.setInterval(5)
    timer.timeout.connect(lambda: pulses.append(time.perf_counter()))
    timer.start()
    try:
        for interval in (15, 30, 60, 180, 360, 1440, 10080):
            writer.stage({"cloud_auto_enabled_drive_a": True, "cloud_auto_interval_drive_a": interval})
        assert not writes
        assert config.get("cloud_auto_interval_drive_a") == 10080
        start = time.perf_counter()
        writer.flush()  # Same handoff used by close_page; never joins on UI.
        handoff = time.perf_counter() - start
        spin(application, started.is_set)
        spin(application, lambda: len(pulses) >= 10)
        assert not done.is_set()
        assert len(writes) == 1
        assert writes[0]["cloud_auto_interval_drive_a"] == 10080
        print(f"background close handoff: {handoff * 1000:.2f} ms; UI timer pulses during blocked fsync: {len(pulses)}")
    finally:
        release.set()
        spin(application, done.is_set)
        timer.stop()
        writer.deleteLater()


def test_overlapping_flushes_persist_in_order(application, encrypted_config, monkeypatch):
    first_started, release, second_done = threading.Event(), threading.Event(), threading.Event()
    original = config.persist_cloud_auto_many
    order = []

    def blocked_write(values, **kwargs):
        order.append(values["cloud_auto_interval_drive_a"])
        if len(order) == 1:
            first_started.set()
            assert release.wait(3)
        original(values, **kwargs)
        if len(order) == 2:
            second_done.set()

    monkeypatch.setattr(config, "persist_cloud_auto_many", blocked_write)
    writer = CloudPreferenceWriter()
    try:
        writer.stage({"cloud_auto_interval_drive_a": 15})
        writer.flush()
        spin(application, first_started.is_set)
        writer.stage({"cloud_auto_interval_drive_a": 10080})
        writer.flush()
        assert config.get("cloud_auto_interval_drive_a") == 10080
    finally:
        release.set()
        spin(application, second_done.is_set)
        writer.deleteLater()
    assert order == [15, 10080]
    config.invalidate_cache()
    assert config.get("cloud_auto_interval_drive_a") == 10080


def test_legacy_slider_baseline_and_background_stage_latency(application, encrypted_config, monkeypatch):
    original = config._save_uncached
    writes = []

    def delayed_save(data, **kwargs):
        time.sleep(.02)  # Synthetic encrypted storage delay, not a real disk claim.
        original(data, **kwargs)
        writes.append(1)

    monkeypatch.setattr(config, "_save_uncached", delayed_save)
    intervals = (15, 30, 60, 180, 360, 1440, 10080)
    baseline = time.perf_counter()
    for interval in intervals:
        # Previous make_auto_slider.save wrote both keys for every valueChanged.
        config.set("cloud_auto_enabled_drive_a", True)
        config.set("cloud_auto_interval_drive_a", interval)
    baseline = time.perf_counter() - baseline
    baseline_writes = len(writes)
    config.set("cloud_auto_interval_drive_a", 60)
    writer = CloudPreferenceWriter()
    start = time.perf_counter()
    for interval in intervals:
        writer.stage({"cloud_auto_enabled_drive_a": True, "cloud_auto_interval_drive_a": interval})
    staging = time.perf_counter() - start
    writes.clear()
    writer.flush()
    spin(application, lambda: bool(writes))
    assert len(writes) == 1
    print(f"7 slider changes, 20ms synthetic persistence delay: baseline {baseline * 1000:.2f} ms / {baseline_writes} writes; staged callbacks {staging * 1000:.2f} ms / 1 background write")
    writer.deleteLater()


def test_real_cloud_slider_keyboard_and_close_handoff(application, encrypted_config, monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QWidget, QSlider
    from core import crypto
    from ui.cloud_sync_controller import CloudSyncController
    from ui.sync_pages import CloudSyncContext, CloudSyncWorkspacePage

    window = QWidget()
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"cloud_auto_{name}_{target}_a"
    window.vault = SimpleNamespace(path=Path("test.pmv"), entries=[], trash=[])
    controller = CloudSyncController(window.vault, vault_path=window.vault.path,
        password=crypto.SecureString("test"), cloud_vault_id="a", parent=window)
    controller.loaded = True
    controller.drive_path = Path("remote.pmv")
    controller.drive_health = "ok"
    window._cloud_controller = controller
    monkeypatch.setattr(controller, "check_remote_updates", lambda: None)
    config.set("cloud_auto_enabled_drive_a", True)
    config.set("cloud_auto_interval_drive_a", 60)
    page = CloudSyncWorkspacePage(CloudSyncContext(window.vault, window.vault.path, None, "a", window), window)
    slider = page.ui.drive.page.findChild(QSlider)
    completed = threading.Event()
    recorded = []
    original = config.persist_cloud_auto_many

    def record(values, **kwargs):
        recorded.append(values)
        original(values, **kwargs)
        completed.set()

    monkeypatch.setattr(config, "persist_cloud_auto_many", record)
    try:
        QTest.keyClick(slider, Qt.Key_Right)
        assert config.get("cloud_auto_interval_drive_a") == 180
        controller.stateChanged.emit()
        assert slider.value() == 3  # Refresh preserves the immediately staged value.
        assert not recorded
        page.close_page("lock")
        spin(application, completed.is_set)
        assert recorded == [{"cloud_auto_enabled_drive_a": True,
                             "cloud_auto_interval_drive_a": 180,
                             "cloud_auto_enabled_at_drive_a": config.get("cloud_auto_enabled_at_drive_a")}]
        config.invalidate_cache()
        assert config.get("cloud_auto_interval_drive_a") == 180
    finally:
        page.close_page("test")
        controller.cancel_active_operations()
        window.deleteLater()
