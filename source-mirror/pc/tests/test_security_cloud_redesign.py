import os
import threading
import time
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QCoreApplication, QEvent, QObject, QThread, QTimer, Qt, Signal
from PySide6.QtWidgets import QApplication, QWidget

from core import config, crypto, password_health
from core.models import Entry
from ui import cloud_sync_controller as cloud_mod
from ui.editor_workspace import EditorWorkspace
from ui.security_page import SecurityCenterPage
from ui.security_results import SecurityResultsModel
from ui.sync_pages import CloudSyncContext, CloudSyncWorkspacePage


@pytest.fixture
def app(monkeypatch):
    application = QApplication.instance() or QApplication([])
    original_windows = set(application.topLevelWidgets())
    monkeypatch.setattr(config, "get", lambda key, default=None: default)
    monkeypatch.setattr(config, "set", lambda *args: None)
    yield application
    for window in application.topLevelWidgets():
        if window in original_windows:
            continue
        close_page = getattr(window, "close_page", None)
        if callable(close_page):
            close_page("test")
        controller = getattr(window, "_cloud_controller", None)
        if controller is not None:
            controller.cancel_active_operations()
        window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    application.processEvents()


def spin(app, until, timeout=3):
    deadline = time.monotonic() + timeout
    while not until() and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(.002)
    assert until()


def test_cloud_drive_download_never_stages_beside_remote_vault(tmp_path):
    remote_dir = tmp_path / "cloud-drive"
    remote_dir.mkdir()
    remote = remote_dir / "FAE.pmv"
    remote.write_bytes(b"encrypted vault fixture")

    snapshots = []
    failures = []
    worker = cloud_mod.CloudDriveWorker("pull_file", remote)
    worker.completed.connect(lambda _action, snapshot: snapshots.append(snapshot))
    worker.failed.connect(failures.append)
    worker.run()

    assert not failures
    assert len(snapshots) == 1
    staged = Path(snapshots[0].path)
    try:
        assert staged.parent != remote_dir
        assert staged.read_bytes() == remote.read_bytes()
        assert list(remote_dir.iterdir()) == [remote]
    finally:
        cloud_mod.CloudSyncController._discard_download("pull_file", snapshots[0])
    assert not staged.exists()


def report():
    a = Entry(title="Work account", username="alice", password="do-not-search")
    b = Entry(title="Personal account", username="bob")
    c = Entry(title="Safe account", username="alice")
    findings = {f.key: () for f in password_health.FINDINGS}
    findings["weak"] = (a,)
    findings["duplicate"] = (a, b)
    return password_health.HealthReport(3, findings, (a, b), (), (c,))


def test_filters_intersect_and_do_not_search_secrets(app):
    model = SecurityResultsModel()
    model.set_report(report())
    model.filter(password_health.HIGH, "weak", "ALICE work")
    assert model.rowCount() == 1
    assert model.index(0).data() == "Work account"
    model.filter(password_health.HEALTHY, "weak", "")
    assert model.rowCount() == 0
    model.filter("", "", "do-not-search")
    assert model.rowCount() == 0
    model.filter("", "", "alice")
    assert model.rowCount() == 2


def test_security_empty_filter_and_refresh_remain_in_same_page(app, monkeypatch):
    monkeypatch.setattr(SecurityCenterPage, "_start_analysis", lambda *a, **k: None)
    page = SecurityCenterPage([], "")
    page._analysis_completed(report())
    page._open_filtered_list("weak")
    assert page._results_model.rowCount() == 1
    activated = []
    page.entryRequested.connect(activated.append)
    page._finding_item_clicked(page._results_model.index(0))
    assert activated == [page._results_model.rows[0][0]]
    page._analysis_completed(password_health.EMPTY_REPORT)
    assert page._results_model.rowCount() == 0
    assert not page._empty.isHidden()
    assert page._finding_filter.currentData() == "weak"
    page.close_page("test")


def test_automatic_scan_does_not_replace_user_operation_notice(app, monkeypatch):
    from ui.widgets import NoticeBar
    monkeypatch.setattr(SecurityCenterPage, "_start_analysis", lambda *a, **k: None)
    host = QWidget()
    host.resize(800, 600)
    notice = NoticeBar(host)
    page = SecurityCenterPage([], "")
    page.statusMessage.connect(notice.show_message)
    host.show()
    page.show()
    notice.show_message("已移入回收站")
    page.update_entries([], "after-delete")
    page._analysis_completed(report())
    assert notice.label.text() == "已移入回收站"
    # An explicit refresh may notify while the security page is being viewed.
    page._manual_refresh = True
    page._analysis_completed(report())
    assert "已扫描" in notice.label.text()
    notice.show_message("同步完成")
    page.hide()
    page._manual_refresh = True
    page._analysis_completed(report())
    assert notice.label.text() == "同步完成"
    page.close_page("test")
    page.close()
    host.close()


def test_large_security_list_has_no_row_widgets(app, monkeypatch):
    monkeypatch.setattr(SecurityCenterPage, "_start_analysis", lambda *a, **k: None)
    page = SecurityCenterPage([], "")
    entries = tuple(Entry(title=f"Account {i}") for i in range(10000))
    findings = {f.key: () for f in password_health.FINDINGS}
    findings["weak"] = entries
    start = time.perf_counter()
    page._analysis_completed(password_health.HealthReport(len(entries), findings, entries, (), ()))
    elapsed = time.perf_counter() - start
    assert page._results_model.rowCount() == 10000
    assert page._finding_list.viewport().findChildren(QWidget) == [page._list_transition]
    assert page._finding_list.indexWidget(page._results_model.index(0, 0)) is None
    assert elapsed < 3  # Loose regression budget, not a UI latency claim.
    print(f"10000 rows indexed and filtered: {elapsed * 1000:.1f} ms")
    page.close_page("test")


def make_controller(parent=None):
    vault = SimpleNamespace(path=Path("test.pmv"), entries=[], trash=[])
    controller = cloud_mod.CloudSyncController(vault, vault_path=vault.path,
        password=crypto.SecureString("test"), cloud_vault_id="test", parent=parent)
    controller.loaded = True
    return controller, vault


def test_cloud_close_reopen_retains_live_task_and_detaches_old_view(app, monkeypatch):
    window = QWidget()
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"{target}_{name}"
    controller, window.vault = make_controller(window)
    window._cloud_controller = controller
    controller.drive_path = Path("remote.pmv")
    controller.drive_health = "ok"
    workspace = EditorWorkspace(QWidget(), parent=window)
    context = lambda: CloudSyncContext(window.vault, window.vault.path, None, "test", window)
    first = workspace.open_page("cloud", "Cloud", lambda: CloudSyncWorkspacePage(context(), window))
    controller._set_busy("drive", True)
    controller.previewChanged.emit("drive", "working")
    assert workspace.request_close("cloud")
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    assert controller.any_busy and not controller._closed
    second = workspace.open_page("cloud", "Cloud", lambda: CloudSyncWorkspacePage(context(), window))
    assert second.controller is controller
    assert second.ui.drive.preview.text() == "working"
    assert not second.ui.drive.sync.isEnabled()
    controller._set_busy("drive", False)
    controller.previewChanged.emit("drive", "done")
    controller.message.emit("Complete", "done", "success")
    assert second.ui.drive.preview.text() == "done"
    assert second.ui.notice.text() == "Complete\ndone"
    workspace.request_close("cloud")
    controller.cancel_active_operations()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_cancel_is_nonblocking_and_late_results_cannot_replace_vault(app):
    class DelayedWorker(QThread):
        completed = Signal(object)
        failed = Signal(str)

        def run(self):
            time.sleep(.15)
            self.completed.emit("late")

    controller, _ = make_controller()
    worker = DelayedWorker(controller)
    called = []
    worker.completed.connect(called.append)
    finished = []
    controller.settled.connect(lambda: finished.append(True))
    controller._start(worker)
    start = time.perf_counter()
    controller.cancel_active_operations()
    assert time.perf_counter() - start < .1
    pulses = []
    QTimer.singleShot(10, lambda: pulses.append(True))
    spin(app, lambda: bool(finished))
    assert pulses and not called


def test_duplicate_operations_and_automatic_sync_are_serialized(app, monkeypatch):
    parent = QWidget()
    parent._auto_sync_workers = {}
    controller, _ = make_controller(parent)
    started = []
    monkeypatch.setattr(controller, "_start", started.append)
    controller.sync_drive(Path("remote.pmv"), associated=False)
    controller.sync_drive(Path("remote.pmv"), associated=False)
    controller.inspect_webdav()
    assert len(started) == 1
    controller._set_busy("drive", False)
    parent._auto_sync_workers["drive"] = object()
    controller.sync_drive(Path("remote.pmv"), associated=False)
    assert len(started) == 1
    for worker in started:
        worker.password.clear()
    controller.cancel_active_operations()


def test_queued_sync_result_after_lock_is_closed_not_adopted(app):
    controller, _ = make_controller()
    closed, adopted = [], []
    controller.vaultReplaced.connect(adopted.append)
    controller.cancel_active_operations()
    replacement = SimpleNamespace(close=lambda: closed.append(True))
    controller._sync_ok(None, "drive", False, (None, replacement, None))
    assert closed == [True] and not adopted


def test_slow_settings_load_keeps_event_loop_alive_and_starts_once(app, monkeypatch):
    controller, vault = make_controller()
    controller.loaded = False
    vault.pmve_identity = SimpleNamespace(vault_id="test")
    vault.root_key_for_device_unlock = lambda: bytes(32)
    calls = []

    def slow_drive(_id):
        calls.append(QThread.currentThread())
        time.sleep(.15)
        return None

    monkeypatch.setattr(cloud_mod.cloud, "load_cloud_drive", slow_drive)
    monkeypatch.setattr(cloud_mod.cloud, "load_cloud_drive_revision", lambda _id: None)
    monkeypatch.setattr(cloud_mod.cloud, "load_cloud_drive_logical_revision", lambda _id: None)
    monkeypatch.setattr(cloud_mod.cloud, "load_webdav", lambda *a, **k: None)
    controller.load_async()
    controller.load_async()
    pulses = []
    QTimer.singleShot(10, lambda: pulses.append(True))
    spin(app, lambda: controller.loaded and not controller._workers)
    assert pulses and len(calls) == 1 and calls[0] != app.thread()
    assert not controller.any_busy
    controller.cancel_active_operations()


def test_settings_initialization_error_releases_busy_state(app):
    controller, vault = make_controller()
    controller.loaded = False
    # A session can be unavailable before the settings worker is constructed.
    controller.load_async()
    assert not controller.loading
    assert not controller.any_busy
    assert controller.can_start(controller.DRIVE)
    assert controller.last_notice[0] == "无法加载同步设置"
    controller.cancel_active_operations()


def test_cloud_menus_and_loading_updates_survive_collection(app):
    import gc
    from shiboken6 import isValid

    window = QWidget()
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"{target}_{name}"
    controller, window.vault = make_controller(window)
    controller.loading = True
    window._cloud_controller = controller
    page = CloudSyncWorkspacePage(CloudSyncContext(window.vault, window.vault.path, None, "test", window), window)
    assert not page.ui.drive.relate.isEnabled()
    gc.collect()
    app.processEvents()
    for target in (page.ui.drive, page.ui.webdav):
        assert isValid(target.menu)
        assert all(isValid(action) for action in target.menu.actions())
    controller._settings_loaded((Path("remote.pmv"), None, None, None, "ok"))
    assert not page._view_detached
    assert page.ui.drive.path.text() == "remote.pmv"
    assert page.ui.drive.sync.isEnabled()
    assert page.ui.webdav.relate.isEnabled()
    calls = []

    def transient_update():
        calls.append(True)
        if len(calls) == 1:
            raise RuntimeError("temporary widget update failure")

    page._subscribe(controller.stateChanged, transient_update)
    controller.stateChanged.emit()
    assert not page._view_detached
    controller.stateChanged.emit()
    assert len(calls) == 2
    page.close_page("user")
    controller.cancel_active_operations()
    window.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_download_replacement_reopens_vault_on_worker_thread(app, monkeypatch, tmp_path):
    remote = tmp_path / "download.tmp"
    remote.write_bytes(b"test")
    threads, closed = [], []
    replacement = SimpleNamespace(close=lambda: closed.append("replacement"))
    original = SimpleNamespace(
        replace_authenticated_file=lambda *a, **k: "identity",
        close=lambda: closed.append("original"),
    )

    def open_vault(*args):
        threads.append(QThread.currentThread())
        return original if len(threads) == 1 else replacement

    monkeypatch.setattr(cloud_mod.Vault, "open_with_password_buffer", open_vault)
    worker = cloud_mod.DownloadReplaceWorker(tmp_path / "local.pmv", crypto.SecureString("test"), remote, force=True)
    result = []
    worker.replaced.connect(result.append)
    worker.start()
    spin(app, lambda: bool(result) and not worker.isRunning())
    assert result == [replacement]
    assert len(threads) == 2 and all(thread != app.thread() for thread in threads)
    assert closed == ["original"] and not remote.exists()
    replacement.close()


def test_local_healthy_result_does_not_imply_online_check(app):
    model = SecurityResultsModel()
    model.set_report(report())
    model.filter(password_health.HEALTHY, "", "")
    assert "联网未检测或结果已过期" in model.index(0).data(Qt.ToolTipRole)


def test_cloud_page_construction_never_shows_detached_form_windows(app):
    class WindowShowRecorder(QObject):
        def __init__(self):
            super().__init__()
            self.shown = []

        def eventFilter(self, watched, event):
            if event.type() == QEvent.Show and isinstance(watched, QWidget) and watched.isWindow():
                self.shown.append(watched.metaObject().className())
            return False

    window = QWidget()
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"{target}_{name}"
    controller, window.vault = make_controller(window)
    window._cloud_controller = controller
    recorder = WindowShowRecorder()
    app.installEventFilter(recorder)
    try:
        # Test both first entry and reopening with the retained controller.
        for _ in range(2):
            context = CloudSyncContext(window.vault, window.vault.path, None, "test", window)
            page = CloudSyncWorkspacePage(context, window)
            page.close_page("user")
            page.deleteLater()
            QCoreApplication.sendPostedEvents(page, QEvent.DeferredDelete)
        assert recorder.shown == []
    finally:
        app.removeEventFilter(recorder)
        controller.cancel_active_operations()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def test_cloud_notice_belongs_to_its_target_and_clears_on_retry(app, monkeypatch):
    window = QWidget()
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"{target}_{name}"
    controller, window.vault = make_controller(window)
    window._cloud_controller = controller
    page = CloudSyncWorkspacePage(CloudSyncContext(window.vault, window.vault.path, None, "test", window), window)
    controller._sync_failed(controller.DRIVE, False, "drive failure")
    assert "云端硬盘同步未完成" in page.ui.notice.text()
    assert page.ui.drive.preview.isHidden()
    assert page.ui.drive.phase.isHidden()
    page.ui._select_target(1)
    assert page.ui.notice.isHidden()
    page.ui._select_target(0)
    assert not page.ui.notice.isHidden()
    controller._set_phase(controller.DRIVE, cloud_mod.CloudSyncPhase.RUNNING, message="正在重试")
    assert page.ui.notice.isHidden()
    assert page.ui.drive.preview.text() == "正在重试"
    page.close_page("user")
    controller.cancel_active_operations()


def test_cloud_scroll_height_uses_only_selected_target(app):
    from ui.cloud_sync_page import CloudSyncPage
    page = CloudSyncPage()
    tall = QWidget()
    tall.setFixedHeight(2000)
    page.webdav.layout.insertWidget(0, tall)
    page.resize(600, 1000)
    page.show()
    app.processEvents()
    assert page.scroll.verticalScrollBar().maximum() == 0
    page._select_target(1)
    app.processEvents()
    assert page.scroll.verticalScrollBar().maximum() > 0
    page._select_target(0)
    app.processEvents()
    assert page.scroll.verticalScrollBar().maximum() == 0
    page.close()


@pytest.mark.parametrize("language", ["zh-Hans", "en"])
def test_cloud_more_actions_remain_clickable_with_live_translation(app, language):
    import gc
    from PySide6.QtTest import QTest
    from shiboken6 import isValid
    from ui import i18n
    from ui.cloud_sync_page import CloudSyncPage

    previous_filter = getattr(app, "_vault_i18n_filter", None)
    previous_locale = i18n.current_locale()
    i18n.install(app, language, "zh_CN")
    translator = app._vault_i18n_filter
    page = CloudSyncPage()
    page.resize(640, 800)
    page.show()
    try:
        app.processEvents()
        gc.collect()
        for index, target in enumerate((page.drive, page.webdav)):
            page._select_target(index)
            app.processEvents()
            for action in (target.overwrite_action, target.download_action, target.relate_action, target.clear_action):
                assert isValid(action)
                assert action in target.menu.actions()
                clicks = []
                action.triggered.connect(lambda checked=False, clicks=clicks: clicks.append(True))
                target.menu.popup(target.more.mapToGlobal(target.more.rect().bottomLeft()))
                app.processEvents()
                QTest.mouseClick(target.menu, Qt.LeftButton, pos=target.menu.actionGeometry(action).center())
                app.processEvents()
                assert clicks == [True]
                assert not target.menu.isVisible()
    finally:
        page.close()
        app.removeEventFilter(translator)
        translator.deleteLater()
        app._vault_i18n_filter = previous_filter
        i18n.set_locale(previous_locale)


def test_cloud_sync_phase_status_transitions():
    controller, _ = make_controller()

    assert controller.status_state("drive") == "idle"
    assert controller.status_text("drive") == "尚未同步"
    assert controller.progress_of("drive") is None

    controller._set_phase(controller.DRIVE, cloud_mod.CloudSyncPhase.RUNNING, message="正在同步到云端硬盘…", progress=0.4)
    assert controller.status_state("drive") == "running"
    assert controller.status_text("drive") == "正在同步到云端硬盘…"
    assert controller.progress_of("drive") == 0.4

    controller._set_phase(controller.DRIVE, cloud_mod.CloudSyncPhase.FAILED, message="云端响应超时")
    assert controller.status_state("drive") == "failed"
    assert controller.status_text("drive") == "云端响应超时"

    controller._mark_success(controller.DRIVE, changed=2, uploaded=True)
    controller._set_phase(controller.DRIVE, cloud_mod.CloudSyncPhase.IDLE, message="")
    text = controller.status_text("drive")
    assert "已同步并通过安全校验" in text
    assert "本地已更新" in text
    assert "已更新云端" in text


def test_cloud_failures_use_classified_user_message():
    controller, _ = make_controller()

    controller._preview_failed(controller.DRIVE, "request timed out while connecting")
    assert controller.status_state("drive") == "failed"
    assert controller.status_text("drive") == "云端响应超时，请检查网络后重试"

    controller._download_failed(controller.WEBDAV, "401 Unauthorized")
    assert controller.status_state("webdav") == "failed"
    assert controller.status_text("webdav") == "云端登录信息已失效，请重新关联"


class _StubWebDavClient:
    """Stand-in for WebDavClient that records the calls the worker makes."""

    metadata_calls = 0
    test_calls = 0
    download_if_exists_calls = 0
    uploaded: list = []

    def __init__(self, _config, **_kwargs):
        pass

    def test(self):
        type(self).test_calls += 1

    def metadata(self, *, verify_size=False):
        del verify_size
        type(self).metadata_calls += 1
        return SimpleNamespace(exists=True, size=4096, modified_at=1.0, revision='"v1"')

    def download_if_exists(self):
        type(self).download_if_exists_calls += 1
        raise AssertionError("关联探测不得整库下载：PMVE 是 file-only")

    def upload_file_if_unchanged(self, source, expected, *, force=False):
        type(self).uploaded.append((Path(source), expected, force))
        return '"v2"'

    def download_to_if_exists(self, target):
        Path(target).write_bytes(b"PMVS-readback")
        return SimpleNamespace(path=Path(target), exists=True, size=14)


def _run_worker(worker):
    outcomes = []
    worker.completed.connect(lambda action, result: outcomes.append(("ok", action, result)))
    worker.failed.connect(lambda message: outcomes.append(("failed", message)))
    worker.run()
    return outcomes


def test_webdav_associate_detects_existing_remote_without_downloading_it(monkeypatch):
    """关联到已有数据的远端时，必须走 metadata 探测而不是整库下载。

    PMVE 云端同步是 file-only，用 download_if_exists 会被拒绝，导致
    「远端已有保险库数据」的合并/覆盖/下载三选一永远无法出现。
    """
    _StubWebDavClient.metadata_calls = 0
    _StubWebDavClient.download_if_exists_calls = 0
    monkeypatch.setattr(cloud_mod.cloud, "WebDavClient", _StubWebDavClient)
    config = cloud_mod.cloud.WebDavConfig("NAS", "https://nas.example/dav/user.pmv", auth_mode="none")

    outcomes = _run_worker(cloud_mod.CloudWorker("connect", config, None))

    assert [item[0] for item in outcomes] == ["ok"]
    assert _StubWebDavClient.test_calls == 1
    assert _StubWebDavClient.metadata_calls == 1
    assert _StubWebDavClient.download_if_exists_calls == 0
    assert outcomes[0][2].exists is True
    assert outcomes[0][2].size == 4096


def test_webdav_connect_result_offers_the_existing_remote_choices(monkeypatch):
    monkeypatch.setattr(cloud_mod.cloud, "WebDavClient", _StubWebDavClient)
    controller, _ = make_controller()
    config = cloud_mod.cloud.WebDavConfig("NAS", "https://nas.example/dav/user.pmv", auth_mode="none")

    asked = []
    controller.askExistingRemote.connect(lambda title, _cb: asked.append(title))
    controller._webdav_associate_tested(config, SimpleNamespace(exists=True, size=4096))

    assert asked == ["远端已有保险库数据"]


def test_webdav_overwrite_worker_publishes_forced_and_reads_back(tmp_path, monkeypatch):
    """上传覆盖是无条件发布：不再引用已重命名的 cloud.MAX_SYNC_BYTES。"""
    _StubWebDavClient.uploaded = []
    monkeypatch.setattr(cloud_mod.cloud, "WebDavClient", _StubWebDavClient)
    local = tmp_path / "local.pmv"
    local.write_bytes(b"PMVS-local")

    outcomes = _run_worker(
        cloud_mod.CloudWorker("overwrite_file", cloud_mod.cloud.WebDavConfig("NAS", "https://nas.example/dav/u.pmv", auth_mode="none"), local)
    )

    assert [item[0] for item in outcomes] == ["ok"]
    assert len(_StubWebDavClient.uploaded) == 1
    source, expected, force = _StubWebDavClient.uploaded[0]
    assert source == local
    assert expected is None
    assert force is True


def test_webdav_push_worker_keeps_the_cas_witness(tmp_path, monkeypatch):
    _StubWebDavClient.uploaded = []
    monkeypatch.setattr(cloud_mod.cloud, "WebDavClient", _StubWebDavClient)
    local = tmp_path / "local.pmv"
    local.write_bytes(b"PMVS-local")
    expected = SimpleNamespace(path=local, revision='"v1"', exists=True)

    _run_worker(
        cloud_mod.CloudWorker(
            "push_file",
            cloud_mod.cloud.WebDavConfig("NAS", "https://nas.example/dav/u.pmv", auth_mode="none"),
            (local, expected),
        )
    )

    _source, passed, force = _StubWebDavClient.uploaded[0]
    assert passed is expected
    assert force is False


def test_cloud_drive_overwrite_worker_accepts_a_bare_path(tmp_path):
    """显式覆盖只传一个 Path；worker 必须能解包，而不是报 cannot unpack。"""
    remote = tmp_path / "remote.pmv"
    remote.write_bytes(b"PMVS-remote")
    local = tmp_path / "local.pmv"
    local.write_bytes(b"PMVS-local")

    outcomes = _run_worker(cloud_mod.CloudDriveWorker("overwrite_file", remote, local))

    assert [item[0] for item in outcomes] == ["ok"]
    assert remote.read_bytes() == b"PMVS-local"


def test_cloud_preview_detail_is_structured_by_lineage():
    from core.storage import VaultLineage

    text = cloud_mod._preview_detail(
        VaultLineage.DIVERGED,
        local_seq=12,
        remote_seq=15,
        local_key=3,
        remote_key=4,
        local_active=147,
        local_trash=1,
        checked="10:30:00",
    )
    assert text.splitlines()[0] == "双方均有修改，可自动合并"
    assert "本地提交 #12" in text and "远端提交 #15" in text
    assert "本地 147 项（回收站 1）" in text
    assert "最近检测：10:30:00" in text
