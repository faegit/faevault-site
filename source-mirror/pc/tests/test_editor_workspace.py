import inspect
import os
import re
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QEvent
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QStackedWidget, QTabBar, QVBoxLayout, QWidget

from ui.app import MainWindow
from ui.editor_workspace import EditorPage, EditorTabBar, EditorWorkspace


def _app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def _no_modal_dialogs(monkeypatch):
    """无头环境下禁止弹出真实模态框。

    断开/关闭前的二次确认一旦漏打桩，widgets.confirm 会 exec() 一个模态对话框：
    没人点击就永远不返回，整个测试进程挂死（表现为跑满超时也没有结果）。
    统一在入口处拦掉，各测试再按需要单独覆盖返回值。
    """
    from ui import widgets as ui_widgets

    monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: True)
    monkeypatch.setattr(ui_widgets, "message", lambda *a, **k: None)


def test_main_detail_builder_uses_editor_workspace_without_embedded_action_footer():
    source = inspect.getsource(MainWindow._build_detail_pane)

    assert "EditorWorkspace" in source
    assert 'QPushButton("编辑")' not in source
    assert 'QPushButton("删除")' not in source
    assert "detail_actions" not in source


def test_list_and_detail_panes_use_draggable_splitter():
    source = inspect.getsource(MainWindow.__init__)

    assert "QSplitter(Qt.Horizontal" in source
    assert "self._list_detail.setChildrenCollapsible(False)" in source
    assert "self._list_detail.setHandleWidth(MAIN_SPLITTER_HANDLE_WIDTH)" in source
    assert "self._list_pane.setMinimumWidth(MIN_LIST_PANE_WIDTH)" in source
    assert "self._detail_pane.setMinimumWidth(MIN_DETAIL_PANE_WIDTH)" in source
    assert "self._list_detail.splitterMoved.connect(self._schedule_list_pane_ratio_save)" in source


def test_splitter_ratio_save_uses_debounced_global_setting():
    init = inspect.getsource(MainWindow.__init__)
    save = inspect.getsource(MainWindow._save_list_pane_ratio)
    restore = inspect.getsource(MainWindow._restore_list_pane_ratio)

    assert "self._list_pane_ratio_save_timer.setSingleShot(True)" in init
    assert "self._list_pane_ratio_save_timer.setInterval(400)" in init
    assert 'config.set("list_pane_ratio", ratio)' in save
    assert 'config.get("list_pane_ratio", config.DEFAULT_LIST_PANE_RATIO)' in restore
    assert "MIN_LIST_PANE_WIDTH" in restore
    assert "MIN_DETAIL_PANE_WIDTH" in restore


def test_detail_floating_actions_are_direct_children_and_float_side_by_side():
    from ui.app import _FloatingDetailActions

    app = _app()
    host = QWidget()
    host.resize(600, 400)
    calls = []
    actions = _FloatingDetailActions(
        host,
        on_edit=lambda: calls.append("edit"),
        on_delete=lambda: calls.append("delete"),
    )
    host.show()
    actions.setVisible(True)
    app.processEvents()

    assert not isinstance(actions, QWidget)
    assert actions.edit_button.parent() is host
    assert actions.delete_button.parent() is host
    assert actions.edit_button.objectName() == "DetailAction"
    assert actions.delete_button.objectName() == "DetailDeleteAction"
    assert actions.edit_button.isVisible()
    assert actions.delete_button.isVisible()
    assert actions.edit_button.height() == actions.delete_button.height()
    assert actions.edit_button.y() == host.height() - actions.edit_button.height() - 18
    assert actions.edit_button.x() + actions.edit_button.width() + _FloatingDetailActions._GAP == actions.delete_button.x()
    pair_width = actions.edit_button.width() + actions.delete_button.width() + _FloatingDetailActions._GAP
    assert abs(actions.edit_button.x() - (host.width() - pair_width) // 2) <= 2
    assert actions.edit_button.y() + actions.edit_button.height() <= host.height()

    actions.edit_button.click()
    actions.delete_button.click()
    assert calls == ["edit", "delete"]
    host.close()


def test_detail_builder_creates_floating_actions_outside_scrolling_content():
    source = inspect.getsource(MainWindow._build_detail_pane)

    assert "_FloatingDetailActions" in source
    # 悬浮条不属于滚动内容：不能加入 self.detail 布局
    assert "self.detail.addWidget(self._detail_fab)" not in source


def test_cloud_page_master_switch_hides_content_when_disabled():
    from pathlib import Path
    from unittest.mock import MagicMock

    from PySide6.QtWidgets import QWidget

    from ui.sync_pages import CloudSyncContext, CloudSyncWorkspacePage

    _app()
    controller = MagicMock()
    controller._closed = False
    controller.loaded = True
    controller.drive_connected = False
    controller.webdav_connected = False
    controller.any_busy = False
    controller.is_busy.return_value = False
    controller.can_start.return_value = True
    controller.previews = {}
    controller.last_notice = None
    controller.notice_for.return_value = None
    controller.pending_question = None
    controller.drive_health = ""
    controller.webdav_health = ""
    controller.drive_path = None
    controller.webdav_config = None
    controller.status_text.return_value = "尚未同步"
    controller.status_state.return_value = "idle"
    controller.progress_of.return_value = None

    state = {"enabled": True}
    window = QWidget()
    window.vault = MagicMock()
    window._cloud_controller = controller
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"{target}_{name}"
    window.cloud_sync_enabled = lambda: state["enabled"]
    window.set_cloud_sync_enabled = lambda value: state.__setitem__("enabled", value)
    context = CloudSyncContext(window.vault, Path("t.pmv"), None, "test", window)
    page = CloudSyncWorkspacePage(context, window)

    assert not page.ui.content.isHidden()
    page.ui.master_toggle.setChecked(False)
    assert state["enabled"] is False
    assert page.ui.content.isHidden()
    page.close_page("user")


def test_cloud_page_callback_survives_its_widgets_being_destroyed():
    """控制器挂在主窗口上、页面销毁后仍在发信号。

    视图回调打到已删除的控件上会刷出
    ``RuntimeError: Internal C++ object (QAction) already deleted``；
    这里要求回调自行断开订阅而不是把异常抛出去。
    """
    from pathlib import Path
    from unittest.mock import MagicMock

    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QWidget

    from ui.sync_pages import CloudSyncContext, CloudSyncWorkspacePage

    app = _app()
    controller = MagicMock()
    controller._closed = False
    controller.loaded = True
    controller.drive_connected = True
    controller.webdav_connected = False
    controller.any_busy = False
    controller.is_busy.return_value = False
    controller.can_start.return_value = True
    controller.previews = {}
    controller.last_notice = None
    controller.notice_for.return_value = None
    controller.pending_question = None
    controller.drive_health = ""
    controller.webdav_health = ""
    controller.drive_path = Path("drive/FAE.pmv")
    controller.webdav_config = None
    controller.status_text.return_value = "尚未同步"
    controller.status_state.return_value = "idle"
    controller.progress_of.return_value = None

    window = QWidget()
    window.vault = MagicMock()
    window._cloud_controller = controller
    window._auto_sync_workers = {}
    window._auto_sync_target_pref_key = lambda name, target: f"{target}_{name}"
    window.cloud_sync_enabled = lambda: True
    window.set_cloud_sync_enabled = lambda _value: None
    context = CloudSyncContext(window.vault, Path("t.pmv"), None, "test", window)
    page = CloudSyncWorkspacePage(context, window)
    try:
        # 取页面登记的那层保护回调，模拟控制器发信号
        slot = controller.stateChanged.connect.call_args[0][0]
        slot()

        # 控件先于页面被销毁（QAction 随「更多操作」菜单一起走）
        page.ui.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()

        slot()  # 不应抛出 RuntimeError
        assert page._view_detached
    finally:
        page.close_page("user")
        window.deleteLater()


def test_show_entry_hides_floating_actions_for_passkeys():
    source = inspect.getsource(MainWindow._show_entry)

    assert "_detail_fab" in source
    assert "SecretType.PASSKEY" in source


def test_refresh_open_feature_pages_reloads_embedded_pages():
    class _RecordingPage(EditorPage):
        def __init__(self):
            super().__init__()
            self.seen = []

        def refresh(self, context):
            self.seen.append(context)

    _app()
    page = _RecordingPage()
    vault = object()
    workspace = SimpleNamespace(
        page_keys=lambda: ("detail", "recycle"),
        page=lambda key: page if key == "recycle" else None,
    )
    host = SimpleNamespace(editor_workspace=workspace, vault=vault)

    MainWindow._refresh_open_feature_pages(host)

    assert page.seen == [vault]


def test_delete_paths_refresh_open_feature_pages():
    for method in (MainWindow.delete_entry, MainWindow._batch_delete):
        assert "_refresh_open_feature_pages" in inspect.getsource(method)


def test_recycle_bin_page_refreshes_after_external_delete():
    from core.models import Entry
    from ui.maintenance_pages import RecycleBinPage

    _app()
    entry = Entry(title="待删除")
    entry.deleted_at = 1.0
    vault = SimpleNamespace(trash=[])
    page = RecycleBinPage(vault)
    workspace = SimpleNamespace(
        page_keys=lambda: ("detail", "recycle"),
        page=lambda key: page if key == "recycle" else None,
    )
    host = SimpleNamespace(editor_workspace=workspace, vault=vault)
    assert page.list.count() == 0

    vault.trash.append(entry)
    MainWindow._refresh_open_feature_pages(host)

    assert page.list.count() == 1


def test_internal_empty_refresh_keeps_active_feature_page():
    _app()
    detail_page = QWidget()
    detail_layout = QVBoxLayout(detail_page)
    workspace = EditorWorkspace(detail_page)
    settings = workspace.open_page("settings", "设置", QWidget)
    host = SimpleNamespace(
        editor_workspace=workspace,
        detail=detail_layout,
        detail_card=detail_page,
        _detail_entry=None,
        _active_type="login",
        _clear_detail=lambda: None,
    )

    MainWindow._show_empty(host)

    assert workspace.current_key() == "settings"
    assert workspace.stack.currentWidget() is settings


def test_user_selection_activates_fixed_detail_page():
    _app()
    workspace = EditorWorkspace(QWidget())
    workspace.open_page("settings", "设置", QWidget)
    timer_starts = []
    host = SimpleNamespace(
        editor_workspace=workspace,
        _update_alpha_nav=lambda: None,
        _pending_select=None,
        _select_timer=SimpleNamespace(start=lambda: timer_starts.append(True)),
    )
    selected = object()

    MainWindow._on_select(host, selected, None)

    assert workspace.current_key() == "detail"
    assert host._pending_select is selected
    assert timer_starts == [True]


def test_internal_selection_restore_does_not_activate_detail_page():
    _app()
    workspace = EditorWorkspace(QWidget())
    settings = workspace.open_page("settings", "设置", QWidget)
    host = SimpleNamespace(
        editor_workspace=workspace,
        _update_alpha_nav=lambda: None,
        _pending_select=None,
        _select_timer=SimpleNamespace(start=lambda: None),
        _restoring_list_selection=True,
    )

    MainWindow._on_select(host, None, None)

    assert workspace.current_key() == "settings"


class FakePage(EditorPage):
    def __init__(self, *, allow_close: bool = True):
        super().__init__()
        assert self.layout() is None
        self.setLayout(QVBoxLayout())
        self.allow_close = allow_close
        self.close_attempts = []
        self.closed_for = None
        self.delete_later_called = False

    def can_close(self, reason: str) -> bool:
        self.close_attempts.append(reason)
        return self.allow_close

    def close_page(self, reason: str) -> None:
        self.closed_for = reason

    def deleteLater(self) -> None:
        self.delete_later_called = True
        super().deleteLater()


def test_editor_page_exposes_signals_without_claiming_a_layout():
    _app()
    page = EditorPage()
    entries = []
    vaults = []
    statuses = []
    page.entryRequested.connect(entries.append)
    page.vaultChanged.connect(vaults.append)
    page.statusMessage.connect(statuses.append)

    vault = object()
    page.entryRequested.emit("entry-1")
    page.vaultChanged.emit(vault)
    page.statusMessage.emit("saved")

    assert page.layout() is None
    assert entries == ["entry-1"]
    assert vaults == [vault]
    assert statuses == ["saved"]
    assert page.can_close("user")
    assert page.close_page("user") is None
    assert page.refresh(None) is None


def test_workspace_keeps_detail_fixed_and_without_close_button():
    _app()
    workspace = EditorWorkspace(QLabel("details"), detail_title="条目详情")

    assert workspace.page_keys() == ("detail",)
    assert workspace.current_key() == "detail"
    assert workspace.page("detail").text() == "details"
    assert all(
        workspace.tabs.tabButton(0, position) is None
        for position in (
            QTabBar.ButtonPosition.LeftSide,
            QTabBar.ButtonPosition.RightSide,
        )
    )
    assert not workspace.request_close("detail")
    assert not workspace.request_close("missing")
    assert workspace.page_keys() == ("detail",)


def test_open_page_reuses_same_key_and_activates_existing_page():
    _app()
    workspace = EditorWorkspace(QLabel("details"))
    created = []

    def factory():
        page = QWidget()
        created.append(page)
        return page

    first = workspace.open_page("settings", "设置", factory)
    workspace.show_detail()
    second = workspace.open_page("settings", "unused", factory)

    assert first is second
    assert created == [first]
    assert workspace.page_keys() == ("detail", "settings")
    assert workspace.current_key() == "settings"
    assert workspace.page("settings") is first
    assert any(
        workspace.tabs.tabButton(1, position) is not None
        for position in (
            QTabBar.ButtonPosition.LeftSide,
            QTabBar.ButtonPosition.RightSide,
        )
    )
    assert workspace.stack.currentWidget() is first


def test_current_changed_emits_key_after_switching_stack_page():
    _app()
    detail = QLabel("details")
    workspace = EditorWorkspace(detail)
    changes = []
    workspace.currentChanged.connect(lambda key: changes.append((key, workspace.stack.currentWidget())))

    settings = workspace.open_page("settings", "设置", FakePage)
    workspace.show_detail()

    assert changes == [("settings", settings), ("detail", detail)]


def test_request_close_keeps_page_when_guard_refuses():
    _app()
    workspace = EditorWorkspace(QLabel("details"))
    page = workspace.open_page(
        "sync",
        "同步",
        lambda: FakePage(allow_close=False),
    )

    assert not workspace.request_close("sync", "lock")
    assert page.close_attempts == ["lock"]
    assert page.closed_for is None
    assert workspace.page_keys() == ("detail", "sync")
    assert workspace.page("sync") is page
    assert workspace.current_key() == "sync"


def test_request_close_cleans_page_and_activates_left_neighbor():
    _app()
    workspace = EditorWorkspace(QLabel("details"))
    settings = workspace.open_page("settings", "设置", FakePage)
    sync = workspace.open_page("sync", "同步", FakePage)

    assert workspace.request_close("sync")

    assert sync.close_attempts == ["user"]
    assert sync.closed_for == "user"
    assert sync.delete_later_called
    assert workspace.page_keys() == ("detail", "settings")
    assert workspace.page("sync") is None
    assert workspace.current_key() == "settings"
    assert workspace.stack.currentWidget() is settings
    assert workspace.stack.count() == workspace.tabs.count() == 2


def test_close_all_pages_cleans_features_and_keeps_detail():
    _app()
    detail = QLabel("details")
    workspace = EditorWorkspace(detail)
    settings = workspace.open_page("settings", "设置", FakePage)
    sync = workspace.open_page("sync", "同步", FakePage)

    workspace.close_all_pages("lock")

    assert settings.close_attempts == sync.close_attempts == ["lock"]
    assert settings.closed_for == sync.closed_for == "lock"
    assert settings.delete_later_called and sync.delete_later_called
    assert workspace.page_keys() == ("detail",)
    assert workspace.page("detail") is detail
    assert workspace.current_key() == "detail"
    assert workspace.stack.currentWidget() is detail
    assert workspace.stack.count() == workspace.tabs.count() == 1


def test_close_non_active_tab_keeps_visibility_and_emits_once():
    _app()
    workspace = EditorWorkspace(QLabel("details"))
    settings = workspace.open_page("settings", "设置", FakePage)
    sync = workspace.open_page("sync", "同步", FakePage)
    changes = []
    workspace.currentChanged.connect(changes.append)

    assert workspace.request_close("settings")

    assert workspace.current_key() == "sync"
    assert workspace.stack.currentWidget() is sync
    # 关闭非活动标签不得切走可见页面，也不得对仍可见页面重复发放 currentChanged。
    assert changes == []


def test_request_close_honors_duck_typed_guard_on_plain_widget():
    _app()
    workspace = EditorWorkspace(QLabel("details"))
    page = QWidget()
    page.allow = False
    page.can_close = lambda reason: page.allow
    page.close_page = lambda reason: setattr(page, "closed_for", reason)
    workspace.open_page("sync", "同步", lambda: page)

    assert not workspace.request_close("sync", "lock")
    assert workspace.page_keys() == ("detail", "sync")
    assert workspace.page("sync") is page
    assert getattr(page, "closed_for", None) is None

    page.allow = True
    assert workspace.request_close("sync", "lock")
    assert page.closed_for == "lock"


# ---------- Task 5: maintenance pages ----------


@pytest.fixture
def fake_vault():
    return SimpleNamespace(trash=[])


def test_maintenance_pages_are_widgets_not_dialogs(fake_vault):
    from ui.maintenance_pages import DedupPage, RecycleBinPage, SameServicePage

    _app()
    pages = [
        RecycleBinPage(fake_vault),
        DedupPage([]),
        SameServicePage([]),
    ]
    assert all(not isinstance(page, QDialog) for page in pages)


def test_maintenance_actions_float_and_survive_content_rebuild(fake_vault):
    from ui.maintenance_pages import DedupPage, RecycleBinPage, SameServicePage

    app = _app()
    recycle = RecycleBinPage(fake_vault)
    dedup = DedupPage([])
    same_service = SameServicePage([])
    for page, button in ((dedup, dedup._confirm_btn), (same_service, same_service._merge_btn)):
        page.resize(640, 480)
        page.show()
        app.processEvents()
        assert button.objectName() == "FloatingPrimaryAction"
        assert button.parentWidget().width() > button.width()
        assert button.y() > 0
        page.hide()
    assert recycle.clear_btn.objectName() == "FloatingDangerAction"
    assert recycle.batch_bar.objectName() == "FloatingActionGroup"
    dedup.reset([])
    same_service.reset([])
    assert dedup._confirm_btn.objectName() == "FloatingPrimaryAction"
    assert same_service._merge_btn.objectName() == "FloatingPrimaryAction"


def test_dedup_compare_uses_internal_stack_and_preserves_progress():
    from ui.maintenance_pages import DedupPage

    _app()
    page = DedupPage([])
    assert isinstance(page.stack, QStackedWidget)
    assert page.pending_results == {}


def test_same_service_entry_click_emits_workspace_navigation():
    from ui.maintenance_pages import SameServicePage

    _app()
    page = SameServicePage([])
    seen = []
    page.entryRequested.connect(seen.append)
    page.request_entry("entry-9")
    assert seen == ["entry-9"]


# ---------- Task 6: settings page ----------


@pytest.fixture
def window_stub(monkeypatch):
    from unittest.mock import MagicMock

    from ui.settings_page import SettingsPage

    # These tests exercise layout and page lifetime, not a real Windows probe.
    # A native worker owned by QApplication otherwise outlives the test suite.
    monkeypatch.setattr(SettingsPage, "_start_environment_probe", lambda self: None)

    window = MagicMock()
    window.cloud_sync_enabled.return_value = False
    window.vault.key_updated_at = 0.0
    window.vault.key_revision = 1
    window.vault.path = "vault.pmv"
    return window


def test_settings_page_is_embedded_and_retains_immediate_save(window_stub):
    from ui.settings_page import SettingsPage

    _app()
    page = SettingsPage(window_stub)
    assert not isinstance(page, QDialog)
    page.lock_enabled.setChecked(False)
    assert page.lock_enabled.isChecked() is False
    page.close_page("test")


def test_settings_page_close_clears_sensitive_session(window_stub):
    from ui.settings_page import SettingsPage

    _app()
    page = SettingsPage(window_stub)
    page._sensitive_verified = True
    page._session_master = "secret"
    page.close_page("user")
    assert page._sensitive_verified is False
    assert page._session_master is None


def test_settings_consolidates_groups_and_can_expand_advanced_options(window_stub):
    from PySide6.QtWidgets import QPushButton
    from ui.settings_page import SettingsPage

    app = _app()
    page = SettingsPage(window_stub)
    groups = [page._content_lay.itemAt(i).widget() for i in range(page._content_lay.count())]
    groups = [group for group in groups if group is not None]
    titles = [group.layout().itemAt(0).widget().text() for group in groups]
    assert titles == ["外观", "账户与解锁", "隐私与安全", "自动填充与通行密钥", "启动与后台", "关于与支持"]
    by_title = dict(zip(titles, groups))
    assert by_title["账户与解锁"].isAncestorOf(page.hello_enabled)
    assert by_title["账户与解锁"].isAncestorOf(page._recovery_box.itemAt(0).widget())
    assert by_title["隐私与安全"].isAncestorOf(page.allow_capture)
    integration = by_title["自动填充与通行密钥"]
    assert integration.isAncestorOf(page.native_autofill_enabled)
    assert integration.isAncestorOf(page._browser_autofill_install)
    assert integration.isAncestorOf(page._passkey_provider_status)
    assert by_title["启动与后台"].isAncestorOf(page.start_at_login)
    assert by_title["启动与后台"].isAncestorOf(page.silent_start)
    assert any(button.text() == "打开赞助页面" for button in by_title["关于与支持"].findChildren(QPushButton))
    assert page._advanced_content.isHidden()
    page._advanced_toggle.click()
    app.processEvents()
    assert not page._advanced_content.isHidden()
    assert page._advanced_content.isAncestorOf(page.kdf_profile)
    page._advanced_toggle.click()
    assert page._advanced_content.isHidden()
    page.close_page("test")
    page.deleteLater()


def test_settings_entrypoint_opens_workspace_page_without_modal_flow():
    source = inspect.getsource(MainWindow.open_settings)

    assert ".exec(" not in source
    assert "_open_workspace_page" in source
    assert "SettingsPage" in source


# ---------- Task 7: cloud sync and local backup pages ----------


@pytest.fixture
def cloud_context(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    import ui.sync_pages as sync_pages

    controller = MagicMock()
    controller.DRIVE, controller.WEBDAV = "drive", "webdav"
    controller.previews = {}
    controller.notice_for.return_value = None
    controller.status_text.return_value = "尚未同步"
    controller.status_state.return_value = "idle"
    controller.drive_connected = False
    controller.webdav_connected = False
    controller.webdav_config = None
    controller.drive_path = None
    controller.is_busy = lambda _target: False
    controller.any_busy = False
    monkeypatch.setattr(sync_pages, "CloudSyncController", lambda **_kwargs: controller)
    return sync_pages.CloudSyncContext(
        vault=MagicMock(),
        vault_path=tmp_path / "test.pmv",
        password=MagicMock(),
        cloud_vault_id="test-vault",
        window=MagicMock(),
    )


def test_cloud_page_reports_busy_state_to_close_guard(cloud_context):
    from ui.sync_pages import CloudSyncWorkspacePage

    _app()
    page = CloudSyncWorkspacePage(cloud_context)
    page._busy_targets.add("drive")
    assert page.has_active_task()


def test_local_backup_page_is_single_embedded_widget():
    from unittest.mock import MagicMock

    from ui.sync_pages import LocalBackupPage

    _app()
    page = LocalBackupPage(MagicMock())
    assert page.objectName() == "LocalBackupPage"
    assert page.parent() is None


def test_local_backup_controls_keep_natural_height_on_tall_page():
    from unittest.mock import MagicMock

    from ui.sync_pages import LocalBackupPage

    application = _app()
    page = LocalBackupPage(MagicMock())
    page.resize(900, 700)
    page.show()
    application.processEvents()
    assert page.body.geometry().height() < page.height() // 2
    assert page.backup_enabled.geometry().top() < 150
    page.close()


def test_cloud_and_backup_entrypoints_do_not_execute_modal_main_flows():
    source = inspect.getsource(MainWindow._open_cloud_sync) + inspect.getsource(MainWindow._open_local_backup)

    assert ".exec(" not in source
    assert "CloudSyncWorkspacePage" in source
    assert "LocalBackupPage" in source


# ---------- Task 8: LAN station and connection pages ----------


@pytest.fixture
def lan_context():
    from unittest.mock import MagicMock

    from ui.sync_pages import LanPageContext

    return LanPageContext(
        vault=MagicMock(),
        copy_secret=lambda _value: None,
        set_auto_lock_blocker=lambda _key, _active: None,
    )


def test_lan_connection_page_can_switch_idle_mode_but_not_active_mode(lan_context):
    from ui.sync_pages import LanConnectionPage

    _app()
    page = LanConnectionPage(lan_context, preset_mode="sync")
    assert page.select_mode("transfer")
    page._state["client"] = object()
    assert not page.select_mode("sync")


def test_lan_sync_result_lands_on_the_sync_gear_not_the_station_page(lan_context, monkeypatch):
    """同步结论落在同步挡位的结果卡上，不再留在传输站主页。

    合并摘要里会出现「已采用对方的新内容」这类文案，它属于同步通道的信息；传输站
    主页只承载与连接状态有关的内容。结果卡与摘要行同源（_lan_sync_result_rows），
    旧的状态面板收起，避免同屏两份。
    """

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        action = page.sync_page.sync_view.action_btn
        page.sync_page.sync_view.set_phase("同步中", finished=False)
        assert action.text() == "断开连接"
        station.show_result(
            {
                "local_count": 3,
                "merged_count": 5,
                "verified": True,
                "lineage": "FAST_FORWARD",
            }
        )

        result_card = page.sync_page.sync_view.result_card
        rows = " | ".join(w.text() for w in result_card.findChildren(QLabel) if w.text())
        assert "已采用对方的新内容" in rows
        assert "本地 3 项 → 合并后 5 项" in rows
        assert not result_card.isHidden(), "结果卡应显示"
        assert page.sync_page.sync_view.action_btn is action
        assert action.text() == "关闭页面"
        # 旧状态面板收起：同一屏两份摘要会让人怀疑数字对不上
        assert station._session_panels["sync"].isHidden()
        # 传输站主页上不应再出现结果卡片
        assert not hasattr(station, "result_panel")
    finally:
        page.close_page("user")


def test_lan_connector_sync_completion_shows_result_card(lan_context):
    from ui.sync_pages import LanWorkspacePage

    _app()
    lan_context.window = SimpleNamespace(
        vault=SimpleNamespace(),
        reload=lambda: None,
    )
    page = LanWorkspacePage(lan_context)
    sync_page = page.sync_page
    try:
        sync_page._state.update(
            client=SimpleNamespace(cancel=lambda: None),
            mode="sync",
            sync_succeeded=True,
            sync_result={
                "local_count": 3,
                "merged_count": 5,
                "verified": True,
                "lineage": "FAST_FORWARD",
            },
            reload_pending=True,
        )

        sync_page.poll_timer.timeout.emit()

        result_card = sync_page.sync_view.result_card
        assert not result_card.isHidden()
        assert result_card.values["lineage"].text() == "已采用对方的新内容"
        assert result_card.values["counts"].text() == "本地 3 项 → 合并后 5 项"
        assert sync_page.sync_view.action_btn.text() == "关闭页面"

        sync_page._finish_connection()
        assert sync_page._state["client"] is None
        assert not result_card.isHidden()
        sync_page._on_exit_sync_session()
        assert sync_page.sync_view.isHidden()
        assert not sync_page.connect_view.isHidden()
    finally:
        sync_page._state["client"] = None
        _close(page)


def test_lan_workspace_page_has_three_gears_with_sync_as_default(lan_context):
    """一页三档：建立传输站 / 局域网同步 / 文件传输，默认停在局域网同步。"""
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    try:
        assert page.slider.count() == 3
        assert page.slider.label_at(LanWorkspacePage.HOST) == "建立传输站"
        assert page.slider.label_at(LanWorkspacePage.SYNC) == "局域网同步"
        assert page.slider.label_at(LanWorkspacePage.TRANSFER) == "文件传输"
        assert page.current_gear() == LanWorkspacePage.SYNC
        assert page.stack.currentWidget() is page.sync_page
        # 三个档位各自承载原页面，且内嵌页自带的页头已收起
        assert page.stack.count() == 3
        assert page.station_page.page_header.title.isHidden()
        assert page.sync_page.page_header.title.isHidden()

        page.select_gear(LanWorkspacePage.TRANSFER, animate=False)
        assert page.stack.currentWidget() is page.transfer_page
        page.select_gear(LanWorkspacePage.HOST, animate=False)
        assert page.stack.currentWidget() is page.station_page
    finally:
        page.close_page("user")


def test_lan_station_gear_exposes_its_own_start_entry(lan_context, monkeypatch):
    """菜单收敛成单个「局域网」后，建立传输站必须由页内按钮触发，否则该档是空面板。"""
    from ui import widgets as ui_widgets
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    try:
        confirmed: list[str] = []
        monkeypatch.setattr(
            ui_widgets,
            "confirm",
            lambda parent, title, text, **kwargs: (confirmed.append(title), False)[1],
        )
        page.select_gear(LanWorkspacePage.HOST, animate=False)
        # 页面未 show 时 isVisible() 恒为 False，这里只看显式隐藏状态
        assert not page.station_page.intro.isHidden()
        assert not page.station_page.start_btn.isHidden()

        page.station_page.start_btn.click()
        assert confirmed == ["建立传输站"]
        # 取消后入口保持可用
        assert not page.station_page.intro.isHidden()
    finally:
        page.close_page("user")


def test_lan_station_gear_offers_a_close_button(lan_context, monkeypatch):
    """建立传输站后必须有「关闭传输站」：停服、放开自动锁定阻断、入口重新可用。"""
    from ui import widgets as ui_widgets
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    try:
        monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: True)
        station = page.station_page
        stopped: list[bool] = []
        station.server = SimpleNamespace(stop=lambda: stopped.append(True), _result=None)
        station.poll_timer.start()
        session = QWidget()
        station._add_session_widget(session)
        station.intro.setVisible(False)

        station._stop_station()

        assert stopped == [True]
        assert station.server is None
        assert not station.poll_timer.isActive()
        assert not station.intro.isHidden()
        assert session.isHidden()
    finally:
        page.close_page("user")


def test_lan_station_page_has_two_mutually_exclusive_state_buttons(lan_context, monkeypatch):
    """传输站页面只有「建立传输站」与「关闭传输站」两个状态按钮，互斥出现。

    本页只管传输站自己的生死；断开对端会话的出口在同步/传输挡位上。旧实现曾
    在这里同时摆「断开连接」和「结束传输」，两者还隔了近 500px。
    """

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        # 已开站：只应有「关闭传输站」
        assert _shown_within(station.stop_btn, station), "已开站时应显示关闭传输站"
        assert station.start_btn.isHidden(), "已开站时不应再显示建立传输站"
        assert not hasattr(station, "disconnect_btn"), "本页不应再有断开连接按钮"
        assert not hasattr(station, "header_row"), "页头那一行已移除"
        assert not hasattr(station, "station_title"), "重复的「传输站」标题已移除"

        # 关站：换回「建立传输站」，状态回到未开启
        station.stop_btn.click()
        QCoreApplication.processEvents()
        assert _shown_within(station.start_btn, station)
        assert station.start_btn.isEnabled()
        assert station.stop_btn.isHidden(), "两个按钮不能同时出现"
        assert station.host_status.text() == "未开启"
        assert server.stopped >= 1
    finally:
        _close(page)


def test_lan_workspace_keeps_gear_sliding_available_while_a_task_runs(lan_context):
    """任务进行中仍允许切档。

    早先按 is_busy() 锁死滑块，用户被钉在当前挡位：既看不了另一个通道，也没有
    就地中断的入口。现在改成可切，由每个挡位自己说明另一个通道正在做什么。
    """
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    try:
        assert page.slider.isEnabled()
        page.sync_page._state["client"] = object()
        page._refresh_busy_state()
        assert page.slider.isEnabled(), "会话进行中不应锁住切档"
        page.select_gear(LanWorkspacePage.TRANSFER, animate=False)
        assert page.current_gear() == LanWorkspacePage.TRANSFER
        page.sync_page._state["client"] = None
        page._refresh_busy_state()
        assert page.slider.isEnabled()
    finally:
        page.close_page("user")


class _FakeLanServer:
    """站起传输站所需的最小服务端替身：可控制 connected / _result 走到收尾分支。"""

    def __init__(self, _vault, _same_lineage):
        import time as _time

        self._inner = SimpleNamespace(
            authenticated_at=_time.time() - 42.0,
            sessions={"t": {"op": "sync", "authorized_device_id": None, "authorized_public_key": None, "client_ip": "192.168.1.87"}},
            pending_transfer_device=None,
            pending_export_device=None,
        )
        self.device_auth_enabled = False
        self.sync_approval_enabled = False
        self.pairing_url = "https://127.0.0.1:18765"
        self.connected = False
        self._transfer_active = False
        self._transfer_lock = threading.Lock()
        self._transfer_outgoing: dict = {}
        self.transfer_received: list = []
        self.transfer_sent: list = []
        self.sync_phase = "idle"
        self.sync_send_progress = None
        self.sync_receive_progress = None
        self.pending_sync_device = None
        self._result = None
        self.stopped = 0

    @property
    def _server(self):
        return self._inner

    def start(self):
        return "https://127.0.0.1:18765", "123456"

    def stop(self):
        self.stopped += 1
        # 真实 stop() 会清空 sessions 并把 _server 置 None，connected 随之变 False。
        if self._inner is not None:
            self._inner.sessions = {}
            self._inner = None
        self.connected = False

    def authorize_peer(self) -> None:
        """模拟挑战确认通过：会话拿到对方 device_id。"""
        if self._inner is not None:
            self._inner.sessions["t"]["authorized_device_id"] = "FAE-7f3a91c4"

    @property
    def peer_info(self):
        """与真实 SyncServer.peer_info 同形：未接入时为 None。"""
        if not self.connected or self._inner is None:
            return None
        if not self._inner.sessions.get("t", {}).get("authorized_device_id"):
            return None
        return {
            "device_id": "FAE-7f3a91c4-2b8e-4d1a-9f33-6c0e5a7b1d42",
            "fingerprint": "3f9a2b71c8e04d56a1f0b3c9d2e7a845",
            "client_ip": "192.168.1.87",
            "operation": "transfer" if self._transfer_active else "sync",
            "authenticated_at": time.time() - 42.0,
        }

    def approve_sync(self, _token):
        pass

    def reject_sync(self, _token):
        pass

    def approve_transfer(self, _token):
        pass

    def reject_transfer(self, _token):
        pass

    def cancel_transfer_item(self, _item_id):
        return True

    def approve_export(self, _payload):
        pass

    def reject_export(self, _payload):
        pass


def _open_station(lan_context, monkeypatch):
    """真正建立一个传输站，返回 (workspace, station_page, fake_server)。

    回调（channel_changed / 收尾）只在 is_busy() 为真时才会跑，所以测试必须真的
    开一个站；只发信号而不开站的话断言会恒真，什么也没验证到。
    """
    import core.sync_server as sync_server_module
    from ui import widgets as ui_widgets
    from ui.sync_pages import LanWorkspacePage

    _app()
    monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: True)
    monkeypatch.setattr(ui_widgets, "message", lambda *a, **k: None)
    monkeypatch.setattr(sync_server_module, "SyncServer", _FakeLanServer)

    page = LanWorkspacePage(lan_context)
    station = page.station_page
    station.start_station()
    return page, station, station.server


def _pump(station, *, until_idle: bool = False, until=None, seconds: float = 2.0) -> None:
    """把 300ms 的轮询改成 1ms 并驱动若干拍，让 refresh_transfer_status 真正执行。

    条件一满足就提前退出：早先每个用例都空转满 3 秒，既慢又把大量 processEvents
    塞进同一个进程，放大了本机 Qt 退出期的访问违例（0xC0000005）。
    """
    station.poll_timer.setInterval(1)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        QCoreApplication.processEvents()
        if until is not None and until():
            return
        time.sleep(0.005)
        if until_idle and not station.poll_timer.isActive():
            return
    if not until_idle:
        # 保持轮询在跑，后续还要继续驱动
        station.poll_timer.setInterval(1)


def _close(page) -> None:
    """彻底收尾：停掉全部定时器、关闭页面、回收对象。

    这些用例会真的把轮询改成 1ms 并反复 processEvents；若不显式停掉，悬空的
    QTimer 会在后续用例里对已回收的 C++ 对象触槽，导致解释器中途崩在
    0xC0000005（本机 headless Qt 的退出期本就不稳，已在 56363e7 上复现）。
    """
    for child in page.pages:
        for name in ("poll_timer", "keepalive_timer", "busy_timer"):
            timer = getattr(child, name, None)
            if timer is not None:
                timer.stop()
    page.busy_timer.stop()
    page.close_page("user")
    page.deleteLater()
    QCoreApplication.processEvents()


def _shown_within(widget, root) -> bool:
    """widget 及其所有祖先（到 root 为止）都没有被显式隐藏时才算真正显示。

    直接用 isVisible() 需要祖先链真的可见（得造真实顶层窗口，退出时会把 Qt 撞出
    访问违例）；单看 isHidden() 又会漏掉「父容器已隐藏」的情况——隐藏面板里的子控件
    自己并没有被标记隐藏。这里沿父链逐级检查，两边的问题都避开。
    """
    node = widget
    while node is not None and node is not root:
        if node.isHidden():
            return False
        node = node.parentWidget()
    return node is root


def test_host_gear_only_ever_shows_connection_related_content(lan_context, monkeypatch):
    """建立传输站挡位只允许出现与连接状态有关的内容。

    回归点：收尾时曾把二维码/服务器地址/扫码提示放回去，而那时 server.stop() 已经
    执行——那张二维码指向一个已经不存在的传输站，扫了也连不上。断开后应回到「未开启」
    态：只有说明文字、状态行和「建立传输站」。
    """
    from PySide6.QtWidgets import QLabel, QPushButton

    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:

        def host_gear_texts() -> list[str]:
            page.select_gear(LanWorkspacePage.HOST, animate=False)
            return [w.text().replace("\n", " ").strip() for w in station.findChildren(QLabel) if _shown_within(w, station) and w.text().strip()] + [
                w.text() for w in station.findChildren(QPushButton) if _shown_within(w, station)
            ]

        server.connected = True
        _pump(station)
        server.connected = False
        server._result = {"transfer_ended": True}
        _pump(station, until_idle=True)
        assert server.stopped > 0, "服务端应已停止"

        shown = host_gear_texts()
        joined = " | ".join(shown)

        assert "服务器地址" not in joined, f"地址不应再出现：{shown}"
        assert "请用手机扫描二维码" not in joined, f"扫码提示不应再出现：{shown}"
        assert "已连接，等待同步或传输" not in joined
        assert "对方已关闭连接" not in joined
        # 回到未开启态
        assert "未开启" in shown
        assert "建立传输站" in shown
        assert "关闭传输站" not in shown
    finally:
        _close(page)


def test_station_entry_returns_after_a_completed_sync(lan_context, monkeypatch):
    """同步正常结束后，建立传输站入口必须回到主页。

    回归点：同步成功会走 _handle_station_result → show_result → 把结果面板挂到同步
    挡位，而挂载动作会顺带收起「建立传输站」入口——收尾明明刚把它放回来。用户看到
    的就只剩一个「已断开」，既不能重新开站、也不知道发生了什么。
    """
    from PySide6.QtWidgets import QPushButton

    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        # 一次正常完成的同步
        server.connected = True
        _pump(station)
        server.connected = False
        server._result = {"local_count": 3, "merged_count": 5, "verified": True}
        _pump(station, until_idle=True)
        QCoreApplication.processEvents()

        page.select_gear(LanWorkspacePage.HOST, animate=False)
        buttons = [w.text() for w in station.findChildren(QPushButton) if _shown_within(w, station)]
        assert "建立传输站" in buttons, f"同步结束后应能重新建立传输站，实际按钮：{buttons}"
        # 服务端已停，关闭按钮不该再出现
        assert "关闭传输站" not in buttons
        assert station.start_btn.isEnabled(), "建立按钮应可点击"
    finally:
        _close(page)


def test_gear_switching_stays_available_while_a_session_runs(lan_context, monkeypatch):
    """传输站会话中允许切档，并停在有说明的那一挡。"""
    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        server.connected = True
        server.authorize_peer()
        _pump(station, until=lambda: page.sync_page._host_mode)
        assert station.is_busy()
        assert page.slider.isEnabled(), "会话中必须仍可切档"

        # 切到没在跑的那一挡：只显示说明，不提供任何操作
        page.select_gear(LanWorkspacePage.TRANSFER, animate=False)
        assert page.current_gear() == LanWorkspacePage.TRANSFER
        notice = page.transfer_page._busy_notice
        assert not notice.isHidden()
        assert "局域网同步" in notice.text()
        assert page.transfer_page.connect_view.isHidden(), "说明状态下不该露出连接表单"
    finally:
        _close(page)


def test_inactive_gear_explains_the_running_channel(lan_context, monkeypatch):
    """在跑文件传输时，同步挡位应说明「正在进行文件传输」，反之亦然。"""
    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        server.connected = True
        server.authorize_peer()
        server._transfer_active = True
        _pump(station, until=lambda: page.current_gear() == LanWorkspacePage.TRANSFER)

        # 传输在跑 -> 同步挡位给出说明
        page.select_gear(LanWorkspacePage.SYNC, animate=False)
        notice = page.sync_page._busy_notice
        assert not notice.isHidden()
        assert "文件传输" in notice.text()
        assert page.sync_page.connect_view.isHidden()
        assert page.sync_page.sync_view.isHidden(), "说明状态下不该同时挂会话视图"

        # 会话结束 -> 说明撤掉，连接表单回来
        server.connected = False
        server._transfer_active = False
        server._result = {"transfer_ended": True}
        _pump(station, until_idle=True)
        assert page.sync_page._busy_notice.isHidden()
    finally:
        _close(page)


def test_transfer_page_shows_peer_device_as_plain_text(lan_context, monkeypatch):
    """传输页顶部只加一行对方设备文本，不做卡片。

    授权记录里没有「设备名称」这个字段（PC 与 Android 都没有设备名概念），
    所以只能取 device_id 前 8 位；标签写「对方设备」而非「名称」，不把 ID 截断
    说成一个名字。
    """
    from PySide6.QtWidgets import QFrame

    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        label = page.transfer_page.peer_device_label
        assert label.isHidden(), "没有会话时不该显示对方设备"

        server.connected = True
        server.authorize_peer()
        server._transfer_active = True
        _pump(station, until=lambda: page.current_gear() == LanWorkspacePage.TRANSFER)

        page.select_gear(LanWorkspacePage.TRANSFER, animate=False)
        QCoreApplication.processEvents()
        assert not label.isHidden()
        # device_id 是 UUID，取前 8 位（与日志里 device_id[:8] 的既有约定一致）
        assert label.text() == "对方设备：FAE-7f3a"
        # 只要文本：外面没有卡片容器
        assert not isinstance(label.parentWidget(), QFrame) or label.parentWidget().objectName() != "SettingGroupBox"

        # 同步在跑时传输挡位只显示说明，对方设备文本要撤掉
        server._transfer_active = False
        _pump(station, until=lambda: page.current_gear() == LanWorkspacePage.SYNC)
        assert label.isHidden(), "切到说明状态后不该还留着对方设备"
    finally:
        _close(page)


def test_transfer_page_offers_an_end_button_while_a_session_runs(lan_context, monkeypatch):
    """传输页的底部按钮与同步页同一套阶段逻辑：进行中=断开连接，结束后=退出传输。"""
    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        panel = station._session_panels["transfer"]
        # 用 _shown_within（沿父链判断显隐）而不是 isVisible()：后者要求祖先可见，
        # 测试里工作区并未 show，会让断言恒假。
        assert not _shown_within(panel._end_btn, panel), "没有会话时不该显示结束按钮"

        server.connected = True
        server._transfer_active = True
        _pump(station)
        page.select_gear(LanWorkspacePage.TRANSFER, animate=False)
        QCoreApplication.processEvents()

        assert _shown_within(panel._end_btn, panel), "传输会话中应显示结束按钮"
        assert panel._end_btn.text() == "断开连接", "进行中应为断开连接"

        # 点它：断开，但页面不关
        panel._end_btn.click()
        QCoreApplication.processEvents()
        _pump(station, until_idle=True)
        assert "已结束本次传输" in panel._feedback.text()
        assert page.current_gear() == LanWorkspacePage.TRANSFER, "断开不应关闭页面"
        # 断开后按钮留着，但改名成「退出传输」——这时点「断开连接」已经没有对象可断
        assert _shown_within(panel._end_btn, panel), "断开后按钮要留着，否则退不出该页"
        assert panel._end_btn.text() == "关闭页面"
        assert panel._end_btn.accessibleName() == "关闭页面"

        # 已经断开了，再点一次才退出传输视图
        panel._end_btn.click()
        QCoreApplication.processEvents()
        assert not page.transfer_page._host_mode, "退出后应恢复连接方 UI"
        assert page.transfer_page.connect_view.isHidden() is False
    finally:
        _close(page)


def test_lan_connector_transfer_can_close_after_disconnect(lan_context):
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    transfer_page = page.transfer_page
    panel = transfer_page.connector_transfer_panel
    try:
        transfer_page._state.update(client=object(), mode="transfer")
        transfer_page._disconnect_now = lambda: None
        transfer_page.connect_view.hide()
        panel.show()
        panel.set_composer_visible(True)
        panel.set_end_visible(True)
        panel.set_end_active(True)

        panel.endRequested.emit()

        assert transfer_page._state["client"] is None
        assert panel._send_text.isHidden()
        assert not panel.isHidden()
        assert panel._end_btn.text() == "关闭页面"

        panel.endRequested.emit()

        assert panel.isHidden()
        assert not transfer_page.connect_view.isHidden()
        assert not transfer_page.status_label.isHidden()
    finally:
        transfer_page._state["client"] = None
        _close(page)


def test_station_page_shows_peer_and_session_cards_without_progress(lan_context, monkeypatch):
    """接入后传输站页面显示对方设备 + 本次连接两张卡，且不含任何进度。"""
    from PySide6.QtWidgets import QLabel, QProgressBar

    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        cards = station.peer_cards
        assert not _shown_within(cards, station), "未接入时不该显示信息卡"

        server.connected = True
        server.authorize_peer()
        _pump(station, until=lambda: page.sync_page._host_mode)
        page.select_gear(LanWorkspacePage.HOST, animate=False)

        assert _shown_within(cards, station), "接入后应显示信息卡"
        shown = {w.text() for w in cards.findChildren(QLabel) if _shown_within(w, station) and w.text()}
        joined = " | ".join(shown)
        # 对方设备
        assert "FAE-7f3a91c4-2b8e-4d1a-9f33-6c0e5a7b1d42" in joined
        assert "3f9a2b71c8e04d56a1f0b3c9d2e7a845" in joined, "应显示公钥指纹"
        assert "192.168.1.87" in joined, "应显示对端地址"
        # 本次连接：只有通道和时长（mm:ss）
        assert "局域网同步" in joined
        assert any(re.fullmatch(r"\d{2}:\d{2}(:\d{2})?", t) for t in shown), f"应有时长（mm:ss）：{shown}"
        # 明确不要进度
        assert not cards.findChildren(QProgressBar), "这两张卡里不该有进度条"
        for word in ("%", "进度", "已传"):
            assert word not in joined, f"卡里不该出现进度相关内容：{word}"

        # 断开后收回
        server.connected = False
        server._result = {"transfer_ended": True}
        _pump(station, until_idle=True)
        assert not _shown_within(cards, station)
    finally:
        _close(page)


def test_lan_workspace_jumps_to_the_gear_matching_the_connected_channel(lan_context, monkeypatch):
    """本机传输站被对端连接后，跳到对应挡位展示会话状态。

    旧断言（连接后仍停在「建立传输站」挡位）在没有真正开站时恒真——is_busy() 为
    False，回调直接 return，所以那条测试其实什么都没验证。这里真的开一个站再触发。
    """
    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        # 对端接入同步通道
        server.connected = True
        server.authorize_peer()
        _pump(station, until=lambda: page.sync_page._host_mode)
        assert page.current_gear() == LanWorkspacePage.SYNC
        assert page.stack.currentWidget() is page.sync_page

        # 同一会话改走文件传输通道
        server._transfer_active = True
        _pump(station, until=lambda: page.current_gear() == LanWorkspacePage.TRANSFER)
        assert page.current_gear() == LanWorkspacePage.TRANSFER
        assert page.stack.currentWidget() is page.transfer_page
    finally:
        _close(page)


def test_station_page_keeps_only_status_and_close_while_connected(lan_context, monkeypatch):
    """被连接后传输站主页只保留连接状态与「关闭传输站」，二维码/地址/提示全部隐藏。"""
    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        server.connected = True
        _pump(station)

        # 二维码、服务器地址、提示行都不可见
        for label in station._pairing_labels:
            assert label.isHidden(), f"{label.objectName() or type(label).__name__} 不应可见"
        # 只剩连接状态 + 关闭传输站
        assert not station.host_status.isHidden()
        assert station.host_status.text() != ""
        assert not station.stop_btn.isHidden()
        # 「建立传输站」入口收起
        assert station.intro.isHidden()
    finally:
        _close(page)


def test_connected_gears_hide_every_scan_entry_point(lan_context, monkeypatch):
    """已连接期间，当前可见的挡位不得出现扫码/地址/连接入口。

    只检查当前显示的那一挡：非当前挡位在 QStackedWidget 里恒为 isHidden()，把
    隐藏当成通过会让这条断言永远成立，等于没测。
    """

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        server.connected = True
        _pump(station)
        shown = page.stack.currentWidget()
        assert shown is page.sync_page
        assert shown._host_mode, "同步挡位应进入主机模式"
        assert shown.connect_view.isHidden(), "地址/扫码/连接入口不应出现"
        assert shown.status_label.isHidden()
        assert not shown.host_attach.isHidden(), "应显示主机侧会话状态"

        server._transfer_active = True
        _pump(station)
        shown = page.stack.currentWidget()
        assert shown is page.transfer_page
        assert shown._host_mode, "文件传输挡位应进入主机模式"
        assert shown.connect_view.isHidden(), "地址/扫码/连接入口不应出现"
        assert shown.status_label.isHidden()
        assert not shown.host_attach.isHidden()
    finally:
        _close(page)


def test_session_end_keeps_the_gear_and_shows_disconnected(lan_context, monkeypatch):
    """对端断开后留在当前挡位，不跳回、也不把扫码入口摆回来。"""
    from ui.sync_pages import LanWorkspacePage

    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        server.connected = True
        server.authorize_peer()
        _pump(station, until=lambda: page.sync_page._host_mode)
        assert page.current_gear() == LanWorkspacePage.SYNC

        server.connected = False
        server._result = {"transfer_ended": True}
        _pump(station, until_idle=True)

        assert page.current_gear() == LanWorkspacePage.SYNC, "应留在原挡位"
        assert page.stack.currentWidget() is page.sync_page
        # 同一屏里不应又冒出扫码入口
        assert page.sync_page.connect_view.isHidden()
    finally:
        _close(page)


def _drive_station_page(lan_context, monkeypatch, result):
    """真正建立传输站、让设备连上、再把会话推到结束，返回 (page, station, server)。"""
    import core.sync_server as sync_server_module
    from ui import widgets as ui_widgets
    from ui.sync_pages import LanWorkspacePage

    _app()
    monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: True)
    monkeypatch.setattr(ui_widgets, "message", lambda *a, **k: None)
    monkeypatch.setattr(sync_server_module, "SyncServer", _FakeLanServer)

    page = LanWorkspacePage(lan_context)
    station = page.station_page
    station.start_station()
    server = station.server
    # 设备完成配对：connected 变真，状态区显示「已连接，等待同步或传输…」。
    server.connected = True
    server._result = result
    # 让 300ms 的轮询立即跑一拍，真实执行 _finish_if_done。
    station.poll_timer.setInterval(1)
    deadline = time.monotonic() + 3.0
    while station.poll_timer.isActive() and time.monotonic() < deadline:
        QCoreApplication.processEvents()
        time.sleep(0.005)
    return page, station, server


def test_lan_station_clears_connected_text_before_restoring_start_entry(lan_context, monkeypatch):
    """对方断开后不得留下「已连接」文案而按钮又可用这一矛盾状态。

    回归点：_finish_if_done 原先在 server.stop() 之前先刷一次状态，那一刻
    server.connected 仍为 True，「已连接，等待同步或传输…」被写进状态区；紧接着
    轮询停止，于是该文案永久冻结，而入口已经恢复可用。断开后状态行回到「未开启」。
    """
    from ui.sync_pages import LanSyncStatusPanel

    page, station, _server = _drive_station_page(lan_context, monkeypatch, {"timeout": "等待连接超时"})
    try:
        status = station.findChild(LanSyncStatusPanel)
        if status is not None:
            assert status._status.text() != "已连接，等待同步或传输…"
        assert station.host_status.text() == "未开启"
        assert _shown_within(station.start_btn, station)
        assert station.start_btn.isEnabled()
    finally:
        _close(page)


def test_lan_station_restores_start_entry_after_peer_ends_transfer(lan_context, monkeypatch):
    """对方主动结束传输同样要给出已断开状态、复原入口，而不是留下已连接的假象。"""
    from ui.sync_pages import LanSyncStatusPanel

    page, station, _server = _drive_station_page(lan_context, monkeypatch, {"transfer_ended": True})
    try:
        status = station.findChild(LanSyncStatusPanel)
        assert status is not None
        assert status._status.text() == "已断开"
        assert not station.intro.isHidden()
        assert station.start_btn.isEnabled()
    finally:
        _close(page)


def test_lan_station_pairing_chrome_comes_back_after_session_ends(lan_context, monkeypatch):
    """连接时自动收起的二维码/地址/提示，会话结束后要放回，入口才是真正初始态。"""
    page, station, _server = _drive_station_page(lan_context, monkeypatch, {"transfer_ended": True})
    try:
        labels = [w for w in station._session_widgets if w.__class__.__name__ == "QLabel"]
        assert labels, "配对区标签应已建立"
        assert all(not w.isHidden() for w in labels)
    finally:
        _close(page)


def test_lan_station_start_entry_is_replaced_while_a_station_runs(lan_context, monkeypatch):
    """开站期间「建立传输站」应被换掉，而不是留在原地灰着。

    旧实现只是 setEnabled(False)，按钮还在页面上，用户会以为可以直接再开一个站。
    """
    page, station, server = _open_station(lan_context, monkeypatch)
    try:
        # _open_station 已经开好站：应当只剩「关闭传输站」
        assert station.start_btn.isHidden(), "开站后应换成关闭传输站"
        assert _shown_within(station.stop_btn, station)
        assert station.host_status.text() == "等待设备接入"

        # 结束会话后换回来
        server.connected = True
        server.authorize_peer()
        _pump(station, until=lambda: page.sync_page._host_mode)
        server.connected = False
        server._result = {"transfer_ended": True}
        _pump(station, until_idle=True)
        assert _shown_within(station.start_btn, station)
        assert station.start_btn.isEnabled()
        assert station.stop_btn.isHidden()
        assert station.host_status.text() == "未开启"
    finally:
        _close(page)


def test_sync_server_stop_clears_transfer_and_sync_phase():
    """_transfer_active 原先只在 __init__ 置 False、stop() 不清。

    UI 的 is_busy() 读它来决定是否禁用三档滑块，不清就会在传输跑完后永久禁用。
    """
    from core.sync_server import SyncServer

    server = SyncServer.__new__(SyncServer)
    server._transfer_active = True
    server.sync_phase = "sending"
    server.sync_send_progress = (1, 2)
    server.sync_receive_progress = (3, 4)
    server._transfer_lock = threading.Lock()
    server._transfer_outgoing = {}
    server._transfer_received = []
    server._transfer_sent = []
    server._active_connections_lock = threading.Lock()
    server._active_connections = []
    server._transfer_active_connections = {}
    server._server = None
    server._tls_paths = None
    # 必须是一个专属子目录：stop() 会对 _transfer_dir 执行 rmtree，指向 gettempdir()
    # 会把整个 %TEMP% 连同 pytest 的临时目录一起删掉。
    server._transfer_dir = Path(tempfile.mkdtemp(prefix="lan-stop-test-"))
    server.pin = "123456"
    server.pairing_ticket = "t"
    server._result = None

    server.stop()

    assert server._transfer_active is False
    assert server.sync_phase == "idle"
    assert server.sync_send_progress is None
    assert server.sync_receive_progress is None


def test_lan_workspace_re_enables_gears_after_a_transfer_ended(lan_context, monkeypatch):
    """端到端：传输跑完后三档滑块必须恢复可切，而不是被 is_busy() 永久锁死。"""
    page, station, _server = _drive_station_page(lan_context, monkeypatch, {"transfer_ended": True})
    try:
        station.server = None
        page._refresh_busy_state()
        assert page.slider.isEnabled()
    finally:
        _close(page)


def test_lan_entrypoints_open_workspace_pages_without_modal_flow():
    """三个局域网入口都开同一个三档页，只切换滑块档位，不弹模态流程。"""
    source = (
        inspect.getsource(MainWindow._open_lan_station_page)
        + inspect.getsource(MainWindow._open_lan_connection_page)
        + inspect.getsource(MainWindow._open_lan_page)
    )
    lane = inspect.getsource(MainWindow._open_lan_page)
    assert ".exec(" not in source
    assert "LanWorkspacePage" in lane
    # 三档各自承载原页面，入口只负责选档
    assert "LanWorkspacePage.HOST" in source
    assert "LanWorkspacePage.SYNC" in source
    assert "LanWorkspacePage.TRANSFER" in source


# ---------- Task 9: theme, accessibility, and modal-entry removal ----------


def test_editor_tab_theme_uses_palette_tokens():
    from ui import theme

    sheet = theme.stylesheet("dark")
    assert "QTabBar#EditorTabBar" in sheet
    assert "QTabBar#EditorTabBar::tab:selected" in sheet
    assert theme.DARK["surface"] in sheet
    assert theme.DARK["accent_soft"] in sheet


def test_editor_tab_bar_uses_window_background_for_unselected_tabs():
    from ui import theme

    light = theme.stylesheet("light")
    bar = light.split("QTabBar#EditorTabBar {")[1].split("}")[0]
    assert f"background: {theme.LIGHT['bg']}" in bar
    assert "border-left" not in bar  # 竖线改为自绘，避免上下贯穿

    selected = light.split("QTabBar#EditorTabBar::tab:selected")[1].split("}")[0]
    assert f"background: {theme.LIGHT['surface']}" in selected
    assert "border: none" in selected
    assert "border-top-left-radius" in selected  # 顶部标题的圆角效果
    assert "accent" not in selected  # 不再用强调色下划线标记选中


def test_editor_tabs_have_no_vertical_or_bottom_separators():
    from PySide6.QtGui import QColor

    from ui import theme

    app = _app()
    bar = EditorTabBar()
    bar.addTab("One")
    bar.addTab("Two")
    bar.setCurrentIndex(1)
    bar.resize(400, 36)
    bar.show()
    app.processEvents()

    image = bar.grab().toImage()
    border = QColor(theme.active()["border"]).name()
    separator_x = bar.tabRect(1).left()
    column = [image.pixelColor(separator_x, y).name() for y in range(bar.height())]
    hits = [y for y, name in enumerate(column) if name == border]
    assert not hits, "相邻标题之间不应有竖分割线"

    bottom = bar.height() - 1
    assert all(image.pixelColor(x, bottom).name() != border for x in range(2, bar.width() - 2)), "标题栏底部不应有分割线"


def test_editor_workspace_keeps_tab_bar_adjacent_to_content():
    _app()
    workspace = EditorWorkspace(QWidget())
    layout = workspace.layout()

    assert isinstance(workspace.tabs, EditorTabBar)
    assert [layout.itemAt(index).widget() for index in range(layout.count())] == [
        workspace.tabs,
        workspace.stack,
    ]


def test_workspace_page_margins_come_from_one_constant():
    from ui.editor_workspace import PAGE_MARGINS

    assert PAGE_MARGINS == (20, 20, 20, 20)
    root = Path(__file__).resolve().parents[1] / "ui"
    # 页面级边距只在 page_shell 里落地，功能页不再自己写
    shell_source = (root / "editor_workspace.py").read_text(encoding="utf-8")
    assert "root.setContentsMargins(*PAGE_MARGINS)" in shell_source
    # 条目详情页不参与统一，仍直接引用同一条边距常量
    app_source = (root / "app.py").read_text(encoding="utf-8")
    assert "self.detail.setContentsMargins(*PAGE_MARGINS)" in app_source
    pages = (
        "app.py",
        "cloud_sync_page.py",
        "maintenance_pages.py",
        "security_page.py",
        "settings_page.py",
        "sync_pages.py",
    )
    for name in pages:
        source = (root / name).read_text(encoding="utf-8")
        # 各页面不再各写各的页面级边距字面量
        assert "setContentsMargins(20, 20, 20, 20)" not in source, name
        assert "setContentsMargins(28, 8, 28, 24)" not in source, name


def test_detail_page_title_and_content_margins_come_from_shared_template():
    """详情页标题卡与字段内容的内边距/行距统一走 DETAIL_* 模板常量。"""
    from ui import editor_workspace as ws

    assert ws.DETAIL_CARD_MARGINS == (12, 12, 12, 12)
    assert ws.DETAIL_COLUMN_MARGINS == (0, 0, 0, 0)
    assert ws.DETAIL_FIELD_SPACING == 3
    assert ws.DETAIL_BLOCK_SPACING == 12
    assert ws.DETAIL_FIELD_ROW_SPACING == 6
    # 排版节奏：标题与其内容贴紧，标题与下一个标题留白。
    assert ws.DETAIL_FIELD_SPACING < ws.DETAIL_BLOCK_SPACING

    root = Path(__file__).resolve().parents[1] / "ui"
    app_source = (root / "app.py").read_text(encoding="utf-8")
    for name in (
        "DETAIL_CARD_MARGINS",
        "DETAIL_COLUMN_MARGINS",
        "DETAIL_FIELD_SPACING",
        "DETAIL_BLOCK_SPACING",
        "DETAIL_FIELD_ROW_SPACING",
    ):
        assert "from .editor_workspace import" in app_source
        assert name in app_source, name
        # 标题卡 / 字段 / 关联自动填充卡不再各写各的字面量
        assert "setContentsMargins(12, 12, 12, 12)" not in app_source, name
        assert "setContentsMargins(12, 10, 12, 10)" not in app_source, name
        assert "setSpacing(3)" not in app_source, name

    # 详情页的标题卡与字段行确实落在同一套常量上
    main_source = inspect.getsource(MainWindow._detail_title_card)
    assert "layout.setContentsMargins(*DETAIL_CARD_MARGINS)" in main_source
    assert "text_col.setContentsMargins(*DETAIL_COLUMN_MARGINS)" in main_source
    assert "text_col.setSpacing(DETAIL_FIELD_SPACING)" in main_source
    field_source = inspect.getsource(MainWindow._field)
    assert "lay.setContentsMargins(*DETAIL_COLUMN_MARGINS)" in field_source
    assert "lay.setSpacing(DETAIL_FIELD_SPACING)" in field_source
    assert "row.setSpacing(DETAIL_FIELD_ROW_SPACING)" in field_source
    markdown_source = inspect.getsource(MainWindow._markdown_field)
    assert "lay.setSpacing(DETAIL_FIELD_SPACING)" in markdown_source
    # 图片字段与二维码字段的「标题 → 内容」也走同一条「近」节奏
    assert "lay.setSpacing(DETAIL_FIELD_SPACING)" in inspect.getsource(MainWindow._images_field)
    assert "lay.setSpacing(DETAIL_FIELD_SPACING)" in inspect.getsource(MainWindow._photo_module_field)
    # 块与块之间走同一条「远」节奏
    pane_source = inspect.getsource(MainWindow._build_detail_pane)
    assert "self.detail.setSpacing(DETAIL_BLOCK_SPACING)" in pane_source


def test_every_workspace_page_shares_one_header_layout(monkeypatch, fake_vault, window_stub, cloud_context, lan_context):
    from unittest.mock import MagicMock

    from ui.editor_workspace import PAGE_MARGINS
    from ui.maintenance_pages import DedupPage, RecycleBinPage, SameServicePage
    from ui.security_page import SecurityCenterPage
    from ui.settings_page import SettingsPage
    from ui.sync_pages import (
        CloudSyncWorkspacePage,
        LanConnectionPage,
        LanStationPage,
        LocalBackupPage,
    )

    _app()
    monkeypatch.setattr(SecurityCenterPage, "_start_analysis", lambda *a, **k: None)
    pages = (
        SecurityCenterPage([], ""),
        SettingsPage(window_stub),
        RecycleBinPage(fake_vault),
        DedupPage([]),
        SameServicePage([]),
        CloudSyncWorkspacePage(cloud_context),
        LocalBackupPage(MagicMock()),
        LanStationPage(lan_context),
        LanConnectionPage(lan_context, preset_mode="sync"),
    )
    for page in pages:
        name = type(page).__name__
        header = page.page_header
        assert header.title.objectName() == "WorkspacePageTitle", name
        assert header.subtitle.objectName() == "SettingNote", name
        assert header.title.text(), name
        # 没有小标题的页面隐藏该标签，不占高度
        assert header.subtitle.isHidden() is not bool(header.subtitle.text()), name
        # 云同步工作区页是薄包装，骨架在内嵌的 CloudSyncPage 上
        shell_owner = page.ui if isinstance(page, CloudSyncWorkspacePage) else page
        margins = shell_owner.layout().contentsMargins()
        assert (margins.left(), margins.top(), margins.right(), margins.bottom()) == PAGE_MARGINS, name


def test_page_headers_survive_content_rebuilds():
    """头部必须挂在根布局上：两个页面会反复清空内容区。"""
    from ui.maintenance_pages import DedupPage, SameServicePage

    _app()
    for page in (SameServicePage([]), DedupPage([])):
        name = type(page).__name__
        header = page.page_header
        page.reset([])
        page.reset([])
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        assert page.page_header is header, name
        assert page.layout().itemAt(0).layout() is header.row, name
        assert not header.title.isHidden(), name


def test_lan_connection_page_keeps_one_live_status_line(lan_context):
    """页头小标题是静态的；连接状态行必须是一个能被反复 setText 的控件。"""
    from ui.sync_pages import LanConnectionPage

    _app()
    page = LanConnectionPage(lan_context, preset_mode="sync")
    hints = [label for label in page.findChildren(QLabel) if "粘贴传输站" in label.text()]
    assert len(hints) == 1
    hints[0].setText("正在连接…")
    assert page.page_header.subtitle.text() != "正在连接…"


def test_feature_entrypoints_do_not_execute_modal_main_flows():
    for method in (
        MainWindow._open_security_center,
        MainWindow.open_recycle_bin,
        MainWindow.open_settings,
        MainWindow.dedup_entries,
        MainWindow.merge_same_service_entries,
        MainWindow._open_cloud_sync,
        MainWindow._open_local_backup,
        MainWindow._open_lan_station_page,
        MainWindow._open_lan_connection_page,
    ):
        assert ".exec(" not in inspect.getsource(method)


def test_feature_tab_close_button_has_accessible_name():
    from ui.editor_workspace import EditorWorkspace

    _app()
    workspace = EditorWorkspace(QWidget(), detail_title="Entry details")
    workspace.open_page("settings", "Settings", QWidget)
    button = workspace.tabs.tabButton(1, QTabBar.ButtonPosition.RightSide)
    assert button is not None
    assert "Settings" in button.accessibleName()


# ---------- 断开后：发送区必须收起，按钮必须变成「关闭页面」 ----------


def _assert_disconnected_look(panel, where: str) -> None:
    """断开后的统一外观：发送区收起、按钮留着但不再叫「断开连接」。"""
    assert panel._send_text.isHidden(), f"{where}：输入框应收起"
    assert panel._actions.isHidden(), f"{where}：发送按钮区应收起"
    assert not panel._send_text_btn.isEnabled(), f"{where}：发送按钮应禁用"
    assert panel._end_btn.text() == "关闭页面", f"{where}：按钮应切到「关闭页面」"
    assert panel._end_btn.accessibleName() == "关闭页面"


@pytest.mark.parametrize(
    "result",
    [
        {"transfer_ended": True, "by": "local"},
        {"transfer_ended": True, "by": "peer"},
        {"timeout": "等待连接超时"},
    ],
    ids=["local-ended", "peer-ended", "timeout"],
)
def test_host_side_disconnects_every_way_collapse_the_sender(
    lan_context, monkeypatch, result
):
    """主机侧三种断开方式（本地结束/对方结束/超时）都要收起发送区。

    回归：原先只有 transfer_ended 分支调 set_send_enabled(False)，而那只禁用
    控件、不隐藏，输入框仍占着页面，看着还能发其实已经发不出去；超时分支连
    禁用都没有。set_composer_visible 统一收口后三条路径行为一致。
    """
    from ui.sync_pages import LanWorkspacePage  # noqa: F401

    page, station, _server = _drive_station_page(lan_context, monkeypatch, result)
    try:
        # 主机侧用的是它自己那份传输会话面板（_session_panels），会话时被挂进
        # host_attach；不是连接方的那个对象。
        panel = station._session_panels["transfer"]
        _assert_disconnected_look(panel, f"host {result}")
    finally:
        _close(page)


def test_connector_collapses_sender_when_the_station_closes(lan_context):
    """连接方：对方关闭传输站后必须收起发送区并切「关闭页面」。

    回归：_poll_loop 原先把 list_transfer_items() 的异常一律 pass 掉，连接方
    对「对方已关闭」完全失明——client 永不被置空，发送区留着、按钮还写着
    「断开连接」。现在连续失败到阈值就判定断开并在主线程收口。
    """
    from ui.sync_pages import LanConnectionPage, LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    conn = page.sync_page
    try:
        panel = conn.connector_transfer_panel
        conn._state.update(client=object(), mode="transfer")
        panel.show()
        panel.set_composer_visible(True)
        panel.set_end_visible(True)
        panel.set_end_active(True)
        panel._send_text.show()
        panel._actions.show()

        # 轮询线程判定断开后置位，poll 定时器在主线程消费。
        conn._state["connector_disconnected"] = True
        conn._state["transfer_feedback"] = "对方已关闭连接，可继续查看传输记录"
        conn.poll_timer.timeout.emit()

        assert conn._state["client"] is None, "断开后应释放 client，切档才能恢复"
        _assert_disconnected_look(panel, "connector")
        # 记录留着可看，不该把传输视图整个收走
        assert not panel.isHidden()
    finally:
        conn._state["client"] = None
        _close(page)


def test_connector_failed_connection_also_collapses_the_sender(lan_context):
    """连接失败也是一次断开：不能留下一个能输入但发不出去的发送区。"""
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    conn = page.sync_page
    try:
        panel = conn.connector_transfer_panel
        panel.show()
        panel.set_composer_visible(True)
        panel._send_text.show()
        panel._actions.show()

        conn._state.update(client=object(), mode="transfer", connect_error="无法连接")
        conn.poll_timer.timeout.emit()

        assert conn._state["client"] is None
        _assert_disconnected_look(panel, "connect-failed")
    finally:
        conn._state["client"] = None
        _close(page)


def test_poll_failure_threshold_requires_consecutive_errors():
    """单次网络抖动不该判定断开，连续失败到阈值才算。"""
    import ui.sync_pages as sync_pages_module

    assert sync_pages_module._POLL_FAILURES_TO_END >= 2, "阈值太低会把抖动误判成断开"


def test_sync_disconnect_asks_first_and_cancels_cleanly(lan_context, monkeypatch):
    """同步中断开必须先确认；选取消时既不断连也不改任何状态。"""
    from ui import widgets as ui_widgets
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    conn = page.sync_page
    try:
        conn._state["client"] = object()
        conn.sync_view.setVisible(True)
        seen = []
        monkeypatch.setattr(
            ui_widgets, "confirm", lambda *a, **k: seen.append(a[1] if len(a) > 1 else "") or False
        )

        conn._on_exit_sync_session()

        assert seen, "应弹出二次确认"
        assert conn._state["client"] is not None, "选取消不得断开"
        # 页面在 QStackedWidget 里，isVisible() 对非当前挡恒为假，只能看 isHidden()
        assert not conn.sync_view.isHidden(), "选取消不得关闭同步视图"

        # 选确认才真的断
        monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: True)
        disconnected = []
        conn._disconnect_now = lambda: disconnected.append(True)
        conn._on_exit_sync_session()
        assert disconnected, "确认后应执行断开"
    finally:
        conn._state["client"] = None
        _close(page)


def test_transfer_end_asks_before_dropping_the_sender(lan_context, monkeypatch):
    """连接方结束传输也要确认：选取消时发送区与连接都不能动。"""
    from ui import widgets as ui_widgets
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    conn = page.transfer_page
    try:
        conn._state.update(client=object(), mode="transfer")
        panel = conn.connector_transfer_panel
        panel.show()
        panel._send_text.show()
        panel._actions.show()
        monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: False)

        panel.endRequested.emit()

        assert conn._state["client"] is not None, "选取消不得断开"
        assert not panel._send_text.isHidden(), "选取消不得收起发送区"

        monkeypatch.setattr(ui_widgets, "confirm", lambda *a, **k: True)
        panel.endRequested.emit()
        assert panel._send_text.isHidden(), "确认后应收起发送区"
        assert panel._end_btn.text() == "关闭页面"
    finally:
        conn._state["client"] = None
        _close(page)


def test_exiting_host_mode_restores_the_connector_entry(lan_context):
    """退出主机视角后连接方入口要回来，否则点「关闭页面」像没反应。

    回归点有两个：LanConnectionPage 缺 _workspace()/set_workspace()，主机侧那条
    路径会 AttributeError 崩掉（Qt 吞掉异常，表现为点了没反应）；以及
    exit_host_mode 没有把 connect_view/status_label 放回来。
    """
    from ui.sync_pages import LanWorkspacePage

    _app()
    page = LanWorkspacePage(lan_context)
    conn = page.sync_page
    try:
        # LanWorkspacePage 构造时已给三页挂上工作区引用，缺了它主机侧关闭会崩。
        assert conn._workspace() is page
        conn.enter_host_mode()
        assert conn.connect_view.isHidden(), "进入主机模式应藏起连接入口"
        assert conn._host_mode

        conn._sync_finished = True
        conn._on_exit_sync_session()

        assert not conn._host_mode, "同步结束后应退出主机模式"
        assert conn.host_attach.isHidden(), "主机挂载区应隐藏"
        assert not conn.connect_view.isHidden(), "连接入口要放回"
        assert not conn.status_label.isHidden(), "状态行要放回"
    finally:
        conn._state["client"] = None
        _close(page)


def test_startup_controls_apply_registration_and_flush_silent_preference(window_stub, monkeypatch):
    from core import config, startup
    from ui.settings_page import SettingsPage
    _app()
    registrations, staged, saved = [], [], []
    monkeypatch.setattr(startup, "is_enabled", lambda: False)
    monkeypatch.setattr(startup, "set_enabled", registrations.append)
    monkeypatch.setattr(config, "stage_many", staged.append)
    monkeypatch.setattr(config, "set_many", saved.append)
    page = SettingsPage(window_stub)
    page.start_at_login.setChecked(True)
    assert registrations == [True]
    value = not page.silent_start.isChecked()
    page.silent_start.setChecked(value)
    assert staged[-1] == {"silent_start": value}
    page.close_page("test")
    assert saved[-1] == {"silent_start": value}
