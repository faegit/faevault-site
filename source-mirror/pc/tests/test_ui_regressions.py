import os
import ast
import contextlib
import inspect
import json
import tempfile
import time
import uuid
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QLocale, QMimeData, QObject, QPoint, Qt, QUrl
from PySide6.QtGui import QAction, QCloseEvent, QColor, QFontMetrics, QPalette, QPixmap
from PySide6.QtTest import QTest
from PySide6.QtWidgets import (
    QApplication,
    QAbstractButton,
    QAbstractItemView,
    QComboBox,
    QDialog,
    QGroupBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ui import app as app_ui
from ui.app import (
    MainWindow,
    _auto_sync_controls_enabled,
    _lan_connection_user_message,
    _lan_sync_result_summary,
    _lan_sync_user_message,
)
from ui.lan_panels import _TransferTextEdit, _clipboard_local_files, _transfer_parent_directory
from ui import dialogs
from ui import i18n
from ui import module_editor
from ui import theme
from ui import widgets as ui_widgets
from ui.dialogs import RecoveryKeyConfirmDialog, RelockDialog, _VaultImportCopyWorker
from ui.module_editor import ModuleCard, PasskeyStatus, passkey_display_rows, passkey_status
from ui.cloud_sync_page import CloudSyncPage
from ui.security_page import SecurityCenterPage
from ui.settings_page import SettingsPage
from ui.sync_pages import (
    CloudSyncWorkspacePage,
    LanConnectionPage,
    LanStationPage,
    LocalBackupPage,
)
from core import modules, passkeys
from core.models import Entry, SecretType


@pytest.fixture(autouse=True)
def _isolate_settings_environment_probe(monkeypatch):
    """Layout tests must not launch machine-dependent QThreads/PowerShell.

    Patch before page construction so queued callbacks capture the no-op,
    even if the next test is the first to pump the Qt event loop.
    """
    original = SettingsPage._start_environment_probe
    monkeypatch.setattr(SettingsPage, "_start_environment_probe", lambda self: None)
    return original


@pytest.fixture(autouse=True)
def _restore_ui_locale():
    """语言环境是进程级全局状态：个别用例切到英文后不还原，会让后续用例按英文渲染。

    这里在每个用例结束后统一还原，避免断言中文文案的用例受执行顺序影响。
    """
    yield
    i18n.set_locale("zh-Hans")


def _valid_passkey_module() -> dict:
    fixture_path = Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json"
    record = json.loads(fixture_path.read_text(encoding="utf-8"))["records"][0]["record"]
    return {
        "id": "android-passkey",
        "type": modules.PASSKEY,
        "title": "Passkey",
        "config": {},
        "sensitive": True,
        "value": record,
    }


def test_auto_sync_interval_is_enabled_as_soon_as_toggle_has_a_target():
    assert _auto_sync_controls_enabled(toggle_checked=True, target_count=1)
    assert not _auto_sync_controls_enabled(toggle_checked=True, target_count=0)
    assert not _auto_sync_controls_enabled(toggle_checked=False, target_count=1)


def test_auto_lock_blockers_pause_timeout_and_restart_after_last_task_finishes():
    calls = []
    timer = SimpleNamespace(stop=lambda: calls.append("stop"))
    host = SimpleNamespace(
        _auto_lock_blockers=set(),
        _idle_timer=timer,
        _reset_idle_timer=lambda: calls.append("reset"),
        lock_now=lambda: calls.append("lock"),
    )

    MainWindow._set_auto_lock_blocker(host, "lan-sync", True)
    MainWindow._on_idle_timeout(host)
    assert "lock" not in calls

    MainWindow._set_auto_lock_blocker(host, "lan-sync", False)
    MainWindow._on_idle_timeout(host)
    assert calls[-2:] == ["reset", "lock"]


def test_transfer_parent_directory_uses_real_source_and_hides_text_staging_paths(tmp_path):
    received = tmp_path / "received" / "note.txt"
    sent = tmp_path / "source" / "report.pdf"
    assert _transfer_parent_directory({"direction": "接收", "path": str(received)}) == str(received.parent)
    assert _transfer_parent_directory(
        {"direction": "发送", "kind": "file", "source_path": str(sent), "path": str(tmp_path / "stage.bin")}
    ) == str(sent.parent)
    assert _transfer_parent_directory(
        {"direction": "发送", "kind": "text", "path": str(tmp_path / "staged-text.txt")}
    ) == ""


def test_lan_sync_server_address_widget_follows_dialog_width():
    source = inspect.getsource(LanStationPage.start_station)
    assert "lbl_url.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)" in source
    # 地址控件加入页面内容区；会话控件统一经 _add_session_widget 记录，便于重新建立时回收
    assert "self._add_session_widget(lbl_url)" in source


def test_lan_station_hides_pairing_chrome_after_any_connection():
    source = inspect.getsource(LanStationPage.start_station)

    assert "(server.connected or server._transfer_active) and not pairing_auto_collapsed" in source
    assert "server.stop()" in source


def test_lan_sync_errors_match_android_actionable_branches():
    assert "允许本次同步" in _lan_connection_user_message(RuntimeError("HTTP 403 设备尚未完成授权"))
    assert "同一账户" in _lan_sync_user_message(RuntimeError("两端不是同一份 PMVE 保险库"))
    assert "未保存任何不完整数据" in _lan_sync_user_message(RuntimeError("收到的数据不完整"))


def test_lan_connection_errors_do_not_misreport_pairing_or_capacity_failures():
    """旧二维码/旧 PIN/错配 ticket 在传输站侧一律回 403，含义与「未授权设备」无关。"""
    stale_pairing = _lan_connection_user_message(RuntimeError("配对失败（HTTP 403）"))
    assert "重新" in stale_pairing
    assert "允许本次同步" not in stale_pairing
    # 传输站已关闭/会话释放同样回 403 Forbidden，但指向完全不同的补救动作
    released = _lan_connection_user_message(RuntimeError("拉取保险库失败（HTTP 403）：Forbidden"))
    assert "重新建立传输站" in released
    assert "允许本次同步" not in released
    # 设备授权的 403 仍需命中「未授权」档（设备未授权或已撤销）
    assert "允许本次同步" in _lan_connection_user_message(
        RuntimeError("设备认证失败（HTTP 403）：设备未授权或已撤销")
    )
    # 等待确认的 423：补救动作是重新开站扫码
    pending = _lan_connection_user_message(
        RuntimeError("等待主机确认同步超时（HTTP 423）：等待主机确认同步")
    )
    assert "重新建立传输站" in pending
    assert "锁定" not in pending
    # 锁定态同样用 423 上报（安卓主机回「PMVE 会话已锁定」）：动作是去解锁，
    # 不能被 423 档吞成「重新建立传输站」——重新开站对锁定态无效。
    locked = _lan_connection_user_message(
        RuntimeError('推送保险库失败（HTTP 423）：{"error": "PMVE 会话已锁定"}')
    )
    assert "解锁" in locked
    assert locked != pending
    # 容量上限不能被说成网络问题
    assert "文件传输" in _lan_sync_user_message(
        RuntimeError("拉取保险库失败（HTTP 413）：账户数据超过 10 GB，暂时无法通过局域网传输")
    )
    assert "检查网络" not in _lan_sync_user_message(RuntimeError("当前账户数据超过 10 GB，暂时无法发送"))


def test_lan_client_surfaces_a_locked_android_host_instead_of_a_pending_approval():
    """PC 作为客户端回推给安卓主机时，主机锁定会以 423 +「已锁定」上报。"""
    message = _lan_sync_user_message(
        RuntimeError('推送保险库失败（HTTP 423）：{"error": "PMVE 会话已锁定", "lineage": "x"}')
    )

    assert "解锁" in message
    assert "尚未确认" not in message


def test_station_pairing_hint_matches_the_rotation_interval():
    """提示里的刷新周期必须等于 PIN_ROTATE_INTERVAL：写短了会让用户扫到已轮换的旧码。"""
    from core.sync_server import PIN_ROTATE_INTERVAL

    source = inspect.getsource(LanStationPage.start_station)
    assert f"每 {PIN_ROTATE_INTERVAL // 60} 分钟自动刷新" in source
    assert f"每 {PIN_ROTATE_INTERVAL} 秒自动刷新" not in source


def test_lan_sync_result_reports_counts_upload_and_verification():
    text = _lan_sync_result_summary({
        "lineage": "DIVERGED",
        "local_count": 12,
        "merged_count": 14,
        "uploaded": True,
        "verified": True,
    })
    assert text == "双方修改已自动合并 · 本地 12 项 → 合并后 14 项 · 已回推更新 · 已通过安全校验"


def test_settings_does_not_duplicate_home_vault_maintenance_actions():
    app = QApplication.instance() or QApplication([])
    window = SimpleNamespace(
        vault=SimpleNamespace(path=Path("vault.pmv"), recovery_key_info=("", 0), key_revision=1),
        _native_hotkey_registered=False,
        cloud_sync_enabled=lambda: False,
        set_cloud_sync_enabled=lambda _enabled: None,
        apply_theme=lambda _dark: None,
        apply_lock_settings=lambda: None,
        apply_privacy_settings=lambda: None,
        apply_native_autofill_settings=lambda: None,
        reload=lambda: None,
        dedup_entries=lambda: None,
        merge_same_service_entries=lambda: None,
    )
    dialog = SettingsPage(window)
    labels = {button.text() for button in dialog.findChildren(QPushButton)}

    assert "保险库维护" not in {button.text() for button in dialog.findChildren(QPushButton)}
    assert {"重复条目对比", "相同服务处理", "数据库清理/压缩"}.isdisjoint(labels)
    dialog.deleteLater()


def test_category_bar_has_no_bottom_sidebar_toggle():
    """分类栏底部的三横线开关已移除，导入/导出/整理不再挂在侧边栏。"""
    sidebar = inspect.getsource(MainWindow._build_sidebar)

    assert "_action_btn" not in sidebar
    assert "_action_footer" not in sidebar
    assert "ActionToggle" not in sidebar
    assert "ui_icon(\"menu\")" not in sidebar


def test_more_menu_owns_sync_and_maintenance_groups():
    """更多功能承载同步（导入导出/本地备份/局域网/云端同步）与库维护两组菜单。"""
    top_bar = inspect.getsource(MainWindow._build_top_bar)
    sync_menu = inspect.getsource(MainWindow._build_sync_menu)
    maintenance_menu = inspect.getsource(MainWindow._build_maintenance_menu)

    assert "_more_btn" in top_bar
    assert "_build_sync_menu" in top_bar
    assert "_build_maintenance_menu" in top_bar

    assert 'i18n.tr("导入导出")' in sync_menu
    assert 'i18n.tr("本地备份")' in sync_menu
    assert 'i18n.tr("局域网")' in sync_menu
    assert 'i18n.tr("云端同步")' in sync_menu
    # 两级菜单顺序：导入导出 → 本地备份 → 局域网 → 云端同步
    order = [
        sync_menu.index('i18n.tr("导入导出")'),
        sync_menu.index('i18n.tr("本地备份")'),
        sync_menu.index('i18n.tr("局域网")'),
        sync_menu.index('i18n.tr("云端同步")'),
    ]
    assert order == sorted(order)

    assert 'i18n.tr("重复条目合并")' in maintenance_menu
    assert 'i18n.tr("相同服务合并")' in maintenance_menu
    # 数据库清理/压缩改为自动执行，不再有手动入口
    assert "数据库清理" not in maintenance_menu



def test_settings_page_has_no_duplicate_cloud_sync_group():
    """云端同步的开关与关联都由「云端同步」页自带，设置页不再重复一份。"""
    source = inspect.getsource(SettingsPage.__init__)
    cls_source = inspect.getsource(SettingsPage)

    assert "启用联网同步" not in source
    assert "cloud_sync_enabled" not in source
    assert "启用联网同步" not in cls_source
    assert "_on_cloud_sync_enabled_toggled" not in cls_source


def test_cloud_sync_entry_is_always_reachable_from_more_menu():
    """开关已收敛到云端同步页：菜单入口必须常驻，否则关闭后再也进不去。"""
    source = inspect.getsource(MainWindow._build_sync_menu)
    setter = inspect.getsource(MainWindow.set_cloud_sync_enabled)

    assert 'menu.addAction(i18n.tr("云端同步"), self._open_cloud_sync)' in source
    assert "setVisible" not in source
    assert "setVisible" not in setter


def test_capsule_segmented_control_clicks_silent_sets_and_ignores_disabled():
    """三档胶囊滑块：点击选档并发信号，静默设置不发信号，禁用时点击无效。"""
    app = QApplication.instance() or QApplication([])
    control = ui_widgets.CapsuleSegmentedControl(
        [("host", "建立传输站"), ("sync", "局域网同步"), ("transfer", "文件传输")],
        current=1,
    )
    control.resize(600, 46)
    control.show()
    app.processEvents()
    seen: list[int] = []
    control.changed.connect(seen.append)

    assert (control.count(), control.current_key()) == (3, "sync")

    QTest.mouseClick(control, Qt.LeftButton, pos=QPoint(int(control.width() * 0.2), 20))
    assert (control.current_index(), control.current_key(), seen) == (0, "host", [0])

    QTest.mouseClick(control, Qt.LeftButton, pos=QPoint(int(control.width() * 0.9), 20))
    assert (control.current_index(), control.current_key(), seen) == (2, "transfer", [0, 2])

    control.setEnabled(False)
    QTest.mouseClick(control, Qt.LeftButton, pos=QPoint(int(control.width() * 0.1), 20))
    assert control.current_index() == 2

    control.setEnabled(True)
    control.set_current_index(1, animate=False, notify=False)
    assert (control.current_index(), seen) == (1, [0, 2])
    control.deleteLater()


def test_top_notice_bar_floats_centered_capped_and_dismisses_on_click():
    """通知条浮在内容上方：顶部居中、宽度上限 560、点击可关。"""
    app = QApplication.instance() or QApplication([])
    host = QWidget()
    host.resize(1200, 700)
    bar = ui_widgets.NoticeBar(host)
    host.show()
    app.processEvents()
    assert not bar.isVisible()

    bar.show_message("已切换到「FAE」")
    app.processEvents()

    assert bar.isVisible()
    assert bar.width() == 560
    assert bar.x() == (host.width() - bar.width()) // 2
    assert bar.y() > 0
    assert bar.label.text() == "已切换到「FAE」"

    # 窄窗口下按可用宽度收缩，仍然居中
    host.resize(400, 500)
    bar.reposition()
    app.processEvents()
    assert bar.width() == 400 - 32
    assert bar.x() == 16

    QTest.mouseClick(bar, Qt.LeftButton)
    for _ in range(12):
        app.processEvents()
        app.thread().msleep(40)
    assert not bar.isVisible()
    host.deleteLater()
    bar.deleteLater()


def test_main_window_replaces_bottom_status_bar_with_top_notice_bar():
    """底部通知占位条移除，_flash 改走顶部悬浮通知条。"""
    init = inspect.getsource(MainWindow.__init__)
    flash = inspect.getsource(MainWindow._flash)

    assert "_status_bar" not in init
    assert "_notice_bar" in init
    assert "_notice_bar.show_message" in flash


def test_home_restores_separate_list_and_detail_cards_without_outer_workbench_card():
    source = inspect.getsource(MainWindow.__init__)
    assert "self._list_detail = QSplitter(Qt.Horizontal" in source
    assert "WorkbenchCard" not in source
    assert "self._list_detail.addWidget(self._list_pane)" in source
    assert "self._list_detail.addWidget(self._detail_pane)" in source
    assert "self._list_detail.setStretchFactor(0, 4)" in source
    assert "self._list_detail.setStretchFactor(1, 6)" in source
    assert "QSplitter#MainSplitter::handle" in theme.stylesheet("light")


def test_detail_content_is_top_aligned_and_avoids_vertical_fill():
    detail_build = inspect.getsource(MainWindow._build_detail_pane)
    detail_show = inspect.getsource(MainWindow._show_entry)
    markdown = inspect.getsource(MainWindow._markdown_field)
    module_render = inspect.getsource(MainWindow._render_modules)

    assert "self.detail.setAlignment(Qt.AlignTop)" in detail_build
    assert "self.detail_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)" in detail_build
    assert "self.detail.addStretch()" not in detail_show
    assert "self.detail.addWidget(self._markdown_field(title, text, guarded=guarded_all), 1)" not in module_render
    assert "wrap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)" in markdown
    assert "lay.addWidget(viewer)" in markdown


def test_detail_title_uses_colored_type_card_style():
    source = inspect.getsource(MainWindow._show_entry)
    card_source = inspect.getsource(MainWindow._detail_title_card)
    assert "self.detail.addWidget(MainWindow._detail_title_card(self, entry, shown_type))" in source
    assert "DetailTitleCard" in card_source
    assert "DetailTypeBadge" in card_source
    assert "border-left: 4px solid" in card_source
    assert app_ui._detail_type_color("login") == "#1E88E5"
    assert app_ui._detail_type_color("card_document") == "#3F51B5"
    assert app_ui._detail_type_color("wifi") == "#06B6D4"
    assert app_ui._detail_type_color("api_key") == "#43A047"
    assert app_ui._detail_type_color("otp") == "#00BFA5"
    assert app_ui._detail_type_color("secure_note") == "#546E7A"
    assert app_ui._detail_type_color("server") == "#00897B"
    assert app_ui._detail_type_color("custom") == "#6D4C41"
    assert app_ui._detail_type_color("passkey") == "#7C3AED"


def _rendered_colors(widget: QWidget) -> tuple[str, str]:
    """取控件渲染后的左侧描边与内部底色（都避开文字像素）。"""
    image = widget.grab().toImage()
    middle = widget.height() // 2
    return (
        QColor(image.pixel(0, middle)).name().upper(),
        QColor(image.pixel(6, middle)).name().upper(),
    )


@contextlib.contextmanager
def _theme_applied(mode: str):
    """临时套用主题全局样式表；用完还原，避免影响其它用例的布局度量。"""
    app = QApplication.instance() or QApplication([])
    previous = app.styleSheet()
    app.setStyleSheet(theme.stylesheet(mode))
    try:
        yield app
    finally:
        app.setStyleSheet(previous)


def test_detail_title_card_follows_theme_switch():
    """卡片底色与描边来自全局样式表，切换主题后立即跟随，不残留旧主题配色。"""
    entry = SimpleNamespace(secret_type="login", title="示例条目")

    with _theme_applied("light") as app:
        card = MainWindow._detail_title_card(SimpleNamespace(), entry, "login")
        card.resize(280, 56)
        light_accent, light_fill = _rendered_colors(card)

        app.setStyleSheet(theme.stylesheet("dark"))
        dark_accent, dark_fill = _rendered_colors(card)

    assert light_fill == QColor(theme.LIGHT["surface_alt"]).name().upper()
    assert dark_fill == QColor(theme.DARK["surface_alt"]).name().upper()
    accent = QColor(app_ui._detail_type_color("login")).name().upper()
    assert light_accent == dark_accent == accent
    card.deleteLater()


def test_detail_status_labels_follow_theme_switch():
    """过期提示条与泄露字段标签随主题刷新（配色改由全局样式表提供）。"""
    with _theme_applied("light") as app:
        banner = QLabel("已过期")
        banner.setObjectName("EntryExpiryBanner")
        banner.setProperty("state", "expired")
        banner.resize(200, 40)
        _, light_fill = _rendered_colors(banner)

        app.setStyleSheet(theme.stylesheet("dark"))
        _, dark_fill = _rendered_colors(banner)

        wrap = MainWindow._field(SimpleNamespace(), "密码", "secret", leaked=True)
        leaked_lbl = wrap.findChild(QLabel, "FieldLabel")
        leaked_lbl.show()
        dark_color = QColor(leaked_lbl.palette().color(QPalette.WindowText)).name().upper()

        app.setStyleSheet(theme.stylesheet("light"))
        light_color = QColor(leaked_lbl.palette().color(QPalette.WindowText)).name().upper()

    assert light_fill == QColor(theme.LIGHT["danger_soft"]).name().upper()
    assert dark_fill == QColor(theme.DARK["danger_soft"]).name().upper()
    assert light_color == QColor(theme.LIGHT["danger"]).name().upper()
    assert dark_color == QColor(theme.DARK["danger"]).name().upper()

    banner.deleteLater()
    wrap.close()


def test_settings_keeps_recycle_auto_cleanup_without_maintenance_actions():
    source = inspect.getsource(SettingsPage.__init__)
    auto_save = inspect.getsource(SettingsPage._connect_auto_save)
    save_all = inspect.getsource(SettingsPage._save_all)
    assert '"回收站自动清理"' in source
    assert "config.DEFAULT_RECYCLE_BIN_RETENTION_DAYS" in source
    assert '(self.recycle_days, "recycle_bin_retention_days")' in auto_save
    assert "self._flush_config_saves()" in save_all
    assert "self._window.reload()" not in save_all
    assert "数据库清理/压缩" not in source
    assert "重复条目对比" not in source
    assert "相同服务处理" not in source


def test_allowing_screen_capture_requires_password_and_warning(monkeypatch):
    app = QApplication.instance() or QApplication([])
    checkbox = __import__("PySide6.QtWidgets", fromlist=["QCheckBox"]).QCheckBox()
    saved = []
    page = SimpleNamespace(
        allow_capture=checkbox,
        _require_master=lambda *args, **kwargs: None,
        _queue_config_save=lambda key, value: saved.append((key, value)),
    )
    SettingsPage._on_allow_capture_toggled(page, True)
    assert not checkbox.isChecked()
    assert saved == []

    page._require_master = lambda *args, **kwargs: "verified"
    monkeypatch.setattr("ui.settings_page.widgets.confirm", lambda *args, **kwargs: False)
    checkbox.setChecked(True)
    SettingsPage._on_allow_capture_toggled(page, True)
    assert not checkbox.isChecked()
    assert saved == []

    monkeypatch.setattr("ui.settings_page.widgets.confirm", lambda *args, **kwargs: True)
    SettingsPage._on_allow_capture_toggled(page, True)
    assert saved == [("screen_capture_allowed", True)]
    checkbox.deleteLater()


def test_copy_button_is_icon_only_and_temporarily_switches_to_success():
    app = QApplication.instance() or QApplication([])
    button = app_ui.widgets.icon_only_button("copy", "复制")
    original_icon = button.icon().cacheKey()
    original_size = button.iconSize()

    assert button.text() == ""
    assert button.accessibleName() == "复制"
    app_ui.widgets.flash_copy_success(button, duration_ms=0)
    assert button.text() == ""
    assert button.accessibleName() == "已复制"
    assert button.icon().cacheKey() != original_icon
    assert button.iconSize() == original_size

    app.processEvents()
    assert button.text() == ""
    assert button.accessibleName() == "复制"
    assert button.icon().cacheKey() == original_icon
    assert button.iconSize() == original_size
    button.deleteLater()


def test_copy_success_icon_matches_copy_icon_style():
    root = Path(__file__).resolve().parents[1]
    copy_svg = (root / "ui" / "assets" / "ui-icons" / "copy.svg").read_text(encoding="utf-8")
    success_svg = (root / "ui" / "assets" / "ui-icons" / "success.svg").read_text(encoding="utf-8")

    assert "#6B7280" in copy_svg
    assert "#6B7280" in success_svg
    assert "<circle" not in success_svg
    assert "#23B5A5" not in success_svg
    assert "#FFD166" not in success_svg


def test_reveal_eye_buttons_use_transparent_icon_style_without_container():
    stylesheet = app_ui.theme.stylesheet()

    assert "QPushButton#RevealIconBtn" in stylesheet
    assert "QPushButton#RevealIconBtn {\n        background: transparent;" in stylesheet
    assert "QPushButton#RevealIconBtn {\n        background: transparent;\n        border: none;" in stylesheet
    assert "QPushButton#RevealIconBtn:checked {\n        background: transparent;" in stylesheet
    assert 'setObjectName("RevealIconBtn")' in inspect.getsource(MainWindow)
    assert "widgets.add_password_reveal(edit)" in inspect.getsource(dialogs.EntryDialog._secret_field)
    assert "widgets.add_password_reveal(edit)" in inspect.getsource(module_editor.ModuleCard)


def test_copy_buttons_use_same_transparent_docked_feedback_as_reveal_buttons():
    stylesheet = app_ui.theme.stylesheet()

    ghost_default = stylesheet.split("QPushButton#Ghost {", 1)[1].split("QPushButton#Ghost:hover", 1)[0]
    ghost_hover = stylesheet.split("QPushButton#Ghost:hover {", 1)[1].split("QPushButton#Ghost:pressed", 1)[0]
    reveal_hover = stylesheet.split("QPushButton#RevealIconBtn:hover {", 1)[1].split("QPushButton#RevealIconBtn:pressed", 1)[0]

    assert "background: transparent;" in ghost_default
    assert "border: none;" in ghost_default
    assert "border-radius: 6px;" in ghost_default
    assert "background:" in ghost_hover
    assert ghost_hover.split("background:", 1)[1].split(";", 1)[0].strip() == (
        reveal_hover.split("background:", 1)[1].split(";", 1)[0].strip()
    )


def test_detail_image_card_copy_action_keeps_text_label():
    app = QApplication.instance() or QApplication([])
    pixmap = QPixmap(1, 1)
    pixmap.fill(Qt.black)
    card = app_ui._DetailImgCard("not-real-image")
    card._px = pixmap

    assert card._copy_btn.text() == "复制"
    assert card._copy_btn.accessibleName() == "复制图片"
    assert card._copy_btn.icon().isNull()
    card._flash_copy_text(duration_ms=0)
    assert card._copy_btn.text() == "已复制"
    app.processEvents()
    assert card._copy_btn.text() == "复制"
    card.deleteLater()
    app.processEvents()


def test_detail_image_copy_clear_timer_uses_python_callback_not_qt_dynamic_method():
    source = inspect.getsource(app_ui._DetailImgCard._do_copy)

    assert "QGuiApplication.clipboard().clear" not in source
    assert "lambda: _clipboard.clear_image_if_present()" in source


def test_dialog_close_buttons_are_neutral_until_hovered():
    stylesheet = app_ui.theme.stylesheet()
    source = inspect.getsource(app_ui.widgets._WindowControlButton.paintEvent)
    theme_source = inspect.getsource(app_ui.theme.stylesheet)

    win_default = stylesheet.split("QPushButton#WinBtn, QPushButton#WinClose {", 1)[1].split("QWidget#Sidebar", 1)[0]
    img_default = stylesheet.split("QPushButton#ImgClose {", 1)[1].split("QPushButton#ImgClose:hover", 1)[0]
    settings_default = stylesheet.split("QPushButton#SettingsClose {", 1)[1].split("QPushButton#SettingsClose:hover", 1)[0]

    assert "background: transparent;" in win_default
    assert "border: none;" in win_default
    assert "danger" not in win_default
    assert "white" not in win_default
    assert "background:" in win_default
    assert "background: #FFFFFF" not in win_default
    assert "background: transparent;" in img_default
    assert "border: none;" in img_default
    assert "danger" not in img_default
    assert "background: white" not in img_default
    assert "background: #FFFFFF" not in img_default
    assert "background: transparent;" in settings_default
    assert "border: none;" in settings_default
    assert "danger" not in settings_default
    assert "white" not in settings_default
    assert "background: #FFFFFF" not in settings_default
    assert 'if self._kind == "close" and hovered:' in source
    assert 'background = QColor(colors["danger_soft"])' in source
    assert "if self.isEnabled() and (hovered or pressed):" in source
    assert "background = QColor(Qt.transparent)" in source
    assert "QPushButton#WinClose:hover" not in theme_source
    assert "QPushButton#WinClose:pressed" not in theme_source


def test_auxiliary_dialogs_use_common_neutral_close_control():
    app = QApplication.instance() or QApplication([])
    dialogs_to_check = [
        app_ui.widgets.ShadowDialog("通用弹窗"),
        app_ui.widgets.ShadowDialog("图片预览"),
    ]
    try:
        for dialog in dialogs_to_check:
            close_button = dialog.title_bar._buttons._close
            assert isinstance(close_button, app_ui.widgets._WindowControlButton)
            assert close_button.objectName() == "WinClose"
            assert close_button._kind == "close"
            assert close_button.icon().isNull()
            assert close_button.text() == ""
            assert close_button.styleSheet() == ""
    finally:
        for dialog in dialogs_to_check:
            dialog.close()
            dialog.deleteLater()
            app.processEvents()


def test_settings_is_embedded_workspace_page_not_a_dialog():
    app = QApplication.instance() or QApplication([])
    window = SimpleNamespace(
        vault=SimpleNamespace(path=Path("vault.pmv"), recovery_key_info=("", 0), key_revision=1),
        _native_hotkey_registered=False,
        cloud_sync_enabled=lambda: False,
        set_cloud_sync_enabled=lambda _enabled: None,
        apply_theme=lambda _dark: None,
        apply_lock_settings=lambda: None,
        apply_privacy_settings=lambda: None,
        apply_native_autofill_settings=lambda: None,
        reload=lambda: None,
        open_vault_folder=lambda: None,
    )
    page = SettingsPage(window)
    try:
        assert not isinstance(page, QDialog)
        assert page.objectName() != "Dialog"
    finally:
        page.close()
        page.deleteLater()
        app.processEvents()


def test_cloud_sync_auth_dropdown_requires_click_before_wheel_scroll():
    source = inspect.getsource(CloudSyncWorkspacePage._build_cloud_ui)

    assert "auth_mode = _NoScrollComboBox()" in source
    assert "auth_mode = QComboBox()" not in source


def test_cloud_panel_keeps_actions_above_auto_sync():
    source = inspect.getsource(CloudSyncPage._build_target)

    assert source.index("layout.addWidget(more)") < source.index("auto_anchor = QWidget()")


def test_image_viewer_uses_custom_window_chrome_without_duplicate_close_button():
    source = inspect.getsource(dialogs.show_image_viewer)

    assert 'widgets.ShadowDialog("图片预览"' in source
    assert "QDialog(parent, Qt.Dialog | Qt.FramelessWindowHint)" not in source
    assert 'QPushButton("关闭")' not in source
    assert 'QPushButton("复原")' in source
    assert "dlg.body.addWidget(canvas, 1)" in source


def test_reorder_mode_hides_sidebar_create_controls_and_restores_them():
    QApplication.instance() or QApplication([])
    sidebar = QWidget()
    layout = QVBoxLayout(sidebar)
    separator = QWidget()
    create = QWidget()
    add = QPushButton("新建条目", create)
    layout.addStretch()
    layout.addWidget(separator)
    layout.addWidget(create)
    sidebar.show()
    original_width = sidebar.width()
    original_limits = (sidebar.minimumWidth(), sidebar.maximumWidth())
    host = SimpleNamespace(
        _reorder_active=False, _sidebar_widget=sidebar, _sidebar_lay=layout,
        _sidebar_separator=separator, _sidebar_create_section=create,
        _get_type_order=lambda: [SecretType.LOGIN],
        _rebuild_reorder_chips=lambda: None, _rebuild_type_chips=lambda: None,
    )
    MainWindow._enter_reorder_mode(host)
    sidebar.adjustSize()
    assert sidebar.width() == original_width
    assert sidebar.minimumWidth() == sidebar.maximumWidth() == original_width
    assert not create.isVisible() and not separator.isVisible()
    assert not add.isVisible()
    MainWindow._exit_reorder_mode(host)
    assert (sidebar.minimumWidth(), sidebar.maximumWidth()) == original_limits
    assert create.isVisible() and separator.isVisible() and add.isVisible()
    sidebar.close()


def test_edit_page_renders_each_autofill_link_with_independent_remove():
    """编辑页逐条展示关联填充内容，每条可独立删除（对齐 Android autofillLinks.forEach）。"""
    import tempfile
    from pathlib import Path
    from types import SimpleNamespace

    from PySide6.QtWidgets import QLabel, QPushButton, QWidget

    from core import autofill_sources as afs
    from core.models import Entry, SecretType
    from core.storage import Vault
    from ui.dialogs import EntryDialog

    app = QApplication.instance() or QApplication([])

    directory = Path(tempfile.mkdtemp())
    vault = Vault.create(directory / "links.pmv", "TestMaster123!")
    otp = Entry(
        title="邮箱验证码",
        secret_type=SecretType.OTP,
        fields={"label": "mail", "issuer": "Ex", "secret": "JBSWY3DPEHPK3PXP"},
    )
    wifi = Entry(title="公司WiFi", secret_type=SecretType.WIFI, fields={"ssid": "Corp", "wifi_password": "x"})
    vault.add(otp)
    vault.add(wifi)
    login = Entry(
        title="Example 登录",
        secret_type=SecretType.LOGIN,
        username="u",
        password="p",
        url="https://e.com",
    )
    login.fields = afs.encode_links_into_fields(
        dict(login.fields),
        [
            afs.AutofillLink(
                id="L1",
                source_entry_id=otp.id,
                fields=(
                    afs.AutofillFieldRef(None, "secret", "one_time_code", False),
                    afs.AutofillFieldRef(None, "label", "username", False),
                ),
            ),
            afs.AutofillLink(
                id="L2",
                source_entry_id=wifi.id,
                fields=(afs.AutofillFieldRef(None, "ssid", "custom_text", False),),
            ),
        ],
    )
    vault.add(login)
    vault.save()

    opened = Vault.open(directory / "links.pmv", "TestMaster123!")
    parent = QWidget()
    parent.vault = opened
    dialog = EntryDialog(entry=opened.read_entry(login.id), parent=parent)
    dialog.show()
    app.processEvents()

    page = dialog._pages[0]
    layout = page.autofill_link_lay

    def chips():
        found = []
        for index in range(layout.count()):
            widget = layout.itemAt(index).widget()
            if widget is not None and widget.objectName() == "AutofillLinkChip":
                found.append(widget)
        return found

    rendered = chips()
    assert len(rendered) == 2
    labels = [
        [label.text() for label in chip.findChildren(QLabel) if label.text()]
        for chip in rendered
    ]
    # 顺序与 links 一致，且文案为「来源标题 · 角色」
    assert any("邮箱验证码" in text and "动态码" in text for text in labels[0])
    assert any("公司WiFi" in text and "自定义文本" in text for text in labels[1])
    # 添加按钮始终保留在流式布局首位
    assert layout.itemAt(0).widget() is page.autofill_button

    # 独立删除第一条，不影响第二条
    rendered[0].findChildren(QPushButton)[0].click()
    app.processEvents()
    app.processEvents()

    assert [link.id for link in page.autofill_links] == ["L2"]
    assert len(chips()) == 1
    assert page.autofill_button.text()

    dialog.close()


def test_login_windows_reserve_biometric_row_and_inline_error():
    """登录窗口：生物识别行始终占位、错误提示并入副标题、密码框内嵌小眼睛。"""
    import ui.dialogs as D

    app = QApplication.instance() or QApplication([])

    def force_hello(cls, method):
        def patched(self, *args, **kwargs):
            self._hello_ok = True
            self.hello_btn.setEnabled(True)
            self.hello_btn.setVisible(True)
        original = getattr(cls, method)
        setattr(cls, method, patched)
        return original

    # 两个窗口的 WinRT 探测方法名不同
    cases = [
        ("RelockDialog", "_check_hello", lambda: D.RelockDialog("someuser", lambda **kwargs: True)),
        ("UnlockDialog", "_load_hello_availability", lambda: D.UnlockDialog()),
    ]
    for name, method, make in cases:
        original = force_hello(getattr(D, name), method)
        dialog = make()
        dialog.show()
        app.processEvents()
        app.processEvents()

        # 生物识别行始终占位（可用性在 showEvent 之后才确定）
        assert dialog.hello_btn.height() > 0
        baseline = dialog.height()
        default_sub = dialog.sub_label.text()

        # 错误提示并入副标题并标红，窗口尺寸不变
        dialog.warn("主密码不正确")
        app.processEvents()
        app.processEvents()
        assert "主密码不正确" in dialog.sub_label.text()
        assert dialog.sub_label.objectName() == "FieldError"
        assert dialog.height() == baseline

        # 提示清除后副标题恢复默认文案
        dialog._set_hint("")
        app.processEvents()
        assert dialog.sub_label.text() == default_sub
        assert dialog.sub_label.objectName() == "Empty"
        assert dialog.height() == baseline

        # 密码框小眼睛内嵌：作为 trailing action 挂在输入框上
        from PySide6.QtWidgets import QLineEdit

        assert dialog.pw.echoMode() == QLineEdit.Password
        actions = dialog.pw.actions()
        assert actions, "密码框缺少小眼睛切换"
        assert actions[0].isCheckable()
        actions[0].setChecked(True)
        app.processEvents()
        assert dialog.pw.echoMode() == QLineEdit.Normal

        dialog.close()
        setattr(getattr(D, name), method, original)


def test_unlock_user_picker_needs_multiple_users_and_biometric_matches_unlock(monkeypatch):
    from core import config
    from ui import dialogs

    QApplication.instance() or QApplication([])
    users = [{"name": "Alice", "file": "alice.pmv"}]
    monkeypatch.setattr(config, "list_users", lambda: list(users))
    monkeypatch.setattr(config, "get_current_user", lambda: "Alice")
    monkeypatch.setattr(dialogs, "_supports_recovery_unlock", lambda _path: False)
    dialog = dialogs.UnlockDialog()
    try:
        assert not dialog.user_combo.isEnabled()
        assert "down-arrow { image: none" in dialog.user_combo.styleSheet()
        assert dialog.hello_btn.height() == dialog.btn.height()
        users.append({"name": "Bob", "file": "bob.pmv"})
        dialog._reload_users(select="Alice")
        assert dialog.user_combo.isEnabled()
        assert dialog.user_combo.styleSheet() == ""
    finally:
        dialog.close()


def test_empty_detail_message_is_vertically_centred():
    """条目详情页空状态文案在视口内垂直居中（切换条目后能还原为顶部排布）。"""
    import tempfile
    from pathlib import Path

    from PySide6.QtWidgets import QLabel, QSizePolicy

    from core.models import Entry, SecretType
    from core.storage import Vault
    from ui.app import MainWindow

    app = QApplication.instance() or QApplication([])

    directory = Path(tempfile.mkdtemp())
    created = Vault.create(directory / "empty.pmv", "TestMaster123!")
    created.add(Entry(
        title="测试条目",
        secret_type=SecretType.LOGIN,
        username="u",
        password="p",
        url="https://e.com",
    ))
    created.save()
    vault = Vault.open(directory / "empty.pmv", "TestMaster123!")

    window = MainWindow(vault)
    window.resize(1280, 760)
    window.show()
    app.processEvents()
    app.processEvents()

    def empty_label():
        # 条目详情里的「创建时间 / 最后修改」也用 #Empty，按文案特征排除。
        for index in range(window.detail.count()):
            widget = window.detail.itemAt(index).widget()
            if not isinstance(widget, QLabel) or widget.objectName() != "Empty":
                continue
            if "选择一个条目" in widget.text() or "暂无通行密钥" in widget.text():
                return widget
        return None

    def centre_offset():
        label = empty_label()
        if label is None:
            return None
        viewport = window.detail_scroll.viewport()
        return label.mapToGlobal(label.rect().center()).y() - viewport.mapToGlobal(
            viewport.rect().center()
        ).y()

    window._show_empty()
    app.processEvents()
    assert centre_offset() == 0
    assert window.detail_card.sizePolicy().verticalPolicy() == QSizePolicy.Policy.Expanding

    window._show_entry(vault.entries[0])
    app.processEvents()
    assert empty_label() is None
    assert window.detail_card.sizePolicy().verticalPolicy() == QSizePolicy.Policy.Maximum

    # 再次进入空状态仍应居中
    window._show_empty()
    app.processEvents()
    assert centre_offset() == 0

    window.close()


def test_sidebar_bottom_safe_margin_applies_to_separator_and_add_button():
    """侧边栏底部的分隔线与「＋ 新增条目」按钮共用同一底部安全距离。"""
    import tempfile
    from pathlib import Path

    from core.storage import Vault
    from ui.app import MainWindow, SIDEBAR_BOTTOM_SAFE_MARGIN

    app = QApplication.instance() or QApplication([])
    assert SIDEBAR_BOTTOM_SAFE_MARGIN == 20

    vault = Vault.create(Path(tempfile.mkdtemp()) / "sidebar.pmv", "TestMaster123!")
    window = MainWindow(vault)
    window.resize(1280, 760)
    window.show()
    app.processEvents()
    app.processEvents()

    def global_bottom(widget) -> int:
        return widget.mapToGlobal(widget.rect().topLeft()).y() + widget.height()

    sidebar = window._sidebar_widget
    add_button = window._add_btn
    separator = window._sidebar_separator

    # 按钮底距侧边栏底恰为安全距离；分隔线在该组之上，不贴窗口下沿。
    assert global_bottom(sidebar) - global_bottom(add_button) == SIDEBAR_BOTTOM_SAFE_MARGIN
    assert global_bottom(separator) <= global_bottom(add_button)
    assert global_bottom(sidebar) - global_bottom(separator) > SIDEBAR_BOTTOM_SAFE_MARGIN

    window.close()


def test_detail_page_lists_linked_autofill_sources():
    """详情页展示「关联自动填充内容」，对齐 Android 的 linkedAutofillDetailGroups。"""
    import tempfile
    from pathlib import Path

    from core import autofill_sources as afs
    from core.storage import Vault
    from core.models import Entry, SecretType
    from ui.app import MainWindow, linked_autofill_detail_groups

    app = QApplication.instance() or QApplication([])

    vault = Vault.create(Path(tempfile.mkdtemp()) / "links.pmv", "TestMaster123!")
    otp = Entry(
        title="邮箱验证码",
        secret_type=SecretType.OTP,
        fields={"label": "mail", "issuer": "Example", "secret": "JBSWY3DPEHPK3PXP"},
    )
    vault.add(otp)
    consumer = Entry(
        title="Example 登录",
        secret_type=SecretType.LOGIN,
        username="u",
        url="https://example.com",
    )
    # 同一来源的两个 link：详情页应合并为一组，角色去重后按顺序展示。
    consumer.fields = afs.encode_links_into_fields(
        dict(consumer.fields),
        [
            afs.AutofillLink(
                id="L1",
                source_entry_id=otp.id,
                fields=(afs.AutofillFieldRef(None, "secret", "one_time_code", False),),
            ),
            afs.AutofillLink(
                id="L2",
                source_entry_id=otp.id,
                fields=(afs.AutofillFieldRef(None, "username", "username", False),),
            ),
        ],
    )
    vault.add(consumer)
    vault.save()
    entry = vault.read_entry(consumer.id)

    groups = linked_autofill_detail_groups(entry, vault.entries)
    assert len(groups) == 1
    assert groups[0].source_entry_id == otp.id
    assert groups[0].source is not None and groups[0].source.title == "邮箱验证码"
    assert groups[0].roles == ["one_time_code", "username"]

    window = MainWindow(vault)
    window.resize(1280, 760)
    window.show()
    app.processEvents()
    window._show_entry(entry)
    app.processEvents()
    app.processEvents()

    section_titles = []
    cards = []
    for index in range(window.detail.count()):
        widget = window.detail.itemAt(index).widget()
        if widget is None:
            continue
        if isinstance(widget, QLabel) and widget.text():
            section_titles.append(widget.text())
        if widget.objectName() == "LinkedAutofillCard":
            cards.append([label.text() for label in widget.findChildren(QLabel) if label.text()])

    assert "关联自动填充内容" in section_titles
    assert len(cards) == 1
    assert any("邮箱验证码" in text for text in cards[0])
    # 副标题呈现「类目 · 角色」，与 Android 的 sourceCategory · roleLabels 一致
    assert any("动态码" in text and "一次性验证码" in text for text in cards[0])

    window.close()


def test_detail_associated_app_stacks_label_above_value_instead_of_same_row():
    """关联程序 / 包名与用户名、密码一致：标题一行、内容一行，长包名换行而非右对齐裁切。"""
    import tempfile
    from pathlib import Path

    from core import modules
    from core.storage import Vault
    from core.models import Entry, SecretType
    from ui.app import MainWindow

    app = QApplication.instance() or QApplication([])
    package = "com.example.android.application.some.very.long.package.name"
    vault = Vault.create(Path(tempfile.mkdtemp()) / "app.pmv", "TestMaster123!")
    vault.add(
        Entry(
            title="示例登录",
            secret_type=SecretType.LOGIN,
            username="user@example.com",
            fields={
                modules.MODULES_KEY: [
                    {
                        "id": "m1",
                        "type": modules.TARGET_APP,
                        "title": "关联程序",
                        "value": package,
                    }
                ]
            },
        )
    )
    entry = vault.read_entry(vault.entries[0].id)

    window = MainWindow(vault)
    window.resize(900, 700)
    window.show()
    app.processEvents()
    window._show_entry(entry)
    for _ in range(3):
        app.processEvents()

    row = None
    for index in range(window.detail.count()):
        widget = window.detail.itemAt(index).widget()
        if widget is None:
            continue
        labels = widget.findChildren(QLabel)
        if any(label.objectName() == "FieldLabel" and label.text() == "关联程序 / 包名" for label in labels):
            row = (widget, labels)
            break
    assert row is not None, "详情页应展示「关联程序 / 包名」"
    widget, labels = row
    title = next(label for label in labels if label.objectName() == "FieldLabel")
    value = next(label for label in labels if label is not title and label.text())
    # 标题在上、内容在下：不是同一行的左右并排。
    assert value.y() > title.y()
    assert value.text() == package
    assert value.wordWrap()
    # 不再是右对齐的 Tag 胶囊，也不再把整行撑到包名那么宽。
    assert value.objectName() != "Tag"
    # 行的最小宽度不再由包名的自然像素宽度撑开（此前 852px 的 Tag 会把整行撑爆）。
    natural = QFontMetrics(value.font()).horizontalAdvance(package)
    assert natural > 200
    assert widget.minimumSizeHint().width() < natural

    window.close()


def test_detail_status_badges_move_leak_and_expiry_into_title_card():
    """泄露与到期徽章渲染在标题卡内部，对齐 Android 的 BadgeChip 位置。"""
    import tempfile
    from pathlib import Path

    from core.storage import Vault
    from core.models import Entry, SecretType
    from ui.app import MainWindow, detail_status_badges

    app = QApplication.instance() or QApplication([])

    vault = Vault.create(Path(tempfile.mkdtemp()) / "badges.pmv", "TestMaster123!")
    entry = Entry(
        title="过期且泄露的卡",
        secret_type=SecretType.CARD_DOCUMENT,
        username="4111111111111111",
        fields={"expiry": "12/20", "cardholder": "USER"},
    )
    vault.add(entry)
    vault.save()
    stored = vault.read_entry(entry.id)
    # 泄露缓存的 revision 必须等于 updated_at，否则 has_current_check 判为无缓存
    stored.leak_check_revision = stored.updated_at
    stored.leak_pwned_count = 7
    stored.leak_checked_at = stored.updated_at

    badges = detail_status_badges(stored, SecretType.CARD_DOCUMENT)
    assert any("已泄露 7 次" in text for text, _ in badges)
    assert any("已过期" in text for text, _ in badges)
    assert {state for _, state in badges} == {"danger"}

    window = MainWindow(vault)
    window.resize(1280, 760)
    window.show()
    app.processEvents()
    window._show_entry(stored)
    app.processEvents()
    app.processEvents()

    title_card = None
    outside = []
    for index in range(window.detail.count()):
        widget = window.detail.itemAt(index).widget()
        if widget is None:
            continue
        if widget.objectName() == "DetailTitleCard":
            title_card = widget
        elif widget.objectName() in ("ModuleCard", "EntryExpiryBanner"):
            outside.append(widget.objectName())

    assert title_card is not None
    chips = [
        label
        for label in title_card.findChildren(QLabel)
        if label.objectName() == "DetailStatusChip"
    ]
    assert len(chips) == 2
    assert all("已" in chip.text() for chip in chips)
    # 卡外不再重复渲染
    assert outside == []

    window.close()


def test_image_gallery_delete_close_is_hidden_and_neutral_until_hover(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(dialogs._ImageCard, "_set_pixmap", lambda _self, _value: None)

    card = dialogs._ImageCard("invalid")
    close_button = card.findChild(QPushButton, "ImgClose")
    stylesheet = dialogs.theme.stylesheet()
    img_default = stylesheet.split("QPushButton#ImgClose {", 1)[1].split("QPushButton#ImgClose:hover", 1)[0]

    assert close_button is not None
    assert not close_button.isVisible()
    assert close_button.text() == "×"
    assert close_button.icon().isNull()
    assert close_button.styleSheet() == ""
    assert "background: transparent;" in img_default
    assert "border: none;" in img_default
    assert "danger" not in img_default
    card.deleteLater()
    app.processEvents()



def test_more_menu_entries_have_english_copy():
    """“更多功能”菜单的两级条目在英文界面下必须有对应文案。"""
    i18n.set_locale("en")
    try:
        for source in ("更多功能", "同步", "库维护", "导入导出", "重复条目合并", "相同服务合并"):
            assert i18n.tr(source) != source, f"en is missing: {source}"
    finally:
        i18n.set_locale("zh-Hans")



def test_privacy_initialization_does_not_create_a_native_window_before_first_show(monkeypatch):
    capture_guard_calls = []
    window = SimpleNamespace(
        isVisible=lambda: False,
        _schedule_leak_audit=lambda: None,
    )
    monkeypatch.setattr(app_ui.widgets, "apply_capture_permission", capture_guard_calls.append)

    MainWindow.apply_privacy_settings(window)

    assert capture_guard_calls == []


def test_background_hide_setting_only_applies_to_close_button():
    assert app_ui.config.DEFAULT_BACKGROUND_HIDE is False
    source = inspect.getsource(MainWindow.eventFilter)
    # 点击外部区域或右键托盘不再隐藏窗口，只有关闭按钮触发托盘隐藏。
    assert "QEvent.ApplicationDeactivate" not in source
    assert "background_hide" not in source


def test_main_window_close_hides_to_tray_and_locks_when_enabled(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(
        app_ui.config,
        "get",
        lambda key, default=None: True if key == "background_hide" else default,
    )
    calls = {"locked": 0, "unregistered": 0}
    win = MainWindow.__new__(MainWindow)
    win._maintenance_worker = None
    win._unregister_native_autofill_hotkey = lambda: calls.__setitem__(
        "unregistered", calls["unregistered"] + 1
    )
    tray = SimpleNamespace(isVisible=lambda: True)
    setattr(win, "_tray", tray)
    setattr(win, "_enter_locked_state", lambda reason: calls.__setitem__("locked", 1))

    event = QCloseEvent()
    MainWindow.closeEvent(win, event)

    assert not event.isAccepted()  # 关闭被拦截，程序不退出
    assert calls["locked"] == 1  # 退托盘时自动锁定
    assert calls["unregistered"] == 0  # 后台运行，不注销自动填充热键


def test_main_window_close_falls_back_to_minimize_without_tray(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(
        app_ui.config,
        "get",
        lambda key, default=None: True if key == "background_hide" else default,
    )
    calls = {"minimized": 0}
    win = MainWindow.__new__(MainWindow)
    win._maintenance_worker = None
    setattr(win, "_tray", None)
    setattr(win, "_unregister_native_autofill_hotkey", lambda: None)
    setattr(win, "showMinimized", lambda: calls.__setitem__("minimized", calls["minimized"] + 1))

    event = QCloseEvent()
    MainWindow.closeEvent(win, event)

    assert not event.isAccepted()
    assert calls["minimized"] == 1  # 无托盘时退回任务栏最小化，保证窗口可恢复


def test_main_window_close_falls_back_to_quitting_when_background_hide_off():
    source = inspect.getsource(MainWindow.closeEvent)
    assert "self._unregister_native_autofill_hotkey()" in source
    assert "super().closeEvent(event)" in source


def test_main_window_tray_reuses_shared_open_and_quit_menu():
    source = inspect.getsource(MainWindow._setup_tray)
    assert "app_tray.setup_tray(" in source
    assert "self._show_from_tray," in source
    assert "self._tray = shared" in source
    # 主窗口在共享托盘上补充实用操作
    assert 'i18n.tr("立即锁定")' in source
    assert 'i18n.tr("清空剪贴板")' in source
    assert 'i18n.tr("建立传输站")' in source
    # 共享托盘基础菜单为“打开保险库 / 退出程序”
    import ui.tray as app_tray_mod

    tray_source = inspect.getsource(app_tray_mod.setup_tray)
    assert 'i18n.tr("打开保险库")' in tray_source
    assert 'i18n.tr("退出程序")' in tray_source
    assert "extra_actions" in tray_source


def test_tray_double_click_activation_is_debounced():
    import ui.tray as app_tray_mod

    _app = QApplication.instance() or QApplication([])
    calls = []
    app_tray_mod.set_open_callback(lambda: calls.append(True))
    app_tray_mod._last_activation = 0.0
    reason = app_tray_mod.QSystemTrayIcon.ActivationReason
    # Windows 双击会连发 Trigger + DoubleClick，只应触发一次打开
    app_tray_mod._handle_activated(reason.Trigger)
    app_tray_mod._handle_activated(reason.DoubleClick)
    assert len(calls) == 1


def test_relock_prompt_guards_against_duplicate_dialogs():
    source = inspect.getsource(MainWindow._relock_prompt)
    assert "self._relock_prompt_open" in source
    assert "finally:" in source


def test_tray_clear_clipboard_clears_system_clipboard():
    from PySide6.QtGui import QGuiApplication

    _app = QApplication.instance() or QApplication([])
    QGuiApplication.clipboard().setText("sensitive-secret")
    win = MainWindow.__new__(MainWindow)
    MainWindow._clear_clipboard_now(win)
    assert QGuiApplication.clipboard().text() == ""


def test_show_from_tray_prompts_unlock_when_locked():
    calls = {"prompted": 0}
    win = MainWindow.__new__(MainWindow)
    win._locked = True
    setattr(win, "_relock_prompt", lambda reason: calls.__setitem__("prompted", 1))
    MainWindow._show_from_tray(win)
    assert calls["prompted"] == 1


def test_main_window_autofill_flow_skips_excluded_foreground_app(monkeypatch):
    app = QApplication.instance() or QApplication([])
    excluded = {"chrome.exe"}
    monkeypatch.setattr(
        app_ui.config,
        "get",
        lambda key, default=None: excluded if key == "native_autofill_excluded" else default,
    )
    calls = {"fill": 0}
    prepared = SimpleNamespace(
        target=SimpleNamespace(process_id=999, process_name="chrome.exe"),
        fields=(),
    )
    win = MainWindow.__new__(MainWindow)
    setattr(win, "_native_autofill_prepared", prepared)
    setattr(win, "_locked", False)
    setattr(win, "vault", SimpleNamespace(entries=[]))
    setattr(win, "_native_autofill_backend", SimpleNamespace(fill=lambda *_: calls.__setitem__("fill", 1)))
    setattr(win, "_native_autofill_busy", True)
    setattr(win, "_flash", lambda _text: None)
    setattr(win, "_native_autofill_failed", lambda _msg: None)

    MainWindow._complete_native_autofill(win)

    assert calls["fill"] == 0  # 被排除程序静默跳过，与安卓端“不显示建议”一致


def test_native_autofill_unlock_keeps_main_window_hidden(monkeypatch):
    QApplication.instance() or QApplication([])
    calls = {"shown": 0, "media": 0, "reset": 0, "dialog": None}

    class FakeRelockDialog:
        unlocked = True

        def __init__(self, *args, **kwargs):
            calls["dialog"] = kwargs

        def exec(self):
            return QDialog.Accepted

    monkeypatch.setattr(app_ui, "RelockDialog", FakeRelockDialog)
    monkeypatch.setattr(app_ui.config, "get_current_user", lambda: "FAE")
    monkeypatch.setattr(
        app_ui.media_files,
        "ensure_vault_context",
        lambda _vault: calls.__setitem__("media", calls["media"] + 1),
    )
    win = MainWindow.__new__(MainWindow)
    win._locked = True
    win._native_autofill_unlock_open = False
    win.vault = SimpleNamespace(
        verify_password=lambda _password: True,
        device_unlock_key_format="pmve-root-key",
        pmve_identity=SimpleNamespace(vault_id="vault"),
    )
    win.show = lambda: calls.__setitem__("shown", calls["shown"] + 1)
    win._reset_idle_timer = lambda: calls.__setitem__("reset", calls["reset"] + 1)
    win._run_auto_maintenance = lambda: None
    prepared = SimpleNamespace(target=SimpleNamespace(process_name="example.exe"))

    assert MainWindow._unlock_for_native_autofill(win, prepared)
    assert not win._locked
    assert calls["shown"] == 0
    assert calls["media"] == 1
    assert calls["reset"] == 1
    assert calls["dialog"]["auto_hello"] is True
    assert "example.exe" in calls["dialog"]["description"]


def test_relock_dialog_auto_starts_windows_hello(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    vault_path = tmp_path / "fae.pmv"
    identity = SimpleNamespace(vault_id="vault", signing_public_key=b"s" * 32)
    opened = SimpleNamespace(
        device_unlock_key_format="pmve-root-key",
        pmve_identity=identity,
        close=lambda: None,
    )
    calls = []
    monkeypatch.setattr(dialogs.biometric, "available", lambda: True)
    monkeypatch.setattr(dialogs.biometric, "is_enabled", lambda _path: True)
    monkeypatch.setattr(dialogs.biometric, "open_vault", lambda _path: calls.append("hello") or opened)
    monkeypatch.setattr(dialogs.config, "_user_record", lambda _name: {"name": "FAE", "file": "fae.pmv"})
    monkeypatch.setattr(dialogs.config, "user_vault_path", lambda _record: vault_path)
    monkeypatch.setattr(dialogs.config, "get_lockout", lambda _key: (0, True))
    monkeypatch.setattr(dialogs.config, "set_lockout", lambda _key, _value: None)

    dialog = RelockDialog(
        "FAE",
        lambda _password: True,
        expected_pmve_identity=identity,
        auto_hello=True,
    )
    dialog.show()
    app.processEvents()
    app.processEvents()

    assert calls == ["hello"]
    assert dialog.unlocked


def test_native_autofill_exclude_dialog_adds_normalizes_and_removes(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(app_ui.config, "_config_cache", {})
    monkeypatch.setattr(
        app_ui.config,
        "get",
        lambda key, default=None: app_ui.config._config_cache.get(key, default),
    )
    monkeypatch.setattr(
        app_ui.config,
        "set",
        lambda key, value: app_ui.config._config_cache.__setitem__(key, value),
    )

    dlg = dialogs.NativeAutofillExcludeDialog()
    try:
        dlg._input.setText(r'"C:\Program Files\Chrome\Application\CHROME.EXE"')
        dlg._add_from_input()
        assert app_ui.config.get("native_autofill_excluded") == ["chrome.exe"]

        dlg._add("chrome.exe")
        assert app_ui.config.get("native_autofill_excluded") == ["chrome.exe"]  # 去重

        dlg._remove("chrome.exe")
        assert app_ui.config.get("native_autofill_excluded") == []
        assert not dlg._empty.isHidden()  # 清空后显示“暂未排除任何程序”

        dlg._input.setText("https://Login.Example.com/path")
        dlg._add_from_input()
        assert app_ui.config.get("browser_autofill_excluded_hosts") == ["login.example.com"]
        dlg._remove_exclusion("hosts", "login.example.com")
        assert app_ui.config.get("browser_autofill_excluded_hosts") == []
    finally:
        dlg.deleteLater()


def test_login_editor_links_external_otp_through_general_autofill_source_picker() -> None:
    app = QApplication.instance() or QApplication([])
    otp_module = modules.new_module(modules.OTP)
    otp_module["value"].update(secret="JBSWY3DPEHPK3PXP", issuer="External")
    source = Entry(
        title="External code",
        secret_type=SecretType.OTP,
        fields=modules.fields_with_modules({}, [otp_module]),
    )

    class _Vault:
        entries = [source]

        def list_entry_ids(self, secret_type):
            return (source.id,) if secret_type == SecretType.OTP else ()

        def read_entry(self, entry_id):
            return source if entry_id == source.id else None

    parent = QWidget()
    parent.vault = _Vault()
    login = Entry(title="Login", username="alice", password="secret")
    dlg = dialogs.EntryDialog(login, parent)
    try:
        page = dlg.stacked.currentWidget()
        candidate = next(value for value in dialogs.source_values(source) if value.role == "one_time_code")
        dlg._choose_autofill_source(page, source, candidate)
        dlg.accept()
        links = dlg.entry.autofill_links()
        assert [(link.source_entry_id, link.fields[0].role) for link in links] == [
            (source.id, "one_time_code"),
        ]
        assert "bound_otp_id" not in dlg.entry.fields
    finally:
        dlg.deleteLater()
        parent.deleteLater()


def test_capture_setting_uses_allow_semantics(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(app_ui.config, "_config_path", lambda: tmp_path / "config.json")
    monkeypatch.setattr(app_ui.config, "_config_integrity_failed", False)
    monkeypatch.setattr(dialogs.screen_capture, "supported", lambda: True)
    monkeypatch.setattr(app_ui.config, "_config_cache", {"screen_capture_protect": True})
    window = SimpleNamespace(
        vault=SimpleNamespace(path=Path("sample.pmv"), recovery_key_info=("ABC", time.time()), key_revision=1),
        _native_hotkey_registered=False,
        apply_theme=lambda _dark: None,
        apply_lock_settings=lambda: None,
        apply_privacy_settings=lambda: None,
        apply_native_autofill_settings=lambda: None,
        cloud_sync_enabled=lambda: False,
        set_cloud_sync_enabled=lambda _enabled: None,
        reload=lambda: None,
        open_vault_folder=lambda: None,
        hide=lambda: None,
        dedup_entries=lambda: None,
        merge_same_service_entries=lambda: None,
    )
    dialog = SettingsPage(window)
    try:
        monkeypatch.setattr(dialog, "_require_master", lambda *_args, **_kwargs: object())
        monkeypatch.setattr(ui_widgets, "confirm", lambda *_args, **_kwargs: True)
        assert dialog.allow_capture.text() == "允许截屏"
        assert dialog.allow_capture.isChecked() is False
        dialog.allow_capture.setChecked(True)
        assert app_ui.config.screen_capture_allowed() is True
        dialog.allow_capture.setChecked(False)
        assert app_ui.config.screen_capture_allowed() is False
    finally:
        dialog._config_save_timer.stop()
        dialog._pending_config_saves.clear()
        dialog.deleteLater()


def test_screen_capture_permission_blocks_by_default_and_keeps_explicit_choices(monkeypatch):
    # 全新安装两个键都不存在：默认禁止截屏。
    monkeypatch.setattr(app_ui.config, "_config_cache", {})
    assert app_ui.config.screen_capture_allowed() is app_ui.config.DEFAULT_SCREEN_CAPTURE_ALLOWED
    assert app_ui.config.screen_capture_allowed() is False
    # 旧的反向键仍按原义解释，且与「键不存在」区分开。
    monkeypatch.setattr(app_ui.config, "_config_cache", {"screen_capture_protect": False})
    assert app_ui.config.screen_capture_allowed() is True
    monkeypatch.setattr(app_ui.config, "_config_cache", {"screen_capture_protect": True})
    assert app_ui.config.screen_capture_allowed() is False
    # 新键优先于旧键。
    monkeypatch.setattr(app_ui.config, "_config_cache", {
        "screen_capture_protect": True,
        "screen_capture_allowed": True,
    })
    assert app_ui.config.screen_capture_allowed() is True


def test_closing_settings_flushes_only_values_changed_on_that_page(monkeypatch):
    calls = []
    monkeypatch.setattr(app_ui.config, "set_many", lambda values: calls.append(values.copy()))
    window = SimpleNamespace(
        apply_lock_settings=lambda: None,
        apply_privacy_settings=lambda: None,
        apply_native_autofill_settings=lambda: None,
    )
    page = SimpleNamespace(
        _config_save_timer=SimpleNamespace(stop=lambda: None),
        _pending_config_saves={"theme_mode": "dark"},
        _window=window,
    )
    page._flush_config_saves = lambda: SettingsPage._flush_config_saves(page)

    SettingsPage._save_all(page)

    assert calls == [{"theme_mode": "dark"}]
    assert page._pending_config_saves == {}


def test_native_autofill_picker_single_click_starts_fill():
    app = QApplication.instance() or QApplication([])
    entry = Entry(title="Epic test", username="test@example.invalid", password="test-only")
    dialog = dialogs.NativeAutofillPickerDialog([entry], "EpicGamesLauncher.exe")
    try:
        item = dialog._list.item(0)
        dialog._list.itemClicked.emit(item)
        assert dialog.result() == QDialog.Accepted
        assert dialog.selected_entry is entry
        assert dialog.action == "fill"
    finally:
        dialog.deleteLater()


def test_native_autofill_picker_manual_mode_requires_explicit_field_choice():
    app = QApplication.instance() or QApplication([])
    entry = Entry(title="Epic test", username="test@example.invalid", password="test-only")
    dialog = dialogs.NativeAutofillPickerDialog([entry], "EpicGamesLauncher.exe", manual_focus=True)
    try:
        dialog._list.itemClicked.emit(dialog._list.item(0))
        assert dialog.result() != QDialog.Accepted
        dialog._choose_manual("username")
        assert dialog.result() == QDialog.Accepted
        assert dialog.selected_entry is entry
        assert dialog.action == "manual_username"
    finally:
        dialog.deleteLater()


def test_first_batch_locales_resolve_system_variants_and_fallbacks():
    assert i18n.resolve_locale("auto", "en_US") == "en"
    assert i18n.resolve_locale("auto", "fr_FR") == "zh-Hans"
    assert i18n.resolve_locale("de", "zh_CN") == "zh-Hans"


def test_language_selector_only_offers_system_chinese_and_english():
    assert i18n.LANGUAGE_OPTIONS == (
        ("跟随系统", "auto"),
        ("简体中文", "zh-Hans"),
        ("English", "en"),
    )


def test_appearance_selector_exposes_three_modes_in_consistent_order():
    source = (Path(__file__).resolve().parents[1] / "ui" / "settings_page.py").read_text(encoding="utf-8")
    expected = (
        '("跟随系统", "auto")',
        '("浅色", "light")',
        '("深色", "dark")',
    )
    positions = [source.index(option) for option in expected]
    assert positions == sorted(positions)
    # “品牌蓝”主题已并入浅色并移除入口
    assert "brand_blue" not in source


def test_theme_consumers_keep_explicit_mode_instead_of_collapsing_to_boolean():
    root = Path(__file__).resolve().parents[1]
    main_source = (root / "__main__.py").read_text(encoding="utf-8")
    host_source = (root / "browser_host.py").read_text(encoding="utf-8")
    app_source = (root / "ui" / "app.py").read_text(encoding="utf-8")
    settings_source = (root / "ui" / "settings_page.py").read_text(encoding="utf-8")

    assert "stylesheet(config.theme_mode())" in main_source
    assert "theme.stylesheet(config.theme_mode())" in host_source
    assert "def apply_theme(self, mode: str, *, animate: bool = True)" in app_source
    assert 'self.apply_theme("auto", animate=False)' in app_source
    assert "self._window.apply_theme(mode)" in settings_source
    assert "apply_theme(theme.resolve_dark" not in app_source + settings_source


def test_install_applies_the_resolved_locale_to_qt_standard_widgets():
    app = QApplication.instance() or QApplication([])
    i18n.install(app, "en", "zh_CN")
    try:
        assert QLocale().language() == QLocale.English
    finally:
        i18n.install(app, "zh-Hans", "zh_CN")


def test_english_copy_is_semantic_instead_of_literal():
    i18n.set_locale("en")
    try:
        assert i18n.tr("安全中心") == "Security"
        assert i18n.tr("导入密码数据") == "Import passwords"
        assert i18n.tr("选择用户并输入主密码以解锁。") == "Choose a vault and enter its master password."
    finally:
        i18n.set_locale("zh-Hans")


def test_supported_pc_locales_cover_home_detail_settings_and_security_copy():
    visible_copy = (
        "＋ 新增条目", "已泄露", "已过期", "即将过期", "搜索名称、用户名、标签…",
        "用户名", "密码", "网址", "创建时间", "最后修改", "编辑", "删除", "复制",
        "外观", "安全", "原生程序自动填充", "通行密钥服务", "隐私", "用户", "关于", "赞助支持",
        "自动锁定", "修改主密码", "打开密码库所在文件夹", "删除当前用户",
        "安全检测", "密码安全总览", "高风险", "需改进", "未发现问题", "高风险检测",
        "重新执行本地检测", "执行联网泄露检测",
        "每个条目依次完成本地风险检查和可选的联网泄露查询，进度按已完成条目数推进。",
        "本地规则不会上传密码；联网泄露检测使用密码哈希前 5 位校验。",
        "新增条目", "规则通过率", "显示后自动隐藏", "回收站自动清理", "联系",
        "尚未授权 IP 地址来源",
        "输入紧急恢复密钥并设置新的主密码。成功后恢复密钥本身保持不变。",
        "开启后，本机保险库会在 3 分钟内允许同局域网设备凭二维码和 PIN 拉取并同步数据。\n\n开启局域网同步需要验证当前主密码。",
    )
    for locale in ("en",):
        i18n.set_locale(locale)
        for source in visible_copy:
            assert i18n.tr(source) != source, f"{locale} is missing: {source}"
    i18n.set_locale("en")
    assert i18n.tr_dynamic("创建时间：2026-07-15") == "Created: 2026-07-15"
    assert i18n.tr_dynamic("最后修改：2026-07-15") == "Last updated: 2026-07-15"
    assert i18n.tr_dynamic("共 12/34 条") == "12/34 items"
    assert i18n.tr_dynamic("7 个未发现问题") == "7 with no issues found"
    assert i18n.tr_dynamic("共检测 10 个含密码条目") == "10 password items checked"
    assert i18n.tr_dynamic("已扫描 10 个含密码条目：高风险 1，需改进 2，未发现问题 7。") == "Checked 10 password items: 1 high risk, 2 need attention, 7 with no issues found."
    assert i18n.tr_dynamic("正在扫描本地规则：3/10 个含密码条目") == "Scanning local rules: 3/10 password items"
    assert i18n.tr_dynamic("删除后移入账户回收站，30 天内可恢复，逾期自动删除。") == "Moved to account Trash and kept for 30 days before permanent deletion."
    i18n.set_locale("zh-Hans")


def test_dynamic_visible_labels_are_translated_after_the_window_is_shown():
    app = QApplication.instance() or QApplication([])
    i18n.install(app, "en", "en_US")
    root = QWidget()
    layout = QVBoxLayout(root)
    label = QLabel()
    layout.addWidget(label)
    root.show()
    app.processEvents()

    label.setText("创建时间：2026-07-15")
    app.processEvents()

    assert label.text() == "Created: 2026-07-15"
    root.close()
    i18n.set_locale("zh-Hans")


def test_default_module_title_is_localized_without_changing_stored_data():
    QApplication.instance() or QApplication([])
    i18n.set_locale("en")
    card = ModuleCard(modules.new_module(modules.LOGIN_ACCOUNT))
    assert card.title.text() == "Login"
    assert card.value()["title"] == "登录"
    card.close()
    i18n.set_locale("zh-Hans")


def test_text_title_equal_to_contact_name_remains_custom_on_save():
    QApplication.instance() or QApplication([])
    i18n.set_locale("en")
    module = modules.new_module(modules.TEXT)
    module["title"] = "Email"
    card = ModuleCard(module)
    try:
        assert card.title.text() == "Email"
        assert card.value()["title"] == "Email"
    finally:
        card.close()
        i18n.set_locale("zh-Hans")


def test_module_card_preserves_opaque_autofill_roles_until_selector_changes():
    QApplication.instance() or QApplication([])
    i18n.set_locale("en")
    try:
        for raw_role in (7, "future_role"):
            module = modules.new_module(modules.TEXT)
            module["config"] = {"autofill_role": raw_role, "future_config": "keep"}
            card = ModuleCard(module)
            try:
                saved = card.value()
                assert saved["config"] == {
                    "autofill_role": raw_role,
                    "future_config": "keep",
                }
                if isinstance(raw_role, str):
                    labels = {
                        card._autofill_role.itemText(index)
                        for index in range(card._autofill_role.count())
                    }
                    assert f"Unavailable: {raw_role}" in labels
            finally:
                card.close()
    finally:
        i18n.set_locale("zh-Hans")


def test_module_picker_omits_contact_modules_because_text_variants_replace_them():
    QApplication.instance() or QApplication([])
    i18n.set_locale("en")
    dialog = module_editor.ModulePickerDialog()
    try:
        assert dialog.title_bar._title.text() == "Add module"
        labels = {label.text() for label in dialog.findChildren(QLabel)}
        buttons = {button.text() for button in dialog.findChildren(QPushButton)}
        assert "General" in labels
        assert not ({"Email", "Phone", "Postal code"} & buttons)
        assert not ({"通用", "邮箱", "电话", "邮编"} & (labels | buttons))
    finally:
        dialog.close()
        i18n.set_locale("zh-Hans")


def test_shared_value_dropdown_marks_the_current_default_with_a_blue_dot():
    QApplication.instance() or QApplication([])
    combo = app_ui.widgets.selection_combo()
    combo.addItem("First", "first")
    combo.addItem("Second", "second")
    assert not combo.itemIcon(0).isNull()
    assert combo.itemIcon(1).isNull()
    combo.setCurrentIndex(1)
    assert combo.itemIcon(0).isNull()
    assert not combo.itemIcon(1).isNull()


def test_pc_visible_literal_copy_has_a_non_chinese_supported_translation():
    visible_constructors = {"QLabel", "QPushButton", "QCheckBox", "QRadioButton"}
    visible_methods = {"setPlaceholderText", "setText", "addRow", "addItem", "_group", "_note", "_flash"}
    sources = set()
    root = Path(__file__).resolve().parents[1]
    for relative in ("ui/app.py", "ui/dialogs.py", "ui/module_editor.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            name = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else ""
            if name not in visible_constructors | visible_methods:
                continue
            for argument in call.args[:2]:
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str) and any("\u4e00" <= char <= "\u9fff" for char in argument.value):
                    sources.add(argument.value)
    i18n.set_locale("en")
    missing = sorted(source for source in sources if i18n.tr(source) == source)
    i18n.set_locale("zh-Hans")
    assert missing == []


def test_english_ui_translates_dynamic_and_system_dialog_copy_without_chinese_fragments():
    visible_calls = {
        "QLabel", "QPushButton", "QCheckBox", "QRadioButton", "QGroupBox",
        "ShadowDialog", "ConfirmPasswordDialog", "MessageDialog", "icon_text",
        "message", "confirm", "setText", "setPlaceholderText", "setToolTip",
        "setAccessibleName", "setWindowTitle", "addRow", "addItem", "addTab",
        "_group", "_note", "_flash", "getOpenFileName", "getOpenFileNames",
        "getSaveFileName", "getExistingDirectory", "drawText", "showMessage",
        "_confirm_master_password", "_confirm_password", "_require_master",
        "_warn", "warn", "_set_hint", "_field", "_spinbox_row",
        "_show_leak_progress", "BatchTagInputDialog", "QProgressDialog",
        "PasskeyStatus", "CloudError", "NativeAutofillError", "DecryptError",
        "ValueError", "RuntimeError", "addAction", "append", "emit", "set",
        "get", "choose_existing", "_do_lock", "tr", "__init__",
        "_btn",
    }

    def rendered_sample(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(
                value.value if isinstance(value, ast.Constant) else "Sample"
                for value in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = rendered_sample(node.left)
            right = rendered_sample(node.right)
            return left + right if left is not None and right is not None else None
        return None

    root = Path(__file__).resolve().parents[1]
    missing = []
    i18n.set_locale("en")
    try:
        for relative in ("ui/app.py", "ui/dialogs.py", "ui/module_editor.py", "ui/widgets.py", "browser_host.py"):
            tree = ast.parse((root / relative).read_text(encoding="utf-8"))
            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                name = call.func.id if isinstance(call.func, ast.Name) else (
                    call.func.attr if isinstance(call.func, ast.Attribute) else ""
                )
                if name not in visible_calls:
                    continue
                for argument in call.args:
                    source = rendered_sample(argument)
                    if not source or not any("\u4e00" <= char <= "\u9fff" for char in source):
                        continue
                    translated = i18n.tr_dynamic(source)
                    if any("\u4e00" <= char <= "\u9fff" for char in translated):
                        missing.append((relative, getattr(argument, "lineno", call.lineno), source))
    finally:
        i18n.set_locale("zh-Hans")

    assert missing == []


def test_representative_english_pages_render_without_chinese_ui_copy():
    app = QApplication.instance() or QApplication([])
    i18n.install(app, "en", "en_US")
    settings_window = SimpleNamespace(
        vault=SimpleNamespace(
            path=Path("sample.pmv"),
            recovery_key_info=("ABC", time.time()),
            key_revision=1,
        ),
        _native_hotkey_registered=False,
        apply_theme=lambda _dark: None,
        apply_lock_settings=lambda: None,
        apply_privacy_settings=lambda: None,
        apply_native_autofill_settings=lambda: None,
        cloud_sync_enabled=lambda: False,
        set_cloud_sync_enabled=lambda _enabled: None,
        reload=lambda: None,
        open_vault_folder=lambda: None,
        hide=lambda: None,
    )
    pages = [
        RecoveryKeyConfirmDialog(),
        dialogs.AddUserDialog([]),
        dialogs.EntryDialog(),
        dialogs.NativeAutofillPickerDialog(
            [Entry(title="Sample", username="user", password="password")],
            "sample.exe",
        ),
        dialogs.BackupPasswordDialog("export"),
        dialogs.BackupPasswordDialog("import"),
        dialogs.TagFilterDialog(["work"]),
        dialogs.TagRenameDialog(["work"]),
        dialogs.AccountRenameDialog("FAE", ["FAE", "Bob"]),
        SettingsPage(settings_window),
            dialogs.NativeAutofillExcludeDialog(),
            dialogs._MergeConflictDialog(
            ["One", "Two"],
            ["user", "user2"],
            ["password", "password2"],
        ),
        ModuleCard(modules.new_module(modules.PASSKEY)),
        ModuleCard(_valid_passkey_module()),
        SecurityCenterPage([], "revision"),
    ]
    missing = []
    try:
        for page in pages:
            page.show()
            app.processEvents()
            widgets = [page, *page.findChildren(QWidget)]
            actions = page.findChildren(QAction)
            for child in [*widgets, *actions]:
                values = []
                if isinstance(child, (QLabel, QAbstractButton, QGroupBox, QAction)):
                    values.append(child.text())
                if hasattr(child, "placeholderText"):
                    values.append(child.placeholderText())
                if hasattr(child, "toolTip"):
                    values.append(child.toolTip())
                if hasattr(child, "accessibleName"):
                    values.append(child.accessibleName())
                if isinstance(child, QComboBox):
                    values.extend(child.itemText(index) for index in range(child.count()))
                if isinstance(child, QTabWidget):
                    values.extend(child.tabText(index) for index in range(child.count()))
                if isinstance(child, QListWidget):
                    values.extend(child.item(index).text() for index in range(child.count()))
                for value in values:
                    if value and any("\u4e00" <= char <= "\u9fff" for char in value):
                        missing.append((type(page).__name__, type(child).__name__, value))
    finally:
        for page in pages:
            if hasattr(page, "close_page"):
                page.close_page("test")
            page.close()
        i18n.set_locale("zh-Hans")

    assert missing == []


def test_english_translates_core_errors_that_can_reach_the_ui():
    def rendered_sample(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            return "".join(
                value.value if isinstance(value, ast.Constant) else "Sample"
                for value in node.values
            )
        return None

    root = Path(__file__).resolve().parents[1]
    missing = []
    i18n.set_locale("en")
    try:
        for path in (root / "core").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for raised in (node for node in ast.walk(tree) if isinstance(node, ast.Raise)):
                if not isinstance(raised.exc, ast.Call):
                    continue
                for argument in raised.exc.args:
                    source = rendered_sample(argument)
                    if not source or not any("\u4e00" <= char <= "\u9fff" for char in source):
                        continue
                    if any("\u4e00" <= char <= "\u9fff" for char in i18n.tr_dynamic(source)):
                        missing.append((path.name, raised.lineno, source))
    finally:
        i18n.set_locale("zh-Hans")

    assert missing == []


def test_clipboard_local_files_extracts_real_files_and_ignores_dirs_and_links() -> None:
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        installer = root / "app.apk"
        installer.write_bytes(b"x" * 8)
        folder = root / "folder"
        folder.mkdir()
        mime = QMimeData()
        mime.setUrls(
            [
                QUrl.fromLocalFile(str(installer)),
                QUrl.fromLocalFile(str(folder)),
                QUrl("https://example.com/file.apk"),
            ]
        )
        assert _clipboard_local_files(mime) == [str(installer)]


def test_clipboard_local_files_returns_empty_for_text_only() -> None:
    app = QApplication.instance() or QApplication([])
    mime = QMimeData()
    mime.setText("hello")
    assert _clipboard_local_files(mime) == []


def test_alpha_key_uses_first_character_like_android() -> None:
    # 数字/符号开头归入 #；字母取自身；中文取拼音首字母（与安卓侧边栏一致）。
    assert app_ui.MainWindow._alpha_key("0011.ai") == "#"
    assert app_ui.MainWindow._alpha_key("123pan.com") == "#"
    assert app_ui.MainWindow._alpha_key("555yy1.com") == "#"
    assert app_ui.MainWindow._alpha_key(".hidden") == "#"
    assert app_ui.MainWindow._alpha_key("amazon") == "A"
    assert app_ui.MainWindow._alpha_key("baidu.com") == "B"
    assert app_ui.MainWindow._alpha_key("微信") == "W"


def test_native_file_dialogs_receive_localized_titles_and_filters():
    root = Path(__file__).resolve().parents[1]
    missing = []
    for relative in ("ui/app.py", "ui/dialogs.py", "ui/module_editor.py"):
        tree = ast.parse((root / relative).read_text(encoding="utf-8"))
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr not in {
                "getOpenFileName", "getOpenFileNames", "getSaveFileName", "getExistingDirectory",
            }:
                continue
            for argument in call.args:
                if (
                    isinstance(argument, ast.Constant)
                    and isinstance(argument.value, str)
                    and any("\u4e00" <= char <= "\u9fff" for char in argument.value)
                ):
                    missing.append((relative, argument.lineno, argument.value))
    assert missing == []


def test_pmv_import_copy_runs_in_worker_and_preserves_bytes(tmp_path):
    source = tmp_path / "source.pmv"
    destination = tmp_path / "destination.pmv"
    source.write_bytes(b"PMVS" + b"vault-data" * 1024)

    worker = _VaultImportCopyWorker(source, destination)
    worker.start()

    assert worker.wait(5_000)
    assert worker.error is None
    assert destination.read_bytes() == source.read_bytes()


def test_recovery_confirmation_reveal_expands_window_to_show_verification_step():
    app = QApplication.instance() or QApplication([])
    dialog = RecoveryKeyConfirmDialog()
    dialog.show()
    app.processEvents()
    before_width = dialog.width()
    before_height = dialog.height()

    copy_button = next(button for button in dialog.findChildren(QPushButton) if button.accessibleName() == "复制密钥")
    assert copy_button.text() == ""
    copy_button.click()
    app.processEvents()

    assert dialog.width() > before_width
    assert dialog.height() > before_height
    assert not dialog._verification_panel.isHidden()
    assert dialog._content_scroll.horizontalScrollBar().maximum() == 0
    assert dialog._content_scroll.verticalScrollBar().maximum() == 0
    available = dialog.screen().availableGeometry()
    assert dialog.width() <= available.width() - 80
    assert dialog.height() <= available.height() - 80
    dialog.close()


def test_recovery_availability_accepts_pmve(tmp_path):
    path = tmp_path / "vault.pmv"
    path.write_bytes(b"PMVS" + b"payload")

    assert dialogs._supports_recovery_unlock(path)


def test_empty_unlock_dialog_is_the_only_first_use_surface(monkeypatch):
    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(dialogs.config, "list_users", lambda: [])
    monkeypatch.setattr(dialogs.config, "get_current_user", lambda: None)

    dialog = dialogs.UnlockDialog()
    app.processEvents()

    assert not hasattr(dialog, "_no_user_choice")
    assert dialog.user_combo.currentText() == "暂无账户"
    assert not dialog.user_combo.isEnabled()
    assert not dialog.pw.isEnabled()
    assert not dialog.btn.isEnabled()
    assert "＋ 新建" in [button.text() for button in dialog.findChildren(QPushButton)]
    new_button = next(
        button for button in dialog.findChildren(QPushButton)
        if button.text() == "＋ 新建"
    )
    assert new_button.objectName() == "UnlockNewMenuButton"
    assert new_button.minimumWidth() >= 104
    assert [action.text() for action in new_button.menu().actions()] == [
        "新建账户",
        "导入 .pmv 文件",
        "局域网导入",
    ]
    # 提示文案已并入副标题（不再独占一行），并以 FieldError 标红
    assert "局域网导入" in dialog.sub_label.text()
    assert dialog.sub_label.objectName() == "FieldError"
    dialog.close()


def test_main_window_reuses_shared_app_tray(monkeypatch):
    import ui.tray as app_tray_mod

    source = inspect.getsource(MainWindow._setup_tray)
    assert "app_tray.setup_tray(" in source
    assert "self._show_from_tray," in source
    application = QApplication.instance() or QApplication([])
    created = []
    class Signal:
        def connect(self, callback): pass
    class Tray:
        activated = Signal()
        messageClicked = Signal()
        @staticmethod
        def isSystemTrayAvailable(): return True
        def __init__(self, icon): created.append(self)
        def setToolTip(self, text): pass
        def setContextMenu(self, menu): self.menu = menu
        def show(self): pass
    monkeypatch.setattr(app_tray_mod, "QSystemTrayIcon", Tray)
    monkeypatch.setattr(app_tray_mod, "_tray", None)
    monkeypatch.setattr(app_tray_mod, "_menu", None)
    monkeypatch.setattr(app_tray_mod, "_on_open", None)
    first = app_tray_mod.setup_tray(lambda: None)
    second = app_tray_mod.setup_tray(lambda: None)
    assert first is second and len(created) == 1


def test_unlock_new_menu_button_reserves_space_for_dropdown_arrow():
    app = QApplication.instance() or QApplication([])
    dialog = dialogs.UnlockDialog()
    stylesheet = dialogs.theme.stylesheet()
    block = stylesheet.split("QPushButton#UnlockNewMenuButton {", 1)[1].split(
        "QPushButton#UnlockNewMenuButton:hover", 1
    )[0]
    indicator = stylesheet.split("QPushButton#UnlockNewMenuButton::menu-indicator {", 1)[1].split(
        "QPushButton#Link", 1
    )[0]
    new_button = next(
        button for button in dialog.findChildren(QPushButton)
        if button.text() == "＋ 新建"
    )

    assert new_button.objectName() == "UnlockNewMenuButton"
    assert new_button.minimumWidth() >= 104
    assert "padding: 0px 28px 0px 10px;" in block
    assert "subcontrol-position: center right;" in indicator
    assert "right: 10px;" in indicator
    dialog.close()
    app.processEvents()


def test_new_vault_creation_uses_pmve(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(
        dialogs.Vault,
        "create_pmve_with_password_buffer",
        lambda path, password, recovery: calls.append((path, password, recovery)) or "pmve",
    )

    created = dialogs._create_new_vault(tmp_path / "vault.pmv", bytearray(b"password"), b"r" * 32)

    assert created == "pmve"
    assert calls == [(tmp_path / "vault.pmv", bytearray(b"password"), b"r" * 32)]


@pytest.mark.parametrize("cooling_down", [False, True])
def test_recovery_uses_format_neutral_password_reset_facade(monkeypatch, tmp_path, cooling_down):
    QApplication.instance() or QApplication([])
    secret = b"r" * 32
    new_secret = b"n" * 32
    reset_calls = []
    reissue_calls = []
    vault = SimpleNamespace(
        reset_password_with_recovery=lambda actual_secret, password: reset_calls.append(
            (actual_secret, password)
        ),
        regenerate_recovery_key=lambda ns, old_recovery_secret=None: reissue_calls.append(
            (ns, old_recovery_secret)
        ),
        key_revision=1,
        change_password=lambda _password: pytest.fail("format-specific password-session API used"),
    )
    record = {"name": "FAE", "file": "fae.pmv"}
    path = tmp_path / "fae.pmv"

    # Step 1: unlock only — no password reset yet.
    dialog = dialogs.RecoveryKeyUnlockDialog(path)
    monkeypatch.setattr(dialogs.recovery_key, "decode", lambda _text: secret)
    monkeypatch.setattr(dialogs.Vault, "open_with_recovery_key", lambda _path, _secret: vault)
    dialog.key.setPlainText("PMRK1-test")
    dialog.accept()
    assert dialog.vault is vault
    assert dialog.secret == secret
    assert reset_calls == []

    # Step 2: the dedicated reset dialog carries the new password.
    reset = dialogs._RecoveryResetPasswordDialog()
    reset.new_pw.setText("V7!qL2#nP9@x")
    reset.new_pw2.setText("V7!qL2#nP9@x")
    assert reset.password == "V7!qL2#nP9@x"
    reset.accept()
    assert reset.result() == QDialog.Accepted

    # Full forgot-password orchestration must use the format-neutral facade.
    monkeypatch.setattr(dialogs.UnlockDialog, "cooling_down", cooling_down)
    forgot = dialogs.UnlockDialog.__new__(dialogs.UnlockDialog)
    QDialog.__init__(forgot)
    forgot._unlocking = False
    forgot._current_record = lambda: record
    forgot.passed = lambda: None
    forgot.vault = None
    success_calls = []
    def complete_recovery(record, accepted_vault):
        success_calls.append((record, accepted_vault))
        forgot.vault = accepted_vault
        QDialog.accept(forgot)
    forgot._on_unlock_success = complete_recovery

    monkeypatch.setattr(dialogs.config, "user_vault_path", lambda _r: path)
    monkeypatch.setattr(dialogs.biometric, "is_enabled", lambda _p: False)
    monkeypatch.setattr(dialogs.biometric, "disable", lambda _p: None)
    monkeypatch.setattr(dialogs.config, "set_current_user", lambda _n: None)
    monkeypatch.setattr(dialogs.widgets, "message", lambda *a, **k: None)

    class FakeUnlock:
        def __init__(self, *a, **k):
            pass

        def exec(self):
            return QDialog.Accepted

    FakeUnlock.vault = vault
    FakeUnlock.secret = secret

    class FakeReset:
        password = "V7!qL2#nP9@x"

        def __init__(self, *a, **k):
            pass

        def exec(self):
            return QDialog.Accepted

    class FakeReissue:
        def __init__(self, *a, **k):
            pass

        def exec(self):
            return QDialog.Accepted

    FakeReissue.secret = new_secret

    monkeypatch.setattr(dialogs, "RecoveryKeyUnlockDialog", FakeUnlock)
    monkeypatch.setattr(dialogs, "_RecoveryResetPasswordDialog", FakeReset)
    monkeypatch.setattr(dialogs, "_MandatoryRecoveryReissueDialog", FakeReissue)

    forgot._forgot_password()

    assert reset_calls == [(secret, "V7!qL2#nP9@x")]
    assert reissue_calls == [(new_secret, secret)]
    assert success_calls == [(record, vault)]
    assert forgot.vault is vault
    assert forgot.result() == QDialog.Accepted
    forgot.close()


def test_expired_windows_hello_keeps_its_layout_slot_and_guides_password_login(monkeypatch, tmp_path):
    app = QApplication.instance() or QApplication([])
    vault_path = tmp_path / "fae.pmv"
    parent = QWidget()
    current_identity = SimpleNamespace(vault_id="current", signing_public_key=b"s" * 32)
    parent.vault = SimpleNamespace(
        device_unlock_key_format="pmve-root-key",
        pmve_identity=current_identity,
    )

    monkeypatch.setattr(dialogs.biometric, "available", lambda: True)
    monkeypatch.setattr(dialogs.biometric, "is_enabled", lambda _path: True)
    opened = SimpleNamespace(
        device_unlock_key_format="pmve-root-key",
        pmve_identity=SimpleNamespace(vault_id="other", signing_public_key=b"x" * 32),
        close=lambda: None,
    )
    monkeypatch.setattr(dialogs.biometric, "open_vault", lambda _path: opened)
    monkeypatch.setattr(dialogs.biometric, "disable", lambda _path: None)
    monkeypatch.setattr(dialogs.config, "_user_record", lambda _name: {"name": "FAE", "file": "fae.pmv"})
    monkeypatch.setattr(dialogs.config, "user_vault_path", lambda _record: vault_path)
    monkeypatch.setattr(dialogs.config, "get_lockout", lambda _key: (0, True))

    dialog = RelockDialog("FAE", lambda _password: True, parent)
    dialog.show()
    app.processEvents()
    before_size = dialog.size()

    dialog._unlock_with_hello()
    app.processEvents()

    assert dialog.hello_btn.isVisible()
    assert not dialog.hello_btn.isEnabled()
    assert dialog.hello_btn.text() == "生物识别已失效"
    assert dialog.size() == before_size
    # 失效引导文案并入副标题，不再独占一行
    assert "请用主密码" in dialog.sub_label.text()
    dialog.close()
    parent.close()


def test_relock_windows_hello_matches_pmve_signing_identity_without_a_dek(monkeypatch, tmp_path):
    QApplication.instance() or QApplication([])
    vault_path = tmp_path / "fae.pmv"
    identity = SimpleNamespace(vault_id="vault", signing_public_key=b"s" * 32, key_revision=4)
    parent = QWidget()
    parent.vault = SimpleNamespace(
        device_unlock_key_format="pmve-root-key",
        pmve_identity=identity,
    )
    opened = SimpleNamespace(
        device_unlock_key_format="pmve-root-key",
        pmve_identity=identity,
        close=lambda: None,
    )
    monkeypatch.setattr(dialogs.biometric, "available", lambda: True)
    monkeypatch.setattr(dialogs.biometric, "open_vault", lambda _path: opened)
    monkeypatch.setattr(dialogs.config, "_user_record", lambda _name: {"name": "FAE", "file": "fae.pmv"})
    monkeypatch.setattr(dialogs.config, "user_vault_path", lambda _record: vault_path)
    monkeypatch.setattr(dialogs.config, "get_lockout", lambda _key: (0, True))
    monkeypatch.setattr(dialogs.config, "set_lockout", lambda _key, _value: None)

    dialog = RelockDialog("FAE", lambda _password: True, parent)
    dialog._unlock_with_hello()

    assert dialog.unlocked
    parent.close()


def test_unlock_dialog_uses_format_specific_biometric_open(monkeypatch, tmp_path):
    QApplication.instance() or QApplication([])
    vault_path = tmp_path / "fae.pmv"
    opened = SimpleNamespace(path=vault_path)
    monkeypatch.setattr(dialogs.biometric, "available", lambda: False)
    monkeypatch.setattr(dialogs.biometric, "open_vault", lambda path: opened if path == vault_path else None)
    monkeypatch.setattr(dialogs.config, "list_users", lambda: [{"name": "FAE", "file": "fae.pmv"}])
    monkeypatch.setattr(dialogs.config, "get_current_user", lambda: "FAE")
    monkeypatch.setattr(dialogs.config, "user_vault_path", lambda _record: vault_path)
    monkeypatch.setattr(dialogs.config, "get_lockout", lambda _key: (0, True))
    monkeypatch.setattr(dialogs.config, "set_lockout", lambda _key, _value: None)

    dialog = dialogs.UnlockDialog()
    dialog._unlock_with_hello()

    assert dialog.vault is opened


def test_settings_registers_hello_through_format_specific_vault_api(monkeypatch, tmp_path):
    vault = SimpleNamespace(path=tmp_path / "vault.pmv")
    calls = []
    host = SimpleNamespace(
        _hello_guard=False,
        _window=SimpleNamespace(vault=vault),
        _require_master=lambda *_args, **_kwargs: "master",
        _set_hello_checked=lambda value: calls.append(("checked", value)),
    )
    monkeypatch.setattr(dialogs.biometric, "enable_for_vault", lambda actual: calls.append(actual) or True)
    monkeypatch.setattr(dialogs.widgets, "message", lambda *_args, **_kwargs: None)

    SettingsPage._on_hello_toggled(host, True)

    assert calls == [vault]


def test_main_window_relock_uses_pmve_identity():
    source = inspect.getsource(MainWindow._relock_prompt)

    assert "expected_pmve_identity=" in source
    assert "pmve_identity" in source


def test_passkey_status_is_immutable_and_valid_records_are_available():
    status = passkey_status(_valid_passkey_module())

    assert status == PasskeyStatus(
        code="syncable",
        label="已加密同步",
        detail="PC 可无损保存和同步；使用时需在已授权 Android 设备上释放访问密钥。",
    )
    assert (
        repr(status)
        == "PasskeyStatus(code='syncable', label='已加密同步', detail='PC 可无损保存和同步；使用时需在已授权 Android 设备上释放访问密钥。')"
    )
    with pytest.raises(FrozenInstanceError):
        status.code = "corrupt"


@pytest.mark.parametrize(
    "malformed",
    (
        None,
        [],
        {},
        {"type": modules.PASSKEY, "config": {}, "value": None},
        {"type": modules.PASSKEY, "config": {}, "value": "HOSTILE_RAW_PASSKEY_VALUE"},
    ),
)
def test_passkey_status_maps_malformed_values_to_one_generic_corrupt_state(malformed):
    status = passkey_status(malformed)

    assert status.code == "corrupt"
    assert status.label == "通行密钥数据损坏"
    assert status.detail == "请从可信设备重新同步该通行密钥。"
    assert "HOSTILE_RAW_PASSKEY_VALUE" not in repr(status)


def test_passkey_conflict_takes_precedence_without_validating_hostile_value(monkeypatch):
    def must_not_validate(_value):
        raise AssertionError("validation must not run before conflict detection")

    monkeypatch.setattr(module_editor.passkeys, "parse_record", must_not_validate)
    module = {
        "type": modules.PASSKEY,
        "config": {"passkeyConflictStatus": "key_mismatch"},
        "value": "HOSTILE_CONFLICT_VALUE",
    }

    status = passkey_status(module)

    assert status.code == "key_conflict"
    assert status.label == "通行密钥冲突"
    assert status.detail == "请在可信设备上保留正确凭据并重新同步。"
    assert "HOSTILE_CONFLICT_VALUE" not in repr(status)


def test_passkey_status_redacts_hostile_validation_exception_text(monkeypatch, caplog):
    marker = "PRIVATE_KEY_CREDENTIAL_RP_USER_BASE64_DER_CBOR_MARKER"

    def hostile_failure(_value):
        raise passkeys.PasskeyError(marker)

    monkeypatch.setattr(module_editor.passkeys, "parse_record", hostile_failure)

    status = passkey_status(_valid_passkey_module())

    rendered = repr(status)
    assert status.code == "corrupt"
    assert marker not in rendered
    assert marker not in caplog.text


def test_passkey_presentation_rows_contain_only_allowlisted_non_key_material():
    module = _valid_passkey_module()
    value = module["value"]

    rows = passkey_display_rows(module)
    rendered = repr(rows)

    assert [label for label, _value in rows] == [
        "依赖方",
        "账户",
        "创建时间",
        "最后使用",
        "计数器模式",
        "存储模式",
    ]
    assert rows[-1][1] == "PMV 同步型"
    for hidden_key in ("private_key", "public_key", "credential_id", "user_id"):
        assert hidden_key not in rendered
        hidden_value = value[hidden_key]
        if isinstance(hidden_value, dict):
            hidden_value = json.dumps(hidden_value, sort_keys=True)
        assert hidden_value not in rendered


def test_passkey_module_card_is_read_only_and_hides_all_key_material():
    app = QApplication.instance() or QApplication([])
    i18n.set_locale("en")
    module = _valid_passkey_module()
    value = module["value"]

    card = ModuleCard(module)
    card.show()
    app.processEvents()
    text_widgets = (
        card.findChildren(QLabel)
        + card.findChildren(QLineEdit)
        + card.findChildren(QPushButton)
    )
    rendered = "\n".join(
        widget.text()
        for widget in text_widgets
        if hasattr(widget, "text")
    )

    assert isinstance(card.title, QLabel)
    assert card.title.text() == "Passkey"
    assert card._editors == {}
    assert "Counter mode: Synchronized zero counter" in rendered
    assert not any(button.text() == "复制" for button in card.findChildren(QPushButton))
    for hidden_key in ("private_key", "public_key", "credential_id", "user_id"):
        assert hidden_key not in rendered
        hidden_value = value[hidden_key]
        if isinstance(hidden_value, dict):
            hidden_value = json.dumps(hidden_value, sort_keys=True)
        assert hidden_value not in rendered
    card.close()


def test_corrupt_passkey_module_card_never_falls_back_to_an_ordinary_editor():
    QApplication.instance() or QApplication([])
    i18n.set_locale("en")
    marker = "RAW_CORRUPT_PASSKEY_MATERIAL"
    module = {
        "id": "corrupt-passkey",
        "type": modules.PASSKEY,
        "title": "RAW_CORRUPT_PASSKEY_TITLE",
        "config": {},
        "value": marker,
    }

    card = ModuleCard(module)
    rendered = "\n".join(label.text() for label in card.findChildren(QLabel))

    assert isinstance(card.title, QLabel)
    assert card.title.text() == "Passkey"
    assert card._editors == {}
    assert marker not in rendered
    assert "RAW_CORRUPT_PASSKEY_TITLE" not in rendered
    card.close()


def test_main_detail_passkey_rendering_is_allowlisted_noncopyable_and_redacted():
    QApplication.instance() or QApplication([])
    module = _valid_passkey_module()
    value = module["value"]
    calls = []
    container = QWidget()

    def field(label, text, **options):
        calls.append((label, text, options))
        return QLabel(f"{label}：{text}")

    host = SimpleNamespace(
        detail=QVBoxLayout(container),
        _field=field,
    )
    host._render_passkey_rows = lambda passkey_module: MainWindow._render_passkey_rows(host, passkey_module)
    entry = SimpleNamespace(fields=modules.fields_with_modules({}, [module]))

    MainWindow._render_modules(host, entry)

    assert [label for label, _text, _options in calls] == [
        "依赖方",
        "账户",
        "创建时间",
        "最后使用",
        "计数器模式",
        "存储模式",
    ]
    assert all(options.get("no_select") is True for _label, _text, options in calls)
    assert all(not options.get("copyable", False) for _label, _text, options in calls)
    rendered = repr(calls)
    for hidden_key in ("private_key", "public_key", "credential_id", "user_id"):
        assert hidden_key not in rendered
        hidden_value = value[hidden_key]
        if isinstance(hidden_value, dict):
            hidden_value = json.dumps(hidden_value, sort_keys=True)
        assert hidden_value not in rendered
    container.close()


def test_secure_note_detail_renders_attachment_and_additional_custom_modules():
    QApplication.instance() or QApplication([])
    container = QWidget()
    rendered_fields = []
    rendered_attachments = []
    primary_note = modules.new_module(modules.MULTILINE)
    primary_note["value"] = "main note"
    attachment = modules.new_module(modules.ATTACHMENTS)
    attachment["value"] = [{"name": "report.pdf", "size": 3, "data": "YWJj"}]
    extra_text = modules.new_module(modules.TEXT)
    extra_text["title"] = "附加说明"
    extra_text["value"] = "visible detail"
    entry = SimpleNamespace(
        secret_type="secure_note",
        fields=modules.fields_with_modules({}, [primary_note, attachment, extra_text]),
    )

    host = SimpleNamespace(
        detail=QVBoxLayout(container),
        _attachments_field=lambda label, value, guarded=False: rendered_attachments.append((label, value, guarded)) or QLabel(label),
        _images_field=lambda *_args, **_kwargs: QLabel("images"),
        _field=lambda label, value, **options: rendered_fields.append((label, value, options)) or QLabel(label),
        _render_passkey_rows=lambda _module: None,
    )

    MainWindow._render_modules(host, entry)

    assert rendered_attachments == [("附件", attachment["value"], True)]
    assert [(label, value) for label, value, _options in rendered_fields] == [("附加说明", "visible detail")]
    container.close()


def test_compound_card_module_renders_images_as_images_not_base64_text():
    QApplication.instance() or QApplication([])
    container = QWidget()
    rendered_fields = []
    rendered_images = []
    card = modules.new_module(modules.CARD_DOCUMENT)
    card["value"] = {"bank": "Example Bank", "images": ["base64-image"]}
    entry = SimpleNamespace(secret_type="custom", fields=modules.fields_with_modules({}, [card]))
    host = SimpleNamespace(
        detail=QVBoxLayout(container),
        _attachments_field=lambda *_args, **_kwargs: QLabel("attachments"),
        _photo_module_field=lambda *_args, **_kwargs: pytest.fail("复合模块图片应使用横向平铺图片条"),
        _images_field=lambda label, value, guarded=False: rendered_images.append((label, value, guarded)) or QLabel(label),
        _field=lambda label, value, **options: rendered_fields.append((label, value, options)) or QLabel(label),
        _render_passkey_rows=lambda _module: None,
    )

    MainWindow._render_modules(host, entry)

    assert rendered_images == [("图片", ["base64-image"], True)]
    assert all("base64-image" not in value for _label, value, _options in rendered_fields)
    container.close()


def test_custom_compound_module_images_use_same_horizontal_image_strip():
    QApplication.instance() or QApplication([])
    container = QWidget()
    rendered_images = []
    custom_module = {
        "id": "custom-images",
        "type": modules.ADDRESS,
        "title": "自定义图片",
        "config": {},
        "sensitive": False,
        "value": {"name": "demo", "images": ["custom-image"]},
    }
    entry = SimpleNamespace(secret_type="custom", fields=modules.fields_with_modules({}, [custom_module]))
    host = SimpleNamespace(
        detail=QVBoxLayout(container),
        _attachments_field=lambda *_args, **_kwargs: QLabel("attachments"),
        _photo_module_field=lambda *_args, **_kwargs: pytest.fail("自定义模块图片应使用横向平铺图片条"),
        _images_field=lambda label, value, guarded=False: rendered_images.append((label, value, guarded)) or QLabel(label),
        _field=lambda *_args, **_kwargs: QLabel("field"),
        _render_passkey_rows=lambda _module: None,
    )

    MainWindow._render_modules(host, entry)

    assert rendered_images == [("图片", ["custom-image"], False)]
    container.close()


def test_photo_module_detail_uses_horizontal_image_strip():
    QApplication.instance() or QApplication([])
    container = QWidget()
    rendered_photos = []
    module = modules.new_module(modules.IMAGES)
    module["value"] = ["photo-a", "photo-b"]
    entry = SimpleNamespace(secret_type="custom", fields=modules.fields_with_modules({}, [module]))
    host = SimpleNamespace(
        detail=QVBoxLayout(container),
        _attachments_field=lambda *_args, **_kwargs: QLabel("attachments"),
        _photo_module_field=lambda *_args, **_kwargs: pytest.fail("照片模块应使用横向平铺图片条"),
        _images_field=lambda label, value, guarded=False: rendered_photos.append((label, value, guarded)) or QLabel(label),
        _field=lambda *_args, **_kwargs: QLabel("field"),
        _render_passkey_rows=lambda _module: None,
    )

    MainWindow._render_modules(host, entry)

    assert rendered_photos == [("图片", ["photo-a", "photo-b"], False)]
    container.close()


def test_current_card_images_use_horizontal_image_strip_without_legacy_fallback():
    bank_source = inspect.getsource(MainWindow._render_credit_card)

    assert 'self._images_field("卡片图片", imgs, guarded=True)' in bank_source
    assert 'self._photo_module_field("卡片图片", imgs, guarded=True)' not in bank_source
    assert 'entry.fields.get("card_images_b64")' in bank_source
    assert "id_images_b64" not in bank_source


def test_markdown_detail_and_editor_previews_keep_content_height_without_stretch():
    render_source = inspect.getsource(MainWindow._render_modules)
    detail_source = inspect.getsource(MainWindow._markdown_field)
    editor_source = inspect.getsource(module_editor.ModuleCard.__init__)

    assert "self.detail.addWidget(self._markdown_field(title, text, guarded=guarded_all), 1)" not in render_source
    assert "wrap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)" in detail_source
    assert "MarkdownViewer(text or \"*（空）*\", min_height=440)" in detail_source
    assert "viewer.setFixedHeight(440)" in detail_source
    assert "lay.addWidget(viewer)" in detail_source
    assert "MarkdownViewer(text, min_height=220)" in editor_source


def test_detail_image_card_handles_locked_pmve_media_without_crashing(monkeypatch):
    QApplication.instance() or QApplication([])

    def _raise_locked(*_args, **_kwargs):
        raise RuntimeError("媒体未解锁，无法访问 PMVE 对象")

    monkeypatch.setattr(app_ui, "load_image_thumbnail", _raise_locked)

    card = app_ui._DetailImgCard({"$pmv_media_ref": "pmv4-object-v1"}, large=True)
    try:
        card._thumbnail_future.result(timeout=2)
    except RuntimeError:
        pass
    card._finish_thumbnail()

    assert "PMVE" in card._load_error
    assert card.width() == 252
    assert card.height() == 190
    card.deleteLater()


def test_detail_image_card_does_not_wait_for_thumbnail(monkeypatch):
    from threading import Event
    from PySide6.QtGui import QImage

    QApplication.instance() or QApplication([])
    started, release = Event(), Event()

    def slow_thumbnail(_value):
        started.set()
        release.wait(3)
        return QImage()

    monkeypatch.setattr(app_ui, "load_image_thumbnail", slow_thumbnail)
    try:
        card = app_ui._DetailImgCard("synthetic-image")
        assert started.wait(2)
        assert not card._thumbnail_future.done()
    finally:
        release.set()
        if "card" in locals():
            card._thumbnail_future.result(timeout=3)
            card._finish_thumbnail()
            card.deleteLater()


def test_passkey_navigation_detail_is_read_only_and_skips_underlying_entry_fields():
    QApplication.instance() or QApplication([])
    container = QWidget()
    detail_activations = []
    rendered_entries = []
    host = SimpleNamespace(
        detail=QVBoxLayout(container),
        editor_workspace=SimpleNamespace(show_detail=lambda: detail_activations.append(True)),
        _clear_detail=lambda: None,
        _render_passkey_modules=rendered_entries.append,
    )
    entry = SimpleNamespace(
        secret_type="login",
        title="UNDERLYING_ENTRY_TITLE_MUST_NOT_RENDER",
        # 9fdad22 起 passkey 也渲染标签区（不再在标签渲染前早退），因此桩要带上
        # tags，否则 _show_entry 走到 `if entry.tags` 会 AttributeError。
        tags=[],
    )

    MainWindow._show_entry(host, entry, display_type="passkey")

    visible_text = "\n".join(label.text() for label in container.findChildren(QLabel))
    assert detail_activations == []
    assert rendered_entries == [entry]
    assert "UNDERLYING_ENTRY_TITLE_MUST_NOT_RENDER" not in visible_text
    container.close()


def test_passkey_navigation_double_click_does_not_open_the_ordinary_entry_editor(monkeypatch):
    class ListItem:
        pass

    edit_calls = []
    host = SimpleNamespace(
        _active_type="passkey",
        edit_entry=lambda: edit_calls.append(True),
    )
    monkeypatch.setattr(app_ui, "EntryListItem", ListItem)

    MainWindow._on_double_click(host, ListItem())

    assert edit_calls == []


def test_passkey_navigation_direct_edit_entry_is_rejected():
    host = SimpleNamespace(
        _active_type="passkey",
        list=SimpleNamespace(currentItem=lambda: object()),
    )

    assert MainWindow.edit_entry(host) is None


def test_passkey_context_menu_does_not_offer_edit(monkeypatch):
    QApplication.instance() or QApplication([])

    class ListItem:
        def __init__(self):
            self.entry = SimpleNamespace(secret_type="login")

        def setSelected(self, _selected):
            pass

    item = ListItem()
    actions = []

    class Menu:
        def __init__(self, _parent):
            pass

        def addAction(self, text):
            actions.append(text)
            return SimpleNamespace(triggered=SimpleNamespace(connect=lambda _callback: None))

        def addSeparator(self):
            actions.append("|")

        def exec(self, _pos):
            pass

    host = SimpleNamespace(
        _active_type="passkey",
        list=SimpleNamespace(
            itemAt=lambda _pos: item,
            selectedItems=lambda: [item],
            clearSelection=lambda: None,
            setCurrentItem=lambda _item: None,
            viewport=lambda: SimpleNamespace(mapToGlobal=lambda pos: pos),
        ),
        edit_entry=lambda: None,
        delete_entry=lambda: None,
    )
    monkeypatch.setattr(app_ui, "EntryListItem", ListItem)
    monkeypatch.setattr(app_ui, "QMenu", Menu)

    MainWindow._show_context_menu(host, object())

    assert "编辑" not in actions


def test_cloud_sync_page_keeps_primary_and_destructive_actions_separate():
    QApplication.instance() or QApplication([])
    page = CloudSyncPage()

    assert page.stack.count() == 2
    assert page.drive.sync.text() == "同步"
    assert page.webdav.sync.text() == "同步"
    assert page.drive.sync.objectName() == "Primary"
    # 破坏性操作收进「更多操作」菜单，主操作仍独立按钮
    assert page.drive.more.menu() is not None
    assert page.drive.clear_action.text() == "取消关联"
    assert page.drive.overwrite_action.text() == "上传覆盖"
    assert page.drive.download_action.text() == "下载覆盖本地"
    assert page.drive.preview.textInteractionFlags() & Qt.TextSelectableByMouse


def test_cloud_sync_uses_full_width_controls_and_vertical_content_scroll():
    app = QApplication.instance() or QApplication([])
    page = CloudSyncPage()
    page.resize(600, 680)
    page.show()
    app.processEvents()

    target_switch = page.findChild(QWidget, "CloudTargetSwitch")
    assert target_switch is not None
    # 页面保留与其他工作区页面一致的安全边距，控件仍铺满内容宽度
    margins = page.layout().contentsMargins()
    assert (margins.left(), margins.top(), margins.right(), margins.bottom()) == (20, 20, 20, 20)
    assert target_switch.width() == page.width() - margins.left() - margins.right()
    assert page.drive.sync.width() > page.width() * 0.8
    assert page.drive.more.width() > page.width() * 0.8
    assert page.scroll.verticalScrollBarPolicy() == Qt.ScrollBarAsNeeded
    assert page.scroll.horizontalScrollBarPolicy() == Qt.ScrollBarAlwaysOff
    assert page.scroll.sizePolicy().verticalPolicy() == QSizePolicy.Expanding
    page.close()


def test_cloud_target_switch_is_capsule_control_like_lan():
    """云端目标切换复用局域网档位条的胶囊控件，而不是一对 QPushButton。"""
    app = QApplication.instance() or QApplication([])
    page = CloudSyncPage()
    page.resize(600, 680)
    page.show()
    app.processEvents()

    switch = page.findChild(QWidget, "CloudTargetSwitch")
    assert isinstance(switch, ui_widgets.CapsuleSegmentedControl)
    assert (switch.count(), switch.current_key()) == (2, "drive")
    assert (switch.label_at(0), switch.label_at(1)) == ("云端硬盘", "WebDAV")
    # 整档切换条铺满内容宽度（与局域网档位条一致）。
    assert switch.sizePolicy().horizontalPolicy() == QSizePolicy.Expanding
    assert page.findChildren(QPushButton, "CloudTargetButton") == []

    seen: list[int] = []
    page.targetChanged.connect(seen.append)
    QTest.mouseClick(switch, Qt.LeftButton, pos=QPoint(int(switch.width() * 0.85), 20))
    assert (switch.current_index(), page.stack.currentIndex(), seen) == (1, 1, [1])
    page.close()


def test_capsule_segmented_control_fills_width_and_allows_many_instances():
    """行内档：高度可配、横向铺满；同页多个实例并存（曾在布局期抛错升级为访问冲突）。"""
    app = QApplication.instance() or QApplication([])
    controls = []
    for _ in range(3):
        control = ui_widgets.CapsuleSegmentedControl(
            [("edit", "编辑"), ("view", "查看")],
            current=0,
            height=30,
        )
        control.show()
        controls.append(control)
    app.processEvents()

    for control in controls:
        assert control.height() == 30
        assert control.sizePolicy().horizontalPolicy() == QSizePolicy.Expanding
        # 绘制依赖的 font 度量在构造期就可用（sizeHint 覆写不得引用未初始化状态）
        assert control.sizeHint() is not None
        assert control.minimumSizeHint() is not None
        # 两段等分，thumb 需完整落在轨道内
        assert control._index_at(control.width() * 0.9) == 1
        assert control._index_at(0) == 0
    for control in controls:
        control.deleteLater()


def test_cloud_target_switch_returns_scroll_to_top():
    app = QApplication.instance() or QApplication([])
    page = CloudSyncPage()
    tall_content = QWidget()
    tall_content.setFixedHeight(900)
    page.webdav.layout.insertWidget(2, tall_content)
    page.resize(600, 680)
    page._select_target(1)
    page.show()
    app.processEvents()

    scrollbar = page.scroll.verticalScrollBar()
    assert scrollbar.maximum() > 0
    scrollbar.setValue(scrollbar.maximum())
    page._select_target(0)
    assert scrollbar.value() == 0
    page.close()


def test_cloud_busy_refresh_does_not_persist_unchanged_auto_sync_settings():
    source = inspect.getsource(CloudSyncWorkspacePage._build_cloud_ui)
    refresh_body = source.split("def refresh_controls()", 1)[1].split("def choose_existing", 1)[0]

    assert "save_drive()" not in refresh_body
    assert "save_nas()" not in refresh_body


def test_cloud_sync_does_not_pass_removed_allow_different_flag():
    source = inspect.getsource(CloudSyncWorkspacePage._build_cloud_ui)
    assert "allow_different" not in source


def test_manual_cloud_sync_keeps_reconciliation_off_the_ui_thread():
    import ui.cloud_sync_controller as controller_mod

    source = inspect.getsource(controller_mod)
    # 同步、检测认证、下载替换的重活全部封装在 QThread 中执行。
    assert "class InteractiveCloudSyncWorker(QThread)" in source
    assert "class RemotePreviewWorker(QThread)" in source
    assert "class RemoteVerifyWorker(QThread)" in source
    assert "class DownloadReplaceWorker(QThread)" in source
    # 控制器主线程方法只编排线程，不直接做 PMVE 认证 / 整库替换。
    sync_body = source.split("def sync_drive", 1)[1].split("def sync_webdav", 1)[0]
    assert "authenticate_external_file" not in sync_body
    assert "replace_authenticated_file" not in sync_body
    preview_body = source.split("def _preview_pulled", 1)[1].split("def _preview_ready", 1)[0]
    assert "authenticate_external_file" not in preview_body
    assert "RemotePreviewWorker(" in preview_body
    download_body = source.split("def _download_pulled", 1)[1].split("def _download_replaced", 1)[0]
    assert "replace_authenticated_file" not in download_body
    assert "DownloadReplaceWorker(" in download_body


def test_cloud_controller_holds_state_and_emits_signals(monkeypatch):
    app = QApplication.instance() or QApplication([])
    import ui.cloud_sync_controller as controller_mod
    from ui.cloud_sync_controller import CloudSyncController

    captured = []
    monkeypatch.setattr(controller_mod.cloud, "load_cloud_drive", lambda _vid: Path("C:/cloud/FAE.pmv"))
    monkeypatch.setattr(controller_mod.cloud, "load_cloud_drive_revision", lambda _vid: "r1")
    monkeypatch.setattr(controller_mod.cloud, "load_cloud_drive_logical_revision", lambda _vid: None)
    monkeypatch.setattr(controller_mod.cloud, "load_webdav", lambda _vid, **_kwargs: None)

    vault = SimpleNamespace(
        path=Path("local.pmv"),
        pmve_identity=SimpleNamespace(vault_id=uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")),
        root_key_for_device_unlock=lambda: bytes(32),
        save=lambda *a, **k: None,
    )
    secret = SimpleNamespace(reveal=lambda: "pw", clear=lambda: None)
    controller = CloudSyncController(
        vault,
        vault_path=Path("local.pmv"),
        password=secret,
        cloud_vault_id="vid",
    )
    controller.stateChanged.connect(lambda: captured.append("state"))
    controller.load()

    assert controller.drive_connected
    assert controller.drive_health == "missing"
    assert not controller.webdav_connected
    assert captured


class _FakeList:
    """只实现被测跳转逻辑用到的那几个 QListWidget 接口。"""

    def __init__(self, entries):
        self._items = [SimpleNamespace(entry=entry) for entry in entries]
        self.current_row = -1

    def count(self):
        return len(self._items)

    def item(self, index):
        return self._items[index]

    def setCurrentRow(self, index):  # noqa: N802
        self.current_row = index


class _FakeSearch:
    def __init__(self, text=""):
        self._text = text
        self.blocked = None

    def text(self):
        return self._text

    def clear(self):
        self._text = ""

    def blockSignals(self, value):  # noqa: N802
        self.blocked = value


def _jump_host(entries, visible):
    """搭一个只带跳转所需状态的主窗口壳。"""
    host = MainWindow.__new__(MainWindow)
    host.vault = SimpleNamespace(entries=list(entries))
    host._active_type = visible[0].secret_type
    host._active_tag = None
    host._password_filter = None
    host.search = _FakeSearch("")
    host._search_timer = SimpleNamespace(stop=lambda: None)
    host._select_timer = SimpleNamespace(stop=lambda: None)
    host._list_add_btn = SimpleNamespace(setVisible=lambda _flag: None)
    host._update_chip_styles = lambda: None
    host.list = _FakeList(list(visible))
    reloads: list[bool] = []

    def reload(*, data_changed=True):
        reloads.append(data_changed)
        host.list = _FakeList(
            [e for e in host.vault.entries if host._active_type in (None, e.secret_type)]
        )

    host.reload = reload
    return host, reloads


def test_security_center_jump_across_categories_reveals_the_entry():
    """安全中心按条目自身类型列结果：左侧停在登录时点 WiFi 条目必须能跳过去。"""
    login = Entry(title="登录项", secret_type=SecretType.LOGIN)
    wifi = Entry(title="WiFi 项", secret_type=SecretType.WIFI)
    host, reloads = _jump_host([login, wifi], [login])
    assert host.list.count() == 1

    MainWindow._show_workspace_entry(host, wifi.id)

    assert host._active_type == SecretType.WIFI
    assert reloads == [False]
    assert host.list.current_row == 0
    assert host.list.item(0).entry.id == wifi.id


def test_security_center_jump_within_category_keeps_filters():
    """同类型条目本来就在列表里，跳转不应顺手清掉用户的筛选。"""
    login = Entry(title="登录项", secret_type=SecretType.LOGIN)
    host, reloads = _jump_host([login], [login])

    MainWindow._show_workspace_entry(host, login.id)

    assert reloads == []
    assert host.list.current_row == 0


def test_security_center_jump_releases_search_and_tag_filters():
    """被搜索词或标签挡住的条目同样要能跳过去。"""
    wifi = Entry(title="WiFi 项", secret_type=SecretType.WIFI)
    host, reloads = _jump_host([wifi], [wifi])
    host.search = _FakeSearch("对不上的关键词")
    host._active_tag = "某个标签"
    host.list = _FakeList([])

    MainWindow._show_workspace_entry(host, wifi.id)

    assert host.search.text() == ""
    assert host.search.blocked is False
    assert host._active_tag is None
    assert reloads == [False]
    assert host.list.current_row == 0


def test_cloud_controller_explains_why_a_start_is_refused():
    """被挡下的云端操作必须给出原因，否则界面上就是「点了没反应」。"""
    QApplication.instance() or QApplication([])
    from ui.cloud_sync_controller import CloudSyncController

    vault = SimpleNamespace(path=Path("local.pmv"), pmve_identity=None, save=lambda *a, **k: None)
    secret = SimpleNamespace(reveal=lambda: "pw", clear=lambda: None)
    controller = CloudSyncController(
        vault,
        vault_path=Path("local.pmv"),
        password=secret,
        cloud_vault_id="vid",
    )
    notices: list[tuple] = []
    controller.message.connect(lambda *args: notices.append(args))

    assert controller.start_block_reason() == ""
    assert controller.can_start(controller.DRIVE)

    controller.loading = True
    assert "加载" in controller.start_block_reason()
    assert not controller.can_start(controller.DRIVE)
    controller.loading = False

    controller._busy_targets.add(controller.DRIVE)
    assert "正在进行" in controller.start_block_reason()

    controller.inspect_drive()
    assert notices and notices[-1][0] == "无法开始"
    assert "正在进行" in notices[-1][1]


def test_cloud_pull_without_association_releases_busy():
    """检测途中关联被清掉时，pull 必须收尾：否则 busy 永真、状态永远停在检测中。"""
    QApplication.instance() or QApplication([])
    from ui.cloud_sync_controller import CloudSyncController, CloudSyncPhase

    vault = SimpleNamespace(path=Path("local.pmv"), pmve_identity=None, save=lambda *a, **k: None)
    secret = SimpleNamespace(reveal=lambda: "pw", clear=lambda: None)
    controller = CloudSyncController(
        vault,
        vault_path=Path("local.pmv"),
        password=secret,
        cloud_vault_id="vid",
    )
    controller.drive_path = None
    controller._set_busy(controller.DRIVE, True)

    controller._pull_and_preview(controller.DRIVE, "云端硬盘")

    assert not controller.any_busy
    assert controller.drive_health == "failed"
    assert controller.phase_of(controller.DRIVE) is CloudSyncPhase.FAILED


def test_cloud_controller_association_asks_mode_when_remote_has_data(monkeypatch):
    app = QApplication.instance() or QApplication([])
    import ui.cloud_sync_controller as controller_mod
    from ui.cloud_sync_controller import CloudSyncController
    from PySide6.QtCore import QObject, QTimer, Signal

    vault = SimpleNamespace(path=Path("local.pmv"), pmve_identity=None, save=lambda *a, **k: None)
    secret = SimpleNamespace(reveal=lambda: "pw", clear=lambda: None)
    controller = CloudSyncController(
        vault,
        vault_path=Path("local.pmv"),
        password=secret,
        cloud_vault_id="vid",
    )

    class InspectStub(QObject):
        completed = Signal(str, object)
        failed = Signal(str)
        finished = Signal()

        def __init__(self, action, target, payload=None, parent=None):
            super().__init__(parent)

        def start(self):
            QTimer.singleShot(
                0,
                lambda: (
                    self.completed.emit("inspect", SimpleNamespace(exists=True, size=100)),
                    self.finished.emit(),
                ),
            )

    monkeypatch.setattr(controller_mod, "CloudDriveWorker", InspectStub)
    asked = []
    synced = []
    controller.askExistingRemote.connect(lambda title, cb: asked.append((title, cb)))
    controller.sync_drive = lambda target, *, associated: synced.append((target, associated))

    controller.associate_drive(Path("C:/cloud/FAE.pmv"))
    app.processEvents()

    assert len(asked) == 1
    title, callback = asked[0]
    assert title == "云端已有保险库数据"
    callback("merge")
    assert synced == [(Path("C:/cloud/FAE.pmv"), True)]


def test_dynamic_dialog_shrinks_after_optional_content_is_hidden_without_becoming_mini():
    app = QApplication.instance() or QApplication([])
    dialog = QDialog()
    dialog_layout = QVBoxLayout(dialog)
    fixed = QWidget()
    fixed.setFixedHeight(120)
    optional = QWidget()
    optional.setFixedHeight(360)
    dialog_layout.addWidget(fixed)
    dialog_layout.addWidget(optional)
    dialog.show()
    app.processEvents()

    app_ui._fit_dialog_to_visible_content(dialog, preferred_width=520, min_height=360)
    expanded_height = dialog.height()

    optional.hide()
    app.processEvents()
    app_ui._fit_dialog_to_visible_content(dialog, preferred_width=520, min_height=360)

    assert dialog.height() < expanded_height
    assert dialog.height() >= 360
    assert dialog.width() >= 520
    dialog.close()


def test_lan_sync_menu_keeps_one_entry_for_the_three_gear_page():
    """局域网已是一页三档，菜单里只保留单个入口，不再展开三级下拉。"""
    source = inspect.getsource(MainWindow._build_sync_menu)
    assert 'menu.addAction(i18n.tr("局域网"), self._open_lan_page)' in source
    assert "addMenu" not in source.split("本地备份")[1]
    # 建立传输站 / 文件传输 不再是菜单项，而是页内档位
    assert 'i18n.tr("建立传输站")' not in source
    assert 'i18n.tr("文件传输")' not in source
    # 文件传输已存在，不再新增重复的“文件互传”入口
    assert "文件互传" not in source


def test_top_bar_nav_is_right_aligned_and_search_stays_in_list_column():
    top_bar = inspect.getsource(MainWindow._build_top_bar)
    list_pane = inspect.getsource(MainWindow._build_list_pane)

    for attribute in ("_more_btn", "_security_btn", "_recycle_btn", "_settings_btn"):
        assert attribute in top_bar
    # 拉伸项先于导航按钮：按钮组右对齐，紧随应用筛选标签与锁定按钮
    assert top_bar.index("lay.addStretch()") < top_bar.index("lay.addWidget(self._more_btn)")
    assert top_bar.index("lay.addWidget(self._settings_btn)") < top_bar.index("lay.addWidget(self._app_label)")
    # 搜索框留在条目列表栏，迷你栏不承载搜索；使用 RepeatSafeLineEdit 防御长按删除时光标与内容不同步
    assert "self.search = widgets.RepeatSafeLineEdit()" in list_pane
    assert "self.search = widgets.RepeatSafeLineEdit()" not in top_bar
    # 标题栏仍贴合详情面板上沿和左右边框。
    app = QApplication.instance() or QApplication([])
    host = SimpleNamespace(edit_entry=lambda: None, delete_entry=lambda: None, _show_empty=lambda: None)
    detail = MainWindow._build_detail_pane(host)
    margins = detail.layout().contentsMargins()
    assert (margins.left(), margins.top(), margins.right()) == (0, 0, 0)
    detail.close()


def test_fixed_height_row_lists_scroll_per_pixel():
    """固定行高的列表逐像素滚动：按行步进时每次滚动后布局完全一致，像原地换内容。"""
    from ui.maintenance_pages import RecycleBinPage
    from ui.security_page import SecurityCenterPage

    # 主列表的半行位移另有真实布局测试；这里验证维护页面的实际控件配置。
    app = QApplication.instance() or QApplication([])
    recycle = RecycleBinPage(SimpleNamespace(trash=[]))
    security = SecurityCenterPage([], "scroll-test")
    assert recycle.list.verticalScrollMode() == QAbstractItemView.ScrollPerPixel
    assert security._finding_list.verticalScrollMode() == QAbstractItemView.ScrollPerPixel
    security.close_page("test")
    recycle.close()
    security.close()


def test_entry_list_scrolls_to_partial_offsets():
    """条目列表能停在半行位置；按行滚动只能整行跳，看起来就是原地换内容。"""
    app = QApplication.instance() or QApplication([])
    host = MainWindow.__new__(MainWindow)
    host._search_timer = SimpleNamespace(start=lambda: None)
    host._active_type = SecretType.LOGIN
    host._get_type_order = lambda: [SecretType.LOGIN]
    for name in ("rename_tag", "_jump_to_alpha", "add_entry", "_on_select", "_on_double_click", "_show_context_menu"):
        setattr(host, name, lambda *_a, **_k: None)

    # 标签区控件会 installEventFilter(self)，PySide6 要求过滤器是已初始化的 QObject；
    # MainWindow.__new__ 绕过 __init__，故把方法绑到一个真正的 QObject 上再构造桩。
    class _EventFilterHost(QObject):
        def eventFilter(self, obj, event):
            del obj, event
            return False

    class _PaneHost(_EventFilterHost):
        _search_timer = None
        _active_type = None

        def _get_type_order(self):
            return [SecretType.LOGIN]

        def rename_tag(self, *_a, **_k):
            return None

        def _jump_to_alpha(self, *_a, **_k):
            return None

        def add_entry(self, *_a, **_k):
            return None

        def _on_select(self, *_a, **_k):
            return None

        def _on_double_click(self, *_a, **_k):
            return None

        def _show_context_menu(self, *_a, **_k):
            return None

    host = _PaneHost()
    host._search_timer = SimpleNamespace(start=lambda: None)
    host._active_type = SecretType.LOGIN

    pane = MainWindow._build_list_pane(host)
    pane.resize(360, 620)
    for i in range(50):
        host.list.addItem(QListWidgetItem(f"条目 {i}"))
    pane.show()
    app.processEvents()

    assert host.list.verticalScrollMode() == QAbstractItemView.ScrollPerPixel
    host.list.verticalScrollBar().setValue(12)
    assert host.list.visualItemRect(host.list.item(0)).top() == -12
    pane.close()


def test_list_add_button_is_floating_instead_of_embedded():
    """「新增条目」不铺满列表栏，也不独占一行：浮在条目之上。"""
    source = inspect.getsource(MainWindow._build_list_pane)

    assert "_FloatingAddButton(list_card," in source
    # 悬浮按钮不属于布局内容，卡片也不为它预留行高
    assert "list_card_lay.addWidget(self._list_add_btn)" not in source
    assert "addSpacing" not in source
    assert "GhostBar" not in source


def test_list_add_button_floats_centered_over_entries():
    from ui.app import LIST_ADD_BOTTOM_MARGIN, _FloatingAddButton

    app = QApplication.instance() or QApplication([])
    host = QWidget()
    host.resize(320, 480)
    under = QWidget(host)
    under.setStyleSheet("background: #FF00FF;")
    under.setGeometry(0, 0, 320, 480)
    button = _FloatingAddButton(host, "＋ 新增条目")
    host.show()
    button.show()
    app.processEvents()

    assert button.objectName() == "FloatingAddButton"
    assert button.isVisible()
    assert button.width() < host.width() // 2
    assert button.y() == host.height() - button.height() - LIST_ADD_BOTTOM_MARGIN
    assert button.y() + button.height() <= host.height()
    assert abs((button.x() + button.width() // 2) - host.width() // 2) <= 2
    # 浮在条目之上：按钮位置上盖住了下层内容
    image = host.grab().toImage()
    # The new floating shadow softly darkens the pixels immediately outside the button.
    assert QColor(image.pixel(button.x() - 24, button.y() + button.height() // 2)).name().upper() == "#FF00FF"
    assert QColor(image.pixel(button.x() + button.width() // 2, button.y() + button.height() // 2)).name().upper() != "#FF00FF"

    host.close()


def test_list_add_button_shares_detail_action_button_size_and_style():
    """悬浮「新增条目」与详情操作按钮等高、同款，且随主题同步。"""
    from ui.app import _FloatingAddButton, _FloatingDetailActions

    app = QApplication.instance() or QApplication([])
    list_host = QWidget()
    list_host.resize(320, 480)
    floating = _FloatingAddButton(list_host, i18n.tr("＋ 新增条目"))
    list_host.show()
    floating.show()

    detail_host = QWidget()
    detail_host.resize(600, 400)
    actions = _FloatingDetailActions(
        detail_host,
        on_edit=lambda: None,
        on_delete=lambda: None,
    )
    detail_host.show()
    actions.setVisible(True)
    app.processEvents()

    assert floating.height() == actions.edit_button.height() == actions.delete_button.height()
    assert floating.minimumHeight() == floating.maximumHeight()

    for mode in ("light", "dark"):
        with _theme_applied(mode):
            app.processEvents()
            assert _rendered_colors(floating) == _rendered_colors(actions.edit_button)

    list_host.close()
    detail_host.close()


def test_list_add_button_aligns_vertically_with_detail_action_buttons():
    """列表栏「＋ 新增条目」与详情页操作条相对各自容器的留白必须一致。

    两侧可见容器底边同高，按钮相对各自卡片使用相同留白。
    """
    from ui.app import (
        FLOATING_ACTION_BOTTOM_MARGIN,
        LIST_ADD_BOTTOM_MARGIN,
        _FloatingAddButton,
        _FloatingDetailActions,
    )

    app = QApplication.instance() or QApplication([])
    assert LIST_ADD_BOTTOM_MARGIN == FLOATING_ACTION_BOTTOM_MARGIN

    # 用真实的 ListCard / DetailPaneCard 结构测量：两卡片底边同高，
    # 详情页与列表卡片的宿主均没有额外边框内缩。
    from PySide6.QtWidgets import QFrame

    from core.storage import Vault
    from ui.app import MainWindow
    import tempfile
    from pathlib import Path

    vault = Vault.create(Path(tempfile.mkdtemp()) / "align.pmv", "TestMaster123!")
    window = MainWindow(vault)
    window._detail_fab.setVisible(True)
    window.resize(1280, 760)
    window.show()
    app.processEvents()
    app.processEvents()

    def global_bottom(widget) -> int:
        return widget.mapToGlobal(widget.rect().topLeft()).y() + widget.height()

    add_button = window._list_add_btn
    list_card = add_button._float_host
    detail_card = window.findChild(QFrame, "DetailPaneCard")

    assert list_card.objectName() == "ListCard"
    assert detail_card is not None
    # 两侧可见容器底边同高
    assert global_bottom(list_card) == global_bottom(detail_card)
    # 按钮相对各自容器的留白一致
    add_gap = global_bottom(list_card) - global_bottom(add_button)
    edit_gap = global_bottom(detail_card) - global_bottom(window._detail_fab.edit_button)
    assert add_gap == edit_gap
    # 且两条按钮落在同一水平线上
    assert add_button.mapToGlobal(add_button.rect().topLeft()).y() == window._detail_fab.edit_button.mapToGlobal(
        window._detail_fab.edit_button.rect().topLeft()
    ).y()

    window.close()


def test_transfer_station_window_keeps_qr_and_transfer_view_with_auto_jump():
    station_source = inspect.getsource(LanStationPage.start_station)
    assert "lbl_img" in station_source  # 二维码
    assert "LanSyncStatusPanel()" in station_source  # 同步状态页
    # 传输页复用共享面板，并在确有互传活动时自动显示
    assert "transfer_panel = LanTransferPanel()" in station_source
    assert "server._transfer_active and not transfer_panel.isVisible()" in station_source
    assert "transfer_panel.setVisible(True)" in station_source
    # 进入文件传输视图后隐藏同步状态页，避免同步/传输状态同屏堆叠
    assert "sync_panel.setVisible(False)" in station_source
    # 连接后自动隐藏连接信息，避免二次连接
    assert "set_pairing_chrome_hidden(True)" in station_source
    # 不再提供手动展开/显示的切换按钮
    assert "transfer_toggle" not in station_source
    assert "pairing_toggle" not in station_source
    assert "toggle_pairing_chrome" not in station_source


def test_lan_sync_client_window_exposes_verify_phase_and_progress():
    source = inspect.getsource(LanConnectionPage._build_connection_ui)
    assert 'phase == "verify"' in source
    assert 'sync_panel.update_status("verifying")' in source
    assert "LanSyncStatusPanel()" in source
    assert '"progress": (0, 0)' in source
    # 验证文案在共享面板中统一维护
    import ui.lan_panels as lan_panels_mod
    assert "正在验证并合并数据…" in inspect.getsource(lan_panels_mod.LanSyncStatusPanel)


def test_lan_connect_jumps_to_channel_specific_ui_after_connect():
    source = inspect.getsource(LanConnectionPage._build_connection_ui)
    # 连接视图整体收进容器，连接成功后整体隐藏（跳转）
    assert "connect_view = QWidget()" in source
    assert "connect_view.setVisible(False)" in source
    # 同步自动开始，文件传输通道只显示与主机一致的传输面板
    assert "show_sync = self._state[\"mode\"] == SYNC_OP" in source
    assert "show_transfer = self._state[\"mode\"] == TRANSFER_OP" in source
    assert "sync_panel.setVisible(show_sync)" in source
    assert "transfer_panel.setVisible(show_transfer)" in source
    assert "sync_btn" not in source


def test_lan_connect_waits_for_peer_approval_without_freezing():
    source = inspect.getsource(LanConnectionPage._build_connection_ui)
    # 配对 + 设备认证放在后台线程，对方弹窗确认期间本端不卡死
    assert "_threading.Thread(target=_establish, name=\"station-connect\", daemon=True).start()" in source
    assert "正在等待对方确认同步…" in source
    # 后台线程通过轮询把等待状态展示到界面
    assert "poll.start()" in source
    # 后台线程不得用 QTimer.singleShot 回调 UI（在无事件循环的普通线程里永不触发），
    # 跳转/失败必须由主线程轮询消费标记完成。
    assert "self._state[\"connect_ready\"] = True" in source
    assert "self._state[\"connect_error\"]" in source
    tick_body = source.split("def _tick()", 1)[1].split("\n        poll.timeout", 1)[0]
    assert "connect_ready" in tick_body
    assert "connect_error" in tick_body
    assert "QTimer.singleShot(0, _connected)" not in source
    assert "QTimer.singleShot(0, _fail" not in source


def test_lan_scan_qr_auto_connects_after_recognition():
    source = inspect.getsource(LanConnectionPage._build_connection_ui)
    scan_body = source.split("def scan_qr()", 1)[1].split("\n        def start_sync", 1)[0]
    # 扫码识别到有效地址后自动连接，无需手动点击“连接”
    assert "if apply_scan_payloads(cam.qr_payloads):" in scan_body
    assert "connect_now()" in scan_body


def test_client_reuses_shared_lan_panels():
    client_source = inspect.getsource(LanConnectionPage._build_connection_ui)
    # 连接方复用与主机一致的共享页面（不再各自定义一套传输/同步 UI）
    assert "sync_panel = LanSyncStatusPanel()" in client_source
    assert "transfer_panel = LanTransferPanel()" in client_source
    assert "transfer_panel.set_on_copy" in client_source
    assert "transfer_panel.sendText.connect" in client_source
    assert "transfer_panel.sendPaths.connect" in client_source
    assert "transfer_panel.set_records" in client_source
    assert "sync_btn" not in client_source
    assert "send_image_btn" not in client_source


def test_host_and_client_share_the_same_panel_components():
    import ui.lan_panels as lan_panels_mod

    station_source = inspect.getsource(LanStationPage.start_station)
    client_source = inspect.getsource(LanConnectionPage._build_connection_ui)
    # 主机与连接方都复用同一套共享页面组件
    assert "LanSyncStatusPanel()" in station_source
    assert "LanTransferPanel()" in station_source
    assert "LanSyncStatusPanel()" in client_source
    assert "LanTransferPanel()" in client_source
    # 页面组件本身只定义一次
    assert "class LanSyncStatusPanel" in inspect.getsource(lan_panels_mod)
    assert "class LanTransferPanel" in inspect.getsource(lan_panels_mod)


def test_lan_sync_client_auto_starts_and_auto_closes_after_success():
    source = inspect.getsource(LanConnectionPage._build_connection_ui)
    # 连接后自动开始同步，无需手动点击
    assert "QTimer.singleShot(0, start_sync)" in source
    # 连接方同步不再提供手动“同步保险库”按钮
    assert 'QPushButton(i18n.tr("同步保险库"))' not in source
    assert "sync_btn" not in source
    # 同步成功后短暂展示结果并自动断开关闭（仅同步通道）
    assert 'self._state.get("sync_succeeded") and self._state["mode"] == SYNC_OP' in source
    assert "_finish_connection()" in source
    # 完成后结果停留更久再自动收尾，保证同步结果可见
    assert "2500," in source


def test_lan_sync_does_not_misreport_start_as_retry():
    from core import sync_client as sync_client_mod

    sync_source = inspect.getsource(sync_client_mod.LanSyncClient.sync_vault)
    # 同步开始不再发出 (0,0)，避免被误判为“数据检查未通过，正在自动重试”
    assert 'on_phase("download", 0, 0)' not in sync_source


def test_lan_station_window_requires_sync_approval():
    station_source = inspect.getsource(LanStationPage.start_station)
    assert "server.sync_approval_enabled = True" in station_source
    assert '"pending_sync_device"' in station_source
    assert "server.approve_sync(session_token)" in station_source
    assert "server.reject_sync(session_token)" in station_source


def test_lan_flows_actively_disconnect_on_completion():
    station_source = inspect.getsource(LanStationPage.start_station)
    # 主机：同步/导出流程完成后主动关闭服务器并把结果留在页面内
    assert "server.stop()" in station_source
    assert "_handle_station_result" in station_source
    client_source = inspect.getsource(LanConnectionPage._build_connection_ui)
    # 连接方：流程完成/关闭时主动断开（cancel / end_transfer）
    assert "def disconnect_now()" in client_source
    assert "client.cancel" in client_source
    assert "disconnect_now()" in client_source


def test_qr_camera_scan_tries_camera_indexes_0_to_5_before_failing():
    import ui.module_editor as module_editor_mod

    init_source = inspect.getsource(module_editor_mod._CameraCaptureDialog.__init__)
    class_source = inspect.getsource(module_editor_mod._CameraCaptureDialog)
    assert "for index in range(6)" in init_source
    assert "cv2.CAP_DSHOW" in init_source
    assert "cv2.CAP_MSMF" in init_source
    # 全部索引/驱动都打不开时才报“摄像头未连接”
    assert "未检测到可用摄像头，或摄像头正被其他程序占用" in init_source
    # 扫码模式开启自动识别：取帧时周期性解码，识别到即自动完成
    assert "def _auto_scan_qr" in class_source
    assert "_auto_scan_qr(frame)" in class_source
    assert "自动识别中" in init_source


def test_qr_camera_auto_scan_accepts_when_qr_recognized():
    import io as _io

    import cv2
    import numpy as np
    import qrcode
    import ui.module_editor as module_editor_mod

    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data("https://192.168.1.5:18765/api/sync/vault?ticket=abc123&pin=123456")
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    buf = _io.BytesIO()
    img.save(buf, format="PNG")
    frame = cv2.imdecode(np.frombuffer(buf.getvalue(), dtype=np.uint8), cv2.IMREAD_COLOR)

    dlg = module_editor_mod._CameraCaptureDialog.__new__(module_editor_mod._CameraCaptureDialog)
    dlg._qr_found = False
    dlg.qr_payloads = []
    dlg._cv2 = cv2
    accepted = []
    dlg.accept = lambda: accepted.append(True)

    dlg._auto_scan_qr(frame)
    assert accepted == [True]
    assert dlg.qr_payloads and dlg.qr_payloads[0].startswith("https://192.168.1.5")
    # 已识别后不再重复处理
    dlg._auto_scan_qr(frame)
    assert accepted == [True]


def test_transfer_input_paste_sends_real_file_not_uri_text(tmp_path):
    _app = QApplication.instance() or QApplication([])
    box = _TransferTextEdit()
    sent = []
    box._on_files_paste = sent.append

    # 1) 标准文件 URL 剪贴板（资源管理器复制）：直接发送文件
    real = tmp_path / "release.apk"
    real.write_bytes(b"APK")
    mime = QMimeData()
    mime.setUrls([QUrl.fromLocalFile(str(real))])
    assert box._handle_mime(mime) is True
    assert sent and sent[-1] == [str(real)]

    # 2) 纯文本 file:// 路径（复制路径文本）：仍按真实文件发送
    mime_text = QMimeData()
    mime_text.setText(QUrl.fromLocalFile(str(real)).toString())
    assert box._handle_mime(mime_text) is True
    assert sent[-1] == [str(real)]

    # 3) 不指向真实文件的 file:// 文本：不拦截，作为普通文本
    mime_ghost = QMimeData()
    mime_ghost.setText("file:///C:/nonexistent/ghost.apk")
    assert box._handle_mime(mime_ghost) is False

    # 拖拽/右键粘贴路径同样拦截（Python 覆写 insertFromMimeData）
    assert type(box).insertFromMimeData.__qualname__ == "_TransferTextEdit.insertFromMimeData"


def test_transfer_list_uses_visible_row_separators():
    import ui.lan_panels as lan_panels_mod

    panel_source = inspect.getsource(lan_panels_mod.LanTransferPanel)
    assert "setAlternatingRowColors(True)" in panel_source
    theme_source = inspect.getsource(app_ui.theme.stylesheet)
    assert "QTreeWidget#TransferList::item" in theme_source
    assert "border-bottom: 1px solid" in theme_source
    assert "alternate-background-color" in theme_source
    # 表头列之间加竖向分割线
    assert "QTreeWidget#TransferList QHeaderView::section" in theme_source
    assert "border-right: 1px solid" in theme_source


def test_transfer_input_enter_sends_and_shift_enter_newline():
    _app = QApplication.instance() or QApplication([])
    panel = app_ui.LanTransferPanel()
    panel.show()
    _app.processEvents()
    sent = []
    panel.sendText.connect(sent.append)

    box = panel._send_text
    QTest.keyClicks(box, "hello")
    QTest.keyClick(box, Qt.Key_Return)  # Enter → 发送
    assert sent == ["hello"]
    assert box.toPlainText() == ""  # 发送后清空输入

    QTest.keyClicks(box, "line1")
    QTest.keyClick(box, Qt.Key_Return, Qt.ShiftModifier)  # Shift+Enter → 换行
    assert sent == ["hello"]
    assert box.toPlainText() == "line1\n"
    panel.close()


def test_sent_text_row_click_is_inert_without_local_file():
    _app = QApplication.instance() or QApplication([])
    panel = app_ui.LanTransferPanel()
    panel.set_records([
        {
            "id": "s1",
            "name": "文本",
            "kind": "text",
            "size": 5,
            "transferred": 5,
            "status": "已发送",
            "direction": "发送",
            "path": r"C:\tmp\no-such-dir\sent.txt",
        }
    ])
    item = panel.transfer_list.topLevelItem(0)
    # 已发送的文本：本地暂存文件可能已不存在，点击不应报错也不应复制。
    panel._activate_item(item, 0)
    assert panel._feedback.text() == ""
    # 提示为“已发送的文本”，而不是“点击复制文本”
    tooltip = item.toolTip(0)
    assert "点击复制" not in tooltip
    assert i18n.tr("已发送的文本") in tooltip  # 当前语言下的“已发送的文本”提示
    panel.close()


def test_main_window_first_frame_is_revealed_only_after_final_geometry(monkeypatch):
    app = QApplication.instance() or QApplication([])
    # Native DWM style mutation is exercised by the packaged Windows app, not
    # by a short-lived pytest QWidget whose native handle is immediately GC'd.
    monkeypatch.setattr(app_ui.widgets.FramelessMain, "_enable_native_frame", lambda _self: None)
    monkeypatch.setattr(app_ui.widgets.FramelessMain, "_apply_native_corners", lambda _self: None)
    window = app_ui.widgets.FramelessMain("测试", min_size=(900, 640))
    window.resize(1280, 760)

    assert window.windowOpacity() == 0
    window.show()
    app.processEvents()

    assert window.windowOpacity() == 1
    assert window.width() >= 900
    assert window.height() >= 640
    window.close()
    window.deleteLater()
    app.processEvents()


def test_reload_initializes_leaked_entries_when_nothing_matches():
    source = inspect.getsource(MainWindow.reload)
    # 空保险库或当前筛选无匹配时也必须初始化，否则云端同步成功后的
    # reload() 会抛 UnboundLocalError，导致关联成功页面不刷新。
    assert "leaked_entries = []" in source


def test_shadow_dialog_is_hidden_until_first_frameless_paint():
    app = QApplication.instance() or QApplication([])
    dialog = app_ui.widgets.ShadowDialog("测试")

    dialog._prepare_for_exec()

    assert dialog.windowFlags() & Qt.FramelessWindowHint
    assert dialog.windowOpacity() == 0
    app.processEvents()
    assert dialog.windowOpacity() == 1
    dialog.close()


def test_attachment_export_preserves_typed_pmve_object_ref(monkeypatch, tmp_path):
    ref = {
        "$pmv_media_ref": "pmv4-object-v1",
        "object_id": "12345678-1234-5678-9234-567812345678",
        "generation": 7,
        "kind": "attachment",
        "size": 3,
        "sha256": "ab" * 32,
    }
    destination = tmp_path / "report.bin"
    exported = []
    monkeypatch.setattr(app_ui.QFileDialog, "getSaveFileName", lambda *_args, **_kwargs: (str(destination), ""))
    monkeypatch.setattr(app_ui.media_files, "export_value", lambda value, path: exported.append((value, path)))
    monkeypatch.setattr(app_ui.widgets, "message", lambda *_args, **_kwargs: None)

    MainWindow._export_attachment(
        SimpleNamespace(vault=None),
        {"name": "report.bin", "data": ref},
    )

    assert exported == [(ref, destination)]


def test_pmve_relock_restores_vault_media_context():
    source = inspect.getsource(MainWindow._relock_prompt)

    assert "ensure_vault_context(self.vault)" in source
    assert "set_media_context_if_absent" not in source


def test_pmve_media_save_uses_atomic_adapter_without_ui_pretouch(monkeypatch):
    entry = Entry.from_dict({"id": "00000000-0000-0000-0000-000000000201", "fields": {}})
    previous = Entry.from_dict(entry.to_dict())
    original_updated_at = entry.updated_at
    committed = Entry.from_dict(entry.to_dict())
    calls = []
    vault = SimpleNamespace()
    # 媒体提交后主窗口会按媒体阈值机会式压缩，宿主需暴露该钩子。
    host = SimpleNamespace(vault=vault, _maybe_compact_large_media=lambda: None)
    monkeypatch.setattr(app_ui.media_files, "has_pending_imports", lambda value: value is entry)
    monkeypatch.setattr(
        app_ui.media_files,
        "commit_entry_imports",
        lambda actual_vault, actual_entry, **kwargs: calls.append(
            (actual_vault, actual_entry, kwargs)
        ) or committed,
    )

    result = MainWindow._persist_entry(host, entry, previous=previous)

    assert result is committed
    assert entry.updated_at == original_updated_at
    assert calls == [(vault, entry, {"expected_entry_updated_at": previous.updated_at})]


def test_cancelled_entry_dialog_never_publishes_staged_media(monkeypatch):
    class CancelledDialog:
        entry = Entry()

        def __init__(self, **_kwargs):
            pass

        def exec(self):
            return 0

        def deleteLater(self):
            pass

    published = []
    host = SimpleNamespace(
        vault=SimpleNamespace(),
        list=SimpleNamespace(
            clearSelection=lambda: None,
            setCurrentRow=lambda _row: None,
        ),
        _persist_entry=lambda *_args, **_kwargs: published.append(True),
    )
    monkeypatch.setattr(app_ui, "EntryDialog", CancelledDialog)

    MainWindow.add_entry(host)

    assert published == []


def test_reload_no_longer_decrypts_passwords_on_main_thread():
    reload_src = inspect.getsource(app_ui.MainWindow.reload)
    assert "self._password_filter_entries(password_filter)" not in reload_src
    update_src = inspect.getsource(app_ui.MainWindow._update_password_stats)
    assert "_get_password_stats" not in update_src
    assert hasattr(app_ui._PasswordStatsWorker, "result")


def test_settings_defers_slow_windows_capability_probes(monkeypatch, _isolate_settings_environment_probe):
    from ui import settings_page

    app = QApplication.instance() or QApplication([])
    calls = []
    scheduled = []
    monkeypatch.setattr(SettingsPage, "_start_environment_probe", _isolate_settings_environment_probe)
    # Inspect the real scheduling contract without leaving a callback behind
    # that could run after the provider mocks have been restored.
    monkeypatch.setattr(settings_page.QTimer, "singleShot", lambda delay, callback: scheduled.append((delay, callback)))
    monkeypatch.setattr(dialogs.biometric, "available", lambda: calls.append("hello") or False)
    monkeypatch.setattr(
        dialogs.PasskeyProviderStatus,
        "query",
        lambda _self: calls.append("passkey") or None,
    )
    window = SimpleNamespace(
        vault=SimpleNamespace(path=Path("vault.pmv"), recovery_key_info=("", 0), key_revision=1),
        _native_hotkey_registered=False,
        cloud_sync_enabled=lambda: False,
        set_cloud_sync_enabled=lambda _enabled: None,
        apply_theme=lambda _dark: None,
        apply_lock_settings=lambda: None,
        apply_privacy_settings=lambda: None,
        apply_native_autofill_settings=lambda: None,
        reload=lambda: None,
        open_vault_folder=lambda: None,
    )

    dialog = SettingsPage(window)

    assert calls == []
    assert any(
        delay == 0 and getattr(callback, "__func__", None) is _isolate_settings_environment_probe
        for delay, callback in scheduled
    )
    assert dialog.hello_enabled.isEnabled() is False
    assert "正在检测" in dialog._passkey_provider_status.text()
    dialog.deleteLater()


def test_password_stats_worker_computes_off_main_thread(tmp_path):
    from ui.app import _PasswordStatsWorker
    from core.storage import Vault
    import core.leak as leak

    vault = Vault.create(tmp_path / "v.pmv", "master")
    vault.add(Entry(title="A", password="weak"))
    vault.add(Entry(title="B", password="weak"))
    vault.add(Entry(title="C", password="StrongPassw0rd!xyz"))
    vault.save()

    calls = {"n": 0}
    orig = leak.entry_secret

    def counting(entry, *args, **kwargs):
        calls["n"] += 1
        return orig(entry, *args, **kwargs)

    leak.entry_secret = counting
    try:
        collected = {}
        worker = _PasswordStatsWorker(vault, "sig", lambda p: len(p) < 10)
        worker.result.connect(
            lambda sig, counts, sets: collected.update(sig=sig, counts=counts, sets=sets)
        )
        worker.run()
    finally:
        leak.entry_secret = orig

    assert calls["n"] == 3
    assert collected["counts"]["duplicate"] == 2
    assert collected["counts"]["weak"] == 2
    assert collected["counts"]["risk"] == 0
    assert collected["sig"] == "sig"


def test_repeat_safe_line_edit_expands_compressed_backspace():
    """Qt 在长按退格时会把 auto-repeat 合并成 count>1 的压缩事件；原生 QLineEdit
    只删除一次却把光标跳走，导致内容残留。RepeatSafeLineEdit 应按 count 逐个删除。"""
    from PySide6.QtCore import QEvent
    from PySide6.QtGui import QKeyEvent

    application = QApplication.instance() or QApplication([])
    editor = ui_widgets.RepeatSafeLineEdit()
    editor.setText("abcdefghijklmnop")
    editor.setCursorPosition(len(editor.text()))
    application.processEvents()

    # 模拟主线程繁忙期间被压缩成单个事件的 6 次退格（count=6）
    event = QKeyEvent(QEvent.KeyPress, Qt.Key_Backspace, Qt.NoModifier, 0, 0, 0, "", True, 6)
    QApplication.sendEvent(editor, event)
    application.processEvents()

    assert editor.text() == "abcdefghij"
    assert editor.cursorPosition() == len(editor.text())

    # count==1 时行为与原生一致（保底走 Qt 默认路径）
    editor.home(False)
    editor.setText("abcd")
    editor.setCursorPosition(len(editor.text()))
    application.processEvents()
    single = QKeyEvent(QEvent.KeyPress, Qt.Key_Backspace, Qt.NoModifier, 0, 0, 0, "", True, 1)
    QApplication.sendEvent(editor, single)
    application.processEvents()
    assert editor.text() == "abc"
    assert editor.cursorPosition() == 3


def test_repeat_safe_line_edit_expands_compressed_delete():
    from PySide6.QtCore import QEvent
    from PySide6.QtGui import QKeyEvent

    application = QApplication.instance() or QApplication([])
    editor = ui_widgets.RepeatSafeLineEdit()
    editor.setText("abcdefghijklmnop")
    editor.setCursorPosition(0)
    application.processEvents()

    # 压缩的 Delete 事件同理需要逐个删除、光标同步
    event = QKeyEvent(QEvent.KeyPress, Qt.Key_Delete, Qt.NoModifier, 0, 0, 0, "", True, 5)
    QApplication.sendEvent(editor, event)
    application.processEvents()

    assert editor.text() == "fghijklmnop"
    assert editor.cursorPosition() == 0


def test_update_dialog_constructor_lives_in_the_class_body():
    """UpdateDialog.__init__ 曾因缩进丢失落到模块层级。

    那样 UpdateDialog 会继承 ShadowDialog(title, parent) 的签名，而调用处传的是
    (parent, version, notes)，于是构造时抛 TypeError。异常发生在 Qt 槽里会被
    PySide6 吞掉（窗口版构建还会丢弃 stderr），表现为「检查更新」按钮变回原状却
    没有任何弹窗——应用内更新通道整体静默失效。
    """
    assert "__init__" in dialogs.UpdateDialog.__dict__, (
        "UpdateDialog.__init__ 必须定义在类体内，否则会退回继承来的构造签名"
    )


def test_update_dialog_accepts_the_call_sites_argument_count():
    """锁住 (parent, version, notes) 这个调用约定，防止再次出现签名不匹配。"""
    inspect.signature(dialogs.UpdateDialog.__init__).bind(
        object(), object(), "4.6.3", "### 修复\n- 更新说明"
    )
