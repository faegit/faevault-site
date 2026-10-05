import inspect
import os
import ctypes
from ctypes import wintypes

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEvent, QPoint, Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QWidget

from ui import i18n, widgets
from ui.widgets import _WindowButtons, _WindowControlButton


class _Host(QWidget):
    def __init__(self):
        super().__init__()
        self.minimized = 0
        self.closed = 0

    def animateMinimize(self):
        self.minimized += 1

    def close(self):
        self.closed += 1
        return True


def test_window_controls_have_large_targets_and_invoke_expected_actions():
    app = QApplication.instance() or QApplication([])
    host = _Host()
    controls = _WindowButtons(host)
    controls.show()
    app.processEvents()

    by_kind = {
        button._kind: button
        for button in controls.findChildren(_WindowControlButton)
    }
    assert set(by_kind) == {"minimize", "maximize", "close"}
    assert all(button.width() >= 44 and button.height() >= 36 for button in by_kind.values())

    QTest.mouseClick(by_kind["minimize"], Qt.LeftButton)
    QTest.mouseClick(by_kind["close"], Qt.LeftButton)
    assert host.minimized == 1
    assert host.closed == 1


def test_maximize_button_updates_its_semantics_when_window_state_changes():
    app = QApplication.instance() or QApplication([])
    host = _Host()
    controls = _WindowButtons(host)
    controls._max.set_kind("restore", "还原")
    app.processEvents()

    assert controls._max.accessibleName() == "还原"
    assert controls._max.toolTip() == "还原"
    assert controls._max._kind == "restore"


def test_minimize_glyph_is_vertically_centered_and_all_controls_are_self_drawn():
    app = QApplication.instance() or QApplication([])
    host = _Host()
    controls = _WindowButtons(host)
    controls.show()
    app.processEvents()

    buttons = controls.findChildren(_WindowControlButton)
    minimize = next(button for button in buttons if button._kind == "minimize")
    assert minimize._glyph_center_y() == minimize.height() / 2
    assert all(button.icon().isNull() for button in buttons)
    assert all(not button.grab().isNull() for button in buttons)


def test_window_controls_use_rounded_docked_containers_with_native_title_bar():
    source = inspect.getsource(_WindowControlButton.paintEvent)
    title_source = inspect.getsource(widgets.TitleBar)

    assert "drawRoundedRect" in source
    assert "QColor(Qt.transparent)" in source
    assert 'colors["surface_alt"]' in source
    assert "if self.isEnabled() and (hovered or pressed):" in source
    assert "def _snap_to_edge" not in title_source
    assert "def _is_native_caption_area" in inspect.getsource(widgets._is_native_caption_area)


def test_title_bar_blank_area_is_native_caption_but_buttons_are_interactive():
    app = QApplication.instance() or QApplication([])
    host = _Host()
    bar = widgets.TitleBar(host, "测试")
    bar.show()
    app.processEvents()

    title_center = bar._title.mapToGlobal(bar._title.rect().center())
    assert widgets._is_native_caption_area(bar, title_center)

    close_center = bar._buttons._close.mapToGlobal(bar._buttons._close.rect().center())
    assert not widgets._is_native_caption_area(bar, close_center)

    outside = QPoint(title_center.x(), bar.mapToGlobal(QPoint(0, -10)).y())
    assert not widgets._is_native_caption_area(bar, outside)


def test_window_controls_use_docked_feedback_and_reset_after_click(monkeypatch):
    app = QApplication.instance() or QApplication([])
    host = _Host()
    controls = _WindowButtons(host)
    monkeypatch.setattr(_WindowControlButton, "underMouse", lambda self: False)
    controls.show()
    app.processEvents()
    by_kind = {
        button._kind: button
        for button in controls.findChildren(_WindowControlButton)
    }

    by_kind["minimize"].clearFocus()
    app.processEvents()
    by_kind["minimize"].setFocus(Qt.TabFocusReason)
    app.processEvents()
    assert by_kind["minimize"]._hover_feedback_active()

    QTest.mouseClick(by_kind["minimize"], Qt.LeftButton)
    app.processEvents()
    assert not by_kind["minimize"]._hover_feedback_active()
    assert not by_kind["minimize"].hasFocus()

    source = inspect.getsource(_WindowControlButton.paintEvent)
    assert "hint_pen" not in source
    assert "self.height() - 3" not in source


def test_window_control_hover_state_clears_after_mouse_leaves(monkeypatch):
    app = QApplication.instance() or QApplication([])
    host = _Host()
    controls = _WindowButtons(host)
    monkeypatch.setattr(_WindowControlButton, "underMouse", lambda self: False)
    controls.show()
    app.processEvents()
    minimize = next(
        button for button in controls.findChildren(_WindowControlButton) if button._kind == "minimize"
    )

    # Mouse-click focus alone must not light the docked surface.
    minimize.clearFocus()
    app.processEvents()
    minimize.setFocus(Qt.MouseFocusReason)
    app.processEvents()
    assert minimize.hasFocus()
    assert not minimize._hover_feedback_active()
    app.sendEvent(minimize, QEvent(QEvent.Leave))
    app.processEvents()
    assert not minimize._hover_feedback_active()
    assert not minimize.hasFocus()

    # Genuine keyboard focus keeps the affordance visible while focused.
    minimize.setFocus(Qt.TabFocusReason)
    app.processEvents()
    assert minimize._hover_feedback_active()
    minimize.clearFocus()
    app.processEvents()
    assert not minimize._hover_feedback_active()


def test_modal_dialog_close_control_is_self_drawn_and_can_be_safely_suspended():
    app = QApplication.instance() or QApplication([])
    dialog = widgets.ShadowDialog("测试")
    close_button = dialog.title_bar._buttons._close

    assert isinstance(close_button, _WindowControlButton)
    assert close_button.icon().isNull()
    assert close_button._kind == "close"

    dialog.set_close_enabled(False)
    assert not close_button.isEnabled()
    assert close_button.accessibleName() == i18n.tr("操作完成后可关闭")

    dialog.set_close_enabled(True)
    assert close_button.isEnabled()
    assert close_button.accessibleName() == i18n.tr("关闭")
    dialog.close()


def test_main_window_native_frame_clears_popup_style_for_dwm_rounding():
    source = inspect.getsource(widgets.FramelessMain._enable_native_frame)

    assert "get_style.argtypes" in source
    assert "set_style.argtypes" in source
    assert "style &= ~0x80000000" in source
    assert "style |= 0x00CF0000" in source


def test_native_corners_use_standard_round_radius_to_match_other_apps():
    source = inspect.getsource(widgets.FramelessMain._apply_native_corners)

    # DWMWCP_ROUND = 2（标准圆角），DWMWCP_DONOTROUND = 1（最大化直角）。
    assert "1 if self.isMaximized() else 2" in source


def test_native_event_returns_caption_for_title_bar_even_when_maximized():
    app = QApplication.instance() or QApplication([])
    win = widgets.FramelessMain("测试")
    win.show()
    win.showMaximized()
    app.processEvents()
    assert win.isMaximized()

    msg = wintypes.MSG()
    msg.message = 0x0084  # WM_NCHITTEST
    pos = win.title_bar._title.mapToGlobal(win.title_bar._title.rect().center())
    msg.lParam = ((pos.y() & 0xFFFF) << 16) | (pos.x() & 0xFFFF)

    handled, result = win.nativeEvent(b"windows_generic_MSG", ctypes.addressof(msg))
    assert handled
    assert result == 2  # HTCAPTION：最大化时也交给系统，一次下拉即可还原
    win.close()


def test_native_event_resize_hit_zones_only_apply_when_not_maximized():
    app = QApplication.instance() or QApplication([])
    win = widgets.FramelessMain("测试")
    win.show()
    app.processEvents()

    msg = wintypes.MSG()
    msg.message = 0x0084  # WM_NCHITTEST
    edge = win.mapToGlobal(QPoint(2, win.height() // 2))
    msg.lParam = ((edge.y() & 0xFFFF) << 16) | (edge.x() & 0xFFFF)
    handled, result = win.nativeEvent(b"windows_generic_MSG", ctypes.addressof(msg))
    assert handled
    assert result == 10  # HTLEFT：普通状态下左边缘可缩放
    win.close()


def test_sidebar_places_new_entry_at_bottom_with_upward_indicator():
    from ui.app import MainWindow, theme

    source = inspect.getsource(MainWindow._build_sidebar)
    assert 'setObjectName("SidebarAddMenuButton")' in source
    assert "self._sidebar_lay.addStretch()" in source
    assert source.index("self._sidebar_lay.addStretch()") < source.index("self._sidebar_lay.addWidget(self._sidebar_separator)")
    assert source.index("self._sidebar_lay.addWidget(self._sidebar_separator)") < source.index("self._sidebar_lay.addWidget(self._sidebar_create_section)")

    stylesheet = theme.stylesheet("light")
    indicator = stylesheet.split("QPushButton#SidebarAddMenuButton::menu-indicator {", 1)[1].split(
        "QPushButton#UnlockNewMenuButton", 1
    )[0]
    assert "chevron-up.svg" in indicator
    assert "subcontrol-position: center right;" in indicator
    assert "right: 10px;" in indicator


def test_sidebar_reserves_left_safe_distance_for_new_entry_button():
    from ui.app import SIDEBAR_BOTTOM_SAFE_MARGIN, MainWindow

    source = inspect.getsource(MainWindow._build_sidebar)
    assert "setContentsMargins(16, 12, 8, SIDEBAR_BOTTOM_SAFE_MARGIN)" in source
    assert SIDEBAR_BOTTOM_SAFE_MARGIN == 20
