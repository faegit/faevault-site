"""Floating actions use small cached backdrop regions, never whole-page captures."""

import os
import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication, QWidget

from ui.floating_actions import (
    BottomFloatingAction, TranslucentActionButton, TranslucentPanel,
)


def _app():
    return QApplication.instance() or QApplication([])


def test_surface_glass_is_translucent_in_both_themes():
    """The floating controls read as glass only if the token is translucent."""
    from ui import theme

    for name in ("LIGHT", "DARK"):
        value = getattr(theme, name)["surface_glass"]
        assert value.startswith("rgba("), f"{name} 应为半透明 rgba，实为 {value}"
        alpha = float(value.rsplit(",", 1)[1].rstrip(") "))
        assert 0.0 < alpha < 1.0, f"{name} alpha 应在 (0,1) 之间，实为 {alpha}"


def test_unbound_floating_controls_never_grab_the_backdrop():
    """未绑定滚动内容时使用普通半透明表面，不尝试抓取宿主。"""
    _app()
    host = QWidget()
    host.resize(300, 200)
    backdrop = QWidget(host)
    backdrop.setGeometry(0, 0, 300, 200)

    calls: list = []
    backdrop.grab = lambda rect=None: (calls.append(rect), super(type(backdrop), backdrop).grab(rect))[1]  # type: ignore[method-assign]

    button = TranslucentActionButton("确定", host)
    button.setGeometry(40, 40, 120, 40)
    panel = TranslucentPanel(host)
    panel.setGeometry(40, 100, 120, 40)
    host.show()
    _app().processEvents()

    button.repaint()
    panel.repaint()
    _app().processEvents()

    assert calls == [], f"不应再抓取背景，实测 {len(calls)} 次"
    host.close()


def test_bottom_floating_action_stays_centered_above_the_bottom():
    _app()
    host = QWidget()
    host.resize(400, 300)
    button = BottomFloatingAction("合并", host)
    host.show()
    _app().processEvents()

    button._position()
    assert button.width() > 0
    assert button.x() + button.width() <= host.width()
    assert button.y() + button.height() <= host.height()
    assert button.y() > host.height() // 2, "应贴在底部而不是顶部"
    host.close()


def test_backdrop_is_blurred_and_capture_is_limited_to_button_region():
    from PySide6.QtCore import Qt, qInstallMessageHandler
    from PySide6.QtGui import QColor, QPainter
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QScrollArea

    class Stripes(QWidget):
        def paintEvent(self, event):
            painter = QPainter(self)
            for x in range(0, self.width(), 4):
                painter.fillRect(x, 0, 4, self.height(), QColor("black" if x % 8 == 0 else "white"))

    _app()
    host = QWidget()
    host.resize(800, 600)
    scroll = QScrollArea(host)
    scroll.setGeometry(host.rect())
    content = Stripes()
    content.resize(1000, 1500)
    scroll.setWidget(content)
    viewport = scroll.viewport()
    captured = []
    original = viewport.grab
    def capture(rect):
        captured.append(rect)
        return original(rect)
    viewport.grab = capture
    button = TranslucentActionButton("确定", host)
    button.setGeometry(40, 440, 180, 48)
    button.set_backdrop_source(scroll)
    messages = []
    old_handler = qInstallMessageHandler(lambda _kind, _context, message: messages.append(message))
    host.show()
    try:
        QTest.qWait(150)
        assert not any("parent must be in parent hierarchy" in message for message in messages)
        assert captured
        assert all(rect.width() <= button.width() + 32 for rect in captured)
        assert all(rect.height() <= button.height() + 32 for rect in captured)
        assert all(rect.width() < viewport.width() for rect in captured)
        image = button._backdrop.toImage()
        colors = [image.pixelColor(x, image.height() // 2).red()
                  for x in range(20, image.width() - 20)]
        assert max(colors) - min(colors) < 80, "条纹应被真正模糊，而非仅叠加透明色"
        count = len(captured)
        button.repaint()
        assert len(captured) == count, "按钮绘制不得同步抓取内容"
        QTest.qWait(150)
        count = len(captured)
        QTest.qWait(150)
        assert len(captured) == count, "静止页面不应持续抓取背景"
        scroll.verticalScrollBar().setValue(120)
        QTest.qWait(100)
        assert len(captured) > count
        button.hide()
        assert button._backdrop.isNull(), "隐藏按钮时应清理内容截图"
    finally:
        qInstallMessageHandler(old_handler)
        host.close()


@pytest.mark.parametrize("mode", ["light", "dark"])
@pytest.mark.parametrize("action", ["edit_button", "delete_button"])
def test_detail_button_hover_preserves_visible_blurred_content(mode, action):
    from PySide6.QtCore import QPoint
    from PySide6.QtGui import QColor, QPainter
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QScrollArea
    from ui import theme
    from ui.app import _FloatingDetailActions

    class ColoredContent(QWidget):
        def paintEvent(self, event):
            painter = QPainter(self)
            for x in range(0, self.width(), 4):
                painter.fillRect(x, 0, 4, self.height(), QColor("red" if x % 8 == 0 else "blue"))

    app = _app()
    old_sheet = app.styleSheet()
    app.setStyleSheet(theme.stylesheet(mode))
    host = QWidget()
    host.resize(600, 320)
    scroll = QScrollArea(host)
    scroll.setGeometry(host.rect())
    content = ColoredContent()
    content.resize(900, 1000)
    scroll.setWidget(content)
    actions = _FloatingDetailActions(host, on_edit=lambda: None, on_delete=lambda: None)
    for button in (actions.edit_button, actions.delete_button):
        button.set_backdrop_source(scroll)
    host.show()
    actions.setVisible(True)
    try:
        QTest.qWait(150)
        button = getattr(actions, action)
        QTest.mouseMove(button, QPoint(button.width() // 2, button.height() // 2))
        QTest.qWait(60)
        image = host.grab().toImage()
        sample = image.pixelColor(button.x() + button.width() // 2, button.y() + 10)
        stripe_red = [image.pixelColor(button.x() + x, button.y() + 10).red()
                      for x in range(40, button.width() - 40)]
        assert max(stripe_red) - min(stripe_red) < 20, "实际按钮表面不能透出未模糊的清晰条纹"
        opaque_hover = QColor(theme.active()["accent_soft" if action == "edit_button" else "danger_soft"])
        difference = max(abs(sample.red() - opaque_hover.red()),
                         abs(sample.green() - opaque_hover.green()),
                         abs(sample.blue() - opaque_hover.blue()))
        assert difference > 20, "悬停填充不应遮住按钮背后的彩色内容"
    finally:
        host.close()
        app.setStyleSheet(old_sheet)


def test_detail_child_repaint_updates_blur_without_scrolling():
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPainter
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QScrollArea

    class Content(QWidget):
        color = "red"
        def paintEvent(self, event):
            painter = QPainter(self)
            painter.fillRect(self.rect(), QColor(self.color))

    _app()
    host = QWidget()
    host.resize(400, 300)
    scroll = QScrollArea(host)
    scroll.setGeometry(host.rect())
    content = Content()
    content.setAttribute(Qt.WA_OpaquePaintEvent)
    content.resize(600, 700)
    scroll.setWidget(content)
    button = TranslucentActionButton("编辑", host)
    button.setGeometry(80, 200, 150, 48)
    button.set_backdrop_source(scroll)
    host.show()
    try:
        QTest.qWait(150)
        initial = button._backdrop.toImage().pixelColor(30, 30)
        assert initial.red() > 200
        content.color = "blue"
        content.update()
        QTest.qWait(150)
        updated = button._backdrop.toImage().pixelColor(30, 30)
        assert updated.blue() > 200 and updated.red() < 20
    finally:
        host.close()


def test_late_created_timestamp_labels_are_included_in_detail_blur():
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QLabel, QScrollArea
    from ui import theme
    from ui.app import _FloatingDetailActions

    app = _app()
    old_sheet = app.styleSheet()
    app.setStyleSheet(theme.stylesheet("light"))
    host = QWidget()
    host.resize(600, 360)
    scroll = QScrollArea(host)
    scroll.setGeometry(host.rect())
    content = QWidget()
    content.resize(800, 800)
    content.setStyleSheet("background: transparent;")
    scroll.setWidget(content)
    actions = _FloatingDetailActions(host, on_edit=lambda: None, on_delete=lambda: None)
    for button in (actions.edit_button, actions.delete_button):
        button.set_backdrop_source(scroll)
    host.show()
    actions.setVisible(True)
    try:
        QTest.qWait(150)
        before = actions.edit_button._backdrop.toImage().copy()
        labels = []
        for y, text in ((294, "创建时间：2026-10-02 14:40"), (320, "最后修改：2026-10-02 15:20")):
            label = QLabel(text, content)
            label.setGeometry(100, y, 400, 24)
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("color: black; background: transparent; font-size: 14px;")
            label.show()
            labels.append(label)
        QTest.qWait(150)
        after = actions.edit_button._backdrop.toImage()
        assert after != before, "详情中后创建的时间标签必须触发背景模糊刷新"
        colors = [after.pixelColor(x, y).red() for y in range(16, after.height() - 16)
                  for x in range(16, after.width() - 16)]
        assert min(colors) < 250, "模糊图中必须包含时间文字，而非空白背景"
        assert min(colors) > 100, "时间文字应被模糊，不能直接保留清晰黑色字形"
        assert all(after.pixelColor(x, 30).alpha() == 255 for x in range(20, after.width() - 20)), "透明背景的时间标签必须先合成不透明底图，防止原字形透出"
    finally:
        host.close()
        app.setStyleSheet(old_sheet)
