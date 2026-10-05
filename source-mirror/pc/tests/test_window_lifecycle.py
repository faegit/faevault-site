import os

import pytest
from PySide6.QtCore import QEvent, QObject, QPoint, QPointF, Qt
from PySide6.QtGui import QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QComboBox, QVBoxLayout, QWidget

from core import modules
from ui import widgets
from ui.module_editor import ModuleCard


@pytest.fixture
def application():
    app = QApplication.instance() or QApplication([])
    widgets.install_combobox_wheel_guard()
    return app


@pytest.mark.parametrize("kind", ["detail", "editor"])
@pytest.mark.parametrize("dialog", [False, True])
def test_late_markdown_does_not_recreate_main_window(application, kind, dialog):
    if os.name != "nt" or application.platformName() != "windows":
        pytest.skip("Requires the real Windows compositor")
    window = widgets.ShadowDialog("Window lifecycle regression") if dialog else widgets.FramelessMain("Window lifecycle regression")
    layout = window.body if dialog else QVBoxLayout(window.content)
    window.show()
    QTest.qWait(100)
    before = int(window.winId())
    events = []

    class Recorder(QObject):
        def eventFilter(self, watched, event):
            if event.type() in (QEvent.WinIdChange, QEvent.Hide, QEvent.Close):
                events.append(event.type().name)
            return False

    recorder = Recorder()
    window.installEventFilter(recorder)
    try:
        for _ in range(2):
            content = widgets.MarkdownViewer("# Custom entry") if kind == "detail" else ModuleCard(modules.new_module(modules.MULTILINE))
            layout.addWidget(content)
            QTest.qWait(300)
            assert int(window.winId()) == before
            assert not events
            content.hide()
            layout.removeWidget(content)
            content.deleteLater()
            QTest.qWait(50)
    finally:
        window.removeEventFilter(recorder)
        window.close()
        window.deleteLater()
        QTest.qWait(30)


def wheel(widget):
    event = QWheelEvent(QPointF(5, 5), QPointF(widget.mapToGlobal(QPoint(5, 5))),
                        QPoint(), QPoint(0, -120), Qt.NoButton, Qt.NoModifier, Qt.NoScrollPhase, False)
    QApplication.sendEvent(widget, event)


def test_combobox_wheel_requires_open_popup_even_if_automatically_focused(application):
    host = QWidget()
    layout = QVBoxLayout(host)
    combo = QComboBox()
    combo.addItems(["one", "two", "three"])
    layout.addWidget(combo)
    host.resize(400, 150)
    host.show()
    host.raise_()
    host.activateWindow()
    QTest.qWaitForWindowActive(host)
    combo.setFocus()
    QTest.qWait(30)
    try:
        wheel(combo)
        assert combo.currentIndex() == 0
        QTest.mouseClick(combo, Qt.LeftButton, pos=combo.rect().center())
        QTest.qWait(350)  # Native Windows popup animation precedes view visibility.
        assert combo.view().isVisible()
        QTest.keyClick(combo.view(), Qt.Key_Down)
        QTest.keyClick(combo.view(), Qt.Key_Return)
        assert combo.currentIndex() == 1
        wheel(combo)
        assert combo.currentIndex() == 1
    finally:
        host.close()
        host.deleteLater()
        QTest.qWait(20)


def test_notice_replaces_text_and_measures_wrapped_height(application):
    host = QWidget()
    host.resize(400, 600)
    notice = widgets.NoticeBar(host)
    host.show()
    try:
        for text in ("安全扫描完成", "已移入回收站", "同步完成", "<条目>已删除", "较长的同步结果说明。" * 24):
            notice.show_message(text)
            QTest.qWait(30)
            assert notice.label.text() == text
            assert notice.isVisible()
            assert notice.label.textFormat() == Qt.PlainText
            assert notice.height() >= notice.layout().totalHeightForWidth(notice.width())
    finally:
        host.close()
        host.deleteLater()
        QTest.qWait(20)
