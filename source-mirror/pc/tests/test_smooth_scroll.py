"""Wheel input should move entry content continuously, independently of row height."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QPoint, QPointF, Qt
from PySide6.QtGui import QWheelEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QListWidget
from ui.smooth_scroll import enable_smooth_scroll


def app():
    return QApplication.instance() or QApplication([])


def wheel(view, *, angle=-120, pixels=0):
    event = QWheelEvent(QPointF(40, 40), QPointF(40, 40), QPoint(0, pixels),
                        QPoint(0, angle), Qt.NoButton, Qt.NoModifier,
                        Qt.NoScrollPhase, False)
    QApplication.sendEvent(view.viewport(), event)


def list_view():
    app()
    view = QListWidget()
    view.resize(240, 240)
    for index in range(80):
        view.addItem(f"Entry {index}")
    controller = enable_smooth_scroll(view)
    view.show()
    app().processEvents()
    return view, controller


def test_wheel_moves_rows_through_intermediate_positions():
    view, controller = list_view()
    try:
        positions = []
        view.verticalScrollBar().valueChanged.connect(positions.append)
        wheel(view)
        assert view.verticalScrollBar().value() == 0
        QTest.qWait(240)
        assert len(set(positions)) >= 4
        assert 0 < positions[0] < positions[-1]
        assert positions[-1] == 72
        assert view.visualItemRect(view.item(0)).top() < 0
    finally:
        view.close()


def test_multiple_wheel_notches_accumulate_without_losing_distance():
    view, controller = list_view()
    try:
        wheel(view)
        wheel(view)
        QTest.qWait(240)
        assert view.verticalScrollBar().value() == 144
        wheel(view, angle=120)
        QTest.qWait(240)
        assert view.verticalScrollBar().value() == 72
    finally:
        view.close()


def test_touchpad_pixels_are_applied_directly_without_extra_animation():
    view, controller = list_view()
    try:
        wheel(view, angle=0, pixels=-13)
        assert view.verticalScrollBar().value() == 13
        QTest.qWait(240)
        assert view.verticalScrollBar().value() == 13
    finally:
        view.close()


def test_dragging_scrollbar_cancels_pending_wheel_motion():
    view, controller = list_view()
    try:
        wheel(view)
        QTest.qWait(30)
        view.verticalScrollBar().sliderPressed.emit()
        view.verticalScrollBar().setValue(200)
        QTest.qWait(240)
        assert view.verticalScrollBar().value() == 200
    finally:
        view.close()


def test_replaced_scrollbar_does_not_use_deleted_native_object():
    from PySide6.QtWidgets import QScrollBar
    from shiboken6 import isValid
    view, controller = list_view()
    try:
        old_bar = view.verticalScrollBar()
        replacement = QScrollBar(Qt.Vertical)
        replacement.setRange(0, 2000)
        view.setVerticalScrollBar(replacement)
        app().processEvents()
        assert not isValid(old_bar)
        wheel(view)
        QTest.qWait(240)
        assert replacement.value() > 0
    finally:
        view.close()


def test_late_wheel_event_after_scrollbar_destruction_is_ignored():
    from shiboken6 import delete
    view, controller = list_view()
    viewport = view.viewport()
    delete(view)
    event = QWheelEvent(QPointF(40, 40), QPointF(40, 40), QPoint(), QPoint(0, -120),
                        Qt.NoButton, Qt.NoModifier, Qt.NoScrollPhase, False)
    assert controller.eventFilter(viewport, event) is False


def test_touchpad_interrupts_wheel_without_jumping_to_its_pending_target():
    view, controller = list_view()
    try:
        wheel(view)
        QTest.qWait(30)
        current = view.verticalScrollBar().value()
        wheel(view, angle=0, pixels=-13)
        assert view.verticalScrollBar().value() == current + 13
        QTest.qWait(240)
        assert view.verticalScrollBar().value() == current + 13
    finally:
        view.close()
