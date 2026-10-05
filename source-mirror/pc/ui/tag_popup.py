"""Tag list with a custom insertion marker for the sort dialog."""

from PySide6.QtCore import QPoint, Qt, QTimer
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QListWidget, QListWidgetItem,
)

from . import theme


class _ReorderTagList(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._insert_row: int | None = None
        self._dragged_item: QListWidgetItem | None = None
        self._press_pos: QPoint | None = None
        self._pointer_pos: QPoint | None = None
        self._dragging = False
        self.setDragDropMode(QAbstractItemView.NoDragDrop)
        self.setDropIndicatorShown(False)
        self.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setInterval(30)
        self._scroll_timer.timeout.connect(self._scroll_during_drag)

    def mousePressEvent(self, event) -> None:
        self._finish_drag()
        super().mousePressEvent(event)
        if event.button() == Qt.LeftButton:
            self._press_pos = event.position().toPoint()
            self._dragged_item = self.itemAt(self._press_pos)

    def mouseMoveEvent(self, event) -> None:
        if self._dragged_item is None or not event.buttons() & Qt.LeftButton:
            super().mouseMoveEvent(event)
            return
        pos = event.position().toPoint()
        if not self._dragging:
            if (pos - self._press_pos).manhattanLength() < QApplication.startDragDistance():
                return
            self._dragging = True
            self.viewport().setCursor(Qt.ClosedHandCursor)
            self._scroll_timer.start()
        self._pointer_pos = pos
        self._update_target()
        event.accept()

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and self._dragging:
            pos = event.position().toPoint()
            if self.viewport().rect().contains(pos):
                self._move_dragged_item(self._row_at(pos))
            self._finish_drag()
            event.accept()
            return
        self._finish_drag()
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event) -> None:
        if event.key() == Qt.Key_Escape and self._dragged_item is not None:
            self._finish_drag()
            event.accept()
            return
        super().keyPressEvent(event)

    def hideEvent(self, event) -> None:
        self._finish_drag()
        super().hideEvent(event)

    def _finish_drag(self) -> None:
        self._scroll_timer.stop()
        self._dragged_item = None
        self._press_pos = None
        self._pointer_pos = None
        self._dragging = False
        self._insert_row = None
        self.viewport().unsetCursor()
        self.viewport().update()

    def _row_at(self, pos: QPoint) -> int:
        # Compare centres even in row gaps or horizontal padding.
        for row in range(self.count()):
            if pos.y() < self.visualItemRect(self.item(row)).center().y():
                return row
        return self.count()

    def _update_target(self) -> None:
        pos = self._pointer_pos
        target = self._row_at(pos) if pos is not None and self.viewport().rect().contains(pos) else None
        source = self.row(self._dragged_item) if self._dragged_item is not None else -1
        self._insert_row = None if target in (source, source + 1) else target
        self.viewport().update()

    def _scroll_during_drag(self) -> None:
        pos = self._pointer_pos
        if pos is None or not 0 <= pos.x() < self.viewport().width():
            return
        bar = self.verticalScrollBar()
        if pos.y() < 24:
            bar.setValue(bar.value() - 12)
        elif pos.y() >= self.viewport().height() - 24:
            bar.setValue(bar.value() + 12)
        self._update_target()

    def _move_dragged_item(self, target: int) -> None:
        item = self._dragged_item
        if item is None:
            return
        source = self.row(item)
        if source < 0 or target in (source, source + 1):
            return
        if target > source:
            target -= 1
        self.takeItem(source)
        self.insertItem(target, item)
        self.setCurrentItem(item)

    def _indicator_y(self, row: int) -> int:
        if row == 0:
            y = self.visualItemRect(self.item(0)).top() - self.spacing() // 2
        elif row == self.count():
            y = self.visualItemRect(self.item(row - 1)).bottom() + self.spacing() // 2 + 1
        else:
            previous = self.visualItemRect(self.item(row - 1))
            following = self.visualItemRect(self.item(row))
            y = (previous.bottom() + following.top() + 1) // 2
        return max(1, min(self.viewport().height() - 2, y))

    def paintEvent(self, event) -> None:
        super().paintEvent(event)
        if self._insert_row is None or not self.count():
            return
        y = self._indicator_y(self._insert_row)
        painter = QPainter(self.viewport())
        painter.setPen(QPen(QColor(theme.active()["accent"]), 2))
        painter.drawLine(8, y, self.viewport().width() - 8, y)
        painter.end()
