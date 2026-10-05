"""Circular reveal between the old and new main-window color modes."""

from __future__ import annotations

from math import hypot

from PySide6.QtCore import Property, QEasingCurve, QEvent, QPoint, QPropertyAnimation, Qt
from PySide6.QtGui import QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import QWidget


def reveal_radius(width: int, height: int, origin: QPoint) -> float:
    """Distance to the farthest corner, so the last frame exposes everything."""
    return max(hypot(x - origin.x(), y - origin.y()) for x in (0, width) for y in (0, height))


class ThemeRevealOverlay(QWidget):
    DURATION_MS = 420

    def __init__(self, parent: QWidget, old_frame: QPixmap, origin: QPoint):
        super().__init__(parent)
        self._old_frame = old_frame
        self._origin = origin
        self._radius = 0.0
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setGeometry(parent.rect())
        self._animation = QPropertyAnimation(self, b"radius", self)
        self._animation.setDuration(self.DURATION_MS)
        self._animation.setStartValue(0.0)
        self._animation.setEndValue(reveal_radius(self.width(), self.height(), origin))
        self._animation.setEasingCurve(QEasingCurve.InOutCubic)
        self._animation.finished.connect(self.finish)
        parent.installEventFilter(self)
        self.show()
        self.raise_()
        self._animation.start()

    def get_radius(self) -> float:
        return self._radius

    def set_radius(self, value: float) -> None:
        self._radius = value
        self.update()

    radius = Property(float, get_radius, set_radius)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        old_region = QPainterPath()
        old_region.addRect(self.rect())
        revealed = QPainterPath()
        revealed.addEllipse(self._origin, self._radius, self._radius)
        painter.setClipPath(old_region.subtracted(revealed))
        painter.drawPixmap(self.rect(), self._old_frame)

    def eventFilter(self, watched, event) -> bool:
        if watched is self.parentWidget() and event.type() == QEvent.Resize:
            self.finish()
        return super().eventFilter(watched, event)

    def finish(self) -> None:
        self._animation.stop()
        parent = self.parentWidget()
        if parent is not None:
            parent.removeEventFilter(self)
            if getattr(parent, "_theme_reveal_overlay", None) is self:
                parent._theme_reveal_overlay = None
        self.hide()
        self._old_frame = QPixmap()
        self.deleteLater()
