"""Floating glass controls with cached, bounded backdrop blur."""

from PySide6.QtCore import QEvent, QObject, QPoint, QRect, Qt, QTimer
from PySide6.QtGui import QColor, QImage, QPainter, QPainterPath, QPixmap
from PySide6.QtWidgets import (
    QAbstractScrollArea, QFrame, QGraphicsDropShadowEffect, QPushButton, QWidget,
)
from shiboken6 import isValid
from PIL import Image, ImageFilter
from . import theme


class _BackdropSampler(QObject):
    """Capture only the small region behind a control, outside paintEvent."""
    _PADDING = 16

    def __init__(self, button):
        super().__init__(button)
        self.button = button
        self.source = None
        self._capturing = False
        self._last_image = QImage()
        self._base_color = None
        self._offset = QPoint()
        button._backdrop = QPixmap()
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(32)
        self.timer.timeout.connect(self.refresh)
        button.installEventFilter(self)

    def bind(self, area):
        self.source = area.viewport()
        self._watch_content(self.source)
        area.verticalScrollBar().valueChanged.connect(self.invalidate)
        area.horizontalScrollBar().valueChanged.connect(self.invalidate)
        self.invalidate()

    def _watch_content(self, widget):
        widget.installEventFilter(self)
        for child in widget.findChildren(QWidget):
            child.installEventFilter(self)

    def invalidate(self, *_args):
        if not isValid(self) or not isValid(self.button):
            return
        if self.button.isVisible() and not self._capturing and not self.timer.isActive():
            self.timer.start()

    def clear(self):
        self.timer.stop()
        self._last_image = QImage()
        self.button._backdrop = QPixmap()

    def eventFilter(self, obj, event):
        if not isValid(self) or not isValid(self.button):
            return False
        kind = event.type()
        if kind in (QEvent.ChildAdded, QEvent.ChildPolished):
            child = event.child()
            if isinstance(child, QWidget) and isValid(child):
                self._watch_content(child)
                self.invalidate()
        if obj is self.button and kind == QEvent.Hide:
            self.clear()
        elif kind in (QEvent.Paint, QEvent.Resize, QEvent.Move, QEvent.Show, QEvent.LayoutRequest):
            if obj is not self.button or kind != QEvent.Paint:
                self.invalidate()
        return False

    def refresh(self):
        if not self.button.isVisible() or self.source is None or not isValid(self.source):
            self.clear()
            return
        # The button and viewport are siblings, not ancestors of one another.
        origin = self.source.mapFromGlobal(self.button.mapToGlobal(QPoint()))
        rect = QRect(origin, self.button.size()).adjusted(
            -self._PADDING, -self._PADDING, self._PADDING, self._PADDING,
        ).intersected(self.source.rect())
        if rect.isEmpty():
            self.clear()
            self.button.update()
            return
        self._capturing = True
        try:
            captured = self.source.grab(rect)
        finally:
            self._capturing = False
        image = captured.toImage().convertToFormat(QImage.Format_RGBA8888)
        offset = rect.topLeft() - origin
        base_color = theme.active()["surface"]
        if image == self._last_image and offset == self._offset and base_color == self._base_color:
            return
        self._last_image = image
        self._offset = offset
        self._base_color = base_color
        if image.isNull():
            self.clear()
            return
        # Work on a downsampled button-sized image; no full viewport or graphics scene.
        pixels = Image.frombytes("RGBA", (image.width(), image.height()), bytes(image.constBits()),
                                 "raw", "RGBA", image.bytesPerLine())
        # Transparent labels must not leave holes through which sharp text shows.
        pixels = Image.alpha_composite(Image.new("RGBA", pixels.size, base_color), pixels)
        small = pixels.resize((max(1, image.width() // 2), max(1, image.height() // 2)), Image.Resampling.BILINEAR)
        blurred = small.filter(ImageFilter.GaussianBlur(4 * captured.devicePixelRatio()))
        blurred = blurred.resize(pixels.size, Image.Resampling.BILINEAR)
        data = blurred.tobytes()
        result = QImage(data, blurred.width, blurred.height, blurred.width * 4, QImage.Format_RGBA8888).copy()
        result.setDevicePixelRatio(captured.devicePixelRatio())
        self.button._backdrop = QPixmap.fromImage(result)
        self.button.update()

    def paint(self):
        if self.button._backdrop.isNull():
            return
        painter = QPainter(self.button)
        painter.setRenderHint(QPainter.Antialiasing)
        clip = QPainterPath()
        clip.addRoundedRect(self.button.rect().toRectF(), 12, 12)
        painter.setClipPath(clip)
        painter.drawPixmap(self._offset, self.button._backdrop)
        painter.end()


class TranslucentSurface:
    """半透明表面、投影和按需更新的局部背景模糊。"""

    def _init_surface(self) -> None:
        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(18)
        shadow.setOffset(0, 5)
        shadow.setColor(QColor(0, 0, 0, 48))
        self.setGraphicsEffect(shadow)
        self._backdrop_sampler = _BackdropSampler(self)

    def set_backdrop_source(self, area: QAbstractScrollArea) -> None:
        self._backdrop_sampler.bind(area)

    def paintEvent(self, event):
        self._backdrop_sampler.paint()
        super().paintEvent(event)


class TranslucentActionButton(TranslucentSurface, QPushButton):
    """半透明、带投影的悬浮操作按钮。"""

    def __init__(self, text: str, parent: QWidget | None = None):
        super().__init__(text, parent)
        self._init_surface()


class BottomFloatingAction(TranslucentActionButton):
    """Keep an action centered above the bottom of a scrolling panel."""

    def __init__(self, text: str, host: QWidget):
        super().__init__(text, host)
        self.setFixedHeight(48)
        if isinstance(host, QAbstractScrollArea):
            self.set_backdrop_source(host)
        host.installEventFilter(self)

    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if obj is self.parentWidget() and event.type() in (QEvent.Resize, QEvent.Show):
            self._position()
        return super().eventFilter(obj, event)

    def _position(self) -> None:
        host = self.parentWidget()
        if host is None:
            return
        width = min(max(220, int(host.width() * 0.5)), max(120, host.width() - 32))
        self.setGeometry(max(16, (host.width() - width) // 2), max(16, host.height() - 68), width, 48)
        self.raise_()


class TranslucentPanel(TranslucentSurface, QFrame):
    """半透明容器，用于承载并排的多个操作。"""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._init_surface()
