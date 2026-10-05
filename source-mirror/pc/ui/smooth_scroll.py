"""Continuous wheel scrolling for entry views; touchpad pixels remain native."""
from PySide6.QtCore import QAbstractAnimation, QEasingCurve, QEvent, QObject, Qt, QVariantAnimation
from PySide6.QtWidgets import QAbstractItemView
from shiboken6 import isValid


class SmoothScroll(QObject):
    def __init__(self, view):
        super().__init__(view)
        self.view = view
        self.bar = view.verticalScrollBar()
        self._setting_value = False
        self._target = self.bar.value()
        self._animation = QVariantAnimation(self)
        self._animation.setDuration(180)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)
        self._animation.valueChanged.connect(self._step)
        view.installEventFilter(self)
        view.viewport().installEventFilter(self)
        self._bind_bar()

    def _bind_bar(self):
        self.bar.valueChanged.connect(self._external_scroll)
        self.bar.sliderPressed.connect(self._stop)
        self.bar.rangeChanged.connect(self._stop)
        self.bar.installEventFilter(self)

    def _stop(self, *_args):
        if isValid(self._animation):
            self._animation.stop()

    def _step(self, value):
        if not isValid(self.bar):
            self._stop()
            return
        self._setting_value = True
        try:
            self.bar.setValue(round(value))
        finally:
            self._setting_value = False

    def _external_scroll(self, _value):
        if not self._setting_value:
            self._stop()

    def eventFilter(self, obj, event):
        # A queued wheel event can outlive the view or its replaced scrollbar.
        if not isValid(self) or not isValid(self.view):
            return False
        if not isValid(self.bar):
            self._stop()
            if event.type() != QEvent.Wheel:
                return False
            self.bar = self.view.verticalScrollBar()
            if not isValid(self.bar):
                return False
            self._bind_bar()
        if event.type() in (QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.Hide):
            self._animation.stop()
        if event.type() != QEvent.Wheel or event.modifiers() != Qt.NoModifier:
            return False
        pixels = event.pixelDelta()
        angle = event.angleDelta()
        if abs(pixels.x()) > abs(pixels.y()) or abs(angle.x()) > abs(angle.y()):
            return False
        delta = -pixels.y() if not pixels.isNull() else -angle.y() * 72 / 120
        if not delta:
            return False
        current = self.bar.value()
        running = self._animation.state() == QAbstractAnimation.Running
        base = self._target if pixels.isNull() and running and (self._target - current) * delta > 0 else current
        target = max(self.bar.minimum(), min(self.bar.maximum(), round(base + delta)))
        if target == current:
            self._animation.stop()
            return False  # Let a surrounding scroll area handle an exhausted inner view.
        self._animation.stop()
        self._target = target
        if not pixels.isNull():
            self.bar.setValue(target)
        else:
            self._animation.setStartValue(float(current))
            self._animation.setEndValue(float(target))
            self._animation.start()
        event.accept()
        return True


def enable_smooth_scroll(view):
    existing = getattr(view, "_smooth_scroll", None)
    if existing is not None:
        return existing
    if isinstance(view, QAbstractItemView):
        view.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
    controller = SmoothScroll(view)
    view._smooth_scroll = controller
    return controller
