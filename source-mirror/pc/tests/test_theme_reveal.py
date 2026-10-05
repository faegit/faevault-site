from PySide6.QtCore import QPoint
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import QApplication, QWidget

from ui.theme_reveal import ThemeRevealOverlay, reveal_radius


def test_theme_reveal_opens_from_logo_and_covers_farthest_corner():
    app = QApplication.instance() or QApplication([])
    window = QWidget()
    window.resize(100, 80)
    window.setStyleSheet("background: blue")
    window.show()
    app.processEvents()

    old_frame = QPixmap(window.size())
    old_frame.fill(QColor("red"))
    overlay = ThemeRevealOverlay(window, old_frame, QPoint(10, 10))
    overlay._animation.stop()
    overlay.set_radius(12)
    app.processEvents()

    rendered = window.grab().toImage()
    assert rendered.pixelColor(10, 10) == QColor("blue")
    assert rendered.pixelColor(95, 75) == QColor("red")
    assert reveal_radius(100, 80, QPoint(10, 10)) > 100

    overlay.finish()
    window.close()
