import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest
from PySide6.QtCore import QPoint, QRect
from PySide6.QtWidgets import QApplication, QPushButton, QWidget
from ui.widgets import UpwardMenu


@pytest.mark.parametrize("button_y", [400, 60])
def test_sidebar_menu_opens_upward_and_stays_inside_window(button_y):
    app = QApplication.instance() or QApplication([])
    window = QWidget()
    window.setGeometry(100, 100, 360, 480)
    button = QPushButton("新建条目", window)
    button.setGeometry(20, button_y, 180, 40)
    menu = UpwardMenu(button)
    button.setMenu(menu)
    for i in range(5):
        menu.addAction(f"Category {i}")
    window.show()
    app.processEvents()
    try:
        menu.popup(button.mapToGlobal(QPoint(0, button.height())))
        app.processEvents()
        bounds = QRect(window.mapToGlobal(QPoint()), window.size())
        assert bounds.contains(menu.geometry())
        if button_y == 400:
            assert menu.geometry().bottom() < button.mapToGlobal(QPoint()).y()
        assert menu.width() == button.width()
    finally:
        menu.close()
        window.close()
