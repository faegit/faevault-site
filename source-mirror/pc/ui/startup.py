"""A locked tray session that creates the unlock UI only on user activation."""

from PySide6.QtWidgets import QDialog

from . import tray, widgets
from .dialogs import UnlockDialog


class LockedStartupSession:
    def __init__(self, app):
        self.app = app
        self.window = None
        self._opening = False

    def start(self) -> bool:
        if tray.setup_tray(self.open) is None:
            return False
        self.app.setQuitOnLastWindowClosed(False)
        return True

    def open(self) -> None:
        if self._opening:
            return
        if self.window is not None:
            self.window._show_from_tray()
            return
        self._opening = True
        try:
            dialog = UnlockDialog()
            dialog.setWindowIcon(widgets.app_icon())
            if dialog.exec() != QDialog.Accepted:
                return
            from .app import MainWindow

            self.window = MainWindow(dialog.vault)
            self.app.setQuitOnLastWindowClosed(True)
            self.window.show()
        finally:
            self._opening = False
