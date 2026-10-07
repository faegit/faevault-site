"""程序入口：登录或创建本地库 -> 打开主窗口。"""

from __future__ import annotations

import sys

if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()

from PySide6.QtCore import QEvent, QObject, QLocale, QSharedMemory, QTimer
from PySide6.QtWidgets import QApplication, QDialog

from core import config, startup
from core import log as _log_mod
from core.storage import vault_dir
from ui import i18n, widgets
from ui.dialogs import UnlockDialog
from ui.theme import stylesheet

_log = _log_mod.get("main")

_SHARED_MEM_KEY = "FAEVault_SingleInstance"
_PASSKEY_UNLOCK_ARGUMENT = "--passkey-unlock"


def _passkey_unlock_requested(argv: list[str] | None = None) -> bool:
    """Recognize the one non-secret activation argument accepted by the native provider."""
    values = list(sys.argv[1:] if argv is None else argv)
    return values == [_PASSKEY_UNLOCK_ARGUMENT]


class _FirstPaintHandoff(QObject):
    """Release the modal login only after the main window paints once."""

    def __init__(self, window, dialog):
        super().__init__(window)
        self._window = window
        self._dialog = dialog
        self._ready = False
        window.installEventFilter(self)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Paint and not self._ready:
            self._ready = True
            self._window.removeEventFilter(self)
            QTimer.singleShot(0, self, self._finish)
        return False

    def _finish(self):
        self._dialog.finish_handoff()
        self._window.raise_()
        self._window.activateWindow()


def main() -> "int":
    passkey_unlock_requested = _passkey_unlock_requested()
    # 单实例检测
    shm = QSharedMemory(_SHARED_MEM_KEY)
    if not shm.create(1):
        _log.info("检测到已有实例在运行，激活已有窗口后退出")
        return 0

    _log_mod.setup(log_file=vault_dir() / "vault_pc.log")
    _log.info("程序启动，Python %s，平台 %s", sys.version.split()[0], sys.platform)
    if passkey_unlock_requested:
        _log.info("收到 Windows Passkey 解锁激活请求")

    purged = config.purge_expired_accounts()
    if purged:
        _log.info("已清理 %d 个超期账户：%s", len(purged), "、".join(purged))

    app = QApplication(sys.argv)
    widgets.install_combobox_wheel_guard()
    app.setWindowIcon(widgets.app_icon())
    i18n.install(app, config.language_mode(), QLocale.system().name())
    app.setStyleSheet(stylesheet(config.theme_mode()))

    if startup.silent_requested():
        from ui.startup import LockedStartupSession

        session = LockedStartupSession(app)
        if session.start():
            _log.info("静默启动：保险库保持锁定，等待托盘激活")
            return app.exec()
        _log.info("系统托盘不可用，改为显示解锁窗口")

    windows = []

    def prepare_handoff(dialog):
        # Construct on the UI thread while the completed login stays visible.
        from ui.app import MainWindow

        window = MainWindow(dialog.vault)
        windows.append(window)
        ready = _FirstPaintHandoff(window, dialog)
        window._unlock_handoff = ready
        window.show()

    dlg = UnlockDialog(prepare_handoff=prepare_handoff)
    dlg.setWindowIcon(widgets.app_icon())
    if dlg.exec() != QDialog.Accepted:
        _log.info("用户取消登录，程序退出")
        return 0

    _log.info("登录成功，用户「%s」，载入 %d 条记录", config.get_current_user(), len(dlg.vault.entries))
    code = app.exec()
    _log.info("程序正常退出，返回码 %d", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
