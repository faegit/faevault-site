"""程序入口：登录或创建本地库 -> 打开主窗口。"""

from __future__ import annotations

import sys

if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()

from PySide6.QtCore import QLocale, QSharedMemory
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

    dlg = UnlockDialog()
    dlg.setWindowIcon(widgets.app_icon())
    if dlg.exec() != QDialog.Accepted:
        _log.info("用户取消登录，程序退出")
        return 0

    # MainWindow pulls in cloud sync, importers, security scanning and the full
    # entry editor. None of those modules are needed to display the unlock
    # screen, so keep them off the cold-start path. This also matters for the
    # packaged build, where importing the large module graph is more expensive.
    from ui.app import MainWindow

    _log.info("登录成功，用户「%s」，载入 %d 条记录", config.get_current_user(), len(dlg.vault.entries))
    window = MainWindow(dlg.vault)
    window.show()
    code = app.exec()
    _log.info("程序正常退出，返回码 %d", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
