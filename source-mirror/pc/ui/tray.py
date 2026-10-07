"""应用级系统托盘：登录阶段与主窗口共用同一个托盘图标。"""

from __future__ import annotations

import os
import time

from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon

from . import i18n, widgets

_tray: QSystemTrayIcon | None = None
_menu: QMenu | None = None
_on_open = None
_last_activation = 0.0
_update_callback = None


def setup_tray(on_open, extra_actions=None) -> QSystemTrayIcon | None:
    """创建（或复用）应用托盘；返回托盘实例，不可用时返回 None。

    ``extra_actions`` 为 ``(文本, 回调)`` 列表，插在“打开保险库”与“退出程序”之间。
    """
    global _tray, _menu, _on_open
    _on_open = on_open
    if _tray is None and (os.name != "nt" or not QSystemTrayIcon.isSystemTrayAvailable()):
        return None
    menu = QMenu()
    menu.addAction(i18n.tr("打开保险库"), _handle_open)
    for text, callback in (extra_actions or ()):
        menu.addAction(text, callback)
    menu.addSeparator()
    menu.addAction(i18n.tr("退出程序"), _handle_quit)
    tray = _tray if _tray is not None else QSystemTrayIcon(widgets.app_icon())
    tray.setToolTip("FAEVault")
    tray.setContextMenu(menu)
    if _tray is None:
        tray.activated.connect(_handle_activated)
        tray.messageClicked.connect(_handle_update_click)
    tray.show()
    if _menu is not None:
        _menu.deleteLater()
    _tray = tray
    _menu = menu
    return tray


def set_open_callback(on_open) -> None:
    global _on_open
    _on_open = on_open


def is_available() -> bool:
    return _tray is not None and _tray.isVisible()


def context_menu() -> QMenu | None:
    return _menu


def _handle_open() -> None:
    if _on_open is not None:
        _on_open()


def _handle_quit() -> None:
    app = QApplication.instance()
    if app is not None:
        app.quit()


def _handle_activated(reason) -> None:
    if reason in (
        QSystemTrayIcon.ActivationReason.Trigger,
        QSystemTrayIcon.ActivationReason.DoubleClick,
    ):
        global _last_activation
        now = time.monotonic()
        # Windows 双击托盘会同时触发 Trigger 与 DoubleClick，去重避免重复打开窗口。
        if now - _last_activation < 0.35:
            return
        _last_activation = now
        _handle_open()


def show_update_notification(callback, title: str, body: str) -> bool:
    """Callback must open the generic overview: Qt cannot identify an older balloon click."""
    global _update_callback
    if not is_available() or not _tray.supportsMessages():
        return False
    _update_callback = callback
    _tray.showMessage(title, body, QSystemTrayIcon.MessageIcon.Information, 10000)
    return True


def _handle_update_click():
    global _update_callback
    callback, _update_callback = _update_callback, None
    if callback is not None:
        callback()
