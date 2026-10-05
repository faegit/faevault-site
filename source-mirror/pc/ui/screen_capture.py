"""Windows 窗口的“允许截屏”设置。

通过 Win32 ``SetWindowDisplayAffinity`` 把窗口标记为「禁止被捕获」：
窗口对用户正常可见，但在系统截图、录屏、屏幕共享 / 投屏中显示为黑屏。

- ``WDA_EXCLUDEFROMCAPTURE``（0x11）：Windows 10 2004+ 支持，窗口照常合成，
  仅对捕获接口隐藏，体验最佳。
- ``WDA_MONITOR``（0x01）：旧系统回退方案，效果相同但实现更老。

非 Windows 平台为空操作，返回 ``False``。
"""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QWidget

from core.log import get

_log = get("screen_capture")

WDA_NONE = 0x00
WDA_MONITOR = 0x01
WDA_EXCLUDEFROMCAPTURE = 0x11


def supported() -> bool:
    return sys.platform == "win32"


def apply_permission(window: QWidget, allowed: bool) -> bool:
    """设置顶层窗口是否允许被捕获，返回系统调用是否成功。"""
    if not supported():
        return False
    try:
        import ctypes
        from ctypes import wintypes

        hwnd = int(window.winId())
        if not hwnd:
            return False
        user32 = ctypes.windll.user32
        user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
        user32.SetWindowDisplayAffinity.restype = wintypes.BOOL

        if allowed:
            return bool(user32.SetWindowDisplayAffinity(hwnd, WDA_NONE))
        if user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE):
            return True
        # 旧版本 Windows 不支持 EXCLUDEFROMCAPTURE，回退到 MONITOR
        return bool(user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR))
    except Exception as exc:  # pragma: no cover - 平台相关
        _log.warning("设置允许截屏状态失败：%s", exc)
        return False
