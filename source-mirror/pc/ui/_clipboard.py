"""跨平台剪贴板操作。

隐身复制仅在 Windows 10 1703+ 上实际生效（排除 Win+V 历史）；
其他平台 / 旧版 Windows 退化为普通复制，不影响使用。
"""

from __future__ import annotations

import base64
import hashlib
import sys
import time

from PySide6.QtGui import QGuiApplication

from core import config

# ── 公共接口 ──────────────────────────────────────────────


def copy_stealth(text: str) -> None:
    """复制文本到剪贴板，并附带排除监控标记（隐身）。

    Windows 10 1703+ 使用 ExcludeClipboardContentFromMonitorProcessing
    格式标记，让内容不出现在 Win+V 历史中。其他平台退化为普通复制。
    """
    if sys.platform == "win32":
        _stealth_win32(text)
    else:
        QGuiApplication.clipboard().setText(text)


def copy_image(b64_data: str) -> None:
    """复制 base64 编码的图片到剪贴板。"""
    if sys.platform == "win32":
        _image_win32(b64_data)
    else:
        _image_qt(b64_data)


def clear_if_match(expected: str) -> None:
    """如果当前剪贴板内容与 expected 相同，则清除。"""
    cb = QGuiApplication.clipboard()
    if cb.text() == expected:
        cb.clear()
    sweep_expired_text()


def remember_text_expiry(text: str, seconds: int) -> None:
    """Store only an encrypted-config digest and expiry for crash recovery."""
    if seconds <= 0:
        return
    config.set("clipboard_cleanup", {
        "digest": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "expires_at": time.time() + seconds,
    })


def sweep_expired_text() -> None:
    """Clear our expired text after a restart or when the app regains focus."""
    state = config.get("clipboard_cleanup")
    if not isinstance(state, dict):
        return
    try:
        expires_at = float(state["expires_at"])
        digest = str(state["digest"])
    except (KeyError, TypeError, ValueError):
        config.set("clipboard_cleanup", None)
        return
    if time.time() < expires_at:
        return
    cb = QGuiApplication.clipboard()
    mime = cb.mimeData()
    if mime is not None and mime.hasText() and hashlib.sha256(cb.text().encode("utf-8")).hexdigest() == digest:
        cb.clear()
    config.set("clipboard_cleanup", None)


def clear_image_if_present() -> None:
    """Clear image clipboard content without passing a Qt method as a callback."""
    cb = QGuiApplication.clipboard()
    mime = cb.mimeData()
    if mime is not None and mime.hasImage():
        cb.clear()


# ── Win32 隐身复制 ────────────────────────────────────────

_EXCLUDE_FORMAT: int | None = None


def _init_exclude_format() -> int | None:
    if sys.platform != "win32":
        return None
    try:
        import win32clipboard

        return win32clipboard.RegisterClipboardFormat("ExcludeClipboardContentFromMonitorProcessing")
    except Exception:
        return None


_EXCLUDE_FORMAT = _init_exclude_format()


def _stealth_win32(text: str) -> None:
    import ctypes
    import ctypes.wintypes as wt

    import win32con

    k32 = ctypes.windll.kernel32
    u32 = ctypes.windll.user32

    k32.GlobalAlloc.restype = ctypes.c_void_p
    k32.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
    k32.GlobalLock.restype = ctypes.c_void_p
    k32.GlobalLock.argtypes = [ctypes.c_void_p]
    k32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    u32.OpenClipboard.argtypes = [ctypes.c_void_p]
    u32.SetClipboardData.restype = ctypes.c_void_p
    u32.SetClipboardData.argtypes = [wt.UINT, ctypes.c_void_p]

    encoded = (text + "\0").encode("utf-16-le")
    hmem = k32.GlobalAlloc(0x0002, len(encoded))
    ptr = k32.GlobalLock(hmem)
    ctypes.memmove(ptr, encoded, len(encoded))
    k32.GlobalUnlock(hmem)

    hmem_excl = k32.GlobalAlloc(0x0002, 1)

    u32.OpenClipboard(0)
    u32.EmptyClipboard()
    u32.SetClipboardData(win32con.CF_UNICODETEXT, hmem)
    if _EXCLUDE_FORMAT is not None:
        u32.SetClipboardData(_EXCLUDE_FORMAT, hmem_excl)
    u32.CloseClipboard()


# ── Win32 图片复制 ────────────────────────────────────────


def _image_win32(b64_data: str) -> None:
    import io as _io

    import win32clipboard
    import win32con
    from PIL import Image

    img_data = base64.b64decode(b64_data)
    img = Image.open(_io.BytesIO(img_data))
    img = img.convert("RGBA") if img.mode in ("RGBA", "LA", "PA") else img.convert("RGB")

    buf = _io.BytesIO()
    img.save(buf, format="BMP")
    dib = buf.getvalue()[14:]

    win32clipboard.OpenClipboard()
    try:
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32con.CF_DIB, dib)
        if _EXCLUDE_FORMAT is not None:
            try:
                win32clipboard.SetClipboardData(_EXCLUDE_FORMAT, b"\x00")
            except Exception:
                pass
    finally:
        win32clipboard.CloseClipboard()


# ── Qt 图片复制（非 Windows 后备）──────────────────────────


def _image_qt(b64_data: str) -> None:
    from PySide6.QtGui import QImage

    img_data = base64.b64decode(b64_data)
    qimg = QImage.fromData(img_data)
    QGuiApplication.clipboard().setImage(qimg)
