"""前台窗口进程名检测（仅 Windows）。"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

_psapi = ctypes.windll.psapi
_kernel32 = ctypes.windll.kernel32
_user32 = ctypes.windll.user32

_USER32 = ctypes.windll.user32


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def foreground_process_name() -> str | None:
    """返回前台窗口所属进程的可执行文件名（小写），失败时返回 None。"""
    try:
        hwnd = _USER32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = wintypes.DWORD()
        _USER32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not pid.value:
            return None
        handle = _kernel32.OpenProcess(0x0400 | 0x0010, False, pid.value)
        if not handle:
            return None
        try:
            buf = ctypes.create_unicode_buffer(260)
            if _psapi.GetModuleBaseNameW(handle, None, buf, 260):
                return buf.value.lower()
            return None
        finally:
            _kernel32.CloseHandle(handle)
    except Exception:
        return None


def running_processes() -> list[str]:
    """返回当前所有运行中的进程名列表（小写去重排序）。"""
    names: set[str] = set()
    try:
        handle = _kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if handle == wintypes.HANDLE(-1).value:
            return []
        try:
            pe = _PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            if _kernel32.Process32FirstW(handle, ctypes.byref(pe)):
                while True:
                    name = pe.szExeFile.lower()
                    if name.endswith(".exe"):
                        names.add(name)
                    if not _kernel32.Process32NextW(handle, ctypes.byref(pe)):
                        break
        finally:
            _kernel32.CloseHandle(handle)
    except Exception:
        pass
    return sorted(names)


def process_path(pid: int) -> str:
    handle = _kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return ""
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if _kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return buffer.value
        return ""
    finally:
        _kernel32.CloseHandle(handle)


def running_process_identities() -> list[tuple[str, str]]:
    """Return unique running executable names and canonical paths."""
    values: dict[tuple[str, str], None] = {}
    try:
        handle = _kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        if handle == wintypes.HANDLE(-1).value:
            return []
        try:
            pe = _PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            if _kernel32.Process32FirstW(handle, ctypes.byref(pe)):
                while True:
                    name = pe.szExeFile.lower()
                    if name.endswith(".exe"):
                        path = process_path(int(pe.th32ProcessID))
                        values[(name, path)] = None
                    if not _kernel32.Process32NextW(handle, ctypes.byref(pe)):
                        break
        finally:
            _kernel32.CloseHandle(handle)
    except Exception:
        return []
    return sorted(values, key=lambda item: (item[0], item[1].casefold()))
