"""Current-user Windows login startup registration and launch preferences."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from . import config

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE = "FAEVault"


def launch_command() -> str:
    if getattr(sys, "frozen", False):
        args = [sys.executable]
    else:
        executable = Path(sys.executable)
        windowless = executable.with_name("pythonw.exe")
        args = [str(windowless if windowless.exists() else executable),
                str(Path(__file__).resolve().parents[1] / "__main__.py")]
    return subprocess.list2cmdline([*args, "--autostart"])


def is_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, kind = winreg.QueryValueEx(key, RUN_VALUE)
        return kind == winreg.REG_SZ and bool(value)
    except FileNotFoundError:
        return False


def set_enabled(enabled: bool) -> None:
    if sys.platform != "win32":
        raise OSError("开机启动仅支持 Windows")
    import winreg

    if enabled:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, launch_command())
    else:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, RUN_VALUE)
        except FileNotFoundError:
            pass


def silent_requested(argv: list[str] | None = None) -> bool:
    args = sys.argv[1:] if argv is None else argv
    if "--passkey-unlock" in args or "--show" in args:
        return False
    return "--silent" in args or bool(config.get("silent_start", False))
