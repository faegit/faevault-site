"""Status and fixed-command control surface for the Windows Passkey Provider."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


@dataclass(frozen=True)
class ProviderStatus:
    supported: bool
    installed: bool
    registered: bool
    enabled: bool
    cache_healthy: bool
    last_error: str | None = None


Runner = Callable[[Sequence[str], int], subprocess.CompletedProcess[str]]


def _run(command: Sequence[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


class PasskeyProviderStatus:
    PACKAGE_NAME = "FAE.Vault.PasskeyProvider"
    EXECUTABLE = "PasskeyManager.exe"

    def __init__(self, runner: Runner = _run, *, platform: str | None = None,
                 build: int | None = None, revision: int | None = None):
        self._runner = runner
        self._platform = platform or sys.platform
        self._build = build
        self._revision = revision
        self._cache_healthy = False

    def supported(self) -> bool:
        if self._platform != "win32":
            return False
        build, revision = self._windows_version()
        if build in (26100, 26200):
            return revision >= 6725
        return build > 26200

    def query(self) -> ProviderStatus:
        if not self.supported():
            return ProviderStatus(False, False, False, False, False, "当前 Windows 版本不支持第三方 Passkey 提供程序")
        try:
            executable = self._installed_executable()
            if executable is None:
                return ProviderStatus(True, False, False, False, False)
            result = self._runner((str(executable), "--status"), 10)
            if result.returncode in (10, 11):
                return ProviderStatus(True, True, True, result.returncode == 11, self._cache_healthy)
            return ProviderStatus(True, True, False, False, False, self._error(result, "提供程序尚未注册"))
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return ProviderStatus(True, False, False, False, False, str(exc))

    def register(self) -> ProviderStatus:
        self._invoke("--register")
        return self.query()

    def unregister(self) -> ProviderStatus:
        self._invoke("--unregister", allow_absent=True)
        return self.query()

    def repair_cache(self) -> ProviderStatus:
        self._invoke("--reconcile", timeout=30)
        self._cache_healthy = True
        return self.query()

    @staticmethod
    def open_settings() -> None:
        if sys.platform != "win32":
            raise OSError("Windows 设置仅在 Windows 上可用")
        os.startfile("ms-settings:signinoptions-launchsecuritykeyenrollment")  # type: ignore[attr-defined]

    def _invoke(self, argument: str, *, timeout: int = 15, allow_absent: bool = False) -> None:
        executable = self._installed_executable()
        if executable is None:
            if allow_absent:
                return
            raise RuntimeError("FAE Vault Passkey Provider 尚未安装")
        result = self._runner((str(executable), argument), timeout)
        if result.returncode != 0:
            raise RuntimeError(self._error(result, f"操作失败（代码 {result.returncode}）"))

    def _installed_executable(self) -> Path | None:
        command = (
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            f"$p=Get-AppxPackage -Name '{self.PACKAGE_NAME}'; if($p){{$p.InstallLocation}}",
        )
        result = self._runner(command, 10)
        location = (result.stdout or "").strip().splitlines()
        if result.returncode != 0 or not location:
            return None
        root = Path(location[-1].strip()).resolve()
        windows_apps = (Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WindowsApps").resolve()
        try:
            root.relative_to(windows_apps)
        except ValueError as exc:
            raise ValueError("提供程序安装位置未通过系统目录校验") from exc
        executable = root / self.EXECUTABLE
        return executable if executable.is_file() else None

    def _windows_version(self) -> tuple[int, int]:
        if self._build is not None:
            return self._build, int(self._revision or 0)
        version = sys.getwindowsversion()
        revision = 0
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                revision = int(winreg.QueryValueEx(key, "UBR")[0])
        except (OSError, ImportError, ValueError):
            pass
        return int(version.build), revision

    @staticmethod
    def _error(result: subprocess.CompletedProcess[str], fallback: str) -> str:
        text = (result.stderr or result.stdout or "").strip()
        return text[:500] if text else fallback
