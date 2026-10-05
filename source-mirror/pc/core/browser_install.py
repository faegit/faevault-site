"""Per-user installation for browser extension Native Messaging integration."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .browser_autofill import CHROMIUM_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME
from .storage import vault_dir

if os.name == "nt":
    import winreg


CHROMIUM_REGISTRY_ROOTS = (
    rf"Software\Google\Chrome\NativeMessagingHosts\{HOST_NAME}",
    rf"Software\Microsoft\Edge\NativeMessagingHosts\{HOST_NAME}",
    rf"Software\Chromium\NativeMessagingHosts\{HOST_NAME}",
)
FIREFOX_REGISTRY_ROOT = rf"Software\Mozilla\NativeMessagingHosts\{HOST_NAME}"


@dataclass(frozen=True)
class InstallStatus:
    installed: bool
    host_exists: bool
    chromium_registered: bool
    firefox_registered: bool
    extension_dir: Path


def install(host_executable: Path | str, extension_source: Path | str) -> InstallStatus:
    if os.name != "nt":
        raise OSError("通行密钥组件安装目前仅支持 Windows")
    host = Path(host_executable).resolve()
    source = Path(extension_source).resolve()
    if not host.is_file():
        raise FileNotFoundError(f"未找到本机宿主：{host}")
    if not (source / "manifest.json").is_file():
        raise FileNotFoundError(f"未找到浏览器扩展：{source}")

    install_dir = vault_dir() / "browser_autofill"
    extension_dir = install_dir / "extension"
    manifests_dir = install_dir / "native_manifests"
    if extension_dir.exists():
        shutil.rmtree(extension_dir)
    _copy_extension(source, extension_dir / "chromium")
    _copy_extension(source, extension_dir / "firefox")
    shutil.copy2(source / "manifest.firefox.json", extension_dir / "firefox" / "manifest.json")
    manifests_dir.mkdir(parents=True, exist_ok=True)

    chromium_manifest = manifests_dir / f"{HOST_NAME}.chromium.json"
    firefox_manifest = manifests_dir / f"{HOST_NAME}.firefox.json"
    _write_json(
        chromium_manifest,
        {
            "name": HOST_NAME,
            "description": "Vault PC browser autofill host",
            "path": str(host),
            "type": "stdio",
            "allowed_origins": [f"chrome-extension://{CHROMIUM_EXTENSION_ID}/"],
        },
    )
    _write_json(
        firefox_manifest,
        {
            "name": HOST_NAME,
            "description": "Vault PC browser autofill host",
            "path": str(host),
            "type": "stdio",
            "allowed_extensions": [FIREFOX_EXTENSION_ID],
        },
    )
    for key_path in CHROMIUM_REGISTRY_ROOTS:
        _set_registry_default(key_path, chromium_manifest)
    _set_registry_default(FIREFOX_REGISTRY_ROOT, firefox_manifest)
    return status()


def uninstall() -> InstallStatus:
    if os.name != "nt":
        raise OSError("通行密钥组件安装目前仅支持 Windows")
    for key_path in (*CHROMIUM_REGISTRY_ROOTS, FIREFOX_REGISTRY_ROOT):
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except FileNotFoundError:
            pass
    install_dir = vault_dir() / "browser_autofill"
    if install_dir.exists():
        shutil.rmtree(install_dir)
    return status()


def status() -> InstallStatus:
    extension_dir = vault_dir() / "browser_autofill" / "extension"
    paths = [_registry_default(key_path) for key_path in CHROMIUM_REGISTRY_ROOTS]
    firefox_path = _registry_default(FIREFOX_REGISTRY_ROOT)
    chromium_registered = bool(paths) and all(path and Path(path).is_file() for path in paths)
    firefox_registered = bool(firefox_path and Path(firefox_path).is_file())
    host_path = _host_from_manifest(next((path for path in paths if path), firefox_path))
    host_exists = bool(host_path and host_path.is_file())
    installed = (
        host_exists
        and chromium_registered
        and firefox_registered
        and (extension_dir / "chromium" / "manifest.json").is_file()
        and (extension_dir / "firefox" / "manifest.json").is_file()
    )
    return InstallStatus(installed, host_exists, chromium_registered, firefox_registered, extension_dir)


def find_built_host(project_root: Path | str) -> Path | None:
    root = Path(project_root)
    candidates = (
        root / "dist" / "VaultBrowserHost.exe",
        Path(sys.executable).with_name("VaultBrowserHost.exe"),
    )
    return next((path.resolve() for path in candidates if path.is_file()), None)


def launch_extension_manager(browser: str, extension_dir: Path | str) -> None:
    if os.name != "nt":
        return
    targets = {
        "chrome": (Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe", "chrome://extensions"),
        "edge": (Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Microsoft/Edge/Application/msedge.exe", "edge://extensions"),
        "firefox": (Path(os.environ.get("PROGRAMFILES", "")) / "Mozilla Firefox/firefox.exe", "about:debugging#/runtime/this-firefox"),
    }
    executable, page = targets.get(browser, (Path(), ""))
    if not executable.is_file():
        raise FileNotFoundError("未找到所选浏览器")
    subprocess.Popen([str(executable), page], close_fds=True)
    folder = Path(extension_dir) / ("firefox" if browser == "firefox" else "chromium")
    os.startfile(str(folder.resolve()))


def _copy_extension(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns("manifest.firefox.json", "*.zip", "__pycache__")
    shutil.copytree(source, destination, ignore=ignored)


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def _set_registry_default(key_path: str, manifest: Path) -> None:
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, str(manifest.resolve()))


def _registry_default(key_path: str) -> str | None:
    if os.name != "nt":
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
            value, kind = winreg.QueryValueEx(key, "")
            return str(value) if kind == winreg.REG_SZ else None
    except FileNotFoundError:
        return None


def _host_from_manifest(path: str | None) -> Path | None:
    if not path:
        return None
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        host = value.get("path")
        return Path(host) if isinstance(host, str) and host else None
    except (OSError, json.JSONDecodeError):
        return None
