from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.passkey_provider_status import PasskeyProviderStatus


def completed(command, code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, code, stdout, stderr)


def test_background_provider_probe_never_opens_a_console(monkeypatch):
    from core import passkey_provider_status as module
    captured = {}
    monkeypatch.setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)
    def run(command, **kwargs):
        captured.update(kwargs)
        return completed(command)
    monkeypatch.setattr(subprocess, "run", run)
    module._run(["powershell.exe", "-NoProfile", "-Command", "Get-Date"], 4)
    assert captured["creationflags"] & 0x08000000


def test_supported_build_boundary():
    assert not PasskeyProviderStatus(platform="linux", build=99999, revision=99999).supported()
    assert not PasskeyProviderStatus(platform="win32", build=26100, revision=6724).supported()
    assert PasskeyProviderStatus(platform="win32", build=26100, revision=6725).supported()
    assert PasskeyProviderStatus(platform="win32", build=26200, revision=9168).supported()


def test_query_distinguishes_installed_registered_enabled(monkeypatch, tmp_path):
    windows_apps = tmp_path / "WindowsApps"
    install = windows_apps / "FAE.Vault.PasskeyProvider_test"
    install.mkdir(parents=True)
    (install / "PasskeyManager.exe").write_bytes(b"test")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))

    calls = []
    def runner(command, timeout):
        calls.append(tuple(command))
        if command[0] == "powershell.exe":
            return completed(command, stdout=str(install))
        return completed(command, code=11)

    status = PasskeyProviderStatus(runner, platform="win32", build=26200, revision=9168).query()
    assert status.installed and status.registered and status.enabled and not status.cache_healthy
    assert calls[-1] == (str(install / "PasskeyManager.exe"), "--status")


def test_repair_uses_only_fixed_provider_argument(monkeypatch, tmp_path):
    install = tmp_path / "WindowsApps" / "package"
    install.mkdir(parents=True)
    (install / "PasskeyManager.exe").write_bytes(b"test")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    calls = []
    def runner(command, timeout):
        calls.append((tuple(command), timeout))
        if command[0] == "powershell.exe":
            return completed(command, stdout=str(install))
        return completed(command, code=0 if command[-1] == "--reconcile" else 10)
    adapter = PasskeyProviderStatus(runner, platform="win32", build=26200, revision=9168)
    adapter.repair_cache()
    assert any(command[-1] == "--reconcile" and timeout == 30 for command, timeout in calls)


def test_rejects_package_location_outside_windows_apps(monkeypatch, tmp_path):
    bad = tmp_path / "download"
    bad.mkdir()
    (bad / "PasskeyManager.exe").write_bytes(b"test")
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    def runner(command, timeout):
        return completed(command, stdout=str(bad))
    status = PasskeyProviderStatus(runner, platform="win32", build=26200, revision=9168).query()
    assert not status.installed
    assert "系统目录校验" in (status.last_error or "")


def test_automatic_reconcile_skips_disabled_provider_and_unavailable_pipe(monkeypatch):
    from ui import app as app_ui
    from core import passkey_provider_status as provider_module

    calls = []

    class Provider:
        def query(self):
            calls.append("query")
            return SimpleNamespace(enabled=False)

        def repair_cache(self):
            calls.append("repair")

    class ImmediateThread:
        def __init__(self, *, target, **_kwargs):
            self.target = target

        def start(self):
            self.target()

    monkeypatch.setattr(provider_module, "PasskeyProviderStatus", Provider)
    monkeypatch.setattr(app_ui.threading, "Thread", ImmediateThread)
    window = SimpleNamespace(
        _locked=False, _passkey_cache_reconcile_running=False,
        _passkey_cache_reconcile_next=0.0, _passkey_cache_reconcile_failures=0,
        _passkey_broker_server=SimpleNamespace(is_listening=lambda: False),
    )
    app_ui.MainWindow._schedule_passkey_cache_reconcile(window)
    assert calls == []
    window._passkey_broker_server.is_listening = lambda: True
    app_ui.MainWindow._schedule_passkey_cache_reconcile(window)
    assert calls == ["query"]
