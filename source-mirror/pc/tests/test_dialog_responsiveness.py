"""Regression coverage for dialog work that must not block the click handler."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from core.models import SecretType
from ui import dialogs


def test_entry_dialog_builds_only_the_initial_type_page(monkeypatch):
    QApplication.instance() or QApplication([])
    built: list[str] = []
    original = dialogs.EntryDialog._build_page

    def record_build(self, secret_type: str):
        built.append(secret_type)
        return original(self, secret_type)

    monkeypatch.setattr(dialogs.EntryDialog, "_build_page", record_build)
    dialog = dialogs.EntryDialog(default_type=SecretType.LOGIN)

    assert built == [SecretType.LOGIN]
    wifi_index = SecretType.CREATABLE.index(SecretType.WIFI)
    dialog.type_combo.setCurrentIndex(wifi_index)
    assert built == [SecretType.LOGIN, SecretType.WIFI]
    assert hasattr(dialog.stacked.currentWidget(), "wifi_password")
    dialog.close()


def test_wifi_dialog_does_not_scan_profiles_during_construction(monkeypatch):
    QApplication.instance() or QApplication([])
    scanned = False

    def scan_profiles():
        nonlocal scanned
        scanned = True
        return []

    monkeypatch.setattr(dialogs.importers, "available_wifi_profiles", scan_profiles)
    dialog = dialogs.WifiImportDialog()

    assert not scanned
    assert not dialog._run_button.isEnabled()
    dialog.close()


def test_entry_dialog_destroy_cancels_pending_refit():
    from PySide6.QtCore import QCoreApplication, QEvent
    from shiboken6 import isValid

    app = QApplication.instance() or QApplication([])
    dialog = dialogs.EntryDialog(default_type=SecretType.LOGIN)
    dialog._refit_entry_dialog()
    dialog.deleteLater()
    QCoreApplication.sendPostedEvents(dialog, QEvent.DeferredDelete)
    assert not isValid(dialog)
    app.processEvents()


def _update_info():
    from core import updates

    return updates.UpdateInfo(
        version="4.6.5",
        notes="n",
        page_url="https://github.com/faegit/faevault-site/releases/tag/pc/v4.6.5",
        download_url=(
            "https://github.com/faegit/faevault-site/releases/download/pc/v4.6.5/"
            "FAEVault_v4.6.5_Setup.exe"
        ),
    )


def test_update_dialog_does_not_start_the_worker_during_construction(monkeypatch):
    """构造期就 start() 会让下载在窗口显示之前就跑起来。

    下载是十几秒起步的外部请求，进度条得让人先看见窗口再动。
    """
    QApplication.instance() or QApplication([])
    started = []
    monkeypatch.setattr(dialogs._UpdateDownloadWorker, "start", lambda self: started.append(self))
    dialog = dialogs.UpdateDownloadDialog(None, _update_info())
    assert started == []
    dialog.close()


def test_update_dialog_locks_closing_once_the_installer_is_running(monkeypatch):
    """进入安装阶段就不能再让用户关窗。

    回归：原先安装器 Popen 的返回值被丢弃，界面打印一句「安装程序将立即在
    后台运行」就倒计时退出，且窗口随时可关——用户以为取消了，文件替换却仍在
    进行。这里要锁死关闭键与取消按钮。
    """
    QApplication.instance() or QApplication([])
    monkeypatch.setattr(dialogs._UpdateDownloadWorker, "start", lambda self: None)
    dialog = dialogs.UpdateDownloadDialog(None, _update_info())
    try:
        assert dialog._cancel_btn.isEnabled(), "下载阶段应可取消"

        from core import updates

        dialog._on_stage(updates.InstallStage.VERIFYING)
        assert not dialog._cancel_btn.isEnabled(), "校验起不得再可取消"
        assert not dialog.title_bar._buttons._close.isEnabled(), "校验起不得再能关窗"
        assert dialog._bar.maximum() == 0, "无百分比阶段应走不确定态"

        dialog._on_stage(updates.InstallStage.INSTALLING)
        assert "正在安装" in dialog._label.text()

        dialog._on_stage(updates.InstallStage.DONE)
        assert dialog._bar.value() == 100
        assert "安装完成" in dialog._label.text()
    finally:
        dialog.close()


def test_update_dialog_keeps_the_window_when_the_installer_fails(monkeypatch):
    """安装失败要留在窗口里说清楚，不能直接关掉。"""
    QApplication.instance() or QApplication([])
    monkeypatch.setattr(dialogs._UpdateDownloadWorker, "start", lambda self: None)
    dialog = dialogs.UpdateDownloadDialog(None, _update_info())
    try:
        dialog._on_failed("安装程序返回错误代码 5")
        assert "更新失败" in dialog._label.text()
        assert dialog._cancel_btn.isEnabled(), "失败后应允许关闭/重试"
    finally:
        dialog.close()
