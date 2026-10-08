import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace
import pytest
from PySide6.QtWidgets import QApplication, QWidget, QDialog, QPushButton
from core import deletion_baseline as d, device_activity
from ui import app as app_module
from tests.test_deletion_baseline import OWN, OTHER, metadata

@pytest.mark.parametrize("ready", [False, True])
def test_cleanup_disabled_until_ready_and_second_cancel_keeps_data(monkeypatch, ready):
    application = QApplication.instance() or QApplication([])
    parent = QWidget()
    m = d.start(metadata(), OWN)
    if ready:
        m = d.acknowledge(m, OTHER)
    calls = []
    parent.vault = SimpleNamespace(metadata=m, _purge_tombstones=m["purge_tombstones"], deletion_cleanup_state=lambda: (m[d.FIELD], ready), finish_deletion_cleanup=lambda cp: calls.append(cp))
    monkeypatch.setattr(device_activity, "current_device_id", lambda v: OWN)
    confirms = iter([True, False])
    monkeypatch.setattr(app_module.widgets, "confirm", lambda *a, **k: next(confirms))
    def execute(dialog):
        finish = next(b for b in dialog.findChildren(QPushButton) if b.text() == "清理删除记录")
        assert finish.isEnabled() == ready
        if ready:
            finish.click()
        return 0
    monkeypatch.setattr(QDialog, "exec", execute)
    app_module.MainWindow._open_deletion_cleanup(parent)
    assert calls == []
    parent.deleteLater()


def test_cleanup_guard_errors_are_localized():
    from ui import i18n
    previous = i18n.current_locale()
    try:
        i18n.set_locale("en")
        assert i18n.tr_dynamic("清理条件已变化，请所有设备重新同步") == "Cleanup conditions changed. Synchronize all devices again."
        assert i18n.tr_dynamic("删除记录检查点无效") == "Invalid deletion-record checkpoint."
    finally:
        i18n.set_locale(previous)
