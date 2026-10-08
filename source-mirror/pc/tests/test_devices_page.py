import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QPushButton
from core import device_activity
from ui.devices_page import DevicesPage


def test_readonly_page_refreshes_and_stops_after_close(monkeypatch):
    app = QApplication.instance() or QApplication([])
    state = {"name": "first"}
    calls = []
    def devices(vault):
        calls.append(vault)
        return [{"name": state["name"], "is_current": True, "platform": "pc", "authorized": True, "last_seen_at": 0}]
    monkeypatch.setattr(device_activity, "devices", devices)
    vault = SimpleNamespace()
    page = DevicesPage(vault)
    assert "first" in page.devices_list.item(0).text()
    assert not page.remove_button.isEnabled()
    state["name"] = "second"
    page.refresh_button.click()
    assert "second" in page.devices_list.item(0).text()
    page.show()
    state["name"] = "after OS settings"
    page._application_state_changed(Qt.ApplicationActive)
    assert "after OS settings" in page.devices_list.item(0).text()
    count = len(calls)
    page.close_page("lock")
    page.refresh(vault)
    assert len(calls) == count
    assert not hasattr(page, "restoreRequested")


def test_remove_cancel_refresh_and_close_during_confirmation(monkeypatch):
    app = QApplication.instance() or QApplication([])
    records = [{"device_id": "00000000-0000-0000-0000-000000000008", "name": "<remote>", "is_current": False, "platform": "pc", "authorized": True, "last_seen_at": 0}]
    monkeypatch.setattr(device_activity, "devices", lambda vault: list(records))
    calls = []
    def remove(target):
        calls.append(target)
        records.clear()
    vault = SimpleNamespace(_pmve_store=object(), remove_device_record=remove)
    page = DevicesPage(vault)
    page.devices_list.setCurrentRow(0)
    monkeypatch.setattr("ui.devices_page.widgets.confirm", lambda *a, **k: False)
    page.remove_button.click()
    assert not calls and page.devices_list.count() == 1
    monkeypatch.setattr("ui.devices_page.widgets.confirm", lambda *a, **k: True)
    page.remove_button.click()
    assert calls == ["00000000-0000-0000-0000-000000000008"]
    assert page.devices_list.count() == 0
    assert "已删除" in page.status.text()
    records.append({"device_id": "other", "name": "other", "is_current": False, "platform": "pc", "authorized": True, "last_seen_at": 0})
    page.refresh(vault)
    page.devices_list.setCurrentRow(0)
    def close_confirm(*a, **k):
        page.close_page("lock")
        return True
    monkeypatch.setattr("ui.devices_page.widgets.confirm", close_confirm)
    page.remove_button.click()
    assert len(calls) == 1
