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
    assert page.findChildren(QPushButton) == [page.refresh_button]
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
