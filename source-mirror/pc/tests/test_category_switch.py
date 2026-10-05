import os
import time
from types import SimpleNamespace, MethodType

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QLabel, QLineEdit, QListWidget, QPushButton

from core.models import Entry, SecretType
from ui import app as app_ui


@pytest.fixture
def host(monkeypatch):
    application = QApplication.instance() or QApplication([])
    entries = [Entry(title=f"Account {i:04}", secret_type=SecretType.LOGIN if i % 2 else SecretType.WIFI)
               for i in range(1000)]
    calls = []
    def search(query):
        calls.append(("search", query))
        return sorted((e for e in entries if query.casefold() in e.title.casefold()), key=lambda e: e.title)
    vault = SimpleNamespace(entries=entries, search=search)
    window = SimpleNamespace(vault=vault, list=QListWidget(), search=QLineEdit(),
        count_label=QLabel(), _list_add_btn=QPushButton(), _locked=False,
        _active_type=SecretType.LOGIN, _active_tag=None, _password_filter=None,
        _app_filter_enabled=False, _active_app=None, _alpha_buttons={},
        _type_chips={}, _tag_chips={}, _select_timer=QTimer(), _search_timer=QTimer(),
        _sync_kdf_profile_to_config=lambda: calls.append(("kdf",)),
        _rebuild_tag_chips=lambda: None,
        _update_recycle_btn=lambda: calls.append(("recycle",)),
        _update_password_stats=lambda: calls.append(("stats",)),
        _schedule_leak_audit=lambda: calls.append(("audit",)),
        _show_empty=lambda: None, _do_show_selected=lambda: calls.append(("detail",)))
    for name in ("reload", "_set_type_filter", "_set_tag_filter", "_update_chip_styles", "_update_alpha_nav"):
        setattr(window, name, MethodType(getattr(app_ui.MainWindow, name), window))
    window._alpha_key = app_ui.MainWindow._alpha_key
    monkeypatch.setattr(app_ui.media_files, "ensure_vault_context", lambda _vault: calls.append(("media",)))
    monkeypatch.setattr(app_ui.leak, "is_entry_leaked_cached", lambda e: False)
    window.calls = calls
    window._select_timer.setSingleShot(True)
    window._select_timer.setInterval(80)
    window._select_timer.timeout.connect(window._do_show_selected)
    window.reload()
    application.processEvents()
    calls.clear()
    yield window
    application.processEvents()


def test_category_switch_reuses_search_and_skips_data_maintenance(host):
    host._set_type_filter(SecretType.WIFI)
    assert host.list.count() == 500
    assert all(host.list.item(i).entry.secret_type == SecretType.WIFI for i in range(host.list.count()))
    assert not any(call[0] in {"search", "media", "kdf", "stats", "recycle", "audit"} for call in host.calls)
    assert host._select_timer.interval() == 0
    QApplication.instance().processEvents()
    assert ("detail",) in host.calls


def test_data_reload_invalidates_filter_snapshot(host):
    host._set_type_filter(SecretType.WIFI)
    host.vault.entries.append(Entry(title="New Wi-Fi", secret_type=SecretType.WIFI))
    host.reload()
    assert host.list.count() == 501
    assert ("stats",) in host.calls
    host.calls.clear()
    host._set_type_filter(SecretType.LOGIN)
    host._set_type_filter(SecretType.WIFI)
    assert host.list.count() == 501
    assert not any(call[0] == "search" for call in host.calls)


def test_changed_search_is_not_replaced_by_old_category_cache(host):
    host.search.setText("Account 001")
    host._set_type_filter(SecretType.WIFI)
    assert host.list.count() == 5
    assert all("Account 001" in host.list.item(i).entry.title for i in range(host.list.count()))
    assert ("search", "Account 001") in host.calls


def test_reselecting_current_category_does_no_work(host):
    host._set_type_filter(SecretType.LOGIN)
    assert not host.calls


def test_category_projection_preserves_tag_filter_and_empty_result(host):
    host.vault.entries[0].tags = ["work"]
    host.reload()
    host._active_tag = "work"
    host._set_type_filter(SecretType.WIFI)
    assert host.list.count() == 1
    host._set_type_filter(SecretType.LOGIN)
    assert host.list.count() == 0


def test_vault_replacement_cannot_reuse_previous_query_snapshot(host):
    replacement = Entry(title="Replacement", secret_type=SecretType.WIFI)
    host.vault = SimpleNamespace(entries=[replacement], search=lambda _query: [replacement])
    host._set_type_filter(SecretType.WIFI)
    assert host.list.count() == 1
    assert host.list.item(0).entry is replacement


def test_category_keeps_breached_items_first(host, monkeypatch):
    last_wifi = host.vault.entries[-2]
    monkeypatch.setattr(app_ui.leak, "is_entry_leaked_cached", lambda e: e is last_wifi)
    host._set_type_filter(SecretType.WIFI)
    assert host.list.item(0).entry is last_wifi
    assert host._alpha_index["#"] == 0


def test_visible_entry_list_reload_plays_short_transition(host):
    from PySide6.QtTest import QTest
    from ui import widgets
    host.list.resize(300, 300)
    host._list_transition = widgets.ContentTransition(host.list.viewport())
    host.list.show()
    QApplication.instance().processEvents()
    try:
        host.reload(data_changed=False)
        QApplication.instance().processEvents()
        assert host._list_transition.isVisible()
        QTest.qWait(220)
        assert not host._list_transition.isVisible()
    finally:
        host.list.close()
