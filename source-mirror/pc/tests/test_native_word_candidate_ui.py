from types import SimpleNamespace

import pytest
from PySide6.QtWidgets import QDialog

from core import native_autofill
from core.models import Entry
from ui import app as app_ui


def test_single_word_candidate_requires_picker_before_fill(monkeypatch):
    entry = Entry(title="Example account", password="secret", target_app="other.exe")
    target = native_autofill.NativeTarget(1, 999999, "example.exe", "Example")
    calls = []
    monkeypatch.setattr(app_ui.config, "get", lambda key, default=None: default)
    monkeypatch.setattr(native_autofill, "matching_vault_entries", lambda *args, **kwargs: [entry])
    monkeypatch.setattr(app_ui.autofill_otp, "resolve_source", lambda *args: None)

    class Picker:
        action = "fill"
        selected_entry = None

        def __init__(self, entries, process_name, parent, **kwargs):
            calls.append((entries, kwargs["fallback"]))

        def exec(self):
            return QDialog.Rejected

    monkeypatch.setattr(app_ui, "NativeAutofillPickerDialog", Picker)
    prepared = SimpleNamespace(target=target, fields=(object(),))
    win = SimpleNamespace(
        _native_autofill_prepared=prepared,
        _locked=False,
        vault=SimpleNamespace(autofill_exclusions={"processes": []}),
        _native_autofill_backend=SimpleNamespace(
            capture_credentials=lambda _: native_autofill.CapturedCredentials("", ""),
            fill=lambda *args, **kwargs: pytest.fail("word candidate filled without consent"),
        ),
        _native_autofill_busy=True,
        _native_autofill_failed=lambda text: pytest.fail(text),
    )
    app_ui.MainWindow._complete_native_autofill(win)
    assert calls == [([entry], True)]
    assert win._native_autofill_busy is False


def test_word_candidate_cannot_overwrite_unrelated_saved_login():
    target = native_autofill.NativeTarget(1, 999999, "example.exe", "Example")
    existing = Entry(title="Example", target_app="other.exe", password="old")
    with pytest.raises(native_autofill.NativeAutofillError, match="新建"):
        app_ui.MainWindow._save_native_autofill_credentials(
            SimpleNamespace(), target, native_autofill.CapturedCredentials("alice", "new"), existing,
        )
    assert existing.password == "old"



def test_pending_manual_fill_consumes_request_without_opening_picker(monkeypatch):
    import time
    entry = Entry(username="alice", password="secret")
    target = native_autofill.NativeTarget(1, 999999, "example.exe")
    sent = []
    monkeypatch.setattr(app_ui, "NativeAutofillPickerDialog", lambda *a, **k: pytest.fail("picker stole focus"))
    win = SimpleNamespace(
        _native_autofill_prepared=native_autofill.PreparedFill(target, ()),
        _native_autofill_pending=(target, entry.id, "password", time.monotonic() + 30),
        _locked=False, _native_autofill_busy=True,
        vault=SimpleNamespace(read_entry=lambda _: entry),
        _native_autofill_backend=SimpleNamespace(fill_focused=lambda p, v, **k: sent.append(v)),
        _flash=lambda _: None, _native_autofill_failed=lambda text: pytest.fail(text),
    )
    app_ui.MainWindow._complete_native_autofill(win)
    assert sent == ["secret"]
    assert win._native_autofill_pending is None
    assert not win._native_autofill_busy


@pytest.mark.parametrize("expired, changed, locked", [(True, False, False), (False, True, False), (False, False, True)])
def test_pending_manual_fill_rejects_expired_changed_or_locked_target(expired, changed, locked):
    import time
    target = native_autofill.NativeTarget(1, 999999, "example.exe")
    errors = []
    win = SimpleNamespace(
        _native_autofill_prepared=native_autofill.PreparedFill(
            native_autofill.NativeTarget(2, 999999, "example.exe") if changed else target, ()),
        _native_autofill_pending=(target, "entry", "password", time.monotonic() + (-1 if expired else 30)),
        _locked=locked, _native_autofill_busy=True,
        _native_autofill_failed=errors.append,
    )
    app_ui.MainWindow._complete_native_autofill(win)
    assert errors
    assert win._native_autofill_pending is None
    assert not win._native_autofill_busy


def test_picker_has_explicit_unchecked_remember_and_reasons():
    from PySide6.QtWidgets import QApplication
    application = QApplication.instance() or QApplication([])
    from ui.dialogs import NativeAutofillPickerDialog
    entry = Entry(title="Example", password="secret")
    dialog = NativeAutofillPickerDialog([entry], "example.exe", reasons={entry.id:"name"})
    assert not dialog.remember_binding.isChecked()
    assert dialog._list.item(0).text().count("\n") >= 2
    dialog.reject()


@pytest.mark.parametrize("write_ok", [True, False])
def test_pending_manual_hotp_advances_only_after_success(monkeypatch, write_ok):
    import time
    entry = Entry(password="unused")
    target = native_autofill.NativeTarget(1,999999,"example.exe")
    advances=[]; sent=[]; errors=[]
    value=SimpleNamespace(value="123456",source_entry_id=entry.id)
    monkeypatch.setattr(app_ui.autofill_resolver,"resolve_snapshot",lambda *a,**k:SimpleNamespace(values={"one_time_code":value}))
    monkeypatch.setattr(app_ui.autofill_otp,"snapshot",lambda *a,**k:SimpleNamespace(code="123456",kind="hotp",source_id=entry.id))
    monkeypatch.setattr(app_ui.autofill_otp,"advance_hotp",lambda vault,eid:advances.append(eid))
    def fill(prepared, value, **kwargs):
        if not write_ok:raise native_autofill.NativeAutofillError("failed")
        sent.append(value)
        return native_autofill.FillResult(False,False,True)
    win=SimpleNamespace(_native_autofill_prepared=native_autofill.PreparedFill(target,()),
        _native_autofill_pending=(target,entry.id,"one_time_code",time.monotonic()+30),_locked=False,
        vault=SimpleNamespace(read_entry=lambda eid:entry),_native_autofill_backend=SimpleNamespace(fill_focused=fill),
        _native_autofill_busy=True,_flash=lambda text:None,_native_autofill_failed=errors.append)
    app_ui.MainWindow._complete_native_autofill(win)
    assert advances==([entry.id] if write_ok else [])
    assert sent==(["123456"] if write_ok else [])


def test_explicit_picker_cannot_bypass_known_signer_change():
    from core.native_autofill import APP_PATH_FIELD, APP_SIGNER_FIELD, allowed_for_explicit_fill
    entry=Entry(target_app="example.exe",password="secret",fields={APP_PATH_FIELD:"C:/app.exe",APP_SIGNER_FIELD:"a"*64})
    target=native_autofill.NativeTarget(1,123,"example.exe",executable_path="C:/app.exe",signer_sha256="b"*64)
    assert not allowed_for_explicit_fill(entry,target)
    entry.fields={"_autofill_bindings":[{"kind":"windows","process":"example.exe","path":"C:/app.exe","signer":"a"*64}]}
    assert not allowed_for_explicit_fill(entry,target)
