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

