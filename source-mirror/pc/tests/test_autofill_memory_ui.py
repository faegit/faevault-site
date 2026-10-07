from core.models import Entry
from core.autofill_field_mapping import with_mapping, mappings_for
from ui.autofill_memory import memory_rows, revoke_memory, AutofillMemoryDialog


def test_revoke_binding_preserves_unrelated_values_and_legacy_origin():
    selected = {'kind': 'windows', 'process': 'app.exe', 'path': 'C:/app.exe'}
    other = {'kind': 'web', 'origin': 'https://example.com'}
    entry = Entry(password='secret', target_app='app.exe', fields={
        '_autofill_bindings': [selected, other], '_autofill_origin': other,
        'future_field': {'secret': 'keep'}})
    revoked = revoke_memory(entry, 'binding', selected)
    assert revoked.fields['_autofill_bindings'] == [other]
    assert revoked.fields['_autofill_origin'] == other
    assert revoked.fields['future_field'] == {'secret': 'keep'}
    assert revoked.password == 'secret' and revoked.target_app == 'app.exe'
    assert entry.fields['_autofill_bindings'] == [selected, other]


def test_revoke_binding_removes_matching_legacy_and_mapping_tombstone():
    binding = {'kind': 'web', 'origin': 'https://example.com'}
    entry = Entry(fields={'_autofill_bindings': [binding], '_autofill_origin': binding})
    assert '_autofill_origin' not in revoke_memory(entry, 'binding', binding).fields
    entry = with_mapping(entry, 'windows:app', 'uia:phone', 'phone')
    entry = with_mapping(entry, 'windows:other', 'uia:phone', 'email')
    revoked = revoke_memory(entry, 'mapping', ('windows:app', 'uia:phone'))
    assert mappings_for(revoked, 'windows:app') == {}
    assert mappings_for(revoked, 'windows:other') == {'uia:phone': 'email'}
    assert any(row.get('deleted') for row in revoked.fields['_autofill_field_mappings'])
    assert len(memory_rows(revoked)) == 2


def test_picker_available_roles_labels_do_not_expose_values(monkeypatch):
    from PySide6.QtWidgets import QApplication
    from ui.dialogs import NativeAutofillPickerDialog
    app = QApplication.instance() or QApplication([])
    entry = Entry(username='u', password='sensitive value')
    dialog = NativeAutofillPickerDialog([entry], 'app.exe', manual_focus=True,
        available_roles={entry.id: ('phone', 'email')})
    try:
        assert [dialog._role_selector.itemData(i) for i in range(dialog._role_selector.count())] == ['email', 'phone']
        assert 'sensitive value' not in dialog._role_selector.itemText(0)
        dialog._choose_manual('password')
        assert dialog.selected_entry is None
        dialog._choose_manual('phone')
        assert dialog.action == 'manual_phone' and dialog.selected_entry.id == entry.id
        assert not dialog.remember_mapping.isChecked()
    finally:
        dialog.deleteLater()


def test_memory_dialog_failed_update_does_not_remove_ui_row():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    class StaleVault:
        def update(self, entry):
            raise RuntimeError('stale')
    entry = Entry(fields={'_autofill_bindings': [{'kind':'windows','process':'app.exe'}]})
    dialog = AutofillMemoryDialog(StaleVault(), entry)
    try:
        dialog._revoke_selected()
        assert not dialog.changed
        assert dialog._list.count() == 1
        assert not dialog._remove.isEnabled()
    finally:
        dialog.deleteLater()


def test_memory_dialog_update_uses_original_revision_and_reports_completion():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    entry = Entry(updated_at=10, fields={'_autofill_bindings': [{'kind':'windows','process':'app.exe'}]})
    updates = []
    class Vault:
        def update(self, updated):
            assert updated.updated_at == entry.updated_at
            updates.append(updated)
    dialog = AutofillMemoryDialog(Vault(), entry)
    try:
        dialog._revoke_selected()
        assert dialog.changed and len(updates) == 1
        assert dialog._list.count() == 0
        assert dialog._status.text()
    finally:
        dialog.deleteLater()
