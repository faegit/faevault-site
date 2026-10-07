"""Review and revoke entry-scoped autofill choices without changing entry values."""
from __future__ import annotations

import copy
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QListWidget, QListWidgetItem, QPushButton
from core.autofill_field_mapping import FIELD_KEY, mappings_for, with_mapping
from core.autofill_sources import AUTOFILL_BINDINGS_KEY
from core.models import Entry
from . import i18n, widgets
from .module_editor import AUTOFILL_ROLE_LABELS


def memory_rows(entry: Entry) -> list[tuple[str, object, str]]:
    rows = []
    bindings = entry.fields.get(AUTOFILL_BINDINGS_KEY, [])
    for binding in bindings if isinstance(bindings, list) else ():
        if isinstance(binding, dict) and not binding.get('deleted'):
            rows.append(('binding', binding, _binding_label(binding)))
    legacy = entry.fields.get('_autofill_origin')
    if isinstance(legacy, dict) and legacy not in [row[1] for row in rows]:
        rows.append(('legacy', legacy, _binding_label(legacy)))
    raw = entry.fields.get(FIELD_KEY, [])
    origins = dict.fromkeys(row.get('origin') for row in raw if isinstance(row, dict) and isinstance(row.get('origin'), str)) if isinstance(raw, list) else {}
    for origin in origins:
        for key, role in mappings_for(entry, origin).items():
            label = i18n.tr(AUTOFILL_ROLE_LABELS.get(role, role))
            rows.append(('mapping', (origin, key), f'{origin}\n{key} · {label}'))
    return rows


def _binding_label(binding: dict) -> str:
    kind = binding.get('kind')
    if kind == 'windows':
        return str(binding.get('process') or binding.get('path') or i18n.tr('程序关联'))
    if kind == 'web':
        return str(binding.get('origin') or binding.get('host') or i18n.tr('网站关联'))
    return str(binding.get('package') or binding.get('origin') or i18n.tr('已记住关联'))


def revoke_memory(entry: Entry, kind: str, value: object) -> Entry:
    if kind == 'mapping':
        origin, key = value
        return with_mapping(entry, origin, key, '')
    result = Entry.from_dict(entry.to_dict())
    if kind == 'binding':
        bindings = result.fields.get(AUTOFILL_BINDINGS_KEY, [])
        if isinstance(bindings, list):
            result.fields[AUTOFILL_BINDINGS_KEY] = [binding for binding in bindings if binding != value]
        if result.fields.get('_autofill_origin') == value:
            result.fields.pop('_autofill_origin', None)
    elif kind == 'legacy':
        if result.fields.get('_autofill_origin') == value:
            result.fields.pop('_autofill_origin', None)
    else:
        raise ValueError('Unknown autofill memory kind')
    return result


class AutofillMemoryDialog(widgets.ShadowDialog):
    def __init__(self, vault, entry: Entry, parent=None):
        super().__init__(i18n.tr('自动填充记忆'), parent, width=520)
        self._vault = vault
        self._entry = Entry.from_dict(entry.to_dict())
        self.changed = False
        note = QLabel(i18n.tr('移除已记住的关联或字段类型，下次填充时将重新选择。'))
        note.setWordWrap(True)
        self.body.addWidget(note)
        self._list = QListWidget()
        self._list.setMinimumHeight(180)
        self.body.addWidget(self._list)
        self._status = QLabel()
        self._status.setWordWrap(True)
        self.body.addWidget(self._status)
        self._remove = QPushButton(i18n.tr('移除所选记忆'))
        self._remove.clicked.connect(self._revoke_selected)
        self.body.addWidget(self._remove)
        close = QPushButton(i18n.tr('关闭'))
        close.clicked.connect(self.accept)
        self.body.addWidget(close)
        self._list.currentItemChanged.connect(lambda *_: self._remove.setEnabled(self._list.currentItem() is not None))
        self._refresh()

    def _refresh(self):
        self._list.clear()
        for kind, value, label in memory_rows(self._entry):
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, (kind, copy.deepcopy(value)))
            self._list.addItem(item)
        if self._list.count():
            self._list.setCurrentRow(0)
        self._remove.setEnabled(self._list.currentItem() is not None)
        if not self._list.count():
            self._status.setText(i18n.tr('没有已记住的自动填充关联或字段类型。'))

    def _revoke_selected(self):
        item = self._list.currentItem()
        if item is None:
            return
        kind, value = item.data(Qt.UserRole)
        updated = revoke_memory(self._entry, kind, value)
        try:
            self._vault.update(updated)
        except Exception:
            self._status.setText(i18n.tr('移除失败，条目可能已更新。请关闭后重新打开。'))
            self._remove.setEnabled(False)
            return
        self._entry = updated
        self.changed = True
        self._refresh()
        self._status.setText(i18n.tr('已移除所选记忆。'))
