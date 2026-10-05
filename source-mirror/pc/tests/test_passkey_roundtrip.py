import copy
import csv
import json
from pathlib import Path

import pytest

from core import backup, importers, modules
from core.models import Entry
from core.storage import Vault


PASSKEY_FIXTURE = Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json"
RECOVERY_SECRET = bytes(reversed(range(32)))


def _write_archive_csv_fixture(entries, path: Path) -> None:
    """Exercise the CSV payload embedded inside encrypted archives."""
    path.write_bytes(importers._csv_export_payload([entry for entry in entries if entry.deleted_at is None]))


def _mixed_fields():
    ordinary_module = {
        "id": "ordinary",
        "type": modules.TEXT,
        "value": "keep ordinary module text",
        "future_module_field": {"keep": True},
    }
    passkey_module = {
        "id": "passkey",
        "type": modules.PASSKEY,
        "value": {
            "credential_id": "credential-material",
            "private_key": "private-material",
            "public_key": "public-material",
            "future_passkey_field": {"keep_in_encrypted_storage": True},
        },
    }
    second_passkey_module = {
        "id": "second-passkey",
        "type": modules.PASSKEY,
        "value": {
            "credential_id": "second-credential-material",
            "private_key": "second-private-material",
            "public_key": "second-public-material",
        },
    }
    return {
        "ordinary_field": {"nested": ["keep"]},
        modules.MODULES_KEY: [ordinary_module, passkey_module, second_passkey_module],
    }


def _fixture_passkey_record():
    document = json.loads(PASSKEY_FIXTURE.read_text(encoding="utf-8"))
    return document["legacyV2"]["valid"][0]["record"]


def _fixture_passkey_entry():
    record = _fixture_passkey_record()
    return Entry(
        title="Fixture passkey",
        fields={
            modules.MODULES_KEY: [
                {
                    "id": "fixture-passkey",
                    "type": modules.PASSKEY,
                    "title": "Passkey",
                    "required": False,
                    "config": {},
                    "sensitive": True,
                    "value": copy.deepcopy(record),
                    "future_module_field": {"preserve": ["module", 2]},
                },
            ],
            "future_entry_field": {"preserve": True},
        },
    )


def _assert_fixture_passkey_entry_preserved(restored):
    original = _fixture_passkey_entry()
    assert restored.fields == original.fields
    assert restored.fields[modules.MODULES_KEY][0]["value"] == _fixture_passkey_record()


def test_csv_export_omits_top_level_passkey_secret_keys_from_custom_fields(tmp_path):
    entry = Entry(
        title="Legacy custom fields",
        fields={
            "private_key": "TOP-LEVEL-PRIVATE-SECRET",
            "public_key": "TOP-LEVEL-PUBLIC-SECRET",
            "credential_id": "TOP-LEVEL-CREDENTIAL-SECRET",
            "future_field": "keep this ordinary value",
        },
    )
    path = tmp_path / "export.csv"

    _write_archive_csv_fixture([entry], path)

    csv_text = path.read_text(encoding="utf-8-sig")
    assert "TOP-LEVEL-PRIVATE-SECRET" not in csv_text
    assert "TOP-LEVEL-PUBLIC-SECRET" not in csv_text
    assert "TOP-LEVEL-CREDENTIAL-SECRET" not in csv_text


def test_csv_export_recursively_omits_passkey_secret_keys_from_dicts_and_lists(tmp_path):
    fields = {
        "profile": {
            "private_key": "NESTED-PRIVATE-SECRET",
            "unknown": [
                {"public_key": "LIST-PUBLIC-SECRET", "label": "keep list item"},
                [
                    {"credential_id": "DEEP-CREDENTIAL-SECRET", "count": 7},
                    "keep scalar",
                ],
            ],
            "private_key_label": "keep similarly named key",
        },
        "PUBLIC_KEY": "keep differently cased key",
    }
    original_fields = copy.deepcopy(fields)
    entry = Entry(
        title="Malformed nested fields",
        fields=fields,
    )
    path = tmp_path / "export.csv"

    _write_archive_csv_fixture([entry], path)

    csv_text = path.read_text(encoding="utf-8-sig")
    assert "NESTED-PRIVATE-SECRET" not in csv_text
    assert "LIST-PUBLIC-SECRET" not in csv_text
    assert "DEEP-CREDENTIAL-SECRET" not in csv_text
    assert entry.fields == original_fields


def test_csv_export_omits_modules_key_when_only_passkey_modules_remain(tmp_path):
    entry = Entry(
        title="Passkey only",
        fields={
            "ordinary_field": "keep",
            modules.MODULES_KEY: [
                {
                    "id": "passkey-only",
                    "type": modules.PASSKEY,
                    "value": {
                        "private_key": "PASSKEY-ONLY-PRIVATE-SECRET",
                        "public_key": "PASSKEY-ONLY-PUBLIC-SECRET",
                        "credential_id": "PASSKEY-ONLY-CREDENTIAL-SECRET",
                    },
                },
            ],
        },
    )
    path = tmp_path / "export.csv"

    _write_archive_csv_fixture([entry], path)

    csv_text = path.read_text(encoding="utf-8-sig")
    assert modules.MODULES_KEY not in csv_text
    assert "PASSKEY-ONLY-PRIVATE-SECRET" not in csv_text
    assert "PASSKEY-ONLY-PUBLIC-SECRET" not in csv_text
    assert "PASSKEY-ONLY-CREDENTIAL-SECRET" not in csv_text


def test_csv_export_strips_passkey_module_without_mutating_mixed_fields(tmp_path):
    fields = _mixed_fields()
    entry = Entry(
        title="Mixed modules",
        fields=fields,
    )
    original_fields = copy.deepcopy(entry.fields)
    path = tmp_path / "export.csv"

    _write_archive_csv_fixture([entry], path)

    csv_text = path.read_text(encoding="utf-8-sig")
    assert "credential-material" not in csv_text
    assert "private-material" not in csv_text
    assert "public-material" not in csv_text
    assert "credential_id" not in csv_text
    assert "private_key" not in csv_text
    assert "public_key" not in csv_text
    assert "future_passkey_field" not in csv_text
    assert entry.fields == original_fields


def test_csv_export_accepts_tuple_modules_without_leaking_secrets(tmp_path):
    fields = _mixed_fields()
    fields[modules.MODULES_KEY] = tuple(fields[modules.MODULES_KEY])
    original_modules = fields[modules.MODULES_KEY]
    entry = Entry(title="Tuple modules", fields=fields)
    path = tmp_path / "export.csv"

    _write_archive_csv_fixture([entry], path)

    csv_text = path.read_text(encoding="utf-8-sig")
    assert "credential-material" not in csv_text
    assert "private-material" not in csv_text
    assert "public-material" not in csv_text
    assert entry.fields[modules.MODULES_KEY] == original_modules


@pytest.mark.parametrize(
    "malformed_modules",
    [
        {"type": modules.PASSKEY},
        "not-a-module-collection",
        {modules.PASSKEY},
        (module for module in ({"type": modules.PASSKEY},)),
        [{"type": modules.TEXT}, "not-a-module"],
        ({"type": modules.TEXT}, None),
    ],
)
def test_csv_export_fails_closed_on_malformed_module_collections(tmp_path, malformed_modules):
    path = tmp_path / "export.csv"
    path.write_bytes(b"ORIGINAL CSV BYTES")
    entry = Entry(title="Malformed modules", fields={modules.MODULES_KEY: malformed_modules})

    with pytest.raises(importers.PlaintextExportError):
        _write_archive_csv_fixture([entry], path)

    assert path.read_bytes() == b"ORIGINAL CSV BYTES"


@pytest.mark.parametrize("cycle_kind", ["dict", "list", "tuple"])
def test_csv_export_rejects_cycles_without_disclosing_field_values(tmp_path, cycle_kind):
    marker = "ATTACKER-CONTROLLED-CYCLE-MARKER"
    if cycle_kind == "dict":
        value = {"marker": marker}
        value["cycle"] = value
    elif cycle_kind == "list":
        value = [marker]
        value.append(value)
    else:
        holder = [marker]
        value = (holder,)
        holder.append(value)
    entry = Entry(title="Cycle", fields={"ordinary": value})

    with pytest.raises(importers.PlaintextExportError) as caught:
        importers._csv_export_payload([entry])

    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)


def test_csv_export_rejects_excessive_depth(tmp_path):
    value = "leaf"
    for _ in range(importers._PLAINTEXT_EXPORT_MAX_DEPTH + 1):
        value = {"nested": value}
    entry = Entry(title="Too deep", fields={"ordinary": value})

    with pytest.raises(importers.PlaintextExportError):
        importers._csv_export_payload([entry])


def test_csv_export_rejects_excessive_node_count(tmp_path):
    value = {
        f"group-{index}": [None] * importers._PLAINTEXT_EXPORT_MAX_CONTAINER_ITEMS
        for index in range(
            importers._PLAINTEXT_EXPORT_MAX_NODES
            // importers._PLAINTEXT_EXPORT_MAX_CONTAINER_ITEMS
            + 1
        )
    }
    entry = Entry(title="Too many nodes", fields={"ordinary": value})

    with pytest.raises(importers.PlaintextExportError):
        importers._csv_export_payload([entry])


def test_csv_export_rejects_oversized_container(tmp_path):
    value = [None] * (importers._PLAINTEXT_EXPORT_MAX_CONTAINER_ITEMS + 1)
    entry = Entry(title="Oversized container", fields={"ordinary": value})

    with pytest.raises(importers.PlaintextExportError):
        importers._csv_export_payload([entry])


def test_csv_export_uses_generic_redacted_error_for_unsupported_json_value(tmp_path, caplog):
    marker = "ATTACKER-CONTROLLED-UNSUPPORTED-VALUE"

    class Unsupported:
        def __str__(self):
            return marker

        def __repr__(self):
            return marker

    entry = Entry(title="Unsupported", fields={"ordinary": Unsupported()})

    with pytest.raises(importers.PlaintextExportError) as caught:
        importers._csv_export_payload([entry])

    assert str(caught.value) == importers._PLAINTEXT_EXPORT_ERROR
    assert marker not in str(caught.value)
    assert marker not in repr(caught.value)
    assert marker not in caplog.text


def test_csv_export_leaves_normal_entries_and_fields_unchanged(tmp_path):
    fields = {
        "ordinary_field": {"nested": ["alpha", {"unknown_key": 42}]},
        modules.MODULES_KEY: [
            {
                "id": "ordinary",
                "type": modules.TEXT,
                "value": "keep ordinary module text",
                "future_module_field": {"keep": True},
            },
        ],
    }
    entry = Entry(
        title="Normal entry",
        url="https://example.com",
        username="alice",
        password="normal-login-password",
        notes="ordinary note",
        fields=fields,
    )
    original_fields = copy.deepcopy(fields)
    path = tmp_path / "export.csv"

    _write_archive_csv_fixture([entry], path)

    row = next(csv.DictReader(path.read_text(encoding="utf-8-sig").splitlines()))
    assert row["title"] == "Normal entry"
    assert row["url"] == "https://example.com"
    assert row["username"] == "alice"
    assert row["password"] == "normal-login-password"
    assert row["notes"] == "ordinary note"
    assert "fields" not in row
    assert "credential-material" not in path.read_text(encoding="utf-8-sig")
    assert entry.fields == original_fields


def test_encrypted_backup_preserves_complete_mixed_module_fields(tmp_path):
    entry = Entry(title="Mixed modules", fields=_mixed_fields())
    original_fields = copy.deepcopy(entry.fields)
    path = tmp_path / "passkeys.pmbak"

    backup.export_encrypted([entry], path, "backup-password")
    restored = backup.import_encrypted(path, "backup-password")

    assert restored[0].fields == original_fields
    assert entry.fields == original_fields


def test_pmve_vault_preserves_fixture_passkey_record_exactly(tmp_path):
    path = tmp_path / "passkey.pmv"
    vault = Vault.create(path, "master-password", RECOVERY_SECRET)
    try:
        entry = _fixture_passkey_entry()
        entry.tags = ["工作", "私人"]
        vault.add(entry)
    finally:
        vault.close()

    reopened = Vault.open(path, "master-password")
    try:
        assert len(reopened.entries) == 1
        _assert_fixture_passkey_entry_preserved(reopened.entries[0])
        assert reopened.entries[0].tags == ["工作", "私人"]
    finally:
        reopened.close()


def test_encrypted_backup_preserves_fixture_passkey_record_exactly(tmp_path):
    entry = _fixture_passkey_entry()
    entry.tags = ["工作", "私人"]
    path = tmp_path / "fixture-passkey.pmbak"

    backup.export_encrypted([entry], path, "backup-password")
    restored = backup.import_encrypted(path, "backup-password")

    assert len(restored) == 1
    _assert_fixture_passkey_entry_preserved(restored[0])
    assert restored[0].tags == ["工作", "私人"]


def test_passkey_tags_survive_normalization_and_serialization():
    entry = _fixture_passkey_entry()
    entry.tags = ["工作", "私人"]
    restored = Entry.from_dict(entry.to_dict())
    assert restored.tags == ["工作", "私人"]
    assert restored.fields == entry.fields
    assert restored.matches("工作")
