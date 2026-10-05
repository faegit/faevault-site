import copy
import json
from pathlib import Path

import pytest

from core import backup, modules, passkey_merge, passkeys
from core.models import Entry
from core.storage import Vault


FIXTURE = Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json"
STRONG_PASSWORD = "Strong-backup-passphrase-2026"


def fixture_record(name: str) -> dict:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return copy.deepcopy(next(case["record"] for case in document["records"] if case["name"] == name))


def passkey_module(record: dict, module_id: str = "passkey-v3") -> dict:
    return {
        "id": module_id,
        "type": modules.PASSKEY,
        "title": "Passkey",
        "required": False,
        "config": {},
        "sensitive": True,
        "value": copy.deepcopy(record),
    }


def passkey_entry(record: dict) -> Entry:
    return Entry(
        title="Android Passkey v3",
        secret_type="passkey",
        fields={modules.MODULES_KEY: [passkey_module(record)]},
    )


def test_syncable_v3_uses_direct_private_key_and_needs_no_keyset():
    source = fixture_record("syncable_directly_available_after_database_sync")
    parsed = passkeys.parse_record(source)
    assert parsed.schema_version == 3
    assert parsed.key_mode == "syncable"
    assert parsed.value["private_key"] == source["private_key"]
    assert "private_key_envelope" not in parsed.value
    assert not hasattr(parsed, "keyset_id")


def test_removed_keyset_and_recovery_authorization_apis_are_absent():
    for name in ("validate_keyset", "merge_keysets", "create_keyset", "unwrap_pak"):
        assert not hasattr(passkeys, name)
    for name in ("passkey_keyset", "passkey_backup_metadata", "authorize_passkey_access"):
        assert not hasattr(Vault, name)


def test_direct_private_key_survives_passkey_merge():
    local = fixture_record("syncable_directly_available_after_database_sync")
    remote = copy.deepcopy(local)
    remote["last_used_at"] = "2026-08-21T00:00:00Z"
    remote["backup_state"] = "true"
    remote["future_record_field"] = {"revision": 2, "remote": True}
    result = passkey_merge.merge_module_sets(
        [passkey_module(local, "local")],
        [passkey_module(remote, "remote")],
    )
    value = result.modules[0]["value"]
    assert value["private_key"] == remote["private_key"]
    assert value["backup_state"] == "true"
    assert value["future_record_field"] == remote["future_record_field"]
    assert passkeys.parse_record(value).schema_version == 3


def test_encrypted_backup_round_trip_needs_no_passkey_metadata(tmp_path):
    source = passkey_entry(fixture_record("syncable_directly_available_after_database_sync"))
    path = tmp_path / "passkey.pmbak"
    backup.export_encrypted([source], path, STRONG_PASSWORD)
    restored = backup.import_encrypted_with_meta(path, STRONG_PASSWORD)
    assert restored.entries[0].fields == source.fields
    payload = backup._decrypt_payload(path, STRONG_PASSWORD)
    assert "passkey_keyset" not in payload
    assert "source_vault_id" not in payload


@pytest.mark.parametrize("password", ("short", "alllowercasebutlong", "ALLUPPERCASE12345"))
def test_syncable_backup_still_requires_a_strong_independent_password(tmp_path, password):
    source = passkey_entry(fixture_record("syncable_directly_available_after_database_sync"))
    with pytest.raises(ValueError, match="至少需要 14 位"):
        backup.export_encrypted([source], tmp_path / "weak.pmbak", password)


def test_device_bound_backup_does_not_require_syncable_password_policy(tmp_path):
    source = passkey_entry(fixture_record("device_bound_metadata_only"))
    path = tmp_path / "device-bound.pmbak"
    backup.export_encrypted([source], path, "short")
    restored = backup.import_encrypted(path, "short")
    assert restored[0].fields == source.fields
