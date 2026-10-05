import hashlib
import json
from pathlib import Path


FIXTURE = Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json"
ANDROID_FIXTURE = Path(__file__).resolve().parents[2] / "vault_android" / "spec" / "passkey_v3_fixtures.json"
EXPECTED_FIXTURE_SHA256 = "4d07b50eb51be90dcb0781db580b936d1771b4e6ee2446b2c4841da93fa179ee"
EXPECTED_PUBLIC_KEY = (
    "pQECAyYgASFYIGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKW"
    "IlggT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU"
)
REQUIRED_RECORD_FIELDS = {
    "schema_version",
    "rp_id",
    "rp_name",
    "user_id",
    "user_name",
    "user_display_name",
    "credential_id",
    "key_mode",
    "public_key",
    "algorithm",
    "transports",
    "aaguid",
    "discoverable",
    "backup_eligible",
    "backup_state",
    "counter_mode",
    "sign_count",
    "created_at",
    "last_used_at",
}


def fixture_document(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def nested_keys(value) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in nested_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in nested_keys(child)}
    return set()


def test_android_and_pc_passkey_v3_fixture_payloads_match():
    pc = fixture_document(FIXTURE)
    android = fixture_document(ANDROID_FIXTURE)

    assert pc == {key: android[key] for key in pc}


def test_passkey_v3_fixture_shape_and_stable_public_key_encoding():
    raw = FIXTURE.read_bytes()
    normalized = raw.replace(b"\r\n", b"\n")
    document = json.loads(raw.decode("utf-8"))

    assert b"\r" not in normalized, "fixture must not contain lone CR line endings"
    assert normalized.endswith(b"\n"), "fixture must end with one normalized LF"
    assert not normalized.endswith(b"\n\n"), "fixture must not end with a blank line"
    assert hashlib.sha256(normalized).hexdigest() == EXPECTED_FIXTURE_SHA256
    assert document["schemaVersion"] == 3
    assert document["testOnly"] is True
    assert [case["name"] for case in document["records"]] == [
        "syncable_directly_available_after_database_sync",
        "device_bound_metadata_only",
    ]
    assert len(document["invalid"]) >= 2
    assert "private_key_envelope" not in nested_keys(document)

    syncable = document["records"][0]["record"]
    device_bound = document["records"][1]["record"]
    assert REQUIRED_RECORD_FIELDS <= syncable.keys()
    assert REQUIRED_RECORD_FIELDS <= device_bound.keys()
    assert syncable["schema_version"] == "3"
    assert syncable["key_mode"] == "syncable"
    assert syncable["private_key"]
    assert syncable["future_record_field"] == {"revision": 1}
    assert device_bound["key_mode"] == "device_bound"
    assert device_bound["device_binding"]["provider"] == "android_keystore"
    assert syncable["public_key"] == EXPECTED_PUBLIC_KEY
    assert "=" not in syncable["public_key"]
