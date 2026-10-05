from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from core import modules, passkey_merge, passkeys, sync
from core.models import Entry, SecretType
from core.storage import Vault


FIXTURE = Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json"


def b64u(value: bytes, *, padded: bool = False) -> str:
    encoded = base64.urlsafe_b64encode(value).decode("ascii")
    return encoded if padded else encoded.rstrip("=")


def cose_public_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    numbers = private_key.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return b"\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" + x + b"\x22\x58\x20" + y


@pytest.fixture
def fixture_record() -> dict:
    document = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return copy.deepcopy(document["records"][0]["record"])


def record_for_seed(seed: int, *, credential: bytes = b"android-credential-id") -> dict:
    private_key = ec.derive_private_key(seed, ec.SECP256R1())
    return {
        "schema_version": "3",
        "rp_id": "example.com",
        "rp_name": "Example",
        "user_id": b64u(b"user-1"),
        "user_name": "alice@example.com",
        "user_display_name": "Alice",
        "credential_id": b64u(credential),
        "key_mode": "syncable",
        "private_key": b64u(private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )),
        "public_key": b64u(cose_public_key(private_key)),
        "algorithm": "-7",
        "transports": "internal",
        "aaguid": "9a2289d0-7b7b-4c5d-8d77-5f7a0643cc82",
        "discoverable": "true",
        "backup_eligible": "true",
        "backup_state": "false",
        "counter_mode": "synced_zero",
        "sign_count": "0",
        "created_at": "2026-07-16T00:00:00Z",
        "last_used_at": "",
    }


def passkey_module(
    record: dict,
    *,
    module_id: str = "module",
    config: dict | None = None,
    extra: dict | None = None,
) -> dict:
    module = {
        "id": module_id,
        "type": "passkey",
        "title": "Passkey",
        "sensitive": True,
        "required": False,
        "config": copy.deepcopy(config or {}),
        "value": copy.deepcopy(record),
    }
    module.update(copy.deepcopy(extra or {}))
    return module


def test_fixture_same_key_merge_keeps_synced_zero_and_timestamp_rules():
    local_record = record_for_seed(1)
    local_record.update(
        created_at="2026-07-15T00:00:00Z",
        last_used_at="2026-07-15T12:00:00Z",
    )
    remote_record = record_for_seed(1)
    remote_record.update(
        created_at="2026-07-14T00:00:00Z",
        last_used_at="2026-07-16T00:00:00Z",
    )

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    value = result.modules[0]["value"]
    assert value["sign_count"] == "0"
    assert value["counter_mode"] == "synced_zero"
    assert value["created_at"] == "2026-07-14T00:00:00Z"
    assert value["last_used_at"] == "2026-07-16T00:00:00Z"
    assert not result.has_key_conflict


def test_synced_zero_same_key_remains_zero(fixture_record):
    local = passkey_module(fixture_record, module_id="local")
    remote_record = copy.deepcopy(fixture_record)
    remote_record["last_used_at"] = "2026-07-16T02:00:00Z"

    result = passkey_merge.merge_module_sets(
        [local],
        [passkey_module(remote_record, module_id="remote")],
    )

    assert result.modules[0]["value"]["counter_mode"] == "synced_zero"
    assert result.modules[0]["value"]["sign_count"] == "0"


def test_identity_uses_normalized_rp_and_decoded_credential_id(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record["rp_id"] = "Example.COM"
    local_record["credential_id"] = b64u(b"0123456789abcdef", padded=True)
    remote_record = copy.deepcopy(fixture_record)
    remote_record["credential_id"] = b64u(b"0123456789abcdef")
    remote_record["future_remote"] = {"kept": True}

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    assert len(result.modules) == 1
    assert result.modules[0]["value"]["future_remote"] == {"kept": True}


def test_identity_matches_unicode_rp_to_its_idna_ascii_form(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record["rp_id"] = "bücher.example"
    remote_record = copy.deepcopy(fixture_record)
    remote_record["rp_id"] = "xn--bcher-kva.example"

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    assert len(result.modules) == 1


def test_identity_uses_stdlib_idna_sharp_s_mapping_without_rewriting_records(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record["rp_id"] = "straße.example"
    local_record["last_used_at"] = "2026-07-16T03:00:00Z"
    remote_record = copy.deepcopy(fixture_record)
    remote_record["rp_id"] = "strasse.example"
    local = [passkey_module(local_record, module_id="local")]
    remote = [passkey_module(remote_record, module_id="remote")]
    before_local = copy.deepcopy(local)
    before_remote = copy.deepcopy(remote)

    result = passkey_merge.merge_module_sets(local, remote)

    assert len(result.modules) == 1
    assert result.modules[0]["value"]["rp_id"] == "straße.example"
    assert local == before_local
    assert remote == before_remote


@pytest.mark.parametrize(
    ("rp_id", "expected"),
    (
        ("BÜCHER.Example.", "xn--bcher-kva.example"),
        ("XN--BCHER-KVA.Example.", "xn--bcher-kva.example"),
        ("STRASSE.Example.", "strasse.example"),
    ),
)
def test_rp_identity_normalization_converges_case_alabel_and_trailing_dot(rp_id, expected):
    assert passkey_merge._normalized_rp_identity(rp_id) == expected


def test_key_equality_uses_validated_decoded_public_key_not_key_text(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record["public_key"] += "="
    remote_record = copy.deepcopy(fixture_record)
    remote_record["last_used_at"] = "2026-07-16T03:00:00Z"

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    assert len(result.modules) == 1
    assert not result.has_key_conflict
    assert result.modules[0]["value"]["public_key"] in {
        local_record["public_key"],
        remote_record["public_key"],
    }


def test_unique_identities_from_both_sides_survive_in_deterministic_order():
    credential_b = record_for_seed(1, credential=b"bbbbbbbbbbbbbbbb")
    credential_a = record_for_seed(2, credential=b"aaaaaaaaaaaaaaaa")

    result = passkey_merge.merge_module_sets(
        [passkey_module(credential_b, module_id="b")],
        [passkey_module(credential_a, module_id="a")],
    )

    credentials = [passkeys.parse_record(module["value"]).credential_id_bytes for module in result.modules]
    assert credentials == [b"aaaaaaaaaaaaaaaa", b"bbbbbbbbbbbbbbbb"]


def test_unique_module_preserves_existing_config_and_is_deep_copied(fixture_record):
    original = passkey_module(
        fixture_record,
        module_id="only",
        config={
            "passkeyConflictGroupId": "existing-group",
            "passkeyConflictStatus": "key_mismatch",
            "future": {"revision": 7},
        },
    )

    result = passkey_merge.merge_module_sets([original], [])

    assert result.modules[0] == original
    assert result.modules[0] is not original
    assert result.modules[0]["config"] is not original["config"]


def test_unknown_field_union_and_metadata_conflicts_are_reported(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record.update(
        rp_name="Local name",
        local_only={"revision": 1},
        nested_future={"common": "local", "left": True},
    )
    remote_record = copy.deepcopy(fixture_record)
    remote_record.update(
        rp_name="Remote name",
        remote_only={"revision": 2},
        nested_future={"common": "remote", "right": True},
        last_used_at="2026-07-16T04:00:00Z",
    )

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    value = result.modules[0]["value"]
    assert value["local_only"] == {"revision": 1}
    assert value["remote_only"] == {"revision": 2}
    assert value["nested_future"]["left"] is True
    assert value["nested_future"]["right"] is True
    assert value["nested_future"]["common"] == "remote"
    assert value["rp_name"] == "Remote name"
    assert result.metadata_conflicts == ("nested_future.common", "rp_name")


def test_empty_metadata_never_overwrites_nonempty_and_boolean_true_is_not_downgraded(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record.update(rp_name="Kept name", backup_state="true")
    remote_record = copy.deepcopy(fixture_record)
    remote_record.update(rp_name="", backup_state="false", last_used_at="2026-07-16T05:00:00Z")

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    assert result.modules[0]["value"]["rp_name"] == "Kept name"
    assert result.modules[0]["value"]["backup_state"] == "true"


def test_same_key_keeps_one_complete_source_key_bundle_and_exact_strings(fixture_record):
    local_record = copy.deepcopy(fixture_record)
    local_record["user_id"] = b64u(b"user", padded=True)
    local_record["credential_id"] = b64u(b"0123456789abcdef", padded=True)
    local_record["public_key"] += "="
    remote_record = copy.deepcopy(fixture_record)
    remote_record["user_id"] = b64u(b"user")
    remote_record["credential_id"] = b64u(b"0123456789abcdef")
    remote_record["last_used_at"] = "2026-07-16T06:00:00Z"

    result = passkey_merge.merge_module_sets(
        [passkey_module(local_record, module_id="local")],
        [passkey_module(remote_record, module_id="remote")],
    )

    bundle_fields = ("user_id", "credential_id", "public_key", "private_key")

    def bundle_snapshot(record: dict) -> str:
        return json.dumps({key: record[key] for key in bundle_fields}, sort_keys=True)

    assert bundle_snapshot(result.modules[0]["value"]) in {
        bundle_snapshot(local_record),
        bundle_snapshot(remote_record),
    }


def test_different_keys_for_same_credential_create_two_complete_conflict_modules():
    local = passkey_module(record_for_seed(1), module_id="same")
    remote = passkey_module(record_for_seed(2), module_id="same")

    result = passkey_merge.merge_module_sets([local], [remote])

    assert result.has_key_conflict
    assert len(result.modules) == 2
    assert len({module["id"] for module in result.modules}) == 2
    groups = {module["config"]["passkeyConflictGroupId"] for module in result.modules}
    assert len(groups) == 1
    assert all(
        module["config"]["passkeyConflictStatus"] == "key_mismatch"
        for module in result.modules
    )
    private_keys = {module["value"]["private_key"] for module in result.modules}
    assert private_keys == {
        local["value"]["private_key"],
        remote["value"]["private_key"],
    }


def test_same_side_duplicate_identity_with_different_keys_also_fails_closed_as_conflict():
    result = passkey_merge.merge_module_sets(
        [
            passkey_module(record_for_seed(1), module_id="one"),
            passkey_module(record_for_seed(2), module_id="two"),
        ],
        [],
    )

    assert result.has_key_conflict
    assert len(result.modules) == 2


def test_inputs_and_nested_values_are_never_mutated(fixture_record):
    local = [passkey_module(fixture_record, module_id="local", config={"future": {"left": True}})]
    remote_record = copy.deepcopy(fixture_record)
    remote_record["future_field"] = {"remote": [1, 2, 3]}
    remote = [passkey_module(remote_record, module_id="remote")]
    before_local = copy.deepcopy(local)
    before_remote = copy.deepcopy(remote)

    result = passkey_merge.merge_module_sets(local, remote)
    result.modules[0]["value"]["future_field"]["remote"][0] = 99
    result.modules[0]["config"]["future"]["left"] = False

    assert local == before_local
    assert remote == before_remote


def test_output_is_deterministic_except_for_random_conflict_group():
    local = [
        passkey_module(record_for_seed(3, credential=b"bbbbbbbbbbbbbbbb"), module_id="b"),
        passkey_module(record_for_seed(1), module_id="same"),
    ]
    remote = [
        passkey_module(record_for_seed(2), module_id="same"),
        passkey_module(record_for_seed(4, credential=b"aaaaaaaaaaaaaaaa"), module_id="a"),
    ]

    first = passkey_merge.merge_module_sets(local, remote)
    second = passkey_merge.merge_module_sets(local, remote)
    first_modules = copy.deepcopy(first.modules)
    second_modules = copy.deepcopy(second.modules)
    for modules in (first_modules, second_modules):
        for module in modules:
            module["config"].pop("passkeyConflictGroupId", None)

    assert first_modules == second_modules
    assert first.metadata_conflicts == second.metadata_conflicts


@pytest.mark.parametrize(
    "bad_module",
    (
        {"id": "bad", "type": "passkey", "config": {}, "value": {"private_key": "SECRET_MARKER"}},
        {"id": "bad", "type": "text", "config": {}, "value": {}},
        {"id": "bad", "type": "passkey", "config": "SECRET_MARKER", "value": {}},
        {
            "id": "bad",
            "type": "passkey",
            "config": {"future": float("nan")},
            "value": {},
        },
        "SECRET_MARKER",
    ),
)
def test_invalid_or_corrupt_modules_fail_closed_without_secret_leaks(bad_module):
    with pytest.raises(passkeys.PasskeyError) as error:
        passkey_merge.merge_module_sets([bad_module], [])

    assert str(error.value) == "invalid passkey module set"
    assert "SECRET_MARKER" not in str(error.value)


def _entry_with_passkeys(entry_id, passkey_modules, *, updated_at, password=""):
    return Entry(
        id=entry_id,
        title="Shared",
        username="user",
        password=password,
        updated_at=updated_at,
        fields=modules.fields_with_modules({}, passkey_modules),
    )


def _credential_ids(entry):
    return {
        passkeys.parse_record(module["value"]).credential_id_bytes
        for module in modules.modules_from_fields(entry.fields)
        if module.get("type") == modules.PASSKEY
    }


def test_entry_lww_cannot_drop_unique_passkey_from_older_revision(fixture_record):
    local = _entry_with_passkeys(
        "shared",
        [passkey_module(fixture_record, module_id="local")],
        updated_at=100,
    )
    remote = _entry_with_passkeys("shared", [], updated_at=200)

    merged, stats, _purges = sync.merge_with_purges([local], [remote])

    assert _credential_ids(merged[0]) == {passkeys.parse_record(fixture_record).credential_id_bytes}
    assert stats["remote_wins"] == 1


def test_entry_lww_unions_unique_local_and_remote_passkeys(fixture_record):
    remote_record = copy.deepcopy(fixture_record)
    remote_record["credential_id"] = b64u(b"second-credential-id")
    local = _entry_with_passkeys(
        "shared",
        [passkey_module(fixture_record, module_id="local")],
        updated_at=200,
    )
    remote = _entry_with_passkeys(
        "shared",
        [passkey_module(remote_record, module_id="remote")],
        updated_at=100,
    )

    merged, stats = sync.merge([local], [remote])

    assert _credential_ids(merged[0]) == {
        passkeys.parse_record(fixture_record).credential_id_bytes,
        passkeys.parse_record(remote_record).credential_id_bytes,
    }
    assert stats["local_wins"] == 1


def test_entry_lww_reports_key_mismatch_and_preserves_both_records():
    local = _entry_with_passkeys(
        "shared",
        [passkey_module(record_for_seed(1), module_id="local")],
        updated_at=200,
    )
    remote = _entry_with_passkeys(
        "shared",
        [passkey_module(record_for_seed(2), module_id="remote")],
        updated_at=100,
    )

    merged, stats = sync.merge([local], [remote])
    passkey_modules = [
        module
        for module in modules.modules_from_fields(merged[0].fields)
        if module.get("type") == modules.PASSKEY
    ]

    assert len(passkey_modules) == 2
    assert stats["passkey_conflicts"] == 1
    assert {
        module["config"]["passkeyConflictStatus"]
        for module in passkey_modules
    } == {"key_mismatch"}


def test_import_adds_unique_incoming_passkey_as_independent_type(tmp_path, fixture_record):
    vault = Vault.create(tmp_path / "passkey-import.pmv", "master")
    vault.add(_entry_with_passkeys(
        "00000000-0000-0000-0000-000000000001",
        [],
        updated_at=100,
        password="local",
    ))
    incoming = _entry_with_passkeys(
        "00000000-0000-0000-0000-000000000002",
        [passkey_module(fixture_record, module_id="incoming-passkey")],
        updated_at=200,
        password="remote",
    )

    stats = vault.merge([incoming], lambda _old, _inc: "skip")

    assert len(vault.entries) == 2
    saved_login = next(entry for entry in vault.entries if entry.secret_type == SecretType.LOGIN)
    saved_passkey = next(entry for entry in vault.entries if entry.secret_type == SecretType.PASSKEY)
    assert saved_login.password == "local"
    assert _credential_ids(saved_login) == set()
    assert _credential_ids(saved_passkey) == {passkeys.parse_record(fixture_record).credential_id_bytes}
    assert stats["added"] == 1
    assert stats["skipped"] == 0


@pytest.mark.parametrize(
    "rp_id",
    (
        "attacker-marker.example.",
        "xn--attacker-marker-\ud800.example",
        "attacker-marker..example",
    ),
)
def test_invalid_rp_fails_closed_without_raw_domain_leaking_from_error_or_repr(
    fixture_record,
    rp_id,
):
    record = copy.deepcopy(fixture_record)
    record["rp_id"] = rp_id

    with pytest.raises(passkeys.PasskeyError) as error:
        passkey_merge.merge_module_sets([passkey_module(record)], [])

    assert str(error.value) == "invalid passkey module set"
    assert rp_id not in str(error.value)
    assert "attacker-marker" not in repr(error.value)
