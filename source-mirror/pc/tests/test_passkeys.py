import base64
import ast
import copy
import hashlib
import json
import math
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from core import passkeys


def b64u(value: bytes, *, padded: bool = False) -> str:
    encoded = base64.urlsafe_b64encode(value).decode()
    return encoded if padded else encoded.rstrip("=")


def cbor_int(value: int) -> bytes:
    major = 0 if value >= 0 else 1
    argument = value if value >= 0 else -1 - value
    if argument < 24:
        return bytes([(major << 5) | argument])
    if argument <= 0xFF:
        return bytes([(major << 5) | 24, argument])
    if argument <= 0xFFFF:
        return bytes([(major << 5) | 25]) + argument.to_bytes(2, "big")
    raise ValueError("test CBOR integer is too large")


def cose_public_key(
    private_key: ec.EllipticCurvePrivateKey,
    *,
    algorithm: int = -7,
    curve: int = 1,
) -> bytes:
    numbers = private_key.public_key().public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return (
        b"\xa5"
        + cbor_int(1)
        + cbor_int(2)
        + cbor_int(3)
        + cbor_int(algorithm)
        + cbor_int(-1)
        + cbor_int(curve)
        + cbor_int(-2)
        + b"\x58\x20"
        + x
        + cbor_int(-3)
        + b"\x58\x20"
        + y
    )


def android_record() -> dict:
    private_key = ec.derive_private_key(1, ec.SECP256R1())
    return {
        "schema_version": "3",
        "rp_id": "example.com",
        "rp_name": "Example",
        "user_id": b64u(b"user-1"),
        "user_name": "alice@example.com",
        "user_display_name": "Alice",
        "credential_id": b64u(b"android-credential-id"),
        "key_mode": "syncable",
        "private_key": b64u(private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )),
        "public_key": b64u(cose_public_key(private_key)),
        "sign_count": "0",
        "algorithm": "-7",
        "transports": "internal",
        "aaguid": "9a2289d0-7b7b-4c5d-8d77-5f7a0643cc82",
        "discoverable": "true",
        "backup_eligible": "true",
        "backup_state": "false",
        "counter_mode": "synced_zero",
        "created_at": "2026-07-16T00:00:00Z",
        "last_used_at": "",
    }


def test_v3_syncable_record_uses_direct_private_key_and_rejects_removed_envelope():
    fixture = json.loads(
        (Path(__file__).resolve().parents[1] / "spec" / "passkey_v3_fixtures.json").read_text(encoding="utf-8")
    )
    direct = fixture["records"][0]["record"]

    parsed = passkeys.parse_record(direct)

    assert parsed.key_mode == "syncable"
    assert parsed.value["private_key"] == direct["private_key"]
    assert "private_key_envelope" not in parsed.value
    removed = dict(direct)
    removed["private_key_envelope"] = {
        "version": "1",
        "keyset_id": "2e6b26ca-9178-4c4d-a2d8-7b56f0415ba7",
        "nonce": "AAECAwQFBgcICQoL",
        "ciphertext": "AAECAwQFBgcICQoLDA0ODw",
        "aad_version": "1",
    }
    with pytest.raises(passkeys.PasskeyError, match="no longer supported"):
        passkeys.parse_record(removed)


class SelfCopyingMutable:
    def __init__(self) -> None:
        self.items = ["do-not-share"]
        self.deepcopy_calls = 0

    def __deepcopy__(self, memo):
        self.deepcopy_calls += 1
        return self

    def __repr__(self) -> str:
        return "SECRET_SELF_COPYING_OBJECT"


def assert_frozen_json_graph(value) -> None:
    if isinstance(value, MappingProxyType):
        for key, item in value.items():
            assert type(key) is str
            assert_frozen_json_graph(item)
        return
    if type(value) is tuple:
        for item in value:
            assert_frozen_json_graph(item)
        return
    assert type(value) in (str, int, bool, float, type(None))
    if type(value) is float:
        assert math.isfinite(value)


def deeply_nested_json(depth: int) -> dict:
    root: dict = {}
    current = root
    for _ in range(depth):
        child: dict = {}
        current["nested"] = child
        current = child
    current["marker"] = "ATTACKER_CONTROLLED_DEEP_VALUE"
    return root


def test_validates_android_created_record_for_management_and_sync():
    record = passkeys.validate_record(android_record())

    assert record["rp_id"] == "example.com"
    assert record["sign_count"] == "0"
    assert record["algorithm"] == "-7"
    assert record["counter_mode"] == "synced_zero"


@pytest.mark.parametrize(
    "rp_id",
    (
        "Example.COM",
        "bücher.example",
        "l·l.example",
        "͵α.example",
        "א׳.example",
        "カ・ナ.example",
        "example－site.com",
    ),
)
def test_preserves_exact_valid_rp_id_text(rp_id):
    record = android_record()
    record["rp_id"] = rp_id

    assert passkeys.validate_record(record)["rp_id"] == rp_id


@pytest.mark.parametrize(
    "rp_id",
    (
        " example.com",
        "example.com ",
        ".example.com",
        "example.com.",
        "example..com",
        "-example.com",
        "example-.com",
        "exam ple.com",
        "example\\com",
        "https://example.com",
        "example.com/path",
        "example.com:443",
        "user@example.com",
        "under_score.example",
        f"{'a' * 64}.example",
        ".".join(["a" * 63] * 5),
    ),
)
def test_rejects_non_domain_rp_ids_with_generic_redacted_error(rp_id):
    record = android_record()
    record["rp_id"] = rp_id

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.validate_record(record)

    assert str(error.value) == "invalid passkey RP ID"
    assert rp_id not in str(error.value)


@pytest.mark.parametrize(
    "rp_id",
    (
        "example\uff0fattacker-marker.com",
        "example\uff1aattacker-marker.com",
        "example\u3002attacker-marker.com",
        "example\u2215attacker-marker.com",
        "attacker-marker\ud800.example.com",
    ),
)
def test_rejects_nfkc_delimiters_and_invalid_idna_without_leaking_input(rp_id):
    record = android_record()
    record["rp_id"] = rp_id

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.validate_record(record)

    assert str(error.value) == "invalid passkey RP ID"
    assert "attacker-marker" not in str(error.value)


def test_passkeys_has_no_runtime_import_of_third_party_idna():
    source = Path(passkeys.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.add(node.module)

    assert "idna" not in imported_modules


@pytest.mark.parametrize(
    "target",
    (
        "_normalize_rp_id_character",
        "_encode_rp_id_label",
        "_rp_id_is_ip_address",
    ),
)
def test_rp_id_validation_redacts_ordinary_faults_from_every_stage(monkeypatch, target):
    marker = "ATTACKER_CONTROLLED_RP_ID_FAULT"

    def injected_fault(*args, **kwargs):
        raise RuntimeError(marker)

    monkeypatch.setattr(passkeys, target, injected_fault)
    record = android_record()

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.validate_record(record)

    assert str(error.value) == "invalid passkey RP ID"
    assert marker not in str(error.value)


@pytest.mark.parametrize("boundary", (passkeys.validate_record, passkeys.parse_record))
def test_public_boundaries_redact_deeply_nested_json_failures(boundary):
    record = android_record()
    record["future_field"] = deeply_nested_json(2_000)

    with pytest.raises(passkeys.PasskeyError) as error:
        boundary(record)

    assert str(error.value) == "invalid passkey record"
    assert "ATTACKER_CONTROLLED_DEEP_VALUE" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("boundary", "target"),
    (
        (passkeys.validate_record, "_parse_cose_public_key"),
        (passkeys.parse_record, "_freeze_value"),
    ),
)
@pytest.mark.parametrize("fault_type", (RuntimeError, RecursionError, passkeys.PasskeyError))
def test_public_boundaries_redact_injected_validator_faults(
    monkeypatch, boundary, target, fault_type
):
    marker = "ATTACKER_CONTROLLED_VALIDATOR_FAULT"

    def injected_fault(*args, **kwargs):
        raise fault_type(marker)

    monkeypatch.setattr(passkeys, target, injected_fault)

    with pytest.raises(passkeys.PasskeyError) as error:
        boundary(android_record())

    assert str(error.value) == "invalid passkey record"
    assert marker not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("boundary", "target"),
    (
        (passkeys.validate_record, "_parse_cose_public_key"),
        (passkeys.parse_record, "_freeze_value"),
    ),
)
@pytest.mark.parametrize("exception_type", (KeyboardInterrupt, SystemExit, GeneratorExit))
def test_public_boundaries_do_not_catch_process_control_exceptions(
    monkeypatch, boundary, target, exception_type
):
    def injected_fault(*args, **kwargs):
        raise exception_type

    monkeypatch.setattr(passkeys, target, injected_fault)

    with pytest.raises(exception_type):
        boundary(android_record())


@pytest.mark.parametrize("field", ("algorithm", "future_field"))
def test_oversized_python_integers_are_rejected_before_string_conversion(field):
    record = android_record()
    record[field] = 10**5_000

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.validate_record(record)

    assert str(error.value) == "invalid passkey record"
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_largest_bounded_python_integer_is_preserved_exactly():
    value = 10**4_300 - 1
    record = android_record()
    record["future_field"] = value

    assert passkeys.validate_record(record)["future_field"] == value


def test_explicit_passkey_errors_remain_useful_secret_free_and_unchained():
    record = android_record()
    record["created_at"] = "2026-02-30T00:00:00Z"
    record["future_field"] = {"secret": "ATTACKER_CONTROLLED_SECRET"}

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.parse_record(record)

    assert type(error.value) is passkeys.PasskeyError
    assert str(error.value) == "created at must be an RFC3339 timestamp"
    assert "ATTACKER_CONTROLLED" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_preserves_key_strings_unknown_fields_and_callers_input():
    original = android_record()
    original["user_id"] = b64u(b"user", padded=True)
    original["credential_id"] = b64u(b"0123456789abcdef", padded=True)
    original["public_key"] += "="
    original["aaguid"] = "9A2289D0-7B7B-4C5D-8D77-5F7A0643CC82"
    original["rp_name"] = "  Exact RP Name  "
    original["user_name"] = "  exact-user@example.com  "
    original["user_display_name"] = "  Exact Display Name  "
    original["future_field"] = {"revision": 7, "nested": [{"enabled": True}]}
    before = copy.deepcopy(original)

    validated = passkeys.validate_record(original)

    for field in (
        "user_id",
        "credential_id",
        "public_key",
        "aaguid",
        "rp_name",
        "user_name",
        "user_display_name",
    ):
        assert validated[field] == before[field]
    assert validated["future_field"] == before["future_field"]
    assert validated["future_field"] is not original["future_field"]
    validated["future_field"]["nested"][0]["enabled"] = False
    assert original == before


@pytest.mark.parametrize(
    "value",
    (
        "",
        " ",
        None,
        True,
        7,
        1.25,
        [],
        {},
        "not-a-uuid",
        "00000000-0000-0000-0000-00000000000",
    ),
)
def test_v2_requires_a_valid_textual_aaguid(value):
    record = android_record()
    record["aaguid"] = value

    with pytest.raises(passkeys.PasskeyError, match="AAGUID|aaguid"):
        passkeys.validate_record(record)


def test_v2_rejects_missing_aaguid():
    record = android_record()
    record.pop("aaguid")

    with pytest.raises(passkeys.PasskeyError, match="incomplete|AAGUID|aaguid"):
        passkeys.validate_record(record)


@pytest.mark.parametrize(
    "aaguid",
    (
        "00000000-0000-0000-0000-000000000000",
        "9A2289D0-7B7B-4C5D-8D77-5F7A0643CC82",
    ),
)
def test_v2_accepts_and_preserves_valid_aaguid_text(aaguid):
    record = android_record()
    record["aaguid"] = aaguid

    assert passkeys.validate_record(record)["aaguid"] == aaguid


@pytest.mark.parametrize("field", ("rp_name", "user_name", "user_display_name", "last_used_at"))
@pytest.mark.parametrize("value", (None, True, 7, 1.25, [], {}))
def test_v2_known_optional_text_metadata_must_be_strings_when_present(field, value):
    record = android_record()
    record[field] = value

    with pytest.raises(passkeys.PasskeyError, match=field.replace("_", " ") + "|text|string"):
        passkeys.validate_record(record)


@pytest.mark.parametrize("field", ("rp_name", "user_name", "user_display_name", "last_used_at"))
def test_v2_text_metadata_must_be_present(field):
    record = android_record()
    record.pop(field)

    with pytest.raises(passkeys.PasskeyError, match="incomplete"):
        passkeys.validate_record(record)


@pytest.mark.parametrize("value", (None, True, 7, 1.25, [], {}, {"nested": ["value"]}))
def test_v2_unknown_json_compatible_fields_remain_allowed(value):
    record = android_record()
    record["future_optional_metadata"] = value

    assert passkeys.validate_record(record)["future_optional_metadata"] == value


def test_parse_record_returns_frozen_typed_view_without_secret_repr():
    record = android_record()
    parsed = passkeys.parse_record(record)
    public_key_bytes = base64.urlsafe_b64decode(record["public_key"] + "=" * (-len(record["public_key"]) % 4))
    credential_id_bytes = base64.urlsafe_b64decode(
        record["credential_id"] + "=" * (-len(record["credential_id"]) % 4)
    )

    assert parsed.value == passkeys.validate_record(record)
    assert parsed.rp_id == "example.com"
    assert parsed.credential_id_bytes == credential_id_bytes
    assert parsed.public_key_bytes == public_key_bytes
    assert parsed.key_identity == hashlib.sha256(public_key_bytes).hexdigest()
    assert parsed.sign_count == 0
    assert parsed.identity == ("example.com", credential_id_bytes)
    assert record["private_key"] not in repr(parsed)
    assert "private_key_envelope" not in repr(parsed)
    with pytest.raises(FrozenInstanceError):
        parsed.sign_count = 1


def test_validated_passkey_repr_is_constant_and_fully_redacted():
    marker = "attacker-marker"
    record = android_record()
    record["rp_id"] = f"{marker}.example"
    record["rp_name"] = marker
    record["user_name"] = f"{marker}@example.com"
    record["user_display_name"] = marker
    record["future_field"] = {"attacker_controlled": marker}

    rendered = repr(passkeys.parse_record(record))

    assert rendered == "ValidatedPasskey(<redacted>)"
    assert marker not in rendered


def test_parsed_value_is_transitively_immutable_across_reads():
    record = android_record()
    record["future_field"] = {"nested": [{"enabled": True}]}
    parsed = passkeys.parse_record(record)

    first_read = parsed.value
    first_read["rp_id"] = "attacker.example"
    first_read["future_field"]["nested"][0]["enabled"] = False

    second_read = parsed.value
    assert second_read["rp_id"] == "example.com"
    assert second_read["future_field"]["nested"][0]["enabled"] is True
    with pytest.raises(TypeError):
        parsed._value["rp_id"] = "attacker.example"
    with pytest.raises(TypeError):
        parsed._value["future_field"]["nested"][0]["enabled"] = False


def test_rejects_bytearray_in_unknown_json_field_with_redacted_error():
    record = android_record()
    secret = "SECRET_BYTEARRAY_CONTENT"
    record["future_field"] = bytearray(secret.encode())

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.parse_record(record)

    assert secret not in str(error.value)


def test_rejects_self_copying_custom_object_without_calling_deepcopy_or_leaking_repr():
    record = android_record()
    malicious = SelfCopyingMutable()
    record["future_field"] = malicious

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.parse_record(record)

    assert malicious.deepcopy_calls == 0
    assert "SECRET_SELF_COPYING_OBJECT" not in str(error.value)


@pytest.mark.parametrize(
    "invalid_value",
    (
        {"nested": {1: "non-string key"}},
        {"nested": ("tuple",)},
        {"nested": {"set"}},
        {"nested": float("nan")},
        {"nested": float("inf")},
        {"nested": float("-inf")},
    ),
)
def test_rejects_other_non_json_unknown_field_values(invalid_value):
    record = android_record()
    record["future_field"] = invalid_value

    with pytest.raises(passkeys.PasskeyError, match="JSON"):
        passkeys.parse_record(record)


def test_internal_value_graph_contains_only_immutable_json_representations():
    record = android_record()
    record["future_field"] = {
        "nested": [{"enabled": True, "count": 7, "ratio": 1.25, "missing": None}],
    }

    parsed = passkeys.parse_record(record)

    assert_frozen_json_graph(parsed._value)


@pytest.mark.parametrize(
    "field",
    (
        "schema_version",
        "aaguid",
        "discoverable",
        "backup_eligible",
        "backup_state",
        "counter_mode",
    ),
)
def test_missing_version_two_contract_fields_are_rejected(field):
    record = android_record()
    record.pop(field)

    with pytest.raises(passkeys.PasskeyError, match="incomplete"):
        passkeys.validate_record(record)


@pytest.mark.parametrize("value", ("", None, True, 1.0, 1))
def test_v2_signature_counter_requires_a_decimal_string(value):
    record = android_record()
    record["sign_count"] = value

    with pytest.raises(passkeys.PasskeyError, match="signature counter"):
        passkeys.validate_record(record)


def test_very_long_decimal_signature_counter_is_rejected_without_conversion_error_or_leak():
    oversized = "9" * 10_000
    record = android_record()
    record["sign_count"] = oversized

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.validate_record(record)

    assert str(error.value) == "invalid signature counter"
    assert oversized not in str(error.value)


def test_synced_zero_rejects_nonzero_signature_counter():
    record = android_record()
    record["sign_count"] = "1"

    with pytest.raises(passkeys.PasskeyError, match="synced_zero.*zero|zero.*synced_zero"):
        passkeys.validate_record(record)


@pytest.mark.parametrize(
    "mutate,message",
    (
        (lambda record: record.__setitem__("private_key", b64u(b"not-pkcs8")), "private key"),
        (lambda record: record.__setitem__("public_key", b64u(b"\xa1\x01")), "COSE|CBOR"),
        (
            lambda record: record.__setitem__(
                "public_key", b64u(cose_public_key(ec.generate_private_key(ec.SECP256R1()), curve=2))
            ),
            "curve",
        ),
        (
            lambda record: record.__setitem__(
                "public_key", b64u(cose_public_key(ec.generate_private_key(ec.SECP256R1()), algorithm=-257))
            ),
            "algorithm",
        ),
    ),
)
def test_rejects_invalid_key_material_with_useful_errors(mutate, message):
    record = android_record()
    mutate(record)

    with pytest.raises(passkeys.PasskeyError, match=message):
        passkeys.validate_record(record)


@pytest.mark.parametrize(
    "field,decoded_size",
    (("credential_id", 1025), ("public_key", 4097)),
)
def test_rejects_oversized_base64url_key_material(field, decoded_size):
    record = android_record()
    record[field] = b64u(b"x" * decoded_size)

    with pytest.raises(passkeys.PasskeyError, match=field.replace("_", " ") + ".*large|oversized"):
        passkeys.validate_record(record)


@pytest.mark.parametrize("encoded", ("YQ", "YQ=="))
def test_accepts_and_preserves_canonical_base64url_padding_styles(encoded):
    record = android_record()
    record["user_id"] = encoded

    assert passkeys.validate_record(record)["user_id"] == encoded


@pytest.mark.parametrize("encoded", ("YR", "YR=="))
def test_rejects_noncanonical_base64url_pad_bits(encoded):
    record = android_record()
    record["user_id"] = encoded

    with pytest.raises(passkeys.PasskeyError, match="user ID.*base64url"):
        passkeys.validate_record(record)


@pytest.mark.parametrize(
    "field,value",
    (
        ("created_at", "2026-02-30T00:00:00Z"),
        ("created_at", "2026-07-16 00:00:00"),
        ("last_used_at", "yesterday"),
    ),
)
def test_rejects_invalid_rfc3339_timestamps(field, value):
    record = android_record()
    record[field] = value

    with pytest.raises(passkeys.PasskeyError, match=field.replace("_", " ") + "|RFC3339"):
        passkeys.validate_record(record)


@pytest.mark.parametrize(
    "field,value",
    (
        ("discoverable", "yes"),
        ("backup_eligible", True),
        ("backup_state", "1"),
        ("sign_count", True),
        ("sign_count", "1.5"),
        ("counter_mode", "unknown"),
    ),
)
def test_rejects_invalid_v2_booleans_and_counters(field, value):
    record = android_record()
    record[field] = value

    with pytest.raises(passkeys.PasskeyError, match="boolean|counter|counter mode"):
        passkeys.validate_record(record)


def test_rejects_inconsistent_backup_metadata():
    record = android_record()
    record["backup_eligible"] = "false"

    with pytest.raises(passkeys.PasskeyError, match="backup"):
        passkeys.validate_record(record)


def test_rejects_unsupported_transport():
    record = android_record()
    record["transports"] = "usb"

    with pytest.raises(passkeys.PasskeyError, match="transport"):
        passkeys.validate_record(record)


@pytest.mark.parametrize("field", ("algorithm", "transports"))
@pytest.mark.parametrize("value", ("", None))
def test_rejects_blank_or_missing_v2_algorithm_and_transport(field, value):
    record = android_record()
    if value is None:
        record.pop(field)
    else:
        record[field] = value

    with pytest.raises(passkeys.PasskeyError, match="incomplete|algorithm|transport"):
        passkeys.validate_record(record)


@pytest.mark.parametrize(
    "field,value",
    (("rp_id", "localhost"), ("credential_id", "not base64!"), ("sign_count", "-1"), ("algorithm", "-65535")),
)
def test_rejects_invalid_synchronized_record(field, value):
    record = android_record()
    record[field] = value

    with pytest.raises(passkeys.PasskeyError):
        passkeys.validate_record(record)


def test_secret_material_is_not_in_validation_errors():
    record = android_record()
    secret = "c2VjcmV0LXByaXZhdGUta2V5"
    record["private_key"] = secret

    with pytest.raises(passkeys.PasskeyError) as error:
        passkeys.validate_record(record)

    assert secret not in str(error.value)


def test_pc_exposes_no_authenticator_operations():
    assert not hasattr(passkeys, "create")
    assert not hasattr(passkeys, "get")
