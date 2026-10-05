import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.models import Entry


FIXTURE = Path(__file__).resolve().parents[1] / "spec" / "autofill_sources_v1_fixtures.json"


def _sources():
    from core import autofill_sources

    return autofill_sources


def _ref(module_id=None, source_key="value", role="email", verification=False):
    return {
        "module_id": module_id,
        "source_key": source_key,
        "role": role,
        "requires_verification": verification,
    }


def _link(link_id="link", source_id="source", refs=None):
    return {
        "id": link_id,
        "source_entry_id": source_id,
        "fields": refs if refs is not None else [_ref()],
    }


def test_roles_use_stable_strict_wire_values() -> None:
    sources = _sources()
    expected = (
        "username", "email", "password", "one_time_code", "full_name", "phone",
        "country", "region", "city", "street_address", "postal_code", "cardholder",
        "card_number", "card_expiry", "card_cvv", "id_number", "api_key", "api_secret",
        "host", "port", "database", "ssid", "wifi_password", "recovery_answer",
        "custom_text", "custom_secret",
    )

    assert sources.AUTOFILL_ROLES == expected
    assert [sources.parse_role(role) for role in expected] == list(expected)
    assert all(sources.parse_role(value) is None for value in ("", " ", " EMAIL ", "Email", "unknown", 7))


def test_every_shared_fixture_policy_case_is_implemented() -> None:
    sources = _sources()
    cases = json.loads(FIXTURE.read_text(encoding="utf-8"))["policy_cases"]

    for case in cases:
        actual = sources.policy_for_field(case["module_type"], case["field"])
        if case["role"] is None:
            assert actual is None, case["name"]
        else:
            assert actual == sources.FieldPolicy(
                case["role"], case["internal"], case["external_default"], case["verification"]
            ), case["name"]


def test_explicit_policies_fail_closed_without_title_inference() -> None:
    sources = _sources()

    assert sources.policy_for_top_level("username") == sources.FieldPolicy("username", True, True, False)
    assert sources.policy_for_top_level("password") == sources.FieldPolicy("password", True, False, True)
    assert sources.policy_for_field("address", "address").role == "street_address"
    assert sources.policy_for_field("api_credential", "api_secret").role == "api_secret"
    assert sources.policy_for_field("wifi", "admin_password").role == "wifi_password"
    assert sources.policy_for_field("database", "database").role == "database"
    assert sources.policy_for_field("text", "value").role == "custom_text"
    assert sources.policy_for_field("password", "value").role == "custom_secret"
    for module_type, source_key in (
        ("passkey", "user_name"), ("passkey", "private_key"), ("otp", "secret"),
        ("otp", "algorithm"), ("otp", "digits"), ("otp", "period"), ("otp", "counter"),
        ("ssh", "private_key"), ("attachments", "value"), ("images", "value"),
        ("multiline", "value"), ("boolean", "value"), ("target_app", "value"),
        ("card_document", "withdrawal_password"), ("unknown_composite", "value"),
        ("login_account", "unknown"),
    ):
        assert sources.policy_for_field(module_type, source_key) is None
    assert sources.policy_for_top_level("notes") is None
    assert sources.policy_for_top_level("Billing email") is None


def test_sensitive_verification_floor_is_complete_and_centralized() -> None:
    sources = _sources()
    expected = {
        "password", "card_cvv", "id_number", "api_key", "api_secret",
        "wifi_password", "recovery_answer", "custom_secret",
    }

    assert sources.SENSITIVE_ROLES == frozenset(expected)
    for role in sources.AUTOFILL_ROLES:
        assert sources.enforce_verification(role, False) is (role in expected)
        assert sources.enforce_verification(role, True) is True


def test_field_policy_and_link_data_are_frozen() -> None:
    sources = _sources()
    policy = sources.FieldPolicy("email", True, True, False)
    ref = sources.AutofillFieldRef(None, "value", "email", False)
    link = sources.AutofillLink("link", "source", (ref,))

    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.role = "phone"
    with pytest.raises(dataclasses.FrozenInstanceError):
        ref.source_key = "other"
    with pytest.raises(dataclasses.FrozenInstanceError):
        link.id = "other"
    assert isinstance(link.fields, tuple)


def test_link_defensively_copies_caller_fields_into_an_immutable_tuple() -> None:
    sources = _sources()
    email = sources.AutofillFieldRef(None, "value", "email", False)
    caller_fields = [email]

    link = sources.AutofillLink("link", "source", caller_fields)
    caller_fields.append(sources.AutofillFieldRef(None, "value", "phone", False))

    assert link.fields == (email,)
    assert isinstance(link.fields, tuple)
    with pytest.raises(TypeError):
        sources.AutofillLink("invalid", "source", (email, object()))


def test_decoder_isolates_malformed_siblings_and_refs() -> None:
    sources = _sources()
    raw = [
        "broken",
        {"id": "broken-source", "source_entry_id": 7, "fields": "invalid"},
        _link(
            "mixed",
            "source-1",
            [
                "not-object",
                _ref(source_key=""),
                _ref(role="unknown"),
                _ref(module_id=4),
                _ref(verification="false"),
                {"module_id": None, "source_key": "value", "role": "email"},
                {**_ref(), "future": {"ignored": True}},
            ],
        ),
        _link("empty", "source-2", [_ref(source_key=" ")]),
    ]

    assert sources.decode_links(raw) == (
        sources.AutofillLink(
            "mixed", "source-1", (sources.AutofillFieldRef(None, "value", "email", False),)
        ),
    )
    assert sources.decode_links({"autofill_links": raw}) == sources.decode_links(raw)
    assert sources.decode_links({"autofill_links": "invalid"}) == ()


def test_blank_module_id_drops_only_that_reference() -> None:
    sources = _sources()
    raw = [_link(refs=[_ref(module_id=" \t", role="email"), _ref(role="phone")])]

    assert sources.decode_links(raw)[0].fields == (
        sources.AutofillFieldRef(None, "value", "phone", False),
    )


def test_duplicate_ids_match_android_uuid_repair_and_reserve_original_ids() -> None:
    sources = _sources()
    raw = [
        _link("duplicate", "source-1", [_ref(source_key="username", role="username")]),
        _link("other", "source-2", [_ref(role="email")]),
        _link("duplicate", "source-3", [_ref(source_key="postal_code", role="postal_code")]),
        _link("b64f5f60-e857-310b-a6da-cf65cf19105d", "reserved", [_ref(role="phone")]),
        _link("duplicate", "source-4", [_ref(role="phone")]),
    ]

    first = sources.decode_links(raw)
    second = sources.decode_links(raw)
    assert first == second
    assert [link.source_entry_id for link in first] == [
        "source-1", "source-2", "source-3", "reserved", "source-4"
    ]
    # Same concrete index/occurrence input as Android, but the salt=0 ID is reserved.
    assert first[2].id != "b64f5f60-e857-310b-a6da-cf65cf19105d"
    assert len({link.id for link in first}) == len(first)


def test_duplicate_id_matches_android_for_fixed_unreserved_input() -> None:
    sources = _sources()
    raw = [
        _link("duplicate", "source-1", [_ref(source_key="username", role="username")]),
        _link("other", "source-2", [_ref(role="email")]),
        _link("duplicate", "source-3", [_ref(source_key="postal_code", role="postal_code")]),
    ]

    assert sources.decode_links(raw)[2].id == "b64f5f60-e857-310b-a6da-cf65cf19105d"


def test_duplicate_id_lone_surrogate_matches_java_replacement_and_never_throws() -> None:
    sources = _sources()
    lone_surrogate = "\ud800"
    raw = [
        _link(
            "duplicate-" + lone_surrogate,
            "first",
            [_ref(source_key="first", role="email")],
        ),
        _link(
            "duplicate-" + lone_surrogate,
            "source-" + lone_surrogate,
            [_ref(source_key="key-" + lone_surrogate, role="email")],
        ),
    ]

    first = sources.decode_links(raw)
    second = sources.decode_links(raw)

    assert first == second
    assert first[1].id == "43089f38-9869-3a86-bcaa-d892e91fcdc3"


def test_duplicate_id_non_bmp_seed_uses_java_utf16_length() -> None:
    sources = _sources()
    emoji = "😀"
    raw = [
        _link("duplicate-" + emoji, "first", [_ref(source_key="first", role="email")]),
        _link(
            "duplicate-" + emoji,
            "source-" + emoji,
            [_ref(source_key="key-" + emoji, role="email")],
        ),
    ]

    assert sources.decode_links(raw)[1].id == "f35fec10-559c-3ef1-b88f-a7ef90dd665c"


def test_explicit_surrogate_pair_encodes_exactly_like_logical_non_bmp_character() -> None:
    sources = _sources()

    def repaired_id(value):
        raw = [
            _link("duplicate-" + value, "first", [_ref(source_key="first", role="email")]),
            _link(
                "duplicate-" + value,
                "source-" + value,
                [_ref(source_key="key-" + value, role="email")],
            ),
        ]
        return sources.decode_links(raw)[1].id

    assert repaired_id("\ud83d\ude00") == repaired_id("😀")
    assert repaired_id("\ud83d\ude00") == "f35fec10-559c-3ef1-b88f-a7ef90dd665c"


def test_public_encode_normalizes_objects_duplicates_and_verification_floor() -> None:
    sources = _sources()
    valid = sources.AutofillFieldRef(None, "value", "email", False)
    links = [
        sources.AutofillLink(" ", "source-blank", (valid,)),
        sources.AutofillLink("blank-source", "\t", (valid,)),
        sources.AutofillLink(
            "mixed", "source-mixed",
            (sources.AutofillFieldRef(None, " ", "email", False), valid),
        ),
        sources.AutofillLink("empty", "source-empty", ()),
        sources.AutofillLink(
            "duplicate", "source-first",
            (sources.AutofillFieldRef(None, "password", "password", False),),
        ),
        sources.AutofillLink("duplicate", "source-second", (valid,)),
    ]

    encoded = sources.encode_links(links)
    decoded = sources.decode_links(encoded)
    assert [link.source_entry_id for link in decoded] == ["source-mixed", "source-first", "source-second"]
    assert len({link.id for link in decoded}) == 3
    assert decoded[1].fields[0].requires_verification is True
    assert encoded[0]["fields"][0]["module_id"] is None
    assert sources.decode_links(encoded) == decoded


def test_public_encode_skips_only_a_malformed_link_sibling() -> None:
    sources = _sources()
    email = sources.AutofillFieldRef(None, "value", "email", False)
    valid_first = sources.AutofillLink("first", "source-first", (email,))
    valid_last = sources.AutofillLink("last", "source-last", (email,))

    encoded = sources.encode_links([valid_first, object(), valid_last])

    assert [link.id for link in sources.decode_links(encoded)] == ["first", "last"]


def test_public_encode_skips_only_a_malformed_ref_within_a_link() -> None:
    sources = _sources()
    email = sources.AutofillFieldRef(None, "email", "email", False)
    phone = sources.AutofillFieldRef("phone-module", "value", "phone", False)
    malformed_in_memory_link = SimpleNamespace(
        id="mixed",
        source_entry_id="source-mixed",
        fields=(email, object(), phone),
    )

    encoded = sources.encode_links([malformed_in_memory_link])
    decoded = sources.decode_links(encoded)

    assert decoded == (sources.AutofillLink("mixed", "source-mixed", (email, phone)),)


def test_encode_into_fields_copies_preserves_and_removes_unrelated_data() -> None:
    sources = _sources()
    original = {"unrelated": {"nested": "keep"}, "autofill_links": "malformed"}
    link = sources.AutofillLink(
        "link", "source", (sources.AutofillFieldRef(None, "value", "email", False),)
    )

    encoded = sources.encode_links_into_fields(original, [link])
    assert encoded is not original
    assert encoded["unrelated"] == {"nested": "keep"}
    assert sources.decode_links(encoded) == (link,)
    assert sources.encode_links_into_fields(encoded, []) == {"unrelated": {"nested": "keep"}}
    assert original["autofill_links"] == "malformed"


def test_entry_read_never_migrates_or_mutates() -> None:
    entry = Entry(fields={"bound_otp_id": "otp-entry", "unrelated": "keep"})
    original_fields = entry.fields.copy()

    assert entry.autofill_links() == ()
    assert entry.fields == original_fields


def test_entry_explicit_migration_is_idempotent_and_invalidates_haystack() -> None:
    entry = Entry(fields={"bound_otp_id": "otp-entry", "unrelated": "keep"})
    assert entry.matches("otp-entry")
    assert entry._haystack

    entry.migrate_autofill_links()
    links = entry.autofill_links()
    assert len(links) == 1
    assert links[0].source_entry_id == "otp-entry"
    assert links[0].fields == (_sources().AutofillFieldRef(None, "@computed/one_time_code", "one_time_code", False),)
    assert "bound_otp_id" not in entry.fields
    assert entry.fields["unrelated"] == "keep"
    assert entry._haystack == ""

    fields_after_first = json.loads(json.dumps(entry.fields))
    entry.migrate_autofill_links()
    assert entry.fields == fields_after_first
    assert len(entry.autofill_links()) == 1


def test_entry_migration_preserves_equivalent_and_adds_for_module_scoped_non_equivalent() -> None:
    sources = _sources()
    equivalent = sources.AutofillLink(
        "otp", "otp-entry",
        (sources.AutofillFieldRef(None, "@computed/one_time_code", "one_time_code", False),),
    )
    entry = Entry(fields=sources.encode_links_into_fields({"bound_otp_id": "otp-entry"}, [equivalent]))
    entry.migrate_autofill_links()
    assert entry.autofill_links() == (equivalent,)

    scoped = sources.AutofillLink(
        "scoped", "otp-entry",
        (sources.AutofillFieldRef("otp-module", "@computed/one_time_code", "one_time_code", False),),
    )
    entry = Entry(fields=sources.encode_links_into_fields({"bound_otp_id": "otp-entry"}, [scoped]))
    entry.migrate_autofill_links()
    assert [ref.module_id for link in entry.autofill_links() for ref in link.fields] == ["otp-module", None]


def test_entry_migration_isolates_malformed_existing_links() -> None:
    sources = _sources()
    existing = _link("email", "contact", [_ref()])
    entry = Entry(
        fields={
            "bound_otp_id": "otp-entry",
            "autofill_links": ["broken", existing],
            "unrelated": 42,
        }
    )

    entry.migrate_autofill_links()
    assert [link.source_entry_id for link in entry.autofill_links()] == ["contact", "otp-entry"]
    assert entry.fields["unrelated"] == 42


@pytest.mark.parametrize("legacy", [None, "", " \t", 7, False, [], {}])
def test_entry_migration_removes_malformed_legacy_without_adding_link(legacy) -> None:
    entry = Entry(fields={"bound_otp_id": legacy, "unrelated": "keep"})
    entry._build_haystack()

    entry.migrate_autofill_links()

    assert entry.autofill_links() == ()
    assert entry.fields == {"unrelated": "keep"}
    assert entry._haystack == ""
