import io
import json
import struct

import pytest

from core import browser_autofill as autofill
from core.models import Entry, SecretType


def test_normalize_origin_accepts_https_and_removes_default_port():
    assert autofill.normalize_origin("https://LOGIN.Example.com:443") == "https://login.example.com"
    assert autofill.normalize_origin("https://bücher.example:8443/") == "https://xn--bcher-kva.example:8443"


@pytest.mark.parametrize(
    ("origin", "normalized"),
    (
        ("https://192.168.1.10", "https://192.168.1.10"),
        ("https://10.0.0.5:8443", "https://10.0.0.5:8443"),
        ("https://[fc00::10]:9443", "https://[fc00::10]:9443"),
        ("https://127.0.0.1", "https://127.0.0.1"),
        ("https://[::1]", "https://[::1]"),
    ),
)
def test_ip_origins_require_explicit_parser_permission(origin, normalized):
    with pytest.raises(autofill.ProtocolError):
        autofill.normalize_origin(origin)
    assert autofill.normalize_origin(origin, allow_ip=True) == normalized
    assert autofill.is_ip_origin(normalized)


@pytest.mark.parametrize("origin", ("https://8.8.8.8", "https://169.254.1.2", "https://[fe80::1]"))
def test_public_and_link_local_ips_can_reach_explicit_authorization(origin):
    assert autofill.normalize_origin(origin, allow_ip=True) == origin
    assert autofill.is_ip_origin(origin)


@pytest.mark.parametrize("origin", ("https://0.0.0.0", "https://224.0.0.1", "https://[ff02::1]"))
def test_non_unicast_ip_origins_cannot_be_authorized(origin):
    with pytest.raises(autofill.ProtocolError):
        autofill.normalize_origin(origin, allow_ip=True)


@pytest.mark.parametrize(
    "origin",
    (
        "http://example.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://user@example.com",
        "https://example.com/login",
        "https://example.com?next=x",
        "not a url",
    ),
)
def test_normalize_origin_rejects_untrusted_values(origin):
    with pytest.raises(autofill.ProtocolError) as caught:
        autofill.normalize_origin(origin)
    assert caught.value.code == "INVALID_ORIGIN"


def test_matching_entries_requires_exact_origin_and_fillable_login():
    entries = [
        Entry(id="exact", title="Exact", url="https://example.com/login", username="u", password="p"),
        Entry(id="sub", title="Sub", url="https://login.example.com", username="u", password="p"),
        Entry(id="http", title="HTTP", url="http://example.com", username="u", password="p"),
        Entry(id="empty", title="Empty", url="https://example.com", username="u", password=""),
        Entry(id="wifi", title="Wifi", url="https://example.com", password="p", secret_type=SecretType.WIFI),
    ]

    assert [item.id for item in autofill.matching_entries(entries, "https://example.com")] == ["empty", "exact"]


def test_parse_request_validates_action_specific_fields():
    request = autofill.parse_request(
        {
            "version": 1,
            "requestId": "req-1",
            "action": "save",
            "origin": "https://example.com",
            "title": "Example",
            "username": " alice ",
            "password": "secret",
        }
    )

    assert request.origin == "https://example.com"
    assert request.username == "alice"
    assert request.password == "secret"


def test_parse_unlock_request_keeps_master_password_out_of_credential_field():
    request = autofill.parse_request(
        {"version": 1, "requestId": "unlock-1", "action": "unlock", "masterPassword": "master secret"}
    )

    assert request.master_password == "master secret"
    assert request.password == ""

    for invalid in ("", "x" * 129, None):
        with pytest.raises(autofill.ProtocolError):
            autofill.parse_request(
                {"version": 1, "requestId": "unlock-2", "action": "unlock", "masterPassword": invalid}
            )


def test_parse_request_accepts_private_ip_for_native_authorization():
    request = autofill.parse_request(
        {"version": 1, "requestId": "private-1", "action": "list", "origin": "https://192.168.1.20:8443"}
    )
    assert request.origin == "https://192.168.1.20:8443"

    authorize = autofill.parse_request(
        {"version": 1, "requestId": "authorize-1", "action": "authorize", "origin": "https://100.64.0.5"}
    )
    assert authorize.action == "authorize"
    assert authorize.origin == "https://100.64.0.5"


def test_native_message_roundtrip_and_size_limit():
    target = io.BytesIO()
    message = {"version": 1, "requestId": "r", "action": "status"}
    autofill.write_message(target, message)
    target.seek(0)
    assert autofill.read_message(target) == message

    oversized = io.BytesIO(struct.pack("<I", autofill.MAX_MESSAGE_BYTES + 1))
    with pytest.raises(autofill.ProtocolError):
        autofill.read_message(oversized)


def test_invalid_json_frame_is_rejected():
    payload = b"{not-json}"
    stream = io.BytesIO(struct.pack("<I", len(payload)) + payload)
    with pytest.raises(autofill.ProtocolError) as caught:
        autofill.read_message(stream)
    assert caught.value.code == "INVALID_REQUEST"


def test_failure_response_never_contains_exception_details():
    response = autofill.failure("r", autofill.ProtocolError("LOCKED", "保险库已锁定", retryable=True))
    encoded = json.dumps(response, ensure_ascii=False)
    assert response["error"] == {"code": "LOCKED", "message": "保险库已锁定", "retryable": True}
    assert "Traceback" not in encoded


def test_word_suggestions_are_case_insensitive_whole_words_and_not_origin_authorization():
    word = Entry(title="EXAMPLE account", password="p", url="https://different.test")
    substring = Entry(title="exampleplus", password="p")
    url = Entry(title="Other", password="p", url="https://EXAMPLE.net")
    module = Entry(title="Module", password="p", fields={"modules": [
        {"type": "url", "value": "https://Example.org/login"}]})
    passkey = Entry(title="Example", password="p", secret_type=SecretType.PASSKEY)
    assert {e.id for e in autofill.word_matching_entries([word, substring, url, module, passkey], "https://example.com")} == {word.id, url.id, module.id}
    assert autofill.matching_entries([word, url, module], "https://example.com") == []
    assert autofill.word_matching_entries([word], "https://192.168.1.10") == []


def test_word_suggestions_decode_idna_and_do_not_match_domain_suffix():
    unicode_entry = Entry(title="BÜCHER account", password="p")
    suffix = Entry(title="Com account", password="p")
    partial = Entry(title="bücherplus", password="p")
    assert autofill.word_matching_entries([unicode_entry, suffix, partial], "https://xn--bcher-kva.com") == [unicode_entry]
