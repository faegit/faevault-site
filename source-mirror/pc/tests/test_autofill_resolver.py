import pytest

from core import autofill_sources as sources, modules
from core.autofill_resolver import resolve_snapshot, source_values
from core.models import Entry, SecretType


def linked(role, source, module_id, source_key="value", verification=False):
    return sources.AutofillLink(
        "link-" + role,
        source.id,
        (sources.AutofillFieldRef(module_id, source_key, role, verification),),
    )


def test_external_choice_overrides_internal_and_sensitive_internal_stays_protected():
    internal_email = modules.with_autofill_role(modules.new_module(modules.TEXT), "email")
    internal_email["value"] = "internal@example.com"
    external_email = modules.with_autofill_role(modules.new_module(modules.TEXT), "email")
    external_email["value"] = "external@example.com"
    contact = Entry(title="Contact", fields=modules.fields_with_modules({}, [external_email]))
    login = Entry(title="Login", username="alice", password="internal-secret", secret_type=SecretType.LOGIN)
    login.fields = modules.fields_with_modules(login.fields, [internal_email])
    login.fields = sources.encode_links_into_fields(
        login.fields,
        [linked("email", contact, external_email["id"])],
    )

    snapshot = resolve_snapshot(login, [login, contact], now=1_700_000_000)

    assert snapshot["email"].value == "external@example.com"
    assert snapshot["password"].value == "internal-secret"
    assert snapshot["password"].requires_verification is True


def test_missing_external_choice_fails_closed_without_internal_fallback():
    internal = modules.with_autofill_role(modules.new_module(modules.TEXT), "email")
    internal["value"] = "internal@example.com"
    login = Entry(title="Login", fields=modules.fields_with_modules({}, [internal]))
    missing = Entry(title="Missing")
    login.fields = sources.encode_links_into_fields(
        login.fields,
        [linked("email", missing, "gone")],
    )

    snapshot = resolve_snapshot(login, [login])

    assert snapshot.get("email") is None
    assert snapshot.unavailable_roles == frozenset({"email"})


@pytest.mark.parametrize("role", ("email", "phone", "postal_code"))
def test_contact_roles_are_text_variants(role):
    variant = modules.with_autofill_role(modules.new_module(modules.TEXT), role)
    variant["value"] = "value"
    entry = Entry(fields=modules.fields_with_modules({}, [variant]))

    assert resolve_snapshot(entry, [entry])[role].value == "value"


@pytest.mark.parametrize(
    ("secret_type", "fields", "expected"),
    (
        (SecretType.CARD_DOCUMENT, {
            "full_name": "Alice", "id_number": "110", "cardholder": "A. Li",
            "card_number": "4111111111111111", "expiry": "12/30", "cvv": "123",
        }, {"full_name": "full_name", "id_number": "id_number", "cardholder": "cardholder",
            "card_number": "card_number", "card_expiry": "expiry", "card_cvv": "cvv"}),
        (SecretType.WIFI, {"ssid": "Home", "wifi_password": "wifi", "admin_password": "router"},
         {"ssid": "ssid", "wifi_password": "admin_password"}),
        (SecretType.API_KEY, {"api_key": "key", "api_secret": "secret"},
         {"api_key": "api_key", "api_secret": "api_secret"}),
        (SecretType.SERVER, {"server_host": "db.local", "server_port": "5432", "server_user": "alice", "server_pass": "pw"},
         {"host": "server_host", "port": "server_port", "username": "server_user", "password": "server_pass"}),
    ),
)
def test_android_top_level_builtin_fields_are_selectable_sources(secret_type, fields, expected):
    entry = Entry(secret_type=secret_type, fields=fields)

    values = {value.role: value for value in source_values(entry)}

    assert {role: value.source_key for role, value in values.items()} == expected


def test_android_top_level_otp_is_a_computed_source():
    entry = Entry(secret_type=SecretType.OTP, fields={"secret": "JBSWY3DPEHPK3PXP", "period": "30"})

    values = source_values(entry, now=59)

    assert [(value.role, value.module_id, value.source_key) for value in values] == [
        ("one_time_code", None, "@computed/one_time_code")
    ]
