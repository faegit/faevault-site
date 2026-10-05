import json
from pathlib import Path

from core import modules
from core.models import Entry
from core.pmv_entry_codec import decode_entry, encode_entry


FIXTURES = json.loads((Path(__file__).resolve().parents[1] / "spec" / "modules_v1_fixtures.json").read_text("utf-8"))


def test_cross_platform_module_fixtures_roundtrip_and_protection():
    for case in FIXTURES["cases"]:
        normalized = modules.normalize_modules(case["modules"])
        entry = Entry(secret_type=case["secret_type"], fields={"modules": normalized})
        restored = decode_entry(encode_entry(entry))
        out = modules.modules_from_fields(restored.fields)
        assert [item["type"] for item in out] == [item["type"] for item in normalized]
        assert len({item["id"] for item in out}) == len(out)
        if case["name"] == "secure_note_sensitive":
            assert out[0]["future"] == "preserve"
        if case["name"] == "server_mixed":
            assert out[0]["config"]["futureConfig"] == 7
            assert not entry.matches("secret")
        if case["name"] == "mandatory_sensitive_false":
            assert out[0]["sensitive"] is True
            assert not entry.matches("must-stay-hidden")
        if case["name"] == "otp_with_domains":
            assert entry.has_otp()
            assert entry.otp_fields()["secret"] == "JBSWY3DPEHPK3PXP"
            assert entry.otp_fields()["issuer"] == "GitHub"
            assert entry.otp_domains() == ["github.com", "www.github.com"]


def test_shared_fixtures_cover_contact_text_variants_and_custom_modules():
    cases = {case["name"]: case for case in FIXTURES["cases"]}
    contacts = modules.normalize_modules(cases["autofill_contact_text_variants"]["modules"])
    assert [item["type"] for item in contacts] == [modules.TEXT, modules.TEXT, modules.TEXT]
    assert [modules.configured_autofill_role(item) for item in contacts] == ["email", "phone", "postal_code"]

    def round_tripped(name):
        case = cases[name]
        entry = Entry(
            secret_type=case["secret_type"],
            fields={"modules": modules.normalize_modules(case["modules"])},
        )
        restored = decode_entry(encode_entry(entry))
        return modules.modules_from_fields(restored.fields)[0]

    assert round_tripped("custom_text_email_role")["config"]["autofill_role"] == "email"
    assert "autofill_role" not in round_tripped("custom_text_exact_name")["config"]
    assert round_tripped("custom_password_secret_role")["config"]["autofill_role"] == "custom_secret"
    assert round_tripped("custom_text_unknown_role")["config"] == {
        "autofill_role": "future_role", "future_config": "keep",
    }

