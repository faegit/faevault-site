import json
import re
from pathlib import Path


FIXTURE = Path(__file__).resolve().parents[1] / "spec" / "autofill_sources_v1_fixtures.json"

EXPECTED_CASE_NAMES = {
    "policy_cases": [
        "safe_street_address",
        "safe_postal_code",
        "sensitive_card_cvv",
        "excluded_withdrawal_password",
        "excluded_passkey_private_key",
        "excluded_otp_secret",
        "computed_otp_code",
    ],
    "migration_cases": ["legacy_bound_otp"],
    "normalization_cases": [
        "ascii_trim_and_hyphen",
        "unicode_whitespace",
        "ascii_case_and_underscore",
        "ascii_case_and_dot",
        "ascii_slash",
    ],
    "resolution_cases": [
        "priority_top_level_modules_external",
        "safe_external_value_selection",
        "duplicate_role_shadowing",
        "missing_source",
        "missing_module",
        "empty_field",
        "one_hop_only",
        "non_sensitive_custom_exact_name",
        "sensitive_custom_never_title_matched",
        "computed_otp_only",
        "malformed_sibling_link_isolation",
    ],
}

EXPECTED_ISSUE_ORDER = {
    "priority_top_level_modules_external": [
        "ROLE_SHADOWED",
        "ROLE_SHADOWED",
        "ROLE_SHADOWED",
    ],
    "safe_external_value_selection": [],
    "duplicate_role_shadowing": ["ROLE_SHADOWED"],
    "missing_source": ["SOURCE_ENTRY_MISSING"],
    "missing_module": ["SOURCE_MODULE_MISSING"],
    "empty_field": ["SOURCE_FIELD_EMPTY"],
    "one_hop_only": [],
    "non_sensitive_custom_exact_name": [],
    "sensitive_custom_never_title_matched": [],
    "computed_otp_only": [],
    "malformed_sibling_link_isolation": [],
}

KNOWN_ISSUE_CODES = {
    "SOURCE_ENTRY_MISSING",
    "SOURCE_MODULE_MISSING",
    "SOURCE_FIELD_EMPTY",
    "ROLE_SHADOWED",
}

FORBIDDEN_STORED_KEY = re.compile(
    r"password|passwd|secret|seed|private[^a-z0-9]*key|credential[^a-z0-9]*id|aaguid|token|notes?",
    re.I,
)
SECRET_LIKE_VALUE = re.compile(
    r"^\d{6,8}$|BEGIN [A-Z ]*PRIVATE KEY|otpauth://|(?:password|passwd|secret|seed|token)\s*[:=]",
    re.I,
)


def _document() -> dict:
    assert FIXTURE.is_file(), f"shared autofill fixture must exist: {FIXTURE}"
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_fixture_has_stable_version_sections_and_unique_case_names() -> None:
    root = _document()
    assert root["version"] == 1
    for section, expected_names in EXPECTED_CASE_NAMES.items():
        assert isinstance(root[section], list)
        assert all(isinstance(case, dict) for case in root[section])
        names = []
        for index, case in enumerate(root[section]):
            assert isinstance(case.get("name"), str), f"{section}[{index}].name must be a string"
            assert case["name"].strip(), f"{section}[{index}].name must be nonblank"
            names.append(case["name"])
        assert len(names) == len(set(names)), f"{section} case names must be unique"
        assert names == expected_names, f"{section} case order is part of the contract"


def test_policy_migration_and_normalization_cases_lock_required_behavior() -> None:
    root = _document()
    policies = root["policy_cases"]

    def assert_policy(module_type, field, role, internal, external_default, verification):
        policy = next(
            case
            for case in policies
            if case["module_type"] == module_type and case["field"] == field
        )
        assert policy["role"] == role
        assert policy["internal"] is internal
        assert policy["external_default"] is external_default
        assert policy["verification"] is verification

    assert_policy("address", "address", "street_address", True, True, False)
    assert_policy("card_document", "cvv", "card_cvv", True, False, True)
    assert_policy("card_document", "withdrawal_password", None, False, False, True)
    assert_policy("passkey", "private_key", None, False, False, True)
    assert_policy("otp", "secret", None, False, False, True)
    assert_policy("otp", "@computed/one_time_code", "one_time_code", True, True, False)
    assert {case["policy_class"] for case in policies} == {
        "safe_internal_external",
        "sensitive_opt_in",
        "permanently_excluded",
        "computed_otp",
    }

    migration = next(
        case
        for case in root["migration_cases"]
        if case["fields"].get("bound_otp_id") == "otp-entry"
    )
    assert migration["expected_source_entry_id"] == "otp-entry"
    assert migration["expected_source_key"] == "@computed/one_time_code"
    assert migration["expected_role"] == "one_time_code"

    normalizations = {case["input"]: case["expected"] for case in root["normalization_cases"]}
    assert normalizations[" Billing-email "] == "billingemail"
    assert normalizations["账单 邮箱"] == "账单邮箱"
    assert normalizations["BILLING_EMAIL"] == "billingemail"
    assert normalizations["Billing.Email"] == "billingemail"
    assert normalizations["billing/email"] == "billingemail"


def test_resolution_cases_have_complete_inputs_and_ordered_expected_values() -> None:
    cases = _document()["resolution_cases"]
    assert [case["name"] for case in cases] == EXPECTED_CASE_NAMES["resolution_cases"]

    expected_keys = {
        "role",
        "source_entry_id",
        "module_id",
        "source_key",
        "value",
        "requires_verification",
    }
    for case in cases:
        case_name = case["name"]
        input_data = case["input"]
        _assert_nonblank_string(input_data, "host_entry_id", f"{case_name}.input")
        assert isinstance(input_data["entries"], list)
        entries = input_data["entries"]
        assert any(entry["id"] == input_data["host_entry_id"] for entry in entries)
        for entry in entries:
            assert {"id", "type", "title", "fields", "modules"} <= entry.keys()
            _assert_nonblank_string(entry, "id", f"{case_name}.entry")
            _assert_nonblank_string(entry, "type", f"{case_name}.entry")
            _assert_nonblank_string(entry, "title", f"{case_name}.entry")
            assert isinstance(entry["fields"], dict)
            assert isinstance(entry["modules"], list)
            for module in entry["modules"]:
                assert {"id", "type", "title", "fields", "config"} <= module.keys()
                _assert_nonblank_string(module, "id", f"{case_name}.module")
                _assert_nonblank_string(module, "type", f"{case_name}.module")
                _assert_nonblank_string(module, "title", f"{case_name}.module")
                assert isinstance(module["fields"], dict)
                assert isinstance(module["config"], dict)
            links = entry["fields"].get("autofill_links", [])
            assert isinstance(links, list)
            for link_index, link in enumerate(links):
                assert isinstance(link, dict), f"{case_name}.link[{link_index}] must be an object"
                if case_name == "malformed_sibling_link_isolation" and link_index == 0:
                    assert link == {
                        "id": "link-malformed",
                        "source_entry_id": 7,
                        "fields": "invalid",
                    }
                    continue
                _assert_nonblank_string(link, "id", f"{case_name}.link[{link_index}]")
                _assert_nonblank_string(
                    link,
                    "source_entry_id",
                    f"{case_name}.link[{link_index}]",
                )
                assert isinstance(link.get("fields"), list)
                for ref_index, ref in enumerate(link["fields"]):
                    assert isinstance(ref, dict)
                    assert set(ref) == {
                        "module_id",
                        "source_key",
                        "role",
                        "requires_verification",
                    }
                    module_id = ref["module_id"]
                    assert module_id is None or isinstance(module_id, str) and module_id.strip()
                    path = f"{case_name}.link[{link_index}].fields[{ref_index}]"
                    _assert_nonblank_string(ref, "source_key", path)
                    _assert_nonblank_string(ref, "role", path)
                    assert isinstance(ref["requires_verification"], bool)

        assert isinstance(case["expected"], list)
        for expected in case["expected"]:
            assert set(expected) == expected_keys
            _assert_nonblank_string(expected, "role", f"{case_name}.expected")
            _assert_nonblank_string(expected, "source_entry_id", f"{case_name}.expected")
            module_id = expected["module_id"]
            assert module_id is None or isinstance(module_id, str) and module_id.strip()
            _assert_nonblank_string(expected, "source_key", f"{case_name}.expected")
            _assert_nonblank_string(expected, "value", f"{case_name}.expected")
            assert isinstance(expected["requires_verification"], bool)

        assert isinstance(case.get("expected_issues"), list)
        assert all(isinstance(code, str) and code in KNOWN_ISSUE_CODES for code in case["expected_issues"])
        assert case["expected_issues"] == EXPECTED_ISSUE_ORDER[case_name]


def test_fixture_contains_no_secret_material_or_secret_bearing_resolution_fields() -> None:
    root = _document()
    for case in root["resolution_cases"]:
        violations = _secret_violations(case["input"])
        assert not violations, f"{case['name']} contains secret material: {violations}"

    computed_otp = next(case for case in root["resolution_cases"] if case["name"] == "computed_otp_only")
    serialized_input = json.dumps(computed_otp["input"], ensure_ascii=False).lower()
    for forbidden in ('"secret"', '"seed"', '"algorithm"', '"digits"', '"period"', '"counter"'):
        assert forbidden not in serialized_input
    assert [item["source_key"] for item in computed_otp["expected"]] == [
        "@computed/one_time_code"
    ]


def test_recursive_secret_scanner_rejects_nested_keys_and_material() -> None:
    nested_secret_key = {"modules": [{"config": {"SeCrEt": "SHOULD_BE_REJECTED"}}]}
    nested_secret_value = {
        "fields": {"profile": {"value": "password=SHOULD_BE_REJECTED"}}
    }

    assert _secret_violations(nested_secret_key)
    assert _secret_violations(nested_secret_value)


def _secret_violations(value) -> list[str]:
    violations = []

    def walk(item, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                child_path = f"{path}.{key}"
                if FORBIDDEN_STORED_KEY.search(key):
                    violations.append(f"forbidden key at {child_path}")
                walk(child, child_path)
        elif isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]")
        elif isinstance(item, str):
            if item != "VALUE_REDACTED" and SECRET_LIKE_VALUE.search(item):
                violations.append(f"secret-like value at {path}")

    walk(value, "input")
    return violations


def _assert_nonblank_string(value: dict, key: str, path: str) -> None:
    assert isinstance(value.get(key), str), f"{path}.{key} must be a string"
    assert value[key].strip(), f"{path}.{key} must be nonblank"
