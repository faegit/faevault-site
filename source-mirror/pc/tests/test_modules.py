import copy

from core import modules
from core.models import Entry, SecretType


def test_boolean_module_uses_native_bool_and_reads_legacy_strings():
    created = modules.new_module(modules.BOOLEAN)
    assert created["value"] is False
    created["value"] = "true"
    assert modules.normalize_modules([created])[0]["value"] is True


def test_contact_values_use_text_variants_instead_of_dedicated_modules():
    for removed_type in ("email", "phone", "postal_code"):
        assert removed_type not in modules.CATALOG
        assert modules.default_autofill_role(removed_type) is None

    for role in ("email", "phone", "postal_code"):
        text = modules.with_autofill_role(modules.new_module(modules.TEXT), role)
        assert text["type"] == modules.TEXT
        assert modules.configured_autofill_role(text) == role


def test_custom_autofill_role_options_are_stable_and_excluded_kinds_have_none():
    from core import autofill_sources

    non_sensitive_text = tuple(
        role for role in autofill_sources.AUTOFILL_ROLES
        if role not in autofill_sources.SENSITIVE_ROLES
    )
    password = (
        "password", "card_cvv", "id_number", "api_key", "api_secret",
        "wifi_password", "recovery_answer", "custom_secret",
    )
    assert modules.autofill_role_options(modules.TEXT) == non_sensitive_text
    assert modules.autofill_role_options(modules.TEXT, sensitive=True) == autofill_sources.AUTOFILL_ROLES
    assert modules.autofill_role_options(modules.PASSWORD) == password
    assert modules.autofill_role_options(modules.DATETIME) == ("card_expiry", "custom_text")
    for module_type in (
        modules.MULTILINE, modules.BOOLEAN, modules.IMAGES, modules.ATTACHMENTS,
        modules.PASSKEY, modules.OTP, modules.SSH,
        "email", "phone", "postal_code",
    ):
        assert modules.autofill_role_options(module_type) == ()


def test_custom_autofill_role_config_roundtrips_and_unknown_values_stay_opaque():
    raw = modules.new_module(modules.TEXT)
    raw["config"] = {"autofill_role": "future_role", "futureConfig": 7}
    normalized = modules.normalize_modules([raw])[0]
    assert normalized["config"] == {"autofill_role": "future_role", "futureConfig": 7}
    assert modules.configured_autofill_role(normalized) is None

    selected = modules.with_autofill_role(normalized, "email")
    assert modules.configured_autofill_role(selected) == "email"
    assert selected["config"]["futureConfig"] == 7
    cleared = modules.with_autofill_role(selected, None)
    assert "autofill_role" not in cleared["config"]


def test_datetime_modes_have_stable_defaults_and_local_wall_time_values():
    created = modules.new_module(modules.DATETIME)
    assert created["config"] == {"mode": "datetime"}
    assert modules.valid_datetime_value("date", "2026-08-20")
    assert modules.valid_datetime_value("time", "23:59")
    assert modules.valid_datetime_value("datetime", "2026-08-20T23:59")
    assert not modules.valid_datetime_value("datetime", "2026-08-20T23:59Z")


def test_supported_card_type_templates_preserve_existing_and_unknown_values():
    card = modules.new_module(modules.CARD_DOCUMENT)
    assert card["title"] == "卡证"
    assert card["value"]["card_type"] == modules.CARD_BANK
    card["value"].update(bank="Example Bank", future_field={"keep": True})

    for card_type in (modules.CARD_BANK, modules.CARD_ID_CARD, modules.CARD_CUSTOM):
        value = modules.card_value_for_type(card["value"], card_type)
        assert value["card_type"] == card_type
        assert value["bank"] == "Example Bank"
        assert value["future_field"] == {"keep": True}
        assert set(modules.CARD_FIELDS[card_type]) <= value.keys()
        assert value["images"] == []


def test_module_qr_image_decoder_reads_otpauth_payload():
    import io
    import qrcode
    from ui.module_editor import _decode_qr_bytes

    payload = "otpauth://totp/Test:alice?secret=JBSWY3DPEHPK3PXP&issuer=Test"
    image = qrcode.make(payload)
    output = io.BytesIO()
    image.save(output, format="PNG")

    assert _decode_qr_bytes(output.getvalue()) == [payload]


def test_wifi_qr_parser_handles_escaping_and_open_networks():
    from ui.module_editor import _parse_wifi_qr

    assert _parse_wifi_qr(r"WIFI:T:WPA;S:Home\;Lab;P:pa\:ss\\word;;") == {
        "ssid": "Home;Lab",
        "wifi_password": r"pa:ss\word",
        "security_type": "WPA-Personal",
    }
    assert _parse_wifi_qr("WIFI:T:nopass;S:Guest;P:;;") == {
        "ssid": "Guest",
        "wifi_password": "",
        "security_type": "无加密",
    }


def test_wifi_qr_parser_rejects_invalid_or_oversized_fields():
    from ui.module_editor import _parse_wifi_qr

    assert _parse_wifi_qr("otpauth://totp/Test?secret=A") is None
    assert _parse_wifi_qr("WIFI:T:WPA;S:;P:secret;;") is None
    assert _parse_wifi_qr(f"WIFI:T:WPA;S:{'a' * 33};P:secret;;") is None


def test_wifi_qr_parser_normalizes_personal_variant_security():
    from ui.module_editor import _parse_wifi_qr

    assert _parse_wifi_qr("WIFI:T:WPA3-Personal;S:Home;P:hunter2;;")["security_type"] == "WPA3-Personal"
    assert _parse_wifi_qr("WIFI:T:WPA2-Personal;S:Home;P:hunter2;;")["security_type"] == "WPA2-Personal"
    assert _parse_wifi_qr("WIFI:T:SAE;S:Home;P:hunter2;;")["security_type"] == "WPA3-Personal"
    assert _parse_wifi_qr("WIFI:T:Open;S:Guest;P:;;")["security_type"] == "无加密"


def test_normalize_wifi_security_contract():
    from core.modules import normalize_wifi_security, wifi_qr_auth_token

    assert normalize_wifi_security("") == "无加密"
    assert normalize_wifi_security(None) == "无加密"
    assert normalize_wifi_security("nopass") == "无加密"
    assert normalize_wifi_security("WPA2-Personal") == "WPA2-Personal"
    assert normalize_wifi_security("WPA3-Personal") == "WPA3-Personal"
    assert normalize_wifi_security("WPA3-SAE") == "WPA3-Personal"
    assert normalize_wifi_security("Open") == "无加密"
    assert normalize_wifi_security("WPA3-ENTERPRISE") == "WPA3-Enterprise"

    # 二维码 T 字段：WPA 族聚合为 WPA，WEP 精确保留
    assert wifi_qr_auth_token("WPA-Personal", True) == "WPA"
    assert wifi_qr_auth_token("WPA2-Personal", True) == "WPA"
    assert wifi_qr_auth_token("WPA3-Personal", True) == "WPA"
    assert wifi_qr_auth_token("WPA2/WPA3-Personal", True) == "WPA"
    assert wifi_qr_auth_token("WEP", True) == "WEP"
    assert wifi_qr_auth_token("无加密", False) == "nopass"
    # 密码存在时禁止 nopass
    assert wifi_qr_auth_token("无加密", True) == "WPA"


def test_deleted_qt_worker_reference_is_treated_as_finished():
    from ui.module_editor import ModuleCard

    class DeletedWorker:
        def isRunning(self):
            raise RuntimeError("Internal C++ object already deleted")

    class CardState:
        _worker = DeletedWorker()

    state = CardState()
    assert ModuleCard._worker_is_running(state) is False
    assert state._worker is None


def test_normalize_modules_preserves_unknown_and_repairs_ids():
    raw = [
        {"id": "same", "type": "future", "title": "", "future": 1, "value": {"x": "y"}},
        {"id": "same", "type": modules.TEXT, "value": "hello"},
    ]
    out = modules.normalize_modules(raw)
    assert out[0]["future"] == 1
    assert out[0]["title"] == "未知模块"
    assert out[0]["id"] != out[1]["id"]
    assert out[1]["title"] == "文本"


def test_mandatory_sensitive_defaults_cannot_be_disabled():
    password = modules.normalize_modules([{"type": modules.PASSWORD, "sensitive": False}])[0]
    assert password["sensitive"] is True
    assert "secret" in modules.mandatory_sensitive_fields(modules.OTP)
    passkey = modules.normalize_modules([{"type": modules.PASSKEY, "sensitive": False}])[0]
    assert passkey["sensitive"] is True
    assert "private_key" in modules.mandatory_sensitive_fields(modules.PASSKEY)


def test_passkey_module_default_declares_complete_v2_metadata():
    assert modules.CATALOG[modules.PASSKEY]["default"] == {
        "schema_version": "2",
        "rp_id": "",
        "rp_name": "",
        "user_id": "",
        "user_name": "",
        "user_display_name": "",
        "credential_id": "",
        "private_key": "",
        "public_key": "",
        "algorithm": "-7",
        "transports": "internal",
        "aaguid": "",
        "discoverable": "true",
        "backup_eligible": "true",
        "backup_state": "true",
        "counter_mode": "synced_zero",
        "sign_count": "0",
        "created_at": "",
        "last_used_at": "",
    }


def test_normalize_modules_does_not_merge_or_rewrite_existing_passkey_value():
    raw = [{
        "id": "android-passkey",
        "type": modules.PASSKEY,
        "title": "Provider record",
        "sensitive": True,
        "required": False,
        "config": {"provider": "android"},
        "value": {
            "credential_id": "opaque-source-encoding",
            "future_field": {"revision": 7},
        },
        "future_module_field": ["keep"],
    }]
    original = copy.deepcopy(raw)

    normalized = modules.normalize_modules(raw)

    assert raw == original
    assert normalized[0]["value"] == original[0]["value"]
    assert normalized[0]["future_module_field"] == ["keep"]
    normalized[0]["value"]["future_field"]["revision"] = 8
    assert raw == original


def test_compound_module_values_drop_only_empty_text_placeholders():
    assert modules.compact_compound_value({
        "host": "",
        "port": "22",
        "username": "   ",
        "future": {"preserve": True},
    }) == {"port": "22", "future": {"preserve": True}}
    assert modules.new_module(modules.SSH)["value"]["port"] == ""


def test_card_document_module_has_cross_platform_image_collection():
    assert modules.new_module(modules.CARD_DOCUMENT)["value"]["images"] == []
    card = modules.new_module(modules.CARD_DOCUMENT)
    card["value"] = {"bank": "Example Bank", "images": ["base64-secret"]}
    assert modules.searchable_values(card) == ["Example Bank"]


def test_deleted_card_module_types_are_not_rewritten_to_card_document():
    for deleted_type in ("bank_card", "identity_document"):
        raw = [{"id": f"deleted-{deleted_type}", "type": deleted_type, "sensitive": False,
                "value": {"full_name": "测试"}}]
        normalized = modules.normalize_modules(raw)
        assert normalized[0]["type"] == deleted_type


def test_attachment_module_is_sensitive_and_cross_platform_serializable():
    attachment = modules.new_module(modules.ATTACHMENTS)
    assert attachment["sensitive"] is True
    attachment["value"] = [{"name": "report.pdf", "size": 3, "sha256": "abc", "data": "YWJj"}]
    normalized = modules.normalize_modules([attachment])[0]
    assert normalized["value"][0]["name"] == "report.pdf"
    assert modules.searchable_values(normalized) == []


def test_detail_modules_keep_attachments_and_only_consume_primary_specialized_module():
    cases = [
        (SecretType.LOGIN, [modules.TARGET_APP, modules.OTP], [modules.ATTACHMENTS, modules.TARGET_APP]),
        (SecretType.OTP, [modules.OTP], [modules.ATTACHMENTS, modules.OTP]),
        (SecretType.SECURE_NOTE, [modules.MULTILINE], [modules.ATTACHMENTS, modules.MULTILINE]),
        (SecretType.SERVER, [modules.SERVER_CONNECTION], [modules.ATTACHMENTS, modules.SERVER_CONNECTION]),
    ]
    for secret_type, consumed, expected in cases:
        module_list = [modules.new_module(t) for t in consumed]
        module_list.append(modules.new_module(modules.ATTACHMENTS))
        module_list.append(modules.new_module(consumed[0]))
        fields = modules.fields_with_modules({}, module_list)
        assert [item["type"] for item in modules.detail_modules(fields, secret_type)] == expected


def test_search_excludes_sensitive_module_values_and_compound_fields():
    entry = Entry(
        title="server",
        secret_type=SecretType.SERVER,
        fields=modules.fields_with_modules(
            {},
            [
                {"type": modules.TEXT, "title": "region", "value": "beijing"},
                {"type": modules.PASSWORD, "title": "secret", "value": "never-index"},
                {
                    "type": modules.SERVER_CONNECTION,
                    "title": "server",
                    "value": {"host": "example.internal", "password": "root-secret"},
                },
            ],
        ),
    )
    assert entry.matches("beijing")
    assert entry.matches("example.internal")
    assert not entry.matches("never-index")
    assert not entry.matches("root-secret")


def test_searchable_values_handles_cycles_depth_tuples_and_shared_aliases():
    cycle = []
    cycle.append(cycle)
    shared = {"label": "shared-value"}
    deep = "too-deep"
    for _ in range(70):
        deep = [deep]
    module = {
        "type": modules.TEXT,
        "sensitive": False,
        "value": {
            "cycle": cycle,
            "tuple": ("tuple-value",),
            "left": shared,
            "right": shared,
            "deep": deep,
        },
    }

    values = modules.searchable_values(module)

    assert "tuple-value" in values
    assert values.count("shared-value") == 2
    assert "too-deep" not in values


def test_searchable_values_skips_oversized_containers_without_crashing():
    module = {
        "type": modules.TEXT,
        "sensitive": False,
        "value": {"oversized": ["hidden"] * 1_001, "normal": "visible"},
    }

    assert modules.searchable_values(module) == ["visible"]


def test_new_categories_and_presets():
    assert SecretType.SECURE_NOTE in SecretType.ALL
    assert SecretType.SERVER in SecretType.ALL
    assert SecretType.CUSTOM in SecretType.ALL
    assert modules.preset_modules(SecretType.CUSTOM) == []
    assert modules.preset_modules(SecretType.SECURE_NOTE)[0]["required"] is True
    assert modules.preset_modules(SecretType.SERVER)[0]["type"] == modules.SERVER_CONNECTION


def test_passkey_is_persisted_but_not_manually_creatable():
    assert SecretType.PASSKEY in SecretType.NAV_TYPES
    assert SecretType.PASSKEY in SecretType.ALL
    assert SecretType.PASSKEY not in SecretType.CREATABLE


def test_legacy_login_with_passkey_module_is_migrated():
    module = modules.new_module(modules.PASSKEY)
    fields = modules.fields_with_modules({}, [module])
    entry = Entry(secret_type=SecretType.LOGIN, fields=fields)
    assert entry.secret_type == SecretType.PASSKEY


def test_module_card_expiry_is_visible_to_list_status():
    module = modules.new_module(modules.CARD_DOCUMENT)
    module["value"]["expiry"] = "01/20"
    entry = Entry(
        secret_type=SecretType.CARD_DOCUMENT,
        fields=modules.fields_with_modules({}, [module]),
    )
    assert entry.expiry_status() == "expired"


def test_target_app_module_fallback():
    fields = modules.fields_with_modules({}, [modules.new_module(modules.TARGET_APP)])
    fields[modules.MODULES_KEY][0]["value"] = "com.example.android"
    assert modules.target_app_value(fields) == "com.example.android"


def test_otp_domains_parsing_handles_separators_and_schemes():
    from core import otp

    assert otp.parse_otp_domains("https://example.com, www.example.com；baidu.cn") == [
        "example.com",
        "www.example.com",
        "baidu.cn",
    ]
    assert otp.parse_otp_domains(["a.com", "b.com"]) == ["a.com", "b.com"]
    assert otp.parse_otp_domains("") == []
    assert otp.parse_otp_domains(None) == []
    assert otp.parse_otp_domains("http://a.com/\nhttp://b.com/") == ["a.com", "b.com"]


def test_otp_module_value_includes_domains_and_normalize_preserves_them():
    from core import otp

    assert otp.OTP_FIELD_KEYS[-1] == "otp_domains"
    assert "otp_domains" in modules.new_module(modules.OTP)["value"]
    assert modules.ordered_value({"type": modules.OTP, "value": {
        "otp_domains": "a.com", "secret": "JBSWY3DPEHPK3PXP", "counter": "0",
        "period": "30", "issuer": "GitHub", "digits": "6", "type": "totp",
        "label": "", "algorithm": "SHA1",
    }}) == {
        "secret": "JBSWY3DPEHPK3PXP", "issuer": "GitHub", "label": "", "algorithm": "SHA1",
        "digits": "6", "period": "30", "type": "totp", "counter": "0", "otp_domains": "a.com",
    }


def test_otp_module_value_unknown_keys_append_in_relative_order():
    ordered = modules.ordered_value({"type": modules.OTP, "value": {
        "future_x": "1", "secret": "JBSWY3DPEHPK3PXP", "future_y": "2",
    }})
    assert list(ordered) == ["secret", "future_x", "future_y"]


def test_entry_otp_helpers_read_module_first_then_top_level():
    fields = modules.fields_with_modules({}, [
        modules.new_module(modules.OTP),
    ])
    fields[modules.MODULES_KEY][0]["value"] = {
        "secret": "JBSWY3DPEHPK3PXP", "otp_domains": "a.com,b.com", "algorithm": "SHA256",
    }
    entry = Entry(title="login", secret_type=SecretType.LOGIN, fields=fields)
    assert entry.has_otp() is True
    assert entry.otp_fields()["secret"] == "JBSWY3DPEHPK3PXP"
    assert entry.otp_fields()["algorithm"] == "SHA256"
    assert entry.otp_domains() == ["a.com", "b.com"]
    assert entry.otp_binding_id() == ""


def test_entry_otp_helpers_fall_back_to_top_level_fields():
    entry = Entry(
        title="otp",
        secret_type=SecretType.OTP,
        fields={"secret": "JBSWY3DPEHPK3PXP", "otp_domains": "https://example.com"},
    )
    assert entry.has_otp() is True
    assert entry.otp_domains() == ["example.com"]
    assert entry.otp_fields()["secret"] == "JBSWY3DPEHPK3PXP"


def test_entry_otp_binding_id_roundtrip():
    entry = Entry(title="login", secret_type=SecretType.LOGIN, fields={"bound_otp_id": "abc-123"})
    assert entry.otp_binding_id() == "abc-123"
    assert entry.has_otp() is False
    assert entry.otp_domains() == []
