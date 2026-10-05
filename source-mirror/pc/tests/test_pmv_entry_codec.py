from __future__ import annotations

import json
from uuid import UUID

import pytest

from core.models import Entry
from core.pmv_entry_codec import decode_entry, encode_entry


ENTRY_ID = "10213243-5465-7687-98a9-bacbdcedfe0f"


def _full_entry() -> Entry:
    return Entry(
        title="银行 🔐",
        username="用户@example.com",
        password="pāss\n密钥",
        url="https://例子.test/登录",
        target_app="com.example.app",
        notes="第一行\n第二行",
        tags=["工作", "重要"],
        id=ENTRY_ID,
        created_at=1700000000.25,
        updated_at=1700000100.5,
        secret_type="login",
        fields={
            "unknown_extension": {
                "enabled": True,
                "nullable": None,
                "values": [1, "二", False],
                "passkey_record": [
                {
                    "id": "passkey-module",
                    "type": "passkey",
                    "value": {
                        "credential_id": "AQIDBA",
                        "private_key_pkcs8": "MIGH-PRIVATE-KEY-MATERIAL",
                        "rp_id": "例子.test",
                    },
                }
                ],
            },
            "media_refs": ["img:00112233445566778899aabbccddeeff", "att:ffeeddccbbaa99887766554433221100"],
        },
        deleted_at=None,
        leak_check_revision=None,
        leak_pwned_count=7,
        leak_common_weak=False,
        leak_checked_at=1700000200.0,
    )


def test_full_entry_uses_canonical_utf8_key_order_and_round_trips_nested_json() -> None:
    entry = _full_entry()
    raw = encode_entry(entry)
    assert list(json.loads(raw).keys()) == sorted(json.loads(raw), key=lambda key: key.encode("utf-8"))
    assert b"\\u" not in raw
    assert b"1700000200" in raw
    assert b"1700000200.0" not in raw
    assert b"17000002E" not in raw
    decoded = decode_entry(raw, UUID(ENTRY_ID))
    assert encode_entry(decoded) == raw
    assert decoded.fields == entry.fields


def test_defaults_and_explicit_nulls_match_android_serializer() -> None:
    raw = encode_entry(Entry(id=ENTRY_ID, created_at=0.0, updated_at=0.0))
    value = json.loads(raw)
    assert value["deleted_at"] is None
    assert value["leak_check_revision"] is None
    assert value["leak_pwned_count"] is None
    assert value["leak_checked_at"] is None
    assert value["fields"] == {}
    assert value["tags"] == []


def test_unknown_top_level_is_ignored_but_unknown_fields_are_preserved() -> None:
    value = json.loads(encode_entry(_full_entry()))
    value["future_top_level"] = {"ignored": True}
    decoded = decode_entry(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())
    assert "unknown_extension" in decoded.fields
    assert not hasattr(decoded, "future_top_level")


def test_rejects_noncanonical_or_mismatched_id_and_invalid_utf8() -> None:
    with pytest.raises(ValueError, match="canonical UUID"):
        encode_entry({"id": UUID(ENTRY_ID).hex})
    with pytest.raises(ValueError, match="does not match"):
        decode_entry(encode_entry(_full_entry()), UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
    with pytest.raises(ValueError, match="UTF-8 JSON"):
        decode_entry(b"\xff")
