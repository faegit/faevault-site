from __future__ import annotations

from copy import deepcopy
from uuid import UUID

import pytest

from core.pmv_container import BlockType
from core.pmv_vault_metadata import BLOCK_TYPE, decode_metadata, encode_metadata, logical_digest


VAULT_ID = UUID("00112233-4455-6677-8899-aabbccddeeff")


def _metadata() -> dict:
    return {
        "schema": "pmv-vault-metadata",
        "version": 1,
        "vault_id": str(VAULT_ID),
        "entry_order": ["10213243-5465-7687-98a9-bacbdcedfe0f"],
        "trash_order": ["fedcba98-7654-4321-aaaa-bbbbbbbbbbbb"],
        "sync_meta": {
            "device_id": "11111111-2222-3333-4444-555555555555",
            "future_counter": 2,
        },
        "key_revision": 7,
        "export_epoch": 1700000200.0,
        "purge_tombstones": {
            "fedcba98-7654-4321-aaaa-bbbbbbbbbbbb": 1700000100.25,
        },
        "future_extension": {"enabled": True, "label": "保险库"},
    }


def test_canonical_round_trip_preserves_unknown_top_level_fields() -> None:
    metadata = _metadata()
    encoded = encode_metadata(metadata)
    decoded = decode_metadata(encoded, VAULT_ID)
    assert BLOCK_TYPE is BlockType.OBJECT_METADATA
    assert decoded == metadata
    assert encode_metadata(decoded) == encoded
    assert b"future_extension" in encoded
    assert "保险库".encode() in encoded
    assert logical_digest(decoded) == logical_digest(metadata)


def test_rejects_noncanonical_ids_overlap_invalid_utf8_duplicate_keys_and_secrets() -> None:
    invalid = deepcopy(_metadata())
    invalid["vault_id"] = str(VAULT_ID).upper()
    with pytest.raises(ValueError, match="canonical lowercase UUID"):
        encode_metadata(invalid)

    invalid = deepcopy(_metadata())
    invalid["trash_order"] = list(invalid["entry_order"])
    with pytest.raises(ValueError, match="must not overlap"):
        encode_metadata(invalid)

    invalid = deepcopy(_metadata())
    invalid["future_extension"]["password"] = "must-not-live-here"
    with pytest.raises(ValueError, match="must not contain secret"):
        encode_metadata(invalid)

    with pytest.raises(ValueError, match="UTF-8 JSON"):
        decode_metadata(b"\xff")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        decode_metadata(encode_metadata(_metadata())[:-1] + b',"version":1}')
    with pytest.raises(ValueError, match="does not match"):
        decode_metadata(encode_metadata(_metadata()), UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"))
