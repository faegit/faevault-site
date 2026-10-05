import json
import struct
import time
import uuid
from pathlib import Path

import pytest

from core.passkey_broker_protocol import (
    MAX_FRAME,
    ProtocolError,
    b64u_decode,
    decode_frame,
    decode_request,
    encode_frame,
)


def request(message_type="status", **extra):
    return {
        "v": 1,
        "type": message_type,
        "requestId": str(uuid.uuid4()),
        "deadlineMs": int(time.time() * 1000) + 30_000,
        **extra,
    }


def test_request_roundtrip_is_strict():
    decoded = decode_request(encode_frame(request()))
    assert decoded.type == "status"
    assert decoded.payload == {}


@pytest.mark.parametrize("field", ["masterPassword", "rootKey", "vaultPath", "command"])
def test_request_rejects_secret_and_authority_fields(field):
    with pytest.raises(ProtocolError, match="forbidden"):
        decode_request(encode_frame(request(**{field: "x"})))


def test_nested_secret_field_is_rejected_before_dispatch():
    with pytest.raises(ProtocolError, match="sensitive"):
        encode_frame(request("make", record={"password": "x"}))


def test_frame_rejects_oversize_and_trailing_data():
    with pytest.raises(ProtocolError, match="size"):
        decode_frame(struct.pack("<I", MAX_FRAME + 1))
    valid = encode_frame(request())
    with pytest.raises(ProtocolError, match="size"):
        decode_frame(valid + b"x")


def test_request_rejects_expired_or_unbounded_deadline():
    now = 1_000_000
    for deadline in (now, now + 120_001):
        message = request()
        message["deadlineMs"] = deadline
        with pytest.raises(ProtocolError, match="deadline"):
            decode_request(encode_frame(message), now_ms=now)


def test_base64url_requires_canonical_unpadded_text():
    assert b64u_decode("AQI") == b"\x01\x02"
    for invalid in ("AQI=", "@@@", ""):
        with pytest.raises(ProtocolError):
            b64u_decode(invalid)


def test_cpp_header_has_protocol_parity():
    header = (Path(__file__).parents[1] / "native/passkey_provider/shared/BrokerProtocol.h").read_text("utf-8")
    assert "kProtocolVersion = 1" in header
    assert "kMaxFrame = 1024 * 1024" in header
    for name in ("hello", "status", "list", "make", "get", "commit-use", "reconcile", "cancel"):
        assert f'L"{name}"' in header
