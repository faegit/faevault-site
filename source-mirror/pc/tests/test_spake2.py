import hashlib

import pytest

from core import spake2


def test_rfc9382_p256_vector():
    w = int("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f", 16)
    x = int("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729", 16)
    y = int("dcb60106f276b02606d8ef0a328c02e4b629f84f89786af5befb0bc75b6e66be", 16)
    _, p_a = spake2.start_a(w, x)
    p_b, server_keys = spake2.finish_b(w, p_a, b"server", b"client", b"", y)
    client_keys = spake2.finish_a(w, x, p_a, p_b, b"server", b"client", b"")

    assert p_a.hex() == (
        "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470"
        "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c"
    )
    assert client_keys == server_keys
    assert client_keys.shared_key.hex() == "0e0672dc86f8e45565d338b0540abe69"
    assert client_keys.confirm_a.hex() == "58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0"
    assert client_keys.confirm_b.hex() == "d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b"


def test_pin_derivation_is_bound_to_ticket():
    assert spake2.derive_w("123456", "ticket-a") != spake2.derive_w("123456", "ticket-b")


def test_rejects_invalid_peer_point():
    w = spake2.derive_w("123456", "ticket")
    with pytest.raises(ValueError):
        spake2.finish_b(w, b"\x04" + bytes(64), b"client", b"server", hashlib.sha256(b"aad").digest())
