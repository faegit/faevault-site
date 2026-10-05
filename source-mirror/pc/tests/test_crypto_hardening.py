from __future__ import annotations

from pathlib import Path

import pytest

from core import crypto


def test_secure_string_constant_time_comparison_paths() -> None:
    first_input = bytearray(b"same secret")
    second_input = bytearray(b"same secret")
    different_input = bytearray(b"different")
    first = crypto.SecureString.from_utf8(first_input)
    second = crypto.SecureString.from_utf8(second_input)
    different = crypto.SecureString.from_utf8(different_input)
    try:
        assert first.matches_buffer(bytearray(b"same secret"))
        assert first == second
        assert first != different
    finally:
        first.clear()
        second.clear()
        different.clear()


def test_scoped_bytes_are_wiped_after_normal_and_exceptional_exit() -> None:
    secret = crypto.SecureString.from_utf8(bytearray("密钥".encode()))
    with secret.bytes() as normal:
        captured_normal = normal
        assert normal == bytearray("密钥".encode())
    assert captured_normal == bytearray(len(captured_normal))

    with pytest.raises(RuntimeError):
        with secret.bytes() as exceptional:
            captured_exceptional = exceptional
            raise RuntimeError("stop")
    assert captured_exceptional == bytearray(len(captured_exceptional))
    secret.clear()
    with pytest.raises(ValueError):
        with secret.bytes():
            pass


def test_pmve_storage_paths_do_not_reveal_master_password_strings() -> None:
    source = (Path(__file__).parents[1] / "core" / "storage.py").read_text(encoding="utf-8")
    assert "self._password.reveal()" not in source
