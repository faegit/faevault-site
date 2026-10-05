"""加密相关的基础类型与内存保护工具。

- ``DecryptError``：主密码错误或数据损坏的统一异常类型，供 PMVE 主库、
  备份 v2、云同步等模块复用。
- ``SecureString``：以异或混淆方式在内存中保存主密码等敏感字符串。
- ``AESGCM``：re-export ``cryptography`` 的 AES-GCM 实现，供各模块直接使用。
"""

from __future__ import annotations

import hmac
import os
from contextlib import contextmanager
from typing import Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = ["AESGCM", "DecryptError", "SecureString"]


class DecryptError(Exception):
    """主密码错误或数据损坏。"""


class SecureString:
    """以异或混淆方式在内存中保存主密码等敏感字符串。

    并非加密——混淆密钥与数据同样驻留在进程内存中，无法防御拥有完整内存
    转储权限的攻击者；其作用是避免明文长期以可被简单字符串扫描直接命中
    的形式停留在内存中，作为纵深防御的一层。
    """

    __slots__ = ("_data", "_key", "_closed")

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("value must be str; use from_utf8 for mutable input")
        raw = bytearray(value.encode("utf-8"))
        try:
            self._initialize(raw)
        finally:
            raw[:] = b"\x00" * len(raw)

    @classmethod
    def from_utf8(cls, value: bytearray) -> "SecureString":
        if type(value) is not bytearray:
            raise TypeError("value must be bytearray")
        instance = cls.__new__(cls)
        instance._initialize(value)
        return instance

    def _initialize(self, value: bytearray) -> None:
        self._closed = False
        self._key = bytearray(os.urandom(len(value))) if value else bytearray()
        self._data = bytearray(b ^ k for b, k in zip(value, self._key))

    @contextmanager
    def bytes(self) -> Iterator[bytearray]:
        if self._closed:
            raise ValueError("secret has been cleared")
        buffer = bytearray(b ^ k for b, k in zip(self._data, self._key))
        try:
            yield buffer
        finally:
            buffer[:] = b"\x00" * len(buffer)

    def clone(self) -> "SecureString":
        with self.bytes() as value:
            return SecureString.from_utf8(value)

    def is_empty(self) -> bool:
        return not self._data

    def matches_buffer(self, candidate: bytearray) -> bool:
        if type(candidate) is not bytearray or self._closed:
            return False
        with self.bytes() as expected:
            return hmac.compare_digest(expected, candidate)

    def matches(self, candidate: str) -> bool:
        if not isinstance(candidate, str):
            return False
        actual = bytearray(candidate.encode("utf-8"))
        try:
            return self.matches_buffer(actual)
        finally:
            actual[:] = b"\x00" * len(actual)

    def clear(self) -> None:
        self._data[:] = b"\x00" * len(self._data)
        self._key[:] = b"\x00" * len(self._key)
        self._data.clear()
        self._key.clear()
        self._closed = True

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.matches(other)
        if isinstance(other, SecureString):
            if len(self._data) != len(other._data):
                return False
            with self.bytes() as left, other.bytes() as right:
                return hmac.compare_digest(left, right)
        return NotImplemented
