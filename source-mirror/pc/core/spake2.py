"""RFC 9382 SPAKE2 using the P-256/SHA-256/HKDF/HMAC ciphersuite."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets
from Crypto.PublicKey.ECC import EccPoint


P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = EccPoint(
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    curve="P-256",
)
M_ENCODED = bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
N_ENCODED = bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")

Point = EccPoint | None


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    result = left + right
    return None if result.is_point_at_infinity() else result


def point_mul(scalar: int, point: Point) -> Point:
    if scalar < 0:
        return point_mul(-scalar, point_neg(point))
    if point is None or scalar == 0:
        return None
    result = point * scalar
    return None if result.is_point_at_infinity() else result


def point_neg(point: Point) -> Point:
    if point is None:
        return None
    return -point


def decode_point(encoded: bytes) -> Point:
    if len(encoded) == 33 and encoded[0] in (2, 3):
        x = int.from_bytes(encoded[1:], "big")
        if x >= P:
            raise ValueError("SPAKE2 point is outside P-256")
        alpha = (pow(x, 3, P) + A * x + B) % P
        y = pow(alpha, (P + 1) // 4, P)
        if (y * y) % P != alpha:
            raise ValueError("SPAKE2 point is not on P-256")
        if (y & 1) != (encoded[0] & 1):
            y = P - y
        point = EccPoint(x, y, curve="P-256")
    elif len(encoded) == 65 and encoded[0] == 4:
        x = int.from_bytes(encoded[1:33], "big")
        y = int.from_bytes(encoded[33:], "big")
        if x >= P or y >= P or (y * y - (pow(x, 3, P) + A * x + B)) % P:
            raise ValueError("SPAKE2 point is not on P-256")
        point = EccPoint(x, y, curve="P-256")
    else:
        raise ValueError("SPAKE2 point encoding is invalid")
    if point is None or point_mul(ORDER, point) is not None:
        raise ValueError("SPAKE2 point has invalid order")
    return point


def encode_point(point: Point) -> bytes:
    if point is None:
        raise ValueError("SPAKE2 point at infinity is invalid")
    return b"\x04" + int(point.x).to_bytes(32, "big") + int(point.y).to_bytes(32, "big")


M = decode_point(M_ENCODED)
N = decode_point(N_ENCODED)


def _scrypt_w(password: bytes, ticket: str) -> int:
    """任意长度密码的 w 派生（SPAKE2 RFC 9382 使用同一盐与参数）。

    安卓 ``Spake2P256.deriveW`` 与本函数同参；``derive_w`` 另保留 6 位 PIN 的
    长度与字符校验入口。
    """
    if not password or len(password) > 256:
        raise ValueError("SPAKE2 password length is invalid")
    salt = hashlib.sha256(b"Vault LAN Sync SPAKE2 w v1\0" + ticket.encode("utf-8")).digest()
    material = hashlib.scrypt(password, salt=salt, n=1 << 14, r=8, p=1, dklen=40)
    return int.from_bytes(material, "big") % ORDER


def derive_w(pin: str, ticket: str) -> int:
    if len(pin) != 6 or not pin.isascii() or not pin.isdigit():
        raise ValueError("SPAKE2 PIN must contain six ASCII digits")
    return _scrypt_w(pin.encode("ascii"), ticket)


def random_scalar() -> int:
    while True:
        scalar = int.from_bytes(secrets.token_bytes(32), "big")
        if 0 < scalar < ORDER:
            return scalar


def _len(value: bytes) -> bytes:
    return len(value).to_bytes(8, "little") + value


def _hkdf(ikm: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(bytes(32), ikm, hashlib.sha256).digest()
    output = b""
    block = b""
    counter = 1
    while len(output) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        output += block
        counter += 1
    return output[:length]


@dataclass(frozen=True)
class Keys:
    transcript: bytes
    shared_key: bytes
    confirm_a: bytes
    confirm_b: bytes

    def session_token(self, ticket: str) -> bytes:
        return hmac.new(
            self.shared_key,
            b"Vault LAN Sync SPAKE2 Session v1\0" + ticket.encode("utf-8"),
            hashlib.sha256,
        ).digest()


def _keys(w: int, p_a: bytes, p_b: bytes, shared: Point, identity_a: bytes, identity_b: bytes, aad: bytes) -> Keys:
    transcript = b"".join(
        (
            _len(identity_a),
            _len(identity_b),
            _len(p_a),
            _len(p_b),
            _len(encode_point(shared)),
            _len(w.to_bytes(32, "big")),
        )
    )
    digest = hashlib.sha256(transcript).digest()
    shared_key, confirmation_key = digest[:16], digest[16:]
    confirmation_keys = _hkdf(confirmation_key, b"ConfirmationKeys" + aad, 32)
    confirm_a = hmac.new(confirmation_keys[:16], transcript, hashlib.sha256).digest()
    confirm_b = hmac.new(confirmation_keys[16:], transcript, hashlib.sha256).digest()
    return Keys(transcript, shared_key, confirm_a, confirm_b)


def start_a(w: int, scalar: int | None = None) -> tuple[int, bytes]:
    x = scalar if scalar is not None else random_scalar()
    if not 0 < x < ORDER:
        raise ValueError("SPAKE2 scalar is invalid")
    return x, encode_point(point_add(point_mul(x, G), point_mul(w, M)))


def password_masks(w: int) -> tuple[Point, Point]:
    if not 0 <= w < ORDER:
        raise ValueError("SPAKE2 password scalar is invalid")
    return point_mul(w, M), point_mul(w, N)


def finish_a(w: int, x: int, p_a: bytes, p_b: bytes, identity_a: bytes, identity_b: bytes, aad: bytes) -> Keys:
    received = decode_point(p_b)
    shared = point_mul(x, point_add(received, point_neg(point_mul(w, N))))
    if shared is None:
        raise ValueError("SPAKE2 shared point is invalid")
    return _keys(w, p_a, p_b, shared, identity_a, identity_b, aad)


def finish_b(
    w: int,
    p_a: bytes,
    identity_a: bytes,
    identity_b: bytes,
    aad: bytes,
    scalar: int | None = None,
    masks: tuple[Point, Point] | None = None,
) -> tuple[bytes, Keys]:
    y = scalar if scalar is not None else random_scalar()
    if not 0 < y < ORDER:
        raise ValueError("SPAKE2 scalar is invalid")
    received = decode_point(p_a)
    masked_m, masked_n = masks if masks is not None else password_masks(w)
    p_b = encode_point(point_add(point_mul(y, G), masked_n))
    shared = point_mul(y, point_add(received, point_neg(masked_m)))
    if shared is None:
        raise ValueError("SPAKE2 shared point is invalid")
    return p_b, _keys(w, p_a, p_b, shared, identity_a, identity_b, aad)
