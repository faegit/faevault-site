"""OTP helpers shared by storage, importers, and UI."""

from __future__ import annotations

import hashlib
import hmac
import struct
import time
from urllib.parse import parse_qs, unquote, urlparse

BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
BASE32_LOOKUP = {c: i for i, c in enumerate(BASE32_ALPHABET)}

OTP_FIELD_DEFAULTS = {
    "algorithm": "SHA1",
    "digits": "6",
    "period": "30",
    "issuer": "",
    "label": "",
    "type": "totp",
    "counter": "0",
}

OTP_FIELD_KEYS = ("secret", "algorithm", "digits", "period", "issuer", "label", "type", "counter", "otp_domains")
ALGORITHMS = ("SHA1", "SHA256", "SHA512")


def normalize_secret(secret: str) -> str:
    return "".join(c for c in str(secret or "").strip().upper() if c.isalnum() and c != "=")


def parse_otp_domains(raw) -> list[str]:
    """解析关联域名列表，兼容 list/逗号/分号/中英文分隔符，并去掉 scheme 与尾部斜杠。"""
    if isinstance(raw, (list, tuple)):
        items = [str(i) for i in raw]
    else:
        text = str(raw or "")
        for ch in ("，", "；", ";", "\n", "\r"):
            text = text.replace(ch, ",")
        items = text.split(",")
    out: list[str] = []
    for item in items:
        item = item.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        if item:
            out.append(item)
    return out


def normalize_fields(fields: dict | None) -> dict[str, str]:
    src = fields if isinstance(fields, dict) else {}
    out = {}
    for k, v in src.items():
        if v is None:
            continue
        if k == "otp_domains" and isinstance(v, (list, tuple)):
            out[k] = ",".join(str(i) for i in v if i is not None)
        else:
            out[k] = str(v)
    out["secret"] = normalize_secret(out.get("secret", ""))
    algo = out.get("algorithm", OTP_FIELD_DEFAULTS["algorithm"]).upper()
    out["algorithm"] = algo if algo in ALGORITHMS else OTP_FIELD_DEFAULTS["algorithm"]
    out["digits"] = _clamp_int_str(out.get("digits"), default=6, minimum=6, maximum=8)
    out["period"] = _clamp_int_str(out.get("period"), default=30, minimum=1, maximum=3600)
    typ = out.get("type", OTP_FIELD_DEFAULTS["type"]).lower()
    out["type"] = typ if typ in ("totp", "hotp") else OTP_FIELD_DEFAULTS["type"]
    out["counter"] = _clamp_int_str(out.get("counter"), default=0, minimum=0, maximum=2**63 - 1)
    for k, v in OTP_FIELD_DEFAULTS.items():
        out.setdefault(k, v)
    return out


def _clamp_int_str(value, *, default: int, minimum: int, maximum: int) -> str:
    try:
        n = int(str(value).strip())
    except Exception:
        n = default
    return str(max(minimum, min(maximum, n)))


def base32_decode(s: str) -> bytes:
    clean = normalize_secret(s)
    if not clean:
        return b""
    bits = ""
    for c in clean:
        v = BASE32_LOOKUP.get(c)
        if v is None:
            return b""
        bits += format(v, "05b")
    byte_count = len(bits) // 8
    if byte_count == 0:
        return b""
    return int(bits[: byte_count * 8], 2).to_bytes(byte_count, "big")


def generate_hotp(secret: str, counter: int, digits: int = 6, algo: str = "sha1") -> str:
    key = base32_decode(secret)
    if not key:
        return "ERROR"
    try:
        digest_name = _hash_name(algo)
        msg = struct.pack(">Q", max(0, int(counter)))
        h = hmac.new(key, msg, digest_name).digest()
    except Exception:
        return "ERROR"
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF) % (10 ** int(digits))
    return f"{code:0{int(digits)}d}"


def generate_totp(secret: str, time_step: int, digits: int = 6, algo: str = "sha1") -> str:
    return generate_hotp(secret, time_step, digits, algo)


def current_totp(secret: str, digits: int = 6, algo: str = "sha1", period: int = 30, now: float | None = None) -> str:
    ts = int((time.time() if now is None else now) // max(1, int(period)))
    return generate_totp(secret, ts, digits, algo)


def code_from_fields(fields: dict, now: float | None = None) -> str:
    f = normalize_fields(fields)
    algo = _hash_name(f["algorithm"])
    digits = int(f["digits"])
    if f["type"] == "hotp":
        return generate_hotp(f["secret"], int(f["counter"]), digits, algo)
    return current_totp(f["secret"], digits, algo, int(f["period"]), now)


def seconds_remaining(fields: dict, now: float | None = None) -> int:
    f = normalize_fields(fields)
    period = max(1, int(f["period"]))
    current = time.time() if now is None else now
    return period - (int(current) % period)


def _hash_name(algo: str) -> str:
    name = str(algo or "SHA1").lower().replace("-", "")
    if name in ("sha1", "sha256", "sha512"):
        return name
    if name in hashlib.algorithms_available:
        return name
    return "sha1"


def parse_otpauth_uri(uri: str) -> dict[str, str]:
    parsed = urlparse(str(uri or "").strip())
    if parsed.scheme.lower() != "otpauth":
        return {}
    typ = parsed.netloc.lower()
    if typ not in ("totp", "hotp"):
        return {}
    qs = {k.lower(): v[-1] for k, v in parse_qs(parsed.query, keep_blank_values=True).items() if v}
    raw_secret = qs.get("secret", "")
    secret = "".join(c for c in raw_secret.strip().upper() if not c.isspace()).rstrip("=")
    if not secret or any(c not in BASE32_ALPHABET for c in secret) or not base32_decode(secret):
        return {}
    algorithm = qs.get("algorithm", OTP_FIELD_DEFAULTS["algorithm"]).upper()
    if algorithm not in ALGORITHMS:
        return {}
    try:
        digits = int(qs.get("digits", OTP_FIELD_DEFAULTS["digits"]))
        period = int(qs.get("period", OTP_FIELD_DEFAULTS["period"]))
    except (TypeError, ValueError):
        return {}
    if not 6 <= digits <= 8 or not 1 <= period <= 300:
        return {}
    if typ == "hotp":
        try:
            counter = int(qs["counter"])
        except (KeyError, TypeError, ValueError):
            return {}
        if counter < 0:
            return {}
    else:
        counter = 0
    label = unquote(parsed.path.lstrip("/"))
    issuer = qs.get("issuer", "")
    if ":" in label:
        maybe_issuer, account = label.split(":", 1)
        issuer = issuer or maybe_issuer
        label = account
    fields = {
        "type": typ,
        "secret": secret,
        "algorithm": algorithm,
        "digits": str(digits),
        "period": str(period),
        "issuer": issuer,
        "label": qs.get("label", label),
        "counter": str(counter),
    }
    return normalize_fields(fields)
