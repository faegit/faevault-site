"""无依赖的小工具：密码生成与强度评估。"""

from __future__ import annotations

import math
import secrets
import string

_AMBIGUOUS = "Il1O0|`'\"{}[]()/\\"


def generate_password(
    length: int = 18,
    *,
    upper: bool = True,
    lower: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = True,
) -> str:
    pools: list[str] = []
    if upper:
        pools.append(string.ascii_uppercase)
    if lower:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*-_=+?")
    if not pools:
        pools.append(string.ascii_letters + string.digits)

    if avoid_ambiguous:
        pools = ["".join(c for c in p if c not in _AMBIGUOUS) or p for p in pools]

    alphabet = "".join(pools)
    # 保证每个所选类别至少出现一次
    chars = [secrets.choice(p) for p in pools]
    chars += [secrets.choice(alphabet) for _ in range(max(0, length - len(chars)))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars[:length])


def strength(password: str) -> tuple[int, str]:
    """返回 (0-100 分数, 文字等级)。基于字符空间的估算熵。"""
    if not password:
        return 0, "无"
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    bits = len(password) * math.log2(pool) if pool else 0
    score = max(0, min(100, int(bits / 80 * 100)))
    if bits < 40:
        label = "弱"
    elif bits < 70:
        label = "中"
    elif bits < 100:
        label = "强"
    else:
        label = "极强"
    return score, label
