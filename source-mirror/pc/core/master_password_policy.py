"""Conservative offline admission policy for new master passwords."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from . import leak

MIN_USABLE_ENTROPY_BITS = 40.0
RECOMMENDED_ENTROPY_BITS = 60.0

_TRAILING_DECORATION = re.compile(r"[\d\W_]+$", re.UNICODE)
_PASSPHRASE_SEPARATOR = re.compile(r"[\s_-]+")
_PREDICTABLE_SUFFIX = re.compile(r"^([A-Za-z]{4,})(\d{1,6})([^A-Za-z0-9]*)$")
_OBVIOUS_PATTERNS = ("1234", "4321", "abcd", "qwerty", "password", "letmein")
_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "|": "i", "0": "o", "5": "s", "$": "s", "7": "t"})


class PasswordRisk(Enum):
    BLOCKED = "blocked"
    WEAK = "weak"
    STRONG = "strong"


class PasswordIssue(Enum):
    COMMON_PASSWORD = "common_password"
    VERY_LOW_ENTROPY = "very_low_entropy"
    BELOW_RECOMMENDATION = "below_recommendation"
    NONE = "none"


@dataclass(frozen=True)
class MasterPasswordAssessment:
    risk: PasswordRisk
    estimated_entropy_bits: float
    issue: PasswordIssue

    def permits(self, *, high_security_mode: bool, weak_password_confirmed: bool) -> bool:
        if self.risk is PasswordRisk.BLOCKED:
            return False
        if self.risk is PasswordRisk.STRONG:
            return True
        return not high_security_mode and weak_password_confirmed


def assess_master_password(
    password: str,
    *,
    common_password_check: Callable[[str], bool] = leak.is_common_weak,
) -> MasterPasswordAssessment:
    common = any(common_password_check(candidate) for candidate in _common_candidates(password))
    bits = estimate_entropy_bits(password)
    if common:
        return MasterPasswordAssessment(PasswordRisk.BLOCKED, bits, PasswordIssue.COMMON_PASSWORD)
    if bits < MIN_USABLE_ENTROPY_BITS:
        return MasterPasswordAssessment(PasswordRisk.BLOCKED, bits, PasswordIssue.VERY_LOW_ENTROPY)
    if bits < RECOMMENDED_ENTROPY_BITS:
        return MasterPasswordAssessment(PasswordRisk.WEAK, bits, PasswordIssue.BELOW_RECOMMENDATION)
    return MasterPasswordAssessment(PasswordRisk.STRONG, bits, PasswordIssue.NONE)


def estimate_entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    words = [word for word in _PASSPHRASE_SEPARATOR.split(password) if len(word) >= 3 and any(ch.isalpha() for ch in word)]
    bits = len(words) * 13.0 if len(words) >= 3 else len(password) * math.log2(_character_pool(password))
    if len(words) >= 3:
        distinct_words = len({word.lower() for word in words})
        repeated_character_words = sum(len(set(word)) <= 1 for word in words)
        if distinct_words < 3 or repeated_character_words * 2 >= len(words):
            bits = min(bits, 35.0)
    if password.isalpha():
        bits = min(bits, len(password) * 2.5)
    match = _PREDICTABLE_SUFFIX.fullmatch(password)
    if match:
        letters, digits, decoration = match.groups()
        bits = min(bits, len(letters) * 2.5 + len(digits) * math.log2(10.0) + len(decoration) * 2.0)
    unit = _repeated_unit(password)
    if unit:
        bits = min(bits, _basic_entropy(unit) + math.log2(len(password) // len(unit) + 1))
    lower = password.lower()
    if any(pattern in lower for pattern in _OBVIOUS_PATTERNS):
        bits = min(bits, 35.0)
    return bits


def _common_candidates(password: str) -> frozenset[str]:
    lower = password.strip().lower()
    de_leeted = lower.translate(_LEET)
    return frozenset(filter(None, (
        password,
        lower,
        de_leeted,
        _TRAILING_DECORATION.sub("", lower),
        _TRAILING_DECORATION.sub("", de_leeted),
    )))


def _character_pool(password: str) -> int:
    pool = 0
    pool += 26 if any(ch.islower() for ch in password) else 0
    pool += 26 if any(ch.isupper() for ch in password) else 0
    pool += 10 if any(ch.isdigit() for ch in password) else 0
    pool += 1 if " " in password else 0
    pool += 32 if any(0x21 <= ord(ch) <= 0x2F or 0x3A <= ord(ch) <= 0x40 or 0x5B <= ord(ch) <= 0x60 or 0x7B <= ord(ch) <= 0x7E for ch in password) else 0
    pool += 100 if any(ord(ch) > 0x7E for ch in password) else 0
    return max(pool, 1)


def _basic_entropy(value: str) -> float:
    return len(value) * math.log2(_character_pool(value))


def _repeated_unit(value: str) -> str | None:
    for size in range(1, len(value) // 2 + 1):
        if len(value) % size == 0:
            unit = value[:size]
            if unit * (len(value) // size) == value:
                return unit
    return None
