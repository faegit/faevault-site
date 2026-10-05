"""Shared readable bounds, write profiles, and calibration policy for PMVH Argon2id."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True, slots=True)
class PmvKdfParameters:
    memory_kib: int
    iterations: int
    parallelism: int


class PmvKdfProfile(Enum):
    STANDARD = PmvKdfParameters(65_536, 3, 1)
    HARDENED = PmvKdfParameters(131_072, 4, 1)

    @property
    def parameters(self) -> PmvKdfParameters:
        return self.value

    @classmethod
    def from_parameters(cls, parameters: "PmvKdfParameters") -> "PmvKdfProfile":
        """将实际 KDF 参数映射回最接近的预设等级（同步后据此识别强度）。"""
        for profile in cls:
            if profile.parameters == parameters:
                return profile
        return cls.HARDENED if parameters.memory_kib >= cls.HARDENED.parameters.memory_kib else cls.STANDARD


def kdf_config_key_for(vault) -> str:
    """与设置页一致的、按保险库隔离的 KDF 等级配置键。"""
    try:
        identity = vault.pmve_identity
        vault_id = str(identity.vault_id)
    except (AttributeError, ValueError):
        vault_id = str(getattr(vault, "path", "vault"))
    suffix = hashlib.sha256(vault_id.encode("utf-8")).hexdigest()[:24]
    return f"kdf_profile_{suffix}"


class KdfMigrationState(Enum):
    CURRENT = "current"
    UPGRADE_RECOMMENDED = "upgrade_recommended"
    UNSUPPORTED = "unsupported"


class UnsupportedKdfParameters(ValueError):
    pass


class PmvKdfPolicy:
    MIN_MEMORY_KIB = 65_536
    MAX_MEMORY_KIB = 262_144
    MIN_ITERATIONS = 3
    MAX_ITERATIONS = 10
    MIN_PARALLELISM = 1
    MAX_PARALLELISM = 4
    HARDENED_MAX_MEDIAN_MILLIS = 1_500

    @classmethod
    def validate(cls, parameters: PmvKdfParameters) -> None:
        if not isinstance(parameters, PmvKdfParameters):
            raise TypeError("parameters must be PmvKdfParameters")
        if not cls.MIN_MEMORY_KIB <= parameters.memory_kib <= cls.MAX_MEMORY_KIB:
            raise UnsupportedKdfParameters("Argon2 memory parameter is outside the supported range")
        if not cls.MIN_ITERATIONS <= parameters.iterations <= cls.MAX_ITERATIONS:
            raise UnsupportedKdfParameters("Argon2 iteration parameter is outside the supported range")
        if not cls.MIN_PARALLELISM <= parameters.parallelism <= cls.MAX_PARALLELISM:
            raise UnsupportedKdfParameters("Argon2 parallelism parameter is outside the supported range")

    @classmethod
    def migration_state(
        cls,
        current: PmvKdfParameters,
        requested: PmvKdfProfile,
    ) -> KdfMigrationState:
        try:
            cls.validate(current)
        except UnsupportedKdfParameters:
            return KdfMigrationState.UNSUPPORTED
        if current == requested.parameters:
            return KdfMigrationState.CURRENT
        if current == PmvKdfProfile.STANDARD.parameters and requested is PmvKdfProfile.HARDENED:
            return KdfMigrationState.UPGRADE_RECOMMENDED
        return KdfMigrationState.CURRENT

    @classmethod
    def recommended_profile(
        cls,
        elapsed_millis: tuple[int, int, int] | list[int],
        available_budget_kib: int,
    ) -> PmvKdfProfile:
        if len(elapsed_millis) != 3:
            raise ValueError("KDF calibration requires exactly three samples")
        if any(sample < 0 for sample in elapsed_millis):
            raise ValueError("KDF calibration samples must be non-negative")
        median = sorted(elapsed_millis)[1]
        required_budget_kib = PmvKdfProfile.HARDENED.parameters.memory_kib * 2
        if median <= cls.HARDENED_MAX_MEDIAN_MILLIS and available_budget_kib >= required_budget_kib:
            return PmvKdfProfile.HARDENED
        return PmvKdfProfile.STANDARD
