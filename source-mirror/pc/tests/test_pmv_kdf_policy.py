from __future__ import annotations

import pytest

from core.pmv_kdf_policy import (
    KdfMigrationState,
    PmvKdfParameters,
    PmvKdfPolicy,
    PmvKdfProfile,
    UnsupportedKdfParameters,
)


def test_profiles_match_cross_platform_parameters() -> None:
    assert PmvKdfProfile.STANDARD.parameters == PmvKdfParameters(65_536, 3, 1)
    assert PmvKdfProfile.HARDENED.parameters == PmvKdfParameters(131_072, 4, 1)


def test_supported_range_is_separate_from_write_profiles() -> None:
    for parameters in (
        PmvKdfParameters(65_536, 3, 1),
        PmvKdfParameters(262_144, 10, 4),
        PmvKdfParameters(96_000, 5, 2),
    ):
        PmvKdfPolicy.validate(parameters)

    for parameters in (
        PmvKdfParameters(65_535, 3, 1),
        PmvKdfParameters(262_145, 3, 1),
        PmvKdfParameters(65_536, 2, 1),
        PmvKdfParameters(65_536, 11, 1),
        PmvKdfParameters(65_536, 3, 0),
        PmvKdfParameters(65_536, 3, 5),
    ):
        with pytest.raises(UnsupportedKdfParameters):
            PmvKdfPolicy.validate(parameters)


def test_migration_and_calibration_match_android_policy() -> None:
    assert PmvKdfPolicy.migration_state(
        PmvKdfProfile.STANDARD.parameters,
        PmvKdfProfile.HARDENED,
    ) is KdfMigrationState.UPGRADE_RECOMMENDED
    assert PmvKdfPolicy.recommended_profile((1450, 1500, 1100), 262_144) is PmvKdfProfile.HARDENED
    assert PmvKdfPolicy.recommended_profile((1100, 1501, 1600), 262_144) is PmvKdfProfile.STANDARD
    assert PmvKdfPolicy.recommended_profile((900, 1000, 1100), 262_143) is PmvKdfProfile.STANDARD
