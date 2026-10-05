package com.vault.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PmvKdfPolicyTest {
    @Test
    fun `profiles use the shared standard and hardened parameters`() {
        assertEquals(PmvKdfParameters(65_536, 3, 1), PmvKdfProfile.STANDARD.parameters)
        assertEquals(PmvKdfParameters(131_072, 4, 1), PmvKdfProfile.HARDENED.parameters)
    }

    @Test
    fun `migration state compares known profiles without rejecting old vaults`() {
        assertEquals(
            KdfMigrationState.UPGRADE_RECOMMENDED,
            PmvKdfPolicy.migrationState(PmvKdfProfile.STANDARD.parameters, PmvKdfProfile.HARDENED),
        )
        assertEquals(
            KdfMigrationState.CURRENT,
            PmvKdfPolicy.migrationState(PmvKdfProfile.HARDENED.parameters, PmvKdfProfile.STANDARD),
        )
    }

    @Test
    fun `validation separates supported range from write defaults`() {
        listOf(
            PmvKdfParameters(65_536, 3, 1),
            PmvKdfParameters(262_144, 10, 4),
            PmvKdfParameters(96_000, 5, 2),
        ).forEach(PmvKdfPolicy::validate)

        listOf(
            PmvKdfParameters(65_535, 3, 1),
            PmvKdfParameters(262_145, 3, 1),
            PmvKdfParameters(65_536, 2, 1),
            PmvKdfParameters(65_536, 11, 1),
            PmvKdfParameters(65_536, 3, 0),
            PmvKdfParameters(65_536, 3, 5),
        ).forEach { parameters ->
            assertThrows(UnsupportedKdfParameters::class.java) {
                PmvKdfPolicy.validate(parameters)
            }
        }
    }

    @Test
    fun `calibration recommends hardened only within time and memory budget`() {
        assertEquals(
            PmvKdfProfile.HARDENED,
            PmvKdfPolicy.recommendedProfile(listOf(1_450, 1_500, 1_100), availableBudgetKiB = 262_144),
        )
        assertEquals(
            PmvKdfProfile.STANDARD,
            PmvKdfPolicy.recommendedProfile(listOf(1_100, 1_501, 1_600), availableBudgetKiB = 262_144),
        )
        assertEquals(
            PmvKdfProfile.STANDARD,
            PmvKdfPolicy.recommendedProfile(listOf(900, 1_000, 1_100), availableBudgetKiB = 262_143),
        )
    }
}
