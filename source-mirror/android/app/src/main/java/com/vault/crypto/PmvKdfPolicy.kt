package com.vault.crypto

/** Authenticated Argon2id parameters stored in the PMVH bootstrap header. */
data class PmvKdfParameters(
    val memoryKiB: Int,
    val iterations: Int,
    val parallelism: Int,
)

/** Cross-platform write profiles. Readers accept the wider range in [PmvKdfPolicy]. */
enum class PmvKdfProfile(val parameters: PmvKdfParameters) {
    STANDARD(PmvKdfParameters(memoryKiB = 65_536, iterations = 3, parallelism = 1)),
    HARDENED(PmvKdfParameters(memoryKiB = 131_072, iterations = 4, parallelism = 1)),
}

enum class KdfMigrationState {
    CURRENT,
    UPGRADE_RECOMMENDED,
    UNSUPPORTED,
}

class UnsupportedKdfParameters(message: String) : IllegalArgumentException(message)

/** Separates readable safety bounds, fixed write profiles, and local calibration advice. */
object PmvKdfPolicy {
    const val MIN_MEMORY_KIB = 65_536
    const val MAX_MEMORY_KIB = 262_144
    const val MIN_ITERATIONS = 3
    const val MAX_ITERATIONS = 10
    const val MIN_PARALLELISM = 1
    const val MAX_PARALLELISM = 4
    const val HARDENED_MAX_MEDIAN_MILLIS = 1_500L

    fun validate(parameters: PmvKdfParameters) {
        if (parameters.memoryKiB !in MIN_MEMORY_KIB..MAX_MEMORY_KIB) {
            throw UnsupportedKdfParameters("Argon2 memory parameter is outside the supported range")
        }
        if (parameters.iterations !in MIN_ITERATIONS..MAX_ITERATIONS) {
            throw UnsupportedKdfParameters("Argon2 iteration parameter is outside the supported range")
        }
        if (parameters.parallelism !in MIN_PARALLELISM..MAX_PARALLELISM) {
            throw UnsupportedKdfParameters("Argon2 parallelism parameter is outside the supported range")
        }
    }

    fun migrationState(
        current: PmvKdfParameters,
        requested: PmvKdfProfile,
    ): KdfMigrationState = try {
        validate(current)
        when {
            current == requested.parameters -> KdfMigrationState.CURRENT
            current == PmvKdfProfile.STANDARD.parameters && requested == PmvKdfProfile.HARDENED ->
                KdfMigrationState.UPGRADE_RECOMMENDED
            else -> KdfMigrationState.CURRENT
        }
    } catch (_: UnsupportedKdfParameters) {
        KdfMigrationState.UNSUPPORTED
    }

    fun recommendedProfile(
        elapsedMillis: List<Long>,
        availableBudgetKiB: Int,
    ): PmvKdfProfile {
        require(elapsedMillis.size == 3) { "KDF calibration requires exactly three samples" }
        require(elapsedMillis.all { it >= 0 }) { "KDF calibration samples must be non-negative" }
        val median = elapsedMillis.sorted()[1]
        val requiredBudgetKiB = PmvKdfProfile.HARDENED.parameters.memoryKiB * 2
        return if (median <= HARDENED_MAX_MEDIAN_MILLIS && availableBudgetKiB >= requiredBudgetKiB) {
            PmvKdfProfile.HARDENED
        } else {
            PmvKdfProfile.STANDARD
        }
    }
}
