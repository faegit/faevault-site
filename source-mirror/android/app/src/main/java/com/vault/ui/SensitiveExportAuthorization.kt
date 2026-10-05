package com.vault.ui

/** Immutable fields used to bind a one-shot authorization to the selected export destination. */
internal data class SensitiveExportGrant(
    val vaultName: String?,
    val generation: Long,
    val operation: String,
    val destination: String,
    val expiresAtElapsedMs: Long,
)

internal fun SensitiveExportGrant.matches(
    vaultName: String?,
    generation: Long,
    operation: String,
    destination: String,
    nowElapsedMs: Long,
): Boolean = expiresAtElapsedMs > nowElapsedMs && this.vaultName == vaultName &&
    this.generation == generation && this.operation == operation && this.destination == destination
