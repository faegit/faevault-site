package com.vault.storage

data class RemoteUpdateState(
    val enabled: Boolean = false,
    val baseline: String = "",
    val pending: String = "",
    val notified: List<String> = emptyList(),
    val detectedAt: Long = 0,
    val lastCheckedAt: Long = 0,
)

object RemoteUpdatePolicy {
    fun mayAcceptObservation(capturedGeneration: Long, currentGeneration: Long, paused: Boolean): Boolean =
        !paused && capturedGeneration == currentGeneration

    data class Observation(val state: RemoteUpdateState, val notify: Boolean = false)
    fun version(value: CloudFileVersion): String? = when {
        !value.exists -> null
        !value.etag.isNullOrBlank() -> "etag:${value.etag}"
        value.lastModified > 0 && value.size >= 0 -> "meta:${value.lastModified}:${value.size}"
        else -> null
    }
    fun observe(state: RemoteUpdateState, version: String, now: Long): Observation {
        if (version.isBlank()) return Observation(state)
        if (state.baseline.isBlank()) return Observation(state.copy(baseline = version))
        if (state.baseline == version) return Observation(state.copy(pending = "", detectedAt = 0))
        val notify = version !in state.notified
        return Observation(state.copy(pending = version,
            detectedAt = if (state.pending == version) state.detectedAt else now,
            notified = if (notify) (state.notified + version).takeLast(32) else state.notified), notify)
    }
    fun acknowledge(state: RemoteUpdateState, version: String, consumedVersion: String = ""): RemoteUpdateState {
        if (version.isBlank()) return state
        val matched = state.pending == version || (consumedVersion.isNotBlank() && state.pending == consumedVersion)
        return state.copy(baseline = version, pending = if (matched) "" else state.pending,
            detectedAt = if (matched) 0 else state.detectedAt)
    }
}
