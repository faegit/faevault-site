package com.vault.storage

/** Per-source throttling for failed LAN pairing authentication. */
internal class LanAuthFailureBudget(
    private val maxFailures: Int = 10,
    private val windowMillis: Long = 60_000L,
    private val lockoutMillis: Long = 30_000L,
    private val maxTrackedAddresses: Int = 256,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private data class Window(var startedAt: Long, var failures: Int = 0, var blockedUntil: Long = 0L)

    private val windows = HashMap<String, Window>()

    @Synchronized
    fun isLocked(address: String): Boolean = (windows[address]?.blockedUntil ?: 0L) > clock()

    @Synchronized
    fun recordFailure(address: String) {
        val now = clock()
        var window = windows[address]
        if (window == null) {
            windows.entries.removeIf { now - it.value.startedAt >= windowMillis }
            if (windows.size >= maxTrackedAddresses) return
            window = Window(now)
            windows[address] = window
        }
        if (now - window.startedAt >= windowMillis) {
            window.startedAt = now
            window.failures = 0
            window.blockedUntil = 0L
        }
        window.failures++
        if (window.failures >= maxFailures) window.blockedUntil = now + lockoutMillis
    }
}
