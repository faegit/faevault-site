package com.vault.ui

/** Observe real input without consuming it or generating activity between events. */
internal class UserActivityDispatcher(private val onActivity: () -> Unit) {
    fun <T> dispatch(forward: () -> T): T {
        onActivity()
        return forward()
    }
}
