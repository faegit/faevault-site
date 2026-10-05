package com.vault.ui

import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

class CloudSyncUiProjectionTest {
    @Test
    fun progressUpdatesDoNotRepublishTheWholeScreenBusyState() = runBlocking {
        val running = VaultViewModel.CloudSyncUiState(
            phase = VaultViewModel.CloudSyncPhase.RUNNING,
            progress = 0.1f,
        )

        val events = cloudSyncBusyChanges(
            flowOf(
                running,
                running.copy(progress = 0.4f, busyMessage = "正在上传…"),
                running.copy(progress = 0.9f, busyMessage = "正在校验…"),
                running.copy(phase = VaultViewModel.CloudSyncPhase.IDLE, progress = null),
            ),
        ).toList()

        assertEquals(listOf(true, false), events)
    }
}
