package com.vault.ui

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map

/**
 * The settings screen needs only the operation boundary. Progress/message changes are rendered by
 * the small status component and must not invalidate the complete settings hierarchy.
 */
internal fun cloudSyncBusyChanges(
    states: Flow<VaultViewModel.CloudSyncUiState>,
): Flow<Boolean> = states
    .map { it.phase == VaultViewModel.CloudSyncPhase.RUNNING }
    .distinctUntilChanged()
