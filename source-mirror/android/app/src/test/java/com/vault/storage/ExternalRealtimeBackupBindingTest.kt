package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ExternalRealtimeBackupBindingTest {
    @Test
    fun `preflight preserves every non-known binding state`() {
        assertNull(ExternalRealtimeBackupCopier.blockedTargetStatus(StorageBindingState.KNOWN))
        assertEquals(
            ExternalRealtimeBackupCopier.TargetStatus.SUSPECTED_ORIGINAL,
            ExternalRealtimeBackupCopier.blockedTargetStatus(StorageBindingState.SUSPECTED_ORIGINAL),
        )
        assertEquals(
            ExternalRealtimeBackupCopier.TargetStatus.IDENTITY_ANOMALY,
            ExternalRealtimeBackupCopier.blockedTargetStatus(StorageBindingState.IDENTITY_ANOMALY),
        )
        assertEquals(
            ExternalRealtimeBackupCopier.TargetStatus.NEW_DEVICE,
            ExternalRealtimeBackupCopier.blockedTargetStatus(StorageBindingState.NEW_DEVICE),
        )
    }

    @Test
    fun `copy outcome preserves every non-known binding state`() {
        assertNull(ExternalRealtimeBackupCopier.blockedOutcome(StorageBindingState.KNOWN))
        assertEquals(
            ExternalRealtimeBackupCopier.Outcome.SUSPECTED_ORIGINAL,
            ExternalRealtimeBackupCopier.blockedOutcome(StorageBindingState.SUSPECTED_ORIGINAL),
        )
        assertEquals(
            ExternalRealtimeBackupCopier.Outcome.IDENTITY_ANOMALY,
            ExternalRealtimeBackupCopier.blockedOutcome(StorageBindingState.IDENTITY_ANOMALY),
        )
        assertEquals(
            ExternalRealtimeBackupCopier.Outcome.NEW_DEVICE,
            ExternalRealtimeBackupCopier.blockedOutcome(StorageBindingState.NEW_DEVICE),
        )
    }
}
