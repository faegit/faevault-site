package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Test

class StorageBindingPolicyTest {
    private val uuid = "123e4567-e89b-12d3-a456-426614174000"
    private val otherUuid = "123e4567-e89b-12d3-a456-426614174001"

    @Test fun `both identifiers match is known`() {
        assertEquals(StorageBindingState.KNOWN, StorageBindingPolicy.evaluate(uuid, "saf:a", uuid, "saf:a"))
    }

    @Test fun `uuid match and access changed requires confirmation`() {
        assertEquals(StorageBindingState.SUSPECTED_ORIGINAL, StorageBindingPolicy.evaluate(uuid, "saf:a", uuid, "saf:b"))
    }

    @Test fun `access match with missing or changed uuid is anomalous`() {
        assertEquals(StorageBindingState.IDENTITY_ANOMALY, StorageBindingPolicy.evaluate(uuid, "saf:a", null, "saf:a"))
        assertEquals(StorageBindingState.IDENTITY_ANOMALY, StorageBindingPolicy.evaluate(uuid, "saf:a", otherUuid, "saf:a"))
    }

    @Test fun `neither identifier matches is new device`() {
        assertEquals(StorageBindingState.NEW_DEVICE, StorageBindingPolicy.evaluate(uuid, "saf:a", otherUuid, "saf:b"))
        assertEquals(StorageBindingState.NEW_DEVICE, StorageBindingPolicy.evaluate(null, null, null, "saf:b"))
    }

    @Test fun `backup handling allows known and suspected-original, blocks anomaly and new device`() {
        assertEquals(null, StorageBindingPolicy.blockedBackupToken(StorageBindingState.KNOWN))
        assertEquals(null, StorageBindingPolicy.blockedBackupToken(StorageBindingState.SUSPECTED_ORIGINAL))
        assertEquals("backup-device-abnormal", StorageBindingPolicy.blockedBackupToken(StorageBindingState.IDENTITY_ANOMALY))
        assertEquals("backup-device-abnormal", StorageBindingPolicy.blockedBackupToken(StorageBindingState.NEW_DEVICE))
    }
}
