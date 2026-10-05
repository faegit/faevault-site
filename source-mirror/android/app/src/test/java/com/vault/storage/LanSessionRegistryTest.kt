package com.vault.storage

import java.util.UUID
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LanSessionRegistryTest {
    @Test
    fun `three channel sessions retain independent operation and authorization`() {
        val registry = LanSessionRegistry()
        val syncDevice = UUID.randomUUID()
        val exportDevice = UUID.randomUUID()

        val sync = registry.add("sync-token", SyncServerHost.SYNC_OP)
        sync.authorizedDeviceId = syncDevice
        val transfer = registry.add("transfer-token", SyncServerHost.TRANSFER_OP)
        val secondTransfer = registry.add("second-transfer-token", SyncServerHost.TRANSFER_OP)
        transfer.transferApproved.set(true)
        transfer.authorizedDeviceId = UUID.randomUUID()
        val export = registry.add("export-token", SyncServerHost.EXPORT_OP)
        export.authorizedDeviceId = exportDevice
        export.exportApproved.set(true)

        assertEquals(SyncServerHost.SYNC_OP, registry.find("sync-token")?.op)
        assertEquals(syncDevice, registry.find("sync-token")?.authorizedDeviceId)
        assertEquals(SyncServerHost.TRANSFER_OP, registry.find("transfer-token")?.op)
        assertEquals("transfer-token", registry.find("transfer-token")?.token)
        assertTrue(registry.find("transfer-token")!!.transferApproved.get())
        assertFalse(registry.find("second-transfer-token")!!.transferApproved.get())
        assertNull(registry.find("second-transfer-token")?.authorizedDeviceId)
        assertFalse(registry.find("transfer-token")!!.exportApproved.get())
        assertEquals(SyncServerHost.EXPORT_OP, registry.find("export-token")?.op)
        assertEquals(exportDevice, registry.find("export-token")?.authorizedDeviceId)
        assertTrue(registry.find("export-token")!!.exportApproved.get())
        registry.clear()
        assertFalse(transfer.transferApproved.get())
        assertNull(transfer.authorizedDeviceId)
    }
}
