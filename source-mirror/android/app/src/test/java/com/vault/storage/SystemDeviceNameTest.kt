package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Test

class SystemDeviceNameTest {
    @Test fun systemSettingWinsOverModelAndWhitespaceIsTrimmed() {
        assertEquals("My phone", SystemDeviceName.resolve(" My phone ", "Model"))
    }

    @Test fun missingOrBlankSystemNameFallsBackWithoutPermissions() {
        assertEquals("Model", SystemDeviceName.resolve(null, "Model"))
        assertEquals("Model", SystemDeviceName.resolve("  ", "Model"))
        assertEquals("Android", SystemDeviceName.resolve(null, ""))
    }

    @Test fun namesFitCrossClientMetadataLimit() {
        assertEquals(64, SystemDeviceName.resolve("x".repeat(100), "Model").length)
    }
}
