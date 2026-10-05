package com.vault.os

import org.junit.Assert.assertEquals
import org.junit.Test

class WifiSecurityTest {
    @Test
    fun normalizeKeepsCanonicalValues() {
        assertEquals("无加密", WifiSecurity.normalizeSecurity(""))
        assertEquals("无加密", WifiSecurity.normalizeSecurity(null))
        assertEquals("无加密", WifiSecurity.normalizeSecurity("无加密"))
        assertEquals("WEP", WifiSecurity.normalizeSecurity("WEP"))
        assertEquals("WPA-Personal", WifiSecurity.normalizeSecurity("WPA-Personal"))
        assertEquals("WPA2-Personal", WifiSecurity.normalizeSecurity("WPA2-Personal"))
        assertEquals("WPA2/WPA3-Personal", WifiSecurity.normalizeSecurity("WPA2/WPA3-Personal"))
        assertEquals("WPA3-Personal", WifiSecurity.normalizeSecurity("WPA3-Personal"))
        assertEquals("WPA-Enterprise", WifiSecurity.normalizeSecurity("WPA-Enterprise"))
        assertEquals("WPA2-Enterprise", WifiSecurity.normalizeSecurity("WPA2-Enterprise"))
        assertEquals("WPA3-Enterprise", WifiSecurity.normalizeSecurity("WPA3-Enterprise"))
    }

    @Test
    fun normalizeMapsExternalTokensToCanonicalEnum() {
        assertEquals("无加密", WifiSecurity.normalizeSecurity("nopass"))
        assertEquals("无加密", WifiSecurity.normalizeSecurity("OPEN"))
        assertEquals("WPA-Personal", WifiSecurity.normalizeSecurity("WPA"))
        assertEquals("WPA-Personal", WifiSecurity.normalizeSecurity("wpa-personal"))
        assertEquals("WPA2-Personal", WifiSecurity.normalizeSecurity("WPA2"))
        assertEquals("WPA2-Personal", WifiSecurity.normalizeSecurity("WPA2-PSK"))
        assertEquals("WPA2/WPA3-Personal", WifiSecurity.normalizeSecurity("WPA2/WPA3"))
        assertEquals("WPA3-Personal", WifiSecurity.normalizeSecurity("WPA3-Personal"))
        assertEquals("WPA3-Personal", WifiSecurity.normalizeSecurity("SAE"))
        assertEquals("WPA3-Personal", WifiSecurity.normalizeSecurity("WPA3-SAE"))
    }

    @Test
    fun normalizeMapsLegacyAggregatesToTransitionMode() {
        assertEquals("WPA2/WPA3-Personal", WifiSecurity.normalizeSecurity("WPA-WPA3"))
        assertEquals("WPA2/WPA3-Personal", WifiSecurity.normalizeSecurity("混合加密"))
        assertEquals("WPA2-Personal", WifiSecurity.normalizeSecurity("WPA/WPA2"))
        assertEquals("WPA2-Personal", WifiSecurity.normalizeSecurity("WPA2-Personal"))
    }

    @Test
    fun normalizeMapsEnterpriseTokens() {
        assertEquals("WPA-Enterprise", WifiSecurity.normalizeSecurity("WPA-ENTERPRISE"))
        assertEquals("WPA2-Enterprise", WifiSecurity.normalizeSecurity("WPA2-EAP"))
        assertEquals("WPA3-Enterprise", WifiSecurity.normalizeSecurity("WPA3-ENTERPRISE"))
    }

    @Test
    fun normalizePassesThroughUnknownValues() {
        assertEquals("wpa4-unknown", WifiSecurity.normalizeSecurity("wpa4-unknown"))
    }

    @Test
    fun qrTokenAggregatesWpaFamily() {
        assertEquals("WPA", WifiSecurity.qrAuthToken("WPA-Personal", hasPassword = true))
        assertEquals("WPA", WifiSecurity.qrAuthToken("WPA2-Personal", hasPassword = true))
        assertEquals("WPA", WifiSecurity.qrAuthToken("WPA3-Personal", hasPassword = true))
        assertEquals("WPA", WifiSecurity.qrAuthToken("WPA2/WPA3-Personal", hasPassword = true))
        assertEquals("WPA", WifiSecurity.qrAuthToken("WPA2-Enterprise", hasPassword = true))
    }

    @Test
    fun qrTokenKeepsWepPrecise() {
        assertEquals("WEP", WifiSecurity.qrAuthToken("WEP", hasPassword = true))
    }

    @Test
    fun qrTokenNeverEmitsNopassWithPassword() {
        assertEquals("nopass", WifiSecurity.qrAuthToken("无加密", hasPassword = false))
        assertEquals("WPA", WifiSecurity.qrAuthToken("无加密", hasPassword = true))
    }

    @Test
    fun coercedForSavePromotesOpenNetworkOncePasswordSet() {
        assertEquals("WPA2-Personal", WifiSecurity.coercedForSave("无加密", "secret"))
        assertEquals("无加密", WifiSecurity.coercedForSave("无加密", ""))
        assertEquals("WPA2-Personal", WifiSecurity.coercedForSave("WPA2-Personal", "secret"))
        assertEquals("WPA3-Personal", WifiSecurity.coercedForSave("WPA3-SAE", "secret"))
    }
}