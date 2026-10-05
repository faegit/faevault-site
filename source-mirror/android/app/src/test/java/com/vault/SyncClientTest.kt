package com.vault

import com.vault.storage.SyncClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SyncClientTest {
    @Test fun endpointAddsHttpsSchemeForManualAddress() {
        assertEquals(
            "https://192.168.1.100:18765/api/sync/vault",
            SyncClient.endpoint("192.168.1.100:18765").toString(),
        )
    }

    @Test fun endpointAcceptsFullQrUrlWithoutDuplicatingPath() {
        assertEquals(
            "https://192.168.1.100:18765/api/sync/vault",
            SyncClient.endpoint("https://192.168.1.100:18765/api/sync/vault?ticket=abcdef1234567890").toString(),
        )
    }

    @Test fun pairingTicketIsExtractedFromFullQrUrl() {
        assertEquals(
            "abcdef1234567890",
            SyncClient.pairingTicket("https://192.168.1.100:18765/api/sync/vault?ticket=abcdef1234567890"),
        )
    }

    @Test fun lanEndpointsRejectPublicAndDnsHosts() {
        assertTrue(SyncClient.isAllowedLanImportHost("127.0.0.1"))
        assertTrue(SyncClient.isAllowedLanImportHost("10.1.2.3"))
        assertThrows(IllegalArgumentException::class.java) { SyncClient.endpoint("8.8.8.8:18765") }
        assertThrows(IllegalArgumentException::class.java) { SyncClient.endpoint("example.com:18765") }
    }

    @Test fun lanEndpointsRejectAmbiguousOrCredentialBearingUrls() {
        assertThrows(IllegalArgumentException::class.java) {
            SyncClient.endpoint("https://user:secret@192.168.1.5:18765/?ticket=abcdef1234567890")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SyncClient.endpoint("https://192.168.1.5:18765/?ticket=abcdef1234567890#fragment")
        }
        assertThrows(IllegalArgumentException::class.java) {
            SyncClient.endpoint("https://192.168.1.5:18765/?ticket=" + "a".repeat(3000))
        }
    }
}
