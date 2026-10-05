package com.vault

import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import org.junit.Assert.assertEquals
import org.junit.Test

class VaultOpsSameServiceTest {
    @Test
    fun sameServiceOnlyGroupsActiveLoginEntries() {
        val entries = listOf(
            Entry(id = "login-1", title = "PayPal", url = "https://paypal.com/login"),
            Entry(id = "login-2", title = "PayPal work", url = "https://www.paypal.com/home"),
            Entry(id = "passkey", title = "PayPal passkey", url = "https://paypal.com", secretType = SecretType.PASSKEY),
            Entry(id = "card", title = "PayPal card", url = "https://paypal.com", secretType = SecretType.CREDIT_CARD),
            Entry(id = "deleted", title = "Deleted login", url = "https://paypal.com", deletedAt = 1.0),
        )

        val groups = VaultOps.scanSameService(VaultPayload(entries = entries))

        assertEquals(1, groups.size)
        assertEquals(setOf("login-1", "login-2"), groups.single().entries.map { it.id }.toSet())
    }
}
