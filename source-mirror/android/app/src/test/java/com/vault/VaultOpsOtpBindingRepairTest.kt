package com.vault

import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import com.vault.model.otpBindingId
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class VaultOpsOtpBindingRepairTest {

    private val otpEntry = Entry(
        id = "otp-1",
        secretType = SecretType.OTP,
        fields = mapOf("otp_secret" to JsonPrimitive("JBSWY3DPEHPK3PXP")),
    )

    private fun login(id: String, boundId: String?) = Entry(
        id = id,
        secretType = SecretType.LOGIN,
        username = "u",
        password = "p",
        fields = boundId?.let { mapOf("bound_otp_id" to JsonPrimitive(it)) } ?: emptyMap(),
    )

    @Test
    fun `binding to live otp entry is kept`() {
        val payload = VaultPayload(entries = listOf(login("login-1", "otp-1"), otpEntry))
        assertSame(payload, VaultOps.repairOtpBindings(payload))
        assertEquals("otp-1", payload.entries.first().otpBindingId())
    }

    @Test
    fun `binding to missing entry is stripped`() {
        val payload = VaultPayload(entries = listOf(login("login-1", "otp-missing")))
        val repaired = VaultOps.repairOtpBindings(payload)
        assertNotSame(payload, repaired)
        assertNull(repaired.entries.first().otpBindingId())
    }

    @Test
    fun `binding to trashed otp entry is stripped`() {
        val trashed = otpEntry.copy(deletedAt = 1.0)
        val payload = VaultPayload(entries = listOf(login("login-1", "otp-1"), trashed))
        assertNull(VaultOps.repairOtpBindings(payload).entries.first().otpBindingId())
    }

    @Test
    fun `binding to entry without otp secret is stripped`() {
        val noSecret = Entry(id = "otp-2", secretType = SecretType.OTP)
        val payload = VaultPayload(entries = listOf(login("login-1", "otp-2"), noSecret))
        assertNull(VaultOps.repairOtpBindings(payload).entries.first().otpBindingId())
    }

    @Test
    fun `binding to another login entry is stripped`() {
        val otherLogin = Entry(id = "login-2", secretType = SecretType.LOGIN, username = "u", password = "p")
        val payload = VaultPayload(entries = listOf(login("login-1", "login-2"), otherLogin))
        assertNull(VaultOps.repairOtpBindings(payload).entries.first().otpBindingId())
    }

    @Test
    fun `repair does not bump updatedAt`() {
        val dangling = login("login-1", "otp-missing").copy(updatedAt = 42.0)
        val payload = VaultPayload(entries = listOf(dangling))
        assertEquals(42.0, VaultOps.repairOtpBindings(payload).entries.first().updatedAt, 0.0)
    }
}