package com.vault.security

import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.SecretType
import com.vault.model.withEntryModules
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PasswordHealthTest {
    private val today = 20_000L

    @Test
    fun `primary groups are mutually exclusive while findings may overlap`() {
        val duplicate = "short"
        val entries = listOf(
            Entry(id = "a", title = "A", password = duplicate, updatedAt = today * 86_400.0, secretType = SecretType.LOGIN),
            Entry(id = "b", title = "B", password = duplicate, updatedAt = today * 86_400.0, secretType = SecretType.LOGIN),
            Entry(id = "c", title = "C", password = "Correct-Horse-Battery-Staple!", updatedAt = today * 86_400.0, secretType = SecretType.LOGIN)
                .withEntryModules(listOf(otpModule())),
        )

        val report = PasswordHealth.analyzeForTest(entries, today)

        assertEquals(report.total, report.highRisk.size + report.improvement.size + report.healthy.size)
        assertEquals(2, report.findings.getValue(PasswordFinding.DUPLICATE).size)
        assertEquals(2, report.findings.getValue(PasswordFinding.TOO_SHORT).size)
        assertEquals(2, report.highRisk.size)
        assertEquals(1, report.healthy.size)
    }

    @Test
    fun `custom password modules are included while only login and wifi entries are scanned`() {
        val passwordModule = EntryModules.create(ModuleType.PASSWORD).let { raw ->
            JsonObject(raw + ("value" to JsonPrimitive("M0dule!Only#Credential2026")))
        }
        val loginEntry = Entry(
            id = "module",
            title = "Server",
            updatedAt = (today - 200) * 86_400.0,
            secretType = SecretType.LOGIN,
        ).withEntryModules(listOf(passwordModule))
        val serverEntry = Entry(
            id = "server",
            title = "Server host",
            updatedAt = (today - 200) * 86_400.0,
            secretType = SecretType.SERVER,
        ).withEntryModules(listOf(passwordModule))

        val report = PasswordHealth.analyzeForTest(listOf(loginEntry, serverEntry), today)

        assertEquals(1, report.total)
        assertEquals(listOf(loginEntry.id), report.findings.getValue(PasswordFinding.LONG_UNCHANGED).map(Entry::id))
        assertEquals(listOf(loginEntry.id), report.improvement.map(Entry::id))
        assertTrue(report.entriesFor("all").none { it.id == serverEntry.id })
    }

    @Test
    fun `common password detection remains separate from leaked cache`() {
        val entry = Entry(
            id = "common",
            password = "vendor-default",
            updatedAt = today * 86_400.0,
            secretType = SecretType.LOGIN,
        )

        val report = PasswordHealth.analyzeForTest(listOf(entry), today) { it == "vendor-default" }

        assertEquals(listOf(entry.id), report.findings.getValue(PasswordFinding.COMMON_PATTERN).map(Entry::id))
        assertTrue(report.findings.getValue(PasswordFinding.LEAKED).isEmpty())
    }

    private fun otpModule(): JsonObject = EntryModules.create(ModuleType.OTP)
}
