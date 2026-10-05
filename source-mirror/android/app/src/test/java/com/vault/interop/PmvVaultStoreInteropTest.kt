package com.vault.interop

import com.vault.storage.PmvVaultStore
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest
import java.util.UUID

class PmvVaultStoreInteropTest {
    @Test
    fun `Android and PC complete Store fixtures are mutually readable`() {
        val root = File(requireNotNull(System.getProperty("spec.dir")), "interop/pmv_next/v1")
        val document = Json.parseToJsonElement(File(root, "store_interop.json").readText()).jsonObject
        val password = document.getValue("passwordUtf8").jsonPrimitive.content.encodeToByteArray()
        val recovery = document.getValue("recoverySecretHex").jsonPrimitive.content.decodeHex()
        try {
            document.getValue("cases").jsonArray.forEach { element ->
                val case = element.jsonObject
                val fixture = File(root, case.string("blob"))
                assertTrue("missing complete Store fixture ${fixture.absolutePath}", fixture.isFile)
                assertEquals(case.long("size"), fixture.length())
                assertEquals(case.string("sha256"), sha256(fixture).toHex())
                verify(case, PmvVaultStore.openPassword(fixture, password))
                verify(case, PmvVaultStore.openRecovery(fixture, recovery))
            }
        } finally {
            password.fill(0)
            recovery.fill(0)
        }
    }

    private fun verify(case: kotlinx.serialization.json.JsonObject, session: PmvVaultStore.Session) {
        session.use {
            val identity = it.identity()
            assertEquals(UUID.fromString(case.string("vaultId")), identity.vaultId)
            assertEquals(case.long("sequence"), identity.sequence)
            assertEquals(UUID.fromString(case.string("commitId")), identity.latestCommitId)
            case["parentCommitId"]?.jsonPrimitive?.content?.let { parent ->
                assertEquals(UUID.fromString(parent), identity.parentCommitId)
            }
            assertArrayEquals(case.string("rootDigestHex").decodeHex(), identity.rootDigest)
            assertEquals(
                case.getValue("titles").jsonArray.map { value -> value.jsonPrimitive.content },
                it.listSummaries().map { summary -> summary.displayTitle },
            )
            assertEquals(case.string("metadataMarker"), it.readMetadata().getValue("interop_marker").jsonPrimitive.content)
            val loginId = UUID.fromString(case.string("loginId"))
            val login = requireNotNull(it.readEntry(loginId))
            assertEquals(case.int("extensionAnswer"), login.fields.getValue("future_extension").jsonObject.getValue("answer").jsonPrimitive.content.toInt())
            assertNotNull(it.readEntry(UUID.fromString(case.string("trashId")))?.deletedAt)
            assertEquals(case.string("rpId"), it.readEntry(UUID.fromString(case.string("passkeyId")))?.fields?.get("rp_id")?.jsonPrimitive?.content)
            assertEquals(listOf(loginId), it.queryDomain(case.string("domain")))
            assertEquals(listOf(loginId), it.queryPackage(case.string("package")))
            assertEquals(listOf(UUID.fromString(case.string("passkeyId"))), it.queryRpId(case.string("rpId")))
        }
    }

    private fun sha256(file: File): ByteArray = file.inputStream().use { input ->
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        digest.digest()
    }

    private fun kotlinx.serialization.json.JsonObject.string(name: String) = getValue(name).jsonPrimitive.content
    private fun kotlinx.serialization.json.JsonObject.long(name: String) = string(name).toLong()
    private fun kotlinx.serialization.json.JsonObject.int(name: String) = string(name).toInt()
    private fun String.decodeHex() = ByteArray(length / 2) { substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
