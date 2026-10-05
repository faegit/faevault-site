package com.vault.storage

import com.vault.model.Entry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.boolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import com.vault.ui.media.mediaValueString

class PmvMediaRefTest {
    private val vector: JsonObject by lazy {
        val root = File(requireNotNull(System.getProperty("spec.dir")), "interop/pmv_next/v1/media_ref.json")
        Json.parseToJsonElement(root.readText()).jsonObject["cases"]!!.jsonArray.single().jsonObject
    }

    @Test
    fun `shared vector fixes JSON and string representation`() {
        val expectedJson = vector["json"]!!.jsonObject
        val ref = PmvMediaRef.fromJson(expectedJson)
        assertEquals(expectedJson, ref.toJson())
        assertEquals(vector["string"]!!.jsonPrimitive.content, ref.toExternalString())
        assertEquals(ref, PmvMediaRef.fromExternalString(ref.toExternalString()))
        assertEquals(ref.toExternalString(), mediaValueString(expectedJson))
        assertEquals(ref.toExternalString(), mediaValueString(JsonPrimitive(ref.toExternalString())))
        assertThrows(IllegalArgumentException::class.java) {
            PmvMediaRef.fromExternalString(ref.toExternalString().replace("attachment", "ATTACHMENT"))
        }
    }

    @Test
    fun `shared vector classifies object legacy inline and unknown media fields`() {
        val entry = Entry(id = UUID(0, 1).toString(), fields = vector["fields"]!!.jsonObject)
        val actual = PmvMediaRef.scan(entry).associate { it.path to it.classification.name.lowercase() }
        val expected = vector["classifications"]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }
        assertEquals(expected, actual)
        vector["closure_cases"]!!.jsonArray.forEach { raw ->
            val case = raw.jsonObject
            fun keys(name: String) = case[name]!!.jsonArray.map { it.jsonPrimitive.content }
            val available = keys("available").toSet()
            val imported = keys("imported")
            val referenced = keys("referenced").toSet()
            val valid = imported.size == imported.toSet().size &&
                referenced.all { it in available } && imported.all { it in referenced }
            assertEquals(case["valid"]!!.jsonPrimitive.boolean, valid)
        }
    }

    @Test
    fun `declarative plan creates imports and replaces only resolved legacy paths`() {
        val entry = Entry(id = UUID(0, 1).toString(), fields = vector["fields"]!!.jsonObject)
        val imageId = UUID(0, 2)
        val attachmentId = UUID(0, 3)
        val plan = PmvMediaRef.plan(entry, listOf(
            PmvMediaRef.LegacyStream(
                "/fields/modules/0/value/0", ByteArrayInputStream(byteArrayOf(1, 2)), 2,
                imageId, 4, PmvAttachmentCodec.Kind.IMAGE,
            ),
            PmvMediaRef.LegacyStream(
                "/fields/modules/1/value/0/data", ByteArrayInputStream(byteArrayOf(3)), 1,
                attachmentId, 5, PmvAttachmentCodec.Kind.ATTACHMENT,
            ),
        ))
        assertEquals(listOf(imageId, attachmentId), plan.objectImports.map { it.objectId })
        val refs = listOf(
            PmvVaultStore.ObjectRef(imageId, 4, PmvAttachmentCodec.Kind.IMAGE, 2, ByteArray(32) { 1 }),
            PmvVaultStore.ObjectRef(attachmentId, 5, PmvAttachmentCodec.Kind.ATTACHMENT, 1, ByteArray(32) { 2 }),
        )
        val transformed = plan.transform(refs)
        val scanned = PmvMediaRef.scan(transformed)
        assertTrue(scanned.any { it.path == "/fields/modules/0/value/0" &&
            it.classification == PmvMediaRef.Classification.OBJECT && it.ref?.objectId == imageId })
        assertTrue(scanned.any { it.path == "/fields/modules/1/value/0/data" &&
            it.classification == PmvMediaRef.Classification.OBJECT && it.ref?.objectId == attachmentId })
        assertTrue(scanned.any { it.path == "/fields/modules/0/value/1" &&
            it.classification == PmvMediaRef.Classification.INLINE })
    }

    @Test
    fun `plan bridges legacy stream into the same mutation commit and closure rejects invalid states`() {
        val file = kotlin.io.path.createTempFile("pmv-media-ref-", ".pmv").toFile().also { it.delete() }
        val password = "media-password".encodeToByteArray()
        val recovery = ByteArray(32) { it.toByte() }
        val plain = "streamed legacy image".encodeToByteArray()
        val objectId = UUID(0, 22)
        try {
            PmvVaultStore.create(file, password, recovery, metadata(), emptyList()).use { session ->
                val legacy = Entry(
                    id = UUID(0, 11).toString(),
                    fields = mapOf("images" to JsonArray(listOf(JsonPrimitive("img:legacy.enc")))),
                )
                val plan = PmvMediaRef.plan(legacy, listOf(PmvMediaRef.LegacyStream(
                    "/fields/images/0", ByteArrayInputStream(plain), plain.size.toLong(), objectId, 1,
                    PmvAttachmentCodec.Kind.IMAGE,
                )))
                val committed = session.applyMutation(1, plan.objectImports) { refs -> plan.prepare(refs, metadata()) }
                assertEquals(2L, committed.identity.sequence)
                val output = ByteArrayOutputStream()
                session.openObject(objectId, 1, output)
                assertTrue(plain.contentEquals(output.toByteArray()))

                val dangling = PmvMediaRef.Ref(UUID(0, 99), 1, PmvAttachmentCodec.Kind.IMAGE, 0, ByteArray(32))
                assertThrows(IllegalArgumentException::class.java) {
                    session.applyMutation(2) {
                        PmvVaultStore.MutationContent(metadata(), listOf(legacy.copy(
                            fields = mapOf("images" to JsonArray(listOf(dangling.toJson()))),
                        )))
                    }
                }
                assertThrows(IllegalArgumentException::class.java) {
                    session.applyMutation(2, listOf(PmvVaultStore.ObjectImport(
                        ByteArrayInputStream(byteArrayOf(1)), 1, UUID(0, 33), 1,
                        PmvAttachmentCodec.Kind.ATTACHMENT,
                    ))) {
                        PmvVaultStore.MutationContent(
                            metadata(),
                            listOf(requireNotNull(session.readEntry(UUID.fromString(legacy.id)))),
                        )
                    }
                }
                val duplicate = PmvVaultStore.ObjectImport(
                    ByteArrayInputStream(byteArrayOf(1)), 1, UUID(0, 44), 1, PmvAttachmentCodec.Kind.IMAGE,
                )
                assertThrows(IllegalArgumentException::class.java) {
                    session.applyMutation(2, listOf(duplicate, duplicate)) {
                        PmvVaultStore.MutationContent(metadata(), emptyList())
                    }
                }
                assertEquals(2L, session.identity().sequence)
            }
        } finally {
            password.fill(0)
            recovery.fill(0)
            file.delete()
            File(file.path + ".writer.lock").delete()
        }
    }

    private fun metadata() = JsonObject(mapOf(
        "schema" to JsonPrimitive(PmvVaultMetadataCodec.SCHEMA),
        "version" to JsonPrimitive(PmvVaultMetadataCodec.VERSION),
        "vault_id" to JsonPrimitive(UUID(0, 1).toString()),
        "entry_order" to JsonArray(emptyList()),
        "trash_order" to JsonArray(emptyList()),
        "sync_meta" to JsonObject(mapOf("device_id" to JsonPrimitive(UUID(0, 2).toString()))),
        "key_revision" to JsonPrimitive(0),
        "export_epoch" to JsonNull,
        "purge_tombstones" to JsonObject(emptyMap()),
    ))
}
