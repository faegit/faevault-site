package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import net.lingala.zip4j.ZipFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.OutputStream
import java.util.UUID

class ArchiveExporterTest {

    private val jpgMagic = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte(), 0x00, 0x10)
    private val pdfMagic = "%PDF-1.7".encodeToByteArray()

    private class FakeMediaSource(
        private val jpgRefs: Set<Pair<UUID, Long>>,
        private val jpgMagic: ByteArray,
        private val pdfMagic: ByteArray,
    ) : ArchiveExporter.MediaSource {
        private fun payload(ref: PmvMediaRef.Ref): ByteArray =
            if (ref.kind == PmvAttachmentCodec.Kind.IMAGE && ref.objectId to ref.generation in jpgRefs) jpgMagic else pdfMagic

        override fun readPrefix(ref: PmvMediaRef.Ref, length: Int): ByteArray =
            payload(ref).copyOf(minOf(length, payload(ref).size))

        override fun readAll(ref: PmvMediaRef.Ref, output: OutputStream) = output.write(payload(ref))
    }

    private fun newRef(kind: PmvAttachmentCodec.Kind, size: Long): PmvMediaRef.Ref {
        val digest = ByteArray(32) { (it + 1).toByte() }
        return PmvMediaRef.Ref(UUID.randomUUID(), 1L, kind, size, digest)
    }

    @Test
    fun `attachment restores original name and mime while image uses detected extension`() {
        // 附件对象：入库时保存的原始文件名/MIME + PMVE 引用
        val attRef = newRef(PmvAttachmentCodec.Kind.ATTACHMENT, pdfMagic.size.toLong())
        val attachmentObject = JsonObject(mapOf(
            "name" to JsonPrimitive("合同.pdf"),
            "mime" to JsonPrimitive("application/pdf"),
            "size" to JsonPrimitive(pdfMagic.size),
            "sha256" to JsonPrimitive(attRef.sha256.joinToString("") { "%02x".format(it) }),
            "data" to attRef.toJson(),
        ))
        val note = Entry(
            title = "合同",
            secretType = SecretType.SECURE_NOTE,
            id = "note-1",
            fields = mapOf("attachments" to JsonArray(listOf(attachmentObject))),
        )

        // 图片条目：只存紧凑引用，扩展名靠嗅探
        val imgRef = newRef(PmvAttachmentCodec.Kind.IMAGE, jpgMagic.size.toLong())
        val login = Entry(title = "登录", secretType = SecretType.LOGIN, id = "login-1")
        val bank = Entry(
            title = "银行卡",
            secretType = SecretType.CREDIT_CARD,
            id = "card-1",
            fields = mapOf("images" to JsonArray(listOf(JsonPrimitive(imgRef.toExternalString())))),
        )

        val file = File.createTempFile("export-archive", ".zip")
        file.deleteOnExit()
        val password = "pass-123"
        val stats = ArchiveExporter.writeToZip(
            file.outputStream(),
            vaultName = "测试库",
            password = password,
            entries = listOf(login, note, bank),
            media = FakeMediaSource(setOf(imgRef.objectId to imgRef.generation), jpgMagic, pdfMagic),
        )

        assertEquals(1, stats.loginCount)
        assertEquals(2, stats.otherCount)
        assertEquals(2, stats.mediaCount)

        ZipFile(file, password.toCharArray()).use { zip ->
            val names = zip.fileHeaders.map { it.fileName }
            assertTrue("附件应还原原始文件名", "attachments/合同.pdf" in names)
            assertTrue("图片应按内容嗅探出 jpg 扩展名", "images/card-1_0.jpg" in names)
            assertTrue("manifest 在归档中", "manifest.json" in names)
            assertTrue("logins.csv 在归档中", "logins.csv" in names)
            assertTrue("data.json 在归档中", "data.json" in names)

            val manifest = zip.getInputStream(zip.fileHeaders.first { it.fileName == "manifest.json" })
                .bufferedReader().use { it.readText() }
            assertTrue("manifest 记录 originalName", manifest.contains("\"originalName\":\"合同.pdf\""))
            assertTrue("manifest 记录 mime", manifest.contains("\"mime\":\"application/pdf\""))

            val dataJson = zip.getInputStream(zip.fileHeaders.first { it.fileName == "data.json" })
                .bufferedReader().use { it.readText() }
            val dataRoot = com.vault.storage.VaultCodec.json.parseToJsonElement(dataJson).jsonObject
            val entriesJson = dataRoot["entries"]!!.jsonArray
            assertEquals(2, entriesJson.size)
            val noteEntry = entriesJson.first { it.jsonObject["id"]!!.jsonPrimitive.content == "note-1" }.jsonObject
            val rewritten = noteEntry["fields"]!!.jsonObject["attachments"]!!.jsonArray[0].jsonObject["data"]!!.jsonObject
            assertEquals("file", rewritten["type"]!!.jsonPrimitive.content)
            assertEquals("attachments/合同.pdf", rewritten["path"]!!.jsonPrimitive.content)
            assertEquals("合同.pdf", rewritten["originalName"]!!.jsonPrimitive.content)
            assertEquals("application/pdf", rewritten["mime"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun `attachment without stored name falls back to mime extension`() {
        val attRef = newRef(PmvAttachmentCodec.Kind.ATTACHMENT, pdfMagic.size.toLong())
        val attachmentObject = JsonObject(mapOf(
            "size" to JsonPrimitive(pdfMagic.size),
            "sha256" to JsonPrimitive(attRef.sha256.joinToString("") { "%02x".format(it) }),
            "data" to attRef.toJson(),
        ))
        val note = Entry(
            title = "无名字附件",
            secretType = SecretType.SECURE_NOTE,
            id = "note-2",
            fields = mapOf("attachments" to JsonArray(listOf(attachmentObject))),
        )

        val file = File.createTempFile("export-archive", ".zip")
        file.deleteOnExit()
        ArchiveExporter.writeToZip(
            file.outputStream(),
            "vault",
            "pass",
            listOf(note),
            FakeMediaSource(emptySet(), jpgMagic, pdfMagic),
        )

        ZipFile(file, "pass".toCharArray()).use { zip ->
            val names = zip.fileHeaders.map { it.fileName }
            assertTrue("无原始名时按 MIME 兜底扩展名", names.any { it == "attachments/attachment.pdf" })
        }
    }
}