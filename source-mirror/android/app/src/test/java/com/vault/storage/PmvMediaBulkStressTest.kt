package com.vault.storage

import com.vault.model.Entry
import com.vault.model.SyncMeta
import com.vault.model.VaultPayload
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID

/**
 * 大量图像批量提交压力测试：一次提交 150 张、再追加 50 张，
 * 全部 ObjectRef 必须可回读且内容一致（用于定位"添加大量图像后详情页全部不显示"）。
 */
class PmvMediaBulkStressTest {
    private val password = "bulk-stress-password".encodeToByteArray()
    private val recovery = ByteArray(32) { (it * 3).toByte() }

    @Test
    fun `bulk save one hundred fifty images then append fifty more and reopen all`() = withVault { file, rootKey ->
        val adapter = PmvMediaObjectAdapter(file)
        val first = adapter.saveEntryWithMedia(
            rootKey,
            expectedSequence = 1,
            entry = bulkEntry("bulk", 150),
            expectedEntryRevision = null,
            streams = (0 until 150).map { stream(it) },
        )
        assertEquals(150, first.refs.size)
        val entryId = UUID.nameUUIDFromBytes("bulk-id".encodeToByteArray()).toString()
        val readBack = PmvVaultStore.openRootKey(file, rootKey).use {
            requireNotNull(it.readEntry(UUID.fromString(entryId)))
        }
        assertEquals(150, PmvMediaRef.scan(readBack).size)

        // 追加 50 张：把已保存 entry 的 refs 与新增 inline 引用合并后再保存。
        val mergedImages = readBack.fields["images"]!!.jsonArray.toList() +
            (150 until 200).map { JsonPrimitive("img:extra-$it.enc") }
        val pending = readBack.copy(fields = mapOf("images" to JsonArray(mergedImages)))
        val second = adapter.saveEntryWithMedia(
            rootKey,
            expectedSequence = first.identity.sequence,
            entry = pending,
            expectedEntryRevision = first.entryRevision,
            streams = (150 until 200).map { stream(it) },
        )
        // saveEntryWithMedia 只返回本次新增的 ObjectRef
        assertEquals(50, second.refs.size)

        val finalEntry = PmvVaultStore.openRootKey(file, rootKey).use {
            requireNotNull(it.readEntry(UUID.fromString(entryId)))
        }
        val occurrences = PmvMediaRef.scan(finalEntry)
        assertEquals(200, occurrences.size)
        occurrences.forEachIndexed { index, occurrence ->
            val ref = occurrence.ref ?: error("第 $index 个引用未转为 ObjectRef")
            val output = ByteArrayOutputStream()
            adapter.open(ref, rootKey, output)
            val expected = payloadBytes(index, sizeFor(index))
            assertEquals("第 $index 张图片长度不一致", expected.size.toLong(), ref.size)
            assertArrayEquals("第 $index 张图片内容不一致", expected, output.toByteArray())
        }
    }

    private fun stream(index: Int) = PmvMediaRef.LegacyStream(
        path = "/fields/images/$index",
        input = ByteArrayInputStream(payloadBytes(index, sizeFor(index))),
        expectedSize = sizeFor(index).toLong(),
        objectId = UUID.nameUUIDFromBytes("bulk-$index".encodeToByteArray()),
        generation = 1,
        kind = PmvAttachmentCodec.Kind.IMAGE,
    )

    private fun sizeFor(index: Int): Int = if (index < 150) 12 * 1024 else 8 * 1024

    private fun payloadBytes(index: Int, size: Int): ByteArray =
        ByteArray(size) { ((index * 31 + it * 7) and 0xff).toByte() }

    private fun bulkEntry(seed: String, count: Int) = Entry(
        id = UUID.nameUUIDFromBytes("$seed-id".encodeToByteArray()).toString(),
        title = seed,
        fields = mapOf(
            "images" to JsonArray((0 until count).map { JsonPrimitive("img:$it.enc") }),
        ),
        createdAt = 1.0,
        updatedAt = 2.0,
    )

    private inline fun withVault(block: (File, ByteArray) -> Unit) {
        val file = File.createTempFile("pmv-bulk-stress-", ".pmv").also { it.delete() }
        val payload = VaultPayload(
            syncMeta = SyncMeta(UUID.nameUUIDFromBytes("device".encodeToByteArray()).toString(), 1),
        )
        val rootKey = PmvVaultStore.create(
            file,
            password,
            recovery,
            PmvEPayloadAdapter.toMetadata(payload, UUID(0L, 0L)),
            emptyList(),
        ).use(PmvVaultStore.Session::copyRootKeyForDeviceUnlock)
        try {
            block(file, rootKey)
        } finally {
            rootKey.fill(0)
            file.delete()
            File(file.parentFile, "${file.name}.writer.lock").delete()
        }
    }
}
