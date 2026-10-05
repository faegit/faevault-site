package com.vault.interop

import com.vault.model.Entry
import com.vault.storage.PmvAttachmentCodec
import com.vault.storage.PmvMediaRef
import com.vault.storage.PmvVaultStore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID
import kotlinx.serialization.json.JsonArray
import org.junit.Assert.assertArrayEquals
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Optional live file round-trip driven by vault_pc/tools/verify_media_merge_interop.py. */
class PmvMediaMergeInteropTest {
    @Test
    fun `merge PC media with Android media and reopen PC reverse merge`() {
        val location = System.getenv("PMV_MERGE_INTEROP_DIR")
        assumeTrue("Set PMV_MERGE_INTEROP_DIR to generated disposable fixtures", location != null)
        val dir = File(requireNotNull(location))
        val password = "merge-test".encodeToByteArray()
        val reverse = File(dir, "pc-merged.pmv")
        if (reverse.isFile) {
            PmvVaultStore.openPassword(reverse, password).use(::verify)
            return
        }
        val local = File(dir, "android-local.pmv")
        val candidate = File(dir, "pc-candidate.pmv")
        PmvVaultStore.openPassword(local, password).use { source ->
            val plain = "android-only image".encodeToByteArray()
            source.applyMutation(source.identity().sequence, listOf(PmvVaultStore.ObjectImport(
                ByteArrayInputStream(plain), plain.size.toLong(), UUID(0, 202), 1, PmvAttachmentCodec.Kind.IMAGE,
            ))) { refs ->
                val ref = refs.single().let { PmvMediaRef.Ref(it.objectId, it.generation, it.kind, it.size, it.sha256) }
                PmvVaultStore.MutationContent(source.readMetadata(), listOf(Entry(
                    id = UUID(0, 102).toString(), title = "Android media",
                    fields = mapOf("images" to JsonArray(listOf(ref.toJson()))),
                )))
            }
            PmvVaultStore.openPassword(candidate, password).use { target ->
                val entries = listOf(source, target).flatMap { session ->
                    session.listSummaries().map { requireNotNull(session.readEntry(it.entryId)) }
                }
                target.saveMerged(source, target.readMetadata(), entries, target.identity().sequence)
                verify(target)
            }
        }
    }

    private fun verify(session: PmvVaultStore.Session) {
        listOf(201L to "pc-only image", 202L to "android-only image").forEach { (id, expected) ->
            val output = ByteArrayOutputStream()
            session.openObject(UUID(0, id), 1, output)
            assertArrayEquals(expected.encodeToByteArray(), output.toByteArray())
        }
    }
}
