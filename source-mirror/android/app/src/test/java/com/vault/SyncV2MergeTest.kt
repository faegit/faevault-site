package com.vault

import com.vault.model.Entry
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.double
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 跨端互操作测试：读 spec/sync_v2_fixtures.json 跑 LWW 合并算法，
 * 桌面端必须用同一份 fixture 比对结果，确保两端行为一致（spec/SYNC_V2.md §9）。
 *
 * fixture 里的 "content" 字段映射到 Entry.title，因为 Entry.sameContent 不比 title，
 * 但比 password；为简化，测试 fixture 用 password 字段承载"内容差异"。
 */
class SyncV2MergeTest {

    @Test fun coalescesDifferentIdsWhenOnlyAndroidPackageDiffers() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "pc-id", title = "Example", username = "alice", password = "secret", updatedAt = 100.0),
        ))
        val incoming = listOf(
            Entry(
                id = "android-id",
                title = "Example",
                username = "alice",
                password = "secret",
                targetApp = "com.example.app",
                updatedAt = 200.0,
            ),
        )

        val (out, stats) = VaultOps.mergeLww(local, incoming)

        assertEquals(1, out.entries.size)
        assertEquals("pc-id", out.entries.single().id)
        assertEquals("com.example.app", out.entries.single().targetApp)
        assertTrue(out.purgeTombstones.getValue("android-id") > 200.0)
        assertEquals(1, stats.coalesced)
    }

    @Test fun keepsIntentionalDuplicatesWhenNeitherHasPackage() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "one", title = "Example", username = "alice", password = "secret"),
        ))
        val incoming = listOf(
            Entry(id = "two", title = "Example", username = "alice", password = "secret"),
        )

        val (out, stats) = VaultOps.mergeLww(local, incoming)

        assertEquals(setOf("one", "two"), out.entries.map { it.id }.toSet())
        assertEquals(0, stats.coalesced)
    }

    private val fixtures: JsonObject by lazy {
        val dir = System.getProperty("spec.dir") ?: "spec"
        Json.parseToJsonElement(File(dir, "sync_v2_fixtures.json").readText()) as JsonObject
    }

    private fun JsonObject.entries(key: String): List<Entry> =
        this[key]!!.jsonObject["entries"]!!.jsonArray.map { it.jsonObject.toEntry() }

    private fun JsonObject.toEntry(): Entry {
        val id = this["id"]!!.jsonPrimitive.contentOrNull ?: ""
        val createdAt = this["createdAt"]!!.jsonPrimitive.double
        val updatedAt = this["updatedAt"]!!.jsonPrimitive.double
        val deletedAt = this["deletedAt"]?.jsonPrimitive?.doubleOrNull
        // 用 content 字段映射到 password，使 sameContent 比较有差异
        val content = this["content"]?.jsonPrimitive?.contentOrNull ?: ""
        return Entry(
            id = id,
            title = "T",                 // 固定 title，让差异只来自 password
            password = content,
            createdAt = createdAt,
            updatedAt = updatedAt,
            deletedAt = deletedAt,
        )
    }

    private fun runFixture(name: String): Pair<VaultPayload, VaultOps.LwwMergeStats> {
        val fixture = fixtures["fixtures"]!!.jsonArray.first {
            it.jsonObject["name"]!!.jsonPrimitive.content == name
        }.jsonObject
        val local = VaultPayload(entries = fixture.entries("local"))
        val incoming = fixture["incoming"]!!.jsonArray.map { it.jsonObject.toEntry() }
        val choice = fixture["onConflict"]?.jsonPrimitive?.contentOrNull
        val cb: (Entry, Entry) -> VaultOps.ConflictChoice = { _, _ ->
            when (choice) {
                "KEEP_LOCAL" -> VaultOps.ConflictChoice.KEEP_LOCAL
                "KEEP_REMOTE" -> VaultOps.ConflictChoice.KEEP_REMOTE
                "KEEP_BOTH" -> VaultOps.ConflictChoice.KEEP_BOTH
                else -> VaultOps.ConflictChoice.KEEP_BOTH
            }
        }
        return VaultOps.mergeLww(local, incoming, incomingExportEpoch = null, onConflict = cb)
    }

    @Test fun fixture1_remoteOnlyNew() {
        val (out, _) = runFixture("1_remote_only_new")
        assertEquals(1, out.entries.size)
        assertEquals("00000000-0000-0000-0000-000000000001", out.entries[0].id)
    }

    @Test fun fixture2_localOnlyKeep() {
        val (out, _) = runFixture("2_local_only_keep")
        assertEquals(1, out.entries.size)
        assertEquals(1700000100.0, out.entries[0].updatedAt, 0.001)
    }

    @Test fun fixture3_remoteNewerWins() {
        val (out, _) = runFixture("3_remote_newer_wins")
        assertEquals(1, out.entries.size)
        assertEquals("new", out.entries[0].password)
        assertEquals(1700000200.0, out.entries[0].updatedAt, 0.001)
    }

    @Test fun fixture4_localNewerWins() {
        val (out, _) = runFixture("4_local_newer_wins")
        assertEquals(1, out.entries.size)
        assertEquals("local", out.entries[0].password)
        assertEquals(1700000200.0, out.entries[0].updatedAt, 0.001)
    }

    @Test fun fixture5_localDeletePropagates() {
        val (out, _) = runFixture("5_local_delete_propagates")
        assertEquals(1, out.entries.size)
        assertEquals(1700000200.0, out.entries[0].deletedAt!!, 0.001)
    }

    @Test fun fixture6_remoteDeletePropagates() {
        val (out, _) = runFixture("6_remote_delete_propagates")
        assertEquals(1, out.entries.size)
        assertEquals(1700000100.0, out.entries[0].deletedAt!!, 0.001)
    }

    @Test fun fixture7_resurrectAfterDelete() {
        val (out, _) = runFixture("7_resurrect_after_delete")
        assertEquals(1, out.entries.size)
        assertEquals(null, out.entries[0].deletedAt)
        assertEquals("X-edited", out.entries[0].password)
    }

    @Test fun fixture8_sameSecondConflictKeepBoth() {
        val (out, stats) = runFixture("8_same_second_conflict_keep_both")
        assertEquals(2, out.entries.size)
        assertEquals(1, stats.keptBoth)
        val origin = out.entries.first { it.id == "00000000-0000-0000-0000-000000000001" }
        val dup = out.entries.first { it.id != "00000000-0000-0000-0000-000000000001" }
        assertEquals("A", origin.password)
        assertEquals("B", dup.password)
        assertNotEquals("KEEP_BOTH 必须复制为新 UUID", origin.id, dup.id)
    }

    @Test fun exportEpochDoesNotRewriteEntryTimestamps() {
        val skewTest = fixtures["clock_skew_test"]!!.jsonObject
        val exportEpoch = skewTest["header_exportEpoch"]!!.jsonPrimitive.int.toDouble()
        val localNow = skewTest["local_now"]!!.jsonPrimitive.int.toDouble()

        val raw = skewTest["incoming_raw"]!!.jsonArray[0].jsonObject.toEntry()
        val (out, stats) = VaultOps.mergeLww(
            local = VaultPayload(entries = emptyList()),
            incoming = listOf(raw),
            incomingExportEpoch = exportEpoch,
            localNow = localNow,
        )

        val entry = out.entries.single()
        assertEquals(raw.createdAt, entry.createdAt, 0.001)
        assertEquals(raw.updatedAt, entry.updatedAt, 0.001)
        assertEquals(raw.deletedAt!!, entry.deletedAt!!, 0.001)
        assertEquals(1, stats.added)
    }

    @Test fun mergeLwwComparesRawPerEntryUpdatedAt() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "Local", password = "old", updatedAt = 1_700_000_040.0),
        ))
        val incoming = listOf(
            Entry(id = "a", title = "Remote", password = "new", updatedAt = 1_700_000_000.0),
        )

        val (out, stats) = VaultOps.mergeLww(
            local = local,
            incoming = incoming,
            incomingExportEpoch = 1_700_000_000.0,
            localNow = 1_700_000_050.0,
        )

        assertEquals("Local", out.entries.single().title)
        assertEquals("old", out.entries.single().password)
        assertEquals(1_700_000_040.0, out.entries.single().updatedAt, 0.001)
        assertEquals(1, stats.takeLocal)
    }

    @Test fun mergeLwwDoesNotTreatOldExportAgeAsClockSkew() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "Android", password = "local", updatedAt = 1_700_000_500.0),
        ))
        val incoming = listOf(
            Entry(id = "a", title = "PC", password = "remote", updatedAt = 1_700_000_000.0),
        )

        val (out, stats) = VaultOps.mergeLww(
            local = local,
            incoming = incoming,
            incomingExportEpoch = 1_700_000_000.0,
            localNow = 1_700_000_600.0,
        )

        assertEquals("Android", out.entries.single().title)
        assertEquals("local", out.entries.single().password)
        assertEquals(1, stats.takeLocal)
    }

    @Test fun sameSecondTitleOrUsernameChangeIsConflictNotIdentical() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "Old", username = "alice", password = "pw", updatedAt = 100.0),
        ))
        val incoming = listOf(
            Entry(id = "a", title = "New", username = "alice", password = "pw", updatedAt = 100.0),
        )

        val (out, stats) = VaultOps.mergeLww(
            local,
            incoming,
            onConflict = { _, _ -> VaultOps.ConflictChoice.KEEP_REMOTE },
        )

        assertEquals("New", out.entries.single().title)
        assertEquals(1, stats.conflicts)
        assertEquals(1, stats.takeRemote)
        assertEquals(0, stats.identical)
    }

    @Test fun sameSecondDeleteStateDifferenceIsConflictNotIdentical() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "A", password = "pw", updatedAt = 100.0, deletedAt = 100.0),
        ))
        val incoming = listOf(
            Entry(id = "a", title = "A", password = "pw", updatedAt = 100.0, deletedAt = null),
        )

        val (out, stats) = VaultOps.mergeLww(
            local,
            incoming,
            onConflict = { _, _ -> VaultOps.ConflictChoice.KEEP_REMOTE },
        )

        assertEquals(null, out.entries.single().deletedAt)
        assertEquals(1, stats.conflicts)
        assertEquals(1, stats.takeRemote)
        assertEquals(0, stats.identical)
    }

    @Test fun restoredOldEntryDoesNotOverwriteNewerRemoteEdit() {
        val restoredLocal = VaultPayload(entries = listOf(
            Entry(id = "a", title = "Old", password = "old", updatedAt = 100.0, deletedAt = null),
        ))
        val incoming = listOf(
            Entry(id = "a", title = "New", password = "new", updatedAt = 200.0, deletedAt = null),
        )

        val (out, stats) = VaultOps.mergeLww(restoredLocal, incoming)

        assertEquals("New", out.entries.single().title)
        assertEquals("new", out.entries.single().password)
        assertEquals(200.0, out.entries.single().updatedAt, 0.001)
        assertEquals(1, stats.takeRemote)
    }

    @Test fun purgeTombstoneRemovesOlderLocalEntry() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "A", password = "pw", updatedAt = 100.0),
        ))

        val (out, stats) = VaultOps.mergeLww(
            local = local,
            incoming = emptyList(),
            incomingPurgeTombstones = mapOf("a" to 200.0),
        )

        assertTrue(out.entries.isEmpty())
        assertEquals(200.0, out.purgeTombstones["a"]!!, 0.001)
        assertEquals(1, stats.purged)
    }

    @Test fun newerLocalEntrySuppressesOlderPurgeTombstone() {
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "A", password = "pw", updatedAt = 300.0),
        ))

        val (out, stats) = VaultOps.mergeLww(
            local = local,
            incoming = emptyList(),
            incomingPurgeTombstones = mapOf("a" to 200.0),
        )

        assertEquals(1, out.entries.size)
        assertTrue("旧删除日志应被丢弃", "a" !in out.purgeTombstones)
        assertEquals(1, stats.purgeSkipped)
    }

    @Test fun statsAreAccurate() {
        // 综合用例：1 added, 1 takeRemote, 1 takeLocal, 1 identical
        val local = VaultPayload(entries = listOf(
            Entry(id = "a", title = "A", updatedAt = 100.0),
            Entry(id = "b", title = "B", password = "old", updatedAt = 100.0),
            Entry(id = "c", title = "C", password = "samesame", updatedAt = 200.0),
            Entry(id = "d", title = "D", password = "local", updatedAt = 300.0),
        ))
        val incoming = listOf(
            Entry(id = "x", title = "X", updatedAt = 100.0),                    // 新 → added
            Entry(id = "b", title = "B", password = "new", updatedAt = 200.0),  // 较新 → takeRemote
            Entry(id = "c", title = "C", password = "samesame", updatedAt = 200.0), // 同秒同内容 → identical
            Entry(id = "d", title = "D", password = "remote", updatedAt = 100.0), // 较旧 → takeLocal
        )
        val (_, stats) = VaultOps.mergeLww(local, incoming)
        assertEquals(1, stats.added)
        assertEquals(1, stats.takeRemote)
        assertEquals(1, stats.identical)
        assertEquals(1, stats.takeLocal)
        assertEquals(0, stats.keptBoth)
        assertEquals(0, stats.conflicts)
    }
}
