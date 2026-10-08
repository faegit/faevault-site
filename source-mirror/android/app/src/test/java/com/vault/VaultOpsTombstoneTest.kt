package com.vault

import com.vault.model.Entry
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Step 3 删除语义：删除 / 恢复 / 物理清理 全在 entries 上以 deletedAt 标记完成。 */
class VaultOpsTombstoneTest {

    @Test
    fun expiredTrashKeepsOldDeletionRecordsAndBlocksStaleReimport() {
        val oldId = "11111111-1111-4111-8111-111111111111"
        val expiredId = "22222222-2222-4222-8222-222222222222"
        val payload = VaultPayload(
            entries = listOf(entry(expiredId).copy(deletedAt = 1.0, updatedAt = 1.0)),
            purgeTombstones = mapOf(oldId to 2.0),
        )
        val purged = VaultOps.purgeExpired(payload, 30)
        assertEquals(2.0, purged.purgeTombstones.getValue(oldId), 0.0)
        assertTrue(purged.purgeTombstones.containsKey(expiredId))
        val stale = VaultPayload(entries = listOf(entry(oldId).copy(updatedAt = 1.0), entry(expiredId)))
        val merged = VaultOps.mergeLww(purged, stale.entries).first
        assertTrue(merged.entries.isEmpty())
        assertEquals(purged.purgeTombstones, merged.purgeTombstones)
    }

    private fun entry(id: String, title: String = "T-$id"): Entry =
        Entry(id = id, title = title, createdAt = 1000.0, updatedAt = 1000.0)

    @Test
    fun deleteMarksTombstoneAndKeepsInEntries() {
        val p = VaultPayload(entries = listOf(entry("a"), entry("b")))
        val after = VaultOps.delete(p, "a")

        assertEquals(2, after.entries.size)
        val a = after.entries.first { it.id == "a" }
        assertNotNull("deletedAt 应被设置", a.deletedAt)
        assertTrue("删除应刷新更新时间", a.updatedAt > 1000.0)

        // 公共 helper
        assertEquals(1, VaultOps.alive(after).size)
        assertEquals(1, VaultOps.trashed(after).size)
        assertEquals("a", VaultOps.trashed(after)[0].id)
    }

    @Test
    fun deleteIdempotentOnAlreadyDeleted() {
        val p = VaultPayload(entries = listOf(entry("a").copy(deletedAt = 500.0, updatedAt = 500.0)))
        val after = VaultOps.delete(p, "a")
        // deletedAt 不应被覆盖
        assertEquals(500.0, after.entries[0].deletedAt!!, 0.001)
    }

    @Test
    fun restoreClearsTombstoneAndUpdatesUpdatedAt() {
        val p = VaultPayload(entries = listOf(entry("a").copy(deletedAt = 500.0, updatedAt = 500.0)))
        val after = VaultOps.restore(p, "a")
        val a = after.entries[0]
        assertNull(a.deletedAt)
        assertTrue("恢复应刷新更新时间", a.updatedAt > 500.0)
    }

    @Test
    fun restoreManyClearsSelectedTombstonesAndUpdatesUpdatedAt() {
        val p = VaultPayload(
            entries = listOf(
                entry("a").copy(deletedAt = 500.0, updatedAt = 111.0),
                entry("b").copy(deletedAt = 600.0, updatedAt = 222.0),
                entry("c").copy(deletedAt = 700.0, updatedAt = 333.0),
            )
        )
        val after = VaultOps.restoreMany(p, setOf("a", "c"))
        val byId = after.entries.associateBy { it.id }

        assertNull(byId["a"]!!.deletedAt)
        assertTrue(byId["a"]!!.updatedAt > 111.0)
        assertEquals(600.0, byId["b"]!!.deletedAt!!, 0.001)
        assertEquals(222.0, byId["b"]!!.updatedAt, 0.001)
        assertNull(byId["c"]!!.deletedAt)
        assertTrue(byId["c"]!!.updatedAt > 333.0)
    }

    @Test
    fun purgeOnlyRemovesTombstones() {
        val p = VaultPayload(
            entries = listOf(
                entry("alive"),
                entry("dead").copy(deletedAt = 500.0),
            )
        )
        // purge 一个活跃条目不应起作用（安全护栏）
        assertEquals(2, VaultOps.purge(p, "alive").entries.size)
        // purge 一个墓碑条目应物理删除
        val after = VaultOps.purge(p, "dead")
        assertEquals(1, after.entries.size)
        assertEquals("alive", after.entries[0].id)
        assertTrue(after.purgeTombstones.containsKey("dead"))
    }

    @Test
    fun purgeAllRemovesOnlyTombstones() {
        val p = VaultPayload(
            entries = listOf(
                entry("a"),
                entry("b").copy(deletedAt = 500.0),
                entry("c"),
                entry("d").copy(deletedAt = 600.0),
            )
        )
        val after = VaultOps.purgeAll(p)
        assertEquals(2, after.entries.size)
        assertEquals(setOf("a", "c"), after.entries.map { it.id }.toSet())
        assertEquals(setOf("b", "d"), after.purgeTombstones.keys)
    }

    @Test
    fun purgeManyRemovesOnlySelectedTombstones() {
        val p = VaultPayload(
            entries = listOf(
                entry("alive"),
                entry("dead1").copy(deletedAt = 500.0),
                entry("dead2").copy(deletedAt = 600.0),
                entry("dead3").copy(deletedAt = 700.0),
            )
        )
        val after = VaultOps.purgeMany(p, setOf("alive", "dead1", "dead3"))

        assertEquals(setOf("alive", "dead2"), after.entries.map { it.id }.toSet())
        assertEquals(setOf("dead1", "dead3"), after.purgeTombstones.keys)
    }

    @Test
    fun purgeExpiredFiltersByCutoff() {
        val now = System.currentTimeMillis() / 1000.0
        val day = 86400.0
        val p = VaultPayload(
            entries = listOf(
                entry("a"),                                                       // 活跃
                entry("b").copy(deletedAt = now - 10 * day),                      // 10 天前删除
                entry("c").copy(deletedAt = now - 100 * day),                     // 100 天前删除
            )
        )
        val after = VaultOps.purgeExpired(p, retentionDays = 30)
        assertEquals(2, after.entries.size)
        assertEquals(setOf("a", "b"), after.entries.map { it.id }.toSet())
        assertTrue(after.purgeTombstones.containsKey("c"))
    }

    @Test
    fun localMutationsStayNewerThanFutureImportedTimestamp() {
        val future = System.currentTimeMillis() / 1000.0 + 86_400.0
        val imported = entry("future").copy(updatedAt = future)

        val edited = VaultOps.update(
            VaultPayload(entries = listOf(imported)),
            imported.copy(title = "Android edit"),
        ).entries.single()
        assertTrue("编辑时间不得倒退", edited.updatedAt > future)

        val deleted = VaultOps.delete(VaultPayload(entries = listOf(imported)), imported.id).entries.single()
        assertTrue("删除时间不得倒退", deleted.updatedAt > future)
        assertEquals(deleted.updatedAt, deleted.deletedAt!!, 0.0001)

        val restored = VaultOps.restore(VaultPayload(entries = listOf(deleted)), deleted.id).entries.single()
        assertTrue("恢复时间必须晚于删除时间", restored.updatedAt > deleted.updatedAt)

        val purged = VaultOps.purge(VaultPayload(entries = listOf(deleted)), deleted.id)
        assertTrue("删除日志必须晚于被删除条目", purged.purgeTombstones.getValue(deleted.id) > deleted.updatedAt)
    }
}
