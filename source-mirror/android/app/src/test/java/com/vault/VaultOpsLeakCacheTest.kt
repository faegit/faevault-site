package com.vault

import com.vault.model.Entry
import com.vault.model.SecretType
import com.vault.model.VaultOps
import com.vault.model.VaultPayload
import com.vault.model.hasCurrentLeakCache
import com.vault.model.needsLeakCheck
import com.vault.model.withLeakCheckResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultOpsLeakCacheTest {

    @Test
    fun duplicateScanNeverGroupsLoginAndPasskey() {
        val login = entry(id = "login")
        val passkey = login.copy(id = "passkey", secretType = SecretType.PASSKEY)
        val payload = VaultPayload(entries = listOf(login, passkey))

        assertTrue(VaultOps.duplicateGroups(payload).isEmpty())
        val (unchanged, stats) = VaultOps.dedupEntries(payload)
        assertEquals(2, unchanged.entries.size)
        assertEquals(0, stats.exactMerged)
    }

    @Test
    fun duplicateMaintenanceOnlyScansAndMergesLoginEntries() {
        val loginPair = listOf(
            entry(id = "login-a"),
            entry(id = "login-b", updatedAt = 1100.0),
        )
        val nonLoginPairs = SecretType.ALL
            .filterNot { it == SecretType.LOGIN }
            .flatMapIndexed { index, type ->
                listOf(
                    entry(id = "$type-a").copy(secretType = type, title = "Same $index"),
                    entry(id = "$type-b").copy(secretType = type, title = "Same $index"),
                )
            }
        val payload = VaultPayload(entries = loginPair + nonLoginPairs)

        assertEquals(VaultOps.DedupScan(exact = 1, pwConflict = 0), VaultOps.scanDuplicates(payload))
        assertEquals(listOf(loginPair.map(Entry::id).toSet()), VaultOps.duplicateGroups(payload).map { group -> group.map(Entry::id).toSet() })

        val (deduplicated, stats) = VaultOps.dedupEntries(payload)

        assertEquals(1, stats.exactMerged)
        assertEquals(1, deduplicated.entries.count { it.secretType == SecretType.LOGIN })
        SecretType.ALL.filterNot { it == SecretType.LOGIN }.forEach { type ->
            assertEquals(2, deduplicated.entries.count { it.secretType == type })
        }
    }

    private fun entry(
        id: String = "a",
        password: String = "pw",
        updatedAt: Double = 1000.0,
    ): Entry = Entry(
        id = id,
        title = "Title",
        username = "user",
        password = password,
        createdAt = 900.0,
        updatedAt = updatedAt,
    )

    @Test
    fun unchangedEditReturnsOriginalPayloadAndPreservesRevision() {
        val existing = entry()
        val payload = VaultPayload(entries = listOf(existing))

        val result = VaultOps.update(payload, existing.copy(updatedAt = 9999.0))

        assertSame(payload, result)
        assertEquals(1000.0, result.entries.single().updatedAt, 0.001)
    }

    @Test
    fun addAlignsFreshLeakResultToFinalRevision() {
        val incoming = entry(updatedAt = 0.0).copy(
            leakPwnedCount = 5,
            leakCommonWeak = true,
        )

        val saved = VaultOps.add(VaultPayload(), incoming).entries.single()

        assertTrue(saved.hasCurrentLeakCache())
        assertEquals(saved.updatedAt, saved.leakCheckRevision!!, 0.001)
        assertEquals(5, saved.leakPwnedCount)
        assertTrue(saved.leakCommonWeak)
        assertTrue(saved.leakCheckedAt != null)
    }

    @Test
    fun updatePreservesLeakCacheWhenSecretIsUnchanged() {
        val existing = entry().copy(
            leakCheckRevision = 1000.0,
            leakPwnedCount = 2,
            leakCommonWeak = true,
            leakCheckedAt = 1001.0,
        )
        val updated = existing.copy(title = "Renamed")

        val saved = VaultOps.update(VaultPayload(entries = listOf(existing)), updated).entries.single()

        assertTrue(saved.updatedAt > existing.updatedAt)
        assertTrue(saved.hasCurrentLeakCache())
        assertEquals(saved.updatedAt, saved.leakCheckRevision!!, 0.001)
        assertEquals(2, saved.leakPwnedCount)
    }

    @Test
    fun updateClearsStaleLeakCacheWhenSecretChangesWithoutFreshResult() {
        val existing = entry().copy(
            leakCheckRevision = 1000.0,
            leakPwnedCount = 2,
            leakCommonWeak = true,
            leakCheckedAt = 1001.0,
        )
        val updated = existing.copy(password = "new-password")

        val saved = VaultOps.update(VaultPayload(entries = listOf(existing)), updated).entries.single()

        assertFalse(saved.hasCurrentLeakCache())
        assertEquals(null, saved.leakCheckRevision)
        assertEquals(null, saved.leakPwnedCount)
        assertFalse(saved.leakCommonWeak)
        assertEquals(null, saved.leakCheckedAt)
    }

    @Test
    fun updateAlignsFreshLeakResultWhenSecretChanges() {
        val existing = entry().copy(
            leakCheckRevision = 1000.0,
            leakPwnedCount = 2,
            leakCommonWeak = true,
            leakCheckedAt = 1001.0,
        )
        val updated = existing.copy(
            password = "new-password",
            leakCheckRevision = null,
            leakPwnedCount = 9,
            leakCommonWeak = true,
            leakCheckedAt = null,
        )

        val saved = VaultOps.update(VaultPayload(entries = listOf(existing)), updated).entries.single()

        assertTrue(saved.hasCurrentLeakCache())
        assertEquals(saved.updatedAt, saved.leakCheckRevision!!, 0.001)
        assertEquals(9, saved.leakPwnedCount)
        assertTrue(saved.leakCommonWeak)
        assertTrue(saved.leakCheckedAt != null)
    }

    @Test
    fun needsLeakCheckTreatsZeroDaysAsAutomaticCheckDisabled() {
        val unchecked = entry()

        assertFalse(unchecked.needsLeakCheck(recheckDays = 0, force = false, now = 2000.0))
        assertTrue(unchecked.needsLeakCheck(recheckDays = 0, force = true, now = 2000.0))
    }

    @Test
    fun needsLeakCheckRechecksExpiredCurrentCache() {
        val checked = entry(updatedAt = 1000.0).copy(
            leakCheckRevision = 1000.0,
            leakPwnedCount = 0,
            leakCommonWeak = false,
            leakCheckedAt = 1000.0,
        )

        assertFalse(checked.needsLeakCheck(recheckDays = 5, now = 1000.0 + 4 * 86400.0))
        assertTrue(checked.needsLeakCheck(recheckDays = 5, now = 1000.0 + 6 * 86400.0))
    }

    @Test
    fun withLeakCheckResultWritesSafeResultCache() {
        val checked = entry().withLeakCheckResult(
            commonWeak = false,
            pwnedCount = 0,
            checkedAt = 1200.0,
        )

        assertTrue(checked.hasCurrentLeakCache())
        assertEquals(0, checked.leakPwnedCount)
        assertFalse(checked.leakCommonWeak)
        assertEquals(1200.0, checked.leakCheckedAt!!, 0.001)
    }

    @Test
    fun mergeImportsLeakCacheForIdenticalLoginEntry() {
        val existing = entry(id = "local")
        val incoming = entry(id = "incoming").copy(
            leakPwnedCount = 42,
            leakCommonWeak = true,
            leakCheckedAt = 1300.0,
        )

        val (payload, stats) = VaultOps.merge(
            VaultPayload(entries = listOf(existing)),
            listOf(incoming),
        ) { _, _ -> VaultOps.MergeAction.SKIP }
        val merged = payload.entries.single()

        assertEquals(0, stats.identical)
        assertEquals(1, stats.overwritten)
        assertEquals(existing.id, merged.id)
        assertEquals(42, merged.leakPwnedCount)
        assertTrue(merged.leakCommonWeak)
        assertEquals(1300.0, merged.leakCheckedAt!!, 0.001)
        assertTrue(merged.hasCurrentLeakCache())
    }

    @Test
    fun mergeLwwImportsLeakCacheForIdenticalBackupEntry() {
        val existing = entry(id = "same", updatedAt = 1000.0)
        val incoming = existing.copy(
            leakPwnedCount = 42,
            leakCommonWeak = true,
            leakCheckedAt = 1300.0,
        )

        val (payload, stats) = VaultOps.mergeLww(
            VaultPayload(entries = listOf(existing)),
            listOf(incoming),
        )
        val merged = payload.entries.single()

        assertEquals(0, stats.identical)
        assertEquals(1, stats.takeRemote)
        assertEquals(existing.id, merged.id)
        assertEquals(42, merged.leakPwnedCount)
        assertTrue(merged.leakCommonWeak)
        assertEquals(1300.0, merged.leakCheckedAt!!, 0.001)
        assertTrue(merged.hasCurrentLeakCache())
    }
}
