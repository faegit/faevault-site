package com.vault.storage

import java.util.UUID
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PmvLoginFastIndexTest {
    private val key = ByteArray(32) { it.toByte() }
    private val exactId = UUID.fromString("00000000-0000-0000-0000-000000000001")
    private val parentId = UUID.fromString("00000000-0000-0000-0000-000000000002")

    @Test
    fun normalizationFixesCaseTrailingDotWwwAndIdnRules() {
        assertEquals("xn--fsqu00a.xn--0zwm56d", PmvLoginFastIndex.normalizeDomain(" WWW.例子.测试. "))
        assertEquals("www.xn--fsqu00a.xn--0zwm56d", PmvLoginFastIndex.normalizeRpId("WWW.例子.测试."))
        assertEquals("com.example_app.login", PmvLoginFastIndex.normalizePackage(" COM.Example_App.Login "))
        assertThrows(IllegalArgumentException::class.java) { PmvLoginFastIndex.normalizeDomain("https://example.com") }
        assertThrows(IllegalArgumentException::class.java) { PmvLoginFastIndex.normalizeDomain("127.0.0.1") }
    }

    @Test
    fun tokensAreKeyedKindSeparatedAndDeterministic() {
        val first = PmvLoginFastIndex.domainToken(key, "www.Example.com.")
        val alias = PmvLoginFastIndex.domainToken(key, "example.com")
        val otherKey = PmvLoginFastIndex.domainToken(ByteArray(32) { 7 }, "example.com")
        val rpId = PmvLoginFastIndex.rpIdToken(key, "example.com")

        assertArrayEquals(first, alias)
        assertFalse(first.contentEquals(otherKey))
        assertFalse(first.contentEquals(rpId))
        assertThrows(IllegalArgumentException::class.java) {
            PmvLoginFastIndex.domainToken(ByteArray(31), "example.com")
        }
    }

    @Test
    fun fixedPageRoundTripContainsOnlyBoundedRecords() {
        val records = sortedRecords(
            record(exactId, PmvLoginFastIndex.LookupKind.DOMAIN, "login.example.com"),
            record(parentId, PmvLoginFastIndex.LookupKind.DOMAIN, "example.com"),
            PmvLoginFastIndex.Record(
                UUID.fromString("00000000-0000-0000-0000-000000000003"),
                PmvLoginFastIndex.EntryType.PASSKEY,
                PmvLoginFastIndex.State.TOMBSTONE,
                PmvLoginFastIndex.LookupKind.RP_ID,
                PmvLoginFastIndex.rpIdToken(key, "example.com"),
            ),
        )
        val encoded = PmvLoginFastIndex.encode(PmvLoginFastIndex.Page(records))
        val decoded = PmvLoginFastIndex.decode(encoded)

        assertEquals(PmvLoginFastIndex.PAGE_SIZE, encoded.size)
        assertEquals(3, decoded.records.size)
        decoded.records.zip(records).forEach { (actual, expected) ->
            assertEquals(expected.entryId, actual.entryId)
            assertEquals(expected.entryType, actual.entryType)
            assertEquals(expected.state, actual.state)
            assertEquals(expected.lookupKind, actual.lookupKind)
            assertArrayEquals(expected.lookupToken, actual.lookupToken)
        }
    }

    @Test
    fun domainQueryReturnsExactThenParentCandidatesAndDeduplicates() {
        val sharedId = UUID.fromString("00000000-0000-0000-0000-000000000004")
        val page = PmvLoginFastIndex.Page(sortedRecords(
            record(exactId, PmvLoginFastIndex.LookupKind.DOMAIN, "accounts.login.example.com"),
            record(parentId, PmvLoginFastIndex.LookupKind.DOMAIN, "example.com"),
            record(sharedId, PmvLoginFastIndex.LookupKind.DOMAIN, "accounts.login.example.com"),
            record(sharedId, PmvLoginFastIndex.LookupKind.DOMAIN, "example.com"),
        ))

        assertEquals(
            listOf(exactId, sharedId, parentId),
            PmvLoginFastIndex.queryDomain(page, key, "www.accounts.login.example.com."),
        )
    }

    @Test
    fun packageAndRpIdAreExactAndTombstonesAreNotCandidates() {
        val activePackage = PmvLoginFastIndex.Record(
            exactId,
            PmvLoginFastIndex.EntryType.LOGIN,
            PmvLoginFastIndex.State.ACTIVE,
            PmvLoginFastIndex.LookupKind.PACKAGE,
            PmvLoginFastIndex.packageToken(key, "com.example.app"),
        )
        val deletedRp = PmvLoginFastIndex.Record(
            parentId,
            PmvLoginFastIndex.EntryType.PASSKEY,
            PmvLoginFastIndex.State.TOMBSTONE,
            PmvLoginFastIndex.LookupKind.RP_ID,
            PmvLoginFastIndex.rpIdToken(key, "example.com"),
        )
        val page = PmvLoginFastIndex.Page(sortedRecords(activePackage, deletedRp))

        assertEquals(listOf(exactId), PmvLoginFastIndex.queryPackage(page, key, "COM.EXAMPLE.APP"))
        assertEquals(emptyList<UUID>(), PmvLoginFastIndex.queryPackage(page, key, "com.example"))
        assertEquals(emptyList<UUID>(), PmvLoginFastIndex.queryRpId(page, key, "example.com"))
    }

    @Test
    fun decoderRejectsNonZeroReservedBytesAndPageRejectsDuplicates() {
        val one = record(exactId, PmvLoginFastIndex.LookupKind.DOMAIN, "example.com")
        assertThrows(IllegalArgumentException::class.java) { PmvLoginFastIndex.Page(listOf(one, one)) }

        val encoded = PmvLoginFastIndex.encode(PmvLoginFastIndex.Page(listOf(one)))
        encoded[19] = 1
        assertThrows(IllegalArgumentException::class.java) { PmvLoginFastIndex.decode(encoded) }
    }

    @Test
    fun multiPagePlanUsesNonOverlappingRangesAndBinaryLookup() {
        val records = (1..300).map { value ->
            PmvLoginFastIndex.Record(
                UUID(0, value.toLong()),
                PmvLoginFastIndex.EntryType.LOGIN,
                PmvLoginFastIndex.State.ACTIVE,
                PmvLoginFastIndex.LookupKind.DOMAIN,
                ByteArray(32).also { token -> token[30] = (value ushr 8).toByte(); token[31] = value.toByte() },
            )
        }
        val plan = PmvLoginFastIndex.buildPlan(records.reversed(), 20_000, 16_528)

        assertEquals(2, plan.pages.size)
        val root = requireNotNull(plan.root)
        assertEquals(2, root.ranges.size)
        val wanted = records.last().lookupToken
        val range = PmvLoginFastIndex.locate(root, PmvLoginFastIndex.LookupKind.DOMAIN, wanted)!!
        assertEquals(20_000L + 16_528L, range.pageOffset)
        assertEquals(
            listOf(records.last().entryId),
            PmvLoginFastIndex.query(root, PmvLoginFastIndex.LookupKind.DOMAIN, wanted) { selected ->
                plan.pages[root.ranges.indexOf(selected)]
            },
        )
        assertNull(PmvLoginFastIndex.locate(root, PmvLoginFastIndex.LookupKind.PACKAGE, wanted))

        val encoded = PmvLoginFastIndex.encodeRoot(root)
        assertEquals(PmvLoginFastIndex.PAGE_SIZE, encoded.size)
        assertArrayEquals("PMLR".encodeToByteArray(), encoded.copyOfRange(0, 4))
        assertEquals(root, PmvLoginFastIndex.decodeRoot(encoded))
    }

    @Test
    fun pageAndRootLogicalDigestsIgnoreOffsetsButBindLogicalRecords() {
        val first = PmvLoginFastIndex.Page(listOf(record(exactId, PmvLoginFastIndex.LookupKind.DOMAIN, "example.com")))
        val changed = PmvLoginFastIndex.Page(listOf(record(parentId, PmvLoginFastIndex.LookupKind.DOMAIN, "example.com")))
        assertFalse(PmvLoginFastIndex.logicalDigest(first).contentEquals(PmvLoginFastIndex.logicalDigest(changed)))

        val rootA = PmvLoginFastIndex.buildRoot(first, PmvLoginFastIndex.PageLocation(20_000, 16_528))
        val rootB = PmvLoginFastIndex.buildRoot(first, PmvLoginFastIndex.PageLocation(40_000, 16_528))
        assertArrayEquals(PmvLoginFastIndex.logicalDigest(rootA), PmvLoginFastIndex.logicalDigest(rootB))
        assertFalse(PmvLoginFastIndex.logicalDigest(rootA).contentEquals(
            PmvLoginFastIndex.logicalDigest(PmvLoginFastIndex.buildRoot(changed, PmvLoginFastIndex.PageLocation(40_000, 16_528))),
        ))
    }

    @Test
    fun multipageBuilderNeverSplitsTokenGroupAndRejectsUnrepresentableOrInvalidRoots() {
        val sharedToken = ByteArray(32) { 7 }
        val oversizedGroup = (1..293).map { value ->
            PmvLoginFastIndex.Record(UUID(0, value.toLong()), PmvLoginFastIndex.EntryType.LOGIN,
                PmvLoginFastIndex.State.ACTIVE, PmvLoginFastIndex.LookupKind.DOMAIN, sharedToken)
        }
        assertThrows(IllegalArgumentException::class.java) { PmvLoginFastIndex.buildPages(oversizedGroup) }
        assertThrows(IllegalArgumentException::class.java) {
            PmvLoginFastIndex.buildPlan(oversizedGroup.take(1), Long.MAX_VALUE - 5, 16_528)
        }

        val root = PmvLoginFastIndex.buildRoot(
            PmvLoginFastIndex.Page(oversizedGroup.take(1)),
            PmvLoginFastIndex.PageLocation(20_000, 16_528),
        )
        val reserved = PmvLoginFastIndex.encodeRoot(root).also { it[34] = 1 }
        assertThrows(IllegalArgumentException::class.java) { PmvLoginFastIndex.decodeRoot(reserved) }
    }

    private fun record(id: UUID, kind: PmvLoginFastIndex.LookupKind, value: String) =
        PmvLoginFastIndex.Record(
            id,
            PmvLoginFastIndex.EntryType.LOGIN,
            PmvLoginFastIndex.State.ACTIVE,
            kind,
            when (kind) {
                PmvLoginFastIndex.LookupKind.DOMAIN -> PmvLoginFastIndex.domainToken(key, value)
                PmvLoginFastIndex.LookupKind.PACKAGE -> PmvLoginFastIndex.packageToken(key, value)
                PmvLoginFastIndex.LookupKind.RP_ID -> PmvLoginFastIndex.rpIdToken(key, value)
            },
        )

    private fun sortedRecords(vararg records: PmvLoginFastIndex.Record): List<PmvLoginFastIndex.Record> =
        records.sortedWith { left, right ->
            val leftBytes = sortKey(left)
            val rightBytes = sortKey(right)
            compareUnsigned(leftBytes, rightBytes)
        }

    private fun sortKey(record: PmvLoginFastIndex.Record): ByteArray =
        byteArrayOf(record.lookupKind.id.toByte()) + record.lookupToken +
            java.nio.ByteBuffer.allocate(16).putLong(record.entryId.mostSignificantBits)
                .putLong(record.entryId.leastSignificantBits).array()

    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        for (index in left.indices) {
            val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return 0
    }
}
