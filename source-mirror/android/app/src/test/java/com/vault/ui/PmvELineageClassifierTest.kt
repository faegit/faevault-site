package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.UUID

class PmvELineageClassifierTest {
    private val vaultId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
    private val signingKey = ByteArray(32) { (it + 1).toByte() }
    private val c1 = UUID.fromString("10000000-0000-0000-0000-000000000001")
    private val c2 = UUID.fromString("10000000-0000-0000-0000-000000000002")
    private val c3 = UUID.fromString("10000000-0000-0000-0000-000000000003")

    @Test fun `same commit requires matching sequence and root digest`() {
        val local = identity(c2, 2, root = 2)
        assertEquals(PmvELineageRelation.SAME, PmvELineageClassifier.classify(local, identity(c2, 2, root = 2)))
        assertEquals(PmvELineageRelation.INVALID, PmvELineageClassifier.classify(local, identity(c2, 2, root = 9)))
        assertEquals(PmvELineageRelation.INVALID, PmvELineageClassifier.classify(local, identity(c2, 3, root = 2)))
    }

    @Test fun `authenticated multi-hop descendant is fast forward`() {
        val local = identity(c1, 1, root = 1)
        val remote = identity(c3, 3, root = 3, ancestors = setOf(c1, c2))

        assertEquals(PmvELineageRelation.FAST_FORWARD, PmvELineageClassifier.classify(local, remote))
    }

    @Test fun `direct parent is fast forward without sequence heuristics`() {
        val local = identity(c1, 10, root = 1)
        val remote = AuthenticatedPmvELineage(
            vaultId = vaultId,
            signingPublicKey = signingKey,
            keyRevision = 0,
            sequence = 42,
            commitId = c2,
            parentCommitId = c1,
            rootDigest = ByteArray(32) { 2 },
            authenticatedAncestorCommitIds = setOf(c1),
        )

        assertEquals(PmvELineageRelation.FAST_FORWARD, PmvELineageClassifier.classify(local, remote))
    }

    @Test fun `authenticated remote ancestor is stale`() {
        val local = identity(c3, 3, root = 3, ancestors = setOf(c1, c2))
        val remote = identity(c1, 1, root = 1)

        assertEquals(PmvELineageRelation.REMOTE_STALE, PmvELineageClassifier.classify(local, remote))
    }

    @Test fun `same vault with unrelated authenticated histories is diverged`() {
        assertEquals(
            PmvELineageRelation.DIVERGED,
            PmvELineageClassifier.classify(identity(c2, 2, root = 2), identity(c3, 2, root = 3)),
        )
    }

    @Test fun `vault id or signing identity mismatch is different`() {
        assertEquals(
            PmvELineageRelation.DIFFERENT,
            PmvELineageClassifier.classify(
                identity(c1, 1, root = 1),
                identity(c1, 1, root = 1, vault = UUID.randomUUID()),
            ),
        )
        assertEquals(
            PmvELineageRelation.DIFFERENT,
            PmvELineageClassifier.classify(
                identity(c1, 1, root = 1),
                identity(c1, 1, root = 1, key = ByteArray(32) { 8 }),
            ),
        )
    }

    @Test fun `key revision never substitutes for commit lineage`() {
        val local = identity(c3, 3, root = 3, ancestors = setOf(c1, c2), keyRevision = 1)
        val olderRemoteWithNewerKeySlot = identity(c1, 1, root = 1, keyRevision = 99)

        assertEquals(
            PmvELineageRelation.REMOTE_STALE,
            PmvELineageClassifier.classify(local, olderRemoteWithNewerKeySlot),
        )
    }

    private fun identity(
        commitId: UUID,
        sequence: Long,
        root: Int,
        ancestors: Set<UUID> = emptySet(),
        vault: UUID = vaultId,
        key: ByteArray = signingKey,
        keyRevision: Long = 1,
    ) = AuthenticatedPmvELineage(
        vaultId = vault,
        signingPublicKey = key,
        keyRevision = keyRevision,
        sequence = sequence,
        commitId = commitId,
        rootDigest = ByteArray(32) { root.toByte() },
        authenticatedAncestorCommitIds = ancestors,
    )
}
