package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class VaultIdentityTest {
    @Test
    fun `identity equality authenticates byte array contents and lineage`() {
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val commitId = UUID.fromString("20000000-0000-4000-8000-000000000002")
        val first = VaultIdentity(vaultId, 7, commitId, null, 3, 4, ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val same = VaultIdentity(vaultId, 7, commitId, null, 3, 4, ByteArray(32) { 1 }, ByteArray(32) { 2 })
        val differentRoot = VaultIdentity(vaultId, 7, commitId, null, 3, 4, ByteArray(32) { 1 }, ByteArray(32) { 3 })

        assertEquals(first, same)
        assertEquals(first.hashCode(), same.hashCode())
        assertNotEquals(first, differentRoot)
        val publicKey = first.signingPublicKey
        publicKey.fill(9)
        assertTrue(first.signingPublicKey.all { it == 1.toByte() })
    }

    @Test
    fun `file classifier distinguishes authenticated ancestry and invalid same commit`() {
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val firstCommit = UUID.fromString("20000000-0000-4000-8000-000000000002")
        val secondCommit = UUID.fromString("20000000-0000-4000-8000-000000000003")
        val local = authenticated(identity(vaultId, firstCommit, 1, 1))
        val remote = authenticated(identity(vaultId, secondCommit, 2, 2), setOf(firstCommit))

        assertEquals(VaultFileRelationship.REMOTE_DESCENDANT, classifyAuthenticatedVaultFiles(local, remote))
        assertEquals(VaultFileRelationship.LOCAL_DESCENDANT, classifyAuthenticatedVaultFiles(remote, local))
        assertEquals(
            VaultFileRelationship.INVALID,
            classifyAuthenticatedVaultFiles(local, authenticated(identity(vaultId, firstCommit, 2, 9))),
        )
    }

    @Test
    fun `repository install policy permits only same or authenticated fast forward`() {
        requireInstallableVaultRelationship(VaultFileRelationship.SAME)
        requireInstallableVaultRelationship(VaultFileRelationship.REMOTE_DESCENDANT)

        listOf(
            VaultFileRelationship.LOCAL_DESCENDANT,
            VaultFileRelationship.DIVERGED,
            VaultFileRelationship.DIFFERENT_VAULT,
            VaultFileRelationship.INVALID,
        ).forEach { relationship ->
            assertThrows(IllegalArgumentException::class.java) {
                requireInstallableVaultRelationship(relationship)
            }
        }
    }

    @Test
    fun `file classifier rejects a commit that appears in its own authenticated ancestry`() {
        // 防环/防自指：commitId 落在自己的已认证祖先集合里，说明谱系被构造过。
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val commitId = UUID.fromString("20000000-0000-4000-8000-000000000002")
        val selfReferencing = authenticated(identity(vaultId, commitId, 2, 5), setOf(commitId))
        val other = authenticated(identity(vaultId, UUID.randomUUID(), 3, 6))

        // 弱分类器只比对双方祖先集合，会把它判成 DIVERGED（进而允许合并安装）。
        assertEquals(VaultFileRelationship.INVALID, classifyAuthenticatedVaultFiles(selfReferencing, other))
        assertEquals(VaultFileRelationship.INVALID, classifyAuthenticatedVaultFiles(other, selfReferencing))
    }

    @Test
    fun `file classifier rejects two commits that each contain the other`() {
        // 双向包含意味着谱系成环，任何一侧都不得被当作可信后代。
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val firstCommit = UUID.fromString("20000000-0000-4000-8000-00000000000a")
        val secondCommit = UUID.fromString("20000000-0000-4000-8000-00000000000b")
        val local = authenticated(identity(vaultId, firstCommit, 1, 1), setOf(secondCommit))
        val remote = authenticated(identity(vaultId, secondCommit, 2, 2), setOf(firstCommit))

        assertEquals(VaultFileRelationship.INVALID, classifyAuthenticatedVaultFiles(local, remote))
        assertEquals(VaultFileRelationship.INVALID, classifyAuthenticatedVaultFiles(remote, local))
    }

    @Test
    fun `file classifier honours parent commit link that is absent from the ancestry set`() {
        // parentCommitId 也是已认证谱系的一部分：远端自述 parent 即本地 HEAD，
        // 即使该 commit 尚未出现在本地祖先集合里，也应判定为快进而非分叉。
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val firstCommit = UUID.fromString("20000000-0000-4000-8000-00000000000a")
        val secondCommit = UUID.fromString("20000000-0000-4000-8000-00000000000b")
        val local = authenticated(identity(vaultId, firstCommit, 1, 1))
        val remote = authenticated(
            VaultIdentity(
                vaultId, 2, secondCommit, firstCommit, 1, 1,
                ByteArray(32) { 1 }, ByteArray(32) { 2 },
            ),
        )

        assertEquals(VaultFileRelationship.REMOTE_DESCENDANT, classifyAuthenticatedVaultFiles(local, remote))
    }

    @Test
    fun `file classifier rejects negative sequence`() {
        // 结构合法性：sequence / keyRevision 为负说明身份字段被破坏，不得参与谱系判定。
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val firstCommit = UUID.fromString("20000000-0000-4000-8000-00000000000a")
        val secondCommit = UUID.fromString("20000000-0000-4000-8000-00000000000b")
        val local = authenticated(identity(vaultId, firstCommit, -1, 1))
        val remote = authenticated(identity(vaultId, secondCommit, 2, 2), setOf(firstCommit))

        assertEquals(VaultFileRelationship.INVALID, classifyAuthenticatedVaultFiles(local, remote))
    }

    @Test
    fun `key revision zero remains a valid lineage input`() {
        // key_revision 的合法下界是 0（Entry 默认值），谱系不得把它误判为非法。
        val vaultId = UUID.fromString("10000000-0000-4000-8000-000000000001")
        val firstCommit = UUID.fromString("20000000-0000-4000-8000-00000000000a")
        val secondCommit = UUID.fromString("20000000-0000-4000-8000-00000000000b")
        fun zeroKeyRevision(commitId: UUID, sequence: Long) = VaultIdentity(
            vaultId, sequence, commitId, null, 0, 1,
            ByteArray(32) { 1 }, ByteArray(32) { sequence.toByte() },
        )
        val local = authenticated(zeroKeyRevision(firstCommit, 1))
        val remote = authenticated(zeroKeyRevision(secondCommit, 2), setOf(firstCommit))

        assertEquals(VaultFileRelationship.REMOTE_DESCENDANT, classifyAuthenticatedVaultFiles(local, remote))
    }

    private fun authenticated(identity: VaultIdentity, ancestors: Set<UUID> = emptySet()) =
        AuthenticatedVaultFile(java.io.File("identity-test.pmv"), VaultFileFormat.PMVE, identity, ancestors)

    private fun identity(vaultId: UUID, commitId: UUID, sequence: Long, rootByte: Int) = VaultIdentity(
        vaultId,
        sequence,
        commitId,
        null,
        1,
        1,
        ByteArray(32) { 1 },
        ByteArray(32) { rootByte.toByte() },
    )
}
