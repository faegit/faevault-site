package com.vault.ui

import java.security.MessageDigest
import java.util.UUID

enum class PmvELineageRelation {
    SAME,
    FAST_FORWARD,
    REMOTE_STALE,
    DIVERGED,
    DIFFERENT,
    INVALID,
}

/**
 * Identity plus a Store-authenticated commit ancestry. Header fields, payload deviceId and
 * keyRevision are not proof of data lineage; ancestry must come from verified Commit blocks.
 */
class AuthenticatedPmvELineage(
    val vaultId: UUID,
    signingPublicKey: ByteArray,
    val keyRevision: Long,
    val sequence: Long,
    val commitId: UUID,
    val parentCommitId: UUID? = null,
    rootDigest: ByteArray,
    authenticatedAncestorCommitIds: Set<UUID>,
) {
    private val signingPublicKeyBytes = signingPublicKey.copyOf()
    private val rootDigestBytes = rootDigest.copyOf()
    val authenticatedAncestorCommitIds: Set<UUID> = authenticatedAncestorCommitIds.toSet()

    internal val structurallyValid: Boolean
        get() = keyRevision >= 0 && sequence >= 0 &&
            signingPublicKeyBytes.size == 32 && rootDigestBytes.size == 32 &&
            commitId !in authenticatedAncestorCommitIds

    internal fun sameSigningIdentity(other: AuthenticatedPmvELineage): Boolean =
        MessageDigest.isEqual(signingPublicKeyBytes, other.signingPublicKeyBytes)

    internal fun sameRootDigest(other: AuthenticatedPmvELineage): Boolean =
        MessageDigest.isEqual(rootDigestBytes, other.rootDigestBytes)
}

object PmvELineageClassifier {
    fun classify(
        local: AuthenticatedPmvELineage,
        remote: AuthenticatedPmvELineage,
    ): PmvELineageRelation {
        if (!local.structurallyValid || !remote.structurallyValid) return PmvELineageRelation.INVALID
        if (local.vaultId != remote.vaultId || !local.sameSigningIdentity(remote)) {
            return PmvELineageRelation.DIFFERENT
        }
        if (local.commitId == remote.commitId) {
            return if (local.sequence == remote.sequence && local.sameRootDigest(remote)) {
                PmvELineageRelation.SAME
            } else {
                PmvELineageRelation.INVALID
            }
        }

        val remoteContainsLocal = local.commitId == remote.parentCommitId ||
            local.commitId in remote.authenticatedAncestorCommitIds
        val localContainsRemote = remote.commitId == local.parentCommitId ||
            remote.commitId in local.authenticatedAncestorCommitIds
        if (remoteContainsLocal && localContainsRemote) return PmvELineageRelation.INVALID
        if (remoteContainsLocal) return PmvELineageRelation.FAST_FORWARD
        if (localContainsRemote) return PmvELineageRelation.REMOTE_STALE
        return PmvELineageRelation.DIVERGED
    }
}
