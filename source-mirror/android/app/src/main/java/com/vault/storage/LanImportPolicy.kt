package com.vault.storage

import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

enum class LanImportConflictKind {
    SAME_VAULT,
    SAME_NAME_DIFFERENT_VAULT,
}

data class LanImportNameResolution(
    val targetName: String,
    val conflictKind: LanImportConflictKind? = null,
    val conflictingName: String? = null,
)

data class LanImportPublicIdentity(
    val vaultId: UUID,
    val signingPublicKey: ByteArray,
) {
    fun matches(other: LanImportPublicIdentity): Boolean =
        vaultId == other.vaultId && MessageDigest.isEqual(signingPublicKey, other.signingPublicKey)
}

/** Pure import decisions shared by the LAN protocol and the account-registration flow. */
object LanImportPolicy {
    const val ENCODED_NAME_HEADER = "X-Vault-Name-B64"

    fun encodeAccountName(value: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8))

    fun decodeAccountName(encoded: String?, legacy: String?): String? {
        val decoded = encoded?.takeIf { it.length <= 256 }?.let { value ->
            runCatching {
                String(Base64.getUrlDecoder().decode(value), Charsets.UTF_8)
            }.getOrNull()
        }
        return decoded?.takeIf(String::isNotBlank) ?: legacy?.trim()?.takeIf(String::isNotBlank)
    }

    fun resolveName(
        sourceName: String?,
        existingNames: Set<String>,
        trashedNames: Set<String>,
        sameVaultExistingName: String?,
    ): LanImportNameResolution {
        val occupied = existingNames + trashedNames
        val preferred = sourceName?.trim()?.take(40).orEmpty().takeIf(::isValidAccountName)
            ?: if (existingNames.isEmpty()) "默认" else "账户${existingNames.size + 1}"
        val target = uniqueName(preferred, occupied)
        return when {
            sameVaultExistingName != null -> LanImportNameResolution(
                target,
                LanImportConflictKind.SAME_VAULT,
                sameVaultExistingName,
            )
            preferred in occupied -> LanImportNameResolution(
                target,
                LanImportConflictKind.SAME_NAME_DIFFERENT_VAULT,
                preferred,
            )
            else -> LanImportNameResolution(target)
        }
    }

    fun readPublicIdentity(file: File): LanImportPublicIdentity? {
        if (!file.isFile || file.length() < PmvContainerFormat.DATA_START) return null
        return runCatching {
            RandomAccessFile(file, "r").use { input ->
                listOf(
                    PmvContainerFormat.VAULT_HEADER_PRIMARY_OFFSET,
                    PmvContainerFormat.VAULT_HEADER_SECONDARY_OFFSET,
                ).mapNotNull { offset ->
                    runCatching {
                        val raw = ByteArray(PmvVaultHeaderCodec.HEADER_SIZE)
                        input.seek(offset)
                        input.readFully(raw)
                        PmvVaultHeaderCodec.decode(raw)
                    }.getOrNull()
                }.maxByOrNull { it.headerRevision }
            }
        }.getOrNull()?.let { header ->
            LanImportPublicIdentity(header.vaultId, header.signingPublicKey.copyOf())
        }
    }

    private fun uniqueName(base: String, occupied: Set<String>): String {
        if (base !in occupied) return base
        var index = 2
        while ("$base$index" in occupied) index++
        return "$base$index"
    }

    private fun isValidAccountName(value: String): Boolean =
        value.isNotEmpty() && value.length <= 40 &&
            value.all { it.isLetterOrDigit() || it == '_' || it == '-' || it in '一'..'鿿' }
}
