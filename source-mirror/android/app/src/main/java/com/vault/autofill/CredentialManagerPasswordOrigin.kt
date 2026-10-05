package com.vault.autofill

import java.util.Locale

/** Builds a password origin only after the installed application's signing identity is available. */
fun credentialManagerPasswordOrigin(
    packageName: String,
    signingCertificateSha256: Set<String>,
): TargetOrigin.AndroidPackage? {
    val certificates = signingCertificateSha256.asSequence()
        .map { it.trim().lowercase(Locale.ROOT) }
        .filter { it.matches(Regex("^[0-9a-f]{64}$")) }
        .toCollection(linkedSetOf())
    if (certificates.isEmpty()) return null
    return TargetOrigin.AndroidPackage(packageName.trim(), certificates)
}
