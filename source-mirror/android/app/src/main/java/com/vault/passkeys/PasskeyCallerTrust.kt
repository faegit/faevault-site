package com.vault.passkeys

import android.content.Context
import androidx.credentials.provider.CallingAppInfo
import java.security.MessageDigest
import java.util.Base64

data class TrustedPasskeyCaller(
    val origin: String,
    val privilegedBrowser: Boolean,
) {
    override fun toString(): String = "TrustedPasskeyCaller(origin=<redacted>)"
}

class PasskeyCallerTrust(
    context: Context,
    private val allowlist: PrivilegedAppAllowlistStore =
        PrivilegedAppAllowlistStore(context.applicationContext),
    private val assetLinks: DigitalAssetLinksVerifier =
        DigitalAssetLinksVerifier(context.applicationContext),
) {
    suspend fun authorize(
        callingAppInfo: CallingAppInfo,
        rpId: String,
        clientDataHash: ByteArray?,
    ): TrustedPasskeyCaller {
        if (callingAppInfo.isOriginPopulated()) {
            require(clientDataHash?.size == 32)
            val origin = callingAppInfo.getOrigin(allowlist.current())
                ?: throw SecurityException("untrusted privileged caller")
            return TrustedPasskeyCaller(origin, privilegedBrowser = true)
        }

        require(clientDataHash == null)
        val signingInfo = callingAppInfo.signingInfo
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.P) {
            // 凭据提供方/PackageInfo#getSigningInfo 自 API 28 起可用
            throw SecurityException("passkey caller verification requires Android 9+")
        }
        require(!signingInfo.hasMultipleSigners())
        val signerCertificates = signingInfo.apkContentsSigners
            .map { it.toByteArray() }
        require(signerCertificates.size == 1)
        return authorizeNativePasskeyCaller(
            rpId = rpId,
            packageName = callingAppInfo.packageName,
            signerCertificates = signerCertificates,
        ) { relyingPartyId, packageName, fingerprints ->
            assetLinks.isAuthorized(relyingPartyId, packageName, fingerprints)
        }
    }
}

internal suspend fun authorizeNativePasskeyCaller(
    rpId: String,
    packageName: String,
    signerCertificates: List<ByteArray>,
    isRpAuthorized: suspend (String, String, Set<String>) -> Boolean,
): TrustedPasskeyCaller {
    val signer = signerCertificates.singleOrNull()
        ?: throw SecurityException("unsupported app signing configuration")
    val digest = MessageDigest.getInstance("SHA-256").digest(signer)
    if (rpId.isNotEmpty()) {
        val fingerprint = digest.joinToString(":") { "%02X".format(it.toInt() and 0xff) }
        if (!isRpAuthorized(rpId, packageName, setOf(fingerprint))) {
            throw SecurityException("native app is not associated with relying party")
        }
    }
    return TrustedPasskeyCaller(
        origin = "android:apk-key-hash:" +
            Base64.getUrlEncoder().withoutPadding().encodeToString(digest),
        privilegedBrowser = false,
    )
}
