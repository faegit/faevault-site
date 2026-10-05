package com.vault.autofill

import android.content.Intent
import android.view.autofill.AutofillId
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Process-independent representation of an Autofill save request.
 *
 * Android may kill the provider process while its system save confirmation is visible. The
 * immutable PendingIntent is retained by the system, so carrying this envelope in that intent
 * lets the save Activity recover without relying on [AutofillRequestStore].
 */
@Serializable
data class SaveRequestEnvelope(
    val packageName: String,
    val originKind: String,
    val originValue: String,
    val originCertificates: List<String> = emptyList(),
    val browserPackageName: String = "",
    val username: String? = null,
    val password: String? = null,
    val newPassword: String? = null,
    val confirmationPassword: String? = null,
) {
    fun toRequest(): PendingAutofillRequest.Save {
        val origin = when (originKind) {
            ORIGIN_ANDROID -> TargetOrigin.AndroidPackage(
                packageName = originValue,
                signingCertificateSha256 = originCertificates.toSet(),
            )
            ORIGIN_WEB -> TargetOrigin.Web(
                host = originValue,
                browserPackageName = browserPackageName,
                browserSigningCertificateSha256 = originCertificates.toSet(),
            )
            else -> error("Unsupported save-request origin")
        }
        val form = ParsedForm<AutofillId>(
            origin = origin,
            fields = emptyList(),
            packageName = packageName,
        )
        return PendingAutofillRequest.Save(
            form = form,
            candidate = SaveCandidate(username, password, newPassword, confirmationPassword),
        )
    }

    companion object {
        private const val ORIGIN_ANDROID = "android"
        private const val ORIGIN_WEB = "web"
        private val json = Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
            explicitNulls = true
        }

        fun from(request: PendingAutofillRequest.Save): SaveRequestEnvelope {
            val origin = request.form.origin
            return when (origin) {
                is TargetOrigin.AndroidPackage -> SaveRequestEnvelope(
                    packageName = request.form.packageName,
                    originKind = ORIGIN_ANDROID,
                    originValue = origin.packageName,
                    originCertificates = origin.signingCertificateSha256.sorted(),
                    username = request.candidate.username,
                    password = request.candidate.password,
                    newPassword = request.candidate.newPassword,
                    confirmationPassword = request.candidate.confirmationPassword,
                )
                is TargetOrigin.Web -> SaveRequestEnvelope(
                    packageName = request.form.packageName,
                    originKind = ORIGIN_WEB,
                    originValue = origin.host,
                    originCertificates = origin.browserSigningCertificateSha256.sorted(),
                    browserPackageName = origin.browserPackageName,
                    username = request.candidate.username,
                    password = request.candidate.password,
                    newPassword = request.candidate.newPassword,
                    confirmationPassword = request.candidate.confirmationPassword,
                )
            }
        }

        fun encode(request: PendingAutofillRequest.Save): String = json.encodeToString(from(request))

        fun decode(encoded: String): PendingAutofillRequest.Save? = runCatching {
            json.decodeFromString<SaveRequestEnvelope>(encoded).toRequest()
        }.getOrNull()
    }
}

object SaveRequestIntentTransport {
    private const val EXTRA_SAVE_REQUEST = "com.vault.autofill.SAVE_REQUEST_V1"

    fun attach(intent: Intent, request: PendingAutofillRequest.Save): Intent = intent.putExtra(
        EXTRA_SAVE_REQUEST,
        SaveRequestEnvelope.encode(request),
    )

    fun read(intent: Intent): PendingAutofillRequest.Save? {
        val encoded = intent.getStringExtra(EXTRA_SAVE_REQUEST) ?: return null
        return SaveRequestEnvelope.decode(encoded)
    }

    fun clear(intent: Intent) {
        intent.removeExtra(EXTRA_SAVE_REQUEST)
    }
}
