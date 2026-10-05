package com.vault.passkeys

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import android.util.Log
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePasswordCredentialRequest
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.annotation.RequiresApi
import com.vault.ui.localizeUiTextFor
import java.util.UUID

@RequiresApi(34)
class FAEVaultCredentialProviderService : CredentialProviderService() {
    override fun onCreate() {
        super.onCreate()
        // 进程死亡恢复：令牌快照加载（幂等）
        PasskeyRequestTokens.install(this)
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        Log.d("VaultCP", "onBeginGetCredentialRequest: options=${request.beginGetCredentialOptions.map { it::class.simpleName }}")
        if (cancellationSignal.isCanceled) return
        val hasPasskey = request.beginGetCredentialOptions.any { it is BeginGetPublicKeyCredentialOption }
        val hasPassword = request.beginGetCredentialOptions.any { it is BeginGetPasswordOption }
        if (!hasPasskey && !hasPassword) {
            callback.onError(GetCredentialUnknownException())
            return
        }
        val builder = BeginGetCredentialResponse.Builder()

        // HyperOS/Chrome's immediately-available flow closes the selector when a provider only
        // returns an AuthenticationAction. Publish one provider-level passkey entry per request
        // option so selecting Vault can launch our own unlock activity. The encrypted vault is
        // opened there; exact matching credentials are chosen only after Vault authentication.
        request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>().forEach { option ->
            val parsed = runCatching { PasskeyRequests.parseGet(option.requestJson) }.getOrNull()
                ?: return@forEach
            val requestToken = PasskeyRequestTokens.create()
            val requestCode = requestToken.hashCode()
            val directPending = pendingIntent(
                activityIntent(PasskeyCredentialActivity.MODE_GET_DISCOVERABLE, requestCode)
                    .setAction("app.fae.vault.passkey.discoverable.${option.id}.$requestToken")
                    .putExtra(PasskeyCredentialActivity.EXTRA_REQUEST_TOKEN, requestToken)
                    .putExtra(
                        PasskeyCredentialActivity.EXTRA_REQUEST_DIGEST,
                        requestFingerprint(option.requestJson),
                    ),
                requestCode,
            )
            val directPasskeyEntry = PublicKeyCredentialEntry.Builder(
                this,
                localizeUiTextFor(this, "保险库"),
                directPending,
                option,
            ).setDisplayName(parsed.rpId).build()
            builder.addCredentialEntry(directPasskeyEntry)
        }

        val token = PasskeyRequestStore.put(request)
        val pending = activityIntent(PasskeyCredentialActivity.MODE_QUERY, token.hashCode())
            .setAction("app.fae.vault.passkey.query.$token")
            .putExtra(PasskeyCredentialActivity.EXTRA_TOKEN, token)
        val action = AuthenticationAction.Builder(
            localizeUiTextFor(this, "解锁保险库"),
            pendingIntent(pending, token.hashCode()),
        ).build()
        builder.addAuthenticationAction(action)
        callback.onResult(builder.build())
    }

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        Log.d("VaultCP", "onBeginCreateCredentialRequest: ${request.type}")
        if (cancellationSignal.isCanceled) return
        when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                // HyperOS gives remote providers a very short response window. Parsing and
                // validating the WebAuthn request belongs in the selected activity, where the
                // full ProviderCreateCredentialRequest is available and already validated.
                val token = PasskeyRequestTokens.create()
                val requestCode = token.hashCode()
                // 请求摘要绑定：令牌只对"这一份 requestJson"有效，即使被错误复用也无法处理其他请求
                val requestDigest = requestFingerprint(request.requestJson)
                val pending = pendingIntent(
                    activityIntent(PasskeyCredentialActivity.MODE_CREATE, requestCode)
                        .setAction("app.fae.vault.passkey.create.$token")
                        .putExtra(PasskeyCredentialActivity.EXTRA_REQUEST_TOKEN, token)
                        .putExtra(PasskeyCredentialActivity.EXTRA_REQUEST_DIGEST, requestDigest),
                    requestCode,
                )
                val entry = CreateEntry.Builder(localizeUiTextFor(this, "保存到保险库"), pending)
                    .setDescription(localizeUiTextFor(this, "创建并加密保存 Passkey"))
                    .setAutoSelectAllowed(true)
                    .build()
                Log.d("VaultCP", "returning passkey create entry")
                callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
                Log.d("VaultCP", "passkey create entry returned")
            }
            is BeginCreatePasswordCredentialRequest -> {
                val requestId = UUID.randomUUID().toString()
                val requestCode = requestId.hashCode()
                val pending = pendingIntent(
                    activityIntent(PasskeyCredentialActivity.MODE_CREATE_PASSWORD, requestCode)
                        .setAction("app.fae.vault.password.create.$requestId"),
                    requestCode,
                    oneShot = true,
                )
                val entry = CreateEntry.Builder(localizeUiTextFor(this, "保存到保险库"), pending)
                    .setDescription(localizeUiTextFor(this, "通过 Credential Manager 保存密码"))
                    .setAutoSelectAllowed(false)
                    .build()
                callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
            }
            else -> callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) = callback.onResult(null)

    private fun activityIntent(mode: String, requestCode: Int) = Intent(this, PasskeyCredentialActivity::class.java)
        .setPackage(packageName)
        .setAction("app.fae.vault.passkey.$mode.$requestCode")
        .putExtra(PasskeyCredentialActivity.EXTRA_MODE, mode)

    private fun pendingIntent(intent: Intent, code: Int, oneShot: Boolean = false) = PendingIntent.getActivity(
        this,
        code,
        intent,
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT or
            (if (oneShot) PendingIntent.FLAG_ONE_SHOT else 0),
    )

    /** 请求摘要：SHA-256(requestJson)，与 Activity 侧 requestFingerprint() 保持一致。 */
    private fun requestFingerprint(requestJson: String): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(requestJson.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
