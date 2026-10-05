package com.vault.passkeys

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import android.content.Context
import android.os.SystemClock
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.credentials.provider.BiometricPromptData
import androidx.credentials.provider.BiometricPromptResult
import com.vault.R
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.resume

enum class PasskeyOperation {
    CREATE,
    GET,
}

fun interface MonotonicClock {
    fun elapsedRealtime(): Long
}

sealed interface UserAuthenticationResult {
    data object Success : UserAuthenticationResult
    data object Cancelled : UserAuthenticationResult
    data object Failure : UserAuthenticationResult
}

sealed interface EmbeddedPromptResult {
    data object Absent : EmbeddedPromptResult
    data object Success : EmbeddedPromptResult
    data object Cancelled : EmbeddedPromptResult
    data object Failure : EmbeddedPromptResult
}

sealed interface UserVerificationResult {
    class Verified(val ticket: UserVerificationTicket) : UserVerificationResult {
        override fun toString(): String = "Verified(ticket=<redacted>)"
    }

    data object Cancelled : UserVerificationResult
    data object Failure : UserVerificationResult
}

/**
 * Opaque proof of a recent user verification. Its identifiers and context binding are deliberately
 * absent from [toString].
 */
class UserVerificationTicket internal constructor(
    internal val id: String,
    val operation: PasskeyOperation,
    val verifiedAtElapsedRealtime: Long,
) {
    override fun toString(): String =
        "UserVerificationTicket(operation=$operation, binding=<redacted>)"
}

/**
 * Process-local, bounded, one-use ticket store. Constructing a new instance represents a process
 * restart: there is no persisted or static ticket state.
 */
class UserVerificationTicketStore(
    private val clock: MonotonicClock,
    private val capacity: Int = DEFAULT_CAPACITY,
    private val lifetimeMillis: Long = TICKET_LIFETIME_MILLIS,
    private val ticketIdGenerator: () -> String = ::newRandomToken,
) {
    private class Record(
        val requestToken: String,
        val operation: PasskeyOperation,
        val contextBinding: String,
        val verifiedAt: Long,
        val insertionOrder: Long,
    ) {
        override fun toString(): String = "VerificationRecord(binding=<redacted>)"
    }

    private val tickets = ConcurrentHashMap<String, Record>()
    private val insertionSequence = AtomicLong()
    private val maintenanceLock = Any()

    init {
        require(capacity > 0) { "ticket capacity must be positive" }
        require(lifetimeMillis > 0) { "ticket lifetime must be positive" }
    }

    internal fun issue(
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
    ): UserVerificationTicket {
        require(requestToken.isNotBlank()) { "request token is required" }
        require(contextBinding.isNotBlank()) { "verification context is required" }
        val now = clock.elapsedRealtime()
        synchronized(maintenanceLock) {
            removeExpired(now)
            while (tickets.size >= capacity) {
                evictOldest()
            }
            while (true) {
                val id = ticketIdGenerator()
                require(id.isNotBlank()) { "ticket identifier generation failed" }
                val record = Record(
                    requestToken = requestToken,
                    operation = operation,
                    contextBinding = contextBinding,
                    verifiedAt = now,
                    insertionOrder = insertionSequence.getAndIncrement(),
                )
                if (tickets.putIfAbsent(id, record) == null) {
                    return UserVerificationTicket(id, operation, now)
                }
            }
        }
    }

    /**
     * Removes before validating, so a wrong binding attempt burns the ticket and cannot race a
     * legitimate consumer.
     */
    fun consume(
        ticket: UserVerificationTicket,
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
    ): Boolean {
        val record = tickets.remove(ticket.id) ?: return false
        val now = clock.elapsedRealtime()
        val age = now - record.verifiedAt
        if (age < 0L || age >= lifetimeMillis) return false
        return ticket.operation == record.operation &&
            ticket.verifiedAtElapsedRealtime == record.verifiedAt &&
            operation == record.operation &&
            constantTimeEquals(requestToken, record.requestToken) &&
            constantTimeEquals(contextBinding, record.contextBinding)
    }

    internal fun activeTicketCount(): Int = synchronized(maintenanceLock) {
        removeExpired(clock.elapsedRealtime())
        tickets.size
    }

    private fun removeExpired(now: Long) {
        tickets.entries.forEach { entry ->
            val age = now - entry.value.verifiedAt
            if (age < 0L || age >= lifetimeMillis) {
                tickets.remove(entry.key, entry.value)
            }
        }
    }

    private fun evictOldest() {
        val oldest = tickets.entries.minByOrNull { it.value.insertionOrder } ?: return
        tickets.remove(oldest.key, oldest.value)
    }

    private fun constantTimeEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(Charsets.UTF_8), right.toByteArray(Charsets.UTF_8))

    companion object {
        const val TICKET_LIFETIME_MILLIS = 30_000L
        const val DEFAULT_CAPACITY = 128
    }
}

class PasskeyUserVerifier(
    private val tickets: UserVerificationTicketStore,
) {
    fun completeAuthentication(
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
        authenticationResult: UserAuthenticationResult,
    ): UserVerificationResult = when (authenticationResult) {
        UserAuthenticationResult.Success -> UserVerificationResult.Verified(
            tickets.issue(requestToken, operation, contextBinding),
        )
        UserAuthenticationResult.Cancelled -> UserVerificationResult.Cancelled
        UserAuthenticationResult.Failure -> UserVerificationResult.Failure
    }

    suspend fun verify(
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
        embeddedPromptResult: EmbeddedPromptResult,
        explicitVerification: suspend () -> UserAuthenticationResult,
    ): UserVerificationResult {
        val authenticationResult = when (embeddedPromptResult) {
            EmbeddedPromptResult.Success -> UserAuthenticationResult.Success
            EmbeddedPromptResult.Cancelled -> UserAuthenticationResult.Cancelled
            EmbeddedPromptResult.Failure -> UserAuthenticationResult.Failure
            EmbeddedPromptResult.Absent -> explicitVerification()
        }
        return completeAuthentication(requestToken, operation, contextBinding, authenticationResult)
    }

    fun consume(
        ticket: UserVerificationTicket,
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
    ): Boolean = tickets.consume(ticket, requestToken, operation, contextBinding)
}

/**
 * Credential Manager coupling for Android 15's embedded user-verification result.
 */
object EmbeddedPasskeyPrompt {
    @RequiresApi(35)
    fun promptData(): BiometricPromptData = BiometricPromptData.Builder()
        .setAllowedAuthenticators(ALLOWED_AUTHENTICATORS)
        .build()

    fun classify(result: BiometricPromptResult?): EmbeddedPromptResult = when {
        result == null -> EmbeddedPromptResult.Absent
        result.isSuccessful -> EmbeddedPromptResult.Success
        result.authenticationError?.errorCode.isCancellationError() ->
            EmbeddedPromptResult.Cancelled
        else -> EmbeddedPromptResult.Failure
    }
}

/**
 * Android 14+ explicit prompt wrapper, also used as the Android 15 fallback when no embedded prompt
 * result is present.
 */
class AndroidPasskeyUserVerifier(
    private val verifier: PasskeyUserVerifier = ProcessLocalPasskeyUserVerifier.instance,
) {
    suspend fun verify(
        activity: FragmentActivity,
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
        embeddedPromptResult: BiometricPromptResult? = null,
    ): UserVerificationResult = verifier.verify(
        requestToken = requestToken,
        operation = operation,
        contextBinding = contextBinding,
        embeddedPromptResult = EmbeddedPasskeyPrompt.classify(embeddedPromptResult),
    ) {
        authenticateExplicitly(activity)
    }

    fun consume(
        ticket: UserVerificationTicket,
        requestToken: String,
        operation: PasskeyOperation,
        contextBinding: String,
    ): Boolean = verifier.consume(ticket, requestToken, operation, contextBinding)

    private suspend fun authenticateExplicitly(
        activity: FragmentActivity,
    ): UserAuthenticationResult = suspendCancellableCoroutine { continuation ->
        val settled = AtomicBoolean()
        lateinit var prompt: BiometricPrompt

        fun finish(result: UserAuthenticationResult) {
            if (settled.compareAndSet(false, true) && continuation.isActive) {
                continuation.resume(result)
            }
        }

        prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    finish(UserAuthenticationResult.Success)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    finish(
                        if (errorCode.isCancellationError()) {
                            UserAuthenticationResult.Cancelled
                        } else {
                            UserAuthenticationResult.Failure
                        },
                    )
                }

                override fun onAuthenticationFailed() {
                    // The prompt remains active so the user can retry.
                }
            },
        )
        continuation.invokeOnCancellation {
            if (settled.compareAndSet(false, true)) {
                prompt.cancelAuthentication()
            }
        }
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(activity.getString(R.string.passkey_verify_title))
            .setSubtitle(activity.getString(R.string.passkey_verify_subtitle))
            .setAllowedAuthenticators(ALLOWED_AUTHENTICATORS)
            // No negative button: BiometricPrompt forbids it with DEVICE_CREDENTIAL.
            .build()
        prompt.authenticate(promptInfo)
    }
}

object ProcessLocalPasskeyUserVerifier {
    val instance: PasskeyUserVerifier by lazy {
        PasskeyUserVerifier(
            UserVerificationTicketStore(
                clock = MonotonicClock(SystemClock::elapsedRealtime),
            ),
        )
    }
}

object PasskeyRequestTokens {
    private val store = PasskeyOperationTokenStore()
    @Volatile private var installed = false

    /**
     * 注入进程死亡恢复能力：令牌及过期时间（墙钟）快照到本地 SP，
     * Service / Activity 任一入口先调用即完成加载合并；重复调用幂等。
     */
    fun install(context: Context) {
        if (installed) return
        synchronized(this) {
            if (installed) return
            // Invalidate legacy plaintext snapshots. Tokens are short-lived; never migrate exposed ones.
            check(context.applicationContext.getSharedPreferences("passkey_operation_tokens", Context.MODE_PRIVATE)
                .edit().clear().commit()) { "Cannot remove legacy operation tokens" }
            val prefs = com.vault.security.SecurePreferences.get(context, "passkey_operation_tokens_v2")
            store.attachSnapshot(object : PasskeyOperationTokenStore.SnapshotStore {
                override fun load(): Map<String, Long> = runCatching {
                    val raw = prefs.getString("snapshot", null) ?: return emptyMap()
                    kotlinx.serialization.json.Json.parseToJsonElement(raw).jsonObject
                        .mapNotNull { (token, expiry) -> expiry.jsonPrimitive.longOrNull?.let { token to it } }.toMap()
                }.getOrDefault(emptyMap())

                override fun save(tokens: Map<String, Long>) {
                    // Token values must not appear as plaintext preference names either.
                    val encoded = kotlinx.serialization.json.JsonObject(tokens.mapValues {
                        kotlinx.serialization.json.JsonPrimitive(it.value)
                    }).toString()
                    check(prefs.edit().putString("snapshot", encoded).commit()) { "Cannot persist operation tokens" }
                }
            })
            installed = true
        }
    }

    fun create(): String = store.issue()

    fun consume(token: String?): Boolean = store.consume(token)
}

private const val ALLOWED_AUTHENTICATORS =
    BiometricManager.Authenticators.BIOMETRIC_STRONG or
        BiometricManager.Authenticators.DEVICE_CREDENTIAL

private fun Int?.isCancellationError(): Boolean = this == BiometricPrompt.ERROR_CANCELED ||
    this == BiometricPrompt.ERROR_USER_CANCELED ||
    this == BiometricPrompt.ERROR_NEGATIVE_BUTTON

private fun newRandomToken(): String = ByteArray(32)
    .also(SecureRandom()::nextBytes)
    .let(Base64.getUrlEncoder().withoutPadding()::encodeToString)
