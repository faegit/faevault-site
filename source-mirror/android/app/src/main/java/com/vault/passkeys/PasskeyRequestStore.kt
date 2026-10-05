package com.vault.passkeys

import android.os.SystemClock
import androidx.credentials.provider.BeginGetCredentialRequest
import java.security.SecureRandom
import java.util.Base64

internal data class PasskeyRequestContract(
    val operation: PasskeyOperation,
    val optionId: String? = null,
) {
    override fun toString(): String = "PasskeyRequestContract([redacted])"
}

internal data class StoredBeginGet(
    val request: BeginGetCredentialRequest,
    val createdAtElapsed: Long,
) {
    override fun toString(): String = "StoredBeginGet(request=[redacted])"
}

/**
 * Process-local handoff for the query-stage framework request.
 *
 * The selected credential's final ProviderGetCredentialRequest is intentionally not accepted by
 * this store. It must come from PendingIntentHandler after Credential Manager mutates the selected
 * entry's PendingIntent.
 */
internal class PasskeyRequestStore(
    private val elapsedRealtime: () -> Long = SystemClock::elapsedRealtime,
    private val secureRandom: SecureRandom = SecureRandom(),
) {
    private data class Item(
        val stored: StoredBeginGet,
        val contract: PasskeyRequestContract,
        val expiresAtElapsed: Long,
        val insertionOrder: Long,
    ) {
        override fun toString(): String = "Item([redacted])"
    }

    private val values = LinkedHashMap<String, Item>()
    private var nextInsertionOrder = 0L

    @Synchronized
    fun put(
        request: BeginGetCredentialRequest,
        contract: PasskeyRequestContract = DEFAULT_CONTRACT,
    ): String {
        val now = elapsedRealtime()
        purgeExpired(now)
        if (values.size >= MAX_REQUESTS) {
            val oldest = values.minWithOrNull(
                compareBy<Map.Entry<String, Item>>(
                    { it.value.expiresAtElapsed },
                    { it.value.insertionOrder },
                ),
            )
            if (oldest != null) values.remove(oldest.key)
        }

        var token: String
        do {
            token = ByteArray(TOKEN_BYTES).also(secureRandom::nextBytes)
                .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
        } while (values.containsKey(token))

        val createdAt = now
        values[token] = Item(
            stored = StoredBeginGet(request, createdAt),
            contract = contract,
            expiresAtElapsed = createdAt + TTL_MS,
            insertionOrder = nextInsertionOrder++,
        )
        return token
    }

    fun take(token: String?): BeginGetCredentialRequest? =
        takeBeginGet(token, DEFAULT_CONTRACT)?.request

    fun take(
        token: String?,
        contract: PasskeyRequestContract,
    ): BeginGetCredentialRequest? = takeBeginGet(token, contract)?.request

    fun get(token: String?): BeginGetCredentialRequest? =
        getBeginGet(token, DEFAULT_CONTRACT)?.request

    @Synchronized
    fun activeRequestCount(): Int {
        purgeExpired(elapsedRealtime())
        return values.size
    }

    @Synchronized
    fun getBeginGet(
        token: String?,
        contract: PasskeyRequestContract = DEFAULT_CONTRACT,
    ): StoredBeginGet? {
        purgeExpired(elapsedRealtime())
        if (token == null) return null
        val item = values[token] ?: return null
        if (item.contract != contract) return null
        return item.stored
    }

    @Synchronized
    fun takeBeginGet(
        token: String?,
        contract: PasskeyRequestContract = DEFAULT_CONTRACT,
    ): StoredBeginGet? {
        purgeExpired(elapsedRealtime())
        if (token == null) return null
        val item = values[token] ?: return null
        if (item.contract != contract) return null
        values.remove(token)
        return item.stored
    }

    private fun purgeExpired(now: Long) {
        values.entries.removeAll { now >= it.value.expiresAtElapsed }
    }

    companion object {
        private const val TOKEN_BYTES = 24
        private const val TTL_MS = 300_000L
        private const val MAX_REQUESTS = 64
        private val DEFAULT_CONTRACT = PasskeyRequestContract(PasskeyOperation.GET)
        private val processStore = PasskeyRequestStore()

        fun put(request: BeginGetCredentialRequest): String = processStore.put(request)

        fun put(
            request: BeginGetCredentialRequest,
            contract: PasskeyRequestContract,
        ): String = processStore.put(request, contract)

        fun take(token: String?): BeginGetCredentialRequest? = processStore.take(token)

        fun take(
            token: String?,
            contract: PasskeyRequestContract,
        ): BeginGetCredentialRequest? = processStore.take(token, contract)

        fun get(token: String?): BeginGetCredentialRequest? = processStore.get(token)

        fun takeBeginGet(
            token: String?,
            contract: PasskeyRequestContract = DEFAULT_CONTRACT,
        ): StoredBeginGet? = processStore.takeBeginGet(token, contract)
    }
}

/**
 * Bounded, process-local lifecycle for create/sign PendingIntent tokens.
 *
 * A token is removed before its result is returned, so concurrent or repeated PendingIntent
 * delivery can never authorize the same operation twice.
 */
internal class PasskeyOperationTokenStore(
    private val elapsedRealtime: () -> Long = SystemClock::elapsedRealtime,
    private val tokenGenerator: () -> String = ::newOperationToken,
    private val clockMillis: () -> Long = elapsedRealtime,
) {
    private val expiresAt = LinkedHashMap<String, Long>()

    /**
     * 进程级持久化钩子（可选）：进程被杀后令牌可从本地快照恢复，
     * 避免"用户操作到一半令牌全灭→请求无效死循环"。快照只含随机令牌与过期时间戳，
     * 不含任何请求敏感内容。
     */
    interface SnapshotStore {
        fun load(): Map<String, Long>
        fun save(tokens: Map<String, Long>)
    }

    @Volatile
    private var snapshot: SnapshotStore? = null

    @Synchronized
    fun attachSnapshot(store: SnapshotStore) {
        snapshot = store
        val now = clockMillis()
        purgeExpired(now)
        // 恢复进程死亡前的未消费令牌（墙钟判断有效性）
        store.load().forEach { (token, expiry) ->
            if (expiry > now && !expiresAt.containsKey(token)) expiresAt[token] = expiry
        }
        store.save(expiresAt.toMap())
    }

    @Synchronized
    private fun syncSnapshot() {
        snapshot?.save(expiresAt.toMap())
    }

    @Synchronized
    fun issue(): String {
        val now = clockMillis()
        purgeExpired(now)
        while (expiresAt.size >= MAX_OPERATION_TOKENS) {
            expiresAt.entries.firstOrNull()?.let { expiresAt.remove(it.key) }
        }
        var token: String
        do token = tokenGenerator() while (expiresAt.containsKey(token))
        expiresAt[token] = now + OPERATION_TOKEN_TTL_MS
        syncSnapshot()
        return token
    }

    @Synchronized
    fun consume(token: String?): Boolean {
        val now = clockMillis()
        purgeExpired(now)
        if (token.isNullOrBlank()) return false
        val expiry = expiresAt.remove(token) ?: return false
        val valid = now < expiry
        if (!valid) expiresAt[token] = expiry // 已过期令牌放回以便快照一致（下次 purge 清除）
        syncSnapshot()
        return valid
    }

    @Synchronized
    fun activeTokenCount(): Int {
        purgeExpired(clockMillis())
        return expiresAt.size
    }

    private fun purgeExpired(now: Long) {
        expiresAt.entries.removeAll { now >= it.value }
    }
}

private const val OPERATION_TOKEN_BYTES = 32
private const val OPERATION_TOKEN_TTL_MS = 300_000L
private const val MAX_OPERATION_TOKENS = 128

private fun newOperationToken(): String = ByteArray(OPERATION_TOKEN_BYTES)
    .also(SecureRandom()::nextBytes)
    .let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
