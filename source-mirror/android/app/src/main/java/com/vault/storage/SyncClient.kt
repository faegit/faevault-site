package com.vault.storage

import com.vault.security.VaultDeviceIdentity
import kotlinx.coroutines.runInterruptible
import java.net.URL
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import org.json.JSONObject
import org.json.JSONArray
import java.io.File
import java.io.InputStream

/**
 * 局域网同步 HTTPS 客户端（仅连接同一局域网内的其他设备，不访问公网）。
 *
 * PC 使用本次会话临时证书；客户端通过 HTTPS 加密传输，并使用 PIN 验证同步会话。
 */
object SyncClient {

    data class PullResult(val bytes: ByteArray)
    data class PushResult(val stats: String)
    data class TransferOffer(
        val id: String,
        val name: String,
        val mime: String,
        val kind: String,
        val size: Long,
        val sha256: String,
    )

    open class SyncException(message: String, cause: Throwable? = null) : Exception(message, cause)
    class IntegrityException(message: String) : SyncException(message)
    class PinValidationException(message: String) : SyncException(message)
    /** 导出内容完整性校验失败（长度/哈希不匹配），与传输链路错误区分开，供 UI 提示重新申请下载。 */
    class ExportIntegrityException(message: String) : SyncException(message)

    /**
     * 423 等待超时的通道名。
     *
     * 423 在三个通道上都会出现（主机分别回「等待主机确认同步/文件传输/导出」），
     * 文案必须跟着通道走：写死成「导出」会让走同步通道的用户读到不相干的字眼，
     * 而 UI 层的错误映射正是按这些关键词分档的。
     */
    private fun sessionOpLabel(op: String): String = when (op) {
        TRANSFER_OP -> "文件传输"
        EXPORT_OP -> "导出"
        else -> "同步"
    }

    private const val PAIRING_HEADER = "X-Vault-Sync-Ticket"
    private const val SESSION_HEADER = "X-Vault-Sync-Session"
    private const val SPAKE2_VERSION = "spake2-rfc9382-p256-sha256-v1"
    /** 安卓端作为客户端声明通道：sync=双向同步 / transfer=文件互传。绑定进 SPAKE2 AAD。 */
    private const val SYNC_OP = "sync"
    private const val TRANSFER_OP = "transfer"
    private const val EXPORT_OP = "export"
    private const val MAX_TRANSFER_BYTES = 10L * 1024L * 1024L * 1024L * 1024L
    private const val MAX_LAN_VAULT_BYTES = 10L * 1024L * 1024L * 1024L
    private const val MAX_INTEGRITY_ATTEMPTS = 3
    private const val CONTENT_SHA256_HEADER = "X-Vault-Content-Sha256"
    private const val STREAM_CHUNK_BYTES = 64 * 1024
    private const val BASE_READ_TIMEOUT_MS = 120_000L
    private const val MIN_BANDWIDTH_BYTES_PER_SEC = 512L * 1024L
    private const val MAX_READ_TIMEOUT_MS = 30L * 60L * 1000L
    private const val MAX_LAN_URL_CHARS = 2048
    private val CLIENT_ID = "vault-android-client".toByteArray()
    private val SERVER_ID = "vault-pc-server".toByteArray()
    /** 在途传输连接注册表：按传输项 key 关联底层连接，断连时关闭全部，单条取消时只关对应连接。 */
    private val inFlightTransfers = ConcurrentHashMap<String, HttpsURLConnection>()
    private data class PairingSession(val token: String, val certificateFingerprint: ByteArray)
    private val sessions = ConcurrentHashMap<String, PairingSession>()

    internal fun endpoint(serverUrl: String, path: String = "/api/sync/vault"): URL {
        val raw = serverUrl.trim().trimEnd('/')
        require(raw.length in 1..MAX_LAN_URL_CHARS) { "连接地址过长或为空" }
        val withScheme = if (raw.contains("://")) raw else "https://$raw"
        val parsed = URL(withScheme)
        require(parsed.protocol == "https") { "局域网同步仅支持 HTTPS" }
        require(parsed.userInfo == null) { "连接地址不能包含用户名或密码" }
        require(parsed.ref == null) { "连接地址不能包含页面片段" }
        require(parsed.port == -1 || parsed.port in 1..65535) { "连接端口无效" }
        require(isAllowedLanImportHost(parsed.host)) { "局域网同步拒绝公网地址或域名" }
        val base = "${parsed.protocol}://${parsed.host}${if (parsed.port >= 0) ":${parsed.port}" else ""}"
        return URL("$base$path")
    }

    internal fun pairingTicket(serverUrl: String): String {
        val raw = serverUrl.trim().trimEnd('/')
        val withScheme = if (raw.contains("://")) raw else "https://$raw"
        val parsed = URL(withScheme)
        val query = parsed.query.orEmpty()
        return query.split('&')
            .mapNotNull { part ->
                val idx = part.indexOf('=')
                if (idx <= 0) null else part.substring(0, idx) to part.substring(idx + 1)
            }
            .filter { it.first == "ticket" }
            .map { URLDecoder.decode(it.second, Charsets.UTF_8.name()) }
            .singleOrNull()
            .orEmpty()
    }

    /** 从同步地址提取内嵌的 6 位 PIN；无或不合法返回 null（手动粘贴含 &pin= 的地址时免输）。 */
    fun embeddedPin(serverUrl: String): String? {
        val raw = serverUrl.trim().trimEnd('/')
        val withScheme = if (raw.contains("://")) raw else "https://$raw"
        val query = runCatching { URL(withScheme).query.orEmpty() }.getOrElse { return null }
        return query.split('&')
            .mapNotNull { part ->
                val idx = part.indexOf('=')
                if (idx <= 0) null else part.substring(0, idx) to part.substring(idx + 1)
            }
            .filter { it.first == "pin" }
            .map { URLDecoder.decode(it.second, Charsets.UTF_8.name()) }
            .singleOrNull()
            ?.takeIf { it.length == 6 && it.all(Char::isDigit) }
    }

    fun forgetSession(baseUrl: String, pin: String) {
        // 清除该地址在 sync / transfer / export 三个通道下的会话，
        // 避免上一次连接（尤其是整库导入）结束后残留旧 token/证书指纹，
        // 导致传输站重启或轮换后再次连接时报证书/解密错误。
        listOf(SYNC_OP, TRANSFER_OP, EXPORT_OP).forEach { op ->
            sessions.remove(sessionKey(baseUrl, op))?.certificateFingerprint?.fill(0)
        }
    }

    /** 拉取并返回远程 .pmv 裸字节（内存版，用于密钥协商等小文件场景）。 */
    fun pull(baseUrl: String, pin: String): ByteArray {
        val conn = openTemporaryHttps(baseUrl, pin)
        conn.requestMethod = "GET"
        conn.setRequestProperty("Connection", "close")
        conn.connectTimeout = 10_000
        conn.readTimeout = 60_000
        try {
            val code = conn.responseCode
            if (code != 200) {
                val body = conn.errorStream?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                throw SyncException("拉取失败，HTTP $code：$body")
            }
            val contentLength = conn.contentLengthLong
            val bytes = conn.inputStream.readBytesLimited(
                if (contentLength > 0) contentLength else MAX_VAULT_BYTES,
                "同步保险库",
            )
            if (contentLength in 1..MAX_VAULT_BYTES && bytes.size.toLong() != contentLength) {
                throw SyncException("拉取保险库不完整，期望 $contentLength 字节，实得 ${bytes.size} 字节")
            }
            return bytes
        } finally {
            conn.disconnect()
        }
    }

    /**
     * 分块流式拉取远程 .pmv 到本地文件，返回实际写入字节数。
     * 全程不将完整保险库载入内存，适用于大库（上限 10 GiB）。
     */
    fun pullToFile(
        baseUrl: String,
        pin: String,
        target: java.io.File,
        onProgress: (transferred: Long, total: Long) -> Unit = { _, _ -> },
        onIntegrityRetry: (attempt: Int, maxAttempts: Int) -> Unit = { _, _ -> },
    ): Long {
        var lastError: IntegrityException? = null
        repeat(MAX_INTEGRITY_ATTEMPTS) { index ->
            try {
                return pullToFileOnce(baseUrl, pin, target, onProgress)
            } catch (error: IntegrityException) {
                target.delete()
                lastError = error
                if (index + 1 < MAX_INTEGRITY_ATTEMPTS) onIntegrityRetry(index + 2, MAX_INTEGRITY_ATTEMPTS)
            }
        }
        throw lastError ?: IntegrityException("收到的数据未通过安全检查")
    }

    private fun pullToFileOnce(
        baseUrl: String,
        pin: String,
        target: File,
        onProgress: (transferred: Long, total: Long) -> Unit,
    ): Long {
        val conn = openTemporaryHttps(baseUrl, pin)
        conn.requestMethod = "GET"
        conn.setRequestProperty("Connection", "close")
        conn.connectTimeout = 10_000
        conn.readTimeout = 30_000
        try {
            val code = conn.responseCode
            if (code != 200) {
                val body = conn.errorStream?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                throw SyncException("拉取失败，HTTP $code：$body")
            }
            val contentLength = conn.contentLengthLong
            if (contentLength !in 1..MAX_LAN_VAULT_BYTES) throw SyncException("对方发送的数据大小无效或超过 10 GB")
            val expectedHash = conn.getHeaderField("X-Vault-Sha256")?.lowercase().orEmpty()
            if (!expectedHash.matches(Regex("[0-9a-f]{64}"))) throw IntegrityException("对方未提供有效的安全校验信息")
            target.parentFile?.mkdirs()
            var total = 0L
            val digest = MessageDigest.getInstance("SHA-256")
            try {
                conn.inputStream.use { input ->
                    target.outputStream().buffered().use { output ->
                        val buffer = ByteArray(STREAM_CHUNK_BYTES)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total > contentLength) throw IntegrityException("收到的数据长度与发送方不一致")
                            digest.update(buffer, 0, count)
                            output.write(buffer, 0, count)
                            onProgress(total, contentLength.coerceAtLeast(total))
                        }
                    }
                }
            } catch (error: Throwable) {
                target.delete()
                throw error
            }
            if (contentLength in 1..MAX_LAN_VAULT_BYTES && total != contentLength) {
                target.delete()
                throw IntegrityException("收到的数据不完整")
            }
            if (!MessageDigest.isEqual(expectedHash.toByteArray(Charsets.US_ASCII), digest.digest().toHex().toByteArray(Charsets.US_ASCII))) {
                target.delete()
                throw IntegrityException("收到的数据未通过安全检查")
            }
            return total
        } finally {
            conn.disconnect()
        }
    }

    /** 分块流式推送本地 .pmv 文件到远程，返回合并统计 JSON。 */
    fun pushFromFile(
        baseUrl: String,
        pin: String,
        source: java.io.File,
        onIntegrityRetry: (attempt: Int, maxAttempts: Int) -> Unit = { _, _ -> },
        onProgress: (transferred: Long, total: Long) -> Unit = { _, _ -> },
    ): String {
        val size = source.length()
        if (size !in 1..MAX_LAN_VAULT_BYTES) throw SyncException("当前账户数据为空或超过 10 GB，暂时无法发送")
        val expectedHash = sha256File(source)
        var lastError: IntegrityException? = null
        repeat(MAX_INTEGRITY_ATTEMPTS) { index ->
            try {
                return pushFromFileOnce(baseUrl, pin, source, size, expectedHash, onProgress)
            } catch (error: IntegrityException) {
                lastError = error
                if (index + 1 < MAX_INTEGRITY_ATTEMPTS) onIntegrityRetry(index + 2, MAX_INTEGRITY_ATTEMPTS)
            }
        }
        throw lastError ?: IntegrityException("发送的数据未通过接收方检查")
    }

    private fun pushFromFileOnce(
        baseUrl: String,
        pin: String,
        source: File,
        size: Long,
        expectedHash: String,
        onProgress: (transferred: Long, total: Long) -> Unit,
    ): String {
        val readTimeout = streamTimeoutFor(size)
        val conn = openTemporaryHttps(baseUrl, pin)
        conn.requestMethod = "PUT"
        conn.doOutput = true
        conn.setFixedLengthStreamingMode(size)
        conn.connectTimeout = 10_000
        conn.readTimeout = readTimeout.toInt()
        conn.setRequestProperty("Connection", "close")
        conn.setRequestProperty("Content-Type", "application/octet-stream")
        conn.setRequestProperty(CONTENT_SHA256_HEADER, expectedHash)
        try {
            var transferred = 0L
            conn.outputStream.use { output ->
                source.inputStream().buffered().use { input ->
                    val buffer = ByteArray(STREAM_CHUNK_BYTES)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        output.write(buffer, 0, count)
                        transferred += count
                        onProgress(transferred, size)
                    }
                }
            }
            val code = conn.responseCode
            if (code !in 200..299) {
                val body = (if (code >= 400) conn.errorStream else conn.inputStream)
                    ?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                if (code == 422) throw IntegrityException("接收方检查未通过，正在重新发送")
                throw SyncException("推送失败，HTTP $code：$body")
            }
            return conn.inputStream.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "同步响应").decodeToString()
        } finally {
            conn.disconnect()
        }
    }

    /** 根据传输大小估算读取超时：保证 512KB/s 以上速率不超时，上限 30 分钟。 */
    private fun streamTimeoutFor(size: Long): Long {
        val estimated = size / MIN_BANDWIDTH_BYTES_PER_SEC * 1000L + 30_000L
        return estimated.coerceIn(BASE_READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS)
    }

    /**
     * SPAKE2 配对后完成设备授权握手（PMVE 同步通道）。
     * 复用按 (baseUrl, pin) 缓存的配对会话，使授权状态绑定到后续 GET/PUT 的同一会话。
     * [op] 为 "read"/"write"；423 表示导出通道等待主机用户确认，重试直到 [maxWaitMillis]。
     */
    fun authenticateDevice(
        baseUrl: String,
        pin: String,
        vaultId: UUID,
        identity: VaultDeviceIdentity,
        op: String,
        onWaitingForExport: () -> Unit = {},
        maxWaitMillis: Long = 150_000L,
        sessionOp: String = SYNC_OP,
    ) {
        val clientNonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val requestBody = JSONObject()
            .put("v", DeviceAuthWire.PROTOCOL_VERSION)
            .put("clientNonce", encode(clientNonce))
            .put("deviceId", identity.deviceId.toString())
            .put("vaultId", vaultId.toString())
            .put("op", op)
            .put("devicePublicKey", encode(identity.publicKey))
            .put("requestedCommitId", JSONObject.NULL)
            .put("requestDigest", encode(ByteArray(32)))
            .toString().toByteArray()
        val deadline = System.currentTimeMillis() + maxWaitMillis
        try {
            while (true) {
                val conn = openTemporaryHttps(baseUrl, pin, "/api/auth/challenge", sessionOp)
                try {
                    conn.requestMethod = "POST"
                    conn.doOutput = true
                    conn.setFixedLengthStreamingMode(requestBody.size)
                    conn.connectTimeout = 10_000
                    conn.readTimeout = 20_000
                    conn.setRequestProperty("Connection", "close")
                    conn.setRequestProperty("Content-Type", "application/json")
                    conn.outputStream.use { it.write(requestBody) }
                    val code = conn.responseCode
                    if (code == 423) {
                        onWaitingForExport()
                        if (System.currentTimeMillis() > deadline) {
                            throw SyncException("等待主机确认${sessionOpLabel(sessionOp)}超时")
                        }
                        Thread.sleep(5_000)
                        continue
                    }
                    if (code != 200) {
                        val body = conn.errorStream
                            ?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                        throw SyncException("设备认证失败，HTTP $code：$body")
                    }
                    val json = JSONObject(
                        conn.inputStream.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "认证响应").decodeToString(),
                    )
                    val challenge = decode(json.getString("challenge"), PmvSyncAuthorization.CHALLENGE_SIZE)
                    val signature = DeviceAuthWire.signChallenge(challenge, identity)
                    try {
                        confirmDeviceAuth(baseUrl, pin, challenge, signature, sessionOp)
                    } finally {
                        signature.fill(0)
                        challenge.fill(0)
                    }
                    return
                } finally {
                    conn.disconnect()
                }
            }
        } finally {
            clientNonce.fill(0)
        }
    }

    private fun confirmDeviceAuth(
        baseUrl: String,
        pin: String,
        challenge: ByteArray,
        signature: ByteArray,
        sessionOp: String = SYNC_OP,
    ) {
        val body = JSONObject()
            .put("v", DeviceAuthWire.PROTOCOL_VERSION)
            .put("challenge", encode(challenge))
            .put("signature", encode(signature))
            .toString().toByteArray()
        val conn = openTemporaryHttps(baseUrl, pin, "/api/auth/challenge/confirm", sessionOp)
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setFixedLengthStreamingMode(body.size)
            conn.connectTimeout = 10_000
            conn.readTimeout = 20_000
            conn.setRequestProperty("Connection", "close")
            conn.setRequestProperty("Content-Type", "application/json")
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            if (code != 200) {
                val error = conn.errorStream
                    ?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                throw SyncException("设备认证确认失败，HTTP $code：$error")
            }
        } finally {
            body.fill(0)
            conn.disconnect()
        }
    }

    fun keepAlive(baseUrl: String, pin: String) {
        val conn = openTemporaryHttps(baseUrl, pin, "/api/sync/keepalive").apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("Connection", "close")
        }
        try {
            val code = conn.responseCode
            if (code != 204) throw SyncException("同步会话续期失败，HTTP $code")
        } finally {
            conn.disconnect()
        }
    }

    private fun sha256File(file: File): String = MessageDigest.getInstance("SHA-256").let { digest ->
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(STREAM_CHUNK_BYTES)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        digest.digest().toHex()
    }

    /** 文件传输通道保活：复用已经建立的 transfer 会话，绝不触发 sync 二次配对。 */
    fun keepTransferAlive(baseUrl: String, pin: String) {
        val conn = openTemporaryHttps(baseUrl, pin, "/api/sync/keepalive", TRANSFER_OP).apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("Connection", "close")
        }
        try {
            val code = conn.responseCode
            if (code != 204) throw SyncException("文件传输会话续期失败，HTTP $code")
        } finally {
            conn.disconnect()
        }
    }

    fun cancelSession(baseUrl: String, pin: String) {
        val conn = openTemporaryHttps(baseUrl, pin, "/api/sync/cancel").apply {
            requestMethod = "GET"
            connectTimeout = 5_000
            readTimeout = 5_000
            setRequestProperty("Connection", "close")
        }
        try {
            val code = conn.responseCode
            if (code != 204) throw SyncException("取消同步会话失败，HTTP $code")
        } finally {
            conn.disconnect()
        }
    }

    fun listTransferOffers(baseUrl: String, pin: String): List<TransferOffer> {
        val conn = openTemporaryHttps(baseUrl, pin, "/api/transfer/items").apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = 15_000
            setRequestProperty("Connection", "close")
        }
        try {
            val code = conn.responseCode
            if (code != 200) throw SyncException("获取待接收内容失败，HTTP $code")
            val body = JSONObject(conn.inputStream.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "传输列表").decodeToString())
            val items = body.optJSONArray("items") ?: JSONArray()
            return buildList {
                for (index in 0 until items.length()) {
                    val item = items.optJSONObject(index) ?: continue
                    val id = item.optString("id")
                    val size = item.optLong("size", -1L)
                    if (id.isBlank() || size !in 0..MAX_TRANSFER_BYTES) continue
                    add(
                        TransferOffer(
                            id = id,
                            name = item.optString("name").ifBlank { "received.bin" }.take(255),
                            mime = item.optString("mime").ifBlank { "application/octet-stream" }.take(255),
                            kind = item.optString("kind").ifBlank { "file" }.take(16),
                            size = size,
                            sha256 = item.optString("sha256").lowercase(),
                        ),
                    )
                }
            }
        } finally {
            conn.disconnect()
        }
    }

    fun uploadTransferFile(
        baseUrl: String,
        pin: String,
        source: File,
        name: String,
        mime: String,
        kind: String,
        onProgress: (transferred: Long, total: Long) -> Unit = { _, _ -> },
        transferKey: String = "",
    ): TransferOffer = uploadTransferFileWithRetry(
        baseUrl = baseUrl,
        pin = pin,
        inputFactory = { source.inputStream() },
        size = source.length(),
        name = name,
        mime = mime,
        kind = kind,
        onProgress = onProgress,
        transferKey = transferKey,
    )

    fun uploadTransferFileWithRetry(
        baseUrl: String,
        pin: String,
        inputFactory: () -> InputStream,
        size: Long,
        name: String,
        mime: String,
        kind: String,
        onProgress: (transferred: Long, total: Long) -> Unit = { _, _ -> },
        onIntegrityRetry: (attempt: Int, maxAttempts: Int) -> Unit = { _, _ -> },
        transferKey: String = "",
    ): TransferOffer {
        val expectedHash = inputFactory().use { stream -> sha256Stream(stream) }
        var lastError: IntegrityException? = null
        repeat(MAX_INTEGRITY_ATTEMPTS) { index ->
            try {
                return uploadTransferFile(
                    baseUrl, pin, inputFactory(), size, name, mime, kind, onProgress, expectedHash, transferKey,
                )
            } catch (error: IntegrityException) {
                lastError = error
                if (index + 1 < MAX_INTEGRITY_ATTEMPTS) onIntegrityRetry(index + 2, MAX_INTEGRITY_ATTEMPTS)
            }
        }
        throw lastError ?: IntegrityException("文件未通过安全检查")
    }

    fun uploadTransferFile(
        baseUrl: String,
        pin: String,
        input: InputStream,
        size: Long,
        name: String,
        mime: String,
        kind: String,
        onProgress: (transferred: Long, total: Long) -> Unit = { _, _ -> },
        expectedHash: String,
        transferKey: String = "",
    ): TransferOffer {
        if (size !in 0..MAX_TRANSFER_BYTES) throw SyncException("发送内容超过设备可处理范围")
        val id = java.util.UUID.randomUUID().toString()
        val digest = MessageDigest.getInstance("SHA-256")
        val conn = openTemporaryHttps(baseUrl, pin, "/api/transfer/item").apply {
            requestMethod = "PUT"
            doOutput = true
            setFixedLengthStreamingMode(size)
            connectTimeout = 10_000
            readTimeout = streamTimeoutFor(size).toInt()
            setRequestProperty("Connection", "close")
            setRequestProperty("Content-Type", "application/octet-stream")
            setRequestProperty("X-Vault-Transfer-Id", id)
            setRequestProperty("X-Vault-Transfer-Name", encodeTextHeader(name.take(255)))
            setRequestProperty("X-Vault-Transfer-Mime", encodeTextHeader(mime.take(255)))
            setRequestProperty("X-Vault-Transfer-Kind", kind.take(16))
            setRequestProperty(CONTENT_SHA256_HEADER, expectedHash)
        }
        try {
            inFlightTransfers[if (transferKey.isBlank()) id else transferKey] = conn
            var transferred = 0L
            onProgress(0L, size)
            conn.outputStream.use { output ->
                input.use { inputStream ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        if (Thread.currentThread().isInterrupted) throw InterruptedException("传输已中断")
                        val count = inputStream.read(buffer)
                        if (count < 0) break
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                        transferred += count
                        onProgress(transferred, size)
                    }
                }
            }
            val code = conn.responseCode
            if (code !in 200..299) {
                val detail = conn.errorStream
                    ?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "传输错误")
                    ?.decodeToString()
                    .orEmpty()
                if (code == 422) throw IntegrityException("接收方检查未通过，正在重新发送")
                throw SyncException("发送失败，HTTP $code：$detail")
            }
            val sha256 = digest.digest().toHex()
            val response = JSONObject(conn.inputStream.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "传输响应").decodeToString())
            val acceptedHash = response.optString("sha256").lowercase()
            if (acceptedHash.isBlank() || acceptedHash != sha256) throw IntegrityException("接收方文件校验未通过")
            return TransferOffer(id, name, mime, kind, size, sha256)
        } finally {
            inFlightTransfers.remove(if (transferKey.isBlank()) id else transferKey)
            conn.disconnect()
        }
    }

    fun downloadTransferOffer(
        baseUrl: String,
        pin: String,
        offer: TransferOffer,
        target: File,
        onProgress: (transferred: Long, total: Long) -> Unit = { _, _ -> },
        onIntegrityRetry: (attempt: Int, maxAttempts: Int) -> Unit = { _, _ -> },
    ) {
        var lastError: IntegrityException? = null
        repeat(MAX_INTEGRITY_ATTEMPTS) { index ->
            try {
                downloadTransferOfferOnce(baseUrl, pin, offer, target, onProgress)
                return
            } catch (error: IntegrityException) {
                target.delete()
                lastError = error
                if (index + 1 < MAX_INTEGRITY_ATTEMPTS) onIntegrityRetry(index + 2, MAX_INTEGRITY_ATTEMPTS)
            }
        }
        throw lastError ?: IntegrityException("文件未通过安全检查")
    }

    private fun downloadTransferOfferOnce(
        baseUrl: String,
        pin: String,
        offer: TransferOffer,
        target: File,
        onProgress: (transferred: Long, total: Long) -> Unit,
    ) {
        val query = URLEncoder.encode(offer.id, Charsets.UTF_8.name())
        val conn = openTemporaryHttps(baseUrl, pin, "/api/transfer/item?id=$query").apply {
            requestMethod = "GET"
            connectTimeout = 10_000
            readTimeout = streamTimeoutFor(offer.size).toInt()
            setRequestProperty("Connection", "close")
        }
        try {
            inFlightTransfers[offer.id] = conn
            val code = conn.responseCode
            if (code != 200) throw SyncException("接收失败，HTTP $code")
            val length = conn.contentLengthLong
            if (length != offer.size || length !in 0..MAX_TRANSFER_BYTES) throw IntegrityException("文件大小与发送方不一致")
            if (!offer.sha256.matches(Regex("[0-9a-f]{64}"))) throw IntegrityException("发送方未提供有效的文件校验信息")
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            onProgress(0L, offer.size)
            target.outputStream().buffered().use { output ->
                conn.inputStream.use { input ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    while (true) {
                        if (Thread.currentThread().isInterrupted) throw InterruptedException("传输已中断")
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > MAX_TRANSFER_BYTES) throw SyncException("接收内容超过设备可处理范围")
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                        onProgress(total, offer.size)
                    }
                }
            }
            val actualHash = digest.digest().toHex()
            if (total != offer.size || (offer.sha256.isNotBlank() && actualHash != offer.sha256)) {
                target.delete()
                throw IntegrityException("文件未通过安全检查")
            }
        } finally {
            inFlightTransfers.remove(offer.id)
            conn.disconnect()
        }
    }

    private fun sha256Stream(input: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(STREAM_CHUNK_BYTES)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
        return digest.digest().toHex()
    }

    fun acknowledgeTransferOffer(baseUrl: String, pin: String, id: String) {
        val query = URLEncoder.encode(id, Charsets.UTF_8.name())
        val conn = openTemporaryHttps(baseUrl, pin, "/api/transfer/item?id=$query").apply {
            requestMethod = "DELETE"
            connectTimeout = 10_000
            readTimeout = 10_000
            setRequestProperty("Connection", "close")
        }
        try {
            if (conn.responseCode != 204) throw SyncException("确认接收失败，HTTP ${conn.responseCode}")
        } finally {
            conn.disconnect()
        }
    }

    fun endTransfer(baseUrl: String, pin: String) {
        val conn = openTemporaryHttps(baseUrl, pin, "/api/transfer/end").apply {
            requestMethod = "POST"
            doOutput = true
            setFixedLengthStreamingMode(0)
            connectTimeout = 5_000
            readTimeout = 10_000
            setRequestProperty("Connection", "close")
        }
        try {
            conn.outputStream.use { }
            if (conn.responseCode != 204) throw SyncException("结束传输失败，HTTP ${conn.responseCode}")
        } finally {
            conn.disconnect()
        }
    }

    /** 断连时立即中止所有在途传输：关闭底层连接使阻塞的读/写抛错退出。 */
    fun abortTransfers() {
        inFlightTransfers.values.forEach { runCatching { it.disconnect() } }
        inFlightTransfers.clear()
    }

    /** 单条传输取消：关闭该传输项对应的底层连接，使阻塞的读/写立刻抛错退出。 */
    fun abortTransfer(key: String) {
        inFlightTransfers.remove(key)?.let { runCatching { it.disconnect() } }
    }

    internal fun isAllowedLanImportHost(host: String): Boolean {
        if (host.isBlank()) return false
        val literal = when {
            host.contains(':') -> host.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' || it == ':' || it == '.' }
            else -> host.all { it.isDigit() || it == '.' }
        }
        if (!literal) return false
        val address = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
        if (address.isAnyLocalAddress || address.isMulticastAddress) return false
        if (address.isLoopbackAddress || address.isLinkLocalAddress || address.isSiteLocalAddress) return true
        return address is Inet6Address && (address.address[0].toInt() and 0xfe) == 0xfc
    }

    private fun openTemporaryHttps(
        baseUrl: String,
        pin: String,
        path: String = "/api/sync/vault",
        opOverride: String? = null,
    ): HttpsURLConnection {
        if (pin.length != 6 || !pin.all(Char::isDigit)) throw SyncException("同步 PIN 格式无效")
        val ticket = pairingTicket(baseUrl)
        if (ticket.length < 12) throw SyncException("同步配对票据无效，请重新扫描二维码")
        // 通道按请求路径决定：传输端点走 transfer 通道，其余（同步/保活）走 sync 通道
        val op = opOverride ?: if (path.startsWith("/api/transfer/")) TRANSFER_OP else SYNC_OP
        val session = sessions.getOrPut(sessionKey(baseUrl, op)) { pair(baseUrl, pin, ticket, op) }
        return openHttps(baseUrl, path, session.certificateFingerprint).apply {
            setRequestProperty(PAIRING_HEADER, ticket)
            setRequestProperty(SESSION_HEADER, session.token)
        }
    }

    /** 成功导入后通知传输站关闭：使用导出通道会话，避免额外配对。 */
    fun cancelExportSession(baseUrl: String, pin: String) {
        val conn = openTemporaryHttps(baseUrl, pin, "/api/sync/cancel", EXPORT_OP).apply {
            requestMethod = "GET"
            connectTimeout = 5_000
            readTimeout = 5_000
            setRequestProperty("Connection", "close")
        }
        try {
            val code = conn.responseCode
            if (code != 204) throw SyncException("关闭传输站失败，HTTP $code")
        } finally {
            conn.disconnect()
        }
    }

    /**
     * 局域网导入（整库导出）：以导出通道连接传输站，等待主机“允许导出”后
     * 流式下载完整 .pmv 保险库到 [target]。首次拉库前 vault_id 未知，以零 UUID 占位。
     */
    suspend fun downloadVaultExport(
        baseUrl: String,
        pin: String,
        target: java.io.File,
        onWaitingForExport: () -> Unit = {},
        onProgress: ((Long, Long) -> Unit)? = null,
        onVerifying: () -> Unit = {},
        onVaultName: ((String?) -> Unit)? = null,
    ) {
        val ticket = pairingTicket(baseUrl)
        // 一次导入只下载一次：全程共用同一设备身份与同一配对会话。
        // 不做自动重试，避免整库被重复下载两次（进度 0→100% 走两遍）。
        val identity = com.vault.security.VaultDeviceIdentity.generate()
        try {
            runInterruptible {
                authenticateDevice(
                    baseUrl,
                    pin,
                    UUID(0L, 0L),
                    identity,
                    "read",
                    onWaitingForExport = onWaitingForExport,
                    sessionOp = EXPORT_OP,
                )
            }
            val conn = openTemporaryHttps(baseUrl, pin, "/api/sync/vault", EXPORT_OP)
            try {
                conn.requestMethod = "GET"
                conn.connectTimeout = 20_000
                conn.readTimeout = 120_000
                conn.setRequestProperty("Connection", "close")
                val code = conn.responseCode
                if (code != 200) {
                    val body = conn.errorStream
                        ?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                    throw SyncException("导出失败，HTTP $code：$body")
                }
                onVaultName?.invoke(
                    LanImportPolicy.decodeAccountName(
                        conn.getHeaderField(LanImportPolicy.ENCODED_NAME_HEADER),
                        conn.getHeaderField("X-Vault-Name"),
                    ),
                )
                val expectedSha = conn.getHeaderField("X-Vault-Sha256")
                val length = conn.contentLengthLong
                if (length !in 1..MAX_LAN_VAULT_BYTES) {
                    throw ExportIntegrityException("对方发送的数据大小无效或超过 10 GB")
                }
                if (expectedSha == null || !expectedSha.matches(Regex("[0-9a-fA-F]{64}"))) {
                    throw ExportIntegrityException("对方未提供有效的完整性校验信息")
                }
                val digest = MessageDigest.getInstance("SHA-256")
                var total = 0L
                runInterruptible {
                    target.outputStream().buffered().use { out ->
                        conn.inputStream.use { input ->
                            val buffer = ByteArray(STREAM_CHUNK_BYTES)
                            while (true) {
                                val count = input.read(buffer)
                                if (count < 0) break
                                total += count
                                if (total > length || total > MAX_LAN_VAULT_BYTES) {
                                    throw ExportIntegrityException("收到的数据超过预期大小，已停止保存")
                                }
                                digest.update(buffer, 0, count)
                                out.write(buffer, 0, count)
                                onProgress?.invoke(total, length)
                            }
                            out.flush()
                        }
                    }
                }
                onVerifying()
                if (total != length) {
                    throw ExportIntegrityException("收到的数据不完整，请重新接收")
                }
                val actual = digest.digest().joinToString("") { "%02x".format(it) }
                if (!MessageDigest.isEqual(
                        expectedSha.lowercase().toByteArray(Charsets.US_ASCII),
                        actual.toByteArray(Charsets.US_ASCII),
                    )
                ) {
                    throw ExportIntegrityException("收到的数据未通过安全检查，请重新接收")
                }
            } finally {
                conn.disconnect()
            }
        } finally {
            identity.close()
        }
    }

    private fun pair(baseUrl: String, pin: String, ticket: String, op: String): PairingSession {
        val start = try {
            Spake2P256.start(pin, ticket)
        } catch (error: IllegalArgumentException) {
            throw SyncException("同步 PIN 格式无效", error)
        }
        val requestBody = JSONObject()
            .put("version", SPAKE2_VERSION)
            .put("op", op)
            .put("share", encode(start.share))
            .toString().toByteArray()
        val conn = openUnauthenticatedHttps(baseUrl, "/api/sync/pair").apply {
            requestMethod = "POST"
            doOutput = true
            setFixedLengthStreamingMode(requestBody.size)
            connectTimeout = 10_000
            readTimeout = 20_000
            setRequestProperty("Connection", "close")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty(PAIRING_HEADER, ticket)
        }
        var fingerprint: ByteArray? = null
        try {
            conn.connect()
            fingerprint = certificateFingerprint(conn)
            conn.outputStream.use { it.write(requestBody) }
            val code = conn.responseCode
            if (code != 200) {
                val body = conn.errorStream?.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "错误响应")?.decodeToString() ?: ""
                throw SyncException("同步配对失败，HTTP $code：$body")
            }
            val json = JSONObject(conn.inputStream.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "配对响应").decodeToString())
            if (json.optString("version") != SPAKE2_VERSION) throw SyncException("对方设备不支持当前 SPAKE2 协议")
            val handshake = json.optString("handshake")
            val serverShare = decode(json.optString("share"), 65)
            if (handshake.length < 24) throw SyncException("同步配对响应无效")
            val result = Spake2P256.finish(
                start,
                serverShare,
                CLIENT_ID,
                SERVER_ID,
                spake2Aad(ticket, fingerprint, op),
                ticket,
            )
            try {
                confirmPairing(baseUrl, ticket, handshake, fingerprint, result)
                return PairingSession(encode(result.sessionToken), fingerprint.copyOf())
            } finally {
                result.clear()
            }
        } finally {
            requestBody.fill(0)
            conn.disconnect()
            fingerprint?.fill(0)
        }
    }

    private fun confirmPairing(
        baseUrl: String,
        ticket: String,
        handshake: String,
        fingerprint: ByteArray,
        result: Spake2P256.ClientResult,
    ) {
        val body = JSONObject()
            .put("handshake", handshake)
            .put("confirmation", encode(result.confirmation))
            .toString().toByteArray()
        val conn = openHttps(baseUrl, "/api/sync/pair/confirm", fingerprint).apply {
            requestMethod = "POST"
            doOutput = true
            setFixedLengthStreamingMode(body.size)
            connectTimeout = 10_000
            readTimeout = 15_000
            setRequestProperty("Connection", "close")
            setRequestProperty("Content-Type", "application/json")
            setRequestProperty(PAIRING_HEADER, ticket)
        }
        try {
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            if (code != 200) throw PinValidationException("PIN 码错误")
            val json = JSONObject(conn.inputStream.readBytesLimited(MAX_NETWORK_MESSAGE_BYTES, "配对确认").decodeToString())
            val confirmation = decode(json.optString("confirmation"), 32)
            if (json.optString("version") != SPAKE2_VERSION ||
                !MessageDigest.isEqual(confirmation, result.expectedServerConfirmation)
            ) {
                throw PinValidationException("PIN 码错误")
            }
            confirmation.fill(0)
        } finally {
            body.fill(0)
            conn.disconnect()
        }
    }

    private fun openUnauthenticatedHttps(baseUrl: String, path: String): HttpsURLConnection =
        openHttps(baseUrl, path, null)

    @Suppress("CustomX509TrustManager", "BadHostnameVerifier", "TrustAllX509TrustManager")
    private fun openHttps(baseUrl: String, path: String, expectedFingerprint: ByteArray?): HttpsURLConnection {
        // 局部、带理由地抑制：本同步通道以离线登记的证书指纹（expectedFingerprint）为唯一信任锚，
        // 主机名被有意忽略（绑定顺序为 先指纹比对、再建立 TLS）；expectedFingerprint 为空时仅用于
        // 显式配对以读取对端指纹，不会用于常规数据传输。
        val trustManager = object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                throw java.security.cert.CertificateException("不接受客户端证书")
            }
            override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
                if (chain.isNullOrEmpty()) throw java.security.cert.CertificateException("服务器未提供证书")
                if (expectedFingerprint != null) {
                    val actual = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded)
                    val matches = MessageDigest.isEqual(actual, expectedFingerprint)
                    actual.fill(0)
                    if (!matches) throw java.security.cert.CertificateException("同步服务器证书已变化")
                }
            }
        }
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
        return (endpoint(baseUrl, path).openConnection() as HttpsURLConnection).apply {
            sslSocketFactory = context.socketFactory
            hostnameVerifier = HostnameVerifier { _, _ -> true }
            instanceFollowRedirects = false
        }
    }

    private fun sessionKey(baseUrl: String, op: String = SYNC_OP): String =
        "${endpoint(baseUrl)}#${pairingTicket(baseUrl)}#$op"

    private fun certificateFingerprint(conn: HttpsURLConnection): ByteArray {
        val certificate = conn.serverCertificates.firstOrNull() as? X509Certificate
            ?: throw SyncException("服务器未提供有效证书")
        return MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
    }

    private fun spake2Aad(ticket: String, fingerprint: ByteArray, op: String): ByteArray =
        "Vault LAN Sync SPAKE2 RFC9382 v2\u0000".toByteArray() +
            op.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            ticket.toByteArray() + byteArrayOf(0) + fingerprint.toHex().toByteArray(Charsets.US_ASCII)

    private fun encode(value: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun encodeTextHeader(value: String): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8))

    private fun decode(value: String, expectedLength: Int): ByteArray {
        if (value.isBlank() || value.length > 2048 || value.any { !it.isLetterOrDigit() && it != '-' && it != '_' }) {
            throw SyncException("SPAKE2 响应编码无效，收到 ${value.length} 字符")
        }
        val raw = try { Base64.getUrlDecoder().decode(value) } catch (error: IllegalArgumentException) {
            throw SyncException("SPAKE2 响应编码无效，收到 ${value.length} 字符", error)
        }
        if (raw.size != expectedLength) throw SyncException("SPAKE2 响应长度无效，收到 ${raw.size} 字节，期望 $expectedLength 字节")
        return raw
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
