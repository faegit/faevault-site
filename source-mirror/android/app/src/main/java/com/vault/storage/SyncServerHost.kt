package com.vault.storage

import android.content.Context
import android.os.Environment
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.json.JSONArray
import org.json.JSONObject

/**
 * 局域网「传输站」HTTPS 服务端。协议与 PC 端 `sync_server.py` 逐字对齐：
 * 同 SPAKE2 配对、同端点、同会话/传输语义，使其他安卓/PC 客户端凭二维码或
 * 手动地址+PIN 连入本机，进行库同步与双向文件/文本互传。
 *
 * 本机扮演服务端：identity 仍固定为 `vault-android-client`/`vault-pc-server`
 * （协议级常量，与真实角色无关），从而与现有客户端保持 transcript 一致。
 */
class SyncServerHost(
    private val context: Context,
    private val vaultName: String,
) {
    /** Android 注册表中的 [vaultName] 已是真实账户名，不是带前缀的存储文件名。 */
    private fun exportedAccountName(): String = vaultName

    companion object {
        const val PORT = 18765
        const val SPAKE2_VERSION = "spake2-rfc9382-p256-sha256-v1"
        const val PAIRING_HEADER = "X-Vault-Sync-Ticket"
        const val SESSION_HEADER = "X-Vault-Sync-Session"

        val CLIENT_ID: ByteArray = "vault-android-client".toByteArray()
        val SERVER_ID: ByteArray = "vault-pc-server".toByteArray()

        private const val MAX_PAIRING_BODY = 4096
        private const val MAX_REQUEST_LINE_CHARS = 4096
        private const val MAX_HEADER_LINE_CHARS = 8192
        private const val MAX_HEADER_BYTES = 32 * 1024
        private const val MAX_HEADER_COUNT = 64
        private const val MAX_ACTIVE_CONNECTIONS = 16
        private const val HEADER_READ_TIMEOUT_MS = 15_000
        private const val MAX_SYNC_BYTES = 10L * 1024L * 1024L * 1024L
        /** 传输溢出护栏：与 PC 端对齐为 10 TiB；>10 GiB 仅由 UI 单次提示，不做传输限制。 */
        const val MAX_TRANSFER_BYTES = 10L * 1024L * 1024L * 1024L * 1024L
        private const val MAX_TRANSFER_TEXT_BYTES = 1024 * 1024
        private const val MAX_AUTH_FAILURES = 10
        private const val PAIRING_TIMEOUT_MS = 180_000L
        /** 活跃会话空闲超时：PC 客户端每 15s 保活，40s 足以区分健康会话与断连，避免“过一会才识别断开”。 */
        private const val ACTIVE_IDLE_TIMEOUT_MS = 40_000L
        /**
         * 文件选择器、后台切换和系统省电可能暂停轮询几十秒；给 transfer 2 分钟失联宽限。
         * 正常退出仍由 /api/transfer/end 立即关闭，6 小时硬超时保持不变。
         */
        private const val TRANSFER_IDLE_TIMEOUT_MS = 120_000L
        private const val SESSION_HARD_TIMEOUT_MS = 900_000L
        private const val TRANSFER_SESSION_HARD_TIMEOUT_MS = 6L * 60L * 60L * 1000L
        private const val CERT_VALIDITY_MS = TRANSFER_SESSION_HARD_TIMEOUT_MS + 120_000L
        private const val HANDSAKE_DEADLINE_MS = 30_000L
        private const val CHUNK = 64 * 1024
        /** 同步连接码（PIN）周期刷新间隔：避免被拍照的二维码/PIN 长时间可用（120 秒）。 */
        private const val PIN_ROTATE_INTERVAL_MS = 120_000L
        /** 同步配对声明的会话通道：sync=双向同步，transfer=文件互传，export=仅导出拉库。 */
        const val SYNC_OP = "sync"
        const val TRANSFER_OP = "transfer"
        const val EXPORT_OP = "export"

        /**
         * 导出下发完成后的兜底关闭宽限期。
         *
         * 客户端校验并入库通常只需几秒，期间它会发 cancel 让本机立即关闭；这段宽限
         * 只兜住「客户端没发」的情况（例如它在校验阶段就退出了）。给得比正常 cancel
         * 慢，客户端先到先关，不会被这里拖住。
         */
        private const val EXPORT_AUTO_CLOSE_GRACE_MS = 30_000L
    }

    /** 库同步异常：code 为返回给客户端的 HTTP 状态码。 */
    class HostError(val code: Int, override val message: String) : Exception(message)

    /** 接收端收到客户端推送的 .pmv 后处理入库，返回合并统计 JSON 字符串。 */
    fun interface VaultHandler {
        fun onReceiveVault(file: File): String
    }

    /** 接收端收到客户端上传的传输文件后落地，返回展示路径。 */
    fun interface TransferSink {
        fun onReceive(file: File, name: String, mime: String, kind: String): String
    }

    data class HostItem(
        val id: String,
        val name: String,
        /** 文本传输的内容预览（首行截断）；文件传输为空。 */
        val textPreview: String = "",
        val kind: String,
        val size: Long,
        val direction: String,
        val status: String,
        val path: String,
        val transferred: Long,
    )

    data class HostStatus(
        val running: Boolean = false,
        val url: String = "",
        val pin: String = "",
        val paired: Boolean = false,
        val pairSeq: Int = 0,
        val op: String = "",
        val items: List<HostItem> = emptyList(),
        val error: String? = null,
        /** 对方设备 ID（未接入时为空）。界面只显示前几位，够用户核对即可。 */
        val peerDeviceId: String? = null,
        /** 对方公钥的 SHA-256 前 24 位十六进制；与同步/互传确认弹窗里显示的是同一个值。 */
        val peerFingerprint: String = "",
        /** 对方 IP。 */
        val peerAddress: String = "",
        /** 认证通过的时刻（墙钟毫秒）；界面据此算连接时长。 */
        val peerConnectedAtMillis: Long = 0L,
    )

    private val _status = MutableStateFlow(HostStatus())
    val status: StateFlow<HostStatus> = _status.asStateFlow()

    var vaultHandler: VaultHandler? = null
    var transferSink: TransferSink? = null

    /** 设备授权提供者：由已解锁调用方注入（PMVE 库）；null 表示设备认证不可用。 */
    interface DeviceAuthProvider {
        fun registry(): PmvSyncAuthorization.AuthorizationRegistry?
        fun enrollExportDevice(deviceId: UUID, devicePublicKey: ByteArray): Boolean
        fun enrollSyncDevice(deviceId: UUID, devicePublicKey: ByteArray): Boolean
    }
    var deviceAuthProvider: DeviceAuthProvider? = null

    /** 收到未授权同步设备的认证请求时回调（主机需确认后才能允许其读写本机库）。 */
    var onSyncApprovalPending: ((sessionToken: String, deviceId: UUID) -> Unit)? = null
    var onExportApprovalPending: ((sessionToken: String, deviceId: UUID?) -> Unit)? = null
    var onTransferApprovalPending: ((sessionToken: String, deviceId: UUID) -> Unit)? = null

    /** 同步请求在传输敏感数据前被拒绝时，把可操作原因同步给传输站界面。 */
    var onSyncRejected: ((String) -> Unit)? = null

    /** 会话自行结束时（超时/客户端取消）回调；[reason] 为 null 表示用户主动停止。 */
    var onStopped: ((reason: String?) -> Unit)? = null

    /** 双向同步成功合并完成后回调：用于传输站“合并后立即断开连接”。 */
    var onSyncCompleted: (() -> Unit)? = null
    var onSyncStarted: (() -> Unit)? = null
    /** 主机侧同步数据传输进度：发送（拉取）方向。 */
    var onVaultSendProgress: ((transferred: Long, total: Long) -> Unit)? = null
    /** 主机侧同步数据传输进度：接收（回推）方向。 */
    var onVaultReceiveProgress: ((transferred: Long, total: Long) -> Unit)? = null

    private var serverSocket: SSLServerSocket? = null
    private val activeConnections = ConcurrentHashMap.newKeySet<Socket>()
    private val activeConnectionCount = AtomicInteger(0)
    private val running = AtomicBoolean(false)
    private val startedAt = AtomicLong(0)
    private val accessTime = AtomicLong(0)
    private val authenticatedAt = AtomicLong(0)
    private val transferActive = AtomicBoolean(false)
    private val paired = AtomicBoolean(false)
    private val pairCount = AtomicInteger(0)
    private val authFailureBudget = LanAuthFailureBudget(maxFailures = MAX_AUTH_FAILURES)
    /** 已配对会话按令牌隔离通道、设备授权与导出门控，后配对者不会覆盖旧会话。 */
    private val sessions = LanSessionRegistry()
    /** 未确认握手按 handshake ID 隔离，避免并发扫码互相覆盖。 */
    private val pendingHandshakes = ConcurrentHashMap<String, Handshake>()
    @Volatile private var pendingSyncApprovalSession: LanSessionRegistry.Session? = null
    @Volatile private var pendingExportApprovalSession: LanSessionRegistry.Session? = null
    @Volatile private var pendingTransferApprovalSession: LanSessionRegistry.Session? = null
    /** 仅用于 UI 展示最近连接的通道，不参与任何权限判断。 */
    @Volatile private var latestOp = SYNC_OP

    private var pinRotator: ScheduledExecutorService? = null

    @Volatile private var pin = ""
    private var ticket = ""
    private var certFingerprint = ""
    @Volatile private var url = ""
    private var host = ""

    private val registry = VaultRegistry(context)
    private val tempDir = File(context.cacheDir, "vault-host-transfer").apply { mkdirs() }
    private val receiveDir = (context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
        ?.resolve("Vaultshare") ?: File(context.filesDir, "Vaultshare")).apply { mkdirs() }

    private val transferLock = Any()
    private val outgoing = LinkedHashMap<String, TransferItem>()
    private val received = mutableListOf<TransferItem>()
    private val sent = mutableListOf<TransferItem>()
    /** 单条传输正在服务的连接（按传输项 id）：取消该条目时关闭连接以中断阻塞读写。 */
    private val activeItemConnections = ConcurrentHashMap<String, Socket>()

    private class TransferItem(
        val id: String,
        val name: String,
        val mime: String,
        val kind: String,
        val size: Long,
        @Volatile var sha256: String,
        val sourcePath: File?,
        val temporary: Boolean,
        @Volatile var preview: String = "",
        @Volatile var transferred: Long,
        @Volatile var status: String,
        @Volatile var path: String = "",
        @Volatile var canceled: Boolean = false,
    )

    private data class Handshake(
        val value: String,
        val result: Spake2P256.ServerResult,
        val deadline: Long,
        val op: String,
    )

    /** 启动传输站，返回 (url, pin)。 */
    fun start(): Pair<String, String> {
        if (serverSocket != null) throw IllegalStateException("传输站已在运行")
        val host = localIp()
        this.host = host
        ticket = secureToken(18)
        pin = "%06d".format(SecureRandom().nextInt(1_000_000))
        url = "https://$host:$PORT/api/sync/vault?ticket=$ticket&pin=$pin"

        val (sslContext, fingerprint, _) = generateCertificate(host)
        certFingerprint = fingerprint

        val socket = sslContext.serverSocketFactory.createServerSocket(
            PORT, 16, InetAddress.getByName("0.0.0.0"),
        ) as SSLServerSocket
        socket.reuseAddress = true
        socket.soTimeout = 1_000
        socket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")
        serverSocket = socket

        running.set(true)
        startedAt.set(System.currentTimeMillis())
        accessTime.set(System.currentTimeMillis())
        _status.value = HostStatus(running = true, url = url, pin = pin)
        Thread {
            while (running.get()) {
                val client = try {
                    socket.accept()
                } catch (error: SocketTimeoutException) {
                    continue
                } catch (error: Exception) {
                    break
                }
                if (!running.get()) {
                    runCatching { client.close() }
                    break
                }
                if (activeConnectionCount.incrementAndGet() > MAX_ACTIVE_CONNECTIONS) {
                    activeConnectionCount.decrementAndGet()
                    runCatching { client.close() }
                    continue
                }
                // 认证前只给 15 秒提交完整请求头，避免慢速连接长期占用线程。
                runCatching { client.soTimeout = HEADER_READ_TIMEOUT_MS }
                activeConnections.add(client)
                if (!running.get()) {
                    activeConnections.remove(client)
                    activeConnectionCount.decrementAndGet()
                    runCatching { client.close() }
                    break
                }
                Thread { handleConnection(client) }.apply {
                    name = "vault-host-conn"
                    isDaemon = true
                }.start()
            }
        }.apply { name = "vault-host-accept"; isDaemon = true }.start()
        startMonitor()
        pinRotator = Executors.newSingleThreadScheduledExecutor { runnable ->
            Thread(runnable, "vault-host-pin-rotator").apply { isDaemon = true }
        }
        pinRotator?.scheduleAtFixedRate(
            { runCatching { rotatePin() } },
            PIN_ROTATE_INTERVAL_MS, PIN_ROTATE_INTERVAL_MS, TimeUnit.MILLISECONDS,
        )
        return url to pin
    }

    /** 配对凭据只用于建立新会话；已有会话由不可预测的会话令牌维持。 */
    @Synchronized
    private fun rotatePin() {
        val now = System.currentTimeMillis()
        pendingHandshakes.entries.removeIf { (_, handshake) ->
            if (now > handshake.deadline) {
                handshake.result.clear()
                true
            } else false
        }
        // 进行中的 SPAKE2 配对已绑定旧 PIN，此时轮换会打断握手，跳过本轮
        if (pendingHandshakes.isNotEmpty()) return
        pin = "%06d".format(SecureRandom().nextInt(1_000_000))
        ticket = secureToken(18)
        url = "https://$host:$PORT/api/sync/vault?ticket=$ticket&pin=$pin"
        if (running.get()) {
            _status.value = _status.value.copy(url = url, pin = pin)
        }
    }

    /** 主动停止传输站。 */
    fun stop() = stopInternal(null)

    /**
     * 断开当前接入的设备，但传输站继续监听、可再接新设备。
     *
     * 与 [stop] 的区别是不拆监听：只断连接、清配对会话与传输态，并复位状态标志，
     * 让 UI 立刻回到「等待接入」。主机侧原先没有这个能力，UI 上的「断开连接」
     * 只能退出传输页而并没有真的断开对方。
     */
    fun disconnectPeer() {
        if (!running.get()) return
        activeConnections.toList().forEach { runCatching { it.close() } }
        activeConnections.clear()
        activeItemConnections.clear()
        // 会话按认证时刻回溯定位（与 peerIdentity 同一口径），清掉即解除配对。
        sessions.sessions()
            .filter { it.authenticatedAtMillis == authenticatedAt.get() }
            .forEach { sessions.remove(it.token) }
        authenticatedAt.set(0L)
        paired.set(false)
        transferActive.set(false)
        latestOp = ""
        updateStatus()
    }

    private fun stopInternal(reason: String?) {
        if (!running.getAndSet(false)) return
        runCatching { serverSocket?.close() }
        serverSocket = null
        activeConnections.toList().forEach { runCatching { it.close() } }
        activeConnections.clear()
        activeItemConnections.clear()
        pinRotator?.shutdownNow()
        pinRotator = null
        pendingHandshakes.values.forEach { it.result.clear() }
        pendingHandshakes.clear()
        sessions.clear()
        // 会话标志一并复位：停机后若 transferActive 仍为真，下一次 updateStatus()
        // 会把「传输中」重新发布出去，UI 就继续显示「断开连接」，必须手动点一次
        // 才收口。paired/latestOp 同理，避免停机后又被判成有对端在会话中。
        paired.set(false)
        transferActive.set(false)
        latestOp = ""
        authenticatedAt.set(0L)
        synchronized(transferLock) {
            received.forEach { it.status = if (it.status == "接收中") "已中断" else it.status }
            outgoing.values.forEach {
                it.status = if (it.status == "等待接收") "已中断" else it.status
                // 剪贴板/选择器等临时来源：传输站停止后不再引用，删除缓存文件。
                if (it.temporary) runCatching { it.sourcePath?.delete() }
            }
        }
        _status.value = HostStatus(
            running = false,
            error = reason,
            items = currentItems(),
        )
        onStopped?.invoke(reason)
    }

    private fun startMonitor() {
        Thread {
            while (running.get()) {
                Thread.sleep(5_000)
                if (!running.get()) break
                val now = System.currentTimeMillis()
                val authenticated = authenticatedAt.get()
                when {
                    authenticated == 0L && now - startedAt.get() > PAIRING_TIMEOUT_MS -> {
                        stopInternal("等待连接超时")
                    }
                    authenticated > 0L -> {
                        val transfer = transferActive.get()
                        val hard = if (transfer) TRANSFER_SESSION_HARD_TIMEOUT_MS else SESSION_HARD_TIMEOUT_MS
                        val idle = if (transfer) TRANSFER_IDLE_TIMEOUT_MS else ACTIVE_IDLE_TIMEOUT_MS
                        when {
                            now - authenticated > hard -> stopInternal("会话已超时")
                            now - accessTime.get() > idle -> stopInternal("连接已断开")
                        }
                    }
                }
            }
        }.apply { name = "vault-host-monitor"; isDaemon = true }.start()
    }

    // ── 对外：排队待发送内容（用户从本机挑选文件/文本发往连入设备） ─────────

    fun queueTransferFile(source: File, name: String?, mime: String?, kind: String, temporary: Boolean = false): HostItem {
        if (source.length() > MAX_TRANSFER_BYTES) throw IllegalArgumentException("发送文件超过 10 TiB 溢出护栏")
        val safeName = sanitizeName(name ?: source.name)
        val item = TransferItem(
            id = UUID.randomUUID().toString(),
            name = safeName,
            mime = (mime ?: guessMime(safeName)).take(255),
            kind = if (kind == "text") "text" else "file",
            size = source.length(),
            sha256 = "",
            sourcePath = source,
            temporary = temporary,
            preview = "",
            transferred = 0L,
            status = "等待接收",
        )
        synchronized(transferLock) { outgoing[item.id] = item }
        Thread {
            item.sha256 = sha256File(source)
            updateStatus()
        }.also { it.name = "vault-host-digest"; it.isDaemon = true }.start()
        updateStatus()
        return item.toHostItem("outgoing", "等待接收")
    }

    fun queueTransferText(text: String): HostItem {
        val encoded = text.toByteArray(Charsets.UTF_8)
        if (encoded.size > MAX_TRANSFER_TEXT_BYTES) throw IllegalArgumentException("发送文本超过 1 MB 安全限制")
        val id = UUID.randomUUID().toString()
        val staged = File(tempDir, "text-$id.txt")
        staged.writeBytes(encoded)
        val queued = queueTransferFile(
            staged,
            name = "message_${SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())}.txt",
            mime = "text/plain; charset=utf-8",
            kind = "text",
        )
        // 记录文本预览：传输列表要显示内容本身，而不是上面那个生成的文件名。
        synchronized(transferLock) {
            outgoing[queued.id]?.preview = text.lineSequence().firstOrNull().orEmpty().take(80)
        }
        updateStatus()
        return queued.copy(textPreview = text.lineSequence().firstOrNull().orEmpty().take(80))
    }

    // ── HTTP 处理 ─────────────────────────────────────────────────────────

    private inner class HttpRequest(
        val method: String,
        val path: String,
        val query: String,
        val headers: Map<String, String>,
        val input: InputStream,
        val contentLength: Long,
        val remoteAddress: String,
    ) {
        fun readBody(cap: Long): ByteArray =
            if (contentLength > 0) input.readExact(minOf(contentLength, cap)) else ByteArray(0)

        fun streamToFile(target: File, onChunk: (transferred: Long) -> Unit = { _ -> }): Long {
            var total = 0L
            val buffer = ByteArray(CHUNK)
            target.outputStream().buffered().use { output ->
                while (total < contentLength) {
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), contentLength - total).toInt())
                    if (count < 0) throw EOFException("连接已断开")
                    output.write(buffer, 0, count)
                    total += count
                    onChunk(total)
                    // 大文件上传期间持续刷新活跃时间，避免空闲超时误杀进行中的传输
                    accessTime.set(System.currentTimeMillis())
                }
            }
            return total
        }
    }

    private fun handleConnection(socket: Socket) {
        try {
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            val request = try {
                readRequest(input, output, socket.inetAddress.hostAddress.orEmpty())
            } catch (error: HostError) {
                sendError(output, error.code, error.message)
                return
            } ?: return
            // 请求头已完整且边界检查通过；大文件流允许正常的分块读取等待。
            socket.soTimeout = 120_000
            accessTime.set(System.currentTimeMillis())
            dispatch(request, output, socket)
        } catch (_: Exception) {
            // 连接中断/解析失败：静默关闭
        } finally {
            activeConnections.remove(socket)
            activeConnectionCount.decrementAndGet()
            runCatching { socket.close() }
        }
    }

    private fun readRequest(input: InputStream, output: OutputStream, remoteAddress: String): HttpRequest? {
        val requestLine = input.readLineCrLf(MAX_REQUEST_LINE_CHARS) ?: return null
        if (requestLine.isBlank()) return null
        val parts = requestLine.split(' ')
        if (parts.size != 3 || parts[2] != "HTTP/1.1") throw HostError(400, "Bad Request")
        val method = parts[0]
        val rawPath = parts[1]
        if (!rawPath.startsWith('/') || rawPath.length > MAX_REQUEST_LINE_CHARS) throw HostError(400, "Bad Request")
        val path = rawPath.substringBefore('?')
        val query = rawPath.substringAfter('?', "")

        val headers = LinkedHashMap<String, String>()
        var headerBytes = 0
        while (true) {
            val line = input.readLineCrLf(MAX_HEADER_LINE_CHARS) ?: throw HostError(400, "Bad Request")
            if (line.isBlank()) break
            headerBytes += line.length + 2
            if (headerBytes > MAX_HEADER_BYTES || headers.size >= MAX_HEADER_COUNT) throw HostError(431, "Request Header Fields Too Large")
            val idx = line.indexOf(':')
            if (idx <= 0) throw HostError(400, "Bad Request")
            val name = line.substring(0, idx).trim().lowercase(Locale.US)
            if (name.isEmpty() || name.any { !it.isLetterOrDigit() && it != '-' }) throw HostError(400, "Bad Request")
            if (headers.putIfAbsent(name, line.substring(idx + 1).trim()) != null) throw HostError(400, "Bad Request")
        }
        if (headers.containsKey("transfer-encoding")) throw HostError(400, "Bad Request")
        val contentLength = headers["content-length"]?.let {
            it.toLongOrNull()?.takeIf { value -> value >= 0L } ?: throw HostError(400, "Bad Request")
        } ?: 0L
        if (headers["expect"]?.lowercase(Locale.US) == "100-continue") {
            output.write("HTTP/1.1 100 Continue\r\n\r\n".toByteArray(Charsets.US_ASCII))
            output.flush()
        }
        return HttpRequest(method, path, query, headers, input, contentLength, remoteAddress)
    }

    private fun dispatch(req: HttpRequest, output: OutputStream, socket: Socket) {
        try {
            when {
                req.method == "POST" && req.path == "/api/sync/pair" -> handlePair(req, output)
                req.method == "POST" && req.path == "/api/sync/pair/confirm" -> handlePairConfirm(req, output)
                req.method == "POST" && req.path == "/api/auth/challenge" -> requireSession(req, output) { session ->
                    requireOp(session, output, SYNC_OP, EXPORT_OP, TRANSFER_OP) { handleDeviceChallenge(session, req, output) }
                }
                req.method == "POST" && req.path == "/api/auth/challenge/confirm" -> requireSession(req, output) { session ->
                    requireOp(session, output, SYNC_OP, EXPORT_OP, TRANSFER_OP) { handleDeviceChallengeConfirm(session, req, output) }
                }
                req.method == "GET" && req.path == "/api/sync/vault" -> requireSession(req, output) { session -> requireOp(session, output, SYNC_OP, EXPORT_OP) { handleVaultGet(session, output) } }
                req.method == "PUT" && req.path == "/api/sync/vault" -> requireSession(req, output) { session -> requireOp(session, output, SYNC_OP) { handleVaultPut(session, req, output) } }
                req.method == "GET" && req.path == "/api/sync/keepalive" -> requireSession(req, output) { _ -> sendNoContent(output) }
                req.method == "GET" && req.path == "/api/sync/cancel" -> requireSession(req, output) { _ ->
                    sendNoContent(output)
                    stopInternal("客户端已断开")
                }
                req.method == "GET" && req.path == "/api/transfer/items" -> requireSession(req, output) { session -> requireOp(session, output, TRANSFER_OP) { requireTransferAuthorized(session, output) { handleTransferItems(output) } } }
                req.method == "GET" && req.path == "/api/transfer/item" -> requireSession(req, output) { session -> requireOp(session, output, TRANSFER_OP) { requireTransferAuthorized(session, output) { handleTransferDownload(req, output, socket) } } }
                req.method == "PUT" && req.path == "/api/transfer/item" -> requireSession(req, output) { session -> requireOp(session, output, TRANSFER_OP) { requireTransferAuthorized(session, output) { handleTransferUpload(req, output, socket) } } }
                req.method == "DELETE" && req.path == "/api/transfer/item" -> requireSession(req, output) { session -> requireOp(session, output, TRANSFER_OP) { requireTransferAuthorized(session, output) { handleTransferAck(req, output) } } }
                req.method == "POST" && req.path == "/api/transfer/end" -> requireSession(req, output) { session ->
                    requireOp(session, output, TRANSFER_OP) {
                        requireTransferAuthorized(session, output) {
                            sendNoContent(output)
                            // 对端主动断开：会话标志必须在 stopInternal 之前清掉。
                            // 原先这里误写成 transferActive.set(true)，与随后的停机
                            // 相矛盾——状态位仍是「传输中」，下一次 updateStatus() 会把
                            // 传输中重新发布出去，UI 于是继续显示「断开连接」，
                            // 用户必须手动点一次才收口。
                            transferActive.set(false)
                            stopInternal("对方已关闭连接")
                        }
                    }
                }
                else -> sendError(output, 404, "Not Found")
            }
        } catch (error: HostError) {
            sendJsonError(output, error.code, error.message)
        } catch (error: Exception) {
            val detail = error.message.orEmpty().trim().take(200)
            sendJsonError(
                output,
                500,
                if (detail.isBlank()) "传输站处理请求失败，未返回具体原因" else "传输站处理请求失败：$detail",
            )
        }
    }

    private inline fun requireSession(req: HttpRequest, output: OutputStream, block: (LanSessionRegistry.Session) -> Unit) {
        val session = findSession(req)
        if (session == null) {
            sendError(output, 403, "Forbidden")
            return
        }
        block(session)
    }

    /** 通道权限：仅当当前会话声明的通道属于 [allowed] 时才放行，否则 403。 */
    private inline fun requireOp(session: LanSessionRegistry.Session, output: OutputStream, vararg allowed: String, block: () -> Unit) {
        if (session.op in allowed) block() else sendError(output, 403, "Forbidden")
    }

    private inline fun requireTransferAuthorized(session: LanSessionRegistry.Session, output: OutputStream, block: () -> Unit) {
        if (session.transferApproved.get() && session.authorizedDeviceId != null) block()
        else sendJsonError(output, 403, "设备尚未完成本次传输确认")
    }

    private fun findSession(req: HttpRequest): LanSessionRegistry.Session? {
        val sessionHeader = req.headers[SESSION_HEADER.lowercase(Locale.US)]
        if (sessionHeader.isNullOrBlank()) return null
        return sessions.find(sessionHeader)
    }

    private fun isAuthLocked(remoteAddress: String): Boolean {
        return authFailureBudget.isLocked(remoteAddress)
    }

    private fun recordAuthFailure(remoteAddress: String) {
        authFailureBudget.recordFailure(remoteAddress)
    }

    // ── 端点 ──────────────────────────────────────────────────────────────

    private fun handlePair(req: HttpRequest, output: OutputStream) {
        if (isAuthLocked(req.remoteAddress)) {
            sendError(output, 403, "Forbidden")
            return
        }
        val ticketHeader = req.headers[PAIRING_HEADER.lowercase(Locale.US)].orEmpty()
        if (!MessageDigest.isEqual(ticket.toByteArray(), ticketHeader.toByteArray())) {
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        if (req.contentLength !in 1..MAX_PAIRING_BODY) {
            sendError(output, 400, "Bad Request")
            return
        }
        val json = org.json.JSONObject(String(req.readBody(MAX_PAIRING_BODY.toLong()), Charsets.UTF_8))
        if (json.optString("version") != SPAKE2_VERSION) {
            sendError(output, 400, "Bad Request")
            return
        }
        // 通道声明：sync=双向同步，transfer=文件互传，export=仅导出拉库。绑定进 SPAKE2 AAD，配对后不可更改。
        val op = json.optString("op", SYNC_OP)
        if (op != SYNC_OP && op != TRANSFER_OP && op != EXPORT_OP) {
            sendError(output, 400, "Bad Request")
            return
        }
        val clientShare = try {
            b64decode(json.optString("share"), 65)
        } catch (_: Exception) {
            sendError(output, 400, "Bad Request")
            return
        }
        val start = Spake2P256.serverStart(pin, ticket)
        val result = try {
            Spake2P256.serverFinish(start, clientShare, CLIENT_ID, SERVER_ID, spake2Aad(op), ticket)
        } catch (_: IllegalArgumentException) {
            clientShare.fill(0)
            start.share.fill(0)
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        clientShare.fill(0)
        val shareEncoded = b64encode(start.share)
        start.share.fill(0)
        val handshake = secureToken(24)
        pendingHandshakes.put(handshake, Handshake(handshake, result, System.currentTimeMillis() + HANDSAKE_DEADLINE_MS, op))
        val body = JSONObject()
            .put("version", SPAKE2_VERSION)
            .put("handshake", handshake)
            .put("share", shareEncoded)
        sendJson(output, 200, body)
    }

    private fun handlePairConfirm(req: HttpRequest, output: OutputStream) {
        if (isAuthLocked(req.remoteAddress)) {
            sendError(output, 403, "Forbidden")
            return
        }
        val ticketHeader = req.headers[PAIRING_HEADER.lowercase(Locale.US)].orEmpty()
        if (!MessageDigest.isEqual(ticket.toByteArray(), ticketHeader.toByteArray())) {
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        val bodyBytes = try { req.readBody(MAX_PAIRING_BODY.toLong()) } catch (_: Exception) { ByteArray(0) }
        val json = try {
            org.json.JSONObject(String(bodyBytes, Charsets.UTF_8))
        } catch (_: Exception) {
            recordAuthFailure(req.remoteAddress)
            sendError(output, 400, "Bad Request")
            return
        } finally {
            bodyBytes.fill(0)
        }
        val handshakeId = json.optString("handshake")
        val pending = pendingHandshakes.remove(handshakeId)
        if (pending == null || System.currentTimeMillis() > pending.deadline) {
            pending?.result?.clear()
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        if (json.optString("handshake") != pending.value) {
            pending.result.clear()
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        val confirmation = try {
            b64decode(json.optString("confirmation"), 32)
        } catch (_: Exception) {
            pending.result.clear()
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        if (!MessageDigest.isEqual(confirmation, pending.result.confirmationA)) {
            confirmation.fill(0)
            pending.result.clear()
            recordAuthFailure(req.remoteAddress)
            sendError(output, 403, "Forbidden")
            return
        }
        confirmation.fill(0)
        val session = b64encode(pending.result.sessionToken)
        val confirmationB = b64encode(pending.result.confirmationB)
        pending.result.clear()
        sessions.add(session, pending.op)
        authenticatedAt.compareAndSet(0L, System.currentTimeMillis())
        paired.set(true)
        pairCount.incrementAndGet()
        latestOp = pending.op
        // 一次性连接码：配对成功后立即轮换，旧 PIN 不能再用于新配对
        rotatePin()
        updateStatus()
        sendJson(output, 200, JSONObject()
            .put("version", SPAKE2_VERSION)
            .put("confirmation", confirmationB))
    }

    /** 允许已配对客户端拉取本机保险库（导出确认）。 */
    fun approveExport(sessionToken: String): Boolean {
        val session = sessions.find(sessionToken) ?: return false
        if (session.op != EXPORT_OP) return false
        val pending = session.pendingExportDevice
        if (pending != null) {
            val enrolled = runCatching {
                deviceAuthProvider?.enrollExportDevice(pending.first, pending.second) == true
            }.getOrDefault(false)
            if (!enrolled) return false
            pending.second.fill(0)
            session.pendingExportDevice = null
        }
        pendingExportApprovalSession = pendingExportApprovalSession?.takeUnless { it.token == sessionToken }
        session.exportApproved.set(true)
        return true
    }

    /** 对当前 transfer 会话进行一次性设备确认，并只为该设备签发短期只读授权。 */
    fun approveTransfer(sessionToken: String): Boolean {
        val session = pendingTransferApprovalSession ?: return false
        if (session.token != sessionToken) return false
        if (session.op != TRANSFER_OP) return false
        val pending = session.pendingTransferDevice ?: return false
        val enrolled = runCatching {
            deviceAuthProvider?.enrollExportDevice(pending.first, pending.second) == true
        }.getOrDefault(false)
        if (!enrolled) return false
        pending.second.fill(0)
        session.pendingTransferDevice = null
        pendingTransferApprovalSession = null
        session.transferApproved.set(true)
        return true
    }

    fun rejectTransfer(sessionToken: String) {
        pendingTransferApprovalSession?.takeIf { it.token == sessionToken }?.let { session ->
            session.pendingTransferDevice?.second?.fill(0)
            session.pendingTransferDevice = null
            session.transferApproved.set(false)
            sessions.remove(sessionToken)
        }
        pendingTransferApprovalSession = null
    }

    /** 允许已配对客户端读写本机保险库（同步确认）。 */
    fun approveSync(sessionToken: String): Boolean {
        val session = sessions.find(sessionToken) ?: return false
        if (session.op != SYNC_OP) return false
        val pending = session.pendingSyncDevice ?: return false
        val enrolled = runCatching {
            deviceAuthProvider?.enrollSyncDevice(pending.first, pending.second) == true
        }.getOrDefault(false)
        if (!enrolled) return false
        pending.second.fill(0)
        session.pendingSyncDevice = null
        pendingSyncApprovalSession = pendingSyncApprovalSession?.takeUnless { it.token == sessionToken }
        return true
    }

    fun rejectExport(sessionToken: String) {
        sessions.remove(sessionToken)
        pendingExportApprovalSession = pendingExportApprovalSession?.takeUnless { it.token == sessionToken }
    }

    fun rejectSync(sessionToken: String) {
        sessions.remove(sessionToken)
        pendingSyncApprovalSession = pendingSyncApprovalSession?.takeUnless { it.token == sessionToken }
    }

    // ── 设备授权（Challenge-Response） ──────────────────────────────────

    private fun handleDeviceChallenge(session: LanSessionRegistry.Session, req: HttpRequest, output: OutputStream) {
        val provider = deviceAuthProvider
        val registry = provider?.registry()
        if (registry == null) {
            sendJsonError(output, 500, "设备认证未就绪")
            return
        }
        val request = try {
            DeviceAuthWire.parseChallengeRequest(req.readBody(MAX_PAIRING_BODY.toLong()).decodeToString())
        } catch (error: Exception) {
            sendJsonError(output, 400, error.message ?: "Bad Request")
            return
        }
        if (session.op == TRANSFER_OP && !session.transferApproved.get()) {
            session.pendingTransferDevice?.second?.fill(0)
            session.pendingTransferDevice = request.deviceId to request.devicePublicKey.copyOf()
            pendingTransferApprovalSession = session
            onTransferApprovalPending?.invoke(session.token, request.deviceId)
            sendJsonError(output, 423, "等待主机确认文件传输")
            return
        }
        if (!registry.isAuthorized(request.deviceId, request.operation)) {
            when (session.op) {
                EXPORT_OP -> {
                    session.pendingExportDevice?.second?.fill(0)
                    session.pendingExportDevice = request.deviceId to request.devicePublicKey.copyOf()
                    pendingExportApprovalSession = session
            onExportApprovalPending?.invoke(session.token, request.deviceId)
                    sendJsonError(output, 423, "等待主机确认导出")
                }
                SYNC_OP -> {
                    session.pendingSyncDevice?.second?.fill(0)
                    session.pendingSyncDevice = request.deviceId to request.devicePublicKey.copyOf()
                    pendingSyncApprovalSession = session
                    onSyncApprovalPending?.invoke(session.token, request.deviceId)
                    sendJsonError(output, 423, "等待主机确认同步")
                }
                else -> sendJsonError(output, 403, "设备未授权或已撤销")
            }
            return
        }
        try {
            val encoded = DeviceAuthWire.ServerGate(registry).issue(request)
            session.pendingChallenge?.fill(0)
            session.pendingChallenge = encoded.copyOf()
            sendJson(output, 200, JSONObject(DeviceAuthWire.challengeResponse(encoded)))
        } catch (error: IllegalArgumentException) {
            val message = if (error.message?.contains("不属于本保险库") == true) {
                "两端不是同一份保险库，保险库 ID 不一致；未读取或写入任何保险库数据"
            } else {
                error.message ?: "设备未授权"
            }
            if (session.op == SYNC_OP) onSyncRejected?.invoke(message)
            sendJsonError(output, 403, message)
        }
    }

    private fun handleDeviceChallengeConfirm(session: LanSessionRegistry.Session, req: HttpRequest, output: OutputStream) {
        val provider = deviceAuthProvider
        val registry = provider?.registry()
        if (registry == null) {
            sendJsonError(output, 500, "设备认证未就绪")
            return
        }
        val confirm = try {
            DeviceAuthWire.parseConfirmRequest(req.readBody(MAX_PAIRING_BODY.toLong()).decodeToString())
        } catch (error: Exception) {
            sendJsonError(output, 400, error.message ?: "Bad Request")
            return
        }
        try {
            val expected = session.pendingChallenge
            if (expected == null || !MessageDigest.isEqual(expected, confirm.challenge)) {
                throw IllegalArgumentException("认证 challenge 不属于当前会话")
            }
            val gate = DeviceAuthWire.ServerGate(registry)
            gate.confirm(confirm.challenge, confirm.signature)
            session.authorizedDeviceId = gate.requireAuthorized()
            // 留存对方身份信息，供传输站界面显示「对方设备」与连接时长。
            // 公钥取自授权记录（签名过的那把），不是客户端自报值。
            session.authorizedPublicKey = registry.activeAuthorization(session.authorizedDeviceId!!)
                ?.devicePublicKey?.copyOf()
            session.remoteAddress = req.remoteAddress
            session.authenticatedAtMillis = System.currentTimeMillis()
            // 设备身份是在这一步才确定的（SPAKE2 配对时还没有 device_id），
            // 必须主动刷新一次，否则「对方设备」要等到下一次操作才会出现。
            updateStatus()
        } catch (error: IllegalArgumentException) {
            sendJsonError(output, 403, "设备认证失败")
            return
        } finally {
            session.pendingChallenge?.fill(0)
            session.pendingChallenge = null
        }
        sendJson(output, 200, JSONObject(DeviceAuthWire.confirmResponse()))
    }

    private fun requireDeviceAuthorized(session: LanSessionRegistry.Session, operation: PmvSyncAuthorization.Operation) {
        val deviceId = session.authorizedDeviceId ?: throw HostError(403, "设备尚未完成授权认证")
        val registry = deviceAuthProvider?.registry() ?: throw HostError(500, "设备认证未就绪")
        if (!registry.isAuthorized(deviceId, operation)) {
            throw HostError(403, "设备未授权或权限不足")
        }
    }

    private fun handleVaultGet(session: LanSessionRegistry.Session, output: OutputStream) {
        // 导出门控仅作用于「导出」通道：双向同步（sync）拉取是同步的合法部分，不拦截。
        if (session.op == EXPORT_OP && !session.exportApproved.get()) {
            pendingExportApprovalSession = session
            onExportApprovalPending?.invoke(session.token, session.authorizedDeviceId)
            sendJsonError(output, 423, "等待主机确认导出")
            return
        }
        requireDeviceAuthorized(session, PmvSyncAuthorization.Operation.READ)
        // 同步通道正式开始拉取时通知主机：无论是否经过确认弹窗（已授权设备重连也走到这里）。
        if (session.op == SYNC_OP) {
            runCatching { onSyncStarted?.invoke() }
        }
        val file = registry.fileFor(vaultName)
        if (!file.isFile || file.length() == 0L) {
            sendJsonError(output, 500, "保险库文件不可用")
            return
        }
        if (file.length() > MAX_SYNC_BYTES) {
            sendJsonError(output, 413, "账户数据超过 10 GB，暂时无法通过局域网传输")
            return
        }
        PmvAppendOnlyFile.withExclusiveWriterLock(file) {
            // 打开一次、全程使用同一文件句柄，并在发送期间排除 PMVE 写事务：
            // SHA、长度与响应体始终对应同一个已提交文件状态。
            FileInputStream(file).use { input ->
                // 导出文件 SHA-256：客户端下载后校验，防止传输链路损坏导致导入坏库。
                val exportSha256 = runCatching {
                    MessageDigest.getInstance("SHA-256").let { digest ->
                        val buffer = ByteArray(CHUNK)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            digest.update(buffer, 0, count)
                        }
                        digest.digest().toHex()
                    }
                }.getOrDefault("")
                val length = input.channel.size()
                input.channel.position(0)
                // 导出响应携带源账户名（去掉约定前缀），导入方用它注册同名账户，保证双端账户名一致。
                sendResponseStart(
                    output, 200, "OK", "application/octet-stream", length,
                    extraHeaders = mapOf(
                        // HTTP/1.1 头按 ASCII 写出；真实名称用 UTF-8 base64url 旁路，避免“默认”等名称损坏。
                        LanImportPolicy.ENCODED_NAME_HEADER to LanImportPolicy.encodeAccountName(exportedAccountName()),
                        // 保留旧头供旧客户端读取；仅 ASCII 名称可无损使用。
                        "X-Vault-Name" to exportedAccountName().filter { it.code in 0x20..0x7e },
                        "X-Vault-Sha256" to exportSha256,
                    ),
                )
                // 头部已发出后再出错直接断开连接（客户端凭 Content-Length 感知不完整），
                // 不再尝试写第二个 HTTP 响应以免污染已开始的流。
                try {
                    val buffer = ByteArray(CHUNK)
                    var remaining = length
                    while (remaining > 0) {
                        val count = input.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                        if (count < 0) throw EOFException("保险库读取失败")
                        output.write(buffer, 0, count)
                        remaining -= count
                        if (session.op == SYNC_OP) {
                            runCatching { onVaultSendProgress?.invoke(length - remaining, length) }
                        }
                        // 大库下载期间持续刷新活跃时间，避免空闲超时误杀进行中的同步
                        accessTime.set(System.currentTimeMillis())
                    }
                    output.flush()
                    // 导出下发达成：与双向同步一致，由本机主动断开，不把收尾只交给
                    // 客户端的 cancel——那条路要靠会话头找回会话，一旦 403 就静默
                    // 失败（客户端 runCatching 吞掉），传输站会一直挂在「已连接」。
                    //
                    // 仍留一段宽限期：客户端还要做完整性校验与入库，期间可能因校验
                    // 失败在同一会话里重新申请下载；正常路径客户端会在几秒内发 cancel，
                    // 那时立即关闭，不等宽限期。
                    if (session.op == EXPORT_OP) scheduleExportAutoClose()
                } catch (_: Exception) {
                    // 静默断开
                }
            }
        }
    }

    /**
     * 导出下发达成后的兜底关闭：宽限期内客户端若发来 cancel 会立即关闭，这里只
     * 负责「客户端没发」的情况（例如它在校验阶段就退出了）。
     */
    private fun scheduleExportAutoClose() {
        Thread {
            try {
                Thread.sleep(EXPORT_AUTO_CLOSE_GRACE_MS)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return@Thread
            }
            // 期间若已被 cancel/其它路径关掉，running 已为 false，这里自然无事可做。
            if (running.get()) {
                stopInternal("导出已完成，传输站自动关闭")
            }
        }.apply { name = "vault-host-export-close"; isDaemon = true }.start()
    }

    private fun handleVaultPut(session: LanSessionRegistry.Session, req: HttpRequest, output: OutputStream) {
        requireDeviceAuthorized(session, PmvSyncAuthorization.Operation.WRITE)
        if (req.contentLength <= 0 || req.contentLength > MAX_SYNC_BYTES) {
            sendJsonError(output, 413, "保险库过大或为空")
            return
        }
        val expectedHash = req.headers["x-vault-content-sha256"].orEmpty().lowercase()
        if (!expectedHash.matches(Regex("[0-9a-f]{64}"))) {
            sendJsonError(output, 400, "发送方未提供有效的安全校验信息")
            return
        }
        val temp = File(tempDir, "incoming-${UUID.randomUUID()}.pmv")
        try {
            req.streamToFile(temp) { transferred ->
                if (session.op == SYNC_OP) {
                    runCatching { onVaultReceiveProgress?.invoke(transferred, req.contentLength) }
                }
            }
            if (!MessageDigest.isEqual(
                    expectedHash.toByteArray(Charsets.US_ASCII),
                    sha256File(temp).toByteArray(Charsets.US_ASCII),
                )
            ) {
                sendJsonError(output, 422, "收到的数据未通过安全检查，请重新发送")
                return
            }
            val handler = vaultHandler
                ?: throw HostError(500, "传输站尚未就绪")
            val stats = handler.onReceiveVault(temp)
            sendJson(output, 200, stats)
            // 双向同步完成：传输站合并后主动断开连接（延迟到响应写出后再停，
            // 避免正在处理的连接被立刻关闭导致响应无法送达）。
            val done = onSyncCompleted
            if (done != null) {
                Thread {
                    try {
                        Thread.sleep(300L)
                    } catch (_: InterruptedException) {
                    }
                    runCatching { done() }
                }.apply { name = "vault-host-sync-stop"; isDaemon = true }.start()
            }
        } finally {
            temp.delete()
        }
    }

    private fun handleTransferItems(output: OutputStream) {
        transferActive.set(true)
        val array = org.json.JSONArray()
        synchronized(transferLock) {
            for (item in outgoing.values.filter { it.sha256.matches(Regex("[0-9a-f]{64}")) }) {
                array.put(JSONObject()
                    .put("id", item.id)
                    .put("name", item.name)
                    .put("mime", item.mime)
                    .put("kind", item.kind)
                    .put("size", item.size)
                    .put("sha256", item.sha256))
            }
        }
        sendJson(output, 200, JSONObject().put("items", array))
    }

    private fun handleTransferUpload(req: HttpRequest, output: OutputStream, socket: Socket) {
        transferActive.set(true)
        val id = req.headers["x-vault-transfer-id"].orEmpty()
        if (id.isBlank() || id.length > 64 || !id.all { it.isLetterOrDigit() || it == '-' || it == '_' }) {
            sendError(output, 400, "Bad Request")
            return
        }
        val name = try {
            decodeTextHeader(req.headers["x-vault-transfer-name"])
        } catch (_: Exception) {
            sendError(output, 400, "Bad Request")
            return
        }
        val mime = try {
            decodeTextHeader(req.headers["x-vault-transfer-mime"])
        } catch (_: Exception) {
            sendError(output, 400, "Bad Request")
            return
        }
        val kind = if (req.headers["x-vault-transfer-kind"] == "text") "text" else "file"
        val expectedHash = req.headers["x-vault-content-sha256"].orEmpty().lowercase()
        if (!expectedHash.matches(Regex("[0-9a-f]{64}"))) {
            sendJsonError(output, 400, "发送方未提供有效的文件校验信息")
            return
        }
        if (req.contentLength <= 0 || req.contentLength > MAX_TRANSFER_BYTES) {
            sendJsonError(output, 413, "传输内容过大或为空")
            return
        }
        val safeName = sanitizeName(name)
        val part = File(tempDir, "incoming-$id.part")
        val dest = uniquePath(receiveDir, safeName)
        val item = TransferItem(
            id = id, name = safeName, mime = mime, kind = kind,
            size = req.contentLength, sha256 = "", sourcePath = null,
            temporary = false, preview = "", transferred = 0L, status = "接收中",
        )
        synchronized(transferLock) { received.add(item) }
        activeItemConnections[id] = socket
        if (item.canceled) {
            // 登记前已被取消：不再接收，保持“已取消”记录。
            activeItemConnections.remove(id)
            sendJsonError(output, 410, "传输已被取消")
            return
        }
        updateStatus()
        try {
            var total = 0L
            var lastPercent = -1
            req.streamToFile(part) { transferred ->
                total = transferred
                synchronized(transferLock) { item.transferred = transferred }
                val percent = transferPercent(transferred, item.size)
                if (percent != lastPercent) {
                    lastPercent = percent
                    updateStatus()
                }
            }
            val hash = sha256File(part)
            item.sha256 = hash
            if (total != req.contentLength) throw HostError(400, "接收内容不完整")
            if (!MessageDigest.isEqual(
                    expectedHash.toByteArray(Charsets.US_ASCII),
                    hash.toByteArray(Charsets.US_ASCII),
                )
            ) throw HostError(422, "文件校验未通过，请重新发送")
            if (kind == "text" && req.contentLength <= MAX_TRANSFER_TEXT_BYTES) {
                item.preview = part.readText(Charsets.UTF_8).take(160)
            }
            val sink = transferSink
            val publishedPath = try {
                if (sink != null) {
                    sink.onReceive(part, safeName, mime, kind)
                } else {
                    part.copyTo(dest, overwrite = true)
                    dest.absolutePath
                }
            } catch (error: Exception) {
                if (error is HostError) throw error
                part.copyTo(dest, overwrite = true)
                dest.absolutePath
            }
            item.status = "已接收"
            item.transferred = req.contentLength
            item.path = publishedPath
            updateStatus()
            sendJson(output, 201, JSONObject()
                .put("id", id)
                .put("sha256", hash)
                .put("path", publishedPath))
        } catch (error: HostError) {
            synchronized(transferLock) {
                if (!item.canceled) item.status = "接收失败"
            }
            updateStatus()
            throw error
        } catch (error: Exception) {
            synchronized(transferLock) {
                if (!item.canceled) {
                    // 发送端主动取消/拒绝：连接层表现为 Socket 中断，按对端取消提示，
                    // 避免把“对方取消”误报成本机接收失败。
                    item.status = if (error is java.net.SocketException) "对方已取消发送" else "接收失败"
                }
            }
            updateStatus()
            throw HostError(500, "接收文件失败：${error.message ?: "保存或校验过程中发生错误"}")
        } finally {
            activeItemConnections.remove(id)
            part.delete()
        }
    }

    private fun handleTransferDownload(req: HttpRequest, output: OutputStream, socket: Socket) {
        transferActive.set(true)
        val id = queryParam(req.query, "id")
        val item = synchronized(transferLock) { outgoing[id] }
        if (item == null || item.sourcePath == null || !item.sourcePath.isFile ||
            item.sourcePath.length() != item.size
        ) {
            sendError(output, 410, "Gone")
            return
        }
        activeItemConnections[id ?: ""] = socket
        if (synchronized(transferLock) { outgoing[id] !== item }) {
            // 登记前已被取消：停止发送，保持“已取消”记录。
            activeItemConnections.remove(id ?: "")
            sendError(output, 410, "Gone")
            return
        }
        item.status = "发送中"
        updateStatus()
        sendResponseStart(output, 200, "OK", item.mime, item.size)
        var completed = false
        try {
            FileInputStream(item.sourcePath).use { input ->
                val buffer = ByteArray(CHUNK)
                var total = 0L
                var lastPercent = -1
                while (total < item.size) {
                    val count = input.read(buffer, 0, minOf(buffer.size.toLong(), item.size - total).toInt())
                    if (count < 0) break
                    output.write(buffer, 0, count)
                    total += count
                    item.transferred = total
                    val percent = transferPercent(total, item.size)
                    if (percent != lastPercent) {
                        lastPercent = percent
                        updateStatus()
                    }
                    // 大文件发送期间持续刷新活跃时间，避免空闲超时误杀进行中的传输
                    accessTime.set(System.currentTimeMillis())
                }
                completed = total == item.size
            }
            output.flush()
        } catch (_: Exception) {
            completed = false
        }
        if (!completed && item.status != "已取消") {
            item.status = "发送中断"
            // 发送失败：临时来源的缓存文件不再有用，立即清理。
            if (item.temporary) runCatching { item.sourcePath?.delete() }
        }
        activeItemConnections.remove(id ?: "")
        updateStatus()
    }

    private fun handleTransferAck(req: HttpRequest, output: OutputStream) {
        transferActive.set(true)
        val id = queryParam(req.query, "id")
        val item = synchronized(transferLock) {
            outgoing.remove(id)
        }
        if (item == null) {
            sendError(output, 404, "Not Found")
            return
        }
        item.status = "已发送"
        item.transferred = item.size
        synchronized(transferLock) { sent.add(item) }
        if (item.temporary) {
            runCatching { item.sourcePath?.delete() }
        }
        updateStatus()
        sendNoContent(output)
    }

    /** 取消单条传输（本机作为传输站）：等待接收/发送中/接收中的条目立即终止。 */
    fun cancelTransferItem(id: String): Boolean {
        val item = synchronized(transferLock) {
            val outgoingItem = outgoing.remove(id)
            if (outgoingItem != null) {
                outgoingItem.canceled = true
                outgoingItem.status = "已取消"
                if (outgoingItem.temporary) {
                    runCatching { outgoingItem.sourcePath?.delete() }
                }
                sent.add(outgoingItem)
                outgoingItem
            } else {
                val receivedItem = received.firstOrNull { it.id == id }
                if (receivedItem != null) {
                    receivedItem.canceled = true
                    receivedItem.status = "已取消"
                }
                receivedItem
            }
        } ?: return false
        activeItemConnections.remove(id)?.let { runCatching { it.close() } }
        updateStatus()
        return true
    }

    // ── 响应 ──────────────────────────────────────────────────────────────

    private fun sendJson(output: OutputStream, status: Int, body: String) {
        sendBody(output, status, "application/json", body.toByteArray(Charsets.UTF_8))
    }

    private fun sendJson(output: OutputStream, status: Int, json: org.json.JSONObject) =
        sendJson(output, status, json.toString())

    private fun sendJsonError(output: OutputStream, status: Int, message: String) =
        sendJson(output, status, JSONObject().put("error", message))

    private fun sendNoContent(output: OutputStream) = sendBody(output, 204, "text/plain", ByteArray(0))

    private fun sendError(output: OutputStream, status: Int, reason: String) =
        sendBody(output, status, "text/plain", reason.toByteArray(Charsets.UTF_8))

    private fun sendBody(output: OutputStream, status: Int, contentType: String, body: ByteArray) {
        val head = buildString {
            append("HTTP/1.1 ").append(status).append(' ').append(statusText(status)).append("\r\n")
            if (body.isNotEmpty()) append("Content-Type: ").append(contentType).append("\r\n")
            append("Content-Length: ").append(body.size).append("\r\n")
            append("Connection: close\r\n\r\n")
        }
        output.write(head.toByteArray(Charsets.US_ASCII))
        if (body.isNotEmpty()) output.write(body)
        output.flush()
    }

    private fun sendResponseStart(
        output: OutputStream,
        status: Int,
        reason: String,
        contentType: String,
        length: Long,
        extraHeaders: Map<String, String> = emptyMap(),
    ) {
        val head = "HTTP/1.1 $status $reason\r\n" +
            "Content-Type: $contentType\r\n" +
            "Content-Length: $length\r\n" +
            extraHeaders.entries.joinToString("") { "${it.key}: ${it.value}\r\n" } +
            "Connection: close\r\n\r\n"
        output.write(head.toByteArray(Charsets.US_ASCII))
        output.flush()
    }

    private fun statusText(status: Int): String = when (status) {
        200 -> "OK"
        201 -> "Created"
        204 -> "No Content"
        400 -> "Bad Request"
        403 -> "Forbidden"
        404 -> "Not Found"
        409 -> "Conflict"
        410 -> "Gone"
        411 -> "Length Required"
        413 -> "Payload Too Large"
        431 -> "Request Header Fields Too Large"
        500 -> "Internal Server Error"
        else -> "Error"
    }

    // ── 工具 ──────────────────────────────────────────────────────────────

    private fun spake2Aad(op: String): ByteArray =
        "Vault LAN Sync SPAKE2 RFC9382 v2".toByteArray() + byteArrayOf(0) +
            op.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            ticket.toByteArray() + byteArrayOf(0) + certFingerprint.toByteArray(Charsets.US_ASCII)

    private fun generateCertificate(host: String): Triple<SSLContext, String, ByteArray> {
        val keyPairGen = KeyPairGenerator.getInstance("EC")
        keyPairGen.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = keyPairGen.generateKeyPair()
        val privateKey = keyPair.private as ECPrivateKey
        val publicKey = keyPair.public as ECPublicKey

        val name = X500Name("CN=Vault LAN Sync")
        val now = System.currentTimeMillis()
        val builder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(now),
            Date(now - 60_000L),
            Date(now + CERT_VALIDITY_MS),
            name,
            publicKey,
        )
        builder.addExtension(
            Extension.subjectAlternativeName, false,
            GeneralNames(arrayOf(GeneralName(GeneralName.iPAddress, host))),
        )
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(privateKey)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(cert.encoded).toHex()

        val keyStore = KeyStore.getInstance("PKCS12")
        keyStore.load(null, null)
        keyStore.setKeyEntry("vault", privateKey, CharArray(0), arrayOf<Certificate>(cert))
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, CharArray(0))
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(keyManagerFactory.keyManagers, null, SecureRandom())
        return Triple(sslContext, fingerprint, cert.encoded)
    }

    private fun localIp(): String {
        val candidate = runCatching {
            NetworkInterface.getNetworkInterfaces().asSequence()
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.inetAddresses.asSequence() }
                .filter { it is Inet4Address && !it.isLoopbackAddress }
                .map { it.hostAddress }
                .firstOrNull()
        }.getOrNull()
        // 模拟器 NAT 场景：宿主机上另一台模拟器无法直达 10.0.2.15。
        // 广告 10.0.2.2（宿主机回环别名），配合 adb forward 后另一端可原样复制粘贴连接；
        // 真机/局域网仍使用真实 IP，不受影响。
        if (candidate == "10.0.2.15" && isEmulator()) return "10.0.2.2"
        return candidate ?: "127.0.0.1"
    }

    private fun isEmulator(): Boolean {
        val hardware = android.os.Build.HARDWARE.lowercase()
        val fingerprint = android.os.Build.FINGERPRINT.lowercase()
        return hardware.contains("goldfish") || hardware.contains("ranchu") ||
            fingerprint.contains("generic") || fingerprint.contains("emulator")
    }

    private fun secureToken(bytes: Int): String {
        val raw = ByteArray(bytes)
        SecureRandom().nextBytes(raw)
        return b64encode(raw)
    }

    private fun sha256File(file: File): String = runCatching {
        MessageDigest.getInstance("SHA-256").let { digest ->
            FileInputStream(file).use { input ->
                val buffer = ByteArray(CHUNK)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            digest.digest().toHex()
        }
    }.getOrDefault("")

    private fun sanitizeName(value: String): String {
        val name = value.replace("\\", "/").substringAfterLast('/').take(180)
        val cleaned = name.map { c -> if (c < ' ' || c in "<>:\"/\\|?*") '_' else c }.joinToString("").trim(' ', '.')
        return cleaned.ifEmpty { "received.bin" }
    }

    private fun uniquePath(directory: File, name: String): File {
        var candidate = File(directory, name)
        val stem = candidate.nameWithoutExtension
        val suffix = candidate.extension.let { if (it.isBlank()) "" else ".$it" }
        var index = 2
        while (candidate.exists()) {
            candidate = File(directory, "${stem}_$index$suffix")
            index++
        }
        return candidate
    }

    private fun guessMime(name: String): String = when (name.substringAfterLast('.', "").lowercase(Locale.US)) {
        "txt" -> "text/plain"
        "jpg", "jpeg" -> "image/jpeg"
        "png" -> "image/png"
        "gif" -> "image/gif"
        "webp" -> "image/webp"
        "pdf" -> "application/pdf"
        "mp4" -> "video/mp4"
        "mp3" -> "audio/mpeg"
        "zip" -> "application/zip"
        "7z" -> "application/x-7z-compressed"
        "apk" -> "application/vnd.android.package-archive"
        else -> "application/octet-stream"
    }

    private fun queryParam(query: String, key: String): String? =
        query.split('&').mapNotNull { part ->
            val idx = part.indexOf('=')
            if (idx > 0 && part.substring(0, idx) == key) {
                java.net.URLDecoder.decode(part.substring(idx + 1), Charsets.UTF_8.name())
            } else null
        }.firstOrNull()

    private fun decodeTextHeader(value: String?): String {
        val raw = value.orEmpty()
        if (raw.isEmpty() || raw.length > 2048) throw IllegalArgumentException("invalid transfer header")
        return String(Base64.getUrlDecoder().decode(raw), Charsets.UTF_8)
    }

    private fun currentItems(): List<HostItem> = synchronized(transferLock) {
        val result = mutableListOf<HostItem>()
        for (item in outgoing.values) result.add(item.toHostItem("outgoing", item.status))
        for (item in received) result.add(item.toHostItem("received", item.status))
        for (item in sent) result.add(item.toHostItem("sent", item.status))
        result
    }

    private fun TransferItem.toHostItem(direction: String, status: String) = HostItem(
        id = id, name = name, textPreview = preview, kind = kind, size = size,
        direction = direction, status = status,
        path = sourcePath?.absolutePath ?: path,
        transferred = transferred.coerceIn(0L, size.coerceAtLeast(0L)),
    )

    private fun transferPercent(transferred: Long, total: Long): Int =
        if (total <= 0L) 100 else ((transferred * 100L) / total).toInt().coerceIn(0, 100)

    private fun updateStatus() {
        val peer = peerIdentity()
        _status.value = HostStatus(
            running = true,
            url = url,
            pin = pin,
            paired = paired.get(),
            pairSeq = pairCount.get(),
            op = latestOp,
            items = currentItems(),
            peerDeviceId = peer?.first?.toString(),
            peerFingerprint = peer?.second?.fingerprint.orEmpty(),
            peerAddress = peer?.second?.address.orEmpty(),
            peerConnectedAtMillis = peer?.second?.connectedAtMillis ?: 0L,
        )
    }

    /**
     * 当前接入设备的身份摘要：device_id 与其公钥指纹 / 地址 / 认证时刻。
     *
     * 一次只允许一台设备接入，因此取 authenticatedAt 非零的那条会话即可；没有就返回 null，
     * 界面据此隐藏「对方设备」信息。
     */
    private fun peerIdentity(): Pair<UUID, PeerIdentitySnapshot>? {
        if (authenticatedAt.get() == 0L) return null
        // 不要拿配对时刻去比对会话上的认证时刻：两次独立取时，几乎永不相等。
        val picked = pickLanPeerIdentity(
            sessions.sessions().map { s ->
                LanPeerIdentity(
                    deviceId = s.authorizedDeviceId?.toString().orEmpty(),
                    fingerprint = s.authorizedPublicKey
                        ?.takeIf { it.isNotEmpty() }?.sha256Hex24().orEmpty(),
                    address = s.remoteAddress.orEmpty(),
                    connectedAtMillis = s.authenticatedAtMillis,
                )
            },
        ) ?: return null
        val deviceId = runCatching { UUID.fromString(picked.deviceId) }.getOrNull() ?: return null
        return deviceId to PeerIdentitySnapshot(
            fingerprint = picked.fingerprint,
            address = picked.address,
            connectedAtMillis = picked.connectedAtMillis,
        )
    }

    private data class PeerIdentitySnapshot(
        val fingerprint: String,
        val address: String,
        val connectedAtMillis: Long,
    )

    private fun ByteArray.sha256Hex24(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(this)
        return digest.take(12).joinToString("") { "%02x".format(it) }
    }

    private fun b64encode(value: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(value)

    private fun b64decode(value: String, expectedLength: Int): ByteArray {
        if (value.isBlank() || value.length > 256 || value.any { !it.isLetterOrDigit() && it != '-' && it != '_' }) {
            throw IllegalArgumentException("invalid base64url")
        }
        val raw = Base64.getUrlDecoder().decode(value)
        if (raw.size != expectedLength) throw IllegalArgumentException("invalid decoded length")
        return raw
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}

/** 逐行读取 HTTP 头（\r\n 结尾，剔除 \r）。顶层扩展：嵌套类 HttpRequest 无法访问外层成员扩展。 */
private fun InputStream.readLineCrLf(maxChars: Int): String? {
    val builder = StringBuilder()
    var sawByte = false
    while (true) {
        val b = read()
        if (b < 0) {
            if (builder.isEmpty()) return null
            break
        }
        sawByte = true
        if (b == '\n'.code) {
            if (builder.isNotEmpty() && builder.last() == '\r') builder.deleteCharAt(builder.length - 1)
            break
        }
        builder.append(b.toChar())
        if (builder.length > maxChars) throw SyncServerHost.HostError(431, "Request Header Fields Too Large")
    }
    if (!sawByte && builder.isEmpty()) return null
    return builder.toString()
}

private fun InputStream.readExact(length: Long): ByteArray {
    val buffer = ByteArray(length.toInt().coerceAtMost(64 * 1024))
    val out = ByteArrayOutputStream(length.toInt().coerceAtMost(4096))
    var remaining = length
    while (remaining > 0) {
        val count = read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
        if (count < 0) throw EOFException("连接已断开")
        out.write(buffer, 0, count)
        remaining -= count
    }
    return out.toByteArray()
}
