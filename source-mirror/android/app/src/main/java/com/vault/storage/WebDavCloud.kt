package com.vault.storage

import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.RequestBody.Companion.asRequestBody
import okio.Buffer
import okio.BufferedSink
import okio.ForwardingSink
import okio.buffer
import java.io.IOException
import java.net.URI
import java.security.MessageDigest
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

data class WebDavConfig(
    val label: String,
    val fileUrl: String,
    val username: String,
    val password: String,
    val authMode: String = "basic",
    val bearerToken: String = "",
    val certificateSha256: String = "",
    val createDirectories: Boolean = false,
    val cookie: String = "",
    val clientCertificate: String = "",
    val clientCertificatePassword: String = "",
    val domain: String = "",
)

data class WebDavRemote(val bytes: ByteArray, val etag: String?)
data class WebDavRemoteFile(val file: java.io.File, val etag: String?, val size: Long)
data class WebDavMetadata(val exists: Boolean, val size: Long, val lastModified: Long, val etag: String?)
class WebDavConflict : IOException("云端文件已被其他设备更新，请先下载合并")

object WebDavCloud {
    private const val MAX_TRANSFER_BYTES = 1024L * 1024L * 1024L
    private val mediaType = "application/octet-stream".toMediaType()
    private val clientCache = java.util.concurrent.ConcurrentHashMap<String, OkHttpClient>()

    fun validate(config: WebDavConfig) {
        val uri = runCatching { URI(config.fileUrl.trim()) }.getOrElse { error("地址格式无效") }
        require(uri.scheme.equals("https", true)) { "仅支持 HTTPS 地址（明文 HTTP 已被禁用）" }
        require(!uri.host.isNullOrBlank()) { "地址缺少服务器名称" }
        require(!uri.path.endsWith('/') && uri.path.substringAfterLast('/').isNotBlank()) { "地址必须包含远端文件名" }
        require(config.authMode in setOf("none", "basic", "digest", "bearer", "oauth2", "cookie", "mtls", "ntlm", "kerberos")) { "不支持的认证方式" }
        if (config.authMode == "basic") require(config.username.isNotBlank() == config.password.isNotEmpty()) { "Basic 认证的用户名和密码必须同时填写" }
        if (config.authMode in setOf("digest", "ntlm")) require(config.username.isNotBlank()) { "当前认证方式需要用户名" }
        if (config.authMode in setOf("digest", "ntlm")) require(config.password.isNotEmpty()) { "当前认证方式需要密码" }
        if (config.authMode in setOf("bearer", "oauth2")) require(config.bearerToken.isNotBlank()) { "当前认证方式需要访问令牌" }
        require('\r' !in config.bearerToken && '\n' !in config.bearerToken) { "访问令牌不能包含换行符" }
        if (config.authMode == "cookie") require(config.cookie.isNotBlank()) { "Cookie / Session 认证需要 Cookie" }
        require('\r' !in config.cookie && '\n' !in config.cookie) { "Cookie 不能包含换行符" }
        if (config.authMode == "mtls") require(config.clientCertificate.isNotBlank()) { "客户端证书认证需要 PKCS#12 证书" }
        if (config.authMode in setOf("bearer", "oauth2", "cookie", "mtls", "ntlm", "kerberos")) {
            require(uri.scheme.equals("https", true)) { "此认证方式只允许使用 HTTPS" }
        }
        require(config.authMode !in setOf("ntlm", "kerberos")) {
            "Android 系统未提供可移植的 NTLM/Kerberos 域凭据接口；请使用 HTTPS Basic、Digest、令牌、Cookie 或 mTLS"
        }
        if (config.certificateSha256.isNotBlank()) {
            require(uri.scheme.equals("https", true)) { "证书指纹仅适用于 HTTPS" }
            require(normalizeFingerprint(config.certificateSha256).matches(Regex("[0-9a-f]{64}"))) { "证书 SHA-256 指纹必须是 64 位十六进制" }
        }
    }

    fun configForDirectory(config: WebDavConfig, fileName: String): WebDavConfig {
        val directory = parseHttpUri(config.fileUrl, "目录地址")
        require(directory.rawQuery == null && directory.rawFragment == null) { "目录地址不能包含查询参数或片段" }
        require(fileName.endsWith(".pmv", ignoreCase = true) &&
            fileName.none { it == '/' || it == '\\' }) { "保险库文件名无效" }
        val directoryPath = directory.path.orEmpty().trimEnd('/')
        val filePath = "$directoryPath/$fileName".ifEmpty { "/$fileName" }
        val fileUri = URI(
            directory.scheme,
            directory.userInfo,
            directory.host,
            directory.port,
            filePath,
            null,
            null,
        )
        return config.copy(fileUrl = fileUri.toASCIIString()).also(::validate)
    }

    fun directoryUrl(fileUrl: String): String {
        val file = parseHttpUri(fileUrl, "文件地址")
        val path = file.path.orEmpty()
        val directoryPath = path.substringBeforeLast('/', "").ifEmpty { "/" }
        return URI(
            file.scheme,
            file.userInfo,
            file.host,
            file.port,
            directoryPath,
            null,
            null,
        ).toASCIIString()
    }

    private fun parseHttpUri(value: String, label: String): URI {
        val uri = runCatching { URI(value.trim()) }.getOrElse { error("$label 格式无效") }
        require(uri.scheme.equals("https", true)) { "仅支持 HTTPS 地址（明文 HTTP 已被禁用）" }
        require(!uri.host.isNullOrBlank()) { "$label 缺少服务器名称" }
        return uri
    }

    fun test(config: WebDavConfig) {
        validate(config)
        if (config.createDirectories) ensureDirectories(config)
        val options = execute(config, "OPTIONS", directoryUrl(config.fileUrl), retry = true)
        options.use { response ->
            checkResponse(response.code, allowMissing = false)
            val declared = !response.header("DAV").isNullOrBlank() || response.header("Allow").orEmpty()
                .split(',').any { it.trim().equals("PUT", true) }
            if (!declared) probeWrite(config)
        }
        head(config, config.fileUrl, allowMissing = true)
    }

    /** 使用与关联后预览完全相同的内容探测完成关联检查。 */
    fun inspectAssociation(config: WebDavConfig): WebDavMetadata {
        test(config)
        return metadata(config)
    }

    fun upload(config: WebDavConfig, bytes: ByteArray): WebDavMetadata {
        return upload(config, bytes.toRequestBody(mediaType), bytes.size.toLong(), sha256Hex(bytes), force = false, expected = null)
    }

    fun upload(config: WebDavConfig, file: java.io.File): WebDavMetadata {
        require(file.length() <= MAX_TRANSFER_BYTES) { "本地保险库超过 1 GB 安全限制" }
        return upload(config, file.asRequestBody(mediaType), file.length(), sha256File(file), force = false, expected = null)
    }

    fun uploadOverwrite(
        config: WebDavConfig,
        file: java.io.File,
        onProgress: ((Long, Long) -> Unit)? = null,
    ): WebDavMetadata {
        require(file.length() <= MAX_TRANSFER_BYTES) { "本地保险库超过 1 GB 安全限制" }
        val body = file.asRequestBody(mediaType)
        val tracked = if (onProgress != null) {
            CountingRequestBody(body, file.length(), onProgress)
        } else body
        return upload(config, tracked, file.length(), sha256File(file), force = true, expected = null)
    }

    /** File-only conditional upload. 强 ETag 优先；无强 ETag 时退回 大小+Last-Modified 校验。 */
    fun uploadIfUnchanged(
        config: WebDavConfig,
        file: java.io.File,
        expected: WebDavMetadata,
    ): WebDavMetadata {
        require(file.length() in 1..MAX_TRANSFER_BYTES) { "本地保险库大小为 0 或超过 1 GB 安全限制" }
        if (expected.exists && expected.etag?.let(::isStrongHttpEtag) != true) {
            require(expected.size >= 0L || expected.lastModified > 0L) {
                "WebDAV 服务未提供可用于并发保护的版本信息，需要强 ETag 或文件大小/修改时间"
            }
        }
        return upload(config, file.asRequestBody(mediaType), file.length(), sha256File(file), force = false, expected = expected)
    }

    private fun upload(
        config: WebDavConfig,
        body: okhttp3.RequestBody,
        expectedSize: Long,
        expectedSha256: String,
        force: Boolean,
        expected: WebDavMetadata?,
    ): WebDavMetadata {
        validate(config)
        if (config.createDirectories) ensureDirectories(config)
        // 无强 ETag 时 HEAD 的 Content-Length 可能是陈旧的 0，必须用 HEAD+Range
        // 探测修正后的完整元数据做大小/时间预检。
        val noStrongInitial = expected != null && expected.exists &&
            expected.etag?.let(::isStrongHttpEtag) != true
        val initial = if (noStrongInitial) {
            metadata(config)
        } else {
            metadata(config, config.fileUrl, allowMissing = true)
        }
        val expectedEtag = expected?.etag
        if (expected != null) {
            val strongExpected = expected.etag?.let(::isStrongHttpEtag) == true
            val unchanged = when {
                !expected.exists -> initial.etag == null
                strongExpected -> initial.etag == expectedEtag
                // 无强 ETag：退回 大小+Last-Modified 一致性校验后再上传。
                else -> {
                    val sizeOk = expected.size >= 0L && initial.size == expected.size
                    val timeOk = expected.lastModified > 0L && initial.lastModified == expected.lastModified
                    if (expected.size >= 0L && expected.lastModified > 0L) sizeOk && timeOk else sizeOk || timeOk
                }
            }
            if (!unchanged) throw WebDavConflict()
        }
        // 只向正式 PMV 路径写入一次。旧流程先 PUT `.upload-*.tmp`，再 MOVE 或再次
        // PUT 正式文件，在不支持 MOVE 的服务器上会把整库上传两遍。
        // 条件头直接约束正式写入，提交响应丢失仍由 putAndConfirm 读回摘要确认。
        val strongExpected = expected != null && expected.exists &&
            expected.etag?.let(::isStrongHttpEtag) == true
        when {
            force -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
            )
            expected?.exists == false -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
                requireMissing = true,
            )
            strongExpected -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
                etag = expected?.etag,
            )
            expected != null -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
                unmodifiedSince = expected.lastModified.takeIf { it > 0L },
            )
            !initial.exists -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
                requireMissing = true,
            )
            initial.etag?.let(::isStrongHttpEtag) == true -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
                etag = initial.etag,
            )
            initial.lastModified > 0L -> putAndConfirm(
                config, config.fileUrl, body, expectedSize, expectedSha256,
                unmodifiedSince = initial.lastModified,
            )
            else -> error("WebDAV 服务未提供可用于安全覆盖的版本信息")
        }
        return verifyUploadedContent(config, config.fileUrl, expectedSize, expectedSha256, "远端文件")
    }

    /** 包装上传 RequestBody，按写入字节回调进度（避免把整库读入内存）。 */
    private class CountingRequestBody(
        private val delegate: okhttp3.RequestBody,
        private val total: Long,
        private val onProgress: (Long, Long) -> Unit,
    ) : okhttp3.RequestBody() {
        override fun contentType() = delegate.contentType()

        override fun contentLength() = delegate.contentLength()

        override fun writeTo(sink: BufferedSink) {
            val countingSink = object : ForwardingSink(sink) {
                private var bytesWritten = 0L

                override fun write(source: Buffer, byteCount: Long) {
                    super.write(source, byteCount)
                    bytesWritten += byteCount
                    onProgress(bytesWritten, total)
                }
            }
            val buffered = countingSink.buffer()
            delegate.writeTo(buffered)
            buffered.flush()
        }
    }

    fun metadata(config: WebDavConfig): WebDavMetadata {
        validate(config)
        val head = metadata(config, config.fileUrl, allowMissing = true)
        val content = probeRemoteMetadata(config, config.fileUrl, allowMissing = true)
        if (!content.exists) return content
        return content.copy(
            size = when {
                content.size >= 0L -> content.size
                head.size > 0L -> head.size
                else -> -1L
            },
            lastModified = content.lastModified.takeIf { it > 0L } ?: head.lastModified,
            etag = content.etag ?: head.etag,
        )
    }

    /**
     * 关联阶段必须确认远端文件是否真的包含数据，不能依赖可能被 WebDAV
     * 服务缓存或错误实现的 HEAD Content-Length。
     */
    fun hasContent(config: WebDavConfig): Boolean {
        validate(config)
        val remote = probeRemoteMetadata(config, config.fileUrl, allowMissing = true)
        return remote.exists && remote.size != 0L
    }

    private fun metadata(config: WebDavConfig, url: String, allowMissing: Boolean): WebDavMetadata {
        fun fromResponse(response: okhttp3.Response): WebDavMetadata {
            if (response.code == 404) return WebDavMetadata(false, -1L, 0L, null)
            checkResponse(response.code, allowMissing)
            val contentRangeSize = response.header("Content-Range")
                ?.substringAfterLast('/', "")
                ?.toLongOrNull()
            val size = contentRangeSize ?: response.header("Content-Length")?.toLongOrNull() ?: -1L
            val modified = response.header("Last-Modified")?.let(::parseHttpDate) ?: 0L
            return WebDavMetadata(true, size, modified, strongEtag(response))
        }
        execute(config, "HEAD", url, retry = true).use { response ->
            if (response.code !in setOf(405, 501)) return fromResponse(response)
        }
        return probeRemoteMetadata(config, url, allowMissing)
    }

    private fun verifyUploadedFile(
        config: WebDavConfig,
        url: String,
        expectedSize: Long,
        label: String,
    ): WebDavMetadata {
        val headMetadata = metadata(config, url, allowMissing = true)
        val verified = if (headMetadata.exists && headMetadata.size == expectedSize) {
            headMetadata
        } else {
            val content = probeRemoteMetadata(config, url, allowMissing = false)
            content.copy(
                lastModified = content.lastModified.takeIf { it > 0L } ?: headMetadata.lastModified,
                etag = content.etag ?: headMetadata.etag,
            )
        }
        check(verified.exists) { "${label}不存在" }
        check(verified.size < 0L || verified.size == expectedSize) {
            "${label}大小校验失败：本地 $expectedSize 字节，远端 ${verified.size} 字节"
        }
        return verified
    }

    /** 发布前/发布后逐字节校验，避免“长度相同但内容已损坏”被误认为成功。 */
    private fun verifyUploadedContent(
        config: WebDavConfig,
        url: String,
        expectedSize: Long,
        expectedSha256: String,
        label: String,
    ): WebDavMetadata {
        val (metadata, actualSha256) = remoteDigest(config, url)
        check(metadata.size == expectedSize) {
            "$label 大小校验失败：本地 $expectedSize 字节，远端 ${metadata.size} 字节"
        }
        check(MessageDigest.isEqual(actualSha256.hexBytes(), expectedSha256.hexBytes())) {
            "$label 内容校验失败"
        }
        return metadata
    }

    private fun remoteContentMatches(
        config: WebDavConfig,
        url: String,
        expectedSize: Long,
        expectedSha256: String,
    ): Boolean = runCatching {
        verifyUploadedContent(config, url, expectedSize, expectedSha256, "远端文件")
        true
    }.getOrDefault(false)

    private fun remoteDigest(config: WebDavConfig, url: String): Pair<WebDavMetadata, String> {
        execute(config, "GET", url, retry = true).use { response ->
            checkResponse(response.code, allowMissing = false)
            val body = response.body ?: error("服务器未返回文件内容")
            val declared = body.contentLength()
            if (declared > MAX_TRANSFER_BYTES) error("云端文件超过 1 GB 安全限制")
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            body.byteStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_TRANSFER_BYTES) error("云端文件超过 1 GB 安全限制")
                    digest.update(buffer, 0, count)
                }
            }
            if (declared >= 0L && declared != total) error("云端文件下载不完整")
            val modified = response.header("Last-Modified")?.let(::parseHttpDate) ?: 0L
            return WebDavMetadata(true, total, modified, strongEtag(response)) to digest.digest().toHex()
        }
    }

    /**
     * 部分 WebDAV 服务会对 HEAD 固定返回 Content-Length: 0。
     * 只请求首字节，优先从 Content-Range 取得完整大小；若服务不报告总大小，
     * 至少确认远端文件不是空文件，避免重新下载整个保险库进行校验。
     */
    private fun probeRemoteMetadata(
        config: WebDavConfig,
        url: String,
        allowMissing: Boolean,
    ): WebDavMetadata {
        fun read(response: okhttp3.Response): WebDavMetadata {
            if (response.code == 404) {
                if (allowMissing) return WebDavMetadata(false, -1L, 0L, null)
                checkResponse(response.code, allowMissing = false)
            }
            if (response.code == 416) {
                val total = response.header("Content-Range")
                    ?.substringAfterLast('/', "")
                    ?.toLongOrNull()
                return WebDavMetadata(
                    exists = true,
                    size = total ?: 0L,
                    lastModified = response.header("Last-Modified")?.let(::parseHttpDate) ?: 0L,
                    etag = strongEtag(response),
                )
            }
            checkResponse(response.code, allowMissing = false)
            val body = response.body
            val rangeSize = response.header("Content-Range")
                ?.substringAfterLast('/', "")
                ?.toLongOrNull()
            val declared = body?.contentLength() ?: -1L
            val size = when {
                rangeSize != null -> rangeSize
                response.code == 200 && declared >= 0L -> declared
                body == null -> 0L
                body.byteStream().read() < 0 -> 0L
                else -> -1L
            }
            return WebDavMetadata(
                exists = true,
                size = size,
                lastModified = response.header("Last-Modified")?.let(::parseHttpDate) ?: 0L,
                etag = strongEtag(response),
            )
        }

        execute(
            config,
            "GET",
            url,
            headers = mapOf("Range" to "bytes=0-0"),
            retry = true,
        ).use { response ->
            if (response.code !in setOf(400, 404, 405, 501)) return read(response)
        }
        execute(config, "GET", url, retry = true).use { response ->
            return read(response)
        }
    }

    fun download(config: WebDavConfig): WebDavRemote =
        download(config, config.fileUrl, allowMissing = false) ?: error("远端路径不存在")

    fun downloadIfExists(config: WebDavConfig): WebDavRemote? =
        download(config, config.fileUrl, allowMissing = true)

    fun downloadTo(config: WebDavConfig, target: java.io.File): WebDavRemoteFile =
        downloadToFile(config, config.fileUrl, target, allowMissing = false) ?: error("远端路径不存在")

    fun downloadIfExistsTo(config: WebDavConfig, target: java.io.File): WebDavRemoteFile? =
        downloadToFile(config, config.fileUrl, target, allowMissing = true)

    private fun downloadToFile(
        config: WebDavConfig,
        url: String,
        target: java.io.File,
        allowMissing: Boolean,
    ): WebDavRemoteFile? {
        execute(config, "GET", url, retry = true).use { response ->
            if (allowMissing && response.code == 404) return null
            checkResponse(response.code, allowMissing = false)
            val body = response.body ?: error("服务器未返回文件内容")
            val declared = body.contentLength()
            if (declared > MAX_TRANSFER_BYTES) error("云端文件超过 1 GB 安全限制")
            target.parentFile?.mkdirs()
            try {
                var total = 0L
                body.byteStream().use { input ->
                    java.io.FileOutputStream(target).use { fileOutput ->
                        val output = fileOutput.buffered()
                        val buffer = ByteArray(32 * 1024)
                        while (true) {
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total > MAX_TRANSFER_BYTES) error("云端文件超过 1 GB 安全限制")
                            output.write(buffer, 0, count)
                        }
                        output.flush()
                        fileOutput.fd.sync()
                    }
                }
                if (declared >= 0L && declared != total) {
                    error("云端文件下载不完整：服务器声明 $declared 字节，实际收到 $total 字节")
                }
                return WebDavRemoteFile(target, strongEtag(response), total)
            } catch (error: Throwable) {
                target.delete()
                throw error
            }
        }
    }

    private fun download(config: WebDavConfig, url: String, allowMissing: Boolean = false): WebDavRemote? {
        execute(config, "GET", url, retry = true).use { response ->
            if (allowMissing && response.code == 404) return null
            checkResponse(response.code, allowMissing = false)
            val body = response.body ?: error("服务器未返回文件内容")
            val declared = body.contentLength()
            if (declared > MAX_TRANSFER_BYTES) error("云端文件超过 1 GB 安全限制")
            val output = java.io.ByteArrayOutputStream(if (declared in 1..Int.MAX_VALUE) declared.toInt() else 8192)
            body.byteStream().use { input ->
                val buffer = ByteArray(32 * 1024)
                var total = 0L
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_TRANSFER_BYTES) error("云端文件超过 1 GB 安全限制")
                    output.write(buffer, 0, count)
                }
            }
            return WebDavRemote(output.toByteArray(), strongEtag(response))
        }
    }

    private fun put(config: WebDavConfig, url: String, bytes: ByteArray, etag: String? = null, requireMissing: Boolean = false, unmodifiedSince: Long? = null) =
        put(config, url, bytes.toRequestBody(mediaType), etag, requireMissing, unmodifiedSince)

    private fun put(
        config: WebDavConfig,
        url: String,
        body: okhttp3.RequestBody,
        etag: String? = null,
        requireMissing: Boolean = false,
        unmodifiedSince: Long? = null,
    ) {
        val headers = mutableMapOf<String, String>()
        if (etag != null) {
            if (etag == "*") headers["If-Match"] = "*"
            else if (isStrongHttpEtag(etag)) headers["If-Match"] = etag
        }
        if (requireMissing) headers["If-None-Match"] = "*"
        if (unmodifiedSince != null && unmodifiedSince > 0L) {
            headers["If-Unmodified-Since"] = formatHttpDate(unmodifiedSince)
        }
        execute(config, "PUT", url, body, headers, retry = true).use { response ->
            if (response.code in setOf(409, 412, 423)) throw WebDavConflict()
            checkResponse(response.code, allowMissing = false)
        }
    }

    private fun move(config: WebDavConfig, source: String, destination: String, etag: String?): Boolean {
        val headers = mutableMapOf("Destination" to destination, "Overwrite" to "T")
        if (etag?.let(::isStrongHttpEtag) == true) headers["If"] = "<$destination> ([$etag])"
        execute(config, "MOVE", source, headers = headers, retry = false).use { response ->
            if (response.code in setOf(405, 501)) return false
            if (response.code in setOf(409, 412, 423)) throw WebDavConflict()
            checkResponse(response.code, allowMissing = false)
            return true
        }
    }

    private fun delete(config: WebDavConfig, url: String) {
        execute(config, "DELETE", url, retry = true).use { response ->
            if (response.code != 404) checkResponse(response.code, allowMissing = false)
        }
    }

    private fun probeWrite(config: WebDavConfig) {
        val tempUrl = "${config.fileUrl}.probe-${UUID.randomUUID()}.tmp"
        try {
            put(config, tempUrl, byteArrayOf())
        } finally {
            runCatching { delete(config, tempUrl) }
        }
    }

    private fun ensureDirectories(config: WebDavConfig) {
        val uri = URI(config.fileUrl.trim())
        val segments = uri.path.split('/').filter { it.isNotBlank() }.dropLast(1)
        var path = ""
        for (segment in segments) {
            path += "/$segment"
            val url = URI(uri.scheme, uri.userInfo, uri.host, uri.port, "$path/", null, null).toString()
            execute(config, "MKCOL", url, retry = true).use { response ->
                if (response.code !in 200..299 && response.code !in setOf(301, 302, 405)) {
                    checkResponse(response.code, allowMissing = false)
                }
            }
        }
    }

    private fun head(config: WebDavConfig, url: String, allowMissing: Boolean): String? {
        var remote = metadata(config, url, allowMissing)
        if (!remote.exists) remote = probeRemoteMetadata(config, url, allowMissing)
        if (!remote.exists) return null
        return remote.etag ?: "timestamp:${remote.lastModified}:${remote.size}"
    }

    private fun execute(
        config: WebDavConfig,
        method: String,
        url: String,
        body: okhttp3.RequestBody? = null,
        headers: Map<String, String> = emptyMap(),
        retry: Boolean,
    ): okhttp3.Response {
        var last: IOException? = null
        var digestHeader: String? = null
        repeat(if (retry) 3 else if (config.authMode == "digest") 2 else 1) { attempt ->
            try {
                val original = URI(url)
                var requestUrl = url
                var redirects = 0
                var response: okhttp3.Response
                while (true) {
                    val builder = Request.Builder().url(requestUrl).method(method, body)
                    when (config.authMode) {
                        "basic" -> if (config.username.isNotEmpty() || config.password.isNotEmpty()) builder.header("Authorization", Credentials.basic(config.username, config.password, Charsets.UTF_8))
                        "digest" -> digestHeader?.let { builder.header("Authorization", it) }
                        "bearer", "oauth2" -> builder.header("Authorization", "Bearer ${config.bearerToken.trim()}")
                        "cookie" -> builder.header("Cookie", config.cookie.trim())
                    }
                    headers.forEach(builder::header)
                    response = client(config).newCall(builder.build()).execute()
                    if (response.code !in setOf(301, 302, 307, 308)) break
                    val location = response.header("Location") ?: break
                    val next = response.request.url.resolve(location) ?: run { response.close(); throw IOException("服务器返回无效重定向地址") }
                    response.close()
                    if (!next.host.equals(original.host, true) || (original.scheme.equals("https", true) && next.scheme != "https")) {
                        throw IOException("拒绝跨主机重定向或从 HTTPS 降级到 HTTP")
                    }
                    if (++redirects > 5) throw IOException("云端重定向次数过多")
                    requestUrl = next.toString()
                }
                if (response.code == 401 && config.authMode == "digest" && digestHeader == null) {
                    val challenge = response.header("WWW-Authenticate").orEmpty()
                    response.close()
                    digestHeader = digestAuthorization(challenge, method, URI(requestUrl), config.username, config.password)
                    if (digestHeader == null) throw IOException("服务器 Digest 认证挑战无效或不受支持")
                } else
                if (retry && response.code in setOf(408, 429, 500, 502, 503, 504) && attempt < 2) {
                    response.close()
                    Thread.sleep((500L shl attempt))
                } else return response
            } catch (error: IOException) {
                last = error
                if (!retry || attempt == 2) throw error
                Thread.sleep((500L shl attempt))
            }
        }
        throw last ?: IOException("云端请求失败")
    }

    private fun client(config: WebDavConfig): OkHttpClient {
        // 缓存键只放不可逆摘要：原样拼接 P12（含私钥）与口令，会让私钥材料以明文字符串
        // 长期驻留在进程内的 map 键上（L-04）。
        val cacheKey = buildString {
            append(config.authMode)
            append('|').append(normalizeFingerprint(config.certificateSha256))
            append('|').append(clientCredentialDigest(config.clientCertificate, config.clientCertificatePassword))
        }
        clientCache[cacheKey]?.let { return it }
        val built = buildClient(config)
        if (clientCache.size >= 16) clientCache.clear()
        clientCache[cacheKey] = built
        return built
    }

    /** 客户端证书 + 口令的不可逆摘要，仅用于缓存键：不含明文，也不足以还原任何一半。 */
    private fun clientCredentialDigest(certificate: String, password: String): String {
        if (certificate.isEmpty() && password.isEmpty()) return ""
        val md = MessageDigest.getInstance("SHA-256")
        md.update(certificate.toByteArray(Charsets.UTF_8))
        md.update(0)
        md.update(password.toByteArray(Charsets.UTF_8))
        return md.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun buildClient(config: WebDavConfig): OkHttpClient {
        val builder = OkHttpClient.Builder()
            .connectTimeout(12, TimeUnit.SECONDS)
            .readTimeout(45, TimeUnit.SECONDS)
            .writeTimeout(45, TimeUnit.SECONDS)
            .followRedirects(false)
            .followSslRedirects(false)
        val expected = normalizeFingerprint(config.certificateSha256)
        var keyManagers: Array<javax.net.ssl.KeyManager>? = null
        if (config.authMode == "mtls") {
            val raw = runCatching { android.util.Base64.decode(config.clientCertificate, android.util.Base64.DEFAULT) }
                .getOrElse { throw IOException("客户端证书编码无效", it) }
            require(raw.size <= 1024 * 1024) { "客户端证书超过 1 MB 安全限制" }
            val password = config.clientCertificatePassword.toCharArray()
            val store = runCatching {
                KeyStore.getInstance("PKCS12").apply { raw.inputStream().use { load(it, password) } }
            }.getOrElse { throw IOException("无法读取 PKCS#12 客户端证书，请检查文件和密码", it) }
            val factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
            keyManagers = factory.keyManagers
        }
        if (expected.isNotEmpty()) {
            // 局部、带理由地抑制 CustomX509TrustManager：LAN/自签名同步通过离线登记的证书指纹绑定，
            // 而非系统 CA 或主机名。攻击者模型：网络中间人无法伪造与登记指纹一致的证书；
            // 绑定顺序为先做指纹比对，失败即拒绝，随后才建立 TLS 通道。
            @Suppress("CustomX509TrustManager")
            val trust = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) = Unit
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                    if (!pinnedCertificateMatches(chain, config.certificateSha256)) {
                        throw java.security.cert.CertificateException("服务器证书 SHA-256 指纹不匹配")
                    }
                }
            }
            val context = SSLContext.getInstance("TLS").apply { init(keyManagers, arrayOf<TrustManager>(trust), SecureRandom()) }
            builder.sslSocketFactory(context.socketFactory, trust)
        } else if (keyManagers != null) {
            val trustFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()).apply {
                init(null as KeyStore?)
            }
            val trust = trustFactory.trustManagers.filterIsInstance<X509TrustManager>().first()
            val context = SSLContext.getInstance("TLS").apply { init(keyManagers, arrayOf<TrustManager>(trust), SecureRandom()) }
            builder.sslSocketFactory(context.socketFactory, trust)
        }
        return builder.build()
    }

    private fun normalizeFingerprint(value: String) = value.filter { it.isLetterOrDigit() }.lowercase()

    internal fun serverCertFingerprintHex(chain: Array<out X509Certificate>): String =
        chain.firstOrNull()?.encoded?.let { sha256(it) }?.joinToString("") { "%02x".format(it) }.orEmpty()

    /** 仅当存在 fingerprint 且与叶子证书一致时为 true（空 fingerprint 视为不绑定）。 */
    fun pinnedCertificateMatches(chain: Array<out X509Certificate>, expectedHex: String): Boolean {
        val expected = normalizeFingerprint(expectedHex)
        if (expected.isEmpty()) return false
        return serverCertFingerprintHex(chain).equals(expected, ignoreCase = true)
    }

    private fun sha256Hex(value: ByteArray): String = sha256(value).toHex()

    private fun sha256File(file: java.io.File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().toHex()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexBytes(): ByteArray {
        require(length % 2 == 0) { "摘要格式无效" }
        return ByteArray(length / 2) { index ->
            substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    /** 强 ETag（以双引号开头）才能用于 If-Match / MOVE If 条件的并发保护。 */
    private fun isStrongHttpEtag(value: String) = value.startsWith('"')

    /** 无强 ETag 时的乐观并发预检：大小 + Last-Modified 一致性。 */
    private fun noStrongEtagUnchanged(expected: WebDavMetadata, latest: WebDavMetadata): Boolean {
        val sizeOk = expected.size >= 0L && latest.size == expected.size
        val timeOk = expected.lastModified > 0L && latest.lastModified == expected.lastModified
        return if (expected.size >= 0L && expected.lastModified > 0L) {
            sizeOk && timeOk
        } else {
            sizeOk || timeOk
        }
    }

    /**
     * PUT 的响应可能在服务端提交后丢失。此时不盲目重发，而是先读回目标内容；
     * 只有无法证明提交成功时才把原异常交给上层决定。
     */
    private fun putAndConfirm(
        config: WebDavConfig,
        url: String,
        body: okhttp3.RequestBody,
        expectedSize: Long,
        expectedSha256: String,
        etag: String? = null,
        requireMissing: Boolean = false,
        unmodifiedSince: Long? = null,
    ) {
        val headers = mutableMapOf<String, String>()
        if (etag != null && isStrongHttpEtag(etag)) headers["If-Match"] = etag
        if (requireMissing) headers["If-None-Match"] = "*"
        if (unmodifiedSince != null && unmodifiedSince > 0L) {
            headers["If-Unmodified-Since"] = formatHttpDate(unmodifiedSince)
        }
        try {
            execute(config, "PUT", url, body, headers, retry = false).use { response ->
                if (response.code in setOf(409, 412, 423)) throw WebDavConflict()
                checkResponse(response.code, allowMissing = false)
            }
        } catch (error: IOException) {
            if (!remoteContentMatches(config, url, expectedSize, expectedSha256)) throw error
        }
    }

    private fun moveAndConfirm(
        config: WebDavConfig,
        source: String,
        destination: String,
        etag: String?,
        expectedSize: Long,
        expectedSha256: String,
    ): Boolean = try {
        move(config, source, destination, etag)
    } catch (error: IOException) {
        if (remoteContentMatches(config, destination, expectedSize, expectedSha256)) true else throw error
    }

    /** 只接受强 ETag；Nextcloud 的 OC-ETag 优先（Apache gzip 会改写普通 ETag）。 */
    private fun strongEtag(response: okhttp3.Response): String? =
        response.header("OC-ETag")?.takeIf(::isStrongHttpEtag)
            ?: response.header("ETag")?.takeIf(::isStrongHttpEtag)

    /**
     * 只读一致性比较：允许 Apache 等对压缩响应追加内容编码后缀（-gzip/-br/-zstd/-deflate）
     * 导致的 ETag 变体，其余情况必须完全一致。仅用于校验，不作为 CAS 条件头。
     */
    fun etagVariantsMatch(served: String?, expected: String?): Boolean {
        if (served == null || expected == null) return served == expected
        if (served == expected) return true
        return stripContentCodingSuffix(served) == stripContentCodingSuffix(expected)
    }

    private fun stripContentCodingSuffix(value: String): String {
        if (!value.startsWith('"') && !value.startsWith("W/\"")) return value
        for (suffix in listOf("-gzip", "-br", "-zstd", "-deflate")) {
            val fullSuffix = "$suffix\""
            if (value.endsWith(fullSuffix) && value.length > fullSuffix.length + 1) {
                return value.dropLast(fullSuffix.length) + "\""
            }
        }
        return value
    }

    private fun sha256(value: ByteArray) = MessageDigest.getInstance("SHA-256").digest(value)
    private fun parseHttpDate(value: String): Long? = runCatching {
        java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", java.util.Locale.US).apply {
            isLenient = false
            timeZone = java.util.TimeZone.getTimeZone("GMT")
        }.parse(value)?.time
    }.getOrNull()

    private fun formatHttpDate(epochMillis: Long): String =
        java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", java.util.Locale.US).apply {
            isLenient = false
            timeZone = java.util.TimeZone.getTimeZone("GMT")
        }.format(java.util.Date(epochMillis))

    private fun digestAuthorization(challenge: String, method: String, uri: URI, username: String, password: String): String? {
        if (!challenge.startsWith("Digest ", true)) return null
        val params = Regex("([a-zA-Z]+)=\\\"([^\\\"]*)\\\"|([a-zA-Z]+)=([^, ]+)").findAll(challenge.substringAfter(' '))
            .associate { match ->
                val key = (match.groups[1]?.value ?: match.groups[3]?.value.orEmpty()).lowercase()
                key to (match.groups[2]?.value ?: match.groups[4]?.value.orEmpty())
            }
        val realm = params["realm"] ?: return null
        val nonce = params["nonce"] ?: return null
        val algorithm = params["algorithm"]?.uppercase() ?: "MD5"
        val digestName = when (algorithm.removeSuffix("-SESS")) { "MD5" -> "MD5"; "SHA-256" -> "SHA-256"; else -> return null }
        fun hash(value: String) = MessageDigest.getInstance(digestName).digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
        val requestUri = uri.rawPath + (uri.rawQuery?.let { "?$it" } ?: "")
        val cnonce = UUID.randomUUID().toString().replace("-", "")
        val nc = "00000001"
        var ha1 = hash("$username:$realm:$password")
        if (algorithm.endsWith("-SESS")) ha1 = hash("$ha1:$nonce:$cnonce")
        val ha2 = hash("$method:$requestUri")
        val qop = params["qop"]?.split(',')?.map { it.trim() }?.firstOrNull { it.equals("auth", true) }
        val response = if (qop != null) hash("$ha1:$nonce:$nc:$cnonce:$qop:$ha2") else hash("$ha1:$nonce:$ha2")
        return buildString {
            append("Digest username=\"").append(username).append("\", realm=\"").append(realm)
            append("\", nonce=\"").append(nonce).append("\", uri=\"").append(requestUri)
            append("\", response=\"").append(response).append("\", algorithm=").append(algorithm)
            params["opaque"]?.let { append(", opaque=\"").append(it).append('"') }
            if (qop != null) append(", qop=").append(qop).append(", nc=").append(nc).append(", cnonce=\"").append(cnonce).append('"')
        }
    }

    private fun checkResponse(code: Int, allowMissing: Boolean) {
        if (code in 200..299 || (allowMissing && code == 404)) return
        val message = when (code) {
            401, 403 -> "认证失败，请检查认证方式、凭据和访问权限"
            404 -> "远端路径不存在"
            405 -> "服务器不支持所需的 WebDAV 方法"
            409, 412, 423 -> "云端文件已被其他设备更新或锁定"
            else -> "服务器返回 HTTP $code"
        }
        throw IOException(message)
    }
}
