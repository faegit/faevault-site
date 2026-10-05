package com.vault.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import java.net.ServerSocket
import kotlin.concurrent.thread

class WebDavCloudTest {
    @Test
    fun `resolves a vault file inside a WebDAV directory`() {
        val resolved = WebDavCloud.configForDirectory(
            WebDavConfig("测试", "https://example.com/dav/我的保险库/", "", ""),
            "用户 A.pmv",
        )

        assertEquals(
            "https://example.com/dav/%E6%88%91%E7%9A%84%E4%BF%9D%E9%99%A9%E5%BA%93/%E7%94%A8%E6%88%B7%20A.pmv",
            resolved.fileUrl,
        )
        assertEquals(
            "https://example.com/dav/%E6%88%91%E7%9A%84%E4%BF%9D%E9%99%A9%E5%BA%93",
            WebDavCloud.directoryUrl(resolved.fileUrl),
        )
    }

    @Test
    fun `association inspects the generated vault URL and ignores stale HEAD length`() {
        val requests = mutableListOf<Pair<String, String>>()
        RawHttpServer(4) { method, _, path ->
            requests += method to path
            when (method) {
                "OPTIONS" -> Response(204, headers = "DAV: 1, 2\r\n")
                "HEAD" -> Response(200, headers = "Content-Length: 0\r\nETag: \"stale\"\r\n")
                "GET" -> Response(
                    206,
                    body = byteArrayOf(7),
                    headers = "Content-Range: bytes 0-0/4096\r\nETag: \"actual\"\r\n",
                )
                else -> Response(405)
            }
        }.use { server ->
            val config = WebDavCloud.configForDirectory(
                server.secure(WebDavConfig("测试", "${server.origin}/dav/", "", "", createDirectories = false)),
                "main.pmv",
            )
            val metadata = WebDavCloud.inspectAssociation(config)
            assertEquals(true, metadata.exists)
            assertEquals(4096L, metadata.size)
            assertEquals("\"actual\"", metadata.etag)
        }

        assertEquals(
            listOf(
                "OPTIONS" to "/dav",
                "HEAD" to "/dav/main.pmv",
                "HEAD" to "/dav/main.pmv",
                "GET" to "/dav/main.pmv",
            ),
            requests,
        )
    }

    @Test
    fun `tests WebDAV capability against directory instead of missing vault file`() {
        var requestedPath = ""
        RawHttpServer(4) { method, _, path ->
            if (method == "OPTIONS") {
                requestedPath = path
                Response(204, headers = "DAV: 1, 2\r\n")
            } else Response(404)
        }.use { server ->
            WebDavCloud.test(server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false)))
        }

        assertEquals("/", requestedPath)
    }

    @Test
    fun `validates WebDAV and round trips bytes`() {
        var stored = ByteArray(0)
        var finalAvailable = false
        RawHttpServer(8) { method, body, _ ->
            when (method) {
                "OPTIONS" -> Response(204, headers = "DAV: 1, 2\r\nAllow: OPTIONS, HEAD, GET, PUT\r\n")
                "HEAD" -> if (finalAvailable) Response(200, ByteArray(stored.size), "ETag: \"new\"\r\n") else Response(404)
                "PUT" -> { stored = body; finalAvailable = true; Response(204) }
                "GET" -> if (finalAvailable) Response(200, stored) else Response(404)
                else -> Response(405)
            }
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "user", "password", createDirectories = false))
            WebDavCloud.test(config)
            WebDavCloud.upload(config, byteArrayOf(1, 2, 3))
            assertArrayEquals(byteArrayOf(1, 2, 3), WebDavCloud.download(config).bytes)
        }
    }

    @Test
    fun `falls back to safe write probe when OPTIONS is incomplete`() {
        RawHttpServer(5) { method, _, _ -> if (method == "HEAD") Response(404) else Response(204) }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            WebDavCloud.test(config)
        }
    }

    @Test
    fun `supports Digest authentication challenge`() {
        var request = 0
        RawHttpServer(5) { method, _, _ ->
            request++
            when {
                request == 1 -> Response(401, headers = "WWW-Authenticate: Digest realm=\"vault\", nonce=\"abc\", algorithm=SHA-256, qop=\"auth\"\r\n")
                method == "OPTIONS" -> Response(204, headers = "DAV: 1, 2\r\n")
                else -> Response(404)
            }
        }.use { server ->
            WebDavCloud.test(server.secure(WebDavConfig("测试", server.url, "user", "password", authMode = "digest", createDirectories = false)))
        }
    }

    @Test
    fun `rejects incomplete certificate fingerprint`() {
        assertThrows(IllegalArgumentException::class.java) {
            WebDavCloud.validate(WebDavConfig("测试", "https://example.com/vault.pmv", "", "", certificateSha256 = "1234"))
        }
    }

    @Test
    fun `sensitive authentication modes require HTTPS`() {
        listOf(
            WebDavConfig("测试", "http://example.com/vault.pmv", "", "", authMode = "oauth2", bearerToken = "token"),
            WebDavConfig("测试", "http://example.com/vault.pmv", "", "", authMode = "cookie", cookie = "sid=value"),
            WebDavConfig("测试", "http://example.com/vault.pmv", "", "", authMode = "mtls", clientCertificate = "AA=="),
        ).forEach { config ->
            assertThrows(IllegalArgumentException::class.java) { WebDavCloud.validate(config) }
        }
    }

    @Test
    fun `Android rejects domain authentication without a portable credential provider`() {
        listOf("ntlm", "kerberos").forEach { mode ->
            val config = WebDavConfig("测试", "https://example.com/vault.pmv", "user", "password", authMode = mode)
            val error = assertThrows(IllegalArgumentException::class.java) { WebDavCloud.validate(config) }
            assert(error.message.orEmpty().contains("Android"))
        }
    }

    @Test
    fun `returns null when remote vault does not exist`() {
        RawHttpServer(1) { _, _, _ -> Response(404) }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            assertNull(WebDavCloud.downloadIfExists(config))
        }
    }

    @Test
    fun `metadata verifies stale HEAD size with a one byte content probe`() {
        RawHttpServer(2) { method, _, _ ->
            when (method) {
                "HEAD" -> Response(
                    200,
                    headers = "ETag: \"new\"\r\nLast-Modified: Sun, 02 Aug 2026 10:00:00 GMT\r\n",
                )
                "GET" -> Response(
                    206,
                    body = byteArrayOf(7),
                    headers = "Content-Range: bytes 0-0/4096\r\n",
                )
                else -> Response(405)
            }
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            val metadata = WebDavCloud.metadata(config)
            assertEquals(true, metadata.exists)
            assertEquals(4096L, metadata.size)
            assertEquals("\"new\"", metadata.etag)
            assertEquals(true, metadata.lastModified > 0L)
        }
    }

    @Test
    fun `metadata falls back to range GET when HEAD falsely reports missing`() {
        RawHttpServer(2) { method, _, _ ->
            when (method) {
                "HEAD" -> Response(404)
                "GET" -> Response(
                    206,
                    body = byteArrayOf(7),
                    headers = "Content-Range: bytes 0-0/4096\r\nETag: \"real\"\r\n",
                )
                else -> Response(405)
            }
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            val metadata = WebDavCloud.metadata(config)
            assertEquals(true, metadata.exists)
            assertEquals(4096L, metadata.size)
            assertEquals("\"real\"", metadata.etag)
        }
    }

    @Test
    fun `metadata reports missing only after HEAD and range GET both return 404`() {
        RawHttpServer(3) { _, _, _ -> Response(404) }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            val metadata = WebDavCloud.metadata(config)
            assertEquals(false, metadata.exists)
        }
    }

    @Test
    fun `metadata falls back to plain GET when server rejects ranged file lookup`() {
        var getCount = 0
        RawHttpServer(3) { method, _, _ ->
            when (method) {
                "HEAD" -> Response(404)
                "GET" -> if (++getCount == 1) {
                    Response(404)
                } else {
                    Response(200, body = ByteArray(3072) { 7 }, headers = "ETag: \"plain\"\r\n")
                }
                else -> Response(405)
            }
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            val metadata = WebDavCloud.metadata(config)
            assertEquals(true, metadata.exists)
            assertEquals(3072L, metadata.size)
            assertEquals("\"plain\"", metadata.etag)
        }
    }

    @Test
    fun `association content check falls back to plain GET after ranged lookup returns 404`() {
        var getCount = 0
        RawHttpServer(2) { method, _, _ ->
            check(method == "GET")
            if (++getCount == 1) Response(404) else Response(200, body = byteArrayOf(7, 8, 9))
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            assertEquals(true, WebDavCloud.hasContent(config))
        }
    }

    @Test
    fun `content detection ignores stale HEAD size and reads the first remote byte`() {
        RawHttpServer(1) { method, _, _ ->
            check(method == "GET")
            Response(
                206,
                body = byteArrayOf(7),
                headers = "Content-Range: bytes 0-0/4096\r\n",
            )
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            assertEquals(true, WebDavCloud.hasContent(config))
        }
    }

    @Test
    fun `content detection distinguishes missing and truly empty remote files`() {
        RawHttpServer(2) { _, _, _ -> Response(404) }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            assertEquals(false, WebDavCloud.hasContent(config))
        }
        RawHttpServer(1) { method, _, _ ->
            check(method == "GET")
            Response(416, headers = "Content-Range: bytes */0\r\n")
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            assertEquals(false, WebDavCloud.hasContent(config))
        }
    }

    @Test
    fun `forced upload bypasses remote version and verifies final content`() {
        val expected = byteArrayOf(7, 8, 9)
        val file = kotlin.io.path.createTempFile().toFile().apply { writeBytes(expected) }
        var stored = ByteArray(0)
        try {
            RawHttpServer(3) { method, body, _ ->
                when (method) {
                    "PUT" -> { stored = body; Response(204) }
                    "HEAD" -> Response(200, headers = "ETag: \"old\"\r\n")
                    "GET" -> Response(200, stored, "ETag: \"forced\"\r\n")
                    else -> Response(405)
                }
            }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                WebDavCloud.uploadOverwrite(config, file)
                assertArrayEquals(expected, stored)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `upload tolerates WebDAV servers that keep reporting stale length for HEAD`() {
        val expected = byteArrayOf(7, 8, 9)
        var stored = ByteArray(0)
        RawHttpServer(3) { method, body, _ ->
            when (method) {
                "PUT" -> { stored = body; Response(204) }
                "HEAD" -> Response(
                    200,
                    body = byteArrayOf(0),
                    headers = "ETag: \"stale-length\"\r\n",
                )
                "GET" -> Response(
                    200,
                    body = stored,
                    headers = "ETag: \"stale-length\"\r\n",
                )
                else -> Response(405)
            }
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            val verified = WebDavCloud.upload(config, expected)
            assertEquals(expected.size.toLong(), verified.size)
        }

        assertArrayEquals(expected, stored)
    }

    @Test
    fun `file upload rejects conditional final write after ETag change`() {
        val file = kotlin.io.path.createTempFile().toFile().apply { writeBytes(byteArrayOf(4, 5, 6)) }
        try {
            RawHttpServer(3) { method, _, _ ->
                when (method) {
                    "HEAD" -> Response(200, ByteArray(3), "ETag: \"old\"\r\n")
                    "PUT" -> Response(412)
                    "GET" -> Response(200, byteArrayOf(9, 9, 9), "ETag: \"changed\"\r\n")
                    else -> Response(405)
                }
            }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                assertThrows(WebDavConflict::class.java) {
                    WebDavCloud.uploadIfUnchanged(
                        config,
                        file,
                        WebDavMetadata(true, 3, 10, "\"old\""),
                    )
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `conditional PMV upload writes only the final database path`() {
        val expected = byteArrayOf(4, 5, 6)
        val file = kotlin.io.path.createTempFile().toFile().apply { writeBytes(expected) }
        var stored = ByteArray(0)
        try {
            RawHttpServer(3) { method, body, path ->
                assertFalse("条件同步不得创建远端临时文件", ".upload-" in path)
                when (method) {
                    "HEAD" -> Response(200, ByteArray(3), "ETag: \"old\"\r\n")
                    "PUT" -> {
                        assertEquals("/vault.pmv", path)
                        stored = body
                        Response(204)
                    }
                    "GET" -> Response(200, stored, "ETag: \"new\"\r\n")
                    else -> Response(405)
                }
            }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                val verified = WebDavCloud.uploadIfUnchanged(
                    config,
                    file,
                    WebDavMetadata(true, 3L, 10L, "\"old\""),
                )

                assertEquals(3L, verified.size)
                assertArrayEquals(expected, stored)
                assertEquals(1, server.requestLog.count { it.startsWith("PUT ") })
                assertFalse(server.requestLog.any { ".tmp" in it || it.startsWith("MOVE ") })
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `conditional upload tolerates weak ETag when size or modified anchor exists`() {
        val file = kotlin.io.path.createTempFile().toFile().apply { writeBytes(byteArrayOf(4, 5, 6)) }
        try {
            val config = WebDavConfig(
                "测试",
                "https://example.com/vault.pmv",
                "user",
                "password",
                createDirectories = false,
            )
            // 无强 ETag 且无大小/修改时间锚点 → 仍拒绝（没有任何并发保护依据）。
            val error = assertThrows(IllegalArgumentException::class.java) {
                WebDavCloud.uploadIfUnchanged(
                    config,
                    file,
                    WebDavMetadata(true, -1L, 0L, "W/\"weak\""),
                )
            }
            assert(error.message.orEmpty().contains("版本信息"))
            // 弱 ETag 但存在大小/修改时间锚点 → 强 ETag 门槛放宽，不再被前置拒绝。
            val relaxed = runCatching {
                WebDavCloud.uploadIfUnchanged(
                    config,
                    file,
                    WebDavMetadata(true, 3L, 1000L, "W/\"weak\""),
                )
            }.exceptionOrNull()
            assertTrue(relaxed !is IllegalArgumentException)
        } finally {
            file.delete()
        }
    }

    @Test
    fun `upload falls back to size and last modified when server lacks a strong etag`() {
        val file = kotlin.io.path.createTempFile().toFile().apply { writeBytes(byteArrayOf(7, 8, 9)) }
        val lastModified = 1_785_636_000_000L
        val lastModifiedHeader = java.text.SimpleDateFormat(
            "EEE, dd MMM yyyy HH:mm:ss zzz",
            java.util.Locale.US,
        ).apply {
            isLenient = false
            timeZone = java.util.TimeZone.getTimeZone("GMT")
        }.format(java.util.Date(lastModified))
        try {
            RawHttpServer(4) { method, _, _ ->
                when {
                    method == "HEAD" -> Response(
                        200,
                        byteArrayOf(),
                        "ETag: W/\"weak\"\r\nLast-Modified: $lastModifiedHeader\r\n",
                    )
                    method == "GET" -> Response(
                        200,
                        body = byteArrayOf(7, 8, 9),
                        headers = "Last-Modified: $lastModifiedHeader\r\n",
                    )
                    method == "PUT" -> Response(204)
                    else -> Response(405)
                }
            }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                val verified = try {
                    WebDavCloud.uploadIfUnchanged(
                        config,
                        file,
                        WebDavMetadata(true, 3L, lastModified, null),
                    )
                } catch (error: Throwable) {
                    throw AssertionError("请求序列：${server.requestLog}", error)
                }
                assertEquals(3L, verified.size)
                val finalPut = server.requestHeaders.lastOrNull { it["if-unmodified-since"] != null }
                assertTrue("无强 ETag 时应携带 If-Unmodified-Since", finalPut != null)
                assertEquals(lastModifiedHeader, finalPut?.get("if-unmodified-since"))
                assertFalse("无强 ETag 时不得使用 If-Match", finalPut?.containsKey("if-match") == true)
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `upload fallback rejects when size or last modified changed`() {
        val file = kotlin.io.path.createTempFile().toFile().apply { writeBytes(byteArrayOf(7, 8, 9)) }
        try {
            RawHttpServer(2) { method, _, path ->
                when {
                    method == "HEAD" && ".upload-" in path -> Response(
                        200,
                        byteArrayOf(),
                        "ETag: W/\"weak\"\r\nLast-Modified: Sun, 02 Aug 2026 10:00:00 GMT\r\n",
                    )
                    method == "HEAD" -> Response(
                        200,
                        byteArrayOf(),
                        "ETag: W/\"weak\"\r\nLast-Modified: Sun, 02 Aug 2026 10:00:01 GMT\r\n",
                    )
                    method == "GET" && ".upload-" in path -> Response(
                        206,
                        body = byteArrayOf(7),
                        headers = "Content-Range: bytes 0-0/3\r\nLast-Modified: Sun, 02 Aug 2026 10:00:00 GMT\r\n",
                    )
                    method == "GET" -> Response(
                        206,
                        body = byteArrayOf(7),
                        headers = "Content-Range: bytes 0-0/4\r\nLast-Modified: Sun, 02 Aug 2026 10:00:01 GMT\r\n",
                    )
                    method == "PUT" && ".upload-" in path -> Response(204)
                    method == "PUT" -> Response(204)
                    method == "DELETE" -> Response(204)
                    else -> Response(405)
                }
            }.use { server ->
                val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                assertThrows(WebDavConflict::class.java) {
                    WebDavCloud.uploadIfUnchanged(
                        config,
                        file,
                        WebDavMetadata(true, 3L, 1_785_636_000_000L, null),
                    )
                }
            }
        } finally {
            file.delete()
        }
    }

    @Test
    fun `etag variants tolerate content coding suffixes but never null`() {
        assertTrue(WebDavCloud.etagVariantsMatch("\"abc-gzip\"", "\"abc\""))
        assertTrue(WebDavCloud.etagVariantsMatch("\"abc-br\"", "\"abc\""))
        assertTrue(WebDavCloud.etagVariantsMatch("\"abc-zstd\"", "\"abc\""))
        assertTrue(WebDavCloud.etagVariantsMatch("\"abc-gzip\"", "\"abc-gzip\""))
        assertFalse(WebDavCloud.etagVariantsMatch("\"abc-gzip\"", "\"xyz\""))
        assertFalse(WebDavCloud.etagVariantsMatch("\"abc-gzip\"", null))
        assertFalse(WebDavCloud.etagVariantsMatch(null, "\"abc\""))
        assertTrue(WebDavCloud.etagVariantsMatch(null, null))
    }

    @Test
    fun `metadata prefers canonical OC ETag over gzip mangled ETag`() {
        RawHttpServer(2) { method, _, _ ->
            when (method) {
                "HEAD" -> Response(
                    200,
                    headers = "ETag: \"abc-gzip\"\r\nOC-ETag: \"abc\"\r\n",
                )
                "GET" -> Response(
                    206,
                    body = byteArrayOf(7),
                    headers = "Content-Range: bytes 0-0/10\r\nETag: \"abc-gzip\"\r\nOC-ETag: \"abc\"\r\n",
                )
                else -> Response(405)
            }
        }.use { server ->
            val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
            val metadata = WebDavCloud.metadata(config)
            assertEquals("\"abc\"", metadata.etag)
        }
    }

    @Test
    fun `download returns canonical OC ETag when GET is gzip mangled`() {
        val target = kotlin.io.path.createTempFile().toFile()
        try {
            RawHttpServer(1) { method, _, _ ->
                check(method == "GET")
                Response(
                    200,
                    body = byteArrayOf(7, 8, 9),
                    headers = "ETag: \"abc-gzip\"\r\nOC-ETag: \"abc\"\r\n",
                )
            }.use { server ->
                val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                val remote = WebDavCloud.downloadTo(config, target)
                assertEquals("\"abc\"", remote.etag)
                assertEquals(3L, remote.size)
            }
        } finally {
            target.delete()
        }
    }

    @Test
    fun `download deletes partial target when response ends before declared length`() {
        val target = kotlin.io.path.createTempFile().toFile().apply { writeText("old") }
        try {
            RawHttpServer(1) { method, _, _ ->
                check(method == "GET")
                Response(
                    200,
                    body = byteArrayOf(7, 8, 9),
                    headers = "Content-Length: 9\r\n",
                )
            }.use { server ->
                val config = server.secure(WebDavConfig("测试", server.url, "", "", createDirectories = false))
                assertThrows(Exception::class.java) { WebDavCloud.downloadTo(config, target) }
                assertFalse("不完整下载不得保留为目标文件", target.exists())
            }
        } finally {
            target.delete()
        }
    }

    private data class Response(val status: Int, val body: ByteArray = byteArrayOf(), val headers: String = "")

    private class RawHttpServer(
        private val expectedRequests: Int,
        responder: (String, ByteArray, String) -> Response,
    ) : AutoCloseable {
        private val certificate = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("127.0.0.1")
            .build()
        private val handshake = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        private val socket = javax.net.ssl.SSLContext.getInstance("TLS").apply {
            init(arrayOf(handshake.keyManager), null, null)
        }.serverSocketFactory.createServerSocket(0) as ServerSocket
        private val handledRequests = java.util.concurrent.atomic.AtomicInteger()
        val requestHeaders = java.util.concurrent.CopyOnWriteArrayList<Map<String, String>>()
        val requestLog = java.util.concurrent.CopyOnWriteArrayList<String>()
        private val fingerprint = java.security.MessageDigest.getInstance("SHA-256")
            .digest(certificate.certificate.encoded)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val origin = "https://127.0.0.1:${socket.localPort}"
        val url = "https://127.0.0.1:${socket.localPort}/vault.pmv"

        fun secure(config: WebDavConfig): WebDavConfig = config.copy(certificateSha256 = fingerprint)
        private val worker = thread(start = true, isDaemon = true) {
            while (!socket.isClosed) {
                val client = try {
                    socket.accept()
                } catch (_: java.net.SocketException) {
                    break
                }
                client.use {
                    val input = it.getInputStream().buffered()
                    val requestLine = readLine(input)
                    val method = requestLine.substringBefore(' ')
                    val path = requestLine.substringAfter(' ').substringBefore(' ')
                    var length = 0
                    val headers = mutableMapOf<String, String>()
                    while (true) {
                        val line = readLine(input)
                        if (line.isEmpty()) break
                        val colon = line.indexOf(':')
                        if (colon > 0) {
                            headers[line.substring(0, colon).trim().lowercase()] =
                                line.substring(colon + 1).trim()
                        }
                        if (line.startsWith("Content-Length:", true)) length = line.substringAfter(':').trim().toInt()
                    }
                    requestHeaders.add(headers)
                    requestLog.add("$method $path")
                    val body = ByteArray(length)
                    var offset = 0
                    while (offset < length) offset += input.read(body, offset, length - offset)
                    val response = responder(method, body, path)
                    handledRequests.incrementAndGet()
                    val reason = if (response.status == 404) "Not Found" else "OK"
                    it.getOutputStream().use { output ->
                        val contentLength = if (response.headers.contains("Content-Length:", true)) "" else "Content-Length: ${response.body.size}\r\n"
                        output.write("HTTP/1.1 ${response.status} $reason\r\n${response.headers}${contentLength}Connection: close\r\n\r\n".toByteArray())
                        output.write(response.body)
                    }
                }
            }
        }

        override fun close() {
            socket.close()
            worker.join(2_000)
            assertEquals("unexpected HTTP request count", expectedRequests, handledRequests.get())
        }

        private fun readLine(input: java.io.InputStream): String {
            val bytes = ArrayList<Byte>()
            while (true) {
                val next = input.read()
                if (next < 0 || next == '\n'.code) break
                if (next != '\r'.code) bytes.add(next.toByte())
            }
            return bytes.toByteArray().decodeToString()
        }
    }
}
