package com.vault.storage

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.provider.OpenableColumns
import com.vault.security.SessionBytes
import java.io.ByteArrayOutputStream
import java.io.FileNotFoundException
import java.util.LinkedHashMap
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/** Process-local, expiring tickets for one-shot PMVE preview/share pipes. */
object PmvMediaContentRegistry {
    private const val DEFAULT_TTL_MS = 2 * 60 * 1000L
    private val tickets = ConcurrentHashMap<String, Ticket>()

    internal class Ticket(
        val vaultName: String,
        val ref: PmvMediaRef.Ref,
        val displayName: String,
        val mimeType: String,
        private val rootKey: SessionBytes,
        val expiresAtNanos: Long,
    ) : AutoCloseable {
        fun <T> withRootKey(block: (ByteArray) -> T): T {
            val copy = rootKey.reveal()
            return try { block(copy) } finally { copy.fill(0) }
        }

        override fun close() = rootKey.close()
    }

    fun issue(
        context: Context,
        vaultName: String,
        rootKey: ByteArray,
        ref: PmvMediaRef.Ref,
        displayName: String,
        mimeType: String,
        ttlMillis: Long = DEFAULT_TTL_MS,
    ): Uri {
        require(vaultName.isNotBlank()) { "vaultName 不能为空" }
        require(rootKey.size == 32) { "PMVE RootKey 必须为 32 字节" }
        require(ttlMillis in 1..TimeUnit.MINUTES.toMillis(10)) { "媒体票据有效期无效" }
        require(mimeType.isNotBlank() && '\r' !in mimeType && '\n' !in mimeType) { "MIME type 无效" }
        evictExpired()
        val safeName = displayName.substringAfterLast('/').substringAfterLast('\\')
            .filter { it >= ' ' && it != '\u007f' }
            .take(200)
            .ifBlank { "vault-media" }
        val ticket = Ticket(
            vaultName,
            ref.copySha256(),
            safeName,
            mimeType,
            SessionBytes(rootKey),
            Math.addExact(System.nanoTime(), TimeUnit.MILLISECONDS.toNanos(ttlMillis)),
        )
        var token: String
        do {
            token = UUID.randomUUID().toString()
        } while (tickets.putIfAbsent(token, ticket) != null)
        return Uri.Builder()
            .scheme("content")
            .authority(authority(context))
            .appendPath(token)
            .build()
    }

    fun revoke(uri: Uri) {
        token(uri)?.let(tickets::remove)?.close()
    }

    internal fun peek(uri: Uri): Ticket? {
        evictExpired()
        return token(uri)?.let(tickets::get)?.takeIf { it.expiresAtNanos > System.nanoTime() }
    }

    internal fun take(uri: Uri): Ticket? {
        evictExpired()
        return token(uri)?.let(tickets::remove)?.takeIf { ticket ->
            if (ticket.expiresAtNanos > System.nanoTime()) true else {
                ticket.close()
                false
            }
        }
    }

    internal fun clear() {
        tickets.values.forEach(Ticket::close)
        tickets.clear()
    }

    private fun token(uri: Uri): String? = uri.pathSegments.singleOrNull()

    private fun evictExpired() {
        val now = System.nanoTime()
        tickets.entries.forEach { (token, ticket) ->
            if (ticket.expiresAtNanos <= now && tickets.remove(token, ticket)) ticket.close()
        }
    }

    internal fun authority(context: Context): String = "${context.packageName}.pmvmedia"
}

/** Streams authenticated PMVE media through a pipe; plaintext is never persisted outside PMV. */
class PmvMediaContentProvider : ContentProvider() {
    override fun onCreate(): Boolean = true

    override fun getType(uri: Uri): String? = PmvMediaContentRegistry.peek(uri)?.mimeType

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? {
        val ticket = PmvMediaContentRegistry.peek(uri) ?: return null
        val requested = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(requested).apply {
            addRow(requested.map { column ->
                when (column) {
                    OpenableColumns.DISPLAY_NAME -> ticket.displayName
                    OpenableColumns.SIZE -> ticket.ref.size
                    else -> null
                }
            })
        }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor = openFile(uri, mode, null)

    override fun openFile(
        uri: Uri,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException("PMVE media provider is read-only")
        signal?.throwIfCanceled()
        val ticket = PmvMediaContentRegistry.take(uri) ?: throw FileNotFoundException("媒体票据不存在或已过期")
        val appContext = requireNotNull(context).applicationContext
        val storageManager = appContext.getSystemService(Context.STORAGE_SERVICE) as StorageManager
        return try {
            storageManager.openProxyFileDescriptor(
                ParcelFileDescriptor.MODE_READ_ONLY,
                PmvSeekableCallback(appContext, ticket, signal),
                ioHandler,
            )
        } catch (t: Throwable) {
            ticket.close()
            throw t
        }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? =
        throw UnsupportedOperationException("read-only")

    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("read-only")

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int =
        throw UnsupportedOperationException("read-only")

    /**
     * 可 seek 的代理 FD：BitmapRegionDecoder 等需要随机访问的消费方按 chunk 粒度惰性解密
     * （openPmvEMediaRange），不再整对象物化明文临时文件。共享/导出等顺序消费方经
     * openInputStream 读同一 FD，行为不变。
     */
    private class PmvSeekableCallback(
        context: Context,
        private val ticket: PmvMediaContentRegistry.Ticket,
        private val signal: CancellationSignal?,
    ) : ProxyFileDescriptorCallback() {
        private val repository = VaultRepository(context, VaultRegistry(context), ticket.vaultName)
        private val totalSize = ticket.ref.size
        private val chunkCache = ChunkCache()

        override fun onGetSize(): Long = totalSize

        override fun onRead(offset: Long, size: Int, data: ByteArray): Int {
            signal?.throwIfCanceled()
            if (offset < 0 || offset >= totalSize || size <= 0) return 0
            val len = minOf(size.toLong(), totalSize - offset).toInt()
            chunkCache.copyRange(offset, len, data)
            return len
        }

        override fun onFsync() {
            signal?.throwIfCanceled()
        }

        override fun onRelease() {
            signal?.setOnCancelListener(null)
            ticket.close()
        }

        /** 按 chunk 粒度惰性解密并 LRU 缓存，避免 BitmapRegionDecoder 的重复小读取反复解密同一 8MiB 块。 */
        private inner class ChunkCache {
            private val cache = object : LinkedHashMap<Long, ByteArray>(MAX_CHUNKS, 0.75f, true) {
                override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, ByteArray>): Boolean =
                    size > MAX_CHUNKS
            }

            fun copyRange(offset: Long, length: Int, data: ByteArray) {
                var dst = 0
                var cur = offset
                val end = offset + length
                while (cur < end) {
                    val idx = cur / PmvAttachmentCodec.CHUNK_SIZE
                    val chunkStart = idx * PmvAttachmentCodec.CHUNK_SIZE
                    val chunk = chunk(idx)
                    val from = (cur - chunkStart).toInt()
                    val to = minOf((end - chunkStart).toInt(), chunk.size)
                    System.arraycopy(chunk, from, data, dst, to - from)
                    dst += to - from
                    cur = chunkStart + to
                }
            }

            private fun chunk(idx: Long): ByteArray {
                cache[idx]?.let { return it }
                val chunkStart = idx * PmvAttachmentCodec.CHUNK_SIZE
                val chunkLen = minOf(PmvAttachmentCodec.CHUNK_SIZE.toLong(), totalSize - chunkStart).toInt()
                val out = ByteArrayOutputStream(chunkLen)
                ticket.withRootKey { rootKey ->
                    repository.openPmvEMediaRange(ticket.ref, rootKey, chunkStart, chunkLen.toLong(), out)
                }
                val bytes = out.toByteArray()
                cache[idx] = bytes
                return bytes
            }

        }

        private companion object {
            const val MAX_CHUNKS = 4
        }
    }

    companion object {
        private val ioHandler: Handler by lazy {
            val thread = HandlerThread("pmv-media-seek", Process.THREAD_PRIORITY_BACKGROUND)
            thread.start()
            Handler(thread.looper)
        }
    }
}
