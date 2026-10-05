package com.vault.ui.markdown

import com.vault.storage.MediaCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/** 行为测试用的直通编解码：模拟“总是可加密”的环境，不依赖 MediaCrypto 会话状态。 */
private val PlainPassthroughCodec = object : MermaidSvgDiskCodec {
    override fun encode(plain: String): ByteArray = plain.toByteArray(Charsets.UTF_8)
    override fun decode(raw: ByteArray): String = raw.toString(Charsets.UTF_8)
}

class MermaidSvgCacheTest {

    @Test
    fun `put then get returns svg`() {
        val cache = MermaidSvgCache()
        cache.put("k1", "<svg>a</svg>")
        assertEquals("<svg>a</svg>", cache.get("k1"))
    }

    @Test
    fun `missing key returns null`() {
        val cache = MermaidSvgCache()
        assertNull(cache.get("nope"))
    }

    @Test
    fun `lru evicts oldest beyond capacity`() {
        val cache = MermaidSvgCache(maxEntries = 3)
        cache.put("a", "1")
        cache.put("b", "2")
        cache.put("c", "3")
        cache.get("a") // 触碰 a，使其新于 b
        cache.put("d", "4")
        assertNull(cache.get("b"))
        assertEquals("1", cache.get("a"))
        assertEquals("3", cache.get("c"))
        assertEquals("4", cache.get("d"))
    }

    @Test
    fun `oversized svg rejected`() {
        val cache = MermaidSvgCache(maxSvgChars = 10)
        cache.put("big", "<svg>" + "x".repeat(20) + "</svg>")
        assertNull(cache.get("big"))
        cache.put("small", "<svg/>")
        assertEquals("<svg/>", cache.get("small"))
    }

    @Test
    fun `empty key or svg rejected`() {
        val cache = MermaidSvgCache()
        cache.put("", "<svg/>")
        cache.put("k", "")
        assertNull(cache.get(""))
        assertNull(cache.get("k"))
    }

    @Test
    fun `cache key is stable and source sensitive`() {
        val a1 = mermaidSvgCacheKey("graph TD; A-->B")
        val a2 = mermaidSvgCacheKey("graph TD; A-->B")
        val b = mermaidSvgCacheKey("graph TD; A-->C")
        assertEquals(a1, a2)
        assertNotEquals(a1, b)
    }

    @Test
    fun `disk cache persists across instances`() {
        val dir = Files.createTempDirectory("mermaid_svg").toFile()
        try {
            val writer = MermaidSvgCache(diskDir = dir, codec = PlainPassthroughCodec)
            writer.put("persist", "<svg>disk</svg>")
            assertTrue(java.io.File(dir, "persist.svg").isFile)

            // 新实例（模拟进程重启）：内存为空，从磁盘回源
            val reader = MermaidSvgCache(diskDir = dir, codec = PlainPassthroughCodec)
            assertEquals("<svg>disk</svg>", reader.get("persist"))
            assertNull(reader.get("missing"))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `oversized disk entry is discarded on read`() {
        val dir = Files.createTempDirectory("mermaid_svg2").toFile()
        try {
            val cache = MermaidSvgCache(maxSvgChars = 10, diskDir = dir, codec = PlainPassthroughCodec)
            cache.put("big", "<svg>" + "x".repeat(40) + "</svg>")
            assertNull(cache.get("big"))
        } finally {
            dir.deleteRecursively()
        }
    }

    // ── 磁盘静态加密（VMED / MediaCrypto）──

    @Test
    fun `disk entries are vmed encrypted by default`() {
        MediaCrypto.setContext("vault-t", ByteArray(32) { it.toByte() })
        val dir = Files.createTempDirectory("mermaid_svg_enc").toFile()
        try {
            val cache = MermaidSvgCache(diskDir = dir)
            cache.put("enc", "<svg>secret-content</svg>")

            val file = java.io.File(dir, "enc.svg")
            assertTrue(file.isFile)
            val raw = file.readBytes()
            assertEquals("VMED", raw.copyOfRange(0, 4).toString(Charsets.US_ASCII))
            assertFalse(raw.toString(Charsets.ISO_8859_1).contains("secret-content"))

            // 新实例（模拟进程重启）：密文回源后解密还原
            assertEquals("<svg>secret-content</svg>", MermaidSvgCache(diskDir = dir).get("enc"))
        } finally {
            dir.deleteRecursively()
            MediaCrypto.clear()
        }
    }

    @Test
    fun `inactive media session skips disk persistence`() {
        MediaCrypto.clear()
        val dir = Files.createTempDirectory("mermaid_svg_nolock").toFile()
        try {
            val cache = MermaidSvgCache(diskDir = dir)
            cache.put("nolock", "<svg>x</svg>")
            // 内存命中不受影响，但绝不落明文盘
            assertEquals("<svg>x</svg>", cache.get("nolock"))
            assertFalse(java.io.File(dir, "nolock.svg").exists())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun `encrypted entry unreadable without unlocked media session`() {
        MediaCrypto.setContext("vault-w", ByteArray(32) { 7 })
        val dir = Files.createTempDirectory("mermaid_svg_lock").toFile()
        try {
            MermaidSvgCache(diskDir = dir).put("locked", "<svg>y</svg>")
            MediaCrypto.clear() // 模拟锁定会话

            val file = java.io.File(dir, "locked.svg")
            assertTrue(file.isFile)
            assertNull(MermaidSvgCache(diskDir = dir).get("locked"))
        } finally {
            dir.deleteRecursively()
            MediaCrypto.clear()
        }
    }

    @Test
    fun `legacy plaintext disk entries still readable`() {
        MediaCrypto.setContext("vault-l", ByteArray(32))
        val dir = Files.createTempDirectory("mermaid_svg_legacy").toFile()
        try {
            // 升级前写入的旧明文缓存：decrypt 对无 VMED 头内容原样返回
            java.io.File(dir, "old.svg").writeText("<svg>legacy</svg>")
            assertEquals("<svg>legacy</svg>", MermaidSvgCache(diskDir = dir).get("old"))
        } finally {
            dir.deleteRecursively()
            MediaCrypto.clear()
        }
    }
}
