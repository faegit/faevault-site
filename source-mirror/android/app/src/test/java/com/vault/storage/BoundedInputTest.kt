package com.vault.storage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.ByteArrayInputStream

class BoundedInputTest {
    @Test
    fun `2 GiB safety limit no longer trips the failed-requirement guard`() {
        // MAX_VAULT_BYTES(2 GiB) > Int.MAX_VALUE：旧实现会在入口立即抛“Failed requirement.”
        val data = "backup".toByteArray()
        val read = ByteArrayInputStream(data).readBytesLimited(MAX_VAULT_BYTES, "备份文件")
        assertArrayEquals(data, read)
    }

    @Test
    fun `rejects non positive limits with a clear message`() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            ByteArrayInputStream(ByteArray(1)).readBytesLimited(0L, "备份文件")
        }
        assertEquals("备份文件 大小限制必须为正数", error.message)
    }

    @Test
    fun `enforces the byte cap and reports the label`() {
        val error = assertThrows(IllegalStateException::class.java) {
            ByteArrayInputStream(ByteArray(128)).readBytesLimited(64L, "备份文件")
        }
        assertEquals("备份文件 超过安全大小限制", error.message)
    }
}
