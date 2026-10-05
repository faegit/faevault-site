package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 传输列表显示名。
 *
 * 回归点：主机侧把文本内容暂存成文件后，用生成的文件名（message_<时间戳>.txt）入队，
 * 而连接方侧一直显示内容本身。两端口径不一致，主机侧看上去「不显示内容、只显示文件名」。
 */
class TransferDisplayTest {

    @Test
    fun `text transfer shows the content instead of the generated file name`() {
        assertEquals(
            "这是一段要传过去的文本",
            transferDisplayName("text", "message_20260930-153012.txt", "这是一段要传过去的文本"),
        )
    }

    @Test
    fun `only the first line of a multi line text is shown`() {
        assertEquals(
            "第一行",
            transferDisplayName("text", "message_20260930-153012.txt", "第一行\n第二行\n第三行"),
        )
    }

    @Test
    fun `long text is truncated`() {
        val preview = "x".repeat(200)
        assertEquals(80, transferDisplayName("text", "message_1.txt", preview).length)
    }

    @Test
    fun `file transfer keeps its file name`() {
        assertEquals(
            "年度报告.pdf",
            transferDisplayName("file", "年度报告.pdf", ""),
        )
    }

    @Test
    fun `text without a preview falls back to the file name`() {
        // 没有预览时不该显示成空白
        assertEquals(
            "message_20260930-153012.txt",
            transferDisplayName("text", "message_20260930-153012.txt", ""),
        )
    }
}
