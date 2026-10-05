package com.vault.ui.screens

import com.vault.model.Entry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class AlphabetIndexTest {
    @Test
    fun `leaked entries are excluded without shifting real list indices`() {
        val entries = listOf(
            entry("leaked-a", "Alpha"),
            entry("normal-a", "Alpine"),
            entry("leaked-b", "Beta"),
            entry("normal-c", "Charlie"),
        )

        val index = alphabetFirstIndices(entries, setOf("leaked-a", "leaked-b")) { it.title.first() }

        assertEquals(0, index['#'])
        assertEquals(1, index['A'])
        assertFalse('B' in index)
        assertEquals(3, index['C'])
    }

    @Test
    fun `first occurrence for each normal letter is retained`() {
        val entries = listOf(
            entry("a1", "Alpha"),
            entry("a2", "Atlas"),
            entry("b1", "Beta"),
        )

        assertEquals(mapOf('A' to 0, 'B' to 2), alphabetFirstIndices(entries, emptySet()) { it.title.first() })
    }

    @Test
    fun `every letter locates correctly with leaked group on top`() {
        // 模拟已排序列表：泄露条目置顶（# 分组），其余按字母序。
        val leaked = listOf(entry("l1", "LeakOne"), entry("l2", "LeakTwo"))
        val normal = ('A'..'Z').mapIndexed { i, ch -> entry("n$ch", "$ch-normal") }
        val sorted = leaked + normal

        val index = alphabetFirstIndices(sorted, leaked.map { it.id }.toSet()) { it.title.first() }

        assertEquals(0, index['#'])
        ('A'..'Z').forEach { ch ->
            val expected = leaked.size + (ch - 'A')
            assertEquals("letter $ch should map to index $expected", expected, index[ch])
        }
        assertEquals(27, index.size)
    }

    private fun entry(id: String, title: String): Entry = Entry(id = id, title = title)
}
