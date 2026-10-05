package com.vault.model

import org.junit.Assert.assertEquals
import org.junit.Test

class PinyinFirstLetterTest {
    @Test
    fun `digit and symbol leading titles fall into hash group`() {
        assertEquals('#', Pinyin.firstLetter("0011.ai"))
        assertEquals('#', Pinyin.firstLetter("123pan.com"))
        assertEquals('#', Pinyin.firstLetter("555yy1.com"))
        assertEquals('#', Pinyin.firstLetter("10.5.80.24"))
        assertEquals('#', Pinyin.firstLetter(".hidden"))
        assertEquals('#', Pinyin.firstLetter(""))
    }

    @Test
    fun `letter leading titles use their own letter`() {
        assertEquals('A', Pinyin.firstLetter("amazon"))
        assertEquals('B', Pinyin.firstLetter("baidu.com"))
        assertEquals('Q', Pinyin.firstLetter("QQ"))
    }
}
