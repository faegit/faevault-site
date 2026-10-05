package com.vault.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class EntryNormalizeTagsTest {

    private fun entry(secretType: String, tags: List<String> = listOf("工作")) =
        Entry(title = "示例", secretType = secretType, tags = tags)

    @Test
    fun loginKeepsTags() {
        val out = entry(SecretType.LOGIN).normalized(1.0)
        assertEquals(listOf("工作"), out.tags)
    }

    @Test
    fun everyTypeKeepsTags() {
        // 标签是纯元数据，Passkey 也参与：条目本身不可编辑，但用户需要在
        // 混合类目里筛选与批量整理它们。此前 normalized() 对 passkey 清空 tags。
        for (type in SecretType.ALL) {
            val out = entry(type).normalized(1.0)
            assertEquals("$type 应保留标签", listOf("工作"), out.tags)
        }
    }

    @Test
    fun passkeyKeepsTagsButStaysReadOnly() {
        val out = entry(SecretType.PASSKEY).normalized(1.0)
        assertEquals(listOf("工作"), out.tags)
        // 放开标签不应改变可编辑性：passkey 仍不在可手动新增的类型集合里。
        assertFalse(SecretType.PASSKEY in SecretType.CREATABLE)
    }

    @Test
    fun unknownTypeFallsBackToLoginAndKeepsTags() {
        val out = entry("mystery_type").normalized(1.0)
        assertEquals(SecretType.LOGIN, out.secretType)
        assertEquals(listOf("工作"), out.tags)
    }
}
