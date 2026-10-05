package com.vault

import com.vault.model.EntryModules
import com.vault.model.ModuleType
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

class MarkdownModuleTest {
    @Test
    fun `multiline module is displayed as Markdown and keeps wire type`() {
        assertEquals("multiline", ModuleType.MULTILINE)
        assertEquals("Markdown", EntryModules.catalog.getValue(ModuleType.MULTILINE).title)
        // 旧条目仍以 “multiline” 线格式存取，改名不影响既有数据
        val module = EntryModules.create(ModuleType.MULTILINE)
        assertEquals("multiline", EntryModules.primitive(module["type"]))
    }

    @Test
    fun `text module carries multiline content`() {
        val module = EntryModules.create(ModuleType.TEXT)
        val updated = JsonObject(
            module.toMutableMap().apply {
                this["value"] = JsonPrimitive("line1\nline2\nline3")
            },
        )
        assertEquals("line1\nline2\nline3", EntryModules.primitive(updated["value"]))
    }
}
