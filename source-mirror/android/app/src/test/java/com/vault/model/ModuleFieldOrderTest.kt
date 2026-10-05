package com.vault.model

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertEquals
import org.junit.Test

class ModuleFieldOrderTest {

    /** 模拟 PMVE canonicalJson 落盘排序：对象键按无符号 UTF-8 字节序排列。 */
    private fun canonicalSorted(value: JsonObject): JsonObject {
        fun utf8Compare(a: String, b: String): Int {
            val ab = a.encodeToByteArray()
            val bb = b.encodeToByteArray()
            val common = minOf(ab.size, bb.size)
            for (i in 0 until common) {
                val cmp = (ab[i].toInt() and 0xff).compareTo(bb[i].toInt() and 0xff)
                if (cmp != 0) return cmp
            }
            return ab.size.compareTo(bb.size)
        }
        val sortedKeys = value.keys.sortedWith(::utf8Compare)
        return JsonObject(sortedKeys.associateWith { value.getValue(it) })
    }

    @Test
    fun otpModuleFieldOrderRestoredAfterCanonicalSort() {
        val created = EntryModules.create(ModuleType.OTP)
        val value = created["value"] as JsonObject
        val canonical = canonicalSorted(value)

        // canonical 排序后字段顺序必然与定义顺序不同
        assertEquals(created["value"] as JsonObject, canonical)

        val restored = EntryModules.orderedValue(buildJsonObject {
            put("id", created["id"]!!)
            put("type", created["type"]!!)
            put("value", canonical)
        })
        assertEquals(value.keys.toList(), restored.keys.toList())
        assertEquals(value, restored)
    }

    @Test
    fun unknownKeysAppendAtTailInRelativeOrder() {
        val value = JsonObject(
            linkedMapOf(
                "username" to JsonPrimitive("u"),
                "password" to JsonPrimitive("p"),
                "custom_extra" to JsonPrimitive("x"),
                "another_extra" to JsonPrimitive("y"),
            )
        )
        val module = buildJsonObject {
            put("type", ModuleType.LOGIN_ACCOUNT)
            put("value", value)
        }
        val restored = EntryModules.orderedValue(module)
        assertEquals(listOf("username", "password", "custom_extra", "another_extra"), restored.keys.toList())
    }

    @Test
    fun imagesFieldIsLastWhenPresent() {
        val value = JsonObject(
            linkedMapOf(
                "images" to JsonArray(emptyList()),
                "cardholder" to JsonPrimitive("张三"),
            )
        )
        val module = buildJsonObject {
            put("type", ModuleType.CARD_DOCUMENT)
            put("value", value)
        }
        val restored = EntryModules.orderedValue(module)
        val keys = restored.keys.toList()
        assertEquals("images", keys.last())
        assertEquals(listOf("cardholder", "images"), keys)
    }

    @Test
    fun otpDomainsIsInFieldOrderAndReadable() {
        val value = JsonObject(
            linkedMapOf(
                "secret" to JsonPrimitive("JBSWY3DPEHPK3PXP"),
                "counter" to JsonPrimitive("0"),
                "otp_domains" to JsonPrimitive("example.com, live.com"),
            )
        )
        val module = buildJsonObject {
            put("type", ModuleType.OTP)
            put("value", value)
        }
        val keys = EntryModules.orderedValue(module).keys.toList()
        // 仅实际存在的键按 fieldOrder 排序；otp_domains 在 counter 之后
        assertEquals(listOf("secret", "counter", "otp_domains"), keys)

        val entry = Entry(
            secretType = SecretType.OTP,
            fields = buildJsonObject { put(EntryModules.FIELD_KEY, JsonArray(listOf(module))) },
        )
        assertEquals(listOf("example.com", "live.com"), entry.otpDomains())
    }
}