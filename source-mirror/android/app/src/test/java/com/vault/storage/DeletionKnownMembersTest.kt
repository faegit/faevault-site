package com.vault.storage

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class DeletionKnownMembersTest {
    private val a = "11111111-1111-4111-8111-111111111111"
    private val b = "22222222-2222-4222-8222-222222222222"
    @Test fun activityMergePreservesHistoricalHoldersWithoutProfilesOrAuthorization() {
        val left = buildJsonObject { put(DeletionKnownMembers.KEY, JsonArray(listOf(JsonPrimitive(a)))) }
        val right = buildJsonObject { put(DeletionKnownMembers.KEY, JsonArray(listOf(JsonPrimitive(b)))) }
        assertEquals(listOf(a, b), DeletionKnownMembers.read(DeviceActivity.merge(left, right)))
    }
    @Test fun futureActivityMergeStillPreservesHistoricalHolderKnowledge() {
        val left = buildJsonObject { put(DeletionKnownMembers.KEY, JsonArray(listOf(JsonPrimitive(a)))) }
        val right = buildJsonObject {
            put(DeletionKnownMembers.KEY, JsonArray(listOf(JsonPrimitive(b))))
            put(DeviceActivity.KEY, buildJsonObject { put("version", 2) })
        }
        assertEquals(listOf(a, b), DeletionKnownMembers.read(DeviceActivity.merge(left, right)))
    }
    @Test fun normalTouchRetainsRawDeviceIdsWithUnsupportedDescriptions() {
        for ((platform, name) in listOf("future-platform" to "B", "pc" to "B".repeat(65))) {
            val source = buildJsonObject {
                put(DeviceActivity.KEY, buildJsonObject {
                    put("version", 1)
                    put("profiles", JsonArray(listOf(buildJsonObject {
                        put("device_id", b); put("platform", platform); put("name", name)
                        put("last_seen_at", 1); put("updated_at", 1)
                    })))
                })
            }
            val retained = DeletionKnownMembers.retain(source)
            assertEquals(listOf(b), DeletionKnownMembers.read(retained))
            val touched = DeviceActivity.touch(retained, a, "A", now = 2)
            assertEquals(listOf(a, b), DeletionKnownMembers.read(touched))
        }
    }
    @Test fun malformedRawActivityDeviceIdFailsBeforeNormalization() {
        val source = buildJsonObject { put(DeviceActivity.KEY, buildJsonObject {
            put("version", 1)
            put("profiles", JsonArray(listOf(buildJsonObject { put("device_id", "invalid"); put("platform", "future") })))
        }) }
        assertTrue(runCatching { DeletionKnownMembers.retain(source) }.isFailure)
    }
    @Test fun malformedHolderHistoryIsRejected() {
        for (raw in listOf(JsonPrimitive("invalid"), JsonArray(listOf(JsonPrimitive("invalid"))), JsonArray(listOf(JsonPrimitive(a), JsonPrimitive(a))))) {
            assertTrue(runCatching { DeletionKnownMembers.read(buildJsonObject { put(DeletionKnownMembers.KEY, raw) }) }.isFailure)
        }
    }
}
