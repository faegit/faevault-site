package com.vault.storage

import java.io.File
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class DeviceActivityTest {
    @Test fun sharedWriterFixturesRequireAuthenticatedParentBinding() {
        val fixtures = Json.parseToJsonElement(File(System.getProperty("spec.dir"), "device_activity_v1_fixtures.json").readText()).jsonObject
        fixtures.getValue("writer_cases").jsonArray.forEach { raw ->
            val case = raw.jsonObject
            val metadata = buildJsonObject { put(DeviceActivity.KEY, case.getValue("metadata")) }
            assertEquals(case.getValue("name").jsonPrimitive.content,
                case.getValue("expected_device_id").jsonPrimitive.contentOrNull,
                DeviceActivity.writer(metadata, case.getValue("parent_commit_id").jsonPrimitive.content)?.deviceId)
        }
    }
    @Test fun mergedProfilesUseNicknameRevisionAndMaximumSeenWithoutDroppingOtherMetadata() {
        val base = buildJsonObject { put("future", buildJsonObject { put("nested", true) }) }
        val left = DeviceActivity.touch(base, "00000000-0000-0000-0000-000000000001", "New name", now = 2000, parentCommitId = "p")
        val right = DeviceActivity.touch(base, "00000000-0000-0000-0000-000000000001", "Older name", now = 1000, parentCommitId = "q")
        val merged = DeviceActivity.merge(left, right)
        assertEquals("New name", DeviceActivity.profiles(merged).single().name)
        assertEquals(2000L, DeviceActivity.profiles(merged).single().lastSeenAt)
        assertEquals(base["future"], merged["future"])
        assertEquals(DeviceActivity.merge(left, right), DeviceActivity.merge(right, left))
    }
    @Test fun nicknameLengthIsValidated() {
        try { DeviceActivity.touch(JsonObject(emptyMap()), "00000000-0000-0000-0000-000000000001", "x".repeat(65)); fail() }
        catch (_: IllegalArgumentException) { }
    }
}
