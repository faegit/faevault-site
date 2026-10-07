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
    @Test fun mergedProfilesUseNameRevisionAndMaximumSeenWithoutDroppingOtherMetadata() {
        val base = buildJsonObject { put("future", buildJsonObject { put("nested", true) }) }
        val left = DeviceActivity.touch(base, "00000000-0000-0000-0000-000000000001", "New name", now = 2000, parentCommitId = "p")
        val right = DeviceActivity.touch(base, "00000000-0000-0000-0000-000000000001", "Older name", now = 1000, parentCommitId = "q")
        val merged = DeviceActivity.merge(left, right)
        assertEquals("New name", DeviceActivity.profiles(merged).single().name)
        assertEquals(2000L, DeviceActivity.profiles(merged).single().lastSeenAt)
        assertEquals(base["future"], merged["future"])
        assertEquals(DeviceActivity.merge(left, right), DeviceActivity.merge(right, left))
    }
    @Test fun nameLengthIsValidated() {
        try { DeviceActivity.touch(JsonObject(emptyMap()), "00000000-0000-0000-0000-000000000001", "x".repeat(65)); fail() }
        catch (_: IllegalArgumentException) { }
    }
    @Test fun systemRenameOverridesOldNicknameWithClockRollbackAndPreservesOtherDevices() {
        val id = "00000000-0000-0000-0000-000000000001"
        val other = "00000000-0000-0000-0000-000000000002"
        var metadata = DeviceActivity.touch(JsonObject(emptyMap()), other, "Other", now = 1000)
        metadata = DeviceActivity.touch(metadata, id, "Old nickname", now = 2000)
        val updated = DeviceActivity.touch(metadata, id, "System phone", now = 500)
        val profile = DeviceActivity.profiles(updated).first { it.deviceId == id }
        assertEquals("System phone", profile.name)
        assertTrue(profile.updatedAt > 2000)
        assertEquals("Other", DeviceActivity.profiles(updated).first { it.deviceId == other }.name)
    }

    @Test fun automaticNameRefreshPreservesFutureMetadataSchema() {
        val metadata = buildJsonObject {
            put(DeviceActivity.KEY, buildJsonObject { put("version", 2); put("future", true) })
        }
        assertEquals(metadata, DeviceActivity.touch(metadata,
            "00000000-0000-0000-0000-000000000001", "System name"))
    }

    @Test fun deviceViewShowsOnlyCurrentlyAuthorizedRecords() {
        val rows = listOf("authorized", "revoked", "expired", null, "invalid").mapIndexed { index, status ->
            DeviceActivityProfile("device-$index", "name", "android", 0, 0, authorizationStatus = status)
        }
        assertEquals(listOf(rows.first()), DeviceActivity.authorizedProfiles(rows))
    }

}
