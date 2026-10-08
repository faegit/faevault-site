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

    @Test fun removedProfilesCannotReturnFromStaleMergeAndDeletionTimeIsMonotonic() {
        val id = "00000000-0000-0000-0000-000000000001"
        val old = DeviceActivity.touch(JsonObject(emptyMap()), id, "Fake phone", now = 2000)
        val removed = DeviceActivity.remove(old, id, now = 500)
        assertEquals(2001L, DeviceActivity.deletedProfiles(removed)[id])
        assertTrue(DeviceActivity.profiles(DeviceActivity.merge(removed, old)).isEmpty())
        assertTrue(DeviceActivity.profiles(DeviceActivity.merge(old, removed)).isEmpty())
        val again = DeviceActivity.remove(removed, id, now = 100)
        assertEquals(2002L, DeviceActivity.deletedProfiles(again)[id])
        assertEquals(DeviceActivity.merge(again, removed), DeviceActivity.merge(removed, again))
        val reenrolled = DeviceActivity.touch(again, id, "Fake re-enrolled phone", now = 100)
        assertTrue(DeviceActivity.profiles(reenrolled).single().updatedAt > 2002L)
    }

    @Test fun removalRejectsFutureSchemaWithoutDroppingOpaqueMetadata() {
        val metadata = buildJsonObject { put(DeviceActivity.KEY, buildJsonObject { put("version", 2); put("opaque", "keep") }) }
        assertThrows(IllegalArgumentException::class.java) {
            DeviceActivity.remove(metadata, "00000000-0000-0000-0000-000000000001", now = 2000)
        }
        assertEquals(metadata, DeviceActivity.merge(metadata, JsonObject(emptyMap())))
    }

    @Test fun sharedDeviceRemovalFixtures() {
        val fixtures = Json.parseToJsonElement(File(System.getProperty("spec.dir"), "device_removal_v1_fixtures.json").readText()).jsonObject
        fixtures.getValue("cases").jsonArray.forEach { raw ->
            val case = raw.jsonObject
            val left = buildJsonObject { put(DeviceActivity.KEY, case.getValue("left")) }
            val right = buildJsonObject { put(DeviceActivity.KEY, case.getValue("right")) }
            val merged = DeviceActivity.merge(left, right)
            assertEquals(case.getValue("name").jsonPrimitive.content,
                case.getValue("expected_ids").jsonArray.map { it.jsonPrimitive.content }, DeviceActivity.profiles(merged).map { it.deviceId })
            assertEquals(case.getValue("expected_deleted").jsonObject.mapValues { it.value.jsonPrimitive.long }, DeviceActivity.deletedProfiles(merged))
            assertEquals(merged, DeviceActivity.merge(right, left))
        }
    }

    @Test fun repositoryRemovalGuardRejectsCurrentDeviceIncludingUuidCaseVariants() {
        val id = "00000000-0000-0000-0000-00000000000a"
        assertThrows(IllegalArgumentException::class.java) { DeviceActivity.requireOtherDevice(id.uppercase(), id) }
        DeviceActivity.requireOtherDevice("00000000-0000-0000-0000-000000000002", id)
    }

    @Test fun uuidAliasesUseCanonicalProfilesAndMaximumDeletionTime() {
        val id = "00000000-0000-0000-0000-00000000000a"
        val stale = buildJsonObject { put(DeviceActivity.KEY, buildJsonObject {
            put("version", 1)
            put("profiles", JsonArray(listOf(buildJsonObject {
                put("device_id", id.uppercase()); put("name", "Fake alias"); put("platform", "pc")
                put("updated_at", 100); put("last_seen_at", 100)
            })))
        }) }
        assertEquals(id, DeviceActivity.profiles(stale).single().deviceId)
        val removed = DeviceActivity.remove(stale, id, now = 200)
        assertTrue(DeviceActivity.profiles(removed).isEmpty())
        assertTrue(DeviceActivity.profiles(DeviceActivity.merge(stale, removed)).isEmpty())
        val aliases = buildJsonObject { put(DeviceActivity.KEY, buildJsonObject {
            put("version", 1)
            put("deleted_profiles", buildJsonObject { put(id, 200); put(id.uppercase(), 300) })
        }) }
        assertEquals(mapOf(id to 300L), DeviceActivity.deletedProfiles(aliases))
        val merged = DeviceActivity.merge(stale, aliases)
        assertTrue(DeviceActivity.profiles(merged).isEmpty())
        assertEquals(mapOf(id to 300L), DeviceActivity.deletedProfiles(merged))
        assertTrue(DeviceActivity.profiles(DeviceActivity.remove(stale, id.uppercase(), now = 200)).isEmpty())
    }

    @Test fun uppercaseWriterAndProfileMatchOnlyWithAuthenticatedParentBinding() {
        val id = "00000000-0000-0000-0000-00000000000a"
        val metadata = buildJsonObject { put(DeviceActivity.KEY, buildJsonObject {
            put("version", 1)
            put("profiles", JsonArray(listOf(buildJsonObject {
                put("device_id", id.uppercase()); put("name", "Fake writer"); put("platform", "pc")
                put("updated_at", 100); put("last_seen_at", 100)
            })))
            put("last_writer", buildJsonObject {
                put("device_id", id.uppercase()); put("updated_at", 100); put("parent_commit_id", "fake-authenticated-parent")
            })
        }) }
        assertEquals(id, DeviceActivity.writer(metadata, "fake-authenticated-parent")?.deviceId)
        assertNull(DeviceActivity.writer(metadata, "other-parent"))
        assertNull(DeviceActivity.writer(metadata, null))
    }

}
