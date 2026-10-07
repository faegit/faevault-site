package com.vault.storage

import org.junit.Assert.*
import org.junit.Test
import kotlinx.serialization.json.*
import java.io.File

class RemoteUpdatePolicyTest {
    @Test fun pausedOrResumedSessionRejectsLateMetadataResult() {
        assertTrue(RemoteUpdatePolicy.mayAcceptObservation(1, 1, false))
        assertFalse(RemoteUpdatePolicy.mayAcceptObservation(1, 2, true))
        assertFalse(RemoteUpdatePolicy.mayAcceptObservation(1, 2, false))
        assertFalse(RemoteUpdatePolicy.mayAcceptObservation(1, 1, true))
    }

    @Test fun mergedUploadAcknowledgesConsumedVersionWithoutClearingNewerPending() {
        val consumed = RemoteUpdateState(baseline = "a", pending = "b")
        assertEquals("", RemoteUpdatePolicy.acknowledge(consumed, "c", "b").pending)
        assertEquals("c", RemoteUpdatePolicy.acknowledge(consumed, "c", "b").baseline)
        assertEquals("d", RemoteUpdatePolicy.acknowledge(consumed.copy(pending = "d"), "c", "b").pending)
    }
    @Test fun sharedCrossPlatformPolicyFixtures() {
        val root = Json.parseToJsonElement(File(System.getProperty("spec.dir"), "remote_update_v1_fixtures.json").readText()).jsonObject
        for (case in root.getValue("cases").jsonArray) {
            val initial = case.jsonObject.getValue("initial").jsonObject
            fun initialText(key: String) = initial[key]?.jsonPrimitive?.content.orEmpty()
            var state = RemoteUpdateState(baseline = initialText("baseline"), pending = initialText("pending"),
                notified = initial["notified"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty())
            for (item in case.jsonObject.getValue("events").jsonArray) {
                val event = item.jsonObject
                val version = event["version"]?.jsonPrimitive?.content.orEmpty()
                val result = when (event.getValue("type").jsonPrimitive.content) {
                    "observe" -> RemoteUpdatePolicy.observe(state, version, event["now"]?.jsonPrimitive?.long ?: 0)
                    "acknowledge" -> RemoteUpdatePolicy.Observation(RemoteUpdatePolicy.acknowledge(state, version, event["consumed_version"]?.jsonPrimitive?.content.orEmpty()))
                    "reset" -> RemoteUpdatePolicy.Observation(RemoteUpdateState())
                    else -> RemoteUpdatePolicy.Observation(state)
                }
                state = result.state
                event["expected_baseline"]?.let { assertEquals(it.jsonPrimitive.content, state.baseline) }
                event["expected_pending"]?.let { assertEquals(it.jsonPrimitive.content, state.pending) }
                event["notify"]?.let { assertEquals(it.jsonPrimitive.boolean, result.notify) }
            }
        }
    }
    @Test fun baselineDedupAndMatchingAcknowledgement() {
        val first = RemoteUpdatePolicy.observe(RemoteUpdateState(), "a", 1)
        assertFalse(first.notify)
        val changed = RemoteUpdatePolicy.observe(first.state, "b", 2)
        assertTrue(changed.notify)
        assertFalse(RemoteUpdatePolicy.observe(changed.state, "b", 3).notify)
        val newer = RemoteUpdatePolicy.observe(changed.state, "c", 4).state
        assertEquals("c", RemoteUpdatePolicy.acknowledge(newer, "b").pending)
        assertEquals("", RemoteUpdatePolicy.acknowledge(newer, "c").pending)
    }
    @Test fun missingVersionAndTimestampDirectionNeverInventUpdates() {
        assertNull(RemoteUpdatePolicy.version(CloudFileVersion(true, -1, 0)))
        assertEquals("etag:x", RemoteUpdatePolicy.version(CloudFileVersion(true, -1, 0, "x")))
        val old = RemoteUpdatePolicy.observe(RemoteUpdateState(), "meta:100:1", 1).state
        assertTrue(RemoteUpdatePolicy.observe(old, "meta:10:1", 2).notify)
    }
}
