package com.vault.model

import com.vault.storage.VaultCodec
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class DeletionBaselineTest {
    @Test fun sharedProtocolVectors() {
        val fixture = VaultCodec.json.parseToJsonElement(File(System.getProperty("spec.dir"), "deletion_baseline_v1_fixtures.json").readText()).jsonObject
        for (raw in fixture.getValue("cases").jsonArray) {
            val case = raw.jsonObject
            val local = VaultCodec.json.decodeFromJsonElement(DeletionBaseline.serializer(), case.getValue("local"))
            val remote = VaultCodec.json.decodeFromJsonElement(DeletionBaseline.serializer(), case.getValue("remote"))
            if (case.getValue("op").jsonPrimitive.content == "guard") {
                assertEquals(case.getValue("name").jsonPrimitive.content, case.getValue("allowed").jsonPrimitive.boolean,
                    runCatching { DeletionBaseline.requireCompatible(local, remote) }.isSuccess)
            } else {
                val expected = VaultCodec.json.decodeFromJsonElement(DeletionBaseline.serializer(), case.getValue("expected"))
                assertEquals(expected, DeletionBaseline.merge(local, remote))
            }
        }
    }
    @Test fun expiredTrashPreservesOlderDeletionRecords() {
        val oldId = "11111111-1111-4111-8111-111111111111"
        val payload = VaultPayload(entries = listOf(Entry(id = "22222222-2222-4222-8222-222222222222", deletedAt = 1.0, updatedAt = 1.0)), purgeTombstones = mapOf(oldId to 1.0))
        assertEquals(1.0, VaultOps.purgeExpired(payload, 30).purgeTombstones[oldId])
    }
    @Test fun checkpointRequiresEveryMemberAndExactSnapshot() {
        val a = "11111111-1111-4111-8111-111111111111"
        val b = "22222222-2222-4222-8222-222222222222"
        val checkpointId = "33333333-3333-4333-8333-333333333333"
        val purges = mapOf("44444444-4444-4444-8444-444444444444" to 1.0)
        val checkpoint = DeletionCheckpoint(checkpointId, purges, listOf(a, b), mapOf(a to checkpointId))
        assertFalse(checkpoint.ready(purges, listOf(a, b)))
        val complete = checkpoint.copy(acknowledgements = checkpoint.acknowledgements + (b to checkpointId))
        assertTrue(complete.ready(purges, listOf(a, b)))
        assertFalse(complete.ready(purges + (a to 2.0), listOf(a, b)))
        assertFalse(complete.ready(purges, listOf(a)))
        assertFalse(complete.ready(purges, listOf(a, b, checkpointId)))
        assertFalse(complete.copy(acknowledgements = mapOf(a to checkpointId, b to a)).ready(purges, listOf(a, b)))
    }
    @Test fun acceptedFloorNeverRegressesOrReplacesConcurrentEpoch() {
        val first = DeletionBaseline(generation = 1, epoch = "55555555-5555-4555-8555-555555555555")
        val second = DeletionBaseline(generation = 2, epoch = "66666666-6666-4666-8666-666666666666")
        assertEquals(second, DeletionBaseline.acceptedFloor(first, second))
        assertEquals(second, DeletionBaseline.acceptedFloor(second, second))
        assertTrue(runCatching { DeletionBaseline.acceptedFloor(second, first) }.isFailure)
        assertTrue(runCatching { DeletionBaseline.acceptedFloor(second, DeletionBaseline()) }.isFailure)
        assertTrue(runCatching { DeletionBaseline.acceptedFloor(second, second.copy(epoch = first.epoch)) }.isFailure)
    }
    @Test fun staleBackupCannotMergeAfterCleanup() {
        val local = VaultPayload(deletionBaseline = DeletionBaseline(generation = 1, epoch = "55555555-5555-4555-8555-555555555555"))
        assertTrue(runCatching { VaultOps.mergeLww(local, emptyList()) }.isFailure)
    }
}
