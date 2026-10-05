package com.vault.model

import com.vault.storage.PmvEPayloadAdapter
import com.vault.storage.VaultCodec
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.UUID

class AutofillExclusionsTest {
    @Test fun `shared fixtures converge and metadata round trip retains all platforms and tombstones`() {
        val fixture = VaultCodec.json.parseToJsonElement(File(System.getProperty("spec.dir"), "autofill_exclusions_v1_fixtures.json").readText()).jsonObject
        for (item in fixture.getValue("cases").jsonArray) {
            val case = item.jsonObject
            val local = VaultCodec.json.decodeFromJsonElement(AutofillExclusions.serializer(), case.getValue("local"))
            val remote = VaultCodec.json.decodeFromJsonElement(AutofillExclusions.serializer(), case.getValue("remote"))
            val expected = VaultCodec.json.decodeFromJsonElement(AutofillExclusions.serializer(), case.getValue("expected"))
            val result = local.merge(remote)
            val name = case.getValue("name").jsonPrimitive.content
            assertEquals(name, result, remote.merge(local))
            assertEquals(name, expected.packages, result.packages)
            assertEquals(name, expected.hosts, result.hosts)
            assertEquals(name, expected.processes, result.processes)
            assertEquals(name, result, result.merge(local).merge(remote))
            val payload = VaultPayload(syncMeta = SyncMeta(deviceId = UUID.randomUUID().toString()), autofillExclusions = result)
            val metadata = PmvEPayloadAdapter.toMetadata(payload, UUID.randomUUID())
            assertEquals(name, result, PmvEPayloadAdapter.fromMetadata(metadata, emptyList()).autofillExclusions)
            assertEquals(name, result, VaultOps.mergeDiverged(VaultPayload(autofillExclusions = local), VaultPayload(autofillExclusions = remote)).first.autofillExclusions)
        }
    }

    @Test fun `legacy rules migrate with monotonic edits and deletion survives stale lists`() {
        val legacy = AutofillExclusions(packages = listOf(" Com.Example.App "), hosts = listOf("https://EXAMPLE.com:443/login"), processes = listOf("EXAMPLE.EXE"))
        val migrated = legacy.normalized()
        assertEquals(listOf("example.com"), migrated.hosts)
        assertEquals(listOf("example.exe"), migrated.processes)
        assertEquals(0L, migrated.states.getValue("hosts:example.com").updatedAt)
        val removed = migrated.edit("hosts", "example.com", true, 10)
        assertTrue(removed.merge(legacy).hosts.isEmpty())
        val readded = removed.edit("hosts", "example.com", false, 1)
        assertEquals(11L, readded.states.getValue("hosts:example.com").updatedAt)
        assertEquals(listOf("example.com"), readded.merge(removed).hosts)
        assertEquals(migrated.processes, readded.processes)
    }
}
