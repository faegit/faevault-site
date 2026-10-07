package com.vault.autofill

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

class AutofillMatchingPolicyTest {
    @Test
    fun relatedNamesConformToSharedCrossPlatformFixtures() {
        val fixtures = Json.parseToJsonElement(File(System.getProperty("spec.dir"), "autofill_matching_v2_fixtures.json").readText()).jsonObject
        fixtures.getValue("name_pairs").jsonArray.forEach { raw ->
            val pair = raw.jsonObject
            val left = pair.getValue("left").jsonPrimitive.content
            val right = pair.getValue("right").jsonPrimitive.content
            val expected = pair.getValue("expected").jsonPrimitive.content.toBoolean()
            assertEquals(pair.getValue("id").jsonPrimitive.content, expected, AutofillMatchingPolicy.relatedNames(left, right))
            assertEquals("symmetric", expected, AutofillMatchingPolicy.relatedNames(right, left))
        }
    }
}
