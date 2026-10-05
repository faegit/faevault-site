package com.vault.ui.screens

import com.vault.model.Entry
import com.vault.model.SecretType
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EntryEditDirtyStateTest {
    @Test
    fun blankNewCardDocumentIsNotDirty() {
        val baseline = Entry(secretType = SecretType.CARD_DOCUMENT)

        assertFalse(hasMeaningfulEditorChanges(baseline, baseline.copy()))
    }

    @Test
    fun securityScanMetadataDoesNotMarkBlankEntryDirty() {
        val baseline = Entry(secretType = SecretType.CARD_DOCUMENT)
        val scanned = baseline.copy(
            leakCheckRevision = 3.0,
            leakPwnedCount = 0,
            leakCommonWeak = true,
            leakCheckedAt = 10.0,
        )

        assertFalse(hasMeaningfulEditorChanges(baseline, scanned))
    }

    @Test
    fun editableFieldsStillMarkEntryDirty() {
        val baseline = Entry(secretType = SecretType.CARD_DOCUMENT)

        assertTrue(hasMeaningfulEditorChanges(baseline, baseline.copy(title = "身份证")))
        assertTrue(
            hasMeaningfulEditorChanges(
                baseline,
                baseline.copy(fields = mapOf("id_number" to JsonPrimitive("110101199001010000"))),
            )
        )
    }
}
