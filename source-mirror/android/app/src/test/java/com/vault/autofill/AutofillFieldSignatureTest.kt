package com.vault.autofill

import org.junit.Assert.*
import org.junit.Test

class AutofillFieldSignatureTest {
    @Test fun typeOnlyUnknownInputsHaveNoRememberableSignature() {
        val first = AutofillFieldSignature.create(null, null, null, "text")
        val second = AutofillFieldSignature.create(null, null, null, "text")
        assertEquals(listOf(null, null), AutofillFieldSignature.unique(listOf(first, second)))
    }
    @Test fun repeatedIdentifierMakesBothSignaturesUnusable() {
        val repeated = AutofillFieldSignature.create(null, "same-id", null, "text")
        assertEquals(listOf(null, null), AutofillFieldSignature.unique(listOf(repeated, repeated)))
    }
    @Test fun distinctIdentifiersRemainRememberable() {
        val first = AutofillFieldSignature.create(null, "first", null, "text")
        val second = AutofillFieldSignature.create(null, "second", null, "text")
        assertEquals(listOf(first, second), AutofillFieldSignature.unique(listOf(first, second)))
    }
}
