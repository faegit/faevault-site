package com.vault.autofill

import com.vault.model.autofill.AutofillRole
import org.junit.Assert.*
import org.junit.Test

class AutofillFieldValueResolverTest {
    private fun snapshot(role: AutofillRole, value: String, verify: Boolean = false) = AutofillSnapshot(
        mapOf(role to ResolvedAutofillValue(role, value, "source", null, "field", verify)), emptySet(),
    )
    @Test fun emailOnlyAccountCanFillUsernameAndEmailInputs() {
        val values = snapshot(AutofillRole.EMAIL, "alice@example.com")
        assertEquals("alice@example.com", AutofillFieldValueResolver.value(FieldKind.USERNAME, values, true))
        assertEquals("alice@example.com", AutofillFieldValueResolver.value(FieldKind.EMAIL, values, true))
    }
    @Test fun usernameOnlyAccountCanFillEmailInput() {
        assertEquals("alice", AutofillFieldValueResolver.value(FieldKind.EMAIL, snapshot(AutofillRole.USERNAME, "alice"), true))
    }
    @Test fun specializedRolesRemainExactAndVerificationProtected() {
        val values = snapshot(AutofillRole.CUSTOM_SECRET, "secret", verify = true)
        assertNull(AutofillFieldValueResolver.value(FieldKind.USERNAME, values, true))
        assertNull(AutofillFieldValueResolver.value(FieldKind.CUSTOM_SECRET, values, false))
        assertEquals("secret", AutofillFieldValueResolver.value(FieldKind.CUSTOM_SECRET, values, true))
        assertNull(AutofillFieldValueResolver.value(FieldKind.UNKNOWN, values, true))
    }
}
