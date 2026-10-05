package com.vault

import com.vault.ui.screens.moduleSelectDisplayLabel
import com.vault.ui.screens.moduleSelectValueMatches
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ModuleSelectFieldTest {
    @Test
    fun exactMatchingKeepsWrongCaseAutofillRoleUnavailable() {
        val options = listOf(
            "" to "Match exact field name",
            "email" to "Email",
            "EMAIL" to "Unavailable: EMAIL",
        )

        assertEquals("Email", moduleSelectDisplayLabel("EMAIL", options, exactMatch = false))
        assertEquals("Unavailable: EMAIL", moduleSelectDisplayLabel("EMAIL", options, exactMatch = true))
        assertTrue(moduleSelectValueMatches("EMAIL", "EMAIL", exactMatch = true))
        assertFalse(moduleSelectValueMatches("email", "EMAIL", exactMatch = true))
    }
}
