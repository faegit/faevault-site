package com.vault

import com.vault.model.SecretType
import com.vault.ui.NavOrderPref
import org.junit.Assert.assertEquals
import org.junit.Test

class NavOrderPrefTest {
    @Test
    fun normalizeRemovesUnknownAndDuplicateTypes() {
        assertEquals(
            NavOrderPref.defaultOrder,
            NavOrderPref.normalize(SecretType.ALL + "unknown" + SecretType.LOGIN),
        )
    }

    @Test
    fun normalizeAppendsNewTypesMissingFromStoredOrder() {
        val stored = SecretType.ALL.dropLast(1)
        assertEquals(NavOrderPref.defaultOrder, NavOrderPref.normalize(stored))
    }
}
