package com.vault.storage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LanAuthFailureBudgetTest {
    @Test
    fun `threshold blocks only the source and expires`() {
        var now = 1_000L
        val budget = LanAuthFailureBudget(clock = { now })

        repeat(10) { budget.recordFailure("192.168.1.20") }

        assertTrue(budget.isLocked("192.168.1.20"))
        assertFalse(budget.isLocked("192.168.1.21"))
        now += 30_001L
        assertFalse(budget.isLocked("192.168.1.20"))
    }

    @Test
    fun `failure count resets after its window`() {
        var now = 1_000L
        val budget = LanAuthFailureBudget(clock = { now })

        repeat(9) { budget.recordFailure("192.168.1.20") }
        now += 60_001L
        budget.recordFailure("192.168.1.20")

        assertFalse(budget.isLocked("192.168.1.20"))
    }
}
