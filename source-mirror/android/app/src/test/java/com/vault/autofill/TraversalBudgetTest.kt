package com.vault.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TraversalBudgetTest {
    @Test
    fun enforcesNodeAndDepthLimits() {
        val budget = TraversalBudget(maxNodes = 2, maxDepth = 3)

        assertTrue(budget.accept(depth = 0, cancelled = false))
        assertTrue(budget.accept(depth = 3, cancelled = false))
        assertFalse(budget.accept(depth = 1, cancelled = false))
        assertFalse(budget.accept(depth = 4, cancelled = false))
    }

    @Test
    fun cancellationPermanentlyStopsBudget() {
        val budget = TraversalBudget(maxNodes = 10, maxDepth = 10)

        assertFalse(budget.accept(depth = 0, cancelled = true))
        assertFalse(budget.accept(depth = 0, cancelled = false))
    }
}
