package com.vault.autofill

import com.vault.model.Entry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillEntrySearchTest {
    private val entries = listOf(
        Entry(id = "exact", title = "PayPal", username = "alice", password = "secret"),
        Entry(id = "prefix", title = "PayPal Work", username = "bob", password = "secret"),
        Entry(
            id = "package",
            title = "Payments",
            username = "carol",
            password = "secret",
            url = "https://accounts.example.com/login",
            targetApp = "com.example.payments",
        ),
        Entry(id = "password-only", title = "Unrelated", username = "nobody", password = "paypal"),
    )

    @Test
    fun `manual search ranks exact prefix and typo matches without searching passwords`() {
        assertEquals(listOf("exact", "prefix"), AutofillEntrySearch.search(entries, "paypal").map { it.id })
        assertEquals(listOf("exact", "prefix"), AutofillEntrySearch.search(entries, "payapl").map { it.id })
        assertTrue(AutofillEntrySearch.search(entries, "secret").isEmpty())
    }

    @Test
    fun `manual search includes normalized urls and associated package names`() {
        assertEquals(listOf("package"), AutofillEntrySearch.search(entries, "ACCOUNTS.EXAMPLE").map { it.id })
        assertEquals(listOf("package"), AutofillEntrySearch.search(entries, "example payments").map { it.id })
    }
}
