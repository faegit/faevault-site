package com.vault.ui.screens

import org.junit.Assert.assertEquals
import org.junit.Test

class SponsorPaymentTest {
    @Test fun sponsorSupportUsesThePublishedHttpsDocumentationPage() {
        assertEquals(
            "https://faegit.github.io/faevault-site/zh-cn/support/",
            sponsorSupportTarget(),
        )
        assertEquals("https", java.net.URI(sponsorSupportTarget()).scheme)
    }
}
