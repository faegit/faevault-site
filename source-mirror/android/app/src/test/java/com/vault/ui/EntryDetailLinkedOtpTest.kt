package com.vault.ui

import com.vault.model.AutofillFieldRef
import com.vault.model.AutofillLink
import com.vault.model.Entry
import com.vault.model.EntryModules
import com.vault.model.ModuleType
import com.vault.model.autofill.AutofillRole
import com.vault.model.entryModules
import com.vault.model.withAutofillLinks
import com.vault.model.withEntryModules
import com.vault.ui.screens.detailOtpSource
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

class EntryDetailLinkedOtpTest {
    @Test
    fun linkedExternalOtpModuleTakesPriorityOverLoginInternalOtp() {
        val internal = otpModule("internal", "INTERNAL")
        val selected = otpModule("selected", "SELECTED")
        val other = otpModule("other", "OTHER")
        val source = Entry(id = "otp-source").withEntryModules(listOf(other, selected))
        val login = Entry(id = "login").withEntryModules(listOf(internal)).withAutofillLinks(
            listOf(
                AutofillLink(
                    "link",
                    source.id,
                    listOf(AutofillFieldRef("selected", "@computed/one_time_code", AutofillRole.ONE_TIME_CODE, false)),
                ),
            ),
        )

        val resolved = detailOtpSource(login, listOf(source))!!

        assertEquals(listOf("selected"), resolved.entryModules().map { EntryModules.primitive(it["id"]) })
    }

    private fun otpModule(id: String, secret: String) = JsonObject(
        mapOf(
            "id" to JsonPrimitive(id),
            "type" to JsonPrimitive(ModuleType.OTP),
            "value" to JsonObject(mapOf("secret" to JsonPrimitive(secret))),
        ),
    )
}
