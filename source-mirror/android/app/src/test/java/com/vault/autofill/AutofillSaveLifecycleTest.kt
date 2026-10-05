package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillSaveLifecycleTest {
    @Test
    fun saveDialogUsesApiCompatibleLaunchPath() {
        assertEquals(
            AutofillSaveLaunchMode.SERVICE_ACTIVITY,
            AutofillSaveLifecycle.launchMode(apiLevel = 26),
        )
        assertEquals(
            AutofillSaveLaunchMode.SERVICE_ACTIVITY,
            AutofillSaveLifecycle.launchMode(apiLevel = 27),
        )
        assertEquals(
            AutofillSaveLaunchMode.SYSTEM_INTENT_SENDER,
            AutofillSaveLifecycle.launchMode(apiLevel = 28),
        )
    }

    @Test
    fun dismissingSaveDialogDoesNotReportRequestAsHandled() {
        assertFalse(
            AutofillSaveLifecycle.shouldReportSuccess(
                isSaveRequest = true,
                completion = AutofillSaveCompletion.DISMISSED,
            ),
        )
        assertTrue(
            AutofillSaveLifecycle.shouldReportSuccess(
                isSaveRequest = true,
                completion = AutofillSaveCompletion.HANDLED,
            ),
        )
    }

    @Test
    fun savePlanUsesPasswordAsRequiredAndKeepsLifecycleFallback() {
        val form = ParsedForm(
            origin = TargetOrigin.Web("example.com"),
            packageName = "com.android.chrome",
            fields = listOf(
                ClassifiedField("username", FieldKind.USERNAME, 100, false),
                ClassifiedField("password", FieldKind.PASSWORD, 100, false),
            ),
        )

        val plan = requireNotNull(AutofillSaveLifecycle.plan(form))

        assertEquals(listOf("password"), plan.requiredIds)
        assertEquals(listOf("username"), plan.optionalIds)
        assertTrue(plan.triggerWhenFieldsBecomeInvisible)
        assertTrue(plan.keepActivityFinishFallback)
    }
}
