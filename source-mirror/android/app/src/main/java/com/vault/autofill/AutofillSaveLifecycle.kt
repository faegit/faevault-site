package com.vault.autofill

internal enum class AutofillSaveCompletion { DISMISSED, HANDLED }

internal enum class AutofillSaveLaunchMode { SERVICE_ACTIVITY, SYSTEM_INTENT_SENDER }

internal data class AutofillSavePlan<T>(
    val requiredIds: List<T>,
    val optionalIds: List<T>,
    val triggerWhenFieldsBecomeInvisible: Boolean,
    val keepActivityFinishFallback: Boolean,
)

internal object AutofillSaveLifecycle {
    fun launchMode(apiLevel: Int): AutofillSaveLaunchMode =
        if (apiLevel >= 28) {
            AutofillSaveLaunchMode.SYSTEM_INTENT_SENDER
        } else {
            AutofillSaveLaunchMode.SERVICE_ACTIVITY
        }

    fun shouldReportSuccess(
        isSaveRequest: Boolean,
        completion: AutofillSaveCompletion,
    ): Boolean = isSaveRequest && completion == AutofillSaveCompletion.HANDLED

    fun <T> plan(form: ParsedForm<T>): AutofillSavePlan<T>? {
        val required = form.fields
            .filter { it.kind == FieldKind.PASSWORD || it.kind == FieldKind.NEW_PASSWORD }
            .map { it.id }
        if (required.isEmpty()) return null
        return AutofillSavePlan(
            requiredIds = required,
            optionalIds = form.fields.map { it.id }.filterNot(required::contains),
            triggerWhenFieldsBecomeInvisible = true,
            // Do not add FLAG_DONT_SAVE_ON_FINISH: activity completion remains the fallback.
            keepActivityFinishFallback = true,
        )
    }
}
