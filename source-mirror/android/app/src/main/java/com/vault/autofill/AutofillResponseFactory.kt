package com.vault.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.v1.InlineSuggestionUi
import com.vault.R
import com.vault.MainActivity
import com.vault.model.Entry
import com.vault.model.autofill.AutofillRole

object AutofillResponseFactory {
    fun lockedResponse(
        context: Context,
        form: ParsedForm<android.view.autofill.AutofillId>,
        token: String,
        inlineSpec: InlinePresentationSpec?,
        includeSaveFallback: Boolean = true,
    ): FillResponse {
        val presentation = presentation(context, context.getString(R.string.autofill_unlock))
        val authIntent = Intent(context, AutofillAuthActivity::class.java)
            .setPackage(context.packageName)
            .setAction("com.vault.autofill.FILL.$token")
            .putExtra(AutofillAuthActivity.EXTRA_REQUEST_TOKEN, token)
        val authPendingIntent = PendingIntent.getActivity(
            context,
            token.hashCode(),
            authIntent,
            PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
        @Suppress("DEPRECATION")
        val dataset = Dataset.Builder(presentation).setAuthentication(authPendingIntent.intentSender).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inlineSpec != null) {
                setInlinePresentation(inline(context, context.getString(R.string.autofill_unlock), authPendingIntent, inlineSpec))
            }
            form.fields.forEach { setValue(it.id, null, presentation) }
        }.build()
        return FillResponse.Builder().addDataset(dataset).apply {
            if (includeSaveFallback) buildSaveInfo(form)?.let(::setSaveInfo)
        }.build()
    }

    fun authenticatedDataset(
        context: Context,
        form: ParsedForm<android.view.autofill.AutofillId>,
        entry: Entry,
        inlineSpec: InlinePresentationSpec? = null,
        otpCode: String? = null,
        snapshot: AutofillSnapshot? = null,
        verificationGranted: Boolean = false,
    ): Dataset? {
        val label = listOf(entry.title.ifBlank { form.origin.displayName() }, entry.username)
            .filter { it.isNotBlank() }
            .joinToString(" · ")
            .take(100)
        val presentation = presentation(context, label)
        var values = 0
        val attribution = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        @Suppress("DEPRECATION")
        val builder = Dataset.Builder(presentation).apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inlineSpec != null) {
                setInlinePresentation(inline(context, label, attribution, inlineSpec))
            }
        }
        val otpFields = form.fields.filter { it.kind == FieldKind.OTP }
        val otpValues = OtpAutofill.otpFillValues(otpCode, otpFields.size)
        var otpIndex = 0
        form.fields.forEach { field ->
            val value = when (field.kind) {
                FieldKind.USERNAME, FieldKind.EMAIL -> AutofillFieldValueResolver.value(field.kind, snapshot, verificationGranted)
                    ?: entry.username
                FieldKind.PASSWORD, FieldKind.NEW_PASSWORD -> snapshot?.valueFor(AutofillRole.PASSWORD, verificationGranted)
                    ?: entry.password.takeIf { verificationGranted }.orEmpty()
                FieldKind.UNKNOWN -> ""
                FieldKind.OTP -> otpValues.getOrElse(otpIndex++) { "" }
                FieldKind.FULL_NAME -> snapshot?.valueFor(AutofillRole.FULL_NAME, verificationGranted).orEmpty()
                FieldKind.PHONE -> snapshot?.valueFor(AutofillRole.PHONE, verificationGranted).orEmpty()
                FieldKind.COUNTRY -> snapshot?.valueFor(AutofillRole.COUNTRY, verificationGranted).orEmpty()
                FieldKind.REGION -> snapshot?.valueFor(AutofillRole.REGION, verificationGranted).orEmpty()
                FieldKind.CITY -> snapshot?.valueFor(AutofillRole.CITY, verificationGranted).orEmpty()
                FieldKind.STREET_ADDRESS -> snapshot?.valueFor(AutofillRole.STREET_ADDRESS, verificationGranted).orEmpty()
                FieldKind.POSTAL_CODE -> snapshot?.valueFor(AutofillRole.POSTAL_CODE, verificationGranted).orEmpty()
                FieldKind.CARDHOLDER -> snapshot?.valueFor(AutofillRole.CARDHOLDER, verificationGranted).orEmpty()
                FieldKind.CARD_NUMBER -> snapshot?.valueFor(AutofillRole.CARD_NUMBER, verificationGranted).orEmpty()
                FieldKind.CARD_EXPIRY -> snapshot?.valueFor(AutofillRole.CARD_EXPIRY, verificationGranted).orEmpty()
                FieldKind.CARD_CVV -> snapshot?.valueFor(AutofillRole.CARD_CVV, verificationGranted).orEmpty()
                FieldKind.ID_NUMBER -> snapshot?.valueFor(AutofillRole.ID_NUMBER, verificationGranted).orEmpty()
                FieldKind.API_KEY -> snapshot?.valueFor(AutofillRole.API_KEY, verificationGranted).orEmpty()
                FieldKind.API_SECRET -> snapshot?.valueFor(AutofillRole.API_SECRET, verificationGranted).orEmpty()
                FieldKind.HOST -> snapshot?.valueFor(AutofillRole.HOST, verificationGranted).orEmpty()
                FieldKind.PORT -> snapshot?.valueFor(AutofillRole.PORT, verificationGranted).orEmpty()
                FieldKind.DATABASE -> snapshot?.valueFor(AutofillRole.DATABASE, verificationGranted).orEmpty()
                FieldKind.SSID -> snapshot?.valueFor(AutofillRole.SSID, verificationGranted).orEmpty()
                FieldKind.WIFI_PASSWORD -> snapshot?.valueFor(AutofillRole.WIFI_PASSWORD, verificationGranted).orEmpty()
                FieldKind.RECOVERY_ANSWER -> snapshot?.valueFor(AutofillRole.RECOVERY_ANSWER, verificationGranted).orEmpty()
                FieldKind.CUSTOM_TEXT -> snapshot?.valueFor(AutofillRole.CUSTOM_TEXT, verificationGranted).orEmpty()
                FieldKind.CUSTOM_SECRET -> snapshot?.valueFor(AutofillRole.CUSTOM_SECRET, verificationGranted).orEmpty()
            }
            if (value.isNotEmpty()) {
                builder.setValue(field.id, AutofillValue.forText(value), presentation)
                values++
            }
        }
        return if (values == 0) null else builder.build()
    }

    private fun buildSaveInfo(form: ParsedForm<android.view.autofill.AutofillId>): SaveInfo? {
        val plan = AutofillSaveLifecycle.plan(form) ?: return null
        return SaveInfo.Builder(
            SaveInfo.SAVE_DATA_TYPE_PASSWORD,
            plan.requiredIds.toTypedArray(),
        ).apply {
            if (plan.optionalIds.isNotEmpty()) setOptionalIds(plan.optionalIds.toTypedArray())
            if (plan.triggerWhenFieldsBecomeInvisible) {
                setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            }
        }.build()
    }

    private fun presentation(context: Context, label: String): RemoteViews =
        RemoteViews(context.packageName, R.layout.autofill_dataset).apply {
            setTextViewText(R.id.autofill_title, label)
        }

    @androidx.annotation.RequiresApi(Build.VERSION_CODES.R)
    @android.annotation.SuppressLint("RestrictedApi")
    private fun inline(
        context: Context,
        label: String,
        attribution: PendingIntent,
        spec: InlinePresentationSpec,
    ): InlinePresentation {
        val content = InlineSuggestionUi.newContentBuilder(attribution)
            .setTitle(label.take(100))
            .setStartIcon(Icon.createWithResource(context, R.drawable.ic_brand_lock))
            .setContentDescription(label.take(100))
            .build()
        return InlinePresentation(content.slice, spec, false)
    }

    private fun TargetOrigin.displayName(): String = when (this) {
        is TargetOrigin.AndroidPackage -> packageName
        is TargetOrigin.Web -> host
    }
}
