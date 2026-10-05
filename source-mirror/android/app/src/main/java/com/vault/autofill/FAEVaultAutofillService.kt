package com.vault.autofill

import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import com.vault.passkeys.PrivilegedAppAllowlistStore
import java.util.UUID

class FAEVaultAutofillService : AutofillService() {
    // The service can start without any Activity installing the in-memory vault key.
    private fun isExcluded(origin: TargetOrigin): Boolean = AutofillExcludePref.isExcluded(
        this, origin, com.vault.storage.VaultRegistry(this).current()
            ?: com.vault.security.CurrentVaultKey.DEFAULT,
    )
    private val browserTrustAllowlist by lazy {
        runCatching { PrivilegedAppAllowlistStore(applicationContext).current() }.getOrNull()
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback,
    ) {
        if (cancellationSignal.isCanceled) return callback.onSuccess(null)
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val manual = request.flags and FillRequest.FLAG_MANUAL_REQUEST != 0
        val form = parseForm(structure, cancellationSignal, manual) ?: return callback.onSuccess(null)
        if (isExcluded(form.origin)) return callback.onSuccess(null)
        if (cancellationSignal.isCanceled) return callback.onSuccess(null)
        val inlineSpec = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            request.inlineSuggestionsRequest?.inlinePresentationSpecs?.firstOrNull()
        } else null
        val pending = PendingAutofillRequest.Fill(form, inlineSpec)
        val token = AutofillRequestStore.put(pending)
        callback.onSuccess(
            AutofillResponseFactory.lockedResponse(
                this,
                form,
                token,
                inlineSpec,
            ),
        )
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val forms = request.fillContexts.mapNotNull { context ->
            parseForm(context.structure, CancellationSignal(), manualRequest = true)
        }
        val (form, candidate) = SaveCandidateExtractor.extract(forms) ?: return callback.onSuccess()
        if (isExcluded(form.origin)) return callback.onSuccess()
        val pendingRequest = PendingAutofillRequest.Save(form, candidate)
        val requestId = UUID.randomUUID().toString()
        val intent = SaveRequestIntentTransport.attach(
            Intent(this, AutofillAuthActivity::class.java),
            pendingRequest,
        )
            .setAction("com.vault.autofill.SAVE.$requestId")
            // 只用 NEW_TASK：冷启动（进程不存活）时 CLEAR_TASK 会和系统对保存认证任务
            // 的装配竞争，导致窗口被创建却未被抬到前台；去掉后由系统正常置顶显示。
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        when (AutofillSaveLifecycle.launchMode(Build.VERSION.SDK_INT)) {
            AutofillSaveLaunchMode.SYSTEM_INTENT_SENDER -> {
                // onSuccess(IntentSender) was added in API 28；该模式只在 API 28+ 启用，
                // 这里显式兜底以避免 lint NewApi（正常不会走到 <P 分支）。
                if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.P) {
                    callback.onSuccess()
                } else {
                    val intentSender = PendingIntent.getActivity(
                        this,
                        requestId.hashCode(),
                        intent,
                        PendingIntent.FLAG_CANCEL_CURRENT or
                            PendingIntent.FLAG_ONE_SHOT or
                            PendingIntent.FLAG_IMMUTABLE,
                    ).intentSender
                    callback.onSuccess(intentSender)
                }
            }

            AutofillSaveLaunchMode.SERVICE_ACTIVITY -> {
                // API 26-27 only exposes onSuccess(). Launch the private save Activity directly
                // while the autofilled app is still in the foreground, then complete the callback.
                try {
                    startActivity(intent)
                } catch (_: RuntimeException) {
                    callback.onFailure("Unable to open the FAEVault save window.")
                    return
                }
                callback.onSuccess()
            }
        }
    }

    private fun parseForm(
        structure: android.app.assist.AssistStructure,
        cancellationSignal: CancellationSignal,
        manualRequest: Boolean,
    ): ParsedForm<android.view.autofill.AutofillId>? {
        val targetPackage = structure.activityComponent?.packageName ?: return null
        val certificates = PackageIdentityResolver.signingCertificateSha256(this, targetPackage)
        if (certificates.isEmpty()) return null
        val trustedBrowserCertificates = browserTrustAllowlist?.let { raw ->
            BrowserTrustAllowlist.signingCertificateSha256(raw, targetPackage)
        }.orEmpty()
        return runCatching {
            AssistStructureParser.parse(
                structure = structure,
                cancellationSignal = cancellationSignal,
                ownPackage = packageName,
                manualRequest = manualRequest,
                signingCertificateSha256 = certificates,
                trustedBrowserSigningCertificateSha256 = trustedBrowserCertificates,
            )
        }.getOrNull()
    }
}
