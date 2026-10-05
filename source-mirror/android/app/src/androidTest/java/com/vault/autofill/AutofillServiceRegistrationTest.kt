package com.vault.autofill

import android.Manifest
import android.content.ComponentName
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.os.Build
import com.vault.passkeys.FAEVaultCredentialProviderService
import com.vault.passkeys.PasskeyCredentialActivity
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AutofillServiceRegistrationTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun serviceIsProtectedAndAuthenticationActivityIsPrivate() {
        val pm = context.packageManager
        val service = pm.getServiceInfo(
            ComponentName(context, FAEVaultAutofillService::class.java),
            PackageManager.GET_META_DATA,
        )
        assertTrue(service.exported)
        assertEquals("android.permission.BIND_AUTOFILL_SERVICE", service.permission)
        assertNotNull(service.metaData)

        val activity = pm.getActivityInfo(
            ComponentName(context, AutofillAuthActivity::class.java),
            PackageManager.GET_META_DATA,
        )
        assertFalse(activity.exported)
        assertTrue(activity.flags and ActivityInfo.FLAG_NO_HISTORY != 0)
        assertEquals("com.vault.autofill", activity.taskAffinity)
    }

    @Test
    fun featureDoesNotRequestAccessibilityOrOverlayPermissions() {
        val info = context.packageManager.getPackageInfo(
            context.packageName,
            PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES,
        )
        val permissions = info.requestedPermissions.orEmpty().toSet()
        assertFalse(Manifest.permission.SYSTEM_ALERT_WINDOW in permissions)
        assertFalse("android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions)
        assertTrue(
            info.services.orEmpty().none { it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" },
        )
    }

    @Test
    fun installedApplicationSigningIdentityCanBeResolved() {
        val certificates = PackageIdentityResolver.signingCertificateSha256(context, context.packageName)

        assertTrue(certificates.isNotEmpty())
        assertTrue(certificates.all { it.matches(Regex("^[0-9a-f]{64}$")) })
    }

    @Test
    fun credentialProviderIsSystemProtectedAndActivityIsPrivate() {
        if (Build.VERSION.SDK_INT < 34) return
        val service = context.packageManager.getServiceInfo(
            ComponentName(context, FAEVaultCredentialProviderService::class.java),
            PackageManager.GET_META_DATA,
        )
        assertTrue(service.exported)
        assertEquals("android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE", service.permission)
        assertNotNull(service.metaData)
        val activity = context.packageManager.getActivityInfo(
            ComponentName(context, PasskeyCredentialActivity::class.java), 0,
        )
        assertFalse(activity.exported)
    }
}
