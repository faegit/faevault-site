package com.vault.passkeys

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.vault.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xmlpull.v1.XmlPullParser

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 34)
class PasskeyProviderRegistrationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun providerDeclaresPasswordAndPublicKeyCredentialCapabilities() {
        val service = context.packageManager.getServiceInfo(
            ComponentName(context, FAEVaultCredentialProviderService::class.java),
            PackageManager.GET_META_DATA,
        )
        val metadataResource = service.metaData.getInt(PROVIDER_METADATA_NAME)
        assertEquals(R.xml.credential_provider, metadataResource)

        val capabilities = buildList {
            context.resources.getXml(metadataResource).use { parser ->
                var event = parser.eventType
                while (event != XmlPullParser.END_DOCUMENT) {
                    if (event == XmlPullParser.START_TAG && parser.name == "capability") {
                        add(parser.getAttributeValue(null, "name"))
                    }
                    event = parser.next()
                }
            }
        }

        assertEquals(
            listOf(
                "android.credentials.TYPE_PASSWORD_CREDENTIAL",
                "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL",
            ),
            capabilities,
        )
    }

    @Test
    fun providerServiceIsExportedAndProtectedBySystemBindingPermission() {
        val service = context.packageManager.getServiceInfo(
            ComponentName(context, FAEVaultCredentialProviderService::class.java),
            PackageManager.GET_META_DATA,
        )

        assertTrue(service.exported)
        assertEquals(BIND_PROVIDER_PERMISSION, service.permission)
        assertEquals(
            R.xml.credential_provider,
            service.metaData.getInt(PROVIDER_METADATA_NAME),
        )
    }

    private companion object {
        const val BIND_PROVIDER_PERMISSION =
            "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE"
        const val PROVIDER_METADATA_NAME = "android.credentials.provider"
    }
}
