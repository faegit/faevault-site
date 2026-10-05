package com.vault.passkeys

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
@SdkSuppress(minSdkVersion = 30)
class AndroidPasskeyKeyStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val deviceId = UUID.randomUUID()
    private val store = AndroidPasskeyKeyStore(context, deviceId)
    private var generated: GeneratedDevicePasskey? = null

    @After
    fun cleanup() {
        generated?.let { store.delete(it.binding) }
    }

    @Test
    fun generatedKeyIsLocallyAvailableAndNeverAvailableToAnotherDevice() {
        val allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        assumeTrue(BiometricManager.from(context).canAuthenticate(allowed) == BiometricManager.BIOMETRIC_SUCCESS)

        val value = store.generate(-7).also { generated = it }
        assertEquals(PasskeyAvailability.AVAILABLE, store.availability(value.binding))
        assertEquals(
            PasskeyAvailability.OTHER_DEVICE,
            AndroidPasskeyKeyStore(context, UUID.randomUUID()).availability(value.binding),
        )

        store.delete(value.binding)
        generated = null
        assertEquals(PasskeyAvailability.KEY_MISSING, store.availability(value.binding))
    }
}
