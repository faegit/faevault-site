package com.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * 对应最终状态表：
 *
 * | Provider 当前状态 | App CM capability | 保存通道            | Autofill Save |
 * | 不支持/未启用/未知 | 任意              | AUTOFILL_FALLBACK   | 开启          |
 * | 已启用            | 未观察            | AUTOFILL_FALLBACK   | 开启          |
 * | 已启用            | 已观察            | CREDENTIAL_MANAGER  | 关闭          |
 */
class PasswordSaveChannelPolicyTest {
    @Test
    fun cmChannelChosenOnlyWhenAvailableAndObserved() {
        val channel = PasswordSaveChannelPolicy.choose(
            credentialManagerAvailable = true,
            targetCapabilityObserved = true,
        )

        assertEquals(PasswordSaveChannel.CREDENTIAL_MANAGER, channel)
        // CM 为主通道时必须抑制 Autofill Save，避免同一凭据双弹窗/双份保存
        assertFalse(PasswordSaveChannelPolicy.includeAutofillSaveFallback(channel))
    }

    @Test
    fun autofillRemainsTheFallbackUntilSupportIsProved() {
        assertEquals(
            PasswordSaveChannel.AUTOFILL_FALLBACK,
            PasswordSaveChannelPolicy.choose(
                credentialManagerAvailable = true,
                targetCapabilityObserved = false,
            ),
        )
        assertEquals(
            PasswordSaveChannel.AUTOFILL_FALLBACK,
            PasswordSaveChannelPolicy.choose(
                credentialManagerAvailable = false,
                targetCapabilityObserved = true,
            ),
        )
        assertEquals(
            PasswordSaveChannel.AUTOFILL_FALLBACK,
            PasswordSaveChannelPolicy.choose(
                credentialManagerAvailable = false,
                targetCapabilityObserved = false,
            ),
        )
    }

    @Test
    fun fallbackChannelKeepsAutofillSaveEnabled() {
        assertTrue(
            PasswordSaveChannelPolicy.includeAutofillSaveFallback(
                PasswordSaveChannel.AUTOFILL_FALLBACK,
            ),
        )
    }
}
