package com.vault.autofill

import android.content.Context
import android.os.Build
import com.vault.security.SecurePreferences
import java.security.MessageDigest

enum class PasswordSaveChannel { CREDENTIAL_MANAGER, AUTOFILL_FALLBACK }

/**
 * 实时判定"FAEVault 当前是否为系统已启用的 Credential Provider（可承担密码保存）"。
 *
 * 失败安全原则：任何一步无法确认（API 异常 / 设置键不可读 / 未选中）→ 返回 false，
 * 上层自动回退 Autofill，绝不乐观假定。
 */
object CredentialManagerAvailability {
    private const val SERVICE_CLASS = "com.vault.passkeys.FAEVaultCredentialProviderService"

    // 系统记录已选 Credential Provider 的两个已知 Secure 设置键（不同 ROM 可能只实现其一）
    private val PROVIDER_SETTING_KEYS = listOf(
        "credential_provider_services_primary",
        "credential_provider_services",
    )

    fun passwordSaveAvailable(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return false
        return runCatching {
            val pm = context.packageManager
            val component = android.content.ComponentName(context, SERVICE_CLASS)
            // ① FAEVault 服务组件本身未被显式禁用
            val enabledState = pm.getComponentEnabledSetting(component)
            if (enabledState == android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED ||
                enabledState == android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED_USER
            ) {
                return@runCatching false
            }
            // ② 系统当前选中的 Credential Provider 列表包含 FAEVault
            val expected = component.flattenToString()
            PROVIDER_SETTING_KEYS.any { key ->
                val selected = android.provider.Settings.Secure.getString(
                    context.contentResolver,
                    key,
                )
                !selected.isNullOrBlank() && selected.split(':', ';', ',')
                    .any { it.equals(expected, ignoreCase = true) }
            }
        }.getOrDefault(false)
    }
}

object PasswordSaveChannelPolicy {
    fun choose(
        credentialManagerAvailable: Boolean,
        targetCapabilityObserved: Boolean,
    ): PasswordSaveChannel = if (credentialManagerAvailable && targetCapabilityObserved) {
        PasswordSaveChannel.CREDENTIAL_MANAGER
    } else {
        PasswordSaveChannel.AUTOFILL_FALLBACK
    }

    /**
     * 仅当决策为 Autofill 兜底时才开启自动填充保存。
     * CREDENTIAL_MANAGER 通道下必须抑制 Autofill Save，避免同一凭据双弹窗/双份保存。
     * 前置保证：choose() 的 credentialManagerAvailable 必须来自 [CredentialManagerAvailability]
     * 的实时判定——否则 Provider 被关闭时会出现"两个保存通道一起消失"。
     */
    fun includeAutofillSaveFallback(channel: PasswordSaveChannel): Boolean =
        channel == PasswordSaveChannel.AUTOFILL_FALLBACK
}

/**
 * Remembers only capabilities that a target app has proved by sending this provider a real
 * CreatePasswordRequest. The observation is bound to the installed app version and signing
 * certificates, so an update or package replacement automatically restores the Autofill fallback
 * until Credential Manager support is observed again.
 *
 * 职责边界：本 Registry 只回答"目标 App 当前版本是否真实向 FAEVault 发起过 Password CM 创建"，
 * 不判断"现在该走哪个渠道"——组合决策由 [PasswordSaveChannelPolicy.choose] 完成。
 */
object PasswordSaveChannelRegistry {
    private const val PREFS = "password_save_channels"
    private const val ENTRY_PREFIX = "credential_manager_"

    /**
     * 记录 capability。存储按 packageName 单键覆盖：新版本观察成功后旧版本 token 自动被替换，
     * 天然完成"旧版本 capability 清理"，不会随版本累积。
     */
    fun observeCredentialManagerCreate(context: Context, packageName: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        val token = installedIdentityToken(context, packageName) ?: return
        runCatching {
            SecurePreferences.get(context, PREFS).edit()
                .putString(entryKey(packageName), token)
                .apply()
        }
    }

    fun channelFor(context: Context, packageName: String): PasswordSaveChannel {
        val available = CredentialManagerAvailability.passwordSaveAvailable(context)
        val observed = if (available) {
            val current = installedIdentityToken(context, packageName)
            current != null && runCatching {
                SecurePreferences.get(context, PREFS).getString(entryKey(packageName), null) == current
            }.getOrDefault(false)
        } else {
            false
        }
        return PasswordSaveChannelPolicy.choose(available, observed)
    }

    private fun installedIdentityToken(context: Context, packageName: String): String? = runCatching {
        val info = context.packageManager.getPackageInfo(packageName, 0)
        val version = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }
        val certificates = PackageIdentityResolver.signingCertificateSha256(context, packageName)
        if (certificates.isEmpty()) return@runCatching null
        val identity = buildString {
            append(packageName)
            append('\u0000')
            append(version)
            certificates.sorted().forEach {
                append('\u0000')
                append(it)
            }
        }
        PackageIdentityResolver.sha256(identity.toByteArray())
    }.getOrNull()

    private fun entryKey(packageName: String): String = ENTRY_PREFIX +
        MessageDigest.getInstance("SHA-256")
            .digest(packageName.toByteArray())
            .joinToString("") { "%02x".format(it) }
}
