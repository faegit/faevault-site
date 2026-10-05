package com.vault.passkeys

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.background
import androidx.compose.material.icons.Icons
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import com.vault.ui.screens.VaultActionStyle
import com.vault.ui.screens.VaultDialog
import com.vault.ui.VaultChooserList
import com.vault.ui.VaultUnlockCard
import com.vault.ui.VaultUnlockLoading
import com.vault.ui.VaultUnlockPanel
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.credentials.CreatePasswordRequest
import androidx.credentials.CreatePasswordResponse
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPasswordOption
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PasswordCredential
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.PasswordCredentialEntry
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.PublicKeyCredentialEntry
import com.vault.R
import com.vault.autofill.AppNameResolver
import com.vault.autofill.AndroidAutofillAttemptPolicy
import com.vault.autofill.AndroidAutofillVaultDataSource
import com.vault.autofill.AutofillVaultGateway
import com.vault.autofill.AutofillVaultSession
import com.vault.autofill.AutofillErrorCode
import com.vault.autofill.PasswordSaveChannelRegistry
import com.vault.autofill.PackageIdentityResolver
import com.vault.autofill.TargetOrigin
import com.vault.autofill.AutofillExcludePref
import com.vault.autofill.VaultAuthResult
import com.vault.autofill.VaultWriteResult
import com.vault.autofill.credentialManagerPasswordOrigin
import com.vault.model.EntryModules
import com.vault.model.PasskeyRecord
import com.vault.model.SecretType
import com.vault.model.entryModules
import com.vault.security.BiometricVault
import com.vault.security.VaultDeviceIdentityStore
import com.vault.ui.FAEVaultTheme
import com.vault.ui.VaultButton
import com.vault.ui.VaultButtonVariant
import com.vault.ui.copySensitive
import com.vault.ui.localizeUiTextFor
import com.vault.ui.uiText
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.serialization.json.jsonObject
import java.util.Base64
import java.security.MessageDigest
import java.util.UUID
import kotlin.coroutines.resume
import com.vault.ui.VaultShape

class PasskeyCreateException(message: String) : Exception(message)

@RequiresApi(34)
class PasskeyCredentialActivity : FragmentActivity() {
    private lateinit var gateway: AutofillVaultGateway
    private lateinit var callerTrust: PasskeyCallerTrust
    private val userVerifier = AndroidPasskeyUserVerifier()
    private var activeSession: AutofillVaultSession? = null
    private var vaultUnlockBiometricVerified = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 冷启动补齐「当前保险库」命名空间：进程被系统回收后由凭据管理器直接唤起时，
        // CurrentVaultKey 尚未安装，会回退 DEFAULT 导致 Passkey 模式 / 锁定计数 / 排除列表
        // 等按账户隔离的偏好解析到错误账户。
        com.vault.security.CurrentVaultKey.install(
            com.vault.storage.VaultRegistry(this).current()
                ?: com.vault.security.CurrentVaultKey.DEFAULT,
        )
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        // 进程死亡恢复：令牌快照加载（幂等），须在任何 consume 之前
        PasskeyRequestTokens.install(this)
        if (savedInstanceState != null) return cancel()
        gateway = AutofillVaultGateway(AndroidAutofillVaultDataSource(this), AndroidAutofillAttemptPolicy(this),
            excludeFilter = { origin -> AutofillExcludePref.isExcluded(this, origin) },
            appNameResolver = { AppNameResolver.label(this, it) })
        callerTrust = PasskeyCallerTrust(this)
        observeCredentialManagerPasswordCapability()
        setContent { FAEVaultTheme { AuthScreen() } }
    }

    private fun observeCredentialManagerPasswordCapability() {
        if (intent.getStringExtra(EXTRA_MODE) != MODE_CREATE_PASSWORD) return
        val provider = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: return
        if (provider.callingRequest !is CreatePasswordRequest) return
        PasswordSaveChannelRegistry.observeCredentialManagerCreate(
            this,
            provider.callingAppInfo.packageName,
        )
    }

    override fun onDestroy() {
        activeSession?.clear()
        activeSession = null
        super.onDestroy()
    }

    @Composable
    private fun AuthScreen() {
        val vaults = remember { gateway.listVaults() }
        var selected by remember { mutableStateOf(vaults.singleOrNull()) }
        var password by remember { mutableStateOf("") }
        var error by remember { mutableStateOf("") }
        var busy by remember { mutableStateOf(false) }
        var biometricAttemptedFor by remember { mutableStateOf<String?>(null) }
        val scope = rememberCoroutineScope()

        // 用户在多账户选择器中切换到某个账户后，让 Passkey 模式 / 锁定计数等偏好跟随所选账户。
        LaunchedEffect(selected) {
            selected?.let { com.vault.security.CurrentVaultKey.install(it) }
        }

        var dismissConfirmationVisible by remember { mutableStateOf(false) }

        BackHandler { dismissConfirmationVisible = true }

        fun authenticateWithBiometric(vault: String) {
            val biometric = BiometricVault(this, vault)
            if (!biometric.isEnrolled() || !biometric.canAuthenticate(this)) return
            busy = true
            lifecycleScope.launch {
                runCatching { biometric.unlock(this@PasskeyCredentialActivity) }
                    .onSuccess { material ->
                        try {
                            material.withSecretSuspend(material.binding) { deviceKey ->
                                when (val result = gateway.authenticateWithDeviceKey(vault, deviceKey, material.binding)) {
                                    is VaultAuthResult.Success -> {
                                        vaultUnlockBiometricVerified = true
                                        activeSession = result.session
                                        process(result.session)
                                    }
                                    is VaultAuthResult.WrongPassword -> error = getString(R.string.system_auth_wrong_password_remaining, result.failure.remainingAttempts)
                                    is VaultAuthResult.CoolingDown -> error = getString(R.string.system_auth_attempts_cooldown)
                                    VaultAuthResult.MissingVault -> error = getString(R.string.system_auth_vault_missing)
                                    is VaultAuthResult.Failure -> error = getString(result.code.messageRes())
                                }
                            }
                        } finally {
                            material.close()
                        }
                    }
                    .onFailure { failure ->
                        if (failure !is BiometricVault.BiometricCancelled) {
                            error = getString(R.string.system_auth_biometric_unavailable)
                        }
                    }
                busy = false
            }
        }

        LaunchedEffect(selected) {
            val vault = selected
            if (vault != null && biometricAttemptedFor != vault) {
                biometricAttemptedFor = vault
                authenticateWithBiometric(vault)
            }
        }

        fun authenticateWithPassword(vault: String) {
            busy = true; error = ""
            val chars = password.toCharArray(); password = ""
            scope.launch {
                vaultUnlockBiometricVerified = false
                when (val result = gateway.authenticate(vault, chars)) {
                    is VaultAuthResult.Success -> { activeSession = result.session; process(result.session) }
                    is VaultAuthResult.WrongPassword -> error = getString(R.string.system_auth_wrong_password_remaining, result.failure.remainingAttempts)
                    is VaultAuthResult.CoolingDown -> error = getString(R.string.system_auth_attempts_cooldown)
                    VaultAuthResult.MissingVault -> error = getString(R.string.system_auth_vault_missing)
                    is VaultAuthResult.Failure -> error = getString(result.code.messageRes())
                }
                busy = false
            }
        }

        // 弹窗标题按请求语境区分：创建类 vs 使用/填充类（中英文案见 UiText）
        val title = when (intent.getStringExtra(EXTRA_MODE)) {
            MODE_CREATE -> uiText("创建通行密钥")
            MODE_CREATE_PASSWORD -> uiText("保存密码")
            MODE_QUERY -> uiText("选择通行密钥")
            MODE_GET, MODE_GET_DISCOVERABLE -> uiText("使用通行密钥")
            MODE_GET_PASSWORD -> uiText("填充密码")
            else -> uiText("从保险库填充")
        }

        VaultUnlockCard(
            title = title,
            originText = null,
            onClose = { dismissConfirmationVisible = true },
        ) {
            when {
                vaults.isEmpty() -> Text(
                    uiText("尚未创建保险库，请先打开保险库应用完成设置。"),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                selected == null -> VaultChooserList(vaults) { selected = it }
                busy -> VaultUnlockLoading(isComplete = false)
                else -> {
                    val vault = selected!!
                    VaultUnlockPanel(
                        vaultName = vault,
                        password = password,
                        onPasswordChange = { password = it },
                        message = error,
                        busy = busy,
                        retrySeconds = 0,
                        hasBiometric = runCatching {
                            val bio = BiometricVault(this@PasskeyCredentialActivity, vault)
                            bio.isEnrolled() && bio.canAuthenticate(this@PasskeyCredentialActivity)
                        }.getOrDefault(false),
                        onUnlock = { authenticateWithPassword(vault) },
                        onBiometric = { authenticateWithBiometric(vault) },
                        onSwitch = { selected = null; password = "" },
                    )
                }
            }
        }
        if (dismissConfirmationVisible) {
            VaultDialog(
                onDismissRequest = { dismissConfirmationVisible = false },
                title = uiText("确认退出"),
                text = uiText("退出后需要重新发起通行密钥创建。"),
                confirmText = uiText("确认退出"),
                onConfirm = { cancel() },
                confirmStyle = VaultActionStyle.DANGER,
                dismissText = uiText("继续创建"),
                onDismiss = { dismissConfirmationVisible = false },
            )
        }
    }

    private suspend fun process(session: AutofillVaultSession) {
        try {
            when (intent.getStringExtra(EXTRA_MODE)) {
                MODE_QUERY -> finishQuery(session)
                MODE_CREATE -> finishCreate(session)
                MODE_GET -> finishGet(session)
                MODE_GET_DISCOVERABLE -> finishGetDiscoverable(session)
                MODE_CREATE_PASSWORD -> finishCreatePassword(session)
                MODE_GET_PASSWORD -> finishGetPassword(session)
                else -> error("unknown request mode")
            }
        } catch (_: java.util.concurrent.CancellationException) {
            if (!isFinishing) cancel()
        } catch (error: PasskeyCreateException) {
            Log.e(TAG, "request failed: ${error.message}")
            Toast.makeText(this, localizeUiTextFor(this, error.message ?: getString(R.string.system_auth_request_failed)), Toast.LENGTH_LONG).show()
            cancel()
        } catch (error: Exception) {
            Log.e(TAG, "request failed: ${error::class.java.simpleName}: ${error.message}", error)
            Toast.makeText(this, getString(R.string.system_auth_request_invalid), Toast.LENGTH_LONG).show()
            cancel()
        }
    }

    private fun AutofillErrorCode.messageRes(): Int = when (this) {
        AutofillErrorCode.PASSKEY_INVALID -> R.string.system_auth_passkey_invalid
        AutofillErrorCode.VAULT_OPEN_FAILED -> R.string.system_auth_vault_open_failed
        AutofillErrorCode.DEVICE_BINDING_MISMATCH -> R.string.system_auth_device_binding_mismatch
        AutofillErrorCode.MUTATION_BASELINE_MISSING -> R.string.system_auth_mutation_baseline_missing
        AutofillErrorCode.SESSION_KEY_INVALID -> R.string.system_auth_session_key_invalid
        AutofillErrorCode.SAVE_FAILED, AutofillErrorCode.UNKNOWN -> R.string.system_auth_generic_error
    }

    private suspend fun finishQuery(session: AutofillVaultSession) {
        val request = PasskeyRequestStore.get(intent.getStringExtra(EXTRA_TOKEN)) ?: error("expired request")
        val callingAppInfo = request.callingAppInfo ?: error("missing calling app")
        val callerPackage = callingAppInfo.packageName
        val builder = BeginGetCredentialResponse.Builder()

        request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>().forEach { option ->
            val parsed = try {
                PasskeyRequests.parseGet(option.requestJson)
            } catch (_: Exception) {
                return@forEach
            }
            try {
                callerTrust.authorize(
                    callingAppInfo = callingAppInfo,
                    rpId = parsed.rpId,
                    clientDataHash = option.clientDataHash,
                )
            } catch (_: Exception) {
                return@forEach
            }
            gateway.findPasskeys(session, parsed) { stored -> passkeyAvailability(session, stored) }.forEach { stored ->
                val entry = stored.entry
                val record = stored.record
                val moduleId = stored.moduleId
                val requestToken = PasskeyRequestTokens.create()
                val binding = requestBinding(
                    operation = PasskeyOperation.GET,
                    requestJson = option.requestJson,
                    clientDataHash = option.clientDataHash,
                    packageName = callerPackage,
                    rpId = parsed.rpId,
                    entryId = entry.id,
                    moduleId = moduleId,
                    credentialId = record.credentialId,
                )
                val pending = Intent(this, PasskeyCredentialActivity::class.java)
                    .setPackage(packageName)
                    .setAction("app.fae.vault.passkey.get.${option.id}.${entry.id}.$moduleId.$requestToken")
                    .putExtra(EXTRA_MODE, MODE_GET)
                    .putExtra(EXTRA_ENTRY_ID, entry.id)
                    .putExtra(EXTRA_MODULE_ID, moduleId)
                    .putExtra(EXTRA_REQUEST_TOKEN, requestToken)
                    .putExtra(EXTRA_REQUEST_BINDING, binding)
                val pi = PendingIntent.getActivity(
                    this,
                    binding.hashCode(),
                    pending,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
                val entryBuilder = PublicKeyCredentialEntry.Builder(
                    this,
                    record.userName.ifEmpty { record.userDisplayName },
                    pi,
                    option,
                ).setDisplayName(record.userDisplayName.ifEmpty { record.rpName })
                builder.addCredentialEntry(entryBuilder.build())
            }
        }

        request.beginGetCredentialOptions.filterIsInstance<BeginGetPasswordOption>().forEach { option ->
            try {
                callerTrust.authorize(callingAppInfo, "", null)
            } catch (_: Exception) {
                return@forEach
            }
            val origin = credentialManagerPasswordOrigin(
                callerPackage,
                PackageIdentityResolver.signingCertificateSha256(this, callerPackage),
            ) ?: return@forEach
            gateway.findMatches(session, origin).forEach { match ->
                val entry = gateway.entry(session, match.entryId) ?: return@forEach
                if (entry.secretType != SecretType.LOGIN || entry.password.isEmpty()) return@forEach
                val requestId = UUID.randomUUID().toString()
                val binding = requestBinding(
                    operation = PasskeyOperation.GET,
                    requestJson = "password-credential",
                    clientDataHash = null,
                    packageName = callerPackage,
                    rpId = "",
                    entryId = entry.id,
                )
                val pending = Intent(this, PasskeyCredentialActivity::class.java)
                    .setPackage(packageName)
                    .setAction("app.fae.vault.password.get.${entry.id}.$requestId")
                    .putExtra(EXTRA_MODE, MODE_GET_PASSWORD)
                    .putExtra(EXTRA_ENTRY_ID, entry.id)
                    .putExtra(EXTRA_REQUEST_BINDING, binding)
                val pi = PendingIntent.getActivity(
                    this,
                    requestId.hashCode(),
                    pending,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT or
                        PendingIntent.FLAG_ONE_SHOT,
                )
                builder.addCredentialEntry(
                    PasswordCredentialEntry.Builder(this, entry.username, pi, option).build(),
                )
            }
        }

        val result = Intent()
        PendingIntentHandler.setBeginGetCredentialResponse(result, builder.build())
        setResult(Activity.RESULT_OK, result); finish()
    }

    private suspend fun finishCreatePassword(session: AutofillVaultSession) {
        val provider = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
            ?: error("missing create request")
        val request = provider.callingRequest as? CreatePasswordRequest
            ?: error("unsupported request")
        callerTrust.authorize(provider.callingAppInfo, "", null)
        val callerPackage = provider.callingAppInfo.packageName
        val origin = credentialManagerPasswordOrigin(
            callerPackage,
            PackageIdentityResolver.signingCertificateSha256(this, callerPackage),
        ) ?: throw PasskeyCreateException(getString(R.string.system_auth_request_invalid))
        when (val result = gateway.createLogin(session, origin, request.id, request.password)) {
            is VaultWriteResult.Success -> {}
            is VaultWriteResult.Stale -> throw PasskeyCreateException(getString(R.string.system_auth_entry_changed_retry))
            is VaultWriteResult.Missing -> throw PasskeyCreateException(getString(R.string.system_auth_vault_data_invalid))
            is VaultWriteResult.Failure -> throw PasskeyCreateException(getString(result.code.messageRes()))
        }
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, CreatePasswordResponse())
        setResult(Activity.RESULT_OK, result); finish()
    }

    private suspend fun finishCreate(session: AutofillVaultSession) {
        val provider = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) ?: error("missing create request")
        val request = provider.callingRequest as? CreatePublicKeyCredentialRequest ?: error("unsupported request")
        val parsed = PasskeyRequests.parseCreate(request.requestJson)
        Log.d(TAG, "create request parsed: rpId=${parsed.rpId}, caller=${provider.callingAppInfo.packageName}, delegatedOrigin=${provider.callingAppInfo.isOriginPopulated()}")
        if (gateway.hasExcludedPasskey(session, parsed)) {
            throw PasskeyCreateException(getString(R.string.system_auth_passkey_exists))
        }
        val caller = callerTrust.authorize(
            provider.callingAppInfo,
            parsed.rpId,
            request.clientDataHash,
        )
        Log.d(TAG, "create caller authorized: privileged=${caller.privilegedBrowser}")
        val selectedMode = PasskeyModePref(this).creationPreference.fixedMode
            ?: choosePasskeyMode(parsed)
        val requestToken = intent.getStringExtra(EXTRA_REQUEST_TOKEN) ?: error("missing request token")
        val binding = requestBinding(
            operation = PasskeyOperation.CREATE,
            requestJson = request.requestJson,
            clientDataHash = request.clientDataHash,
            packageName = provider.callingAppInfo.packageName,
            rpId = parsed.rpId,
        )
        if (selectedMode.requiresActivityUserVerification()) {
            requireUserVerification(
                requestToken,
                PasskeyOperation.CREATE,
                binding,
                provider.biometricPromptResult,
            )
        }
        // 请求摘要绑定：令牌只对签发时的那份 requestJson 有效（防错误复用跨请求）
        val expectedDigest = intent.getStringExtra(EXTRA_REQUEST_DIGEST)
        if (expectedDigest != null && !constantTimeEquals(expectedDigest, requestFingerprint(request.requestJson))) {
            Log.w(TAG, "request digest mismatch; silently cancelling")
            cancel()
            return
        }
        if (!PasskeyRequestTokens.consume(requestToken)) {
            // 【防死循环】令牌过期或已被消费：系统可能正在自动重放缓存的历史入口
            // （CreateEntry.setAutoSelectAllowed）。静默取消且不再弹"请求无效"，
            // 否则 Google 页面会立刻自动重试并再次拉起同一入口，形成无限循环。
            Log.w(TAG, "stale or reused request token; silently cancelling")
            cancel()
            return
        }
        val created = when (selectedMode) {
            PasskeyKeyMode.SYNCABLE -> createSyncablePasskey(session, request, caller.origin)
            PasskeyKeyMode.DEVICE_BOUND -> createDeviceBoundPasskey(session, request, caller.origin)
        }
        val result = Intent()
        PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(created.responseJson))
        setResult(Activity.RESULT_OK, result); finish()
    }

    private suspend fun finishGetPassword(session: AutofillVaultSession) {
        val provider = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            ?: error("missing get request")
        provider.credentialOptions.filterIsInstance<GetPasswordOption>().singleOrNull()
            ?: error("unsupported request")
        val entryId = intent.getStringExtra(EXTRA_ENTRY_ID) ?: error("missing entry")
        val binding = requestBinding(
            operation = PasskeyOperation.GET,
            requestJson = "password-credential",
            clientDataHash = null,
            packageName = provider.callingAppInfo.packageName,
            rpId = "",
            entryId = entryId,
        )
        val expectedBinding = intent.getStringExtra(EXTRA_REQUEST_BINDING)
            ?: error("missing request binding")
        require(constantTimeEquals(expectedBinding, binding))
        callerTrust.authorize(provider.callingAppInfo, "", null)
        val entry = gateway.entry(session, entryId) ?: error("password entry not found")
        require(entry.secretType == SecretType.LOGIN && entry.password.isNotEmpty())
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(
            result,
            GetCredentialResponse(PasswordCredential(entry.username, entry.password)),
        )
        setResult(Activity.RESULT_OK, result); finish()
    }

    private suspend fun finishGet(session: AutofillVaultSession) {
        val provider = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: error("missing get request")
        val option = provider.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().singleOrNull() ?: error("unsupported request")
        val parsed = PasskeyRequests.parseGet(option.requestJson)
        val entryId = intent.getStringExtra(EXTRA_ENTRY_ID) ?: error("missing entry")
        val moduleId = intent.getStringExtra(EXTRA_MODULE_ID) ?: error("missing module")
        val entry = gateway.entry(session, entryId) ?: error("missing entry")
        val module = entry.entryModules().firstOrNull { EntryModules.primitive(it["id"]) == moduleId } ?: error("missing module")
        val record = PasskeyRecord.parse(module["value"]?.jsonObject ?: error("invalid module")) ?: error("invalid passkey")
        require(record.rpId == parsed.rpId)
        require(parsed.allowCredentialIds.isEmpty() || record.credentialId in parsed.allowCredentialIds)
        val binding = requestBinding(
            operation = PasskeyOperation.GET,
            requestJson = option.requestJson,
            clientDataHash = option.clientDataHash,
            packageName = provider.callingAppInfo.packageName,
            rpId = parsed.rpId,
            entryId = entryId,
            moduleId = moduleId,
            credentialId = record.credentialId,
        )
        val expectedBinding = intent.getStringExtra(EXTRA_REQUEST_BINDING) ?: error("missing request binding")
        require(constantTimeEquals(expectedBinding, binding))
        val caller = callerTrust.authorize(
            provider.callingAppInfo,
            record.rpId,
            option.clientDataHash,
        )
        val requestToken = intent.getStringExtra(EXTRA_REQUEST_TOKEN) ?: error("missing request token")
        val asserted = if (record.schemaVersion == PasskeyRecord.LEGACY_SCHEMA_VERSION) {
            requireUserVerification(
                requestToken,
                PasskeyOperation.GET,
                binding,
                provider.biometricPromptResult,
            )
            if (!PasskeyRequestTokens.consume(requestToken)) {
                // 【防死循环】同 finishCreate：过期/重复令牌静默取消，不弹错误
                Log.w(TAG, "stale or reused request token; silently cancelling")
                cancel()
                return
            }
            PasskeyAuthenticator.get(
                option.requestJson,
                caller.origin,
                record,
                userVerified = true,
                clientDataHash = option.clientDataHash,
            )
        } else {
            if (record.keyMode.requiresActivityUserVerification()) {
                requireUserVerification(
                    requestToken,
                    PasskeyOperation.GET,
                    binding,
                    provider.biometricPromptResult,
                )
            }
            if (!PasskeyRequestTokens.consume(requestToken)) {
                // 【防死循环】同 finishCreate：过期/重复令牌静默取消，不弹错误
                Log.w(TAG, "stale or reused request token; silently cancelling")
                cancel()
                return
            }
            getV3Passkey(session, entryId, moduleId, record, option.requestJson, caller.origin, option.clientDataHash)
        }
        // 断言已生成，登录本身已完成；此后的记录回写（signCount/lastUsedAt 等元数据）
        // 属于 Best-Effort——写库失败只记日志，不得让整个认证失败。
        // （当前 signCount 策略为 synced_zero，回写内容不含安全关键状态。）
        when (val update = gateway.updatePasskey(session, entryId, moduleId, record.credentialId, asserted.record)) {
            is VaultWriteResult.Success -> Unit
            else -> Log.w(TAG, "post-assertion metadata update skipped: $update")
        }
        val result = Intent()
        PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(PublicKeyCredential(asserted.responseJson)))
        setResult(Activity.RESULT_OK, result); finish()
    }

    /**
     * Provider-level entry used when Chrome requires an immediately available credential entry.
     * It deliberately contains no decrypted account metadata. After Vault's own biometric unlock,
     * resolve the exact passkey and continue through the normal bound GET path.
     */
    private suspend fun finishGetDiscoverable(session: AutofillVaultSession) {
        val provider = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
            ?: error("missing get request")
        val option = provider.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().singleOrNull()
            ?: error("unsupported request")
        val expectedDigest = intent.getStringExtra(EXTRA_REQUEST_DIGEST)
            ?: error("missing request digest")
        if (!constantTimeEquals(expectedDigest, requestFingerprint(option.requestJson))) {
            Log.w(TAG, "discoverable request digest mismatch; silently cancelling")
            cancel()
            return
        }
        val parsed = PasskeyRequests.parseGet(option.requestJson)
        callerTrust.authorize(provider.callingAppInfo, parsed.rpId, option.clientDataHash)
        val candidates = gateway.findPasskeys(session, parsed) { stored ->
            passkeyAvailability(session, stored)
        }
        val stored = when (candidates.size) {
            0 -> throw PasskeyCreateException(getString(R.string.system_auth_passkey_not_found))
            1 -> candidates.single()
            else -> chooseStoredPasskey(candidates)
        }
        val binding = requestBinding(
            operation = PasskeyOperation.GET,
            requestJson = option.requestJson,
            clientDataHash = option.clientDataHash,
            packageName = provider.callingAppInfo.packageName,
            rpId = parsed.rpId,
            entryId = stored.entry.id,
            moduleId = stored.moduleId,
            credentialId = stored.record.credentialId,
        )
        intent.putExtra(EXTRA_MODE, MODE_GET)
            .putExtra(EXTRA_ENTRY_ID, stored.entry.id)
            .putExtra(EXTRA_MODULE_ID, stored.moduleId)
            .putExtra(EXTRA_REQUEST_BINDING, binding)
        finishGet(session)
    }

    private suspend fun createSyncablePasskey(
        session: AutofillVaultSession,
        request: CreatePublicKeyCredentialRequest,
        origin: String,
    ): PasskeyAuthenticator.Created {
        val location = gateway.allocatePasskeyLocation()
        return SoftwarePasskeySigningKey.generate(PasskeyRequests.parseCreate(request.requestJson).algorithm).use { signingKey ->
            val created = PasskeyAuthenticator.create(
                request.requestJson,
                origin,
                true,
                signingKey,
                recordFactory = { seed ->
                    val privateBytes = signingKey.exportPrivateKey()
                    try {
                        recordFromSeed(
                            seed,
                            keyMode = PasskeyKeyMode.SYNCABLE,
                            backupEligible = true,
                            backupState = false,
                            privateKey = Base64.getUrlEncoder().withoutPadding().encodeToString(privateBytes),
                        )
                    } finally {
                        privateBytes.fill(0)
                    }
                },
                clientDataHash = request.clientDataHash,
            )
            requirePasskeySaved(gateway.createPasskey(session, created.record, location))
            created
        }
    }

    private suspend fun createDeviceBoundPasskey(
        session: AutofillVaultSession,
        request: CreatePublicKeyCredentialRequest,
        origin: String,
    ): PasskeyAuthenticator.Created {
        val location = gateway.allocatePasskeyLocation()
        val store = AndroidPasskeyKeyStore(this, physicalDeviceId(session.vaultName))
        val algorithm = PasskeyRequests.parseCreate(request.requestJson).algorithm
        val generated = store.generate(algorithm)
        return try {
            store.openForSigning(this, generated.binding, algorithm, generated.publicKeyCose).use { signingKey ->
                val created = PasskeyAuthenticator.create(
                    request.requestJson,
                    origin,
                    true,
                    signingKey,
                    recordFactory = { seed ->
                        recordFromSeed(
                            seed,
                            keyMode = PasskeyKeyMode.DEVICE_BOUND,
                            backupEligible = false,
                            backupState = false,
                            binding = generated.binding,
                        )
                    },
                    clientDataHash = request.clientDataHash,
                )
                requirePasskeySaved(gateway.createPasskey(session, created.record, location))
                created
            }
        } catch (error: Throwable) {
            store.delete(generated.binding)
            throw error
        } finally {
            generated.publicKeyCose.fill(0)
        }
    }

    private suspend fun getV3Passkey(
        session: AutofillVaultSession,
        entryId: String,
        moduleId: String,
        record: PasskeyRecord,
        requestJson: String,
        origin: String,
        clientDataHash: ByteArray?,
    ): PasskeyAuthenticator.Asserted {
        return when (record.keyMode) {
            PasskeyKeyMode.SYNCABLE -> {
                val privateBytes = Base64.getUrlDecoder().decode(record.privateKey.padBase64())
                val publicCose = Base64.getUrlDecoder().decode(record.publicKey.padBase64())
                try {
                    SoftwarePasskeySigningKey.open(record.algorithm, privateBytes, publicCose).use { key ->
                        PasskeyAuthenticator.get(requestJson, origin, record, true, key, clientDataHash)
                    }
                } finally {
                    privateBytes.fill(0)
                    publicCose.fill(0)
                }
            }
            PasskeyKeyMode.DEVICE_BOUND -> {
                val binding = requireNotNull(record.deviceBinding)
                val publicCose = Base64.getUrlDecoder().decode(record.publicKey.padBase64())
                try {
                    val store = AndroidPasskeyKeyStore(this, physicalDeviceId(session.vaultName))
                    store.openForSigning(this, binding, record.algorithm, publicCose).use { key ->
                        PasskeyAuthenticator.get(
                            requestJson,
                            origin,
                            record,
                            true,
                            key,
                            clientDataHash,
                            localCounterStore = store,
                        )
                    }
                } finally {
                    publicCose.fill(0)
                }
            }
        }
    }

    private fun passkeyAvailability(session: AutofillVaultSession, stored: StoredPasskey): PasskeyAvailability {
        val record = stored.record
        if (record.schemaVersion == PasskeyRecord.LEGACY_SCHEMA_VERSION) return PasskeyAvailability.AVAILABLE
        return when (record.keyMode) {
            PasskeyKeyMode.SYNCABLE -> PasskeyAvailability.AVAILABLE
            PasskeyKeyMode.DEVICE_BOUND -> AndroidPasskeyKeyStore(this, physicalDeviceId(session.vaultName))
                .availability(requireNotNull(record.deviceBinding))
        }
    }

    private fun physicalDeviceId(vaultName: String): UUID =
        VaultDeviceIdentityStore(this, vaultName).loadOrCreate().use { it.deviceId }

    private fun recordFromSeed(
        seed: PasskeyAuthenticator.CreationRecord,
        keyMode: PasskeyKeyMode,
        backupEligible: Boolean,
        backupState: Boolean,
        privateKey: String = "",
        binding: PasskeyDeviceBinding? = null,
    ): PasskeyRecord = PasskeyRecord(
        rpId = seed.rpId,
        rpName = seed.rpName,
        userId = seed.userId,
        userName = seed.userName,
        userDisplayName = seed.userDisplayName,
        credentialId = seed.credentialId,
        privateKey = privateKey,
        publicKey = seed.publicKey,
        signCount = 0,
        createdAt = seed.createdAt,
        lastUsedAt = "",
        transports = "internal",
        algorithm = seed.algorithm,
        schemaVersion = PasskeyRecord.CURRENT_SCHEMA_VERSION,
        aaguid = seed.aaguid,
        discoverable = true,
        backupEligible = backupEligible,
        backupState = backupState,
        keyMode = keyMode,
        deviceBinding = binding,
    )

    private fun requirePasskeySaved(result: VaultWriteResult) {
        when (result) {
            is VaultWriteResult.Success -> Unit
            is VaultWriteResult.Stale -> throw PasskeyCreateException("通行密钥已存在")
            is VaultWriteResult.Missing -> throw PasskeyCreateException("保险库数据异常")
            is VaultWriteResult.Failure -> throw PasskeyCreateException(getString(result.code.messageRes()))
        }
    }

    private suspend fun choosePasskeyMode(request: CreatePasskeyRequest): PasskeyKeyMode =
        suspendCancellableCoroutine { continuation ->
            setContent {
                FAEVaultTheme {
                    var selected by remember { mutableStateOf(PasskeyKeyMode.SYNCABLE) }
                    Box(
                        Modifier.fillMaxSize()
                            .background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.45f))
                            .padding(16.dp),
                    ) {
                        Card(
                            modifier = Modifier.fillMaxWidth().align(Alignment.Center),
                            shape = VaultShape,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        ) {
                            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text(uiText("创建 Passkey"), style = MaterialTheme.typography.titleLarge)
                                Text("${request.rpName.ifEmpty { request.rpId }} · ${request.userName}")
                                val syncSelected = selected == PasskeyKeyMode.SYNCABLE
                                if (syncSelected) {
                                    VaultButton(onClick = { selected = PasskeyKeyMode.SYNCABLE }, modifier = Modifier.fillMaxWidth()) {
                                        Text(uiText("PMV 同步型（推荐）"))
                                    }
                                } else {
                                    VaultButton(
                                        onClick = { selected = PasskeyKeyMode.SYNCABLE },
                                        modifier = Modifier.fillMaxWidth(),
                                        variant = VaultButtonVariant.OUTLINED,
                                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                    ) {
                                        Text(uiText("PMV 同步型（推荐）"))
                                    }
                                }
                                Text(uiText("私钥随加密保险库同步，新设备打开同一数据库后可直接使用。"))
                                if (!syncSelected) {
                                    VaultButton(onClick = { selected = PasskeyKeyMode.DEVICE_BOUND }, modifier = Modifier.fillMaxWidth()) {
                                        Text(uiText("本设备高安全性"))
                                    }
                                } else {
                                    VaultButton(
                                        onClick = { selected = PasskeyKeyMode.DEVICE_BOUND },
                                        modifier = Modifier.fillMaxWidth(),
                                        variant = VaultButtonVariant.OUTLINED,
                                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                                    ) {
                                        Text(uiText("本设备高安全性"))
                                    }
                                }
                                Text(uiText("私钥不可导出且只存在于本机 Android Keystore；设备丢失后无法恢复。"))
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    VaultButton(onClick = {
                                        if (continuation.isActive) continuation.cancel()
                                    }, variant = VaultButtonVariant.OUTLINED) { Text(uiText("取消")) }
                                    VaultButton(
                                        onClick = {
                                            if (continuation.isActive) continuation.resume(selected)
                                        },
                                        modifier = Modifier.weight(1f),
                                    ) { Text(uiText("确认创建")) }
                                }
                            }
                        }
                    }
                }
            }
        }

    private suspend fun chooseStoredPasskey(candidates: List<StoredPasskey>): StoredPasskey =
        suspendCancellableCoroutine { continuation ->
            setContent {
                FAEVaultTheme {
                    Box(
                        Modifier.fillMaxSize()
                            .background(MaterialTheme.colorScheme.scrim.copy(alpha = 0.45f))
                            .padding(16.dp),
                    ) {
                        Card(
                            modifier = Modifier.fillMaxWidth().align(Alignment.Center),
                            shape = VaultShape,
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                        ) {
                            Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text(uiText("选择通行密钥"), style = MaterialTheme.typography.titleLarge)
                                candidates.forEach { stored ->
                                    val record = stored.record
                                    val account = record.userDisplayName.ifEmpty { record.userName }
                                    VaultButton(
                                        onClick = {
                                            if (continuation.isActive) continuation.resume(stored)
                                        },
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text(account.ifEmpty { record.rpName.ifEmpty { record.rpId } })
                                    }
                                }
                                VaultButton(
                                    onClick = {
                                        if (continuation.isActive) continuation.cancel()
                                    },
                                    modifier = Modifier.fillMaxWidth(),
                                    variant = VaultButtonVariant.OUTLINED,
                                ) { Text(uiText("取消")) }
                            }
                        }
                    }
                }
            }
        }

    private suspend fun requireUserVerification(
        requestToken: String,
        operation: PasskeyOperation,
        binding: String,
        embeddedPromptResult: androidx.credentials.provider.BiometricPromptResult?,
    ) {
        if (vaultUnlockBiometricVerified) {
            vaultUnlockBiometricVerified = false
            Log.d(TAG, "reusing fresh strong biometric vault unlock for user verification")
            return
        }
        when (
            val result = userVerifier.verify(
                activity = this,
                requestToken = requestToken,
                operation = operation,
                contextBinding = binding,
                embeddedPromptResult = embeddedPromptResult,
            )
        ) {
            is UserVerificationResult.Verified -> require(
                userVerifier.consume(result.ticket, requestToken, operation, binding),
            )
            UserVerificationResult.Cancelled -> {
                cancel()
                throw java.util.concurrent.CancellationException("user verification cancelled")
            }
            UserVerificationResult.Failure -> throw SecurityException("user verification failed")
        }
    }

    private fun requestBinding(
        operation: PasskeyOperation,
        requestJson: String,
        clientDataHash: ByteArray?,
        packageName: String,
        rpId: String,
        entryId: String = "",
        moduleId: String = "",
        credentialId: String = "",
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        listOf(
            operation.name,
            packageName,
            rpId,
            entryId,
            moduleId,
            credentialId,
            requestJson,
        ).forEach {
            digest.update(it.toByteArray())
            digest.update(0.toByte())
        }
        digest.update(clientDataHash ?: ByteArray(0))
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun constantTimeEquals(left: String, right: String): Boolean =
        MessageDigest.isEqual(left.toByteArray(), right.toByteArray())

    /** 与 Service 侧签发的 EXTRA_REQUEST_DIGEST 对应：SHA-256(requestJson) hex。 */
    private fun requestFingerprint(requestJson: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(requestJson.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

private fun cancel() { setResult(Activity.RESULT_CANCELED); finish() }

    companion object {
        const val EXTRA_MODE = "passkey_mode"; const val EXTRA_TOKEN = "passkey_token"
        const val EXTRA_ENTRY_ID = "passkey_entry_id"; const val EXTRA_MODULE_ID = "passkey_module_id"
        const val EXTRA_REQUEST_TOKEN = "passkey_request_token"
        const val EXTRA_REQUEST_DIGEST = "passkey_request_digest"
        const val EXTRA_REQUEST_BINDING = "passkey_request_binding"
        const val MODE_QUERY = "query"; const val MODE_CREATE = "create"; const val MODE_GET = "get"
        const val MODE_GET_DISCOVERABLE = "get_discoverable"
        const val MODE_CREATE_PASSWORD = "create_password"; const val MODE_GET_PASSWORD = "get_password"
        private const val TAG = "Passkey"
    }
}
