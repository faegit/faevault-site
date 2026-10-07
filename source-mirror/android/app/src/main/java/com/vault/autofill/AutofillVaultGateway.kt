package com.vault.autofill

import android.content.Context
import com.vault.crypto.VaultCrypto
import com.vault.model.Entry
import com.vault.model.AutofillExclusions
import com.vault.model.autofillLinks
import com.vault.model.autofill.AutofillRole
import com.vault.model.EntryModules
import com.vault.model.entryModules
import com.vault.model.hasOtp
import com.vault.model.ModuleType
import com.vault.model.otpBindingId
import com.vault.model.withIncrementedOtpCounter
import com.vault.model.withEntryModules
import com.vault.model.PasskeyRecord
import com.vault.model.SecretType
import com.vault.model.VaultPayload
import com.vault.model.nowSeconds
import com.vault.passkeys.PasskeyMutationResult
import com.vault.passkeys.PasskeyRepository
import com.vault.passkeys.CreatePasskeyRequest
import com.vault.passkeys.GetPasskeyRequest
import com.vault.passkeys.StoredPasskey
import com.vault.passkeys.PasskeyAvailability
import com.vault.security.FailureSource
import com.vault.security.LockoutPref
import com.vault.security.VaultKeyIdentity
import com.vault.storage.VaultRegistry
import com.vault.storage.VaultRepository
import com.vault.storage.VaultIdentity
import com.vault.storage.VaultQuerySession
import com.vault.storage.VaultStaleMutationException
import java.util.UUID
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

interface AutofillVaultDataSource {
    fun listVaults(): List<String>
    fun exists(vaultName: String): Boolean
    fun openQueryWithPassword(vaultName: String, password: String): VaultQuerySession
    fun openQueryWithDeviceKey(vaultName: String, deviceKey: ByteArray): VaultQuerySession
    fun mutatePmvEWithPassword(
        vaultName: String,
        password: String,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity = error("PMVE Mutation 不可用")
    fun mutatePmvEWithDeviceKey(
        vaultName: String,
        deviceKey: ByteArray,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity = error("PMVE Mutation 不可用")
}

data class PasskeyRecordLocation(val entryId: String, val moduleId: String)

data class AutofillOtpSource(val entry: Entry, val moduleId: String?) {
    fun computationEntry(): Entry {
        val selected = moduleId?.let { id ->
            entry.entryModules().firstOrNull {
                EntryModules.primitive(it["type"]) == ModuleType.OTP && EntryModules.primitive(it["id"]) == id
            }
        }
        return if (selected == null) entry else entry.withEntryModules(listOf(selected))
    }
}

interface AutofillAttemptPolicy {
    fun coolingRemainingMs(): Long
    fun recordFailure(): AttemptFailure
    fun clear()
}

data class AttemptFailure(
    val remainingAttempts: Int,
    val retryDelayMs: Long,
    val cooldownMs: Long,
)

sealed interface VaultAuthResult {
    data class Success(val session: AutofillVaultSession) : VaultAuthResult
    data class CoolingDown(val remainingMs: Long) : VaultAuthResult
    data class WrongPassword(val failure: AttemptFailure) : VaultAuthResult
    data object MissingVault : VaultAuthResult
    data class Failure(val code: AutofillErrorCode) : VaultAuthResult
}

sealed interface VaultWriteResult {
    data class Success(val entry: Entry) : VaultWriteResult
    data object Stale : VaultWriteResult
    data object Missing : VaultWriteResult
    data class Failure(val code: AutofillErrorCode) : VaultWriteResult
}

enum class AutofillErrorCode {
    UNKNOWN,
    VAULT_OPEN_FAILED,
    DEVICE_BINDING_MISMATCH,
    PASSKEY_INVALID,
    MUTATION_BASELINE_MISSING,
    SESSION_KEY_INVALID,
    SAVE_FAILED,
}

class AutofillVaultSession internal constructor(
    val vaultName: String,
    private val password: CharArray? = null,
    private val deviceKey: ByteArray? = null,
    val querySession: VaultQuerySession,
    internal var expectedSequence: Long? = null,
) {
    internal fun passwordString(): String? = password?.concatToString()
    internal fun deviceKeyBytes(): ByteArray? = deviceKey?.copyOf()
    fun clear() {
        password?.fill('\u0000')
        deviceKey?.fill(0)
        querySession.close()
    }
}

class AutofillVaultGateway(
    private val dataSource: AutofillVaultDataSource,
    private val attemptPolicy: AutofillAttemptPolicy,
    private val clock: () -> Double = ::nowSeconds,
    private val idFactory: () -> String = { UUID.randomUUID().toString() },
    private val excludeFilter: (TargetOrigin) -> Boolean = { false },
    /** 包名 → 应用名称；解析不到时返回 null，标题回退为包名。 */
    private val appNameResolver: (String) -> String? = { null },
    private val exclusionRulesResolver: ((String) -> AutofillExclusions)? = null,
) {
    fun listVaults(): List<String> = dataSource.listVaults()

    fun authenticate(vaultName: String, password: CharArray): VaultAuthResult {
        val cooldown = attemptPolicy.coolingRemainingMs()
        if (cooldown > 0) return VaultAuthResult.CoolingDown(cooldown)
        if (!dataSource.exists(vaultName)) return VaultAuthResult.MissingVault
        return try {
            val passwordStr = password.concatToString()
            // PMVE 快速路径通过查询会话认证，不物化任何条目。
            val query = dataSource.openQueryWithPassword(vaultName, passwordStr)
            attemptPolicy.clear()
            val session = AutofillVaultSession(
                vaultName,
                password.copyOf(),
                querySession = query,
                expectedSequence = query.identity?.sequence,
            )
            VaultAuthResult.Success(session)
        } catch (_: VaultCrypto.DecryptError) {
            VaultAuthResult.WrongPassword(attemptPolicy.recordFailure())
        } catch (_: Exception) {
            VaultAuthResult.Failure(AutofillErrorCode.VAULT_OPEN_FAILED)
        } finally {
            password.fill('\u0000')
        }
    }

    fun findMatches(session: AutofillVaultSession, origin: TargetOrigin): List<CredentialMatch> {
        return OriginMatcher.rank(findMatchingEntries(session, origin), origin, hasFillableValues = { isFillableLogin(session, it) })
    }

    fun isOriginExcluded(origin: TargetOrigin, session: AutofillVaultSession? = null): Boolean {
        val authenticated = session?.querySession?.autofillExclusions()
        val rules = authenticated?.merge(
            session?.vaultName?.let { exclusionRulesResolver?.invoke(it) } ?: AutofillExclusions(),
        )
        val metadataExcluded = when (origin) {
            is TargetOrigin.AndroidPackage -> AutofillExclusions.normalizeValue("packages", origin.packageName) in rules?.packages.orEmpty()
            is TargetOrigin.Web -> normalizeExcludedHost(origin.host) in rules?.hosts.orEmpty()
        }
        return metadataExcluded || excludeFilter(origin)
    }

    /** Explicit fill picker only. Saving, automatic filling and Credential Manager use strict matches. */
    fun findFillCandidates(session: AutofillVaultSession, origin: TargetOrigin): List<Entry> {
        if (isOriginExcluded(origin, session)) return emptyList()
        val appName = (origin as? TargetOrigin.AndroidPackage)?.let { appNameResolver(it.packageName) }
        return session.querySession.listSummaries().orEmpty().asSequence()
            .filter { it.entryType == SecretType.LOGIN }
            .mapNotNull { session.querySession.readEntry(it.entryId) }
            .distinctBy { it.id }
            .filter { isFillableLogin(session, it) }
            .mapNotNull { entry -> OriginMatcher.fillCandidateReason(origin, entry, appName)?.let { entry to it } }
            .sortedWith(compareByDescending<Pair<Entry, AutofillCandidateReason>> { it.second.score }
                .thenBy { it.first.titleLower }.thenBy { it.first.id })
            .map { it.first }.toList()
    }

    /** 仅返回 LoginFastIndex 候选（PMVE 权威入口）。 */
    fun findMatchingEntries(session: AutofillVaultSession, origin: TargetOrigin): List<Entry> {
        if (isOriginExcluded(origin, session)) return emptyList()
        val query = session.querySession
        val candidateIds = when (origin) {
            is TargetOrigin.Web -> query.queryDomain(origin.host).orEmpty()
            is TargetOrigin.AndroidPackage -> query.queryPackage(origin.packageName).orEmpty()
        }.distinct()
        val candidates = candidateIds.mapNotNull(query::readEntry)
        // PMVE 中 LoginFastIndex 是自动填充的权威候选入口。索引未命中必须返回空，
        // 不能为了兼容旧提交而解密整库；旧提交会在正常保存/迁移时确定性重建索引。
        return candidates.filter {
            isFillableLogin(session, it) &&
                OriginMatcher.matchLevel(origin, it) != OriginMatchLevel.NONE
        }
    }

    /**
     * 动态码候选：携带动态码的条目（独立 OTP 条目，或带动态码模块的登录条目）。
     * 独立 OTP 条目通常无 url，仅按服务商全称（issuer）精确匹配域名。
     * PMVE 快速会话下走 EntryIndex 枚举 + 按需 readEntry：只解密 OTP 类型条目，不物化整库。
     * （带动态码模块的登录条目由 findMatchingEntries/mergeCandidates 覆盖，不在此重复读取。）
     */
    fun findOtpEntries(session: AutofillVaultSession, origin: TargetOrigin): List<Entry> {
        if (isOriginExcluded(origin, session)) return emptyList()
        val query = session.querySession
        // Android 来源只可能靠包名/url 命中，独立 OTP 条目无 url 不参与，全部候选都在登录索引里。
        if (origin is TargetOrigin.AndroidPackage) {
            val ids = query.queryPackage(origin.packageName).orEmpty()
            return ids.distinct().mapNotNull(query::readEntry).filter {
                it.deletedAt == null && it.hasOtp() &&
                    OriginMatcher.matchLevel(origin, it) != OriginMatchLevel.NONE
            }
        }
        // Web 来源：枚举 EntryIndex 只解密 OTP 类型条目，按 issuer 精确匹配域名。
        return query.listSummaries().orEmpty().asSequence()
            .filter { it.entryType == SecretType.OTP }
            .mapNotNull { query.readEntry(it.entryId) }
            .filter {
                it.deletedAt == null && it.hasOtp() &&
                    (OriginMatcher.matchLevel(origin, it) != OriginMatchLevel.NONE ||
                        OtpIssuerMatcher.matches(it, origin))
            }
            .toList()
    }

    /**
     * 其他动态码：未进入主候选列表的独立 OTP 条目（无 url / issuer 未命中，或绑定给未匹配登录条目）。
     * 走 EntryIndex 枚举 + 按需 readEntry：只解密 OTP 类型条目，不物化整库。
     */
    fun findOtherOtpEntries(session: AutofillVaultSession, excludeIds: Set<String>): List<Entry> {
        val query = session.querySession
        return query.listSummaries().orEmpty().asSequence()
            .filter { it.entryType == SecretType.OTP && it.entryId !in excludeIds }
            .mapNotNull { query.readEntry(it.entryId) }
            .filter { it.deletedAt == null && it.secretType == SecretType.OTP && it.hasOtp() }
            .toList()
    }

    /**
     * 全库登录条目（供弹窗搜索兜底）。搜索是显式用户动作；
     * 走 EntryIndex 枚举 + 按需 readEntry：只解密登录类型条目，不物化整库。
     */
    fun findAllLoginEntries(session: AutofillVaultSession): List<Entry> {
        val query = session.querySession
        return query.listSummaries().orEmpty().asSequence()
            .filter { it.entryType == SecretType.LOGIN }
            .mapNotNull { query.readEntry(it.entryId) }
            .filter { isFillableLogin(session, it) }
            .toList()
    }

    /**
     * 登录条目的实际动态码载体：自身携带动态码模块则返回自身，
     * 否则解析其绑定的独立动态码条目（bound_otp_id）。绑定悬空时返回 null。
     */
    fun otpSource(session: AutofillVaultSession, entry: Entry): Entry? {
        return otpSourceRef(session, entry)?.entry
    }

    fun otpSourceRef(session: AutofillVaultSession, entry: Entry): AutofillOtpSource? {
        val linkedRef = entry.autofillLinks().asSequence().flatMap { link ->
            link.fields.asSequence().map { field -> link.sourceEntryId to field }
        }.firstOrNull { (_, field) -> field.role == AutofillRole.ONE_TIME_CODE }
        if (linkedRef != null) {
            val (sourceId, field) = linkedRef
            val source = entry(session, sourceId)?.takeIf { it.deletedAt == null } ?: return null
            val moduleId = field.moduleId ?: return source.takeIf(Entry::hasOtp)?.let { AutofillOtpSource(it, null) }
            val valid = source.entryModules().any {
                EntryModules.primitive(it["id"]) == moduleId && EntryModules.primitive(it["type"]) == ModuleType.OTP
            }
            return source.takeIf { valid }?.let { AutofillOtpSource(it, moduleId) }
        }
        if (entry.hasOtp()) {
            val moduleId = entry.entryModules().firstOrNull {
                EntryModules.primitive(it["type"]) == ModuleType.OTP
            }?.let { EntryModules.primitive(it["id"]).ifBlank { null } }
            return AutofillOtpSource(entry, moduleId)
        }
        val boundId = entry.otpBindingId() ?: return null
        return entry(session, boundId)?.takeIf { it.hasOtp() }?.let { AutofillOtpSource(it, null) }
    }

    /**
     * HOTP 填充后推进计数器并持久化。计数递增始终以库内最新条目为准（原子提交），
     * 传入的 entry 仅是定位 id 的线索，避免基于过期快照重复/跳号。
     * mutate 快路径：transform 内从最新计数 +1，天然无竞态。
     */
    fun advanceOtpCounter(session: AutofillVaultSession, entry: Entry): VaultWriteResult {
        return advanceOtpCounter(session, AutofillOtpSource(entry, null))
    }

    fun advanceOtpCounter(session: AutofillVaultSession, source: AutofillOtpSource): VaultWriteResult {
        val entry = source.entry
        return saveFast(session, entry) { current ->
            val latest = current.entries.firstOrNull { it.id == entry.id }
                ?: throw MutationAbort(VaultWriteResult.Missing)
            if (latest.deletedAt != null) throw MutationAbort(VaultWriteResult.Stale)
            val changed = latest.withIncrementedOtpCounter(source.moduleId).copy(updatedAt = clock())
            current.copy(entries = current.entries.map { if (it.id == entry.id) changed else it })
        }
    }

    fun credential(session: AutofillVaultSession, entryId: String, expectedUpdatedAt: Double): Entry? {
        val query = session.querySession
        val entry = query.readEntry(entryId) ?: return null
        return entry.takeIf {
            it.updatedAt == expectedUpdatedAt && it.deletedAt == null &&
                isFillableLogin(session, it)
        }
    }

    fun resolveAutofillValues(session: AutofillVaultSession, entry: Entry): AutofillSnapshot {
        val linkedEntries = entry.autofillLinks().mapNotNull { link ->
            session.querySession.readEntry(link.sourceEntryId)
        }
        return AutofillSourceResolver.resolve(entry, listOf(entry) + linkedEntries, clock().toLong())
    }

    /** Rechecked at explicit selection and release, including entries discovered through manual search. */
    fun allowedForExplicitFill(session: AutofillVaultSession, entry: Entry, origin: TargetOrigin): Boolean =
        !isOriginExcluded(origin, session) && isFillableLogin(session, entry) && !hasKnownSignerMismatch(entry, origin)

    private fun isFillableLogin(session: AutofillVaultSession, entry: Entry): Boolean =
        entry.deletedAt == null && entry.secretType == SecretType.LOGIN &&
            resolveAutofillValues(session, entry).values.values.any { it.value.isNotEmpty() && it.role != AutofillRole.NONE }

    /** Persist explicit user approval without rewriting module passwords or linked field mappings. */
    fun rememberOriginBinding(session: AutofillVaultSession, entryId: String, origin: TargetOrigin): VaultWriteResult {
        val existing = entry(session, entryId) ?: return VaultWriteResult.Missing
        if (!isFillableLogin(session, existing)) return VaultWriteResult.Missing
        if (hasKnownSignerMismatch(existing, origin)) return VaultWriteResult.Failure(AutofillErrorCode.UNKNOWN)
        val changed = existing.copy(fields = AutofillOriginMetadata.addBinding(existing.fields, origin), updatedAt = clock())
        return saveFast(session, changed) { current ->
            val latest = current.entries.firstOrNull { it.id == entryId } ?: throw MutationAbort(VaultWriteResult.Missing)
            if (latest.deletedAt != null || latest.updatedAt != existing.updatedAt) throw MutationAbort(VaultWriteResult.Stale)
            current.copy(entries = current.entries.map { if (it.id == entryId) changed else it })
        }
    }

    fun forgetOriginPreferences(session: AutofillVaultSession, entryId: String, origin: TargetOrigin): VaultWriteResult {
        val existing = entry(session, entryId) ?: return VaultWriteResult.Missing
        if (hasKnownSignerMismatch(existing, origin)) return VaultWriteResult.Failure(AutofillErrorCode.UNKNOWN)
        val fields = AutofillFieldMappingMetadata.remove(AutofillOriginMetadata.removeBinding(existing.fields, origin), origin)
        val changed = existing.copy(fields = fields, updatedAt = clock())
        return saveFast(session, changed) { current ->
            val latest = current.entries.firstOrNull { it.id == entryId } ?: throw MutationAbort(VaultWriteResult.Missing)
            if (latest.deletedAt != null || latest.updatedAt != existing.updatedAt) throw MutationAbort(VaultWriteResult.Stale)
            current.copy(entries = current.entries.map { if (it.id == entryId) changed else it })
        }
    }

    private fun hasKnownSignerMismatch(entry: Entry, origin: TargetOrigin): Boolean {
        if (origin !is TargetOrigin.AndroidPackage) return false
        if (origin.signingCertificateSha256.isEmpty()) return true
        val identities = AutofillOriginMetadata.androidIdentities(entry).filter { it.packageName == origin.packageName }
        return identities.isNotEmpty() && identities.none {
            it.signingCertificateSha256.intersect(origin.signingCertificateSha256).isNotEmpty()
        }
    }

    fun fieldMappings(session: AutofillVaultSession, entryId: String, origin: TargetOrigin): Map<String, String> =
        entry(session, entryId)?.let { AutofillFieldMappingMetadata.mappings(it.fields, origin) }.orEmpty()

    fun rememberFieldMapping(
        session: AutofillVaultSession, entryId: String, origin: TargetOrigin, fieldKey: String, role: String,
    ): VaultWriteResult {
        val existing = entry(session, entryId) ?: return VaultWriteResult.Missing
        if (!isFillableLogin(session, existing)) return VaultWriteResult.Missing
        if (hasKnownSignerMismatch(existing, origin)) return VaultWriteResult.Failure(AutofillErrorCode.UNKNOWN)
        val updatedFields = runCatching { AutofillFieldMappingMetadata.add(existing.fields, origin, fieldKey, role) }
            .getOrElse { return VaultWriteResult.Failure(AutofillErrorCode.UNKNOWN) }
        if (updatedFields == existing.fields) return VaultWriteResult.Failure(AutofillErrorCode.UNKNOWN)
        val changed = existing.copy(fields = updatedFields, updatedAt = clock())
        return saveFast(session, changed) { current ->
            val latest = current.entries.firstOrNull { it.id == entryId } ?: throw MutationAbort(VaultWriteResult.Missing)
            if (latest.deletedAt != null || latest.updatedAt != existing.updatedAt) throw MutationAbort(VaultWriteResult.Stale)
            current.copy(entries = current.entries.map { if (it.id == entryId) changed else it })
        }
    }

    fun createLogin(
        session: AutofillVaultSession,
        origin: TargetOrigin,
        username: String,
        password: String,
    ): VaultWriteResult {
        val now = clock()
        val entry = Entry(
            id = idFactory(), title = origin.displayName(), username = username, password = password,
            url = origin.binding(), targetApp = (origin as? TargetOrigin.AndroidPackage)?.packageName.orEmpty(),
            createdAt = now, updatedAt = now, secretType = SecretType.LOGIN,
            fields = AutofillOriginMetadata.addBinding(emptyMap(), origin),
        )
        return saveFast(session, entry) { current ->
            if (current.entries.any { it.id == entry.id } || current.trash.any { it.id == entry.id }) {
                throw MutationAbort(VaultWriteResult.Stale)
            }
            current.copy(entries = current.entries + entry)
        }
    }

    fun updateLogin(
        session: AutofillVaultSession,
        entryId: String,
        expectedUpdatedAt: Double,
        username: String,
        password: String,
        origin: TargetOrigin? = null,
    ): VaultWriteResult {
        val existing = entry(session, entryId) ?: return VaultWriteResult.Missing
        if (existing.deletedAt != null || existing.secretType != SecretType.LOGIN || existing.updatedAt != expectedUpdatedAt) {
            return VaultWriteResult.Stale
        }
        val changed = existing.copy(
            username = username,
            password = password,
            targetApp = (origin as? TargetOrigin.AndroidPackage)?.packageName ?: existing.targetApp,
            updatedAt = clock(),
            fields = if (origin == null) existing.fields else AutofillOriginMetadata.addBinding(existing.fields, origin),
        )
        return saveFast(session, changed) { current ->
            val latest = current.entries.firstOrNull { it.id == entryId }
                ?: throw MutationAbort(VaultWriteResult.Missing)
            if (latest.deletedAt != null || latest.secretType != SecretType.LOGIN ||
                latest.updatedAt != expectedUpdatedAt
            ) throw MutationAbort(VaultWriteResult.Stale)
            current.copy(entries = current.entries.map { if (it.id == entryId) changed else it })
        }
    }

    fun upgradeLegacyAndroidBinding(
        session: AutofillVaultSession,
        entryId: String,
        origin: TargetOrigin.AndroidPackage,
    ): VaultWriteResult {
        val existing = entry(session, entryId) ?: return VaultWriteResult.Missing
        if (existing.deletedAt != null || existing.secretType != SecretType.LOGIN || existing.password.isEmpty()) {
            return VaultWriteResult.Missing
        }
        if (OriginMatcher.matchLevel(origin, existing) != OriginMatchLevel.NONE) {
            return VaultWriteResult.Success(existing)
        }
        if (origin.signingCertificateSha256.isEmpty() ||
            !OriginMatcher.hasLegacyPackageBinding(existing, origin.packageName)
        ) {
            return VaultWriteResult.Failure(AutofillErrorCode.UNKNOWN)
        }
        return updateLogin(
            session = session,
            entryId = existing.id,
            expectedUpdatedAt = existing.updatedAt,
            username = existing.username,
            password = existing.password,
            origin = origin,
        )
    }

    fun authenticateWithDek(vaultName: String, dek: ByteArray): VaultAuthResult =
        authenticateWithDeviceKey(vaultName, dek, expectedBinding = null)

    fun authenticateWithDeviceKey(
        vaultName: String,
        deviceKey: ByteArray,
        expectedBinding: VaultKeyIdentity?,
    ): VaultAuthResult {
        return try {
            if (!dataSource.exists(vaultName)) return VaultAuthResult.MissingVault
            val indexKey = deviceKey.copyOf()
            val query = try {
                dataSource.openQueryWithDeviceKey(vaultName, indexKey)
            } finally {
                indexKey.fill(0)
            }
            if (expectedBinding != null) {
                val identity = query.identity
                val actual = identity?.let {
                    VaultKeyIdentity(it.vaultId, it.keyRevision, it.signingPublicKey)
                }
                if (actual == null || !expectedBinding.matches(actual)) {
                    query.close()
                    throw SecurityException("设备解锁信封与当前 PMVE 身份不匹配")
                }
            }
            val session = AutofillVaultSession(
                vaultName,
                deviceKey = deviceKey.copyOf(),
                querySession = query,
                expectedSequence = query.identity?.sequence,
            )
            VaultAuthResult.Success(session)
        } catch (_: SecurityException) {
            VaultAuthResult.Failure(AutofillErrorCode.DEVICE_BINDING_MISMATCH)
        } catch (_: Exception) {
            VaultAuthResult.Failure(AutofillErrorCode.VAULT_OPEN_FAILED)
        } finally {
            deviceKey.fill(0)
        }
    }

    fun allocatePasskeyLocation(): PasskeyRecordLocation = PasskeyRecordLocation(
        entryId = idFactory(),
        moduleId = UUID.randomUUID().toString().replace("-", ""),
    )

    fun createPasskey(
        session: AutofillVaultSession,
        record: PasskeyRecord,
        location: PasskeyRecordLocation = allocatePasskeyLocation(),
    ): VaultWriteResult {
        val now = clock()
        val base = Entry(
            id = location.entryId, title = record.rpName.ifEmpty { record.rpId }, username = record.userName,
            url = "https://${record.rpId}", createdAt = now, updatedAt = now, secretType = SecretType.PASSKEY,
        )
        val local = PasskeyRepository.add(VaultPayload(), base, record, location.moduleId)
        if (local !is PasskeyMutationResult.Success) {
            return VaultWriteResult.Failure(AutofillErrorCode.PASSKEY_INVALID)
        }
        if (passkeysForRpId(session, record.rpId).any {
                it.record.credentialId == record.credentialId
            }
        ) return VaultWriteResult.Stale
        return saveFast(session, local.entry) { current ->
            when (val result = PasskeyRepository.add(current, base, record, location.moduleId)) {
                is PasskeyMutationResult.Success -> result.payload
                PasskeyMutationResult.Duplicate, PasskeyMutationResult.Stale ->
                    throw MutationAbort(VaultWriteResult.Stale)
                PasskeyMutationResult.Missing -> throw MutationAbort(VaultWriteResult.Missing)
                PasskeyMutationResult.Invalid -> throw MutationAbort(VaultWriteResult.Failure(AutofillErrorCode.PASSKEY_INVALID))
            }
        }
    }

    fun updatePasskey(
        session: AutofillVaultSession,
        entryId: String,
        moduleId: String,
        credentialId: String,
        record: PasskeyRecord,
    ): VaultWriteResult {
        val existing = entry(session, entryId) ?: return VaultWriteResult.Missing
        val local = PasskeyRepository.update(
            VaultPayload(entries = listOf(existing)), entryId, moduleId, credentialId, record, clock(),
        )
        if (local !is PasskeyMutationResult.Success) return mutationResult(local)
        return saveFast(session, local.entry) { current ->
            when (val result = PasskeyRepository.update(
                current, entryId, moduleId, credentialId, record, local.entry.updatedAt,
            )) {
                is PasskeyMutationResult.Success -> result.payload
                else -> throw MutationAbort(mutationResult(result))
            }
        }
    }

    fun entry(session: AutofillVaultSession, entryId: String): Entry? =
        session.querySession.readEntry(entryId)?.takeIf { value -> value.deletedAt == null }

    fun findPasskeys(
        session: AutofillVaultSession,
        request: GetPasskeyRequest,
        availability: (StoredPasskey) -> PasskeyAvailability = { PasskeyAvailability.AVAILABLE },
    ): List<StoredPasskey> {
        val query = session.querySession
        val ids = query.queryRpId(request.rpId).orEmpty()
        val candidates = ids.distinct().mapNotNull(query::readEntry)
        return PasskeyRepository.find(VaultPayload(entries = candidates), request, availability)
    }

    fun hasExcludedPasskey(session: AutofillVaultSession, request: CreatePasskeyRequest): Boolean {
        val query = session.querySession
        val ids = query.queryRpId(request.rpId).orEmpty()
        val candidates = ids.distinct().mapNotNull(query::readEntry)
        return PasskeyRepository.hasExcludedCredential(VaultPayload(entries = candidates), request)
    }

    private fun passkeysForRpId(session: AutofillVaultSession, rpId: String): List<StoredPasskey> {
        val query = session.querySession
        val ids = query.queryRpId(rpId).orEmpty()
        val candidates = ids.distinct().mapNotNull(query::readEntry)
        return PasskeyRepository.all(VaultPayload(entries = candidates)).filter { it.record.rpId == rpId }
    }

    private fun saveFast(
        session: AutofillVaultSession,
        entry: Entry,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultWriteResult {
        val expected = session.expectedSequence ?: return VaultWriteResult.Failure(AutofillErrorCode.MUTATION_BASELINE_MISSING)
        return try {
            val identity = session.passwordString()?.let { password ->
                dataSource.mutatePmvEWithPassword(session.vaultName, password, expected, transform)
            } ?: session.deviceKeyBytes()?.let { deviceKey ->
                try {
                    dataSource.mutatePmvEWithDeviceKey(session.vaultName, deviceKey, expected, transform)
                } finally {
                    deviceKey.fill(0)
                }
            } ?: return VaultWriteResult.Failure(AutofillErrorCode.SESSION_KEY_INVALID)
            session.expectedSequence = identity.sequence
            VaultWriteResult.Success(entry)
        } catch (abort: MutationAbort) {
            abort.result
        } catch (_: VaultStaleMutationException) {
            VaultWriteResult.Stale
        } catch (_: Exception) {
            VaultWriteResult.Failure(AutofillErrorCode.SAVE_FAILED)
        }
    }

    private fun mutationResult(result: PasskeyMutationResult): VaultWriteResult = when (result) {
        is PasskeyMutationResult.Success -> VaultWriteResult.Success(result.entry)
        PasskeyMutationResult.Duplicate, PasskeyMutationResult.Stale -> VaultWriteResult.Stale
        PasskeyMutationResult.Missing -> VaultWriteResult.Missing
        PasskeyMutationResult.Invalid -> VaultWriteResult.Failure(AutofillErrorCode.PASSKEY_INVALID)
    }

    private class MutationAbort(val result: VaultWriteResult) : RuntimeException(null, null, false, false)

    private fun TargetOrigin.binding(): String = when (this) {
        is TargetOrigin.AndroidPackage -> packageName
        is TargetOrigin.Web -> "https://$host"
    }

    private fun TargetOrigin.displayName(): String = when (this) {
        is TargetOrigin.AndroidPackage -> appNameResolver(packageName) ?: packageName
        is TargetOrigin.Web -> host
    }
}

internal fun cacheAuthenticatedAutofillExclusions(
    query: VaultQuerySession,
    vaultName: String,
    readCache: (String) -> AutofillExclusions,
    writeCache: (String, AutofillExclusions) -> Unit,
): VaultQuerySession {
    try {
        query.autofillExclusions()?.let { authenticated ->
            writeCache(vaultName, authenticated.merge(readCache(vaultName)))
        }
        return query
    } catch (error: Throwable) {
        runCatching { query.close() }
        throw error
    }
}

class AndroidAutofillVaultDataSource(context: Context) : AutofillVaultDataSource {
    private val appContext = context.applicationContext
    private val registry = VaultRegistry(appContext)
    override fun listVaults(): List<String> = registry.list()
    override fun exists(vaultName: String): Boolean = registry.exists(vaultName)
    override fun openQueryWithPassword(vaultName: String, password: String): VaultQuerySession {
        val passwordUtf8 = password.encodeToByteArray()
        return try {
            cacheQueryRules(vaultName, VaultRepository(appContext, registry, vaultName).openQueryWithPassword(passwordUtf8))
        } finally {
            passwordUtf8.fill(0)
        }
    }
    override fun openQueryWithDeviceKey(vaultName: String, deviceKey: ByteArray): VaultQuerySession =
        cacheQueryRules(vaultName, VaultRepository(appContext, registry, vaultName).openQueryWithDeviceKey(deviceKey))

    private fun cacheQueryRules(vaultName: String, query: VaultQuerySession): VaultQuerySession =
        synchronized(AutofillExcludePref) {
            cacheAuthenticatedAutofillExclusions(query, vaultName,
                readCache = { AutofillExcludePref.snapshot(appContext, it) },
                writeCache = { name, rules -> AutofillExcludePref.replace(appContext, rules, name) })
        }
    override fun mutatePmvEWithPassword(
        vaultName: String,
        password: String,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity {
        val passwordUtf8 = password.encodeToByteArray()
        return try {
            VaultRepository(appContext, registry, vaultName)
                .mutatePmvEWithPassword(passwordUtf8, expectedSequence, transform)
        } finally {
            passwordUtf8.fill(0)
        }
    }
    override fun mutatePmvEWithDeviceKey(
        vaultName: String,
        deviceKey: ByteArray,
        expectedSequence: Long,
        transform: (VaultPayload) -> VaultPayload,
    ): VaultIdentity = VaultRepository(appContext, registry, vaultName)
        .mutatePmvEWithRootKey(deviceKey, expectedSequence, transform)
}

class AndroidAutofillAttemptPolicy(context: Context) : AutofillAttemptPolicy {
    private val appContext = context.applicationContext
    override fun coolingRemainingMs(): Long = LockoutPref.coolingRemainingMs(appContext)
    override fun recordFailure(): AttemptFailure {
        val result = LockoutPref.recordFailure(appContext, FailureSource.SYSTEM)
        return AttemptFailure(
            remainingAttempts = LockoutPref.remainingAttempts(appContext),
            retryDelayMs = result.retryDelayMs,
            cooldownMs = result.cooldownMs,
        )
    }
    override fun clear() = LockoutPref.clear(appContext)
}
