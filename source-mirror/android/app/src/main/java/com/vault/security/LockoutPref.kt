package com.vault.security
import android.content.Context

/**
 * 主密码失败的来源。三条入口共享同一份冷却记录，因此必须记录是谁记下的这一笔：
 * 只有 [SENSITIVE_VERIFY] 自己记满 5 次才自动锁库，避免自动填充/通行密钥在弹窗里
 * 输错密码把用户正在使用的主会话锁掉。
 */
enum class FailureSource {
    /** 解锁页直接输主密码。 */
    UNLOCK,
    /** 已解锁会话里的敏感操作二次验证。 */
    SENSITIVE_VERIFY,
    /** 自动填充 / 通行密钥的系统弹窗。 */
    SYSTEM,
}

/**
 * 主密码解锁失败次数与冷却时间的持久化。规则参考桌面端 dialogs.LockoutMixin：
 *  - MAX_ATTEMPTS = 5：失败计数达上限进入冷却
 *  - LOCKOUT_SECONDS = 30：冷却基础时长，按 rounds 倍数累加（第二轮 60s，第三轮 90s…）
 *  - 失败一次后下一次重试的延迟（指数后退）= 2^(MAX_ATTEMPTS - remaining) * 250ms
 *  - 状态写入 SharedPreferences，应用重启后仍生效
 */
object LockoutPref {
    const val MAX_ATTEMPTS = 5
    const val LOCKOUT_SECONDS = 30

    private const val PREF = "pmv_lockout"
    private const val KEY_FAIL = "fail_count"
    private const val KEY_UNTIL = "lockout_until_ms"
    private const val KEY_ROUNDS = "rounds"
    private const val KEY_NEXT_ATTEMPT = "next_attempt_at_ms"
    private const val KEY_SOURCE = "last_failure_source"

    private fun prefs(ctx: Context) =
        SecurePreferences.get(ctx.applicationContext, vaultPrefName(PREF, CurrentVaultKey.current()))

    fun failCount(ctx: Context): Int = prefs(ctx).getInt(KEY_FAIL, 0).coerceAtLeast(0)
    fun lockoutUntilMs(ctx: Context): Long = prefs(ctx).getLong(KEY_UNTIL, 0L)
    fun rounds(ctx: Context): Int = prefs(ctx).getInt(KEY_ROUNDS, 0).coerceAtLeast(0)

    /** 最近一次失败来自哪条入口；无记录（旧版本数据）时按 [FailureSource.UNLOCK] 处理。 */
    fun lastFailureSource(ctx: Context): FailureSource =
        FailureSource.entries.getOrElse(prefs(ctx).getInt(KEY_SOURCE, FailureSource.UNLOCK.ordinal)) {
            FailureSource.UNLOCK
        }

    /** 是否仍在冷却（lockoutUntil 在未来）。 */
    fun isCoolingDown(ctx: Context): Boolean = coolingRemainingMs(ctx) > 0L
    fun coolingRemainingMs(ctx: Context): Long =
        maxOf(lockoutUntilMs(ctx), prefs(ctx).getLong(KEY_NEXT_ATTEMPT, 0L))
            .minus(System.currentTimeMillis()).coerceAtLeast(0)

    /** 记一次失败，返回新的失败计数与建议延迟（毫秒）。达到上限时进入冷却并清零计数。 */
    data class FailResult(val newFailCount: Int, val retryDelayMs: Long, val enteredCooldown: Boolean, val cooldownMs: Long)

    @Synchronized
    fun recordFailure(ctx: Context, source: FailureSource): FailResult {
        val p = prefs(ctx)
        val count = (failCount(ctx) + 1).coerceAtMost(MAX_ATTEMPTS)
        val remaining = MAX_ATTEMPTS - count
        return if (remaining > 0) {
            // 指数后退：第一次 0.25s，第二次 0.5s，第三次 1s，第四次 2s
            val delay = (1L shl (MAX_ATTEMPTS - remaining - 1)) * 250L
            p.edit().putInt(KEY_FAIL, count)
                .putInt(KEY_SOURCE, source.ordinal)
                .putLong(KEY_NEXT_ATTEMPT, System.currentTimeMillis() + delay).commit()
            FailResult(count, delay, enteredCooldown = false, cooldownMs = 0L)
        } else {
            val newRounds = rounds(ctx) + 1
            val cooldownMs = LOCKOUT_SECONDS * 1000L * newRounds
            val until = System.currentTimeMillis() + cooldownMs
            p.edit()
                .putInt(KEY_FAIL, 0)
                .putInt(KEY_ROUNDS, newRounds)
                .putInt(KEY_SOURCE, source.ordinal)
                .putLong(KEY_UNTIL, until)
                .putLong(KEY_NEXT_ATTEMPT, 0L)
                .commit()
            FailResult(0, 0L, enteredCooldown = true, cooldownMs = cooldownMs)
        }
    }

    /** 向上取整，最后不足一秒仍处于冷却，不能提前开放重试。 */
    fun remainingSeconds(remainingMs: Long): Int =
        ((remainingMs.coerceAtLeast(0L) / 1000L) + if (remainingMs > 0L && remainingMs % 1000L != 0L) 1L else 0L)
            .coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

    /** 解锁成功时清空全部状态。 */
    fun clear(ctx: Context) {
        prefs(ctx).edit()
            .putInt(KEY_FAIL, 0)
            .putInt(KEY_ROUNDS, 0)
            .putLong(KEY_UNTIL, 0L)
            .putLong(KEY_NEXT_ATTEMPT, 0L)
            .remove(KEY_SOURCE)
            .commit()
    }

    fun remainingAttempts(ctx: Context): Int =
        (MAX_ATTEMPTS - failCount(ctx)).coerceAtLeast(0)
}
