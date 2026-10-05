package com.vault.autofill

import com.vault.model.Entry
import com.vault.model.otpBindingId
import com.vault.model.otpDisplaySnapshot

/**
 * 动态码自动填充的码值计算：在填充时刻取最新码值，绝不使用预先缓存的旧值。
 * TOTP 剩余有效期 <= [MIN_FILL_REMAINING] 秒时不填充，等待翻窗后重算，
 * 避免把即将过期、很可能被服务端拒绝的码填进表单。
 */
object OtpAutofill {
    /** 剩余有效期阈值（秒）：低于该值不填充，等待下一时间窗。 */
    const val MIN_FILL_REMAINING = 3

    /**
     * @param now 当前 Unix 秒，可注入以便测试
     * @param sleep 等待翻窗的实现，可注入以便测试
     * @return 可填充的动态码；无可用码（无模块、窗口过短）时返回 null
     */
    suspend fun computeFillCode(
        entry: Entry,
        now: () -> Long = { System.currentTimeMillis() / 1000 },
        sleep: suspend (Long) -> Unit,
    ): String? {
        val first = entry.otpDisplaySnapshot(now()) ?: return null
        if (first.type == "hotp") return first.code
        if (first.period <= MIN_FILL_REMAINING) return null
        if (first.remaining > MIN_FILL_REMAINING) return first.code
        sleep((first.remaining + 1) * 1000L)
        val fresh = entry.otpDisplaySnapshot(now()) ?: return null
        return fresh.code.takeIf { fresh.type == "totp" && fresh.remaining > MIN_FILL_REMAINING }
    }

    /**
     * 合并登录条目与独立动态码候选并去重：
     * - 已被登录条目引用的独立动态码（绑定）不再单独展示，由登录行承载。
     * - 登录条目本身只出现一次。
     */
    fun mergeCandidates(loginEntries: List<Entry>, otpEntries: List<Entry>): List<Entry> {
        val loginIds = loginEntries.mapTo(HashSet()) { it.id }
        val boundIds = loginEntries.mapNotNullTo(HashSet()) { it.otpBindingId() }
        return loginEntries + otpEntries.filter { it.id !in loginIds && it.id !in boundIds }
    }

    /**
     * 计算每个 OTP 输入框应填入的值，按表单结构分发：
     * - 无码：所有框留空；
     * - 框数 == 码长：逐位填入（smsOTPCode{1..N}）；
     * - 框数 × 2 == 码长：每框 2 位（如 6 位码 + 3 框的 Gmail 式布局）；
     * - 其余歧义布局：整码只填入第一个 OTP 框，避免写坏数据。
     */
    fun otpFillValues(code: String?, fieldCount: Int): List<String> {
        if (code.isNullOrEmpty()) return List(fieldCount) { "" }
        if (fieldCount > 1 && code.length == fieldCount) return code.map { it.toString() }
        if (fieldCount > 1 && code.length == fieldCount * 2) {
            return List(fieldCount) { i -> code.substring(i * 2, i * 2 + 2) }
        }
        return List(fieldCount) { i -> if (i == 0) code else "" }
    }
}
