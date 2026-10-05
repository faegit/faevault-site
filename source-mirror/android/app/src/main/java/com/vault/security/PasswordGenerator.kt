package com.vault.security

import java.security.SecureRandom

/**
 * 强随机密码生成器。
 *  - 使用 SecureRandom（CSPRNG），不要用 java.util.Random
 *  - 至少包含每个被启用字符集的至少一个字符（避免"全数字"等弱密码）
 *  - "易读模式"剔除形近字符 0/O/1/l/I 等
 */
object PasswordGenerator {

    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGIT = "0123456789"
    private const val SYMBOL = "!@#$%^&*()-_=+[]{};:,.<>?/~"

    // 易读模式剔除的形近 / 易混字符
    private val AMBIGUOUS = setOf('0', 'O', 'o', '1', 'l', 'I', '|', '`', '\'', '"')

    data class Options(
        val length: Int = 16,
        val lower: Boolean = true,
        val upper: Boolean = true,
        val digit: Boolean = true,
        val symbol: Boolean = true,
        val avoidAmbiguous: Boolean = false,
    )

    fun generate(opts: Options): String {
        val pools = buildList {
            if (opts.lower) add(filtered(LOWER, opts.avoidAmbiguous))
            if (opts.upper) add(filtered(UPPER, opts.avoidAmbiguous))
            if (opts.digit) add(filtered(DIGIT, opts.avoidAmbiguous))
            if (opts.symbol) add(filtered(SYMBOL, opts.avoidAmbiguous))
        }.filter { it.isNotEmpty() }

        require(pools.isNotEmpty()) { "至少需启用一种字符集" }
        val length = opts.length.coerceIn(4, 128)

        val rng = SecureRandom()
        val out = CharArray(length)

        // 先从每个池子取一个字符，保证每类至少一个
        val taken = pools.map { it[rng.nextInt(it.length)] }.toMutableList()
        // 剩余位置从全集随机
        val combined = pools.joinToString("")
        while (taken.size < length) taken.add(combined[rng.nextInt(combined.length)])
        // Fisher–Yates 洗牌打乱顺序
        for (i in taken.indices.reversed()) {
            val j = rng.nextInt(i + 1)
            val tmp = taken[i]; taken[i] = taken[j]; taken[j] = tmp
        }
        for (i in 0 until length) out[i] = taken[i]
        return String(out)
    }

    private fun filtered(pool: String, avoidAmbiguous: Boolean): String =
        if (!avoidAmbiguous) pool else pool.filter { it !in AMBIGUOUS }
}
