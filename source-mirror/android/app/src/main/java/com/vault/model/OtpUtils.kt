package com.vault.model

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * TOTP (RFC 6238) / HOTP (RFC 4226) 纯 Kotlin 实现。
 * 无额外依赖，仅使用 JDK 内置 crypto API。
 */
object OtpUtils {
    private val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray()
    private val BASE32_LOOKUP = IntArray(256) { -1 }.also {
        BASE32_ALPHABET.forEachIndexed { idx, c -> it[c.code] = idx }
    }

    /**
     * Base32 解码（RFC 4648，忽略空白与 padding '='）。
     * 返回空数组表示解码失败。
     */
    fun base32Decode(input: String): ByteArray {
        val clean = input.trim().uppercase().filter { it != '=' && it.isLetterOrDigit() }
        if (clean.isEmpty()) return ByteArray(0)

        val bytes = ByteArray(clean.length * 5 / 8)
        var bitBuffer = 0
        var bitCount = 0
        var outIndex = 0
        for (c in clean) {
            val v = if (c <= 'Z') BASE32_LOOKUP[c.code] else -1
            if (v < 0) return ByteArray(0)
            bitBuffer = (bitBuffer shl 5) or v
            bitCount += 5
            if (bitCount >= 8) {
                bitCount -= 8
                bytes[outIndex++] = ((bitBuffer shr bitCount) and 0xFF).toByte()
            }
        }
        return bytes
    }

    private fun hmacSha(algorithm: String, key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return mac.doFinal(data)
    }

    /**
     * 生成 HOTP (RFC 4226)
     * @param secret Base32 编码的密钥
     * @param counter 计数器值
     * @param digits 位数 (6/7/8)
     * @param algo 算法: "HmacSHA1" / "HmacSHA256" / "HmacSHA512"
     */
    fun generateHOTP(
        secret: String,
        counter: Long,
        digits: Int = 6,
        algo: String = "HmacSHA1"
    ): String {
        val key = base32Decode(secret)
        if (key.isEmpty()) return "ERROR"
        val data = ByteBuffer.allocate(8).putLong(counter).array()
        val hash = hmacSha(algo, key, data)
        val offset = hash[hash.lastIndex].toInt() and 0x0F
        val part1 = (hash[offset].toInt() and 0x7F) shl 24
        val part2 = (hash[offset + 1].toInt() and 0xFF) shl 16
        val part3 = (hash[offset + 2].toInt() and 0xFF) shl 8
        val part4 = (hash[offset + 3].toInt() and 0xFF)
        val code = (part1 or part2 or part3 or part4) % (Math.pow(10.0, digits.toDouble())).toInt()
        return "%0${digits}d".format(code)
    }

    /**
     * 生成 TOTP (RFC 6238)
     * @param secret Base32 编码的密钥
     * @param counter 已计算好的 TOTP 计数器 (= 当前 Unix 秒 / period)
     * @param digits 位数 (6/7/8)
     * @param algo 算法: "HmacSHA1" / "HmacSHA256" / "HmacSHA512"
     */
    fun generateTOTP(
        secret: String,
        counter: Long,
        digits: Int = 6,
        algo: String = "HmacSHA1"
    ): String = generateHOTP(secret, counter, digits, algo)

    /**
     * 当前时间步的 TOTP 码
     */
    fun currentTOTP(
        secret: String,
        digits: Int = 6,
        algo: String = "HmacSHA1",
        period: Int = 30
    ): String {
        val now = System.currentTimeMillis() / 1000
        val counter = now / period
        return generateTOTP(secret, counter, digits, algo)
    }

    /**
     * 当前周期剩余秒数 (用于倒计时进度条)
     */
    fun remainingSeconds(period: Int = 30): Int {
        val now = System.currentTimeMillis() / 1000
        return period - (now % period).toInt()
    }

    /**
     * 当前周期进度 0.0~1.0 (用于倒计时进度条)
     */
    fun progress(period: Int = 30): Float {
        val now = System.currentTimeMillis() / 1000
        return (now % period).toFloat() / period
    }

    /**
     * 解析 otpauth:// URI
     * 支持 totp/hotp，返回 (type, secret, params map)
     * params 中会自动注入 path 中的 label（账户名），
     * 以及从 query 中读取的标准字段：algorithm, digits, period, issuer, counter
     */
    fun parseOtpAuthUri(uri: String): Triple<String?, String?, Map<String, String>>? {
        if (!uri.startsWith("otpauth://", ignoreCase = true)) return null
        try {
            val url = java.net.URI(uri)
            val type = (url.host ?: url.authority ?: "").lowercase() // "totp" / "hotp"
            if (type != "totp" && type != "hotp") return null

            // Label 可能在 path 第二段：otpauth://totp/LABEL 或 otpauth://totp/ISSUER:LABEL
            val rawPath = url.rawPath?.trimStart('/') ?: ""
            val pathLabel = if (rawPath.isNotEmpty()) {
                val raw = java.net.URLDecoder.decode(rawPath, StandardCharsets.UTF_8.name())
                // 去掉可选的 "ISSUER:" 前缀（含冒号）
                if (raw.contains(":")) raw.substringAfter(":") else raw
            } else null

            val query = url.rawQuery ?: return null
            val params = mutableMapOf<String, String>()
            for (pair in query.split("&")) {
                val parts = pair.split("=", limit = 2)
                if (parts.size == 2) {
                    val key = java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name()).lowercase()
                    params[key] = java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name())
                }
            }

            // 如果 query 中没有 label，从 path 中提取
            if (!params.containsKey("label") && pathLabel != null) {
                params["label"] = pathLabel
            }

            val secret = params["secret"]?.filterNot(Char::isWhitespace)?.uppercase()?.trimEnd('=')
            if (secret.isNullOrBlank() || secret.any { it !in BASE32_ALPHABET } || base32Decode(secret).isEmpty()) {
                return null
            }
            params["secret"] = secret

            val algorithm = params["algorithm"]?.uppercase() ?: "SHA1"
            if (algorithm !in setOf("SHA1", "SHA256", "SHA512")) return null
            params["algorithm"] = algorithm

            val digits = params["digits"]?.toIntOrNull() ?: 6
            if (digits !in 6..8) return null
            params["digits"] = digits.toString()

            if (type == "totp") {
                val period = params["period"]?.toIntOrNull() ?: 30
                if (period !in 1..300) return null
                params["period"] = period.toString()
                params.remove("counter")
            } else {
                val counter = params["counter"]?.toLongOrNull() ?: return null
                if (counter < 0) return null
                params["counter"] = counter.toString()
                params.remove("period")
            }
            return Triple(type, secret, params)
        } catch (_: Exception) {
            return null
        }
    }
}
