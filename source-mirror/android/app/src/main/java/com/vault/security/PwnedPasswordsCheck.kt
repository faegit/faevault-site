package com.vault.security

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/**
 * Pwned Passwords API（k‑anonymity 模型）在线泄露查询。
 *
 * 将密码的 SHA‑1 哈希前 5 位作为前缀发给服务器，服务器返回所有以该前缀
 * 开头的哈希后缀及出现次数，本地比对后缀。全程不暴露完整哈希，保护隐私。
 */
object PwnedPasswordsCheck {

    private const val API_URL = "https://api.pwnedpasswords.com/range/"

    /** SHA‑1 十六进制大写字符串。 */
    private fun sha1Hex(input: String): String {
        val digest = MessageDigest.getInstance("SHA-1")
        val bytes = digest.digest(input.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02X".format(it) }
    }

    /**
     * 查询密码在已知泄露中出现的次数。
     * @return 出现次数，0 表示未发现泄露；网络异常时返回 -1。
     */
    suspend fun breachCount(password: String): Int {
        if (password.isEmpty()) return 0
        val hash = sha1Hex(password)
        val prefix = hash.substring(0, 5)
        val suffix = hash.substring(5)

        return try {
            val url = URL("$API_URL$prefix")
            val conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = 8000
            conn.readTimeout = 8000
            conn.requestMethod = "GET"
            conn.setRequestProperty("User-Agent", "FAEVault/1.0")
            conn.setRequestProperty("Add-Padding", "true") // 防止基于响应长度的侧信道

            val responseCode = conn.responseCode
            if (responseCode != HttpURLConnection.HTTP_OK) return -1

            val reader = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8))
            val lines = reader.readLines()
            reader.close()
            conn.disconnect()

            for (line in lines) {
                // 每行格式：<SUFFIX>:<COUNT>
                val parts = line.split(":")
                if (parts.size == 2 && parts[0] == suffix) {
                    return parts[1].trim().toIntOrNull() ?: 0
                }
            }
            0 // 未匹配
        } catch (_: Exception) {
            -1 // 网络不可达 / 超时 / DNS 失败等
        }
    }
}
