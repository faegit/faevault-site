package com.vault.security

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * 离线弱密码 / 泄露密码检测。
 *
 * 与"密码泄露查询服务"不同（那需要联网，且需把哈希前缀发给第三方），本检测完全在本机
 * 完成：把 assets/common_passwords.txt 中收录的高频泄露 / 弱密码全部预加载为 HashSet，
 * 用户密码与之精确匹配则视为"已泄露"。
 *
 * 优点：零网络、与隐私政策一致。
 * 局限：不会发现"只对当前用户的某次泄露"，仅检测全网公认弱密码 / 字典中已收录的密码。
 */
object LeakedPasswordCheck {

    @Volatile
    private var cache: Set<String>? = null

    fun clearMemoryCache() {
        synchronized(this) { cache = null }
    }

    /** 首次调用时同步读入 assets，之后命中缓存。线程安全。 */
    fun isLeaked(context: Context, password: String): Boolean {
        if (password.isEmpty()) return false
        return loadList(context).contains(password)
    }

    private fun loadList(context: Context): Set<String> {
        cache?.let { return it }
        synchronized(this) {
            cache?.let { return it }
            val set = HashSet<String>(1024)
            runCatching {
                context.applicationContext.assets.open("common_passwords.txt").use { input ->
                    BufferedReader(InputStreamReader(input, Charsets.UTF_8)).useLines { lines ->
                        lines.forEach { raw ->
                            val s = raw.trim()
                            if (s.isNotEmpty() && !s.startsWith("#")) set.add(s)
                        }
                    }
                }
            }
            cache = set
            return set
        }
    }
}
