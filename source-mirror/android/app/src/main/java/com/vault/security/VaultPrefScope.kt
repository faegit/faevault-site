package com.vault.security

import android.content.Context
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * 账户（保险库）隔离基础设施。
 *
 * 所有原本「全局单例、固定 key」的偏好，现在都按当前保险库身份 [currentVaultKey] 隔离存储，
 * 避免账户 A 的设置覆盖/泄漏到账户 B。
 */

/** 把保险库标识映射成稳定的短后缀，挂到偏好文件名或 key 上做命名空间隔离。 */
fun vaultPrefName(base: String, vaultKey: String): String {
    val suffix = MessageDigest.getInstance("SHA-256")
        .digest(VaultNameScope.resolve(vaultKey).toByteArray())
        .take(12)
        .joinToString("") { "%02x".format(it) }
    return "${base}_$suffix"
}

/** Keep the original encrypted preference namespace and Keystore alias across a vault rename. */
object VaultNameScope {
    private const val PREFIX = "vault_scope_"
    private val aliases = ConcurrentHashMap<String, String>()

    fun load(context: Context) {
        val values = SecurePreferences.get(context, "pmv_registry").all
        values.forEach { (key, value) ->
            if (key.startsWith(PREFIX) && value is String) aliases[key.removePrefix(PREFIX)] = value
        }
    }

    fun resolve(name: String): String = aliases[name] ?: name

    fun resolve(context: Context, name: String): String {
        val persisted = SecurePreferences.get(context, "pmv_registry").getString(PREFIX + name, null)
        if (persisted != null) aliases[name] = persisted
        return persisted ?: resolve(name)
    }

    fun prepareRename(context: Context, old: String, new: String): Boolean {
        val scope = resolve(context, old)
        val saved = SecurePreferences.get(context, "pmv_registry").edit()
            .putString(PREFIX + new, scope).commit()
        if (saved) aliases[new] = scope
        return saved
    }

    fun releaseName(context: Context, name: String): Boolean {
        val fresh = UUID.randomUUID().toString()
        val saved = SecurePreferences.get(context, "pmv_registry").edit()
            .putString(PREFIX + name, fresh).commit()
        if (saved) aliases[name] = fresh
        return saved
    }
}

/**
 * 进程内「当前保险库」标识。由 [com.vault.ui.VaultViewModel] 在切换/解锁账户时写入，
 * 供没有 ViewModel 上下文的全局消费方（窗口安全、空闲锁、自动隐藏、剪贴板 TTL 等）读取。
 * 在尚未打开任何保险库时回退到 [DEFAULT]，保证读取不会崩溃。
 */
object CurrentVaultKey {
    private val holder = java.util.concurrent.atomic.AtomicReference<String?>(null)

    const val DEFAULT = "default"

    fun install(key: String) {
        if (key.isNotBlank()) holder.set(key)
    }

    fun current(): String = holder.get() ?: DEFAULT
}
