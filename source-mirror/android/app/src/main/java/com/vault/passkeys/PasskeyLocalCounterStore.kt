package com.vault.passkeys

/**
 * 设备本地的 Passkey 签名计数器存储。
 *
 * 仅用于本设备高安全性（DEVICE_BOUND）Passkey：其私钥不可导出、凭证不随保险库同步，
 * 因此单调计数器必须保存在设备本地（而非 PMV 容器），才能对 RP 提供有意义的克隆/重放检测。
 * 同步型（SYNCABLE）Passkey 因密钥合法存在于多台设备，计数器无法跨端单调，继续使用常量 0（synced_zero）。
 *
 * 计数值只写入 [android.webkit.WebAuthn] 的 authenticatorData，绝不回写保险库内的
 * [com.vault.model.PasskeyRecord.signCount]（其解析强制要求为 0）。
 */
interface PasskeyLocalCounterStore {
    /** 返回该凭证下一次（自增后）的签名计数，并在本地持久化。 */
    fun increment(identity: String): Long

    /** 读取当前本地计数（主要用于诊断）。 */
    fun peek(identity: String): Long

    companion object {
        /** 无本地存储实现：恒返回 0。用于单元测试与未初始化场景。 */
        val NoOp = object : PasskeyLocalCounterStore {
            override fun increment(identity: String) = 0L
            override fun peek(identity: String) = 0L
        }
    }
}
