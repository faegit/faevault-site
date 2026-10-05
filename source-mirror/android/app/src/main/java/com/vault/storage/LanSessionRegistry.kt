package com.vault.storage

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.security.MessageDigest

/**
 * 传输站的已配对会话表。
 *
 * 通道、设备授权和导出批准必须跟随会话令牌，不能放在服务端全局单槽中；否则后配对的
 * transfer/export 会覆盖仍在工作的 sync 会话，造成已经连接成功的通道随后随机 403。
 */
internal class LanSessionRegistry {
    class Session internal constructor(val token: String, val op: String) {
        @Volatile var authorizedDeviceId: UUID? = null

        /**
         * 认证通过时留存的对方身份信息，供传输站界面显示「对方设备」与连接时长。
         * 公钥取自授权记录（见 AuthorizationRegistry.activeAuthorization），不是客户端自报值。
         */
        @Volatile var authorizedPublicKey: ByteArray? = null
        @Volatile var remoteAddress: String? = null
        @Volatile var authenticatedAtMillis: Long = 0L

        val exportApproved = AtomicBoolean(false)
        val transferApproved = AtomicBoolean(false)
        @Volatile var pendingExportDevice: Pair<UUID, ByteArray>? = null
        @Volatile var pendingTransferDevice: Pair<UUID, ByteArray>? = null
        @Volatile var pendingSyncDevice: Pair<UUID, ByteArray>? = null
        @Volatile var pendingChallenge: ByteArray? = null

        fun clear() {
            pendingExportDevice?.second?.fill(0)
            pendingExportDevice = null
            pendingTransferDevice?.second?.fill(0)
            pendingTransferDevice = null
            pendingSyncDevice?.second?.fill(0)
            pendingSyncDevice = null
            pendingChallenge?.fill(0)
            pendingChallenge = null
            authorizedPublicKey?.fill(0)
            authorizedPublicKey = null
            remoteAddress = null
            authenticatedAtMillis = 0L
            authorizedDeviceId = null
            exportApproved.set(false)
            transferApproved.set(false)
        }
    }

    private val sessions = ConcurrentHashMap<String, Session>()

    fun add(token: String, op: String): Session = Session(token, op).also { sessions[token] = it }

    /** 避免会话令牌比较因前缀匹配时间泄露信息。 */
    fun find(token: String?): Session? {
        if (token.isNullOrBlank()) return null
        val supplied = token.toByteArray(Charsets.US_ASCII)
        var matched: Session? = null
        sessions.forEach { (candidate, session) ->
            if (MessageDigest.isEqual(candidate.toByteArray(Charsets.US_ASCII), supplied)) matched = session
        }
        supplied.fill(0)
        return matched
    }

    /**
     * 快照当前所有会话，供主机侧汇总「对方设备」信息。
     *
     * 返回副本而非内部集合：调用方只读，避免绕过 clear() 的敏感数据擦除。
     */
    fun sessions(): List<Session> = sessions.values.toList()

    fun remove(token: String) {
        sessions.remove(token)?.clear()
    }

    fun clear() {
        sessions.values.forEach(Session::clear)
        sessions.clear()
    }
}
