package com.vault.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * 传输站「对方设备」的选取。
 *
 * 回归点：原先拿 SPAKE2 配对时刻去比对设备挑战确认时刻——两次独立取时几乎永不相等，
 * 于是对方设备信息恒为空，安卓连安卓时传输站页面一直显示不出对方设备。
 */
class LanPeerIdentityTest {

    @Test
    fun `picks the session that completed device authentication`() {
        val picked = pickLanPeerIdentity(
            listOf(
                LanPeerIdentity("", "", "192.168.1.5", 1_000),   // 已配对但未认证
                LanPeerIdentity("dev-a", "fp-a", "192.168.1.5", 2_000),
            ),
        )
        assertEquals("dev-a", picked?.deviceId)
        assertEquals("fp-a", picked?.fingerprint)
    }

    @Test
    fun `picks the most recently authenticated session`() {
        val picked = pickLanPeerIdentity(
            listOf(
                LanPeerIdentity("old", "fp-old", "192.168.1.4", 1_000),
                LanPeerIdentity("new", "fp-new", "192.168.1.5", 9_000),
            ),
        )
        assertEquals("new", picked?.deviceId)
    }

    @Test
    fun `returns null when nobody finished authentication`() {
        assertNull(pickLanPeerIdentity(listOf(LanPeerIdentity("", "", "192.168.1.5", 1_000))))
        assertNull(pickLanPeerIdentity(emptyList()))
    }

    @Test
    fun `prefers an authenticated session over a newer unauthenticated one`() {
        val picked = pickLanPeerIdentity(
            listOf(
                LanPeerIdentity("authed", "fp", "192.168.1.5", 1_000),
                LanPeerIdentity("", "", "192.168.1.6", 9_999),
            ),
        )
        assertEquals("authed", picked?.deviceId)
    }
}
