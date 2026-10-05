package com.vault.ui

import org.junit.Assert.*
import org.junit.Test

class EdgeBounceTest {
    @Test fun displacementIsBoundedInBothDirections() {
        assertEquals(40f, edgeBounceOffset(0f, 10000f, 40f), 0.001f)
        assertEquals(-40f, edgeBounceOffset(0f, -10000f, 40f), 0.001f)
    }
    @Test fun edgeResistanceIncreasesWithDisplacement() {
        val atRest = edgeBounceOffset(0f, 10f, 40f)
        val nearEdge = edgeBounceOffset(35f, 10f, 40f) - 35f
        assertTrue(atRest > nearEdge)
        assertTrue(nearEdge > 0f)
    }

    /**
     * 收尾时机：按住期间必须定格（此前这里没判断手指状态，导致不松手就弹回）；
     * 而收尾动作本身必须是动画回弹，不能硬置 0（否则松手后残余滚动事件会让位移
     * 硬跳回原位，表现为"闪现回去"）。
     */
    @Test fun settlingHappensOnlyAfterRelease() {
        assertFalse(canRelease(touching = true))
        assertTrue(canRelease(touching = false))

        assertFalse("按住期间即使子级消费了位移也不能收尾", shouldSettle(touching = true, consumed = 50f))
        assertTrue(shouldSettle(touching = false, consumed = 50f))
        assertFalse("没有消费说明仍在边缘，不该收尾", shouldSettle(touching = false, consumed = 0f))
        assertFalse(shouldSettle(touching = true, consumed = 0f))
    }
}
