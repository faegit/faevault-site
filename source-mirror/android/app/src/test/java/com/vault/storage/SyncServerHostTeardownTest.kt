package com.vault.storage

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 停机收尾的源码级护栏。
 *
 * 这里测的不是运行时行为（SyncServerHost 是真实 socket 服务器，起不来单测环境），
 * 而是「停机时会不会把会话标志复位」——这一条曾出过事故，且症状极具迷惑性：
 *
 * `/api/transfer/end` 里原本误写成 `transferActive.set(true)`，紧跟着才停机。
 * 状态位因此停在「传输中」，下一次 `updateStatus()` 会把传输中重新发布出去，
 * 于是 PC 已经断开、安卓主机侧却仍显示「断开连接」，用户必须手动点一次才收口。
 * 表现为「已经提示对方关闭了，页面却还要再断一次」。
 *
 * 断言写成源码检查，是为了让它在纯 JVM 环境下也能守住这条线。
 */
class SyncServerHostTeardownTest {

    private val source: String by lazy {
        File("src/main/java/com/vault/storage/SyncServerHost.kt").readText()
    }

    private fun bodyOf(name: String): String {
        val start = source.indexOf("fun $name(")
        assertTrue("未找到 $name", start >= 0)
        val open = source.indexOf('{', start)
        assertTrue("$name 没有函数体", open > start)
        // 按花括号配对取真正的函数体：这些方法内部还有局部 fun 与嵌套 lambda，
        // 按行或固定窗口切分都会越界。
        var depth = 0
        var i = open
        while (i < source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> {
                    depth--
                    if (depth == 0) return source.substring(start, i + 1)
                }
            }
            i++
        }
        throw AssertionError("$name 的花括号不配对")
    }

    @Test fun `stopping the station clears every session flag`() {
        val body = bodyOf("stopInternal")
        // 停机后若 paired / transferActive 仍为真，updateStatus 会把「有对端在会话中」
        // 重新发布出去，UI 就继续显示「断开连接」。
        for (flag in listOf("paired.set(false)", "transferActive.set(false)")) {
            assertTrue(
                "stopInternal 必须复位 $flag，否则停机后 UI 仍显示断开中",
                body.contains(flag),
            )
        }
        assertTrue("停机应清空会话表", body.contains("sessions.clear()"))
    }

    @Test fun `the transfer end endpoint never re-asserts an active transfer`() {
        // 必须按「代码行」定位，不能直接 indexOf 全文——文件里有多处注释提到
        // /api/transfer/end（超时策略说明里就有一句），命中注释会取到整块错误区间。
        val routeLines = source.lineSequence()
            .map { it.trim() }
            .filterNot { it.startsWith("//") || it.startsWith("*") || it.startsWith("/*") }
            .toList()
        val start = routeLines.indexOfFirst { it.contains("req.path == \"/api/transfer/end\"") }
        assertTrue("未找到 /api/transfer/end 路由", start >= 0)
        // 只看这一条路由的分支体，不越界到相邻路由。
        val end = (start + 1 until routeLines.size)
            .firstOrNull { routeLines[it].contains("else -> sendError") }
        assertNotNull("未找到该路由的结尾", end)
        val route = routeLines.subList(start, end!!).joinToString("\n")
        // 曾经的笔误：断开前先 transferActive.set(true)。
        assertFalse(
            "对端断开时不得把传输重新置为进行中",
            route.contains("transferActive.set(true)"),
        )
        assertTrue("断开前应显式复位传输标志", route.contains("transferActive.set(false)"))
    }

    @Test fun `disconnecting a peer keeps the listener alive`() {
        // disconnectPeer 只断这一对设备，传输站继续监听，可以再接新设备；
        // stopInternal 才是整站停机。两者语义不同，别混用。
        val body = bodyOf("disconnectPeer")
        assertFalse("断开对端不应停站", body.contains("stopInternal("))
        assertFalse("断开对端不应置 running=false", body.contains("running.set(false)"))
    }
}
