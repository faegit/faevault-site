package com.vault.ui

import androidx.compose.runtime.MutableState
import androidx.compose.runtime.mutableLongStateOf
import com.vault.ui.IdleTracker.touch

/**
 * 全局用户活动追踪器。MainActivity 在 dispatchTouchEvent/dispatchKeyEvent 中调用 [touch]，
 * AppRoot 起一个 LaunchedEffect 监听 IdleLockPref.enabled/minutes 与 lastActivityMs 的差值，
 * 超过阈值且当前处于 Unlocked 阶段时调用 vm.lock()。
 */
object IdleTracker {
    val lastActivityMs: MutableState<Long> = mutableLongStateOf(System.currentTimeMillis())

    fun touch() {
        lastActivityMs.value = System.currentTimeMillis()
    }
}
