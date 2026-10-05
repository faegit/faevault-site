package com.vault.ui

import android.os.SystemClock
import android.view.MotionEvent
import androidx.activity.compose.setContent
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.LocalOverscrollConfiguration
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.material3.Text
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
@OptIn(ExperimentalFoundationApi::class)
class EdgeScrollTest {
    @Test(timeout = 45000) fun newDragScrollsImmediatelyDuringEdgeReturn() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val state = LazyListState()
        val packageName = instrumentation.targetContext.packageName
        // MIUI can suppress launches from a newly installed background test package.
        instrumentation.uiAutomation.executeShellCommand(
            "am start -W -n $packageName/com.vault.ui.ScrollTestActivity"
        ).use { android.os.ParcelFileDescriptor.AutoCloseInputStream(it).readBytes() }
        ActivityScenario.launch(ScrollTestActivity::class.java).use { scenario ->
            lateinit var activity: ScrollTestActivity
            scenario.onActivity { host ->
                activity = host
                host.setContent {
                    CompositionLocalProvider(LocalOverscrollConfiguration provides null) {
                        VaultLazyColumn(modifier = Modifier.fillMaxSize(), state = state) {
                            items(80) { Text("Scroll test $it", Modifier.height(64.dp)) }
                        }
                    }
                }
            }
            instrumentation.waitForIdleSync()
            val view = activity.window.decorView
            val x = view.width / 2f
            val middle = view.height / 2f
            var down = SystemClock.uptimeMillis()
            fun touch(action: Int, y: Float) {
                val event = MotionEvent.obtain(down, SystemClock.uptimeMillis(), action, x, y, 0)
                instrumentation.runOnMainSync { view.dispatchTouchEvent(event) }
                event.recycle()
                SystemClock.sleep(16)
            }
            // At the first row, pull outwards, then reverse while the visual spring is returning.
            touch(MotionEvent.ACTION_DOWN, middle)
            for (i in 1..6) touch(MotionEvent.ACTION_MOVE, middle + i * 25)
            touch(MotionEvent.ACTION_UP, middle + 150)
            down = SystemClock.uptimeMillis()
            touch(MotionEvent.ACTION_DOWN, middle)
            for (i in 1..4) touch(MotionEvent.ACTION_MOVE, middle - i * 35)
            instrumentation.runOnMainSync {
                assertTrue("A new drag must scroll before the edge return finishes",
                    state.firstVisibleItemIndex > 0 || state.firstVisibleItemScrollOffset > 40)
            }
            touch(MotionEvent.ACTION_UP, middle - 140)
        }
    }
}
