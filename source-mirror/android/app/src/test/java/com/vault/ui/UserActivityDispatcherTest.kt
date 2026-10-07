package com.vault.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CancellationException
import java.io.File

class UserActivityDispatcherTest {
    @Test fun sharedDialogOwnWindowObservesInputAndRestoresOriginalCallback() {
        val path = "app/src/main/java/com/vault/ui/screens/VaultDialog.kt"
        val source = listOf(File(path), File("..", path)).first(File::isFile).readText()
            .substringAfter("internal fun VaultDialogWindow()")
        assertTrue(source.contains("DisposableEffect(window)"))
        assertTrue(source.contains("UserActivityDispatcher(com.vault.ui.IdleTracker::touch)"))
        for (event in listOf("TouchEvent", "KeyEvent", "KeyShortcutEvent", "GenericMotionEvent")) {
            assertTrue("Missing separate-window input dispatch: $event", source.contains("override fun dispatch$event"))
            assertTrue("Input must still reach original callback: $event", source.contains("callback.dispatch$event(event)"))
        }
        assertTrue(source.contains("window?.callback === tracking"))
        assertTrue(source.contains("window?.callback = original"))
    }

    @Test fun continuedInputKeepsActivityFreshButStoppingStillExpires() {
        var now = 0L
        var lastActivity = now
        val dispatcher = UserActivityDispatcher { lastActivity = now }
        val timeout = 30_000L
        // A long scroll dispatches move events for longer than the configured idle timeout.
        repeat(10) {
            now += 5_000L
            dispatcher.dispatch { false }
            assertTrue(now - lastActivity < timeout)
        }
        now += timeout
        assertEquals(timeout, now - lastActivity)
    }

    @Test fun inputObservationDoesNotConsumeOrReorderDispatch() {
        val calls = mutableListOf<String>()
        val dispatcher = UserActivityDispatcher { calls += "activity" }
        assertFalse(dispatcher.dispatch { calls += "forward"; false })
        assertEquals(listOf("activity", "forward"), calls)
        assertTrue(dispatcher.dispatch { true })
    }

    @Test fun cancellationFromOriginalCallbackPropagatesUnchanged() {
        val dispatcher = UserActivityDispatcher {}
        val cancelled = CancellationException("dialog disposed")
        try {
            dispatcher.dispatch { throw cancelled }
            throw AssertionError("Cancellation must propagate")
        } catch (actual: CancellationException) {
            assertSame(cancelled, actual)
        }
    }
}
