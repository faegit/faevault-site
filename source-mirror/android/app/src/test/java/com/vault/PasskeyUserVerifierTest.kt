package com.vault

import com.vault.passkeys.EmbeddedPromptResult
import com.vault.passkeys.MonotonicClock
import com.vault.passkeys.PasskeyOperation
import com.vault.passkeys.PasskeyUserVerifier
import com.vault.passkeys.UserAuthenticationResult
import com.vault.passkeys.UserVerificationResult
import com.vault.passkeys.UserVerificationTicketStore
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class PasskeyUserVerifierTest {
    @Test
    fun ticketIsConsumedExactlyOnceWithoutLeakingBindings() {
        val fixture = Fixture()
        val result = fixture.verifier.completeAuthentication(
            REQUEST_A,
            PasskeyOperation.CREATE,
            CREATE_CONTEXT,
            UserAuthenticationResult.Success,
        )
        val ticket = (result as UserVerificationResult.Verified).ticket

        assertTrue(fixture.verifier.consume(ticket, REQUEST_A, PasskeyOperation.CREATE, CREATE_CONTEXT))
        assertFalse(fixture.verifier.consume(ticket, REQUEST_A, PasskeyOperation.CREATE, CREATE_CONTEXT))
        assertFalse(ticket.toString().contains(REQUEST_A))
        assertFalse(ticket.toString().contains(CREATE_CONTEXT))
    }

    @Test
    fun ticketIsValidBeforeButNotAtThirtySecondBoundary() {
        val fixture = Fixture(now = 1_000L)
        val beforeBoundary = fixture.verifiedTicket(REQUEST_A)
        fixture.now = 30_999L
        assertTrue(fixture.verifier.consume(beforeBoundary, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT))

        val atBoundary = fixture.verifiedTicket(REQUEST_B)
        fixture.now = 60_999L
        assertFalse(fixture.verifier.consume(atBoundary, REQUEST_B, PasskeyOperation.GET, GET_CONTEXT))
    }

    @Test
    fun wrongRequestTokenOrOperationRejectsAndBurnsTicket() {
        val fixture = Fixture()
        val wrongToken = fixture.verifiedTicket(REQUEST_A)
        assertFalse(fixture.verifier.consume(wrongToken, REQUEST_B, PasskeyOperation.GET, GET_CONTEXT))
        assertFalse(fixture.verifier.consume(wrongToken, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT))

        val wrongOperation = fixture.verifiedTicket(REQUEST_B)
        assertFalse(fixture.verifier.consume(wrongOperation, REQUEST_B, PasskeyOperation.CREATE, GET_CONTEXT))
        assertFalse(fixture.verifier.consume(wrongOperation, REQUEST_B, PasskeyOperation.GET, GET_CONTEXT))
    }

    @Test
    fun ticketCannotBeReusedForAnotherCredentialOrOptionContext() {
        val fixture = Fixture()
        val credentialTicket = fixture.verifiedTicket(REQUEST_A, context = "credential:alpha")
        assertFalse(
            fixture.verifier.consume(
                credentialTicket,
                REQUEST_A,
                PasskeyOperation.GET,
                "credential:beta",
            ),
        )
        assertFalse(
            fixture.verifier.consume(
                credentialTicket,
                REQUEST_A,
                PasskeyOperation.GET,
                "credential:alpha",
            ),
        )

        val optionTicket = fixture.verifiedTicket(REQUEST_B, context = "option:first")
        assertFalse(
            fixture.verifier.consume(optionTicket, REQUEST_B, PasskeyOperation.GET, "option:second"),
        )
    }

    @Test
    fun failedAndCanceledAuthenticationCreateNoTicket() {
        val fixture = Fixture()

        assertEquals(
            UserVerificationResult.Cancelled,
            fixture.verifier.completeAuthentication(
                REQUEST_A,
                PasskeyOperation.CREATE,
                CREATE_CONTEXT,
                UserAuthenticationResult.Cancelled,
            ),
        )
        assertEquals(
            UserVerificationResult.Failure,
            fixture.verifier.completeAuthentication(
                REQUEST_B,
                PasskeyOperation.GET,
                GET_CONTEXT,
                UserAuthenticationResult.Failure,
            ),
        )
        assertEquals(0, fixture.store.activeTicketCount())
    }

    @Test
    fun onlyOneConcurrentConsumerSucceeds() {
        val fixture = Fixture()
        val ticket = fixture.verifiedTicket(REQUEST_A)
        val ready = CountDownLatch(16)
        val start = CountDownLatch(1)
        val successes = AtomicInteger()
        val pool = Executors.newFixedThreadPool(16)

        repeat(16) {
            pool.execute {
                ready.countDown()
                start.await()
                if (fixture.verifier.consume(ticket, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT)) {
                    successes.incrementAndGet()
                }
            }
        }

        assertTrue(ready.await(5, TimeUnit.SECONDS))
        start.countDown()
        pool.shutdown()
        assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS))
        assertEquals(1, successes.get())
    }

    @Test
    fun monotonicClockRollbackRejectsAndBurnsTicket() {
        val fixture = Fixture(now = 10_000L)
        val ticket = fixture.verifiedTicket(REQUEST_A)

        fixture.now = 9_999L
        assertFalse(fixture.verifier.consume(ticket, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT))
        fixture.now = 10_000L
        assertFalse(fixture.verifier.consume(ticket, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT))
    }

    @Test
    fun aNewProcessLocalStoreStartsEmpty() {
        val firstProcess = Fixture()
        val ticket = firstProcess.verifiedTicket(REQUEST_A)
        val restartedProcess = Fixture()

        assertFalse(
            restartedProcess.verifier.consume(ticket, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT),
        )
        assertTrue(firstProcess.verifier.consume(ticket, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT))
    }

    @Test
    fun storeCapacityEvictsOldestTicketAndCleanupRemainsBounded() {
        val fixture = Fixture(capacity = 2)
        val first = fixture.verifiedTicket(REQUEST_A)
        fixture.now++
        val second = fixture.verifiedTicket(REQUEST_B)
        fixture.now++
        val third = fixture.verifiedTicket(REQUEST_C)

        assertEquals(2, fixture.store.activeTicketCount())
        assertFalse(fixture.verifier.consume(first, REQUEST_A, PasskeyOperation.GET, GET_CONTEXT))
        assertTrue(fixture.verifier.consume(second, REQUEST_B, PasskeyOperation.GET, GET_CONTEXT))
        assertTrue(fixture.verifier.consume(third, REQUEST_C, PasskeyOperation.GET, GET_CONTEXT))
    }

    @Test
    fun embeddedSuccessIssuesTicketFailureDoesNotAndAbsentFallsBackExplicitly() = runBlocking {
        val fixture = Fixture()
        var fallbackCalls = 0

        val embeddedSuccess = fixture.verifier.verify(
            REQUEST_A,
            PasskeyOperation.CREATE,
            CREATE_CONTEXT,
            EmbeddedPromptResult.Success,
        ) {
            fallbackCalls++
            UserAuthenticationResult.Failure
        }
        assertTrue(embeddedSuccess is UserVerificationResult.Verified)
        assertEquals(0, fallbackCalls)

        assertEquals(
            UserVerificationResult.Failure,
            fixture.verifier.verify(
                REQUEST_B,
                PasskeyOperation.GET,
                GET_CONTEXT,
                EmbeddedPromptResult.Failure,
            ) {
                fallbackCalls++
                UserAuthenticationResult.Success
            },
        )
        assertEquals(0, fallbackCalls)

        val fallbackSuccess = fixture.verifier.verify(
            REQUEST_C,
            PasskeyOperation.GET,
            GET_CONTEXT,
            EmbeddedPromptResult.Absent,
        ) {
            fallbackCalls++
            UserAuthenticationResult.Success
        }
        assertTrue(fallbackSuccess is UserVerificationResult.Verified)
        assertEquals(1, fallbackCalls)
    }

    private class Fixture(
        var now: Long = 100L,
        capacity: Int = 128,
    ) {
        private val clock = MonotonicClock { now }
        val store = UserVerificationTicketStore(clock = clock, capacity = capacity)
        val verifier = PasskeyUserVerifier(store)

        fun verifiedTicket(
            requestToken: String,
            operation: PasskeyOperation = PasskeyOperation.GET,
            context: String = GET_CONTEXT,
        ) = (
            verifier.completeAuthentication(
                requestToken,
                operation,
                context,
                UserAuthenticationResult.Success,
            ) as UserVerificationResult.Verified
            ).ticket
    }

    private companion object {
        const val REQUEST_A = "random-request-token-a"
        const val REQUEST_B = "random-request-token-b"
        const val REQUEST_C = "random-request-token-c"
        const val CREATE_CONTEXT = "create-option-context"
        const val GET_CONTEXT = "get-credential-context"
    }
}
