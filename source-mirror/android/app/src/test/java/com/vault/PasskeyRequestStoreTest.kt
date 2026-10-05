package com.vault

import androidx.credentials.provider.BeginGetCredentialRequest
import com.vault.passkeys.PasskeyOperation
import com.vault.passkeys.PasskeyOperationTokenStore
import com.vault.passkeys.PasskeyRequestContract
import com.vault.passkeys.PasskeyRequestStore
import com.vault.passkeys.StoredBeginGet
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.lang.reflect.Modifier
import java.util.Base64
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class PasskeyRequestStoreTest {
    @Test
    fun operationTokensAreOneUseExpireAndRejectConcurrentReplay() {
        var now = 1_000L
        var sequence = 0
        val store = PasskeyOperationTokenStore(
            elapsedRealtime = { now },
            tokenGenerator = { "operation-${sequence++}" },
        )
        val token = store.issue()

        assertTrue(store.consume(token))
        assertFalse(store.consume(token))

        val expired = store.issue()
        now += 300_000L
        assertFalse(store.consume(expired))
        assertEquals(0, store.activeTokenCount())

        val shared = store.issue()
        val executor = Executors.newFixedThreadPool(16)
        val start = CountDownLatch(1)
        val results = Collections.synchronizedList(mutableListOf<Boolean>())
        repeat(32) {
            executor.execute {
                start.await()
                results += store.consume(shared)
            }
        }
        start.countDown()
        executor.shutdown()
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(1, results.count { it })
    }

    @Test
    fun tokensContain192RandomBitsAndUseUnpaddedUrlSafeEncoding() {
        val store = PasskeyRequestStore(elapsedRealtime = { 1L })
        val tokens = (1..128).map { store.put(request()) }

        assertEquals(tokens.size, tokens.toSet().size)
        tokens.forEach { token ->
            assertTrue(token.matches(Regex("[A-Za-z0-9_-]{32}")))
            assertEquals(24, Base64.getUrlDecoder().decode(token).size)
        }
    }

    @Test
    fun takeIsAtomicAndOneUse() {
        val store = PasskeyRequestStore(elapsedRealtime = { 1L })
        val request = request()
        val token = store.put(request)

        assertSame(request, store.take(token))
        assertNull(store.take(token))
    }

    @Test
    fun getSupportsCredentialReselectionWithoutExtendingExpiry() {
        var now = 1_000L
        val store = PasskeyRequestStore(elapsedRealtime = { now })
        val request = request()
        val token = store.put(request)

        assertSame(request, store.get(token))
        assertSame(request, store.get(token))
        assertEquals(1, store.activeRequestCount())

        now += 300_000L
        assertNull(store.get(token))
        assertEquals(0, store.activeRequestCount())
    }

    @Test
    fun requestExpiresAtTheFiveMinuteBoundary() {
        var now = 1_000L
        val store = PasskeyRequestStore(elapsedRealtime = { now })
        val beforeBoundaryRequest = request()
        val beforeBoundary = store.put(beforeBoundaryRequest)

        now = 300_999L
        assertSame(beforeBoundaryRequest, store.take(beforeBoundary))

        val atBoundary = store.put(request())
        now += 300_000L
        assertNull(store.take(atBoundary))
        assertEquals(0, store.activeRequestCount())
    }

    @Test
    fun wrongOperationOrOptionDoesNotConsumeMatchingRequest() {
        val store = PasskeyRequestStore(elapsedRealtime = { 1L })
        val request = request()
        val contract = PasskeyRequestContract(PasskeyOperation.GET, "option-a")
        val token = store.put(request, contract)

        assertNull(
            store.take(
                token,
                PasskeyRequestContract(PasskeyOperation.CREATE, "option-a"),
            ),
        )
        assertNull(
            store.take(
                token,
                PasskeyRequestContract(PasskeyOperation.GET, "option-b"),
            ),
        )
        assertSame(request, store.take(token, contract))
        assertNull(store.take(token, contract))
    }

    @Test
    fun capacityEvictsOldestExpiringRequestAndUsesInsertionOrderForTies() {
        var now = 100L
        val store = PasskeyRequestStore(elapsedRealtime = { now })
        val first = store.put(request())
        now = 200L
        val second = store.put(request())
        repeat(62) { store.put(request()) }

        val newest = store.put(request())

        assertEquals(64, store.activeRequestCount())
        assertNull(store.take(first))
        assertTrue(store.take(second) != null)
        assertTrue(store.take(newest) != null)

        now = 500L
        val tiedStore = PasskeyRequestStore(elapsedRealtime = { now })
        val tiedFirst = tiedStore.put(request())
        val tiedSecond = tiedStore.put(request())
        repeat(63) { tiedStore.put(request()) }

        assertNull(tiedStore.take(tiedFirst))
        assertTrue(tiedStore.take(tiedSecond) != null)
    }

    @Test
    fun concurrentPutAndTakeAreSafeAndOnlyOneTakeWins() {
        val store = PasskeyRequestStore(elapsedRealtime = { 1L })
        val executor = Executors.newFixedThreadPool(16)
        val start = CountDownLatch(1)
        val tokens = Collections.synchronizedList(mutableListOf<String>())

        repeat(32) {
            executor.execute {
                start.await()
                tokens += store.put(request())
            }
        }
        start.countDown()
        executor.shutdown()
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(32, tokens.toSet().size)

        val sharedToken = tokens.first()
        val takeExecutor = Executors.newFixedThreadPool(16)
        val takeStart = CountDownLatch(1)
        val results = Collections.synchronizedList(mutableListOf<BeginGetCredentialRequest?>())
        repeat(32) {
            takeExecutor.execute {
                takeStart.await()
                results += store.take(sharedToken)
            }
        }
        takeStart.countDown()
        takeExecutor.shutdown()
        assertTrue(takeExecutor.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(1, results.count { it != null })
    }

    @Test
    fun storeIsProcessLocalAndRetainsOnlyTheBeginFrameworkRequestByIdentity() {
        val request = request()
        val stored = StoredBeginGet(request, createdAtElapsed = 42L)
        val persistentTypeNames = setOf(
            "java.io.File",
            "java.nio.file.Path",
            "android.content.SharedPreferences",
            "android.os.Bundle",
            "java.lang.String",
            "[B",
        )
        val storedFields = StoredBeginGet::class.java.declaredFields
            .filterNot { Modifier.isStatic(it.modifiers) }
            .associateBy { it.name }
        val storeFields = PasskeyRequestStore::class.java.declaredFields
            .filterNot { Modifier.isStatic(it.modifiers) }
        val acceptedPutTypes = PasskeyRequestStore::class.java.declaredMethods
            .filter { it.name == "put" }
            .map { it.parameterTypes.first() }

        assertEquals(setOf("request", "createdAtElapsed"), storedFields.keys)
        assertTrue(storedFields.values.none { it.type.name in persistentTypeNames })
        assertTrue(storeFields.none { it.type.name in persistentTypeNames })
        assertTrue(acceptedPutTypes.isNotEmpty())
        assertTrue(acceptedPutTypes.all { it == BeginGetCredentialRequest::class.java })
        assertSame(request, stored.request)
        assertFalse(stored.toString().contains(request.toString()))
        assertEquals("StoredBeginGet(request=[redacted])", stored.toString())
    }

    private fun request() = BeginGetCredentialRequest(emptyList())
}

