package com.vault.storage

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.math.ec.ECPoint

/** RFC 9382 SPAKE2 P-256/SHA-256/HKDF/HMAC client + server primitives. */
internal object Spake2P256 {
    private val params = SECNamedCurves.getByName("secp256r1")
    private val order: BigInteger = params.n
    private val m: ECPoint = decode(hex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"))
    private val n: ECPoint = decode(hex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"))
    private val random = SecureRandom()

    class ClientStart internal constructor(
        internal val w: BigInteger,
        internal val x: BigInteger,
        internal val maskedN: ECPoint,
        val share: ByteArray,
    )

    data class ClientResult(
        val confirmation: ByteArray,
        val expectedServerConfirmation: ByteArray,
        val sessionToken: ByteArray,
    ) {
        fun clear() {
            confirmation.fill(0)
            expectedServerConfirmation.fill(0)
            sessionToken.fill(0)
        }
    }

    /** 服务端配对起始状态：y 为临时标量，share 为服务端 share（65 字节非压缩点）。 */
    class ServerStart internal constructor(
        internal val w: BigInteger,
        internal val y: BigInteger,
        internal val maskedM: ECPoint,
        val share: ByteArray,
    )

    /** 服务端配对结果：confirmationA 用于校验客户端提交的确认，confirmationB 发给客户端，sessionToken 用于会话鉴权。 */
    class ServerResult(
        val confirmationA: ByteArray,
        val confirmationB: ByteArray,
        val sessionToken: ByteArray,
    ) {
        fun clear() {
            confirmationA.fill(0)
            confirmationB.fill(0)
            sessionToken.fill(0)
        }
    }

    fun start(pin: String, ticket: String): ClientStart = start(deriveW(pin, ticket), randomScalar())

    internal fun start(w: BigInteger, x: BigInteger): ClientStart {
        require(w.signum() >= 0 && w < order) { "invalid SPAKE2 password scalar" }
        require(x.signum() > 0 && x < order) { "invalid SPAKE2 ephemeral scalar" }
        val maskedM = m.multiply(w).normalize()
        val maskedN = n.multiply(w).normalize()
        val share = params.g.multiply(x).add(maskedM).normalize().getEncoded(false)
        return ClientStart(w, x, maskedN, share)
    }

    fun finish(
        start: ClientStart,
        serverShare: ByteArray,
        identityA: ByteArray,
        identityB: ByteArray,
        aad: ByteArray,
        ticket: String,
    ): ClientResult {
        val received = decode(serverShare)
        val shared = received.subtract(start.maskedN).multiply(start.x).normalize()
        require(!shared.isInfinity) { "invalid SPAKE2 shared point" }
        val transcript = transcript(start.w, start.share, serverShare, shared, identityA, identityB)
        val (confirmationA, confirmationB, session) = deriveKeys(transcript, aad, ticket)
        transcript.fill(0)
        return ClientResult(confirmationA, confirmationB, session)
    }

    /** 服务端启动：share = y·G + w·N。 */
    internal fun serverStart(pin: String, ticket: String): ServerStart = serverStart(deriveW(pin, ticket), randomScalar())

    internal fun serverStart(w: BigInteger, y: BigInteger): ServerStart {
        require(w.signum() >= 0 && w < order) { "invalid SPAKE2 password scalar" }
        require(y.signum() > 0 && y < order) { "invalid SPAKE2 ephemeral scalar" }
        val maskedM = m.multiply(w).normalize()
        val maskedN = n.multiply(w).normalize()
        val share = params.g.multiply(y).add(maskedN).normalize().getEncoded(false)
        return ServerStart(w, y, maskedM, share)
    }

    /** 服务端完成：shared = (p_a − w·M)·y，与客户端 `finish` 得到同一共享密钥。 */
    internal fun serverFinish(
        start: ServerStart,
        clientShare: ByteArray,
        identityA: ByteArray,
        identityB: ByteArray,
        aad: ByteArray,
        ticket: String,
    ): ServerResult {
        val received = decode(clientShare)
        val shared = received.subtract(start.maskedM).multiply(start.y).normalize()
        require(!shared.isInfinity) { "invalid SPAKE2 shared point" }
        val transcript = transcript(start.w, clientShare, start.share, shared, identityA, identityB)
        val (confirmationA, confirmationB, session) = deriveKeys(transcript, aad, ticket)
        transcript.fill(0)
        return ServerResult(confirmationA, confirmationB, session)
    }

    /** 双方共用的密钥派生：confirmationA 客户端发送/服务端校验，confirmationB 服务端发送/客户端校验。 */
    private fun deriveKeys(
        transcript: ByteArray,
        aad: ByteArray,
        ticket: String,
    ): Triple<ByteArray, ByteArray, ByteArray> {
        val digest = MessageDigest.getInstance("SHA-256").digest(transcript)
        val sharedKey = digest.copyOfRange(0, 16)
        val confirmationKey = digest.copyOfRange(16, 32)
        val confirmationKeys = hkdf(confirmationKey, "ConfirmationKeys".toByteArray() + aad, 32)
        val confirmationA = hmac(confirmationKeys.copyOfRange(0, 16), transcript)
        val confirmationB = hmac(confirmationKeys.copyOfRange(16, 32), transcript)
        val session = hmac(sharedKey, ("Vault LAN Sync SPAKE2 Session v1" + 0.toChar()).toByteArray() + ticket.toByteArray())
        digest.fill(0)
        sharedKey.fill(0)
        confirmationKey.fill(0)
        confirmationKeys.fill(0)
        return Triple(confirmationA, confirmationB, session)
    }

    internal fun deriveW(pin: String, ticket: String): BigInteger {
        require(pin.length == 6 && pin.all { it in '0'..'9' }) { "invalid SPAKE2 PIN" }
        val salt = MessageDigest.getInstance("SHA-256")
            .digest(("Vault LAN Sync SPAKE2 w v1" + 0.toChar()).toByteArray() + ticket.toByteArray())
        val material = SCrypt.generate(pin.toByteArray(Charsets.US_ASCII), salt, 1 shl 14, 8, 1, 40)
        val value = BigInteger(1, material).mod(order)
        salt.fill(0)
        material.fill(0)
        return value
    }

    private fun transcript(
        w: BigInteger,
        pA: ByteArray,
        pB: ByteArray,
        shared: ECPoint,
        identityA: ByteArray,
        identityB: ByteArray,
    ): ByteArray = ByteArrayOutputStream().use { out ->
        listOf(identityA, identityB, pA, pB, shared.getEncoded(false), fixed32(w)).forEach { value ->
            var length = value.size.toLong()
            repeat(8) {
                out.write((length and 0xff).toInt())
                length = length ushr 8
            }
            out.write(value)
        }
        out.toByteArray()
    }

    private fun decode(encoded: ByteArray): ECPoint {
        require(encoded.size == 33 || encoded.size == 65) { "invalid SPAKE2 point length" }
        val point = try {
            params.curve.decodePoint(encoded).normalize()
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("invalid SPAKE2 point", error)
        }
        require(!point.isInfinity && point.isValid && point.multiply(order).isInfinity) { "invalid SPAKE2 point" }
        return point
    }

    private fun randomScalar(): BigInteger {
        val bytes = ByteArray(32)
        while (true) {
            random.nextBytes(bytes)
            val value = BigInteger(1, bytes)
            if (value.signum() > 0 && value < order) {
                bytes.fill(0)
                return value
            }
        }
    }

    private fun hkdf(input: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = hmac(ByteArray(32), input)
        val output = ByteArrayOutputStream()
        var previous = ByteArray(0)
        var counter = 1
        while (output.size() < length) {
            val block = hmac(prk, previous + info + byteArrayOf(counter.toByte()))
            previous.fill(0)
            previous = block
            output.write(block)
            counter++
        }
        previous.fill(0)
        prk.fill(0)
        return output.toByteArray().copyOf(length)
    }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(key, "HmacSHA256"))
            doFinal(message)
        }

    private fun fixed32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val unsigned = if (raw.size > 32) raw.copyOfRange(raw.size - 32, raw.size) else raw
        return ByteArray(32).also { unsigned.copyInto(it, 32 - unsigned.size) }
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
