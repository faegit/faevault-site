package com.vault.passkeys

import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Security
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec

/** A signing capability. Consumers never need access to an encoded private key. */
interface PasskeySigningKey : AutoCloseable {
    val algorithm: Int
    val publicKeyCose: ByteArray
    fun sign(data: ByteArray): ByteArray
    override fun close()
}

/** Caller-owned software key material used only behind [PasskeySigningKey]. */
class SoftwarePasskeySigningKey private constructor(
    override val algorithm: Int,
    privateKeyPkcs8: ByteArray,
    publicKeyCose: ByteArray,
) : PasskeySigningKey {
    private val privateKeyPkcs8 = privateKeyPkcs8.copyOf()
    private val cose = publicKeyCose.copyOf()
    private var closed = false

    override val publicKeyCose: ByteArray
        get() {
            check(!closed)
            return cose.copyOf()
        }

    override fun sign(data: ByteArray): ByteArray {
        check(!closed)
        return signPkcs8(algorithm, privateKeyPkcs8, data)
    }

    /**
     * 【同步后完整性】私钥/公钥配对自检：随机 challenge → 私钥签名 → COSE 公钥验签。
     * 用于捕获"publicKey 与 privateKey 不属于同一密钥对"的损坏凭据（云同步/导入/合并引入），
     * 防止坏凭据流入 RP 造成"密钥无效"。签名+验签成本毫秒级，随 open() 每次仪式执行。
     */
    fun verifySelfTest(): Boolean {
        val challenge = ByteArray(32).also(SecureRandom()::nextBytes)
        val signature = try {
            signPkcs8(algorithm, privateKeyPkcs8, challenge)
        } catch (error: Throwable) {
            throw IllegalStateException("passkey selftest: signing failed", error)
        }
        return try {
            verifyWithCosePublicKey(challenge, signature)
        } catch (error: Throwable) {
            throw IllegalStateException("passkey selftest: verification setup failed", error)
        }
    }

    /** 使用 COSE 公钥（本类已知的三种算法）验证签名。 */
    private fun verifyWithCosePublicKey(data: ByteArray, signature: ByteArray): Boolean {
        ensureBouncyCastle()
        val entries = CborMiniReader.readMap(cose)
        return when (algorithm) {
            -7 -> {
                val x = entries.getValue(-2L) as ByteArray
                val y = entries.getValue(-3L) as ByteArray
                // 组装未压缩点并包装为标准 SubjectPublicKeyInfo，交由 JCA 验证
                val point = ByteArray(1 + x.size + y.size)
                point[0] = 0x04
                x.copyInto(point, 1); y.copyInto(point, 1 + x.size)
                val spki = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                    org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey,
                        org.bouncycastle.asn1.x9.X962Parameters(
                            org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID("secp256r1"),
                        ),
                    ),
                    point,
                )
                val pub = KeyFactory.getInstance("EC").generatePublic(
                    java.security.spec.X509EncodedKeySpec(spki.encoded),
                )
                Signature.getInstance("SHA256withECDSA").run { initVerify(pub); update(data); verify(signature) }
            }
            -257 -> {
                val n = java.math.BigInteger(1, entries.getValue(-1L) as ByteArray)
                val e = java.math.BigInteger(1, entries.getValue(-2L) as ByteArray)
                val pub = KeyFactory.getInstance("RSA").generatePublic(java.security.spec.RSAPublicKeySpec(n, e))
                Signature.getInstance("SHA256withRSA").run { initVerify(pub); update(data); verify(signature) }
            }
            -8 -> {
                val pub = org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(entries.getValue(-2L) as ByteArray, 0)
                val verifier = org.bouncycastle.crypto.signers.Ed25519Signer()
                verifier.init(false, pub)
                verifier.update(data, 0, data.size)
                verifier.verifySignature(signature)
            }
            else -> false
        }
    }

    /** Returns a transient copy for storage inside the encrypted syncable Passkey entry. */
    fun exportPrivateKey(): ByteArray {
        check(!closed)
        return privateKeyPkcs8.copyOf()
    }

    override fun close() {
        if (!closed) {
            privateKeyPkcs8.fill(0)
            cose.fill(0)
            closed = true
        }
    }

    companion object {
        fun generate(algorithm: Int): SoftwarePasskeySigningKey {
            ensureBouncyCastle()
            val keyPair = when (algorithm) {
                -7 -> KeyPairGenerator.getInstance("EC").run {
                    initialize(ECGenParameterSpec("secp256r1"))
                    generateKeyPair()
                }
                -257 -> KeyPairGenerator.getInstance("RSA").run {
                    initialize(2048)
                    generateKeyPair()
                }
                -8 -> KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider()).generateKeyPair()
                else -> throw IllegalArgumentException("Unsupported Passkey algorithm: $algorithm")
            }
            val encoded = keyPair.private.encoded
            return try {
                SoftwarePasskeySigningKey(
                    algorithm,
                    encoded,
                    PasskeyAuthenticator.buildCosePublicKey(algorithm, keyPair.public),
                )
            } finally {
                encoded.fill(0)
            }
        }

        fun open(
            algorithm: Int,
            privateKeyPkcs8: ByteArray,
            publicKeyCose: ByteArray,
        ): SoftwarePasskeySigningKey {
            require(privateKeyPkcs8.isNotEmpty())
            require(publicKeyCose.isNotEmpty())
            val key = SoftwarePasskeySigningKey(algorithm, privateKeyPkcs8.copyOf(), publicKeyCose)
            // 【同步后完整性】首次使用即验证 private↔public 属于同一密钥对：
            // 随机 challenge → 私钥签名 → COSE 公钥验签。失败说明凭据已损坏（同步/导入损坏），
            // 禁止用于认证，防止把坏凭据交给 RP 触发"密钥无效"。
            require(key.verifySelfTest()) { "Passkey key pair mismatch: credential is corrupted" }
            return key
        }
    }
}

internal fun signPkcs8(algorithm: Int, privateKeyPkcs8: ByteArray, data: ByteArray): ByteArray {
    ensureBouncyCastle()
    return when (algorithm) {
        // WebAuthn 规范要求 ES256 签名为 ASN.1 DER（RFC8152 §8.1），Java Signature.sign()
        // 的输出即是 DER，直接使用；不得转换为 64 字节 P1363(r||s)，否则 RP 验签必败
        -7 -> signature("EC", "SHA256withECDSA", privateKeyPkcs8, data)
        -257 -> signature("RSA", "SHA256withRSA", privateKeyPkcs8, data)
        -8 -> {
            val info = PrivateKeyInfo.getInstance(privateKeyPkcs8)
            val seed = (info.parsePrivateKey() as ASN1OctetString).octets
            try {
                require(seed.size == 32)
                val signer = Ed25519Signer()
                signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
                signer.update(data, 0, data.size)
                signer.generateSignature()
            } finally {
                seed.fill(0)
            }
        }
        else -> throw IllegalArgumentException("Unsupported Passkey algorithm: $algorithm")
    }
}

private fun signature(
    keyFactory: String,
    signatureAlgorithm: String,
    privateKeyPkcs8: ByteArray,
    data: ByteArray,
): ByteArray {
    val privateKey: PrivateKey = KeyFactory.getInstance(keyFactory)
        .generatePrivate(PKCS8EncodedKeySpec(privateKeyPkcs8))
    return Signature.getInstance(signatureAlgorithm).run {
        initSign(privateKey)
        update(data)
        sign()
    }
}

private fun ensureBouncyCastle() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
        Security.addProvider(BouncyCastleProvider())
    }
}

/** Converts the stored COSE key into the DER SubjectPublicKeyInfo required by WebAuthn JSON. */
internal fun cosePublicKeyToSubjectPublicKeyInfo(algorithm: Int, publicKeyCose: ByteArray): ByteArray {
    ensureBouncyCastle()
    val entries = CborMiniReader.readMap(publicKeyCose)
    return when (algorithm) {
        -7 -> {
            val x = entries.getValue(-2L) as ByteArray
            val y = entries.getValue(-3L) as ByteArray
            require(x.size == 32 && y.size == 32)
            val point = byteArrayOf(0x04) + x + y
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                    org.bouncycastle.asn1.x9.X9ObjectIdentifiers.id_ecPublicKey,
                    org.bouncycastle.asn1.x9.X962Parameters(
                        org.bouncycastle.asn1.x9.ECNamedCurveTable.getOID("secp256r1"),
                    ),
                ),
                point,
            ).encoded
        }
        -257 -> {
            val modulus = java.math.BigInteger(1, entries.getValue(-1L) as ByteArray)
            val exponent = java.math.BigInteger(1, entries.getValue(-2L) as ByteArray)
            KeyFactory.getInstance("RSA")
                .generatePublic(java.security.spec.RSAPublicKeySpec(modulus, exponent))
                .encoded
        }
        -8 -> {
            val x = entries.getValue(-2L) as ByteArray
            require(x.size == 32)
            org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                    org.bouncycastle.asn1.edec.EdECObjectIdentifiers.id_Ed25519,
                ),
                x,
            ).encoded
        }
        else -> throw IllegalArgumentException("Unsupported Passkey algorithm: $algorithm")
    }
}

/**
 * 极简 CBOR 读取器：仅支持本模块自产 COSE 公钥用到的子集
 * （无符号/负整数、字节串、定长 map）。键统一转成真实数值（含负数键 -1/-2/-3）。
 */
private object CborMiniReader {
    fun readMap(bytes: ByteArray): Map<Long, Any> {
        var i = 0
        fun head(): Pair<Long, Long> {
            val h = bytes[i++].toInt() and 0xff
            val major = (h ushr 5).toLong()
            val info = (h and 0x1f).toLong()
            return when {
                info < 24 -> major to info
                else -> {
                    val n = 1 shl (info - 24).toInt()
                    require(n in 1..8 && i + n <= bytes.size)
                    var v = 0L
                    repeat(n) { v = (v shl 8) or (bytes[i++].toLong() and 0xff) }
                    major to v
                }
            }
        }
        fun value(): Any {
            val (major, arg) = head()
            return when (major) {
                0L -> arg
                1L -> -1L - arg
                2L -> {
                    val n = arg.toInt()
                    require(i + n <= bytes.size)
                    bytes.copyOfRange(i, i + n).also { i += n }
                }
                5L -> {
                    val pairs = LinkedHashMap<Long, Any>()
                    repeat(arg.toInt()) {
                        val k = value()
                        val v = value()
                        require(k is Long)
                        pairs[k] = v
                    }
                    pairs
                }
                else -> error("unsupported CBOR major type: $major")
            }
        }
        @Suppress("UNCHECKED_CAST")
        return value() as Map<Long, Any>
    }
}
