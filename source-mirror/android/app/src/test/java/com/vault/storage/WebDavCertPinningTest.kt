package com.vault.storage

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.x509.X509V3CertificateGenerator
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import javax.security.auth.x500.X500Principal

class WebDavCertPinningTest {
    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private fun selfSigned(): X509Certificate {
        val kp = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val gen = X509V3CertificateGenerator().apply {
            setSerialNumber(BigInteger.ONE)
            setSubjectDN(X500Principal("CN=test"))
            setIssuerDN(X500Principal("CN=test"))
            setNotBefore(Date(System.currentTimeMillis() - 60_000))
            setNotAfter(Date(System.currentTimeMillis() + 3_600_000))
            setPublicKey(kp.public)
            setSignatureAlgorithm("SHA256WithRSA")
        }
        return gen.generate(kp.private, "BC")
    }

    private fun fingerprintHex(cert: X509Certificate): String =
        MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }

    @Test
    fun `pinned certificate matches registered fingerprint including case-insensitive`() {
        val cert = selfSigned()
        val fp = fingerprintHex(cert)
        assertTrue(WebDavCloud.pinnedCertificateMatches(arrayOf(cert), fp))
        assertTrue(WebDavCloud.pinnedCertificateMatches(arrayOf(cert), fp.uppercase()))
        // 重放：同一证书再次呈现仍匹配（幂等）
        assertTrue(WebDavCloud.pinnedCertificateMatches(arrayOf(cert), fp))
    }

    @Test
    fun `empty or changed fingerprint is rejected`() {
        val cert = selfSigned()
        assertFalse(WebDavCloud.pinnedCertificateMatches(arrayOf(cert), ""))
        assertFalse(WebDavCloud.pinnedCertificateMatches(arrayOf(cert), "00".repeat(32)))
    }

    @Test
    fun `certificate with different fingerprint is rejected regardless of hostname`() {
        // 指纹绑定而非主机名：不同证书（即使主机名相同）指纹不匹配即拒绝
        val certA = selfSigned()
        val certB = selfSigned()
        val fpA = fingerprintHex(certA)
        assertFalse(WebDavCloud.pinnedCertificateMatches(arrayOf(certB), fpA))
    }

    @Test
    fun `validate rejects cleartext http url`() {
        assertThrows(IllegalArgumentException::class.java) {
            WebDavCloud.validate(WebDavConfig("t", "http://example.com/dav/x.pmv", "", ""))
        }
        // https 通过协议校验（其余字段满足最小约束）
        WebDavCloud.validate(WebDavConfig("t", "https://example.com/dav/x.pmv", "", ""))
    }
}
