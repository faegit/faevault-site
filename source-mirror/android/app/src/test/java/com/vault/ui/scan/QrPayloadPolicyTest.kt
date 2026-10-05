package com.vault.ui.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class QrPayloadPolicyTest {
    @Test
    fun purposeRejectsUnrelatedQrPayloads() {
        val otp = "otpauth://totp/Account?secret=JBSWY3DPEHPK3PXP"
        val wifi = "WIFI:T:WPA;S:Home;P:password;;"

        assertTrue(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_OTP, otp))
        assertFalse(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_OTP, wifi))
        assertTrue(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_WIFI, wifi))
        assertFalse(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_WIFI, otp))
    }

    @Test
    fun syncQrRequiresHttpsAndSingleTicket() {
        assertEquals(
            QrPayloadPolicy.SyncPairing("https://192.168.1.5:8443?ticket=abcdef1234567890", null),
            QrPayloadPolicy.parseSync("https://192.168.1.5:8443/sync?ticket=abcdef1234567890"),
        )
        assertNull(QrPayloadPolicy.parseSync("http://192.168.1.5/sync?ticket=abcdef1234567890"))
        assertNull(QrPayloadPolicy.parseSync("https://host/sync?ticket=short"))
        assertNull(QrPayloadPolicy.parseSync("https://host/sync?ticket=abcdef1234567890&ticket=zyxwv9876543210"))
        assertNull(QrPayloadPolicy.parseSync("https://host/sync?pin=123456"))
    }

    @Test
    fun syncQrExtractsEmbeddedPin() {
        // 同步二维码内嵌一次性 6 位 PIN：扫码即免输 PIN
        assertEquals(
            QrPayloadPolicy.SyncPairing("https://192.168.1.5:8443?ticket=abcdef1234567890", "123456"),
            QrPayloadPolicy.parseSync("https://192.168.1.5:8443/sync?ticket=abcdef1234567890&pin=123456"),
        )
        // PIN 非 6 位数字时不提取（仍返回配对信息，由调用方决定是否要求手动输入）
        assertEquals(
            QrPayloadPolicy.SyncPairing("https://192.168.1.5:8443?ticket=abcdef1234567890", null),
            QrPayloadPolicy.parseSync("https://192.168.1.5:8443/sync?ticket=abcdef1234567890&pin=12"),
        )
        assertEquals(
            QrPayloadPolicy.SyncPairing("https://192.168.1.5:8443?ticket=abcdef1234567890", null),
            QrPayloadPolicy.parseSync("https://192.168.1.5:8443/sync?ticket=abcdef1234567890&pin=abcdef"),
        )
        // 重复 pin 参数视为非法，不提取
        assertEquals(
            QrPayloadPolicy.SyncPairing("https://192.168.1.5:8443?ticket=abcdef1234567890", null),
            QrPayloadPolicy.parseSync("https://192.168.1.5:8443/sync?ticket=abcdef1234567890&pin=123456&pin=654321"),
        )
    }

    @Test
    fun otpPurposeRejectsUnsupportedOtpKinds() {
        assertFalse(
            QrPayloadPolicy.accepts(
                QrLiveScanActivity.PURPOSE_OTP,
                "otpauth://steam/Account?secret=JBSWY3DPEHPK3PXP",
            ),
        )
    }

    @Test
    fun importPurposeAcceptsOnlyTransferStationQr() {
        // 导入只认当前传输站二维码（整库导出通道），旧 vault-import:// 专用导入码一律拒绝
        assertTrue(
            QrPayloadPolicy.accepts(
                QrLiveScanActivity.PURPOSE_IMPORT,
                "https://192.168.1.5/sync?ticket=abcdef1234567890&pin=123456",
            ),
        )
        assertFalse(
            QrPayloadPolicy.accepts(
                QrLiveScanActivity.PURPOSE_IMPORT,
                "vault-import://192.168.1.5:18765?v=2&sid=sess_qr00012345&secret=K3f9Lp2xR7qW8zN4tY5uC1vM6bH0jD",
            ),
        )
        // 其他用途的二维码 / 非传输站协议一律拒绝
        assertFalse(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_IMPORT, "otpauth://totp/Account?secret=JBSWY3DPEHPK3PXP"))
        assertFalse(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_IMPORT, "WIFI:T:WPA;S:Home;P:password;;"))
        assertFalse(QrPayloadPolicy.accepts(QrLiveScanActivity.PURPOSE_IMPORT, "https://host/sync?ticket=short"))
    }
}
