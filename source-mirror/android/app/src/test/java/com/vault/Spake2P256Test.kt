package com.vault

import com.vault.storage.Spake2P256
import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class Spake2P256Test {
    @Test
    fun pinDerivationMatchesPcImplementation() {
        assertEquals(
            BigInteger("885e0a1bc149d6164b73066bb8b6f2aea914ac6451879cf2b1ebc93dd1b3e5e7", 16),
            Spake2P256.deriveW("123456", "interop-ticket-123456"),
        )
    }

    @Test
    fun lanPairingTranscriptMatchesPcImplementation() {
        val ticket = "interop-ticket-123456"
        val fingerprint = "0123456789abcdef".repeat(4)
        val w = Spake2P256.deriveW("123456", ticket)
        val x = BigInteger("123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234", 16)
        val start = Spake2P256.start(w, x)
        assertEquals(
            "041d50449d096febd10982d8152d274cefbf3ee8d2a12850a6ac29099ca459be" +
                "efafbcf3b49da772685ec5f5cd94b7b118186f19267b4f157b993be9d0065975dc",
            start.share.toHex(),
        )
        val aad = "Vault LAN Sync SPAKE2 RFC9382 v1\u0000".toByteArray() +
            ticket.toByteArray() + byteArrayOf(0) + fingerprint.toByteArray()
        val result = Spake2P256.finish(
            start,
            hex(
                "04858cfa559db10a8d0316e5f31a8722727c9ad7c47a82cf43a842f6f96340578c" +
                    "68cc64c0bed185ef3e1badd6c6c9c83b5010ec51fec82cd1ffd797c194cd0298"
            ),
            "vault-android-client".toByteArray(),
            "vault-pc-server".toByteArray(),
            aad,
            ticket,
        )
        assertEquals("f153fc9dee820f62e8faec6154175f21fd08b146cad10719f7fc89270914cf30", result.confirmation.toHex())
        assertEquals("431b07bbcd19bec97974c69b92004ad7c8ce6bbc95dd5c01f2ff3e67ea8cae71", result.expectedServerConfirmation.toHex())
        assertEquals("72f28d9ed42f0f45b41130717a6b0f83c2946c29ac21795f0e88f44de7522530", result.sessionToken.toHex())
        result.clear()
    }

    @Test
    fun matchesRfc9382P256Vector() {
        val w = BigInteger("2ee57912099d31560b3a44b1184b9b4866e904c49d12ac5042c97dca461b1a5f", 16)
        val x = BigInteger("43dd0fd7215bdcb482879fca3220c6a968e66d70b1356cac18bb26c84a78d729", 16)
        val serverShare = hex(
            "0406557e482bd03097ad0cbaa5df82115460d951e3451962f1eaf4367a420676" +
                "d09857ccbc522686c83d1852abfa8ed6e4a1155cf8f1543ceca528afb591a1e0b7"
        )
        val start = Spake2P256.start(w, x)

        assertEquals(
            "04a56fa807caaa53a4d28dbb9853b9815c61a411118a6fe516a8798434751470" +
                "f9010153ac33d0d5f2047ffdb1a3e42c9b4e6be662766e1eeb4116988ede5f912c",
            start.share.toHex(),
        )
        val result = Spake2P256.finish(start, serverShare, "server".toByteArray(), "client".toByteArray(), byteArrayOf(), "ticket")
        assertArrayEquals(
            hex("58ad4aa88e0b60d5061eb6b5dd93e80d9c4f00d127c65b3b35b1b5281fee38f0"),
            result.confirmation,
        )
        assertArrayEquals(
            hex("d3e2e547f1ae04f2dbdbf0fc4b79f8ecff2dff314b5d32fe9fcef2fb26dc459b"),
            result.expectedServerConfirmation,
        )
        result.clear()
    }

    @Test
    fun androidServerPairsWithPcRoleClient() {
        // 安卓传输站（serverStart/serverFinish）与 PC 客户端角色（start/finish）必须配对成功：
        // 同一 PIN/ticket/AAD/身份常量下 confirmationA/B 完全一致。
        val ticket = "test-ticket-123456"
        val pin = "123456"
        val fingerprint = "35d70e96fedae1c49bde3cf0703f86a17f2ec35ad6aa2b9abbc10f792f2eda33"
        val aad = "Vault LAN Sync SPAKE2 RFC9382 v2\u0000sync\u0000$ticket\u0000$fingerprint".toByteArray()
        val clientId = "vault-android-client".toByteArray()
        val serverId = "vault-pc-server".toByteArray()

        val clientStart = Spake2P256.start(pin, ticket)
        val serverStart = Spake2P256.serverStart(pin, ticket)
        val serverResult = Spake2P256.serverFinish(
            serverStart, clientStart.share, clientId, serverId, aad, ticket,
        )
        val clientResult = Spake2P256.finish(
            clientStart, serverStart.share, clientId, serverId, aad, ticket,
        )
        try {
            assertArrayEquals("客户端 confirmationA 应与服务端校验值一致", clientResult.confirmation, serverResult.confirmationA)
            assertArrayEquals("客户端期望的 confirmationB 应与服务端发送值一致", clientResult.expectedServerConfirmation, serverResult.confirmationB)
            assertArrayEquals("会话令牌应一致", clientResult.sessionToken, serverResult.sessionToken)
        } finally {
            clientResult.clear()
            serverResult.clear()
        }
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
