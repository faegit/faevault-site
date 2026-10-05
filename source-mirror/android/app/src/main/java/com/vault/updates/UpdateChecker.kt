package com.vault.updates

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.HttpURLConnection
import java.net.URL

private const val RELEASES_API = "https://api.github.com/repos/faegit/faevault-site/releases?per_page=50"

/**
 * Release tag 前缀。Android 与 PC 共用 faegit/faevault-site 仓库但各自发版，
 * 因此不能用 releases/latest（会命中另一端的最新发布）；改为按前缀筛选。
 */
private const val RELEASE_TAG_PREFIX = "android/v"
private val VERSION = Regex("^v?(\\d+)\\.(\\d+)\\.(\\d+)(?:[-+].*)?$")

data class UpdateInfo(
    val version: String,
    val notes: String,
    val pageUrl: String,
    val downloadUrl: String,
    val sha256: String? = null,
)

internal fun versionTuple(value: String): List<Int> =
    VERSION.matchEntire(value.trim())?.groupValues?.drop(1)?.map(String::toInt)
        ?: error("无效版本号")

fun isNewer(latest: String, current: String): Boolean {
    val left = versionTuple(latest)
    val right = versionTuple(current)
    return left.zip(right).firstOrNull { it.first != it.second }?.let { it.first > it.second } ?: false
}

internal fun parseRelease(raw: String, preferredAsset: String): UpdateInfo {
    val root = Json.parseToJsonElement(raw).jsonObject
    require(root["draft"]?.jsonPrimitive?.booleanOrNull != true && root["prerelease"]?.jsonPrimitive?.booleanOrNull != true) {
        "没有可用的正式版本"
    }
    // tag 形如 android/v4.6.2：先去掉端前缀，再去掉 v 前缀。
    val version = root["tag_name"]?.jsonPrimitive?.contentOrNull.orEmpty()
        .removePrefix(RELEASE_TAG_PREFIX)
        .removePrefix("v")
    versionTuple(version)
    val pageUrl = root["html_url"]?.jsonPrimitive?.contentOrNull.orEmpty()
    require(pageUrl.startsWith("https://github.com/faegit/faevault-site/releases/")) { "发布页面地址无效" }
    val assets = root["assets"]?.jsonArray ?: error("发布资产无效")
    val candidates = listOf(preferredAsset, "faevault-universal.apk")
    val asset = candidates.firstNotNullOfOrNull { expected ->
        assets.firstOrNull { it.jsonObject["name"]?.jsonPrimitive?.contentOrNull == expected }?.jsonObject
    } ?: error("未找到适合当前设备的 APK")
    val downloadUrl = asset["browser_download_url"]?.jsonPrimitive?.contentOrNull.orEmpty()
    require(downloadUrl.startsWith("https://github.com/faegit/faevault-site/releases/download/")) { "APK 下载地址无效" }
    val digest = parseAssetDigest(asset["digest"]?.jsonPrimitive?.contentOrNull)
    return UpdateInfo(version, root["body"]?.jsonPrimitive?.contentOrNull.orEmpty().trim(), pageUrl, downloadUrl, digest)
}

fun checkLatest(preferredAsset: String, timeoutMs: Int = 10_000): UpdateInfo {
    val connection = (URL(RELEASES_API).openConnection() as HttpURLConnection).apply {
        connectTimeout = timeoutMs
        readTimeout = timeoutMs
        requestMethod = "GET"
        setRequestProperty("Accept", "application/vnd.github+json")
        setRequestProperty("User-Agent", "FAEVault-Android-UpdateChecker")
        instanceFollowRedirects = false
    }
    return try {
        require(connection.responseCode == 200) { "更新服务返回 HTTP ${connection.responseCode}" }
        val raw = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
        require(raw.length <= 4_000_000) { "更新信息过大" }
        val latest = selectAndroidRelease(raw)
            ?: error("没有找到可用的正式版本")
        parseRelease(latest, preferredAsset)
    } finally {
        connection.disconnect()
    }
}

/**
 * 从 releases 列表里挑出本端最新的正式发布：tag 带 [RELEASE_TAG_PREFIX] 前缀，
 * 非草稿、非预发布，并按版本号从高到低排序（列表顺序不保证与版本顺序一致）。
 */
internal fun selectAndroidRelease(raw: String): String? {
    val releases: List<JsonObject> = Json.parseToJsonElement(raw).jsonArray.mapNotNull { element ->
        element as? JsonObject
    }
    // 版本号编码成单个可比较整数（4.6.2 → 40602），非法版本为 0 排在末尾。
    fun versionKey(release: JsonObject): Int {
        val version = release["tag_name"]?.jsonPrimitive?.contentOrNull.orEmpty()
            .removePrefix(RELEASE_TAG_PREFIX)
            .removePrefix("v")
        val parts = runCatching { versionTuple(version) }.getOrNull()?.takeIf { it.size == 3 }
            ?: return 0
        return parts[0] * 1_000_000 + parts[1] * 1_000 + parts[2]
    }
    return releases
        .filter { release ->
            val tag = release["tag_name"]?.jsonPrimitive?.contentOrNull
            tag != null && tag.startsWith(RELEASE_TAG_PREFIX) &&
                release["draft"]?.jsonPrimitive?.booleanOrNull != true &&
                release["prerelease"]?.jsonPrimitive?.booleanOrNull != true
        }
        .maxByOrNull { release -> versionKey(release) }
        ?.toString()
}

internal fun parseAssetDigest(value: String?): String? {
    if (value == null) return null // Historical releases may predate GitHub asset digests.
    require(Regex("sha256:[0-9a-fA-F]{64}").matches(value)) { "Invalid APK SHA-256 digest" }
    return value.substringAfter(':').lowercase()
}

internal fun requireTrustedDownloadUrl(url: URL) {
    require(url.protocol == "https" && url.userInfo == null && (url.port == -1 || url.port == 443) &&
        url.host.lowercase() in setOf("github.com", "objects.githubusercontent.com",
            "release-assets.githubusercontent.com", "github-releases.githubusercontent.com")) {
        "Untrusted APK download redirect"
    }
}

internal fun verifyAssetDigest(actual: ByteArray, expected: String?) {
    if (expected == null) return
    require(Regex("[0-9a-fA-F]{64}").matches(expected)) { "Invalid APK digest" }
    val wanted = ByteArray(32) { expected.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    require(java.security.MessageDigest.isEqual(actual, wanted)) { "APK SHA-256 mismatch" }
}
