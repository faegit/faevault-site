package com.vault.storage

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.IDN
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.Locale
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * 自动填充快速索引的固定大小明文页。
 *
 * 此页应作为独立 PMV Block 使用并由 SearchIndexKey 之外的索引加密密钥保护。
 * 页面只暴露不可逆的 keyed lookup token 和候选 Entry ID，不保存任何条目 payload。
 */
object PmvLoginFastIndex {
    const val PAGE_SIZE = 16 * 1024

    private const val VERSION = 1
    private const val HEADER_SIZE = 32
    private const val RECORD_SIZE = 56
    private const val TOKEN_SIZE = 32
    private const val MAX_RECORDS = (PAGE_SIZE - HEADER_SIZE) / RECORD_SIZE
    private val MAGIC = "PMLF".encodeToByteArray()
    private const val ROOT_RECORD_SIZE = 120
    private const val MAX_ROOT_RANGES = (PAGE_SIZE - HEADER_SIZE) / ROOT_RECORD_SIZE
    private val ROOT_MAGIC = "PMLR".encodeToByteArray()
    private val LEAF_DIGEST_DOMAIN = "pmv/v1/login-fast-leaf\u0000".encodeToByteArray()
    private val ROOT_DIGEST_DOMAIN = "pmv/v1/login-fast-root\u0000".encodeToByteArray()
    private val TOKEN_PREFIX = "pmv/v1/login-fast-index\u0000".encodeToByteArray()
    private val PACKAGE_PATTERN = Regex("^[a-z][a-z0-9_]*(?:\\.[a-z0-9_]+)+$")
    private val IPV4_PATTERN = Regex("^\\d{1,3}(?:\\.\\d{1,3}){3}$")

    enum class EntryType(val id: Int) {
        LOGIN(1),
        PASSKEY(2),
        ;

        companion object {
            internal fun fromId(id: Int): EntryType = entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("LoginFastIndex Entry 类型无效")
        }
    }

    enum class State(val id: Int) {
        ACTIVE(1),
        TOMBSTONE(2),
        ;

        companion object {
            internal fun fromId(id: Int): State = entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("LoginFastIndex 状态无效")
        }
    }

    enum class LookupKind(val id: Int) {
        DOMAIN(1),
        PACKAGE(2),
        RP_ID(3),
        ;

        companion object {
            internal fun fromId(id: Int): LookupKind = entries.firstOrNull { it.id == id }
                ?: throw IllegalArgumentException("LoginFastIndex token 类型无效")
        }
    }

    class Record(
        val entryId: UUID,
        val entryType: EntryType,
        val state: State,
        val lookupKind: LookupKind,
        lookupToken: ByteArray,
    ) {
        private val token = lookupToken.copyOf()

        init {
            require(token.size == TOKEN_SIZE) { "LoginFastIndex token 必须为 HMAC-SHA256" }
        }

        val lookupToken: ByteArray
            get() = token.copyOf()

        internal fun tokenUnsafe(): ByteArray = token
    }

    class Page(records: List<Record>) {
        val records: List<Record> = records.toList()

        init {
            require(this.records.size <= MAX_RECORDS) { "LoginFastIndex 记录数超过页容量" }
            require(this.records.zipWithNext().all { (left, right) -> compareRecords(left, right) < 0 }) {
                "LoginFastIndex 记录必须严格排序且 token/Entry ID 不能重复"
            }
        }

        /** 返回当前页中与 token 对应的活跃候选 ID；不会读取或返回条目字段。 */
        fun query(kind: LookupKind, token: ByteArray): List<UUID> {
            require(token.size == TOKEN_SIZE) { "LoginFastIndex 查询 token 长度无效" }
            var low = 0
            var high = records.size
            while (low < high) {
                val middle = (low + high).ushr(1)
                val comparison = compareLookup(records[middle], kind, token)
                if (comparison < 0) low = middle + 1 else high = middle
            }
            val result = ArrayList<UUID>()
            var index = low
            while (index < records.size && compareLookup(records[index], kind, token) == 0) {
                val record = records[index++]
                if (record.state == State.ACTIVE) result += record.entryId
            }
            return result
        }
    }

    data class PageLocation(val offset: Long, val length: Long) {
        init {
            require(offset >= PmvContainerFormat.DATA_START) { "LoginFastIndex 页偏移无效" }
            require(length > 0) { "LoginFastIndex 页长度无效" }
            require(offset <= Long.MAX_VALUE - length) { "LoginFastIndex 页范围溢出" }
        }
    }

    class PageRange(
        val minKind: LookupKind,
        minToken: ByteArray,
        val maxKind: LookupKind,
        maxToken: ByteArray,
        val pageOffset: Long,
        val pageLength: Long,
        pageLogicalDigest: ByteArray,
    ) {
        private val minimum = minToken.copyOf()
        private val maximum = maxToken.copyOf()
        private val digest = pageLogicalDigest.copyOf()

        init {
            require(minimum.size == TOKEN_SIZE && maximum.size == TOKEN_SIZE) { "LoginFastIndex 根范围 token 长度无效" }
            require(compareLookupKeys(minKind, minimum, maxKind, maximum) <= 0) { "LoginFastIndex 根范围上下界无效" }
            PageLocation(pageOffset, pageLength)
            require(digest.size == 32 && digest.any { it != 0.toByte() }) { "LoginFastIndex 叶页摘要无效" }
        }

        val minToken: ByteArray get() = minimum.copyOf()
        val maxToken: ByteArray get() = maximum.copyOf()
        val pageLogicalDigest: ByteArray get() = digest.copyOf()
        internal fun minTokenUnsafe(): ByteArray = minimum
        internal fun maxTokenUnsafe(): ByteArray = maximum
        internal fun digestUnsafe(): ByteArray = digest

        override fun equals(other: Any?): Boolean = other is PageRange && minKind == other.minKind &&
            minimum.contentEquals(other.minimum) && maxKind == other.maxKind && maximum.contentEquals(other.maximum) &&
            pageOffset == other.pageOffset && pageLength == other.pageLength && digest.contentEquals(other.digest)

        override fun hashCode(): Int = ((((((minKind.hashCode() * 31 + minimum.contentHashCode()) * 31 +
            maxKind.hashCode()) * 31 + maximum.contentHashCode()) * 31 + pageOffset.hashCode()) * 31 +
            pageLength.hashCode()) * 31) + digest.contentHashCode()
    }

    class Root(ranges: List<PageRange>) {
        val ranges = ranges.toList()

        init {
            require(this.ranges.isNotEmpty()) { "LoginFastIndex 根不能为空" }
            require(this.ranges.size <= MAX_ROOT_RANGES) { "LoginFastIndex 根范围数超过页容量" }
            require(this.ranges.zipWithNext().all { (left, right) ->
                compareLookupKeys(left.maxKind, left.maxTokenUnsafe(), right.minKind, right.minTokenUnsafe()) < 0
            }) { "LoginFastIndex 根范围必须严格排序且不重叠" }
        }

        override fun equals(other: Any?): Boolean = other is Root && ranges == other.ranges
        override fun hashCode(): Int = ranges.hashCode()
    }

    class Plan(pages: List<Page>, val root: Root?) {
        val pages = pages.toList()
        init {
            require((this.pages.isEmpty() && root == null) ||
                (this.pages.isNotEmpty() && root != null && this.pages.size == root.ranges.size)) {
                "LoginFastIndex 计划中的页与根不一致"
            }
        }
    }

    fun encode(page: Page): ByteArray =
        ByteBuffer.allocate(PAGE_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            put(MAGIC)
            putInt(VERSION)
            putInt(PAGE_SIZE)
            putInt(page.records.size)
            putLong(0)
            putLong(0)
            page.records.forEach { record ->
                putLong(record.entryId.mostSignificantBits)
                putLong(record.entryId.leastSignificantBits)
                put(record.entryType.id.toByte())
                put(record.state.id.toByte())
                put(record.lookupKind.id.toByte())
                put(ByteArray(5))
                put(record.tokenUnsafe())
            }
        }.array()

    fun decode(raw: ByteArray): Page {
        require(raw.size == PAGE_SIZE) { "LoginFastIndex 页大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        val magic = ByteArray(MAGIC.size).also(input::get)
        require(magic.contentEquals(MAGIC)) { "LoginFastIndex magic 无效" }
        require(input.int == VERSION) { "LoginFastIndex 版本无效" }
        require(input.int == PAGE_SIZE) { "LoginFastIndex 声明页大小无效" }
        val count = input.int
        require(count in 0..MAX_RECORDS) { "LoginFastIndex 记录数无效" }
        require(input.long == 0L && input.long == 0L) { "LoginFastIndex Header 保留字段非零" }

        val records = ArrayList<Record>(count)
        repeat(count) {
            require(input.remaining() >= RECORD_SIZE) { "LoginFastIndex 记录被截断" }
            val entryId = UUID(input.long, input.long)
            val entryType = EntryType.fromId(input.get().toInt() and 0xff)
            val state = State.fromId(input.get().toInt() and 0xff)
            val kind = LookupKind.fromId(input.get().toInt() and 0xff)
            repeat(5) { require(input.get() == 0.toByte()) { "LoginFastIndex Record 保留字段非零" } }
            records += Record(entryId, entryType, state, kind, ByteArray(TOKEN_SIZE).also(input::get))
        }
        while (input.hasRemaining()) {
            require(input.get() == 0.toByte()) { "LoginFastIndex 页尾保留字段非零" }
        }
        return Page(records)
    }

    /** Canonically sorts and partitions records without ever splitting one lookup-token group. */
    fun buildPages(records: List<Record>): List<Page> {
        if (records.isEmpty()) return emptyList()
        val sorted = records.sortedWith { left, right -> compareRecords(left, right) }
        require(sorted.zipWithNext().all { (left, right) -> compareRecords(left, right) < 0 }) {
            "LoginFastIndex 记录必须唯一"
        }
        val pages = ArrayList<Page>()
        val current = ArrayList<Record>(MAX_RECORDS)
        var index = 0
        while (index < sorted.size) {
            var end = index + 1
            while (end < sorted.size && compareLookup(sorted[index], sorted[end].lookupKind, sorted[end].tokenUnsafe()) == 0) end++
            val groupSize = end - index
            require(groupSize <= MAX_RECORDS) { "LoginFastIndex 单个 token 组超过页容量" }
            if (current.isNotEmpty() && current.size + groupSize > MAX_RECORDS) {
                pages += Page(current.toList())
                current.clear()
            }
            current += sorted.subList(index, end)
            index = end
        }
        if (current.isNotEmpty()) pages += Page(current)
        require(pages.size <= MAX_ROOT_RANGES) { "LoginFastIndex 多页根容量不足" }
        return pages
    }

    fun buildRoot(page: Page, location: PageLocation): Root = buildRoot(listOf(page), listOf(location))

    fun buildRoot(pages: List<Page>, locations: List<PageLocation>): Root {
        require(pages.isNotEmpty() && pages.size == locations.size) { "LoginFastIndex 页与位置数量不匹配" }
        val ranges = pages.zip(locations).map { (page, location) ->
            require(page.records.isNotEmpty()) { "LoginFastIndex 多页叶页不能为空" }
            val first = page.records.first()
            val last = page.records.last()
            PageRange(first.lookupKind, first.tokenUnsafe(), last.lookupKind, last.tokenUnsafe(),
                location.offset, location.length, logicalDigest(page))
        }
        return Root(ranges)
    }

    fun buildPlan(records: List<Record>, firstPageOffset: Long, pageStoredLength: Long): Plan {
        val pages = buildPages(records)
        if (pages.isEmpty()) return Plan(emptyList(), null)
        require(firstPageOffset >= PmvContainerFormat.DATA_START && pageStoredLength > 0) { "LoginFastIndex 页布局无效" }
        val locations = pages.indices.map { pageIndex ->
            require(pageIndex.toLong() <= (Long.MAX_VALUE - firstPageOffset) / pageStoredLength) {
                "LoginFastIndex 页布局超出 signed 64-bit 范围"
            }
            PageLocation(firstPageOffset + pageIndex.toLong() * pageStoredLength, pageStoredLength)
        }
        return Plan(pages, buildRoot(pages, locations))
    }

    fun encodeRoot(root: Root): ByteArray = ByteBuffer.allocate(PAGE_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
        put(ROOT_MAGIC); putInt(VERSION); putInt(PAGE_SIZE); putInt(root.ranges.size); putLong(0); putLong(0)
        root.ranges.forEach { range ->
            put(range.minKind.id.toByte()); put(range.maxKind.id.toByte()); put(ByteArray(6))
            put(range.minTokenUnsafe()); put(range.maxTokenUnsafe())
            putLong(range.pageOffset); putLong(range.pageLength); put(range.digestUnsafe())
        }
    }.array()

    fun decodeRoot(raw: ByteArray): Root {
        require(raw.size == PAGE_SIZE) { "LoginFastIndex 根页大小无效" }
        val input = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        require(ByteArray(4).also(input::get).contentEquals(ROOT_MAGIC)) { "LoginFastIndex 根 magic 无效" }
        require(input.int == VERSION && input.int == PAGE_SIZE) { "LoginFastIndex 根 Header 无效" }
        val count = input.int
        require(count in 1..MAX_ROOT_RANGES) { "LoginFastIndex 根范围数无效" }
        require(input.long == 0L && input.long == 0L) { "LoginFastIndex 根 Header 保留字段非零" }
        val ranges = ArrayList<PageRange>(count)
        repeat(count) {
            val minKind = LookupKind.fromId(input.get().toInt() and 0xff)
            val maxKind = LookupKind.fromId(input.get().toInt() and 0xff)
            repeat(6) { require(input.get() == 0.toByte()) { "LoginFastIndex 根记录保留字段非零" } }
            ranges += PageRange(minKind, ByteArray(TOKEN_SIZE).also(input::get),
                maxKind, ByteArray(TOKEN_SIZE).also(input::get), input.long, input.long,
                ByteArray(32).also(input::get))
        }
        while (input.hasRemaining()) require(input.get() == 0.toByte()) { "LoginFastIndex 根页尾保留字段非零" }
        return Root(ranges)
    }

    /** Physical leaf offsets are excluded; every logical record field is bound. */
    fun logicalDigest(page: Page): ByteArray = digestCanonical(LEAF_DIGEST_DOMAIN) { out ->
        out.writeInt(page.records.size)
        page.records.forEach { record ->
            out.writeByte(record.lookupKind.id); out.write(record.tokenUnsafe())
            out.writeLong(record.entryId.mostSignificantBits); out.writeLong(record.entryId.leastSignificantBits)
            out.writeByte(record.entryType.id); out.writeByte(record.state.id)
        }
    }

    /** Physical leaf offsets are excluded; page length, range keys, and leaf logical digests are bound. */
    fun logicalDigest(root: Root): ByteArray = digestCanonical(ROOT_DIGEST_DOMAIN) { out ->
        out.writeInt(root.ranges.size)
        root.ranges.forEach { range ->
            out.writeByte(range.minKind.id); out.write(range.minTokenUnsafe())
            out.writeByte(range.maxKind.id); out.write(range.maxTokenUnsafe())
            out.writeLong(range.pageLength); out.write(range.digestUnsafe())
        }
    }

    fun locate(root: Root, kind: LookupKind, token: ByteArray): PageRange? {
        require(token.size == TOKEN_SIZE) { "LoginFastIndex 查询 token 长度无效" }
        var low = 0
        var high = root.ranges.size
        while (low < high) {
            val middle = (low + high).ushr(1)
            val range = root.ranges[middle]
            if (compareLookupKeys(range.maxKind, range.maxTokenUnsafe(), kind, token) < 0) low = middle + 1
            else high = middle
        }
        if (low >= root.ranges.size) return null
        val range = root.ranges[low]
        return range.takeIf { compareLookupKeys(kind, token, it.minKind, it.minTokenUnsafe()) >= 0 }
    }

    fun query(root: Root, kind: LookupKind, token: ByteArray, loadPage: (PageRange) -> Page): List<UUID> {
        val range = locate(root, kind, token) ?: return emptyList()
        val page = loadPage(range)
        require(page.records.isNotEmpty()) { "LoginFastIndex 根引用了空叶页" }
        require(MessageDigest.isEqual(logicalDigest(page), range.digestUnsafe())) { "LoginFastIndex 叶页逻辑摘要不一致" }
        val first = page.records.first(); val last = page.records.last()
        require(compareLookupKeys(first.lookupKind, first.tokenUnsafe(), range.minKind, range.minTokenUnsafe()) == 0 &&
            compareLookupKeys(last.lookupKind, last.tokenUnsafe(), range.maxKind, range.maxTokenUnsafe()) == 0) {
            "LoginFastIndex 叶页范围与根不一致"
        }
        return page.query(kind, token)
    }

    fun domainToken(searchIndexKey: ByteArray, domain: String): ByteArray =
        lookupToken(searchIndexKey, LookupKind.DOMAIN, normalizeDomain(domain))

    fun packageToken(searchIndexKey: ByteArray, packageName: String): ByteArray =
        lookupToken(searchIndexKey, LookupKind.PACKAGE, normalizePackage(packageName))

    fun rpIdToken(searchIndexKey: ByteArray, rpId: String): ByteArray =
        lookupToken(searchIndexKey, LookupKind.RP_ID, normalizeRpId(rpId))

    /** 精确域名优先，然后逐级查找至少包含两个 label 的父域；结果按该优先级去重。 */
    fun queryDomain(page: Page, searchIndexKey: ByteArray, domain: String): List<UUID> {
        val normalized = normalizeDomain(domain)
        val candidates = parentDomainCandidates(normalized)
        val result = linkedSetOf<UUID>()
        candidates.forEach { candidate ->
            result += page.query(LookupKind.DOMAIN, lookupToken(searchIndexKey, LookupKind.DOMAIN, candidate))
        }
        return result.toList()
    }

    fun queryPackage(page: Page, searchIndexKey: ByteArray, packageName: String): List<UUID> =
        page.query(LookupKind.PACKAGE, packageToken(searchIndexKey, packageName))

    fun queryRpId(page: Page, searchIndexKey: ByteArray, rpId: String): List<UUID> =
        page.query(LookupKind.RP_ID, rpIdToken(searchIndexKey, rpId))

    fun queryDomain(root: Root, searchIndexKey: ByteArray, domain: String, loadPage: (PageRange) -> Page): List<UUID> {
        val normalized = normalizeDomain(domain)
        val result = linkedSetOf<UUID>()
        parentDomainCandidates(normalized).forEach { candidate ->
            result += query(root, LookupKind.DOMAIN, lookupToken(searchIndexKey, LookupKind.DOMAIN, candidate), loadPage)
        }
        return result.toList()
    }

    fun queryPackage(root: Root, searchIndexKey: ByteArray, packageName: String, loadPage: (PageRange) -> Page): List<UUID> =
        query(root, LookupKind.PACKAGE, packageToken(searchIndexKey, packageName), loadPage)

    fun queryRpId(root: Root, searchIndexKey: ByteArray, rpId: String, loadPage: (PageRange) -> Page): List<UUID> =
        query(root, LookupKind.RP_ID, rpIdToken(searchIndexKey, rpId), loadPage)

    fun normalizeDomain(raw: String): String = normalizeHost(raw, removeWww = true, label = "域名")

    fun normalizeRpId(raw: String): String = normalizeHost(raw, removeWww = false, label = "RP ID")

    fun normalizePackage(raw: String): String {
        val normalized = raw.trim().lowercase(Locale.ROOT)
        require(normalized.length in 3..255 && PACKAGE_PATTERN.matches(normalized)) { "package 名称无效" }
        return normalized
    }

    private fun lookupToken(searchIndexKey: ByteArray, kind: LookupKind, normalized: String): ByteArray {
        require(searchIndexKey.size == TOKEN_SIZE) { "SearchIndexKey 必须为 32 字节" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(searchIndexKey, "HmacSHA256"))
        mac.update(TOKEN_PREFIX)
        mac.update(kind.id.toByte())
        mac.update(normalized.encodeToByteArray())
        return mac.doFinal()
    }

    private fun normalizeHost(raw: String, removeWww: Boolean, label: String): String {
        val cleaned = raw.trim().trimEnd('.').lowercase(Locale.ROOT)
        require(cleaned.isNotEmpty() && !cleaned.contains('/') && !cleaned.contains(':')) { "$label 无效" }
        val ascii = runCatching { IDN.toASCII(cleaned, IDN.USE_STD3_ASCII_RULES) }
            .getOrElse { throw IllegalArgumentException("$label 无效", it) }
            .lowercase(Locale.ROOT)
        require(ascii.length <= 253 && !IPV4_PATTERN.matches(ascii)) { "$label 无效" }
        require(ascii.split('.').let { labels ->
            labels.size >= 2 && labels.all { it.isNotEmpty() && it.length <= 63 }
        }) { "$label 无效" }
        val normalized = if (removeWww) ascii.removePrefix("www.") else ascii
        require(normalized.contains('.')) { "$label 无效" }
        return normalized
    }

    private fun parentDomainCandidates(normalized: String): List<String> {
        val labels = normalized.split('.')
        return (0..labels.size - 2).map { labels.drop(it).joinToString(".") }
    }

    private fun compareRecords(left: Record, right: Record): Int {
        val kind = left.lookupKind.id.compareTo(right.lookupKind.id)
        if (kind != 0) return kind
        val token = compareBytes(left.tokenUnsafe(), right.tokenUnsafe())
        if (token != 0) return token
        return compareUuid(left.entryId, right.entryId)
    }

    private fun compareLookup(record: Record, kind: LookupKind, token: ByteArray): Int {
        val kindComparison = record.lookupKind.id.compareTo(kind.id)
        return if (kindComparison != 0) kindComparison else compareBytes(record.tokenUnsafe(), token)
    }

    private fun compareLookupKeys(leftKind: LookupKind, leftToken: ByteArray, rightKind: LookupKind, rightToken: ByteArray): Int {
        val kind = leftKind.id.compareTo(rightKind.id)
        return if (kind != 0) kind else compareBytes(leftToken, rightToken)
    }

    private inline fun digestCanonical(domain: ByteArray, write: (DataOutputStream) -> Unit): ByteArray {
        val canonical = ByteArrayOutputStream().use { buffer ->
            DataOutputStream(buffer).use { out -> out.write(domain); write(out) }
            buffer.toByteArray()
        }
        return try { MessageDigest.getInstance("SHA-256").digest(canonical) } finally { canonical.fill(0) }
    }

    private fun compareUuid(left: UUID, right: UUID): Int {
        val most = java.lang.Long.compareUnsigned(left.mostSignificantBits, right.mostSignificantBits)
        return if (most != 0) most else java.lang.Long.compareUnsigned(left.leastSignificantBits, right.leastSignificantBits)
    }

    private fun compareBytes(left: ByteArray, right: ByteArray): Int {
        for (index in left.indices) {
            val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return 0
    }
}
