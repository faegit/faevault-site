package com.vault.storage

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/** Fixed 16 KiB object-manifest and chunk lookup leaves plus multi-page range roots. */
object PmvObjectIndexCodec {
    const val PAGE_SIZE = 16 * 1024
    private const val VERSION = 1
    private const val HEADER_SIZE = 32
    private const val OBJECT_RECORD_SIZE = 112
    private const val CHUNK_RECORD_SIZE = 128
    private const val ROOT_RECORD_SIZE = 104
    private val DATA_START = PmvContainerFormat.DATA_START
    private val OBJECT_MAGIC = "PMOI".encodeToByteArray()
    private val CHUNK_MAGIC = "PMCI".encodeToByteArray()
    private val OBJECT_ROOT_MAGIC = "PMOR".encodeToByteArray()
    private val CHUNK_ROOT_MAGIC = "PMCR".encodeToByteArray()

    data class ObjectKey(val objectId: UUID, val generation: Long) : Comparable<ObjectKey> {
        init { require(generation >= 0) { "Object generation 无效" } }
        override fun compareTo(other: ObjectKey): Int = compareValuesBy(this, other, { it.objectId.toString() }, { it.generation })
    }
    data class ChunkKey(val objectId: UUID, val generation: Long, val chunkIndex: Int) : Comparable<ChunkKey> {
        init { require(generation >= 0 && chunkIndex >= 0) { "Chunk key 无效" } }
        override fun compareTo(other: ChunkKey): Int = compareValuesBy(this, other,
            { it.objectId.toString() }, { it.generation }, { it.chunkIndex })
    }
    data class ObjectRecord(val key: ObjectKey, val manifestOffset: Long, val manifestLength: Long,
        val plainDigest: ByteArray, val cipherDigest: ByteArray) {
        init { validateLocation(manifestOffset, manifestLength); digest(plainDigest); digest(cipherDigest) }
        override fun equals(other: Any?) = other is ObjectRecord && key == other.key &&
            manifestOffset == other.manifestOffset && manifestLength == other.manifestLength &&
            plainDigest.contentEquals(other.plainDigest) && cipherDigest.contentEquals(other.cipherDigest)
        override fun hashCode() = ((((key.hashCode()*31+manifestOffset.hashCode())*31+manifestLength.hashCode())*31+
            plainDigest.contentHashCode())*31)+cipherDigest.contentHashCode()
    }
    data class ChunkRecord(val key: ChunkKey, val blockOffset: Long, val blockLength: Long,
        val plainDigest: ByteArray, val cipherDigest: ByteArray) {
        init { validateLocation(blockOffset, blockLength); digest(plainDigest); digest(cipherDigest) }
        override fun equals(other: Any?) = other is ChunkRecord && key == other.key && blockOffset == other.blockOffset &&
            blockLength == other.blockLength && plainDigest.contentEquals(other.plainDigest) && cipherDigest.contentEquals(other.cipherDigest)
        override fun hashCode() = ((((key.hashCode()*31+blockOffset.hashCode())*31+blockLength.hashCode())*31+
            plainDigest.contentHashCode())*31)+cipherDigest.contentHashCode()
    }
    data class ObjectPage(val records: List<ObjectRecord>) {
        init { sortedUnique(records.map { it.key }); require(records.size <= (PAGE_SIZE-HEADER_SIZE)/OBJECT_RECORD_SIZE) }
        fun find(key: ObjectKey): ObjectRecord? = binaryFind(records, key) { it.key }
    }
    data class ChunkPage(val records: List<ChunkRecord>) {
        init { sortedUnique(records.map { it.key }); require(records.size <= (PAGE_SIZE-HEADER_SIZE)/CHUNK_RECORD_SIZE) }
        fun find(key: ChunkKey): ChunkRecord? = binaryFind(records, key) { it.key }
    }
    data class RangeRecord<K : Comparable<K>>(val minKey: K, val maxKey: K, val pageOffset: Long, val pageDigest: ByteArray) {
        init { require(minKey <= maxKey); require(pageOffset >= DATA_START); digest(pageDigest) }
        override fun equals(other: Any?) = other is RangeRecord<*> && minKey == other.minKey && maxKey == other.maxKey &&
            pageOffset == other.pageOffset && pageDigest.contentEquals(other.pageDigest)
        override fun hashCode() = (((minKey.hashCode()*31+maxKey.hashCode())*31+pageOffset.hashCode())*31)+pageDigest.contentHashCode()
    }
    data class RangeRoot<K : Comparable<K>>(val records: List<RangeRecord<K>>) {
        init {
            require(records.size <= (PAGE_SIZE - HEADER_SIZE) / ROOT_RECORD_SIZE)
            require(records.map { it.pageOffset }.toSet().size == records.size)
            require(records.zipWithNext().all { it.first.maxKey < it.second.minKey })
        }
        fun findPage(key: K): RangeRecord<K>? { var lo=0; var hi=records.lastIndex; while(lo<=hi){val m=(lo+hi).ushr(1); val r=records[m]; if(key<r.minKey)hi=m-1 else if(key>r.maxKey)lo=m+1 else return r}; return null }
    }
    data class ExistingPage<K : Comparable<K>>(val minKey: K, val maxKey: K, val offset: Long, val digest: ByteArray)
    data class PlannedPage<P>(val page: P, val digest: ByteArray, val reusedOffset: Long?)

    fun encodeObjectPage(page: ObjectPage) = pageBuffer(OBJECT_MAGIC, page.records.size).apply { page.records.forEach { r ->
        putObjectKey(r.key); putLong(r.manifestOffset); putLong(r.manifestLength); put(r.plainDigest); put(r.cipherDigest); putLong(0)
    }}.array()
    fun decodeObjectPage(raw: ByteArray): ObjectPage { val input=readHeader(raw,OBJECT_MAGIC,(PAGE_SIZE-HEADER_SIZE)/OBJECT_RECORD_SIZE); val count=input.second; val b=input.first
        val records=List(count){ ObjectRecord(ObjectKey(b.uuid(),b.long),b.long,b.long,ByteArray(32).also(b::get),ByteArray(32).also(b::get)).also { require(b.long==0L) } }; zeroTail(b); return ObjectPage(records) }
    fun encodeChunkPage(page: ChunkPage) = pageBuffer(CHUNK_MAGIC,page.records.size).apply { page.records.forEach { r ->
        putChunkKey(r.key); putInt(0); putLong(r.blockOffset); putLong(r.blockLength); put(r.plainDigest); put(r.cipherDigest); putLong(0); putLong(0)
    }}.array()
    fun decodeChunkPage(raw: ByteArray): ChunkPage { val input=readHeader(raw,CHUNK_MAGIC,(PAGE_SIZE-HEADER_SIZE)/CHUNK_RECORD_SIZE); val count=input.second; val b=input.first
        val records=List(count){ val key=ChunkKey(b.uuid(),b.long,b.int); require(b.int==0); ChunkRecord(key,b.long,b.long,ByteArray(32).also(b::get),ByteArray(32).also(b::get)).also { require(b.long==0L&&b.long==0L) } }; zeroTail(b); return ChunkPage(records) }

    fun encodeObjectRoot(root: RangeRoot<ObjectKey>) = encodeRoot(root, OBJECT_ROOT_MAGIC, 16) { putObjectKey(it) }
    fun decodeObjectRoot(raw: ByteArray) = decodeRoot(raw, OBJECT_ROOT_MAGIC, 16, { ObjectKey(it.uuid(),it.long) })
    fun encodeChunkRoot(root: RangeRoot<ChunkKey>) = encodeRoot(root, CHUNK_ROOT_MAGIC, 8) { putChunkKey(it) }
    fun decodeChunkRoot(raw: ByteArray) = decodeRoot(raw, CHUNK_ROOT_MAGIC, 8, { ChunkKey(it.uuid(),it.long,it.int) })

    fun objectPageDigest(page: ObjectPage)=canonical("pmv/v1/object-index-page\u0000",page.records){r->writeUuid(r.key.objectId);writeLong(r.key.generation);writeLong(r.manifestLength);write(r.plainDigest);write(r.cipherDigest)}
    fun chunkPageDigest(page: ChunkPage)=canonical("pmv/v1/chunk-index-page\u0000",page.records){r->writeUuid(r.key.objectId);writeLong(r.key.generation);writeInt(r.key.chunkIndex);writeLong(r.blockLength);write(r.plainDigest);write(r.cipherDigest)}
    fun objectRootDigest(root: RangeRoot<ObjectKey>)=rootDigest("pmv/v1/object-index-root\u0000",root){writeUuid(it.objectId);writeLong(it.generation)}
    fun chunkRootDigest(root: RangeRoot<ChunkKey>)=rootDigest("pmv/v1/chunk-index-root\u0000",root){writeUuid(it.objectId);writeLong(it.generation);writeInt(it.chunkIndex)}

    fun planObjectPages(records: List<ObjectRecord>, previous: List<ExistingPage<ObjectKey>> = emptyList()): List<PlannedPage<ObjectPage>> {
        sortedUnique(records.map { it.key })
        return records.chunked((PAGE_SIZE-HEADER_SIZE)/OBJECT_RECORD_SIZE).map { chunk -> val p=ObjectPage(chunk); plan(p,objectPageDigest(p),chunk.first().key,chunk.last().key,previous) }
    }
    fun planChunkPages(records: List<ChunkRecord>, previous: List<ExistingPage<ChunkKey>> = emptyList()): List<PlannedPage<ChunkPage>> {
        sortedUnique(records.map { it.key })
        return records.chunked((PAGE_SIZE-HEADER_SIZE)/CHUNK_RECORD_SIZE).map { chunk -> val p=ChunkPage(chunk); plan(p,chunkPageDigest(p),chunk.first().key,chunk.last().key,previous) }
    }

    private fun <P,K:Comparable<K>> plan(page:P,d:ByteArray,min:K,max:K,old:List<ExistingPage<K>>) = PlannedPage(page,d,old.firstOrNull{it.minKey==min&&it.maxKey==max&&MessageDigest.isEqual(it.digest,d)}?.offset)
    private fun <K:Comparable<K>> encodeRoot(root:RangeRoot<K>,magic:ByteArray,padding:Int,keyWriter:ByteBuffer.(K)->Unit)=pageBuffer(magic,root.records.size).apply{root.records.forEach{keyWriter(it.minKey);keyWriter(it.maxKey);putLong(it.pageOffset);put(it.pageDigest);repeat(padding){put(0)}}}.array()
    private fun <K:Comparable<K>> decodeRoot(raw:ByteArray,magic:ByteArray,padding:Int,keyReader:(ByteBuffer)->K):RangeRoot<K>{val (b,n)=readHeader(raw,magic,(PAGE_SIZE-HEADER_SIZE)/ROOT_RECORD_SIZE);val out=List(n){val record=RangeRecord(keyReader(b),keyReader(b),b.long,ByteArray(32).also(b::get));repeat(padding){require(b.get()==0.toByte())};record};zeroTail(b);return RangeRoot(out)}
    private fun pageBuffer(magic:ByteArray,count:Int)=ByteBuffer.allocate(PAGE_SIZE).order(ByteOrder.BIG_ENDIAN).apply{put(magic);putInt(VERSION);putInt(PAGE_SIZE);putInt(count);putLong(0);putLong(0)}
    private fun readHeader(raw:ByteArray,magic:ByteArray,max:Int):Pair<ByteBuffer,Int>{require(raw.size==PAGE_SIZE);val b=ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);require(ByteArray(4).also(b::get).contentEquals(magic));require(b.int==VERSION&&b.int==PAGE_SIZE);val n=b.int;require(n in 0..max);require(b.long==0L&&b.long==0L);return b to n}
    private fun zeroTail(b:ByteBuffer){while(b.hasRemaining())require(b.get()==0.toByte())}
    private fun ByteBuffer.putObjectKey(k:ObjectKey){putLong(k.objectId.mostSignificantBits);putLong(k.objectId.leastSignificantBits);putLong(k.generation)}
    private fun ByteBuffer.putChunkKey(k:ChunkKey){putObjectKey(ObjectKey(k.objectId,k.generation));putInt(k.chunkIndex)}
    private fun ByteBuffer.uuid()=UUID(long,long)
    private fun <K:Comparable<K>> sortedUnique(keys:List<K>){require(keys.zipWithNext().all{it.first<it.second})}
    private fun <T,K:Comparable<K>> binaryFind(records:List<T>,key:K,keyOf:(T)->K):T?{var lo=0;var hi=records.lastIndex;while(lo<=hi){val m=(lo+hi).ushr(1);val c=keyOf(records[m]);if(c<key)lo=m+1 else if(c>key)hi=m-1 else return records[m]};return null}
    private fun validateLocation(o:Long,l:Long){require(o>=DATA_START&&l>0)}
    private fun digest(d:ByteArray){require(d.size==32)}
    private fun <T> canonical(domain:String,items:List<T>,write:DataOutputStream.(T)->Unit):ByteArray{val raw=ByteArrayOutputStream().use{buf->DataOutputStream(buf).use{out->out.write(domain.encodeToByteArray());out.writeInt(items.size);items.forEach{v->write.invoke(out,v)}};buf.toByteArray()};return MessageDigest.getInstance("SHA-256").digest(raw)}
    private fun <K:Comparable<K>> rootDigest(domain:String,root:RangeRoot<K>,writeKey:DataOutputStream.(K)->Unit)=canonical(domain,root.records){r->writeKey.invoke(this,r.minKey);writeKey.invoke(this,r.maxKey);write(r.pageDigest)}
    private fun DataOutputStream.writeUuid(v:UUID){writeLong(v.mostSignificantBits);writeLong(v.leastSignificantBits)}
}
