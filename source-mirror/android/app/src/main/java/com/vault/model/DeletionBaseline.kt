package com.vault.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.util.UUID

@Serializable
data class DeletionBaseline(
    @SerialName("schema_version") val schemaVersion: Int = 1,
    val generation: Long = 0,
    val epoch: String = "",
    val checkpoint: DeletionCheckpoint? = null,
) {
    fun validate() {
        require(schemaVersion == 1 && generation >= 0 && (if (generation == 0L) epoch.isEmpty() else canonical(epoch))) { "不支持的删除记录基线，请更新应用" }
        checkpoint?.let { c ->
            require(canonical(c.checkpointId) && c.memberIds.isNotEmpty() && c.memberIds.distinct().size == c.memberIds.size && c.memberIds.all(::canonical)) { "删除记录检查点无效" }
            require(c.purgeSnapshot.all { canonical(it.key) && it.value.isFinite() && it.value >= 0 }) { "删除记录检查点无效" }
            require(c.acknowledgements.all { it.key in c.memberIds && it.value == c.checkpointId }) { "删除记录确认无效" }
        }
    }
    companion object {
        private fun canonical(s: String) = runCatching { UUID.fromString(s).toString() == s }.getOrDefault(false)
        fun requireCompatible(local: DeletionBaseline, remote: DeletionBaseline) {
            local.validate(); remote.validate()
            require(local.generation == remote.generation && local.epoch == remote.epoch) { "删除记录基线不一致，请单独恢复旧备份，不能合并" }
        }
        fun acceptedFloor(previous: DeletionBaseline?, candidate: DeletionBaseline): DeletionBaseline {
            candidate.validate()
            previous?.validate()
            if (previous != null && candidate.generation <= previous.generation) requireCompatible(previous, candidate)
            return candidate.copy(checkpoint = null)
        }
        fun merge(local: DeletionBaseline, remote: DeletionBaseline): DeletionBaseline {
            requireCompatible(local, remote)
            val a = local.checkpoint; val b = remote.checkpoint
            if (a == null) return remote
            if (b == null) return local
            if (a.checkpointId != b.checkpointId || a.purgeSnapshot != b.purgeSnapshot || a.memberIds.toSet() != b.memberIds.toSet()) return local.copy(checkpoint = null)
            return local.copy(checkpoint = a.copy(acknowledgements = a.acknowledgements + b.acknowledgements))
        }
    }
}

@Serializable
data class DeletionCheckpoint(
    @SerialName("checkpoint_id") val checkpointId: String,
    @SerialName("purge_snapshot") val purgeSnapshot: Map<String, Double>,
    @SerialName("member_ids") val memberIds: List<String>,
    val acknowledgements: Map<String, String> = emptyMap(),
) {
    fun matches(purges: Map<String, Double>, members: List<String>): Boolean =
        purgeSnapshot == purges && memberIds.toSet() == members.toSet()
    fun ready(purges: Map<String, Double>, members: List<String>): Boolean =
        purges.isNotEmpty() && matches(purges, members) && memberIds.all { acknowledgements[it] == checkpointId }
}

data class DeletionCleanupState(
    val purgeCount: Int,
    val memberIds: List<String>,
    val acknowledgedIds: Set<String>,
    val checkpointId: String?,
    val ready: Boolean,
    val supported: Boolean,
)
