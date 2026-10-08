package com.vault.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.vault.R
import com.vault.model.DeletionCleanupState
import com.vault.ui.VaultShape
import com.vault.ui.VaultViewModel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
internal fun DeletionCleanupCard(vm: VaultViewModel) {
    val vault by vm.state.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var status by remember { mutableStateOf<DeletionCleanupState?>(null) }
    var deviceNames by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var expanded by remember { mutableStateOf(false) }
    var confirmCheckpoint by remember { mutableStateOf<String?>(null) }
    var acknowledged by remember { mutableStateOf(false) }
    suspend fun refresh() {
        status = null
        busy = true
        error = null
        try {
            deviceNames = vm.deviceProfiles().associate { it.deviceId to it.name }
            status = vm.deletionCleanupState()
        }
        catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: Exception) { error = failure.message }
        finally { busy = false }
    }
    fun operate(cleanup: String? = null) {
        scope.launch {
            busy = true
            status = null
            error = null
            try {
                if (cleanup == null) vm.startDeletionCleanupCheckpoint()
                else vm.executeDeletionCleanup(cleanup)
                refresh()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) { val message = failure.message; refresh(); error = message }
            finally { busy = false }
        }
    }
    LaunchedEffect(vault.payload, vault.credential) {
        confirmCheckpoint = null
        acknowledged = false
        refresh()
    }
    Card(shape = VaultShape, colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(stringResource(R.string.deletion_cleanup_title) + if (expanded) " −" else " +",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.fillMaxWidth().clickable { expanded = !expanded }.padding(vertical = 4.dp))
            Text(stringResource(R.string.deletion_cleanup_description), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            if (expanded) {
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                status?.let { current ->
                    Text(stringResource(R.string.deletion_cleanup_count, current.purgeCount))
                    Text(stringResource(R.string.deletion_cleanup_progress, current.acknowledgedIds.size, current.memberIds.size))
                    current.memberIds.forEach { device ->
                        Text((deviceNames[device]?.takeIf { it.isNotBlank() } ?: device) + " · " + stringResource(if (device in current.acknowledgedIds)
                            R.string.deletion_cleanup_device_ack else R.string.deletion_cleanup_device_waiting),
                            style = MaterialTheme.typography.bodySmall)
                    }
                    Text(stringResource(when {
                        !current.supported -> R.string.deletion_cleanup_unsupported
                        current.purgeCount == 0 -> R.string.deletion_cleanup_empty
                        current.ready -> R.string.deletion_cleanup_ready
                        else -> R.string.deletion_cleanup_waiting
                    }), style = MaterialTheme.typography.bodySmall)
                    VaultActionButton(onClick = { operate() }, enabled = !busy && current.supported && current.purgeCount > 0) {
                        Text(stringResource(R.string.deletion_cleanup_start))
                    }
                }
                VaultActionButton(onClick = { scope.launch { refresh() } }, enabled = !busy) {
                    Text(stringResource(R.string.deletion_cleanup_refresh))
                }
                VaultActionButton(onClick = { confirmCheckpoint = status?.checkpointId; acknowledged = false },
                    style = VaultActionStyle.DANGER,
                    enabled = !busy && status?.supported == true && status?.ready == true && status?.purgeCount != 0) {
                    Text(stringResource(R.string.deletion_cleanup_title))
                }
            }
        }
    }
    if (confirmCheckpoint != null) VaultDialog(
        onDismissRequest = { confirmCheckpoint = null },
        title = { Text(stringResource(R.string.deletion_cleanup_confirm)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.deletion_cleanup_count, status?.purgeCount ?: 0))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = acknowledged, onCheckedChange = { acknowledged = it })
                    Text(stringResource(R.string.deletion_cleanup_ack), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            VaultActionButton(onClick = { val checkpoint = confirmCheckpoint; confirmCheckpoint = null; if (checkpoint != null) operate(checkpoint) },
                style = VaultActionStyle.DANGER,
                enabled = acknowledged && !busy && status?.ready == true && status?.checkpointId == confirmCheckpoint) {
                Text(stringResource(R.string.deletion_cleanup_confirm))
            }
        },
        dismissButton = { VaultActionButton(onClick = { confirmCheckpoint = null }) { Text(stringResource(R.string.cancel)) } },
    )
}
