package com.vault.ui.media

import com.vault.ui.screens.VaultDialog
import com.vault.R
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * 批量导入媒体时的实时进度弹窗：不可取消，逐张展示真实处理进度。
 */
@Composable
fun MediaImportProgressDialog(
    done: Int,
    total: Int,
    label: String = "",
) {
    if (total <= 0) return
    val displayLabel = if (label.isBlank()) stringResource(R.string.system_media_importing) else label
    VaultDialog(
        onDismissRequest = {},
        confirmButton = {},
        text = {
            Column(Modifier.fillMaxWidth()) {
                Text("$displayLabel ${done.coerceIn(0, total)} / $total")
                Spacer(Modifier.height(12.dp))
                LinearProgressIndicator(
                    progress = { done.coerceIn(0, total).toFloat() / total },
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    stringResource(R.string.system_media_import_exit_warning),
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
    )
}
