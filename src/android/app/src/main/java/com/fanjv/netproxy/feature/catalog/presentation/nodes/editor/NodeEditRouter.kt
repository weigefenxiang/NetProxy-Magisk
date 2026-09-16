package com.fanjv.netproxy.feature.catalog.presentation.nodes.editor

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.fanjv.netproxy.feature.catalog.presentation.nodes.CatalogNodesViewModel
import com.fanjv.netproxy.feature.catalog.presentation.nodes.edit.SingBoxNodeEditScreen as StandardNodeEditScreen
import com.fanjv.netproxy.feature.catalog.presentation.nodes.edit.WireGuardNodeEditScreen
import com.fanjv.netproxy.feature.catalog.presentation.nodes.edit.parseWireGuardNodeDocument

/** 根据节点文档类型分发到普通 Outbound 或 WireGuard Endpoint 编辑器。 */
@Composable
internal fun SingBoxNodeEditScreen(
    viewModel: CatalogNodesViewModel,
    nodeRef: String,
    onBack: () -> Unit
) {
    var loaded by remember(nodeRef) { mutableStateOf(false) }
    var documentContent by remember(nodeRef) { mutableStateOf<String?>(null) }

    LaunchedEffect(nodeRef) {
        documentContent = runCatching { viewModel.loadNodeConfigContent(nodeRef) }.getOrNull()
        loaded = true
    }

    if (!loaded) {
        Box(modifier = Modifier.fillMaxSize())
        return
    }

    val content = documentContent
    if (content != null && parseWireGuardNodeDocument(content) != null) {
        WireGuardNodeEditScreen(
            viewModel = viewModel,
            nodeRef = nodeRef,
            documentContent = content,
            onBack = onBack
        )
    } else {
        StandardNodeEditScreen(
            viewModel = viewModel,
            nodeRef = nodeRef,
            onBack = onBack
        )
    }
}
