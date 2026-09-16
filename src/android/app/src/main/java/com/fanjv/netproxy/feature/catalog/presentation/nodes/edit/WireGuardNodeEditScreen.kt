package com.fanjv.netproxy.feature.catalog.presentation.nodes.edit

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.fanjv.netproxy.R
import com.fanjv.netproxy.core.ui.component.AdaptiveTopAppBar
import com.fanjv.netproxy.core.ui.component.AppSnackbarHost
import com.fanjv.netproxy.core.ui.component.BlurredBar
import com.fanjv.netproxy.core.ui.component.rememberAppSnackbarHostState
import com.fanjv.netproxy.core.ui.component.rememberBlurBackdrop
import com.fanjv.netproxy.feature.catalog.presentation.nodes.CatalogNodesViewModel
import com.fanjv.netproxy.feature.catalog.presentation.nodes.edit.components.ActionButtons
import com.fanjv.netproxy.feature.catalog.presentation.nodes.edit.components.EditorField
import com.fanjv.netproxy.feature.catalog.presentation.nodes.edit.components.ValidationPanel
import kotlinx.serialization.json.Json
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.MiuixScrollBehavior
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.SmallTitle
import top.yukonga.miuix.kmp.blur.layerBackdrop
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

/** WireGuard Endpoint 编辑页，只修改首个 Peer 的常用字段并保留其余 Endpoint 数据。 */
@Composable
internal fun WireGuardNodeEditScreen(
    viewModel: CatalogNodesViewModel,
    nodeRef: String,
    documentContent: String,
    onBack: () -> Unit
) {
    val document = remember(documentContent) { parseWireGuardNodeDocument(documentContent) }
        ?: return
    val initial = remember(documentContent) { document.editorValues() }
    val focusManager = LocalFocusManager.current
    val backdrop = rememberBlurBackdrop()
    val barColor = if (backdrop != null) Color.Transparent else colorScheme.surface
    val scrollBehavior = MiuixScrollBehavior()
    val snackbarHostState = rememberAppSnackbarHostState()
    val saveFailed = stringResource(R.string.save_failed_check_permission)

    var notice by remember { mutableStateOf("") }
    var noticeId by remember { mutableStateOf(0L) }
    var tag by remember(documentContent) { mutableStateOf(initial.tag) }
    var localAddresses by remember(documentContent) { mutableStateOf(initial.localAddresses) }
    var privateKey by remember(documentContent) { mutableStateOf(initial.privateKey) }
    var mtu by remember(documentContent) { mutableStateOf(initial.mtu) }
    var workers by remember(documentContent) { mutableStateOf(initial.workers) }
    var server by remember(documentContent) { mutableStateOf(initial.server) }
    var serverPort by remember(documentContent) { mutableStateOf(initial.serverPort) }
    var publicKey by remember(documentContent) { mutableStateOf(initial.publicKey) }
    var preSharedKey by remember(documentContent) { mutableStateOf(initial.preSharedKey) }
    var allowedIps by remember(documentContent) { mutableStateOf(initial.allowedIps) }
    var keepalive by remember(documentContent) { mutableStateOf(initial.keepalive) }
    var reserved by remember(documentContent) { mutableStateOf(initial.reserved) }

    ValidationPanel(
        eventId = noticeId,
        message = notice,
        isError = true,
        hostState = snackbarHostState,
        onConsumed = { notice = "" }
    )

    fun showError(message: String) {
        notice = message
        noticeId++
    }

    Scaffold(
        snackbarHost = { AppSnackbarHost(snackbarHostState) },
        topBar = {
            BlurredBar(backdrop) {
                AdaptiveTopAppBar(
                    color = barColor,
                    title = "编辑 WireGuard 节点",
                    scrollBehavior = scrollBehavior,
                    navigationIcon = {
                        IconButton(onClick = onBack) {
                            Icon(
                                imageVector = Icons.AutoMirrored.Rounded.ArrowBack,
                                contentDescription = stringResource(R.string.back),
                                tint = colorScheme.onBackground
                            )
                        }
                    },
                    actions = {
                        ActionButtons(onSave = {
                            when {
                                tag.isBlank() -> showError("节点名称不能为空")
                                localAddresses.listValuesForValidation().isEmpty() ->
                                    showError("WireGuard 本地地址不能为空")
                                privateKey.isBlank() -> showError("WireGuard 私钥不能为空")
                                server.isBlank() -> showError("服务器地址不能为空")
                                serverPort.toIntOrNull()?.let { it in 1..65535 } != true ->
                                    showError("服务器端口必须是 1-65535 的数字")
                                publicKey.isBlank() -> showError("WireGuard 公钥不能为空")
                                !optionalIntValid(mtu, 1, Int.MAX_VALUE) ->
                                    showError("MTU 必须是正整数")
                                !optionalIntValid(workers, 1, Int.MAX_VALUE) ->
                                    showError("Workers 必须是正整数")
                                !optionalIntValid(keepalive, 0, 65535) ->
                                    showError("Persistent Keepalive 必须是 0-65535 的整数")
                                !reservedValid(reserved) ->
                                    showError("Reserved 只能填写 0-255 的整数，并用逗号分隔")
                                else -> {
                                    val updated = document.updated(
                                        WireGuardEditorValues(
                                            tag = tag,
                                            localAddresses = localAddresses,
                                            privateKey = privateKey,
                                            mtu = mtu,
                                            workers = workers,
                                            server = server,
                                            serverPort = serverPort,
                                            publicKey = publicKey,
                                            preSharedKey = preSharedKey,
                                            allowedIps = allowedIps,
                                            keepalive = keepalive,
                                            reserved = reserved
                                        )
                                    )
                                    val outString = Json { prettyPrint = true }.encodeToString(updated)
                                    viewModel.saveNodeConfigContent(nodeRef, outString) { success ->
                                        if (success) {
                                            onBack()
                                        } else {
                                            showError(saveFailed)
                                        }
                                    }
                                }
                            }
                        })
                    }
                )
            }
        }
    ) { innerPadding ->
        Box(modifier = if (backdrop != null) Modifier.layerBackdrop(backdrop) else Modifier) {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .scrollEndHaptic()
                    .overScrollVertical()
                    .nestedScroll(scrollBehavior.nestedScrollConnection),
                contentPadding = innerPadding,
                overscrollEffect = null
            ) {
                item {
                    SmallTitle(
                        text = "基础设置 · WireGuard",
                        insideMargin = PaddingValues(
                            start = 26.dp,
                            top = 12.dp,
                            bottom = 8.dp,
                            end = 26.dp
                        )
                    )
                }
                item { EditorField(tag, "节点名称 (Tag)", { tag = it }) { focusManager.clearFocus() } }
                item {
                    EditorField(
                        localAddresses,
                        "本地地址 (Address，逗号分隔)",
                        { localAddresses = it }
                    ) { focusManager.clearFocus() }
                }
                item {
                    EditorField(privateKey, "私钥 (Private Key)", { privateKey = it }) {
                        focusManager.clearFocus()
                    }
                }
                item { EditorField(mtu, "MTU（可选）", { mtu = it }) { focusManager.clearFocus() } }
                item {
                    EditorField(workers, "Workers（可选）", { workers = it }) {
                        focusManager.clearFocus()
                    }
                }

                item {
                    SmallTitle(
                        text = "Peer 设置",
                        insideMargin = PaddingValues(
                            start = 26.dp,
                            top = 8.dp,
                            bottom = 8.dp,
                            end = 26.dp
                        )
                    )
                }
                item {
                    EditorField(server, stringResource(R.string.server_address_label), { server = it }) {
                        focusManager.clearFocus()
                    }
                }
                item {
                    EditorField(serverPort, stringResource(R.string.server_port_label), { serverPort = it }) {
                        focusManager.clearFocus()
                    }
                }
                item {
                    EditorField(publicKey, "公钥 (Public Key)", { publicKey = it }) {
                        focusManager.clearFocus()
                    }
                }
                item {
                    EditorField(preSharedKey, "预共享密钥 (Pre-shared Key，可选)", { preSharedKey = it }) {
                        focusManager.clearFocus()
                    }
                }
                item {
                    EditorField(allowedIps, "Allowed IPs（逗号分隔）", { allowedIps = it }) {
                        focusManager.clearFocus()
                    }
                }
                item {
                    EditorField(keepalive, "Persistent Keepalive（秒，可选）", { keepalive = it }) {
                        focusManager.clearFocus()
                    }
                }
                item {
                    EditorField(reserved, "Reserved（0-255，逗号分隔，可选）", { reserved = it }) {
                        focusManager.clearFocus()
                    }
                }
                item { Spacer(modifier = Modifier.height(24.dp)) }
            }
        }
    }
}

private fun String.listValuesForValidation(): List<String> =
    split(',', '\n').map(String::trim).filter(String::isNotEmpty)

private fun optionalIntValid(value: String, min: Int, max: Int): Boolean {
    if (value.isBlank()) return true
    return value.trim().toIntOrNull()?.let { it in min..max } == true
}

private fun reservedValid(value: String): Boolean =
    value.listValuesForValidation().all { token ->
        token.toIntOrNull()?.let { it in 0..255 } == true
    }
