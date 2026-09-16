package com.fanjv.netproxy.feature.catalog.presentation.nodes.edit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

internal data class WireGuardNodeDocument(
    val root: JsonObject,
    val endpoint: JsonObject,
    val wrapped: Boolean
)

internal data class WireGuardEditorValues(
    val tag: String = "",
    val localAddresses: String = "",
    val privateKey: String = "",
    val mtu: String = "",
    val workers: String = "",
    val server: String = "",
    val serverPort: String = "",
    val publicKey: String = "",
    val preSharedKey: String = "",
    val allowedIps: String = "",
    val keepalive: String = "",
    val reserved: String = ""
)

internal fun parseWireGuardNodeDocument(content: String): WireGuardNodeDocument? {
    val root = runCatching { Json.parseToJsonElement(content).jsonObject }.getOrNull() ?: return null
    val endpoint = (root["endpoints"] as? JsonArray)
        ?.firstOrNull()
        ?.let { it as? JsonObject }
    if (endpoint?.get("type")?.jsonPrimitive?.contentOrNull == "wireguard") {
        return WireGuardNodeDocument(root = root, endpoint = endpoint, wrapped = true)
    }
    if (root["type"]?.jsonPrimitive?.contentOrNull == "wireguard") {
        return WireGuardNodeDocument(root = root, endpoint = root, wrapped = false)
    }
    return null
}

internal fun WireGuardNodeDocument.editorValues(): WireGuardEditorValues {
    val peers = endpoint["peers"] as? JsonArray
    val peer = peers?.firstOrNull()?.let { it as? JsonObject }
    return WireGuardEditorValues(
        tag = endpoint["tag"]?.jsonPrimitive?.contentOrNull.orEmpty(),
        localAddresses = endpoint["address"].listableStrings().joinToString(","),
        privateKey = endpoint["private_key"]?.jsonPrimitive?.contentOrNull.orEmpty(),
        mtu = endpoint["mtu"].intText(),
        workers = endpoint["workers"].intText(),
        server = peer?.get("address")?.jsonPrimitive?.contentOrNull.orEmpty(),
        serverPort = peer?.get("port").intText(),
        publicKey = peer?.get("public_key")?.jsonPrimitive?.contentOrNull.orEmpty(),
        preSharedKey = peer?.get("pre_shared_key")?.jsonPrimitive?.contentOrNull.orEmpty(),
        allowedIps = peer?.get("allowed_ips").listableStrings().joinToString(","),
        keepalive = peer?.get("persistent_keepalive_interval").intText(),
        reserved = (peer?.get("reserved") as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.intOrNull }
            ?.joinToString(",")
            .orEmpty()
    )
}

internal fun WireGuardNodeDocument.updated(values: WireGuardEditorValues): JsonObject {
    val endpointMap = endpoint.toMutableMap()
    endpointMap["type"] = JsonPrimitive("wireguard")
    endpointMap["tag"] = JsonPrimitive(values.tag.trim())
    endpointMap["address"] = values.localAddresses.toStringListJson()
    endpointMap["private_key"] = JsonPrimitive(values.privateKey.trim())
    endpointMap.putOptionalInt("mtu", values.mtu)
    endpointMap.putOptionalInt("workers", values.workers)

    val originalPeers = endpoint["peers"] as? JsonArray
    val firstPeer = originalPeers?.firstOrNull()?.let { it as? JsonObject }
    val peerMap = firstPeer?.toMutableMap() ?: mutableMapOf()
    peerMap["address"] = JsonPrimitive(values.server.trim())
    peerMap["port"] = JsonPrimitive(values.serverPort.trim().toInt())
    peerMap["public_key"] = JsonPrimitive(values.publicKey.trim())
    peerMap.putOptionalString("pre_shared_key", values.preSharedKey)
    peerMap.putOptionalStringList("allowed_ips", values.allowedIps)
    peerMap.putOptionalInt("persistent_keepalive_interval", values.keepalive)
    peerMap.putOptionalByteList("reserved", values.reserved)

    val updatedPeers = buildList<JsonElement> {
        add(JsonObject(peerMap))
        originalPeers?.drop(1)?.let(::addAll)
    }
    endpointMap["peers"] = JsonArray(updatedPeers)
    val updatedEndpoint = JsonObject(endpointMap)

    if (!wrapped) return updatedEndpoint
    val rootMap = root.toMutableMap()
    rootMap["endpoints"] = JsonArray(listOf(updatedEndpoint))
    return JsonObject(rootMap)
}

private fun JsonElement?.intText(): String =
    (this as? JsonPrimitive)?.intOrNull?.toString().orEmpty()

private fun String.listValues(): List<String> =
    split(',', '\n').map(String::trim).filter(String::isNotEmpty)

private fun String.toStringListJson(): JsonArray =
    JsonArray(listValues().map(::JsonPrimitive))

private fun MutableMap<String, JsonElement>.putOptionalString(key: String, value: String) {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) remove(key) else this[key] = JsonPrimitive(trimmed)
}

private fun MutableMap<String, JsonElement>.putOptionalStringList(key: String, value: String) {
    val values = value.listValues()
    if (values.isEmpty()) remove(key) else this[key] = JsonArray(values.map(::JsonPrimitive))
}

private fun MutableMap<String, JsonElement>.putOptionalInt(key: String, value: String) {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) {
        remove(key)
    } else {
        this[key] = JsonPrimitive(trimmed.toInt())
    }
}

private fun MutableMap<String, JsonElement>.putOptionalByteList(key: String, value: String) {
    val values = value.listValues()
    if (values.isEmpty()) {
        remove(key)
    } else {
        this[key] = JsonArray(values.map { JsonPrimitive(it.toInt()) })
    }
}
