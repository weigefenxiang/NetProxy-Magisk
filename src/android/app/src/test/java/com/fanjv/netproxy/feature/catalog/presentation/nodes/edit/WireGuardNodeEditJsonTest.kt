package com.fanjv.netproxy.feature.catalog.presentation.nodes.edit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WireGuardNodeEditJsonTest {
    @Test
    fun `wireguard endpoint is selected when outbounds are empty`() {
        val document = parseWireGuardNodeDocument(
            """
            {
              "outbounds": [],
              "endpoints": [
                {
                  "type": "wireguard",
                  "tag": "wg-test",
                  "address": ["10.0.0.2/32"],
                  "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "peers": [
                    {
                      "address": "198.51.100.10",
                      "port": 51820,
                      "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                      "allowed_ips": ["0.0.0.0/0"]
                    }
                  ]
                }
              ]
            }
            """.trimIndent()
        )

        assertNotNull(document)
        val values = document!!.editorValues()
        assertEquals("wg-test", values.tag)
        assertEquals("10.0.0.2/32", values.localAddresses)
        assertEquals("198.51.100.10", values.server)
        assertEquals("51820", values.serverPort)
        assertEquals("0.0.0.0/0", values.allowedIps)
    }

    @Test
    fun `wireguard update stays in endpoints and preserves unedited fields`() {
        val document = parseWireGuardNodeDocument(
            """
            {
              "outbounds": [],
              "endpoints": [
                {
                  "type": "wireguard",
                  "tag": "wg-old",
                  "address": ["10.0.0.2/32"],
                  "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "listen_port": 12345,
                  "udp_timeout": "5m",
                  "peers": [
                    {
                      "address": "198.51.100.10",
                      "port": 51820,
                      "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                      "allowed_ips": ["10.0.0.0/8"],
                      "persistent_keepalive_interval": 25
                    },
                    {
                      "address": "203.0.113.20",
                      "port": 51821,
                      "public_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
                      "allowed_ips": ["192.168.0.0/16"]
                    }
                  ]
                }
              ]
            }
            """.trimIndent()
        )!!

        val updated = document.updated(
            document.editorValues().copy(
                tag = "wg-new",
                server = "198.51.100.11",
                allowedIps = "0.0.0.0/0,::/0",
                mtu = "1408",
                reserved = "1,2,3"
            )
        )

        assertTrue((updated["outbounds"] as JsonArray).isEmpty())
        val endpoint = updated["endpoints"]!!.jsonArray.single().jsonObject
        assertEquals("wireguard", endpoint["type"]!!.jsonPrimitive.content)
        assertEquals("wg-new", endpoint["tag"]!!.jsonPrimitive.content)
        assertEquals(12345, endpoint["listen_port"]!!.jsonPrimitive.content.toInt())
        assertEquals("5m", endpoint["udp_timeout"]!!.jsonPrimitive.content)
        assertEquals(1408, endpoint["mtu"]!!.jsonPrimitive.content.toInt())

        val peers = endpoint["peers"]!!.jsonArray
        assertEquals(2, peers.size)
        val firstPeer = peers[0].jsonObject
        assertEquals("198.51.100.11", firstPeer["address"]!!.jsonPrimitive.content)
        assertEquals(
            listOf("0.0.0.0/0", "::/0"),
            firstPeer["allowed_ips"]!!.jsonArray.map { it.jsonPrimitive.content }
        )
        assertEquals(
            listOf(1, 2, 3),
            firstPeer["reserved"]!!.jsonArray.map { it.jsonPrimitive.content.toInt() }
        )
        assertEquals("203.0.113.20", peers[1].jsonObject["address"]!!.jsonPrimitive.content)
    }

    @Test
    fun `ordinary outbound is not treated as wireguard endpoint`() {
        val document = parseWireGuardNodeDocument(
            """
            {
              "outbounds": [
                {
                  "type": "vless",
                  "tag": "ordinary",
                  "server": "example.com",
                  "server_port": 443
                }
              ]
            }
            """.trimIndent()
        )

        assertEquals(null, document)
    }
}
