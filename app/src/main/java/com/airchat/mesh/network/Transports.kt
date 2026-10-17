package com.airchat.mesh.network

import java.util.UUID

/** Local radio transports managed by the mesh engine. */
enum class TransportType {
    WIFI_DIRECT,
    LOCAL_HOTSPOT,
    BLUETOOTH_CLASSIC,
    BLE
}

/** Application-level packet types carried inside a [MeshPacket]. */
enum class PacketType {
    HANDSHAKE,      // identity announcement / X3DH bundle exchange
    ROUTE_UPDATE,   // AODV RREQ/RREP + routing-table deltas
    TEXT_MESSAGE,   // Double-Ratchet ciphertext
    MEDIA_CHUNK,    // chunked media transfer
    CALL_SIGNAL     // voice-call signalling
}

/**
 * Unit of transfer on the mesh. Relays only inspect the envelope
 * (source / destination / hopCount); the payload stays end-to-end encrypted.
 *
 * Custom equals/hashCode because [encryptedPayload] and [signature] are [ByteArray].
 */
data class MeshPacket(
    val packetId: UUID = UUID.randomUUID(),
    val sourceNodeId: String,
    val destinationNodeId: String,
    val relayNodeId: String?,
    val hopCount: Int = 0,
    val packetType: PacketType,
    val encryptedPayload: ByteArray,
    val signature: ByteArray,
    val timestamp: Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MeshPacket) return false
        return packetId == other.packetId &&
            sourceNodeId == other.sourceNodeId &&
            destinationNodeId == other.destinationNodeId &&
            relayNodeId == other.relayNodeId &&
            hopCount == other.hopCount &&
            packetType == other.packetType &&
            encryptedPayload.contentEquals(other.encryptedPayload) &&
            signature.contentEquals(other.signature) &&
            timestamp == other.timestamp
    }

    override fun hashCode(): Int {
        var result = packetId.hashCode()
        result = 31 * result + sourceNodeId.hashCode()
        result = 31 * result + destinationNodeId.hashCode()
        result = 31 * result + (relayNodeId?.hashCode() ?: 0)
        result = 31 * result + hopCount
        result = 31 * result + packetType.hashCode()
        result = 31 * result + encryptedPayload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        result = 31 * result + timestamp.hashCode()
        return result
    }
}

/** Contract implemented by [AirChatMeshEngine]. */
interface MeshNetworkManager {
    fun startPeerDiscovery()
    fun establishP2PLink(targetNodeId: String, preferredTransport: TransportType)
    fun routePacket(packet: MeshPacket)
    fun broadcastRoutingTableUpdate(routingTableJson: String)
}
