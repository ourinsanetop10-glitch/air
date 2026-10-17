package com.airchat.mesh.routing

import com.airchat.mesh.network.MeshPacket
import com.airchat.mesh.network.PacketType
import com.airchat.mesh.network.TransportType
import org.json.JSONArray
import org.json.JSONObject
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/**
 * One entry of the AODV routing table: how to reach [destId] from here.
 */
data class RouteEntry(
    val destId: String,
    val nextHopId: String,
    val transport: TransportType,
    val hopCount: Int,
    val destSeqNum: Long,
    val expiresAt: Long = System.currentTimeMillis() + AodvRouter.ROUTE_TIMEOUT_MS
)

/**
 * Decentralised Ad-hoc On-Demand Distance Vector routing, implemented in
 * application space (no kernel / root required).
 *
 * Behaviour:
 * - Every packet carries a UUID; a 1000-entry LRU suppresses duplicates so
 *   floods terminate.
 * - Data packets use a fresh route when one exists, otherwise they are flooded
 *   (bounded by TTL) and a route discovery (RREQ) is issued. Discovered routes
 *   flush any buffered data packets waiting for that destination.
 * - RREQ/RREP ride inside ROUTE_UPDATE packets with text bodies:
 *   `RREQ|<wantedDest>|<seq>` and `RREP|<routeDest>|<destSeq>|<hops>`.
 * - Reverse routes are learned from every packet's source, so RREPs unicast
 *   back along the path the RREQ came in on.
 * - Route replacement prefers the freshest destination sequence number, then
 *   the fewest hops (hop minimisation).
 */
class AodvRouter(
    private val selfId: String,
    private val onLocalDelivery: (MeshPacket) -> Unit,
    private val resolveTransport: (String) -> TransportType
) {
    companion object {
        const val TTL_MAX = 7
        const val ROUTE_TIMEOUT_MS = 30_000L
        const val BROADCAST_ID = "*broadcast*"
        private const val MAX_SEEN = 1000
        private const val RREQ_MIN_INTERVAL_MS = 1_000L
    }

    private val table = mutableMapOf<String, RouteEntry>()
    private val seen = object : LinkedHashMap<UUID, Long>(MAX_SEEN, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<UUID, Long>): Boolean =
            size > MAX_SEEN
    }
    private var seqNum = System.currentTimeMillis()
    private val lastRreqAt = mutableMapOf<String, Long>()
    private val pendingData = mutableMapOf<String, MutableList<MeshPacket>>()

    // ------------------------------------------------------------------ wire

    /**
     * Wire format (big-endian):
     * [ver:1][type:1][hop:1][srcLen:2][dstLen:2][relayLen:2, 0xFFFF=null]
     * [payloadLen:4][sigLen:2][packetId:16][timestamp:8]
     * [src][dst][relay?][payload][sig]
     */
    fun serialize(p: MeshPacket): ByteArray {
        val src = p.sourceNodeId.toByteArray(Charsets.UTF_8)
        val dst = p.destinationNodeId.toByteArray(Charsets.UTF_8)
        val relay = p.relayNodeId?.toByteArray(Charsets.UTF_8)
        val buf = ByteBuffer.allocate(
            39 + src.size + dst.size + (relay?.size ?: 0) +
                p.encryptedPayload.size + p.signature.size
        ).order(ByteOrder.BIG_ENDIAN)
        buf.put(0x01.toByte())
        buf.put(p.packetType.ordinal.toByte())
        buf.put(p.hopCount.toByte())
        buf.putShort(src.size.toShort())
        buf.putShort(dst.size.toShort())
        buf.putShort(if (relay == null) 0xFFFF.toShort() else relay.size.toShort())
        buf.putInt(p.encryptedPayload.size)
        buf.putShort(p.signature.size.toShort())
        buf.putLong(p.packetId.mostSignificantBits)
        buf.putLong(p.packetId.leastSignificantBits)
        buf.putLong(p.timestamp)
        buf.put(src)
        buf.put(dst)
        if (relay != null) buf.put(relay)
        buf.put(p.encryptedPayload)
        buf.put(p.signature)
        return buf.array()
    }

    fun deserialize(raw: ByteArray): MeshPacket {
        val buf = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN)
        fun need(n: Int) {
            if (buf.remaining() < n) throw IllegalArgumentException("truncated packet")
        }
        need(39)
        val version = buf.get()
        require(version == 0x01.toByte()) { "unsupported wire version $version" }
        val type = PacketType.entries.getOrElse(buf.get().toInt() and 0xFF) {
            throw IllegalArgumentException("unknown packet type")
        }
        val hop = buf.get().toInt() and 0xFF
        val srcLen = buf.short.toInt() and 0xFFFF
        val dstLen = buf.short.toInt() and 0xFFFF
        val relayLenRaw = buf.short.toInt() and 0xFFFF
        val payloadLen = buf.int
        val sigLen = buf.short.toInt() and 0xFFFF
        require(payloadLen >= 0 && sigLen >= 0) { "negative body length" }
        val msb = buf.long
        val lsb = buf.long
        val timestamp = buf.long
        val relayLen = if (relayLenRaw == 0xFFFF) -1 else relayLenRaw
        need(srcLen + dstLen + (if (relayLen < 0) 0 else relayLen) + payloadLen + sigLen)
        val src = ByteArray(srcLen).also { buf.get(it) }.toString(Charsets.UTF_8)
        val dst = ByteArray(dstLen).also { buf.get(it) }.toString(Charsets.UTF_8)
        val relay = if (relayLen < 0) null
        else ByteArray(relayLen).also { buf.get(it) }.toString(Charsets.UTF_8)
        val payload = ByteArray(payloadLen).also { buf.get(it) }
        val sig = ByteArray(sigLen).also { buf.get(it) }
        return MeshPacket(
            packetId = UUID(msb, lsb),
            sourceNodeId = src,
            destinationNodeId = dst,
            relayNodeId = relay,
            hopCount = hop,
            packetType = type,
            encryptedPayload = payload,
            signature = sig,
            timestamp = timestamp
        )
    }

    // -------------------------------------------------------------- routing

    @Synchronized
    fun shouldForward(packetId: UUID): Boolean {
        if (seen.containsKey(packetId)) return false
        seen[packetId] = System.currentTimeMillis()
        return true
    }

    /** Entry point for locally originated packets. */
    fun routePacket(
        p: MeshPacket,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit,
        broadcast: (raw: ByteArray) -> Unit
    ) {
        if (!shouldForward(p.packetId)) return
        forward(p, sendVia, broadcast)
    }

    /** Entry point for packets arriving from the wire. */
    fun handleIncoming(
        p: MeshPacket,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit,
        broadcast: (raw: ByteArray) -> Unit
    ) {
        if (!shouldForward(p.packetId)) return
        val prevHop = p.relayNodeId ?: p.sourceNodeId
        // Learn the reverse route to the source from every packet seen.
        onRREP(p.sourceNodeId, prevHop, resolveTransport(prevHop), p.hopCount, p.timestamp, sendVia)

        if (p.packetType == PacketType.ROUTE_UPDATE) {
            val body = p.encryptedPayload.toString(Charsets.UTF_8)
            when {
                body.startsWith("RREQ|") -> handleRreq(p, body, sendVia, broadcast)
                body.startsWith("RREP|") -> handleRrep(p, body, prevHop, sendVia)
                p.destinationNodeId == selfId || p.destinationNodeId == BROADCAST_ID ->
                    onLocalDelivery(p) // routing-table gossip
                else -> forward(p, sendVia, broadcast)
            }
            return
        }

        if (p.destinationNodeId == selfId || p.destinationNodeId == BROADCAST_ID) {
            onLocalDelivery(p)
            return
        }
        forward(p, sendVia, broadcast)
    }

    private fun forward(
        p: MeshPacket,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit,
        broadcast: (raw: ByteArray) -> Unit
    ) {
        if (p.hopCount >= TTL_MAX) return
        val now = System.currentTimeMillis()
        val route = table[p.destinationNodeId]
        val fresh = route != null && route.expiresAt > now
        val fwd = p.copy(hopCount = p.hopCount + 1, relayNodeId = selfId)
        val raw = serialize(fwd)
        if (fresh) {
            sendVia(route!!.nextHopId, route.transport, raw)
        } else {
            if (p.packetType != PacketType.ROUTE_UPDATE) {
                // Buffer data until a route is discovered; floods carry a copy now.
                pendingData.getOrPut(p.destinationNodeId) { mutableListOf() }.add(p)
            }
            broadcast(raw)
            // RREQs must not trigger nested discoveries.
            if (p.packetType != PacketType.ROUTE_UPDATE) {
                initiateRREQ(p.destinationNodeId, broadcast)
            }
        }
    }

    private fun unicast(
        p: MeshPacket,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit
    ) {
        val route = table[p.destinationNodeId] ?: return
        if (route.expiresAt <= System.currentTimeMillis()) return
        val fwd = if (p.sourceNodeId == selfId && p.relayNodeId == null) p
        else p.copy(relayNodeId = selfId, hopCount = p.hopCount + 1)
        sendVia(route.nextHopId, route.transport, serialize(fwd))
    }

    // ------------------------------------------------------------ AODV core

    fun initiateRREQ(destId: String, broadcast: (raw: ByteArray) -> Unit) {
        val now = System.currentTimeMillis()
        if (now - (lastRreqAt[destId] ?: 0L) < RREQ_MIN_INTERVAL_MS) return
        lastRreqAt[destId] = now
        seqNum++
        val rreq = MeshPacket(
            sourceNodeId = selfId,
            destinationNodeId = BROADCAST_ID,
            relayNodeId = null,
            packetType = PacketType.ROUTE_UPDATE,
            encryptedPayload = "RREQ|$destId|$seqNum".toByteArray(Charsets.UTF_8),
            signature = ByteArray(64) // production: Ed25519 over the serialised packet
        )
        if (shouldForward(rreq.packetId)) broadcast(serialize(rreq))
    }

    private fun handleRreq(
        p: MeshPacket,
        body: String,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit,
        broadcast: (raw: ByteArray) -> Unit
    ) {
        val parts = body.split("|")
        if (parts.size != 3) return
        val wanted = parts[1]
        val wantSeq = parts[2].toLongOrNull() ?: return
        if (wanted == selfId) {
            sendRrep(routeDest = selfId, requester = p.sourceNodeId, destSeq = ++seqNum, hops = 0, sendVia)
            return
        }
        val route = table[wanted]
        val fresh = route != null &&
            route.expiresAt > System.currentTimeMillis() &&
            route.destSeqNum >= wantSeq
        if (fresh) {
            // Gratuitous reply on behalf of the destination; no re-flood needed.
            sendRrep(wanted, p.sourceNodeId, route!!.destSeqNum, route.hopCount, sendVia)
        } else {
            forward(p, sendVia, broadcast)
        }
    }

    private fun handleRrep(
        p: MeshPacket,
        body: String,
        prevHop: String,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit
    ) {
        val parts = body.split("|")
        if (parts.size != 4) return
        val routeDest = parts[1]
        val destSeq = parts[2].toLongOrNull() ?: return
        val hops = parts[3].toIntOrNull() ?: return
        // The replier is (hops) away; we are one further hop out.
        onRREP(routeDest, prevHop, resolveTransport(prevHop), hops + 1, destSeq, sendVia)
        if (p.destinationNodeId == selfId) return // we requested this route
        val fwd = p.copy(
            relayNodeId = selfId,
            hopCount = p.hopCount + 1,
            encryptedPayload = "RREP|$routeDest|$destSeq|${hops + 1}".toByteArray(Charsets.UTF_8)
        )
        unicast(fwd, sendVia)
    }

    private fun sendRrep(
        routeDest: String,
        requester: String,
        destSeq: Long,
        hops: Int,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit
    ) {
        val rrep = MeshPacket(
            sourceNodeId = selfId,
            destinationNodeId = requester,
            relayNodeId = null,
            packetType = PacketType.ROUTE_UPDATE,
            encryptedPayload = "RREP|$routeDest|$destSeq|$hops".toByteArray(Charsets.UTF_8),
            signature = ByteArray(64)
        )
        unicast(rrep, sendVia)
    }

    /**
     * Learn (or improve) a route. Replacement prefers the freshest destination
     * sequence number, then the fewest hops. Buffered data for [destId] is
     * flushed through the new route when [sendVia] is supplied.
     */
    @Synchronized
    fun onRREP(
        destId: String,
        nextHopId: String,
        transport: TransportType,
        hopCount: Int,
        destSeqNum: Long,
        sendVia: ((nextHop: String, transport: TransportType, raw: ByteArray) -> Unit)? = null
    ) {
        if (destId == selfId) return
        val now = System.currentTimeMillis()
        val existing = table[destId]
        val better = existing == null ||
            existing.expiresAt <= now ||
            destSeqNum > existing.destSeqNum ||
            (destSeqNum == existing.destSeqNum && hopCount < existing.hopCount)
        if (!better) return
        table[destId] = RouteEntry(destId, nextHopId, transport, hopCount, destSeqNum, now + ROUTE_TIMEOUT_MS)
        if (sendVia != null) {
            pendingData.remove(destId)?.forEach { pkt -> unicast(pkt, sendVia) }
        }
    }

    // -------------------------------------------------------- table gossip

    /** DSDV-style delta: neighbours advertise (dest, hops, seq); we add one hop. */
    fun exportTableJson(): String {
        val arr = JSONArray()
        val now = System.currentTimeMillis()
        synchronized(this) {
            table.values.filter { it.expiresAt > now }.forEach { e ->
                arr.put(
                    JSONObject()
                        .put("dest", e.destId)
                        .put("hops", e.hopCount)
                        .put("seq", e.destSeqNum)
                )
            }
        }
        return arr.toString()
    }

    fun importTableJson(
        json: String,
        viaNeighbor: String,
        sendVia: (nextHop: String, transport: TransportType, raw: ByteArray) -> Unit
    ) {
        try {
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                val dest = o.getString("dest")
                if (dest == selfId) continue
                onRREP(
                    dest,
                    viaNeighbor,
                    resolveTransport(viaNeighbor),
                    o.getInt("hops") + 1,
                    o.getLong("seq"),
                    sendVia
                )
            }
        } catch (_: Exception) {
            // Malformed gossip is ignored; the next coalesced broadcast repairs it.
        }
    }

    @Synchronized
    fun snapshot(): List<RouteEntry> = table.values.toList()
}
