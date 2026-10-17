package com.airchat.mesh.network

import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pManager
import com.airchat.mesh.routing.AodvRouter
import com.airchat.mesh.util.RadioOptimizer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/**
 * Central mesh coordinator. Owns the three transports, the [AodvRouter] and
 * the socket data plane.
 *
 * Data plane framing is length-prefixed: `[u32 big-endian length][packet bytes]`.
 * The first frame on every socket must be a HANDSHAKE identifying the peer's
 * nodeId; only then is the socket registered for routing.
 */
class AirChatMeshEngine(
    private val context: Context,
    private val wifiP2pManager: WifiP2pManager,
    private val channel: WifiP2pManager.Channel,
    private val wifiManager: WifiManager,
    private val bluetoothAdapter: BluetoothAdapter?,
    val selfNodeId: String,
    val selfNodeIdHashPrefix: ByteArray
) : MeshNetworkManager {

    companion object {
        const val DATA_PORT = 8888
        const val MAX_FRAME_BYTES = 4 * 1024 * 1024
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val router = AodvRouter(
        selfId = selfNodeId,
        onLocalDelivery = { packet ->
            if (packet.packetType == PacketType.ROUTE_UPDATE &&
                packet.destinationNodeId == AodvRouter.BROADCAST_ID
            ) {
                handleTableGossip(packet)
            } else {
                onMessageReceived?.invoke(packet)
            }
        },
        resolveTransport = { nodeId -> nodeTransports[nodeId] ?: TransportType.WIFI_DIRECT }
    )

    val wifiDirect = WifiDirectTransport(context, wifiP2pManager, channel)
    val ble: BleMeshTransport? = bluetoothAdapter?.let { BleMeshTransport(it) }
    val hotspot = HotspotFallback(wifiManager)

    /** nodeId -> live data-plane socket. */
    private val sockets = ConcurrentHashMap<String, Socket>()
    /** nodeId -> transport that socket arrived on. */
    private val nodeTransports = ConcurrentHashMap<String, TransportType>()

    /** Packets whose destination is this node. Observed by the UI. */
    var onMessageReceived: ((MeshPacket) -> Unit)? = null

    /** Fires whenever the set of directly connected peers changes. */
    var onPeersChanged: ((Set<String>) -> Unit)? = null

    @Volatile
    private var started = false

    fun start() {
        if (started) return
        started = true

        wifiDirect.onSocket = { socket ->
            attachSocket(socket, TransportType.WIFI_DIRECT, initiator = false)
        }
        wifiDirect.onConnectionInfo = { info ->
            // We are the group client: open the data-plane socket to the owner.
            if (info.groupFormed && !info.isGroupOwner) {
                val host = info.groupOwnerAddress?.hostAddress
                if (host != null) {
                    scope.launch {
                        try {
                            val socket = wifiDirect.openSocket(host, DATA_PORT)
                            attachSocket(socket, TransportType.WIFI_DIRECT, initiator = true)
                        } catch (_: Exception) {
                            // Group formed but socket failed; discovery will retry.
                        }
                    }
                }
            }
            // When we are the group owner, peers connect to us and the
            // server-socket accept path handles them.
        }
        wifiDirect.start()
        wifiDirect.startListener(DATA_PORT)

        ble?.startAdvertising(selfNodeIdHashPrefix)

        scope.launch { discoveryLoop() }
    }

    fun stop() {
        started = false
        wifiDirect.stop()
        ble?.stopScanning()
        ble?.stopAdvertising()
        hotspot.shutdown()
        val copy = sockets.values.toList()
        sockets.clear()
        nodeTransports.clear()
        copy.forEach { try { it.close() } catch (_: Exception) {} }
    }

    fun connectedPeers(): Set<String> = sockets.keys.toSet()

    fun routingSnapshot() = router.snapshot()

    // ------------------------------------------------------- MeshNetworkManager

    override fun startPeerDiscovery() {
        wifiDirect.discoverPeers()
        ble?.startScanning(lowPower = true)
    }

    override fun establishP2PLink(targetNodeId: String, preferredTransport: TransportType) {
        when (preferredTransport) {
            TransportType.WIFI_DIRECT -> {
                // Wi-Fi Direct cannot address a nodeId before connecting, so we
                // connect the best available peer; the HANDSHAKE then identifies
                // it. Even a "wrong" peer is useful as a blind relay.
                val device: WifiP2pDevice? =
                    wifiDirect.peers.values.firstOrNull { it.status == WifiP2pDevice.AVAILABLE }
                        ?: wifiDirect.peers.values.firstOrNull()
                if (device != null) wifiDirect.connectTo(device)
            }
            TransportType.LOCAL_HOTSPOT -> hotspot.becomeSoftAp(onReady = {})
            TransportType.BLE, TransportType.BLUETOOTH_CLASSIC ->
                ble?.startScanning(lowPower = false)
        }
    }

    override fun routePacket(packet: MeshPacket) {
        router.routePacket(packet, ::sendVia, ::broadcastRaw)
    }

    override fun broadcastRoutingTableUpdate(routingTableJson: String) {
        val packet = MeshPacket(
            sourceNodeId = selfNodeId,
            destinationNodeId = AodvRouter.BROADCAST_ID,
            relayNodeId = null,
            packetType = PacketType.ROUTE_UPDATE,
            encryptedPayload = routingTableJson.toByteArray(Charsets.UTF_8),
            signature = ByteArray(64) // production: Ed25519 over the serialised packet
        )
        broadcastRaw(router.serialize(packet))
    }

    // ------------------------------------------------------------ data plane

    private fun attachSocket(socket: Socket, transport: TransportType, initiator: Boolean) {
        scope.launch {
            try {
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                // Deadlock-free handshake: the initiator writes first.
                val peerId = if (initiator) {
                    sendHandshake(output)
                    readHandshake(input)
                } else {
                    val id = readHandshake(input)
                    sendHandshake(output)
                    id
                }
                sockets[peerId] = socket
                nodeTransports[peerId] = transport
                // Direct neighbours are one hop away.
                router.onRREP(peerId, peerId, transport, 1, System.currentTimeMillis(), ::sendVia)
                onPeersChanged?.invoke(sockets.keys.toSet())
                pumpLoop(peerId, socket, input)
            } catch (_: Exception) {
                try {
                    socket.close()
                } catch (_: Exception) {
                }
            }
        }
    }

    private fun sendHandshake(out: DataOutputStream) {
        val hello = MeshPacket(
            sourceNodeId = selfNodeId,
            destinationNodeId = "",
            relayNodeId = null,
            packetType = PacketType.HANDSHAKE,
            encryptedPayload = selfNodeId.toByteArray(Charsets.UTF_8),
            signature = ByteArray(64) // production: Ed25519(nodeId || timestamp)
        )
        val raw = router.serialize(hello)
        synchronized(out) {
            out.writeInt(raw.size)
            out.write(raw)
            out.flush()
        }
    }

    private fun readHandshake(input: DataInputStream): String {
        val raw = readFrame(input) ?: throw EOFException("peer closed before handshake")
        val hello = router.deserialize(raw)
        require(hello.packetType == PacketType.HANDSHAKE) { "expected HANDSHAKE frame" }
        return hello.sourceNodeId.ifEmpty { hello.encryptedPayload.toString(Charsets.UTF_8) }
    }

    private suspend fun pumpLoop(peerId: String, socket: Socket, input: DataInputStream) {
        try {
            while (started && !socket.isClosed) {
                val raw = readFrame(input) ?: break
                val packet = router.deserialize(raw)
                if (packet.packetType == PacketType.HANDSHAKE) continue
                router.handleIncoming(packet, ::sendVia, ::broadcastRaw)
            }
        } catch (_: Exception) {
            // Socket died; fall through to cleanup.
        } finally {
            sockets.remove(peerId, socket)
            nodeTransports.remove(peerId)
            try {
                socket.close()
            } catch (_: Exception) {
            }
            onPeersChanged?.invoke(sockets.keys.toSet())
        }
    }

    private fun readFrame(input: DataInputStream): ByteArray? {
        return try {
            val len = input.readInt()
            if (len <= 0 || len > MAX_FRAME_BYTES) return null
            val buf = ByteArray(len)
            input.readFully(buf)
            buf
        } catch (_: EOFException) {
            null
        }
    }

    private fun sendVia(nextHop: String, transport: TransportType, raw: ByteArray) {
        val socket = sockets[nextHop] ?: return
        scope.launch {
            try {
                // One DataOutputStream per send is fine; never close it here.
                val out = DataOutputStream(socket.getOutputStream())
                synchronized(socket) {
                    out.writeInt(raw.size)
                    out.write(raw)
                    out.flush()
                }
            } catch (_: Exception) {
                sockets.remove(nextHop, socket)
                try {
                    socket.close()
                } catch (_: Exception) {
                }
                onPeersChanged?.invoke(sockets.keys.toSet())
            }
        }
    }

    private fun broadcastRaw(raw: ByteArray) {
        sockets.keys.toList().forEach { peer ->
            sendVia(peer, TransportType.WIFI_DIRECT, raw)
        }
    }

    private fun handleTableGossip(packet: MeshPacket) {
        val json = packet.encryptedPayload.toString(Charsets.UTF_8).trimStart()
        // RREQ/RREP bodies are consumed by the router; only JSON gossip lands here.
        if (json.startsWith("[")) {
            router.importTableJson(
                json,
                packet.relayNodeId ?: packet.sourceNodeId,
                ::sendVia
            )
        }
    }

    // ------------------------------------------------------------------ loop

    private suspend fun discoveryLoop() {
        while (started) {
            wifiDirect.discoverPeers()
            ble?.startScanning(lowPower = true)
            delay(RadioOptimizer.BLE_SCAN_WINDOW_MS)
            ble?.stopScanning()
            // Coalesced routing-table gossip keeps the mesh converged.
            broadcastRoutingTableUpdate(router.exportTableJson())
            delay(
                RadioOptimizer.nextScanDelay(
                    peerCount = sockets.size,
                    batteryPct = 100, // production: BatteryManager sticky broadcast
                    isDoze = false    // production: PowerManager.isDeviceIdleMode
                )
            )
        }
    }
}
