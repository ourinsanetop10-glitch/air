package com.airchat.mesh.network

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pInfo
import android.net.wifi.p2p.WifiP2pManager
import android.net.wifi.WpsInfo
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Wi-Fi Direct transport: the primary high-bandwidth data plane for media,
 * database sync and voice calls (up to ~100 m).
 *
 * Owns the P2P broadcast receiver and the server socket. Accepted sockets are
 * handed to [AirChatMeshEngine] which frames packets over them.
 */
class WifiDirectTransport(
    private val context: Context,
    private val manager: WifiP2pManager,
    private val channel: WifiP2pManager.Channel
) {
    /** Latest peer snapshot, keyed by device MAC address. */
    val peers: MutableMap<String, WifiP2pDevice> = mutableMapOf()

    var onPeersChanged: ((List<WifiP2pDevice>) -> Unit)? = null
    var onConnectionInfo: ((WifiP2pInfo) -> Unit)? = null
    var onSocket: ((Socket) -> Unit)? = null

    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> requestPeers()
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION ->
                    manager.requestConnectionInfo(channel) { info ->
                        onConnectionInfo?.invoke(info)
                    }
            }
        }
    }

    fun start() {
        if (!running.compareAndSet(false, true)) return
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        }
        context.registerReceiver(receiver, filter)
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        try {
            context.unregisterReceiver(receiver)
        } catch (_: IllegalArgumentException) {
            // Already unregistered; safe to ignore.
        }
        stopListener()
    }

    @SuppressLint("MissingPermission")
    fun discoverPeers() {
        manager.discoverPeers(channel, object : WifiP2pManager.ActionListener {
            override fun onSuccess() = Unit
            override fun onFailure(reason: Int) = Unit
        })
    }

    @SuppressLint("MissingPermission")
    private fun requestPeers() {
        manager.requestPeers(channel) { deviceList ->
            peers.clear()
            deviceList.deviceList.forEach { peers[it.deviceAddress] = it }
            onPeersChanged?.invoke(deviceList.deviceList.toList())
        }
    }

    @SuppressLint("MissingPermission")
    fun connectTo(device: WifiP2pDevice) {
        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            groupOwnerIntent = 7 // bias towards group-owner for AP-like behaviour
            wps.setup = WpsInfo.PBC
        }
        manager.connect(channel, config, object : WifiP2pManager.ActionListener {
            override fun onSuccess() = Unit
            override fun onFailure(reason: Int) = Unit
        })
    }

    /** Accept loop for the P2P data plane. Call once; the engine handles framing. */
    fun startListener(port: Int = 8888) {
        stopListener()
        acceptThread = Thread({
            try {
                val server = ServerSocket(port)
                serverSocket = server
                while (running.get() && !server.isClosed) {
                    val socket = server.accept()
                    onSocket?.invoke(socket)
                }
            } catch (_: Exception) {
                // Socket closed during shutdown.
            }
        }, "wifidirect-accept").apply {
            isDaemon = true
            start()
        }
    }

    fun stopListener() {
        try {
            serverSocket?.close()
        } catch (_: Exception) {
        }
        serverSocket = null
        acceptThread?.interrupt()
        acceptThread = null
    }

    /** Open an outbound socket once Wi-Fi Direct reports a group formation. */
    fun openSocket(host: String, port: Int = 8888): Socket = Socket(host, port)
}
