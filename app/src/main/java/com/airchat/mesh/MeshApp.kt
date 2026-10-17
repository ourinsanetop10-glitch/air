package com.airchat.mesh

import android.app.Application
import android.bluetooth.BluetoothManager
import android.content.Context
import android.net.wifi.WifiManager
import android.net.wifi.p2p.WifiP2pManager
import android.os.Looper
import com.airchat.mesh.crypto.CryptoEngine
import com.airchat.mesh.network.AirChatMeshEngine
import java.security.MessageDigest

/**
 * Application singleton. Owns the single [AirChatMeshEngine] instance shared by
 * [com.airchat.mesh.network.MeshForegroundService] and
 * [com.airchat.mesh.ui.MainActivity].
 *
 * The node identity is hex(SHA-256(Ed25519 public key)) — deterministic, with
 * no phone number or central account anywhere in the system.
 */
class MeshApp : Application() {

    val engine: AirChatMeshEngine by lazy {
        val wifiP2p = getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
        val channel = wifiP2p.initialize(this, Looper.getMainLooper(), null)
        val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val bluetooth = (getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter

        val identity = CryptoEngine.loadOrGenerateIdentity(this)
        val nodeId = CryptoEngine.nodeIdFor(identity.edPub)
        val hashPrefix = MessageDigest.getInstance("SHA-256")
            .digest(nodeId.toByteArray())
            .copyOf(16)

        AirChatMeshEngine(
            context = this,
            wifiP2pManager = wifiP2p,
            channel = channel,
            wifiManager = wifi,
            bluetoothAdapter = bluetooth,
            selfNodeId = nodeId,
            selfNodeIdHashPrefix = hashPrefix
        )
    }
}
