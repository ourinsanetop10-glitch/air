package com.airchat.mesh.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.core.app.ActivityCompat
import com.airchat.mesh.MeshApp
import com.airchat.mesh.network.MeshForegroundService
import com.airchat.mesh.network.MeshPacket
import com.airchat.mesh.network.PacketType
import java.util.UUID

/**
 * Minimal chat UI (programmatic layout, no XML): peer list, mesh log and a
 * message composer wired directly to the [com.airchat.mesh.network.AirChatMeshEngine].
 *
 * Production path for sending: encrypt with the peer's DoubleRatchet session
 * ([com.airchat.mesh.crypto.DoubleRatchet.ratchetEncrypt]) and place the
 * resulting bytes in [MeshPacket.encryptedPayload]. The scaffold sends
 * plaintext bytes so the mesh data plane can be exercised end to end.
 */
class MainActivity : ComponentActivity() {

    private lateinit var logView: TextView
    private lateinit var peerBox: LinearLayout
    private lateinit var input: EditText
    private var selectedPeer: String? = null

    private val engine get() = (application as MeshApp).engine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestRadioPermissions()
        MeshForegroundService.start(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 24, 24, 24)
        }

        val title = TextView(this).apply {
            text = "AIRCHAT  •  ${engine.selfNodeId.take(12)}…"
            textSize = 18f
        }
        val discoverBtn = Button(this).apply {
            text = "Discover peers"
            setOnClickListener {
                engine.startPeerDiscovery()
                refreshPeers()
            }
        }
        val refreshBtn = Button(this).apply {
            text = "Refresh peers"
            setOnClickListener { refreshPeers() }
        }
        peerBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        logView = TextView(this).apply { text = "— mesh log —\n" }
        val scroll = ScrollView(this).apply {
            addView(logView)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f
            )
        }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        input = EditText(this).apply {
            hint = "Message"
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val sendBtn = Button(this).apply {
            text = "Send"
            setOnClickListener { sendMessage() }
        }
        row.addView(input)
        row.addView(sendBtn)
        root.addView(title)
        root.addView(discoverBtn)
        root.addView(refreshBtn)
        root.addView(peerBox)
        root.addView(scroll)
        root.addView(row)
        setContentView(root)

        engine.onMessageReceived = { packet ->
            runOnUiThread {
                val text = packet.encryptedPayload.toString(Charsets.UTF_8)
                appendLog("${packet.sourceNodeId.take(8)}: $text")
            }
        }
        engine.onPeersChanged = { runOnUiThread { refreshPeers() } }
        refreshPeers()
    }

    private fun refreshPeers() {
        peerBox.removeAllViews()
        val peers = engine.connectedPeers()
        if (peers.isEmpty()) {
            peerBox.addView(TextView(this).apply { text = "No peers yet — tap Discover." })
            return
        }
        peers.forEach { id ->
            peerBox.addView(Button(this).apply {
                text = (if (id == selectedPeer) "● " else "○ ") + id.take(16) + "…"
                setOnClickListener {
                    selectedPeer = id
                    refreshPeers()
                }
            })
        }
    }

    private fun sendMessage() {
        val peer = selectedPeer
        val text = input.text.toString()
        if (peer == null) {
            toast("Select a peer first")
            return
        }
        if (text.isBlank()) return
        val packet = MeshPacket(
            packetId = UUID.randomUUID(),
            sourceNodeId = engine.selfNodeId,
            destinationNodeId = peer,
            relayNodeId = null,
            packetType = PacketType.TEXT_MESSAGE,
            encryptedPayload = text.toByteArray(Charsets.UTF_8),
            signature = ByteArray(64) // production: Ed25519 over the serialised packet
        )
        engine.routePacket(packet)
        appendLog("you → ${peer.take(8)}: $text")
        input.text.clear()
    }

    private fun appendLog(line: String) {
        logView.append(line + "\n")
    }

    private fun toast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    private fun requestRadioPermissions() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        val perms = arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.NEARBY_WIFI_DEVICES
        )
        val missing = perms.filter {
            ActivityCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, missing.toTypedArray(), 1001)
        }
    }
}
