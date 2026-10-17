package com.airchat.mesh.network

import android.annotation.SuppressLint
import android.net.wifi.WifiManager
import android.os.Build

/**
 * Local-only hotspot fallback layer. When Wi-Fi Direct group formation fails,
 * the elected node becomes a software access point and neighbours join as
 * stations.
 *
 * Election (highest battery + strongest BLE RSSI, single AP per partition) is
 * decided by [AirChatMeshEngine]; this class only owns the reservation.
 */
class HotspotFallback(private val wifiManager: WifiManager) {

    private var reservation: WifiManager.LocalOnlyHotspotReservation? = null

    data class SoftApCredentials(val ssid: String, val passphrase: String)

    @SuppressLint("MissingPermission")
    fun becomeSoftAp(
        onReady: (SoftApCredentials) -> Unit,
        onError: (Throwable) -> Unit = {}
    ) {
        if (reservation != null) return
        try {
            wifiManager.startLocalOnlyHotspot(
                object : WifiManager.LocalOnlyHotspotCallback() {
                    override fun onStarted(r: WifiManager.LocalOnlyHotspotReservation) {
                        reservation = r
                        val creds = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            val cfg = r.softApConfiguration
                            SoftApCredentials(cfg.ssid, cfg.passphrase ?: "")
                        } else {
                            @Suppress("DEPRECATION")
                            val cfg = r.wifiConfiguration
                            SoftApCredentials(
                                cfg?.SSID ?: "AIRCHAT",
                                cfg?.preSharedKey ?: ""
                            )
                        }
                        onReady(creds)
                    }

                    override fun onFailed(reason: Int) {
                        onError(IllegalStateException("LocalOnlyHotspot failed: $reason"))
                    }
                },
                null
            )
        } catch (t: Throwable) {
            onError(t)
        }
    }

    fun shutdown() {
        try {
            reservation?.close()
        } catch (_: Exception) {
        }
        reservation = null
    }

    val isActive: Boolean get() = reservation != null
}
