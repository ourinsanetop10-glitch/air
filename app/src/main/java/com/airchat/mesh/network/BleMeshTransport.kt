package com.airchat.mesh.network

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.os.ParcelUuid
import java.util.UUID

/**
 * BLE transport: low-power discovery beacons, routing-table gossip and short
 * text bridging (10–20 m).
 *
 * Advertises the first 16 bytes of SHA-256(nodeId) so relays can recognise
 * peers without exposing long-term identities on the air.
 */
class BleMeshTransport(private val adapter: BluetoothAdapter) {

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("6e400001-b5a3-f393-e0a9-e50e24dcca9e")
        private val SERVICE_PARCEL = ParcelUuid(SERVICE_UUID)
        const val HASH_PREFIX_LEN = 16
    }

    /** (nodeIdHashHex, rssi) sightings from the scan callback. */
    var onPeerSighted: ((nodeIdHashHex: String, rssi: Int) -> Unit)? = null

    private var scanning = false
    private val advertiseCallback = object : AdvertiseCallback() {}

    @SuppressLint("MissingPermission")
    fun startAdvertising(nodeIdHashPrefix: ByteArray) {
        val advertiser = adapter.bluetoothLeAdvertiser ?: return
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW)
            .setConnectable(false)
            .build()
        val data = AdvertiseData.Builder()
            .addServiceUuid(SERVICE_PARCEL)
            .addServiceData(SERVICE_PARCEL, nodeIdHashPrefix.copyOf(HASH_PREFIX_LEN))
            .build()
        try {
            advertiser.startAdvertising(settings, data, advertiseCallback)
        } catch (_: Exception) {
            // Radio unavailable; discovery degrades to Wi-Fi Direct only.
        }
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising() {
        try {
            adapter.bluetoothLeAdvertiser?.stopAdvertising(advertiseCallback)
        } catch (_: Exception) {
        }
    }

    @SuppressLint("MissingPermission")
    fun startScanning(lowPower: Boolean = true) {
        if (scanning) return
        val scanner = adapter.bluetoothLeScanner ?: return
        scanning = true
        val settings = ScanSettings.Builder()
            .setScanMode(
                if (lowPower) ScanSettings.SCAN_MODE_LOW_POWER
                else ScanSettings.SCAN_MODE_LOW_LATENCY
            )
            .build()
        val filter = ScanFilter.Builder().setServiceUuid(SERVICE_PARCEL).build()
        try {
            scanner.startScan(listOf(filter), settings, scanCallback)
        } catch (_: Exception) {
            scanning = false
        }
    }

    @SuppressLint("MissingPermission")
    fun stopScanning() {
        if (!scanning) return
        scanning = false
        try {
            adapter.bluetoothLeScanner?.stopScan(scanCallback)
        } catch (_: Exception) {
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val bytes = result.scanRecord?.getServiceData(SERVICE_PARCEL) ?: return
            val hex = bytes.joinToString("") { "%02x".format(it) }
            onPeerSighted?.invoke(hex, result.rssi)
        }
    }
}
