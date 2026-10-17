package com.airchat.mesh.util

/**
 * Battery and radio optimisation: the mesh must never busy-scan.
 *
 * Policy:
 * - BLE scans run in short windows, more often when peers are around, rarely
 *   when alone, and almost never in Doze.
 * - Wi-Fi Direct discovery is throttled to ~1/minute and only re-armed when
 *   the routing table goes stale or BLE reports a new sighting.
 * - SoftAP election prefers high-battery nodes; the AP shuts down after 10
 *   idle minutes.
 * - Routing-table gossip is coalesced to 2 s deltas, not full broadcasts.
 */
object RadioOptimizer {
    const val BLE_SCAN_WINDOW_MS = 5_000L
    const val BLE_SCAN_INTERVAL_IDLE_MS = 30_000L
    const val BLE_SCAN_INTERVAL_ACTIVE_MS = 10_000L
    const val WIFI_DISCOVER_INTERVAL_MS = 60_000L
    const val ROUTE_BROADCAST_COALESCE_MS = 2_000L
    const val SOFTAP_IDLE_SHUTDOWN_MS = 10 * 60_000L
    const val LOW_BATTERY_THRESHOLD = 20
    const val DOZE_BACKOFF_MS = 15 * 60_000L

    /**
     * How long to wait before the next discovery sweep. Adds jitter so a
     * cluster of nodes does not synchronise into a thundering herd.
     */
    fun nextScanDelay(peerCount: Int, batteryPct: Int, isDoze: Boolean): Long {
        if (isDoze) return DOZE_BACKOFF_MS
        var delay = if (peerCount == 0) BLE_SCAN_INTERVAL_IDLE_MS else BLE_SCAN_INTERVAL_ACTIVE_MS
        if (batteryPct < LOW_BATTERY_THRESHOLD) delay *= 3
        return delay + (0..2000).random()
    }

    /** Throttle for Wi-Fi Direct discovery sweeps. */
    fun wifiDiscoverDelayMs(lastDiscoveryAgeMs: Long): Long =
        (WIFI_DISCOVER_INTERVAL_MS - lastDiscoveryAgeMs).coerceAtLeast(0L)

    /** Whether this node may volunteer as the softAP in hotspot fallback. */
    fun mayBecomeSoftAp(batteryPct: Int, peerCount: Int): Boolean =
        batteryPct >= 40 && peerCount > 0
}
