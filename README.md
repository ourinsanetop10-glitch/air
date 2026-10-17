# AIRCHAT — zero-internet local-mesh WhatsApp clone

Android app (`com.airchat.mesh`, minSdk 26, targetSdk 34) that sends encrypted
messages with **no cellular data and no internet**. All traffic stays on local
radio: Wi-Fi Direct, a local-only hotspot fallback, and BLE.

## Offline-first architecture

```
┌──────────────────────────────────────────────────────────────┐
│ UI (MainActivity)                                            │
│  peer list · mesh log · composer → AirChatMeshEngine          │
├──────────────────────────────────────────────────────────────┤
│ Mesh engine (foreground service)                             │
│  AirChatMeshEngine ──► AodvRouter (app-space AODV)            │
│        │                │ duplicate-suppression LRU           │
│        │                │ RREQ/RREP · TTL 7 · hop minimisation│
│        ▼                                                     │
│  Transports                                                  │
│   1. WifiDirectTransport  — 8888/tcp data plane, ~100 m       │
│   2. HotspotFallback      — LocalOnlyHotspot softAP election │
│   3. BleMeshTransport     — discovery beacons, 10–20 m       │
├──────────────────────────────────────────────────────────────┤
│ Crypto (Tink subtle: Ed25519 + X25519)                        │
│  identity = hex(SHA-256(Ed25519 pub)) · X3DH via QR/BLE      │
│  Double Ratchet → AES-256-GCM per-message keys               │
├──────────────────────────────────────────────────────────────┤
│ Storage (Room, offline-first)                                │
│  nodes · messages · ratchet_states · store_forward           │
│  HELLO/NEED/DATA rejoin sync · LWW conflict resolution       │
└──────────────────────────────────────────────────────────────┘
```

Relays are **zero-trust**: they forward on envelope fields
(`destinationNodeId`, `hopCount`) and can never read payloads.

## Module map

| Path | Responsibility |
|---|---|
| `network/Transports.kt` | `TransportType`, `PacketType`, `MeshPacket`, `MeshNetworkManager` |
| `network/WifiDirectTransport.kt` | `WifiP2pManager` wrapper, peer receiver, `:8888` accept loop |
| `network/BleMeshTransport.kt` | BLE advertiser/scanner, node-id hash beacons |
| `network/HotspotFallback.kt` | `LocalOnlyHotspotReservation` softAP wrapper |
| `network/AirChatMeshEngine.kt` | Transport ownership, length-prefixed socket framing, HANDSHAKE, discovery loop |
| `network/MeshForegroundService.kt` | `connectedDevice` foreground service keeping the mesh alive |
| `routing/AodvRouter.kt` | App-space AODV: wire format, RREQ/RREP, duplicate cache, table gossip |
| `crypto/CryptoEngine.kt` | Ed25519/X25519 via Tink, X3DH, full Double Ratchet |
| `db/MeshDatabase.kt` | Room entities/DAOs, store-and-forward, sync protocol notes |
| `util/RadioOptimizer.kt` | Scan duty cycles, Doze backoff, softAP election guard |
| `ui/MainActivity.kt` | Minimal chat UI wired to the engine |
| `MeshApp.kt` | Application singleton owning the engine |

## 4-layer protocol summary

1. **Low-level Android APIs** — `WifiP2pManager` (discovery, group
   negotiation), `BluetoothLeAdvertiser`/`Scanner` (beacons), `WifiManager`
   local-only hotspot (fallback AP), foreground service with
   `connectedDevice` type, length-prefixed TCP framing on port 8888.
2. **Mesh routing & packets** — AODV in app space: UUID-keyed duplicate
   suppression, RREQ flood with 1 s per-destination throttling and jitter,
   RREP unicast along learned reverse routes, gratuitous replies from
   intermediates, hop minimisation with sequence-number freshness, TTL 7,
   buffered data flushed when routes are discovered, coalesced table gossip.
3. **Local state & sync** — Room keyed by key-hash identities; messages carry
   Lamport clocks; rejoin sync is HELLO (Bloom filter + max clock) → NEED →
   DATA → ACK; store-and-forward queue (24 h TTL) on relays; LWW
   `(timestamp, nodeId)` conflict resolution; ratchet sessions persisted.
4. **Battery & radio** — BLE 5 s windows on 10–30 s intervals (×3 under 20 %
   battery, 15 min in Doze), Wi-Fi Direct discovery ~1/min, single elected
   softAP with 10 min idle shutdown, jittered broadcasts, wakelocks only
   during active transfers.

## Build

Prerequisites: Android Studio Hedgehog+ (AGP 8.3.2, Kotlin 1.9.24),
Android SDK 34.

```bash
# Android Studio: File → Open → ~/workspace/airchat, then Run ▶
# or from the command line (after generating the wrapper once in Studio):
./gradlew :app:assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

Runtime permissions (Android 12+): Bluetooth scan/advertise/connect and
Nearby Wi-Fi Devices are requested on first launch. Location permission is
declared because Wi-Fi Direct discovery requires it on Android 9–11.
