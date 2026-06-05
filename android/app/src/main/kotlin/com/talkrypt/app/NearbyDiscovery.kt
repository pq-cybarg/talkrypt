package com.talkrypt.app

/**
 * SKELETON — hands-free nearby-device discovery for in-person onboarding.
 *
 * Today's in-person flows need a QR (scan-to-join) or the LAN APK share. This is
 * the scaffold for *zero-touch* discovery: two nearby phones find each other and
 * exchange a `talkrypt://` invite automatically, no scanning or typing. It is
 * intentionally not wired up yet — it needs runtime permissions and on-device
 * validation — but the interface + the two intended transports are fixed here so
 * the real implementation drops straight in.
 *
 * What crosses the air is only the **invite descriptor** (`talkrypt://…`), which
 * is itself just a one-time token; the actual chat still runs over the
 * authenticated, AEAD-encrypted session (and can be password- or
 * registry-gated). So discovery is a convenience layer, never a trust anchor —
 * the safety-number / account checks still apply.
 *
 * Two transports to implement (a real build would offer both and merge results):
 *
 *  1. **Wi-Fi Direct** (`android.net.wifi.p2p.WifiP2pManager`)
 *     - Permissions: NEARBY_WIFI_DEVICES (API 33+) or ACCESS_FINE_LOCATION
 *       (pre-33), plus CHANGE_WIFI_STATE.
 *     - `discoverPeers()` + a BroadcastReceiver for WIFI_P2P_PEERS_CHANGED;
 *       on connect, open a socket on the group owner and send the invite.
 *     - Best for the larger APK transfer too (high bandwidth).
 *
 *  2. **BLE** (`BluetoothLeAdvertiser` / `BluetoothLeScanner`)
 *     - Permissions: BLUETOOTH_ADVERTISE + BLUETOOTH_SCAN + BLUETOOTH_CONNECT
 *       (API 31+); pre-31 BLUETOOTH/BLUETOOTH_ADMIN + location.
 *     - Advertise a talkrypt service UUID; put a short rendezvous token in the
 *       service data (the full invite is fetched over a GATT characteristic or
 *       the resulting Wi-Fi/LAN link, since BLE payloads are tiny).
 *     - Best for the initial "who's nearby" beacon (low power).
 *
 * None of the above is invoked yet; MainActivity does not reference this class.
 */
interface NearbyDiscovery {
    /** A peer found nearby, with the invite it is advertising (once fetched). */
    data class Peer(val displayName: String, val inviteUri: String?)

    /** Begin advertising `inviteUri` so nearby talkrypt devices can find us. */
    fun advertise(inviteUri: String)

    /** Begin scanning; `onFound` fires as peers (and their invites) appear. */
    fun scan(onFound: (Peer) -> Unit)

    /** Stop advertising and scanning; release radios. */
    fun stop()

    companion object {
        /** The advertised service identifier shared by Wi-Fi Direct + BLE. */
        const val SERVICE_UUID = "7461-6c6b-7279-7074" // "talkrypt" in hex, grouped

        /**
         * Returns the real implementation once built. Today it returns null so
         * callers fall back to QR / LAN share. Replace with WifiP2p + BLE impls.
         */
        fun create(): NearbyDiscovery? = null
    }
}
