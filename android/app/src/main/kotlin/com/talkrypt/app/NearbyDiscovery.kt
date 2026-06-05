package com.talkrypt.app

import android.content.Context
import java.util.UUID

/**
 * Hands-free nearby-device discovery for in-person onboarding: two phones find
 * each other and exchange a `talkrypt://` invite automatically — no scanning or
 * typing. What crosses the air is only the invite descriptor (a one-time token);
 * the chat itself still runs over the authenticated, AEAD-encrypted session and
 * can be password- or registry-gated, so discovery is convenience, never a trust
 * anchor — the safety-number / account checks still apply.
 *
 * Two real transports implement this:
 *   - [BleNearby]        — Bluetooth LE: advertise presence + serve the invite
 *                          over a GATT characteristic; scan + read it back.
 *   - [WifiDirectNearby] — Wi-Fi Direct: discover peers + exchange the invite
 *                          over a socket (also forms a network with no router).
 */
interface NearbyDiscovery {
    /** A peer found nearby, with the invite it advertised. */
    data class Peer(val name: String, val inviteUri: String)

    /** Advertise `inviteUri` so nearby talkrypt devices can find us (host side). */
    fun startAdvertising(inviteUri: String)

    /** Scan for peers; `onFound` fires per discovered invite, `onError` on failure. */
    fun startScanning(onFound: (Peer) -> Unit, onError: (String) -> Unit)

    /** Stop advertising + scanning and release radios. */
    fun stop()

    companion object {
        // 128-bit UUIDs derived from "talkrypt" — shared by BLE + Wi-Fi Direct.
        val SERVICE_UUID: UUID = UUID.fromString("74616c6b-7279-7074-0000-000000000001")
        val INVITE_CHAR_UUID: UUID = UUID.fromString("74616c6b-7279-7074-0000-000000000002")

        /**
         * Bluetooth LE discovery — best as the low-power "who's nearby" beacon.
         * Tiny payloads, so the invite is fetched over a GATT characteristic.
         */
        fun ble(context: Context): NearbyDiscovery = BleNearby(context)

        /**
         * Wi-Fi Direct discovery — higher bandwidth and forms its own network
         * with no router, so it also suits the larger APK transfer. The invite
         * is exchanged over a socket on the group owner.
         */
        fun wifiDirect(context: Context): NearbyDiscovery = WifiDirectNearby(context)
    }
}
