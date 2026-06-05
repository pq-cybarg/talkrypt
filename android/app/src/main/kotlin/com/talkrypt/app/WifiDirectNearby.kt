package com.talkrypt.app

import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pManager
import android.os.Handler
import android.os.Looper
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * Wi-Fi Direct nearby discovery (`WifiP2pManager`).
 *
 * Higher bandwidth than BLE and forms its own network with no router — so it
 * also suits the larger APK transfer, not just the invite. The invite is
 * exchanged over a TCP socket once a peer connection is formed.
 *
 * Permissions (requested by MainActivity before use):
 *   - API 33+:  NEARBY_WIFI_DEVICES (declared `neverForLocation`)
 *   - pre-33:   ACCESS_FINE_LOCATION
 *   - always:   CHANGE_WIFI_STATE  (ACCESS_WIFI_STATE is install-time)
 *
 * Mechanism:
 *   - advertise: `discoverPeers()`, then accept an incoming connection and write
 *     the invite to whoever connects (the group owner runs a ServerSocket).
 *   - scan: `discoverPeers()` + a receiver for WIFI_P2P_PEERS_CHANGED_ACTION;
 *     `requestPeers()` lists devices, `connect()` to one, then on
 *     WIFI_P2P_CONNECTION_CHANGED read the invite from the group owner's socket.
 *
 * Because connection setup is heavier than BLE, this is the "form a network +
 * move bytes" path; BLE is the lightweight presence beacon. Both implement the
 * same [NearbyDiscovery] interface so the UI can offer either (or both).
 */
class WifiDirectNearby(private val context: Context) : NearbyDiscovery {
    private val main = Handler(Looper.getMainLooper())
    private val manager = context.getSystemService(WifiP2pManager::class.java)
    private var channel: WifiP2pManager.Channel? = null
    private var receiver: BroadcastReceiver? = null
    private var server: ServerSocket? = null

    private var onFoundCb: ((NearbyDiscovery.Peer) -> Unit)? = null
    private var onErrorCb: ((String) -> Unit)? = null

    private val port = 9777

    private fun ensureChannel(): Boolean {
        if (manager == null) return false
        if (channel == null) {
            channel = manager.initialize(context, Looper.getMainLooper(), null)
        }
        return channel != null
    }

    @SuppressLint("MissingPermission")
    override fun startAdvertising(inviteUri: String) {
        if (!ensureChannel()) return
        // Serve the invite to whoever connects to us (we may become group owner).
        startInviteServer(inviteUri)
        registerReceiver()
        try {
            manager?.discoverPeers(channel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {}
                override fun onFailure(reason: Int) {}
            })
        } catch (e: SecurityException) {
            // permission handled by caller
        }
    }

    @SuppressLint("MissingPermission")
    override fun startScanning(
        onFound: (NearbyDiscovery.Peer) -> Unit,
        onError: (String) -> Unit,
    ) {
        if (!ensureChannel()) {
            onError("Wi-Fi Direct unavailable")
            return
        }
        onFoundCb = onFound
        onErrorCb = onError
        registerReceiver()
        try {
            manager?.discoverPeers(channel, object : WifiP2pManager.ActionListener {
                override fun onSuccess() {}
                override fun onFailure(reason: Int) {
                    main.post { onError("Wi-Fi Direct discovery failed ($reason)") }
                }
            })
        } catch (e: SecurityException) {
            onError("Nearby Wi-Fi permission denied")
        }
    }

    /** Group owner socket: hand the invite to any peer that connects. */
    private fun startInviteServer(inviteUri: String) {
        if (server != null) return
        thread(isDaemon = true) {
            try {
                val s = ServerSocket()
                s.reuseAddress = true
                s.bind(InetSocketAddress(port))
                server = s
                while (!s.isClosed) {
                    val sock = try {
                        s.accept()
                    } catch (e: Exception) {
                        break
                    }
                    thread(isDaemon = true) {
                        try {
                            sock.getOutputStream().apply {
                                write((inviteUri + "\n").toByteArray())
                                flush()
                            }
                        } catch (_: Exception) {
                        } finally {
                            runCatching { sock.close() }
                        }
                    }
                }
            } catch (_: Exception) {
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun registerReceiver() {
        if (receiver != null) return
        val filter = IntentFilter().apply {
            addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
        }
        val r = object : BroadcastReceiver() {
            @SuppressLint("MissingPermission")
            override fun onReceive(ctx: Context?, intent: Intent?) {
                when (intent?.action) {
                    WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> requestAndConnect()
                    WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> onConnectionChanged()
                }
            }
        }
        receiver = r
        // Discovery broadcasts are not "exported" from another app; flag for 34+.
        if (android.os.Build.VERSION.SDK_INT >= 34) {
            context.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(r, filter)
        }
    }

    @SuppressLint("MissingPermission")
    private fun requestAndConnect() {
        // Only the scanner side auto-connects to a discovered peer.
        if (onFoundCb == null) return
        val mgr = manager ?: return
        val ch = channel ?: return
        try {
            mgr.requestPeers(ch) { peers ->
                val device: WifiP2pDevice = peers.deviceList.firstOrNull() ?: return@requestPeers
                val config = android.net.wifi.p2p.WifiP2pConfig().apply {
                    deviceAddress = device.deviceAddress
                }
                try {
                    mgr.connect(ch, config, object : WifiP2pManager.ActionListener {
                        override fun onSuccess() {}
                        override fun onFailure(reason: Int) {
                            main.post { onErrorCb?.invoke("Wi-Fi Direct connect failed ($reason)") }
                        }
                    })
                } catch (e: SecurityException) {
                    main.post { onErrorCb?.invoke("Nearby Wi-Fi permission denied") }
                }
            }
        } catch (e: SecurityException) {
            main.post { onErrorCb?.invoke("Nearby Wi-Fi permission denied") }
        }
    }

    @SuppressLint("MissingPermission")
    private fun onConnectionChanged() {
        val mgr = manager ?: return
        val ch = channel ?: return
        if (onFoundCb == null) return // host side serves; only scanner reads
        try {
            mgr.requestConnectionInfo(ch) { info ->
                if (info.groupFormed && !info.isGroupOwner) {
                    val host = info.groupOwnerAddress?.hostAddress ?: return@requestConnectionInfo
                    readInviteFrom(host)
                }
            }
        } catch (e: SecurityException) {
        }
    }

    /** Scanner side: connect to the group owner and read the invite line. */
    private fun readInviteFrom(host: String) {
        thread(isDaemon = true) {
            // The group owner's server may take a moment to come up.
            repeat(10) {
                try {
                    Socket().use { sock ->
                        sock.connect(InetSocketAddress(host, port), 3000)
                        val line = BufferedReader(InputStreamReader(sock.getInputStream()))
                            .readLine()
                            ?.trim()
                        if (line != null && line.startsWith("talkrypt://")) {
                            main.post {
                                onFoundCb?.invoke(NearbyDiscovery.Peer("Wi-Fi Direct peer", line))
                            }
                            return@thread
                        }
                    }
                } catch (_: Exception) {
                    Thread.sleep(500)
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    override fun stop() {
        try {
            receiver?.let { context.unregisterReceiver(it) }
        } catch (_: Exception) {
        }
        receiver = null
        runCatching { server?.close() }
        server = null
        try {
            channel?.let { ch ->
                manager?.stopPeerDiscovery(ch, null)
                manager?.cancelConnect(ch, null)
            }
        } catch (e: SecurityException) {
        }
        onFoundCb = null
        onErrorCb = null
    }
}
