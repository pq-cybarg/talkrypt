package com.talkrypt.app

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Handler
import android.os.Looper
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.Collections
import kotlin.concurrent.thread

/**
 * SUB-SPEC A / #68: a Wi-Fi (NSD / mDNS) radio backend for the pre-session CQ
 * **beacon** — a second [LocalBeaconBackend] alongside [BleBeaconBackend].
 *
 * BLE is the low-power short-range beacon; this carries the same OPAQUE, already
 * PQ+AES-sealed blob over the local Wi-Fi/LAN, which is better for larger payloads
 * and longer range. The beacon's *broadcast* semantics (announce to anyone nearby,
 * no pairing) map cleanly onto **Network Service Discovery**: we register an mDNS
 * service and serve the blob over a tiny TCP socket the service advertises; a
 * scanner discovers + resolves the service, connects, and reads the blob. (Wi-Fi
 * Direct — see [WifiDirectNearby] — is connection/pairing-oriented and a poorer fit
 * for a broadcast beacon.)
 *
 * Same non-negotiable invariant as every backend: it only ever moves the opaque
 * sealed bytes, never keys or plaintext.
 *
 * **Emulator note:** NsdManager works on the emulator, but two emulators are on
 * isolated NAT networks, so cross-device mDNS needs the adb-forward LAN bridge. For
 * a single-device round-trip, [lastAdvertised] exposes the most recent blob core
 * asked us to broadcast — feed it back through `deliverBeacon` to exercise the full
 * core path with the radio spoofed (identical to the BLE backend's self-test).
 */
class WifiBeaconBackend(private val context: Context) : RadioBeacon {
    private val main = Handler(Looper.getMainLooper())
    private val nsd = context.getSystemService(NsdManager::class.java)

    private var serverSocket: ServerSocket? = null
    private var registrationListener: NsdManager.RegistrationListener? = null
    private var discoveryListener: NsdManager.DiscoveryListener? = null
    private val seen = Collections.synchronizedSet(mutableSetOf<String>())

    @Volatile private var blob: ByteArray = ByteArray(0)

    /** The most recent blob passed to [advertise] (for the emulator spoof self-test). */
    override fun lastAdvertised(): ByteArray? = blob.takeIf { it.isNotEmpty() }

    override fun advertise(blob: ByteArray) {
        this.blob = blob
        val n = nsd ?: return
        try {
            // (Re)start a TCP server that hands the current blob to any connection.
            serverSocket?.let { runCatching { it.close() } }
            val server = ServerSocket(0) // ephemeral port
            serverSocket = server
            thread(isDaemon = true, name = "tk-beacon-serve") {
                while (!server.isClosed) {
                    val client = try { server.accept() } catch (e: Exception) { break }
                    thread(isDaemon = true) {
                        runCatching {
                            client.getOutputStream().use { it.write(this.blob); it.flush() }
                            client.close()
                        }
                    }
                }
            }
            // Advertise the beacon service on that port so scanners can find it.
            registrationListener?.let { runCatching { n.unregisterService(it) } }
            val info = NsdServiceInfo().apply {
                serviceName = SERVICE_NAME
                serviceType = SERVICE_TYPE
                port = server.localPort
            }
            val reg = object : NsdManager.RegistrationListener {
                override fun onServiceRegistered(s: NsdServiceInfo?) {}
                override fun onRegistrationFailed(s: NsdServiceInfo?, err: Int) {}
                override fun onServiceUnregistered(s: NsdServiceInfo?) {}
                override fun onUnregistrationFailed(s: NsdServiceInfo?, err: Int) {}
            }
            registrationListener = reg
            n.registerService(info, NsdManager.PROTOCOL_DNS_SD, reg)
        } catch (e: Exception) {
            // Radio/service unavailable — best-effort, never crash the caller.
        }
    }

    override fun stop() {
        val n = nsd
        try {
            registrationListener?.let { n?.unregisterService(it) }
            discoveryListener?.let { n?.stopServiceDiscovery(it) }
            serverSocket?.close()
        } catch (e: Exception) {
        }
        registrationListener = null
        discoveryListener = null
        serverSocket = null
        seen.clear()
        blob = ByteArray(0)
    }

    /**
     * Discover nearby beacon services; for each new one, resolve it, TCP-connect,
     * read the opaque blob, and hand it to [onBlob] with a coarse `source` (host).
     * Wire `onBlob` to `FfiBeacon.deliverBeacon(blob, source)`.
     */
    override fun startScanning(onBlob: (ByteArray, String) -> Unit, onError: (String) -> Unit) {
        val n = nsd ?: run { onError("NSD unavailable"); return }
        val listener = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(serviceType: String?) {}
            override fun onDiscoveryStopped(serviceType: String?) {}
            override fun onStartDiscoveryFailed(serviceType: String?, err: Int) { onError("discovery failed ($err)") }
            override fun onStopDiscoveryFailed(serviceType: String?, err: Int) {}
            override fun onServiceLost(s: NsdServiceInfo?) {}
            override fun onServiceFound(s: NsdServiceInfo?) {
                val svc = s ?: return
                if (svc.serviceType?.contains("talkrypt-beacon") != true) return
                if (seen.add(svc.serviceName ?: return)) resolve(svc, onBlob)
            }
        }
        discoveryListener = listener
        try {
            n.discoverServices(SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            onError("discovery error")
        }
    }

    private fun resolve(svc: NsdServiceInfo, onBlob: (ByteArray, String) -> Unit) {
        val n = nsd ?: return
        val rl = object : NsdManager.ResolveListener {
            override fun onResolveFailed(s: NsdServiceInfo?, err: Int) {}
            override fun onServiceResolved(s: NsdServiceInfo?) {
                val host = s?.host ?: return
                val port = s.port
                thread(isDaemon = true, name = "tk-beacon-read") {
                    runCatching {
                        Socket(host as InetAddress, port).use { sock ->
                            val bytes = sock.getInputStream().readBytes()
                            if (bytes.isNotEmpty()) main.post { onBlob(bytes, host.hostAddress ?: "wifi") }
                        }
                    }
                }
            }
        }
        try { n.resolveService(svc, rl) } catch (e: Exception) {}
    }

    companion object {
        // A DNS-SD service type distinct from anything else on the network.
        const val SERVICE_TYPE = "_talkrypt-beacon._tcp."
        const val SERVICE_NAME = "talkrypt-cq"
    }
}
