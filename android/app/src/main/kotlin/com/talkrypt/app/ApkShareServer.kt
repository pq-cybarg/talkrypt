package com.talkrypt.app

import android.content.Context
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.net.ServerSocket
import kotlin.concurrent.thread

/**
 * Peer-to-peer app distribution over the local network.
 *
 * Serves THIS app's own APK so a friend on the same Wi-Fi/hotspot can download
 * and sideload it — no app store, no internet. The friend opens the printed URL
 * (or scans its QR), downloads `talkrypt.apk`, and installs it (they must allow
 * "install unknown apps" once).
 *
 * Minimal single-route HTTP/1.0 server (`GET /talkrypt.apk`) on an ephemeral
 * port. Bytes are served with the Android package content type so the browser
 * offers to install. This is the "skeleton that works" — good enough for
 * in-person sharing; not a hardened web server.
 */
class ApkShareServer(private val apkPath: String) {
    @Volatile
    private var server: ServerSocket? = null

    /** The shareable URL once [start] succeeds, else null. */
    var url: String? = null
        private set

    /** Start serving; returns the URL, or null if no LAN address was found. */
    fun start(): String? {
        val ip = lanIp() ?: return null
        val s = ServerSocket(0)
        server = s
        val u = "http://$ip:${s.localPort}/talkrypt.apk"
        url = u
        thread(isDaemon = true) {
            while (!s.isClosed) {
                val sock = try {
                    s.accept()
                } catch (e: Exception) {
                    break
                }
                thread(isDaemon = true) {
                    try {
                        // Consume the request line + headers (we serve one file).
                        val input = sock.getInputStream().bufferedReader()
                        input.readLine()
                        while (true) {
                            val line = input.readLine() ?: break
                            if (line.isEmpty()) break
                        }
                        val apk = File(apkPath)
                        val out = sock.getOutputStream()
                        if (apk.exists()) {
                            val header = "HTTP/1.0 200 OK\r\n" +
                                "Content-Type: application/vnd.android.package-archive\r\n" +
                                "Content-Length: ${apk.length()}\r\n" +
                                "Content-Disposition: attachment; filename=\"talkrypt.apk\"\r\n" +
                                "Connection: close\r\n\r\n"
                            out.write(header.toByteArray())
                            apk.inputStream().use { it.copyTo(out) }
                        } else {
                            out.write(
                                "HTTP/1.0 404 Not Found\r\nConnection: close\r\n\r\n".toByteArray(),
                            )
                        }
                        out.flush()
                    } catch (_: Exception) {
                        // best-effort; drop this connection
                    } finally {
                        try {
                            sock.close()
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }
        return u
    }

    fun stop() {
        try {
            server?.close()
        } catch (_: Exception) {
        }
    }

    companion object {
        /** This app's installed APK path (the base.apk for this package). */
        fun apkPath(ctx: Context): String = ctx.applicationInfo.sourceDir

        /**
         * The best LAN IPv4 to advertise so a peer on the same Wi-Fi can dial us.
         * The old "first non-loopback IPv4" was fragile: on a device that's
         * USB-connected (rndis), tethering, on cellular (rmnet), or running
         * Wi-Fi Direct (p2p), it could hand out an address the peer can't reach.
         * We now skip those interfaces and prefer Wi-Fi (wlan*), then any
         * site-local (192.168/10/172.16) address.
         */
        fun lanIp(): String? {
            val candidates = mutableListOf<Pair<Int, String>>() // (priority, ip) — lower is better
            try {
                for (nif in NetworkInterface.getNetworkInterfaces()) {
                    if (!nif.isUp || nif.isLoopback || nif.isVirtual) continue
                    val name = (nif.name ?: "").lowercase()
                    // Skip USB-tethering, cellular, and Wi-Fi Direct interfaces.
                    if (name.startsWith("rndis") || name.startsWith("usb") ||
                        name.startsWith("rmnet") || name.startsWith("p2p")
                    ) continue
                    for (addr in nif.inetAddresses) {
                        if (addr.isLoopbackAddress || addr.isLinkLocalAddress || addr !is Inet4Address) continue
                        val ip = addr.hostAddress ?: continue
                        val priority = when {
                            name.startsWith("wlan") -> 0     // Wi-Fi — best
                            addr.isSiteLocalAddress -> 1     // any private LAN address
                            else -> 2                        // public/other — last resort
                        }
                        candidates.add(priority to ip)
                    }
                }
            } catch (_: Exception) {
            }
            return candidates.minByOrNull { it.first }?.second
        }
    }
}
