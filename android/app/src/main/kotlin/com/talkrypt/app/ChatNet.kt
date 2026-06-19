package com.talkrypt.app

import android.content.Context
import android.os.Build
import uniffi.talkrypt_ffi.Account
import uniffi.talkrypt_ffi.TalkryptClient
import java.io.File

/**
 * Shared chat-networking helpers used by BOTH the Activity and the always-on
 * [ChatService], so a chat connects identically whichever component drives it.
 * Stateless — everything derives from the [Context] (filesDir for Tor state +
 * the "talkrypt" SharedPreferences for the account/contacts). This is the single
 * place that turns a saved [ChatMeta] into a live [TalkryptClient]; both
 * `MainActivity.reconnect` and `ChatService` call [connect].
 */
object ChatNet {
    const val LAN_PORT = 9779
    private const val CONTACT_SEP = "\u001F"

    /**
     * Find a LAN port that's free right now, starting at [LAN_PORT] and stepping
     * up. Each hosted chat needs its OWN TCP listener, so a fixed port would let
     * only one chat host at a time (the second bind fails — "transport error").
     * There's a tiny TOCTOU window before the native transport binds it; fine for
     * user-driven hosting. Falls back to [LAN_PORT] if the whole range is busy.
     */
    fun allocLanPort(): Int {
        for (p in LAN_PORT until LAN_PORT + 64) {
            try {
                java.net.ServerSocket().use { it.bind(java.net.InetSocketAddress("0.0.0.0", p)) }
                return p
            } catch (_: Exception) { /* in use — try the next */ }
        }
        return LAN_PORT
    }

    /** Bind every interface (on [port]) so the listener is reachable via whatever
     *  address we advertise (loopback, the Wi-Fi IP, or the emulator's eth0). */
    fun lanBind(port: Int): String = "0.0.0.0:$port"

    /** Heuristic: are we on the Android emulator (vs. a real handset)? */
    fun isEmulator(): Boolean {
        val fp = Build.FINGERPRINT ?: ""
        return fp.startsWith("generic") || fp.contains("emulator") || fp.contains("sdk_gphone") ||
            Build.MODEL.contains("sdk_gphone") || Build.PRODUCT.contains("sdk_gphone") ||
            Build.HARDWARE.contains("ranchu") || Build.HARDWARE.contains("goldfish")
    }

    /** The dial address a joiner should use (on [port]): our Wi-Fi/hotspot IP on a
     *  real device, or the host-loopback alias 10.0.2.2 on an emulator. */
    fun lanAdvertise(port: Int): String =
        if (isEmulator()) "10.0.2.2:$port" else "${ApkShareServer.lanIp() ?: "127.0.0.1"}:$port"

    fun torDirPath(ctx: Context, sub: String): String =
        File(File(ctx.filesDir, "tor"), sub).absolutePath

    fun freshTorSub(): String = "c" + System.nanoTime().toString(36)

    /**
     * One STABLE Tor state dir shared by every chat. The FFI bootstraps a single
     * Arti client (process-global) the first time Tor is used and reuses it for
     * all chats, so they must share one state dir — and a stable path lets the
     * directory cache (consensus/descriptors) persist across launches, turning
     * cold ~minute bootstraps into warm ~seconds ones. (Per-chat random subdirs
     * would defeat both: Arti locks its dir, and a fresh dir each launch is cold.)
     */
    fun sharedTorDir(ctx: Context): String = torDirPath(ctx, "shared")

    /** The persistent pseudonymous account (generated + saved on first use). */
    fun account(ctx: Context): Account {
        val prefs = ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE)
        prefs.getString("account_seed", null)?.let { seed ->
            runCatching { return Account.fromSeedHex(seed) }
        }
        val a = Account.generate()
        prefs.edit().putString("account_seed", a.seedHex()).apply()
        return a
    }

    /** Re-apply saved contacts to a freshly built client (so peers are
     *  recognized after a reconnect). Same SharedPreferences format the contact
     *  UI in MainActivity writes. */
    fun loadContacts(ctx: Context, client: TalkryptClient) {
        val prefs = ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE)
        prefs.getStringSet("contacts", emptySet()).orEmpty().forEach {
            val p = it.split(CONTACT_SEP)
            if (p.size == 3) runCatching { client.addContactHex(p[0], p[1].ifEmpty { null }, p[2] == "1") }
        }
    }

    /**
     * Build (connect) a live client for a saved chat per its [reconnectPlan].
     * BLOCKING (FFI bootstrap/handshake) — call OFF the main thread. The caller
     * assigns the result to the LiveChat and, for a re-hosted LAN chat, refreshes
     * `meta.inviteUri` from `client.inviteUri()` (a LAN re-host yields a fresh
     * invite; a Tor re-host comes back on the same .onion). Throws on an
     * IMPOSSIBLE plan (a join with no saved invite).
     */
    fun connect(ctx: Context, meta: ChatMeta): TalkryptClient {
        val pst = meta.posture.ifEmpty { "pq-pure" }
        val c = when (reconnectPlan(meta)) {
            ReconnectPlan.HOST_TOR -> TalkryptClient.hostTor(meta.title, pst, sharedTorDir(ctx))
            ReconnectPlan.HOST_LAN -> { val p = allocLanPort(); TalkryptClient.host(lanBind(p), meta.title, pst, lanAdvertise(p)) }
            ReconnectPlan.JOIN_TOR -> TalkryptClient.joinTor(meta.inviteUri!!, sharedTorDir(ctx))
            ReconnectPlan.JOIN_LAN -> TalkryptClient.join(meta.inviteUri!!)
            ReconnectPlan.IMPOSSIBLE -> throw IllegalStateException("no saved invite to reconnect")
        }
        runCatching { c.presentAccount(account(ctx), null) }
        runCatching { loadContacts(ctx, c) }
        if (meta.role == Role.HOST) runCatching { c.setAccessMode(meta.access) }
        return c
    }

    /** Turn a raw FFI/Arti error into a human, actionable line for the chat. */
    fun friendlyError(raw: String?): String {
        val m = (raw ?: "unknown error").lowercase()
        return when {
            m.contains("hidden service circuit") || m.contains("onion") ->
                "host unreachable over Tor — its onion didn't answer (offline, or not republished yet)"
            m.contains("timed out") || m.contains("timeout") ->
                "timed out reaching the host (unreachable from this network?)"
            m.contains("bootstrap") ->
                "Tor isn't ready yet (still bootstrapping)"
            m.contains("no saved invite") ->
                "can't reconnect — no saved invite for this chat"
            else -> raw ?: "unknown error"
        }
    }
}
