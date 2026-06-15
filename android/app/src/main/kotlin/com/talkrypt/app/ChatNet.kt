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

    /** Bind every interface so the listener is reachable via whatever address we
     *  advertise (loopback, the Wi-Fi IP, or the emulator's eth0). */
    fun lanBind(): String = "0.0.0.0:$LAN_PORT"

    /** Heuristic: are we on the Android emulator (vs. a real handset)? */
    fun isEmulator(): Boolean {
        val fp = Build.FINGERPRINT ?: ""
        return fp.startsWith("generic") || fp.contains("emulator") || fp.contains("sdk_gphone") ||
            Build.MODEL.contains("sdk_gphone") || Build.PRODUCT.contains("sdk_gphone") ||
            Build.HARDWARE.contains("ranchu") || Build.HARDWARE.contains("goldfish")
    }

    /** The dial address a joiner should use: our Wi-Fi/hotspot IP on a real
     *  device, or the host-loopback alias 10.0.2.2 on an emulator. */
    fun lanAdvertise(): String =
        if (isEmulator()) "10.0.2.2:$LAN_PORT" else "${ApkShareServer.lanIp() ?: "127.0.0.1"}:$LAN_PORT"

    fun torDirPath(ctx: Context, sub: String): String =
        File(File(ctx.filesDir, "tor"), sub).absolutePath

    fun freshTorSub(): String = "c" + System.nanoTime().toString(36)

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
            ReconnectPlan.HOST_TOR -> TalkryptClient.hostTor(meta.title, pst, torDirPath(ctx, meta.torDir ?: freshTorSub()))
            ReconnectPlan.HOST_LAN -> TalkryptClient.host(lanBind(), meta.title, pst, lanAdvertise())
            ReconnectPlan.JOIN_TOR -> TalkryptClient.joinTor(meta.inviteUri!!, torDirPath(ctx, meta.torDir ?: freshTorSub()))
            ReconnectPlan.JOIN_LAN -> TalkryptClient.join(meta.inviteUri!!)
            ReconnectPlan.IMPOSSIBLE -> throw IllegalStateException("no saved invite to reconnect")
        }
        runCatching { c.presentAccount(account(ctx), null) }
        runCatching { loadContacts(ctx, c) }
        if (meta.role == Role.HOST) runCatching { c.setAccessMode(meta.access) }
        return c
    }
}
