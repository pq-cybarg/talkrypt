package com.talkrypt.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import kotlin.concurrent.thread

/**
 * Foreground service that keeps the process — and therefore the live
 * `TalkryptClient` connections in [SessionHub.sessions] — alive while at least
 * one chat is on the [Persistence.ALWAYS_ON] tier, even when the Activity is
 * gone. It owns a headless poll loop that drains FFI events into the shared
 * model whenever the Activity isn't doing so itself (gated on
 * [SessionHub.foreground], so the queue is drained exactly once), persisting
 * messages that arrive with no UI open. On start (and after reboot, via
 * [BootReceiver]) it reconnects every always-on chat.
 *
 * Honest limits (SECURITY-AUDIT §3b): this keeps the SESSION alive only while
 * the PROCESS is — Android may still kill a foreground service under extreme
 * memory pressure, and the user can force-stop. After a real teardown a chat
 * RECONNECTS (a fresh session to the same .onion) on next start; it does not
 * resume the exact ratchet (that would require sealing evolving session state,
 * weakening forward secrecy — out of scope).
 */
class ChatService : Service() {
    private val ui = Handler(Looper.getMainLooper())
    private val store by lazy { ChatStore(this) }
    private var polling = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        goForeground()
        reconnectAlwaysOn()
        startPolling()
        return START_STICKY
    }

    private fun goForeground() {
        val n = buildNotification()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIF_ID, n)
        }
    }

    /** Reconnect every always-on chat that isn't already connected. */
    private fun reconnectAlwaysOn() {
        for (lc in SessionHub.sessions.all()) {
            if (lc.meta.persistence != Persistence.ALWAYS_ON || lc.client != null) continue
            val plan = reconnectPlan(lc.meta)
            if (plan == ReconnectPlan.IMPOSSIBLE) continue
            val net = if (plan == ReconnectPlan.HOST_TOR || plan == ReconnectPlan.JOIN_TOR) "Tor" else "LAN"
            attemptReconnect(lc, net, retriesLeft = 2)
        }
    }

    /** Try one reconnect; on a (likely transient) failure, retry a bounded number
     *  of times with a delay. Every attempt/outcome is surfaced so the user sees
     *  which chat, over what transport, and why it failed. */
    private fun attemptReconnect(lc: LiveChat, net: String, retriesLeft: Int) {
        if (lc.client != null) return
        val meta = lc.meta
        sys(meta.id, lc, "reconnecting “${meta.title}” over $net…")
        thread {
            runCatching { ChatNet.connect(applicationContext, meta) }
                .onSuccess { c ->
                    ui.post {
                        lc.client = c
                        if (meta.role == Role.HOST) {
                            runCatching { lc.meta = lc.meta.copy(inviteUri = c.inviteUri()) }
                        }
                        sys(meta.id, lc, "reconnected “${meta.title}” over $net")
                        updateNotification()
                    }
                }
                .onFailure { e ->
                    ui.post {
                        if (lc.client != null) return@post
                        val why = ChatNet.friendlyError(e.message)
                        if (retriesLeft > 0) {
                            sys(meta.id, lc, "reconnect failed for “${meta.title}” ($net): $why — retrying…")
                            ui.postDelayed({ attemptReconnect(lc, net, retriesLeft - 1) }, RETRY_MS)
                        } else {
                            sys(meta.id, lc, "reconnect failed for “${meta.title}” ($net): $why")
                        }
                    }
                }
        }
    }

    /** Record + persist a system line for a chat (so reconnect detail survives). */
    private fun sys(id: String, lc: LiveChat, text: String) {
        sessions().recordIncoming(
            id,
            ChatMsg(MsgKind.SYSTEM, null, null, false, text, null, System.currentTimeMillis()),
        )
        runCatching { store.save(lc.meta, lc.history) }
    }

    /**
     * Headless drain. Yields its tick while an Activity is resumed (it drains +
     * renders itself), so the destructive FFI queue is consumed once. Persists
     * any chat that received events. Stops the service when no always-on chat
     * remains.
     */
    private fun startPolling() {
        if (polling) return
        polling = true
        ui.postDelayed(object : Runnable {
            override fun run() {
                if (!polling) return
                if (!SessionHub.foreground) {
                    for (lc in sessions().live()) {
                        val c = lc.client ?: continue
                        var got = false
                        while (true) {
                            val e = runCatching { c.pollEvent() }.getOrNull() ?: break
                            applyEvent(sessions(), lc.meta.id, lc, e)
                            got = true
                        }
                        if (got && lc.meta.persistence != Persistence.EPHEMERAL) {
                            runCatching { store.save(lc.meta, lc.history) }
                        }
                    }
                }
                if (!anyAlwaysOn(sessions())) {
                    stopSelf()
                    return
                }
                ui.postDelayed(this, POLL_MS)
            }
        }, POLL_MS)
    }

    override fun onDestroy() {
        super.onDestroy()
        polling = false
    }

    private fun sessions() = SessionHub.sessions

    private fun buildNotification(): Notification {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            val chan = NotificationChannel(CHAN, "talkrypt connections", NotificationManager.IMPORTANCE_LOW)
            chan.setShowBadge(false)
            mgr.createNotificationChannel(chan)
        }
        val alwaysOn = sessions().all().filter { it.meta.persistence == Persistence.ALWAYS_ON }
        val n = alwaysOn.size
        val connected = alwaysOn.count { it.client != null }
        // Surface health, not just a count: how many are connected vs offline.
        val status = when {
            n == 0 -> "no always-on chats"
            connected == n -> "$n always-on · all connected"
            else -> "$n always-on · $connected connected, ${n - connected} offline"
        }
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        @Suppress("DEPRECATION")
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHAN) else Notification.Builder(this)
        return b
            .setContentTitle("talkrypt")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification() {
        getSystemService(NotificationManager::class.java).notify(NOTIF_ID, buildNotification())
    }

    companion object {
        private const val CHAN = "talkrypt.connections"
        private const val NOTIF_ID = 0x7A10
        private const val POLL_MS = 500L
        private const val RETRY_MS = 8000L // delay between bounded reconnect retries

        /** Start the service if any always-on chat exists; no-op otherwise. */
        fun startIfNeeded(ctx: Context) {
            if (!anyAlwaysOn(SessionHub.sessions)) return
            val i = Intent(ctx, ChatService::class.java)
            if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, ChatService::class.java))
        }
    }
}
