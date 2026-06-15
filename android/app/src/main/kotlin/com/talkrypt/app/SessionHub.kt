package com.talkrypt.app

import android.content.Context

/**
 * Process-lifetime singletons shared by [MainActivity] and the always-on
 * [ChatService], so both observe ONE set of live chats (the Activity renders
 * them; the service keeps the process — hence the connections — alive).
 *
 * The poll loop that drains FFI events is owned by whichever component is
 * "primary": the Activity drains + renders while it's resumed; the service
 * drains headlessly while it isn't. [foreground] is the handoff flag — exactly
 * one side drains at a time, so no event is consumed twice (pollEvent is
 * destructive).
 */
object SessionHub {
    val sessions = Sessions()

    /** True while a resumed Activity is draining events itself; the service
     *  poll loop yields its tick so the FFI event queue is drained once. */
    @Volatile
    var foreground = false

    /**
     * Load saved chats from sealed storage into [sessions] as disconnected
     * records (history only). Skips any chat already in memory, so it never
     * clobbers a live session or unsaved in-memory history. Used by the Activity
     * on launch and by [BootReceiver] after a reboot.
     */
    fun hydrate(ctx: Context) {
        val store = ChatStore(ctx)
        for (id in runCatching { store.ids() }.getOrDefault(emptyList())) {
            if (sessions.get(id) != null) continue
            val (meta, hist) = store.load(id) ?: continue
            val lc = sessions.open(meta, null)
            lc.history.addAll(hist)
        }
    }
}
