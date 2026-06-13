package com.talkrypt.app

import uniffi.talkrypt_ffi.TalkryptClient

/** One chat's live state. `client == null` means saved-but-not-connected. */
class LiveChat(
    var meta: ChatMeta,
    var client: TalkryptClient?,
) {
    val history: MutableList<ChatMsg> = mutableListOf()
    val roster: LinkedHashMap<String, Member> = LinkedHashMap()
    var unread: Int = 0
}

/** Process-lifetime owner of all chats. Pure logic — no Android imports — so it
 *  unit-tests on the JVM. The UI observes via [ordered]/[get]/[active]. */
class Sessions {
    private val chats = LinkedHashMap<String, LiveChat>()
    var active: String? = null
        private set

    /** Open (or update) a chat. Reuses an existing record by id. */
    fun open(meta: ChatMeta, client: TalkryptClient?): LiveChat {
        val existing = chats[meta.id]
        if (existing != null) {
            existing.meta = meta
            if (client != null) existing.client = client
            return existing
        }
        val lc = LiveChat(meta, client)
        chats[meta.id] = lc
        return lc
    }

    fun get(id: String): LiveChat? = chats[id]
    fun all(): Collection<LiveChat> = chats.values
    fun live(): List<LiveChat> = chats.values.filter { it.client != null }

    /** Chats sorted most-recent-first (for the list). */
    fun ordered(): List<LiveChat> = chats.values.sortedByDescending { it.meta.lastActivityAt }

    fun touch(id: String, ts: Long) {
        chats[id]?.let { it.meta = it.meta.copy(lastActivityAt = ts) }
    }

    /** The chat currently on screen; opening one clears its unread badge. */
    fun setActive(id: String?) {
        active = id
        if (id != null) chats[id]?.unread = 0
    }

    /** Record an inbound message: append + bump recency; badge if not active. */
    fun recordIncoming(id: String, msg: ChatMsg) {
        val lc = chats[id] ?: return
        lc.history.add(msg)
        lc.meta = lc.meta.copy(lastActivityAt = msg.ts)
        if (active != id) lc.unread += 1
    }

    /** Disconnect a chat but keep its record/history (the Arc client drops). */
    fun disconnect(id: String) { chats[id]?.let { it.client = null } }

    /** Forget a chat entirely. */
    fun remove(id: String) { chats.remove(id) }
}
