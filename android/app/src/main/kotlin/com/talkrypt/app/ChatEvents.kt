package com.talkrypt.app

import uniffi.talkrypt_ffi.FfiEvent

/**
 * The single place that folds an FFI event into the shared session model —
 * appends the history line and updates the roster. UI-FREE, so it runs the same
 * whether the foreground Activity drains the event (then renders the returned
 * [ChatMsg]) or the headless [ChatService] drains it in the background.
 *
 * Returns the [ChatMsg] it recorded so the caller can render exactly what was
 * stored (no second recording, no drift between model and view).
 */
fun applyEvent(sessions: Sessions, id: String, lc: LiveChat, e: FfiEvent): ChatMsg {
    val now = System.currentTimeMillis()
    val msg = when (e) {
        is FfiEvent.Message ->
            ChatMsg(MsgKind.MESSAGE, e.from, e.from.take(8), false, e.text, e.marking.ifEmpty { null }, now)
        is FfiEvent.Connected -> {
            lc.roster.getOrPut(e.fingerprint) { Member(e.fingerprint) }.connected = true
            sysMsg("● ${e.fingerprint.take(8)} connected", now)
        }
        is FfiEvent.Disconnected -> {
            lc.roster[e.fingerprint]?.connected = false
            sysMsg("○ ${e.fingerprint.take(8)} left", now)
        }
        is FfiEvent.Identity -> {
            val mem = lc.roster.getOrPut(e.accountFingerprint) { Member(e.accountFingerprint) }
            mem.display = e.username.ifEmpty { e.accountFingerprint.take(8) }
            mem.contact = e.contact
            mem.friend = e.friend
            sysMsg(identityLine(e.contact, e.friend, mem.display!!), now)
        }
        is FfiEvent.Error -> sysMsg("! ${e.message}", now)
    }
    sessions.recordIncoming(id, msg)
    return msg
}

/** The roster status line shown when a peer presents an account identity. */
fun identityLine(contact: Boolean, friend: Boolean, who: String): String = when {
    friend -> "✓ friend $who"
    contact -> "• contact $who"
    else -> "• account $who (not a contact)"
}

private fun sysMsg(text: String, ts: Long) = ChatMsg(MsgKind.SYSTEM, null, null, false, text, null, ts)
