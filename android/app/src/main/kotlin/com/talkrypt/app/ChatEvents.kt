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
        is FfiEvent.Message -> {
            // SUB-SPEC A: label the bubble with the sender's resolved self-declared
            // name (set on the roster by a prior Name/Identity event) when we've
            // heard it, else fall back to the fingerprint prefix. This is what makes
            // a CQ callsign actually appear over the peer's messages.
            val who = lc.roster[e.from]?.display ?: e.from.take(8)
            ChatMsg(MsgKind.MESSAGE, e.from, who, false, e.text, e.marking.ifEmpty { null }, now)
        }
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
        is FfiEvent.Name -> {
            // SUB-SPEC A: a peer's resolved self-declared name. Update its roster
            // display and note the change; `tier` badges verified (account-linked)
            // names, `caveat` carries a collision warning.
            val mem = lc.roster.getOrPut(e.from) { Member(e.from) }
            if (e.label.isNotEmpty()) mem.display = e.label
            val badge = when (e.tier) { "Linked" -> "🔗 "; "RegistryConfirmed" -> "✓ "; else -> "" }
            val cav = if (e.caveat.isNotEmpty()) " ⚠ ${e.caveat}" else ""
            val shown = e.label.ifEmpty { e.from.take(8) }
            sysMsg("$badge${e.from.take(8)} is “$shown”$cav", now)
        }
        is FfiEvent.Linkage -> {
            // SUB-SPEC B: a peer disclosed grouping linkage (account-hidden). Mark it
            // as grouped (so it's not rendered as an isolated sybil) and note it.
            val mem = lc.roster.getOrPut(e.subject) { Member(e.subject) }
            mem.grouped = e.verdict
            if (e.verdict) {
                sysMsg("🔗 ${e.subject.take(8)} disclosed grouping ${e.grouping} (account-hidden)", now)
            } else {
                sysMsg("${e.subject.take(8)} presented an invalid grouping proof", now)
            }
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
