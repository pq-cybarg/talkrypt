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
            // SUB-SPEC A: a peer's resolved self-declared name. `tier` badges verified
            // (account-linked) names, `caveat` carries a collision warning, and
            // `safetyNumber` is the always-available honest fallback. An EMPTY label
            // means the name was suppressed or went stale (policy/rename): we drop the
            // displayed name and fall back to the safety number, never showing a name
            // we can't trust.
            val mem = lc.roster.getOrPut(e.from) { Member(e.from) }
            mem.nameTier = e.tier
            mem.safetyNumber = e.safetyNumber
            val badge = when (e.tier) { "Linked" -> "🔗 "; "RegistryConfirmed" -> "✓ "; else -> "" }
            val cav = if (e.caveat.isNotEmpty()) " ⚠ ${e.caveat}" else ""
            if (e.label.isNotEmpty()) {
                mem.display = e.label
                sysMsg("$badge${e.from.take(8)} is “${e.label}”$cav", now)
            } else {
                // Suppressed / stale: forget any prior displayed name for this peer so
                // bubbles fall back to the safety number, not a stale/spoofed callsign.
                mem.display = null
                val sn = e.safetyNumber.ifEmpty { e.from.take(8) }
                sysMsg("${e.from.take(8)} — no verified name ($sn)$cav", now)
            }
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
        is FfiEvent.Vouch -> {
            // SUB-SPEC C: a subject's vouch standing changed (display-only; never gates
            // access). Antibody: inflation_rejected snaps to neutral, never below.
            val mem = lc.roster.getOrPut(e.subject) { Member(e.subject) }
            mem.vouched = e.vouched
            when {
                e.inflationRejected ->
                    sysMsg("${e.subject.take(8)} vouch inflation rejected (sybil) — neutral", now)
                e.vouched ->
                    sysMsg("✳ ${e.subject.take(8)} is vouched (score ${e.weightedScore})", now)
                else ->
                    sysMsg("${e.subject.take(8)} vouch below threshold", now)
            }
        }
        is FfiEvent.Delivered ->
            // D1 delivery receipt — the peer acked our message; note it quietly.
            sysMsg("✓ delivered", now)
        is FfiEvent.OutboxDropped ->
            // D1: a capped/expired outbox drop is never silent (data-loss honesty).
            sysMsg("⚠ ${e.count} queued message(s) dropped (outbox full)", now)
        is FfiEvent.BeaconSeen ->
            // SUB-SPEC A / #68: a nearby device is beaconing this chat over local radio.
            sysMsg("📡 a nearby device is beaconing this chat", now)
        is FfiEvent.PromoteProposed ->
            // SUB-SPEC D2: someone proposed making this chat persistent.
            sysMsg("${e.by.take(8)} proposed making this chat persistent", now)
        is FfiEvent.Promoted ->
            sysMsg("this chat is now persistent", now)
        is FfiEvent.PromoteAborted ->
            sysMsg("promotion aborted — this chat stays ephemeral", now)
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
