package com.talkrypt.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.talkrypt_ffi.FfiEvent

/** The shared event-applier folds FFI events into the model identically whether
 *  the Activity or the headless ChatService drains them (Phase 2b). */
class ChatEventsTest {
    private fun meta(id: String) = ChatMeta(
        id, "#$id", Role.HOST, false, "pq-pure", "open", null, null,
        Persistence.PERSISTENT_LOCAL, "SAFE", 0, 0,
    )

    @Test fun message_is_recorded_and_badged_when_inactive() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        s.open(meta("b"), null)
        s.setActive("b")                       // "a" is in the background
        val msg = applyEvent(s, "a", a, FfiEvent.Message("peerfp", "#a", "hello", ""))!!
        assertEquals(MsgKind.MESSAGE, msg.kind)
        assertEquals("hello", msg.text)
        assertEquals(1, a.history.size)
        assertEquals("hello", a.history[0].text)
        assertEquals(1, s.get("a")!!.unread)   // background chat accrues a badge
    }

    @Test fun message_marking_is_carried() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val msg = applyEvent(s, "a", a, FfiEvent.Message("p", "#a", "x", "SECRET//NOFORN"))!!
        assertEquals("SECRET//NOFORN", msg.marking)
    }

    @Test fun connected_then_disconnected_updates_roster() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val c = applyEvent(s, "a", a, FfiEvent.Connected("abcdef123456"))!!
        assertEquals(MsgKind.SYSTEM, c.kind)
        assertTrue(c.text.contains("abcdef12"))
        assertTrue(a.roster["abcdef123456"]!!.connected)
        applyEvent(s, "a", a, FfiEvent.Disconnected("abcdef123456"))
        assertFalse(a.roster["abcdef123456"]!!.connected)
    }

    @Test fun identity_sets_display_and_contact_flags() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        applyEvent(s, "a", a, FfiEvent.Identity("dev", "acct9999", "alice", false, false))
        val m = a.roster["acct9999"]!!
        assertEquals("alice", m.display)
        assertFalse(m.contact)
        assertFalse(m.friend)
    }

    @Test fun name_updates_roster_display_and_notes() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val m = applyEvent(s, "a", a, FfiEvent.Name("peerfp123456", "", "Whiskey", "Bare", 1uL, "", "sn12ab"))!!
        assertEquals(MsgKind.SYSTEM, m.kind)
        assertTrue(m.text.contains("Whiskey"))
        assertEquals("Whiskey", a.roster["peerfp123456"]!!.display)
        // SUB-SPEC A: the safety number is always captured on the roster member.
        assertEquals("sn12ab", a.roster["peerfp123456"]!!.safetyNumber)
    }

    @Test fun message_bubble_shows_resolved_cq_name_when_known() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        // Before hearing the peer's CQ name, a message is labeled by fingerprint.
        val bare = applyEvent(s, "a", a, FfiEvent.Message("peerfp123456", "#a", "one", ""))!!
        assertEquals("peerfp12", bare.display)
        // After the peer announces its name, later messages carry the resolved name.
        applyEvent(s, "a", a, FfiEvent.Name("peerfp123456", "", "Whiskey", "Bare", 1uL, "", "sn12ab"))
        val named = applyEvent(s, "a", a, FfiEvent.Message("peerfp123456", "#a", "two", ""))!!
        assertEquals("Whiskey", named.display)
    }

    @Test fun suppressed_or_stale_name_drops_display_and_falls_back_to_safety_number() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        // A name is resolved and shown...
        applyEvent(s, "a", a, FfiEvent.Name("peerfp123456", "", "Whiskey", "Bare", 1uL, "", "sn12ab"))
        assertEquals("Whiskey", a.roster["peerfp123456"]!!.display)
        // ...then it's suppressed / goes stale (empty label) — the displayed name is
        // dropped and the honest safety-number fallback is surfaced, never a stale name.
        val m = applyEvent(
            s, "a", a,
            FfiEvent.Name("peerfp123456", "", "", "Bare", 2uL, "name changed", "sn99zz"),
        )!!
        assertEquals(null, a.roster["peerfp123456"]!!.display)
        assertEquals("sn99zz", a.roster["peerfp123456"]!!.safetyNumber)
        assertTrue(m.text.contains("sn99zz"))
        assertTrue(m.text.contains("no verified name"))
        // A later message from that peer no longer shows the stale callsign.
        val msg = applyEvent(s, "a", a, FfiEvent.Message("peerfp123456", "#a", "hi", ""))!!
        assertEquals("peerfp12", msg.display)
    }

    @Test fun linkage_marks_peer_as_grouped_and_notes_it() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val m = applyEvent(s, "a", a, FfiEvent.Linkage("peerfp123456", "abcd1234", true))!!
        assertEquals(MsgKind.SYSTEM, m.kind)
        assertTrue(m.text.contains("grouping"))
        assertTrue(a.roster["peerfp123456"]!!.grouped)
    }

    @Test fun vouch_marks_member_vouched_and_notes_it() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val m = applyEvent(s, "a", a, FfiEvent.Vouch("peerfp123456", 6, true, false))!!
        assertEquals(MsgKind.SYSTEM, m.kind)
        assertTrue(m.text.contains("vouched"))
        assertTrue(a.roster["peerfp123456"]!!.vouched)
    }

    @Test fun vouch_inflation_rejected_is_neutral_not_vouched() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val m = applyEvent(s, "a", a, FfiEvent.Vouch("peerfp123456", -3, false, true))!!
        assertTrue(m.text.contains("inflation rejected"))
        assertFalse(a.roster["peerfp123456"]!!.vouched) // snaps to neutral, never above
    }

    /** A sent bubble as sendMessage records it: mine, SENT, tagged with its gid. */
    private fun sent(text: String, gid: String) =
        ChatMsg(MsgKind.MESSAGE, null, null, mine = true, text = text, marking = null, ts = 0, gossipId = gid, delivery = Delivery.SENT)

    @Test fun delivered_flips_the_matching_bubble_to_delivered_in_place() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        a.history.add(sent("one", "aa11"))
        a.history.add(sent("two", "bb22"))
        // The ack correlates by gossip_id — only the matching bubble upgrades.
        val r = applyEvent(s, "a", a, FfiEvent.Delivered("bb22"))
        assertEquals(null, r)                       // in-place mutation, no new line
        assertEquals(2, a.history.size)             // nothing appended
        assertEquals(Delivery.SENT, a.history[0].delivery)
        assertEquals(Delivery.DELIVERED, a.history[1].delivery)
    }

    @Test fun delivered_for_unknown_gid_changes_nothing() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        a.history.add(sent("one", "aa11"))
        applyEvent(s, "a", a, FfiEvent.Delivered("ffff"))
        assertEquals(Delivery.SENT, a.history[0].delivery) // no bubble matched
    }

    @Test fun outbox_dropped_fails_the_n_most_recent_unacked_bubbles() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        a.history.add(sent("one", "aa11"))
        a.history.add(sent("two", "bb22").also { it.delivery = Delivery.DELIVERED }) // settled — spared
        a.history.add(sent("three", "cc33"))
        a.history.add(sent("four", "dd44"))
        // Two drops fail the two most-recent STILL-unacked (SENT) bubbles, newest
        // first; the already-DELIVERED one is never retroactively failed.
        val r = applyEvent(s, "a", a, FfiEvent.OutboxDropped(2u))
        assertEquals(null, r)
        assertEquals(Delivery.FAILED, a.history[3].delivery)   // four
        assertEquals(Delivery.FAILED, a.history[2].delivery)   // three
        assertEquals(Delivery.DELIVERED, a.history[1].delivery) // two — untouched
        assertEquals(Delivery.SENT, a.history[0].delivery)      // one — beyond the count
    }

    @Test fun identity_line_variants() {
        assertEquals("✓ friend bob", identityLine(true, true, "bob"))
        assertEquals("• contact bob", identityLine(true, false, "bob"))
        assertEquals("• account bob (not a contact)", identityLine(false, false, "bob"))
    }
}
