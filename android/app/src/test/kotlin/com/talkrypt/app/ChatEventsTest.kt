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
        val msg = applyEvent(s, "a", a, FfiEvent.Message("peerfp", "#a", "hello", ""))
        assertEquals(MsgKind.MESSAGE, msg.kind)
        assertEquals("hello", msg.text)
        assertEquals(1, a.history.size)
        assertEquals("hello", a.history[0].text)
        assertEquals(1, s.get("a")!!.unread)   // background chat accrues a badge
    }

    @Test fun message_marking_is_carried() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val msg = applyEvent(s, "a", a, FfiEvent.Message("p", "#a", "x", "SECRET//NOFORN"))
        assertEquals("SECRET//NOFORN", msg.marking)
    }

    @Test fun connected_then_disconnected_updates_roster() {
        val s = Sessions()
        val a = s.open(meta("a"), null)
        val c = applyEvent(s, "a", a, FfiEvent.Connected("abcdef123456"))
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

    @Test fun identity_line_variants() {
        assertEquals("✓ friend bob", identityLine(true, true, "bob"))
        assertEquals("• contact bob", identityLine(true, false, "bob"))
        assertEquals("• account bob (not a contact)", identityLine(false, false, "bob"))
    }
}
