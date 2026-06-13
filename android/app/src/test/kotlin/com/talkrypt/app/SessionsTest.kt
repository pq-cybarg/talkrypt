package com.talkrypt.app

import org.junit.Assert.assertEquals
import org.junit.Test

class SessionsTest {
    private fun meta(id: String, ts: Long) = ChatMeta(
        id, "#$id", Role.HOST, false, "pq-pure", "open", null, null,
        Persistence.PERSISTENT_LOCAL, "SAFE", ts, ts,
    )

    @Test fun ordered_by_recency_desc() {
        val s = Sessions()
        s.open(meta("a", 100), null)
        s.open(meta("b", 200), null)
        s.touch("a", 300)                      // a is now most recent
        assertEquals(listOf("a", "b"), s.ordered().map { it.meta.id })
    }

    @Test fun unread_accrues_only_when_inactive() {
        val s = Sessions()
        s.open(meta("a", 1), null)
        s.open(meta("b", 1), null)
        s.setActive("a")
        s.recordIncoming("a", ChatMsg(MsgKind.MESSAGE, "x", null, false, "hi", null, 2))
        s.recordIncoming("b", ChatMsg(MsgKind.MESSAGE, "y", null, false, "yo", null, 3))
        assertEquals(0, s.get("a")!!.unread)   // active chat: no badge
        assertEquals(1, s.get("b")!!.unread)   // background chat: badged
        s.setActive("b")                        // opening b clears its unread
        assertEquals(0, s.get("b")!!.unread)
    }

    @Test fun open_is_idempotent_by_id() {
        val s = Sessions()
        s.open(meta("a", 1), null)
        s.open(meta("a", 5), null)             // same id → update, not duplicate
        assertEquals(1, s.all().size)
        assertEquals(5, s.get("a")!!.meta.lastActivityAt)
    }

    @Test fun remove_forgets_chat() {
        val s = Sessions()
        s.open(meta("a", 1), null)
        s.remove("a")
        assertEquals(null, s.get("a"))
        assertEquals(0, s.all().size)
    }

    private fun metaOf(role: Role, onion: String?, invite: String?) = ChatMeta(
        "id", "#c", role, false, "pq-pure", "open", invite, onion,
        Persistence.PERSISTENT_LOCAL, "SAFE", 0, 0,
    )

    @Test fun reconnect_plan_selects_transport_and_role() {
        assertEquals(ReconnectPlan.HOST_TOR, reconnectPlan(metaOf(Role.HOST, "abc.onion", "talkrypt://x")))
        assertEquals(ReconnectPlan.HOST_LAN, reconnectPlan(metaOf(Role.HOST, null, "talkrypt://x")))
        assertEquals(ReconnectPlan.JOIN_TOR, reconnectPlan(metaOf(Role.JOIN, "abc.onion", "talkrypt://x")))
        assertEquals(ReconnectPlan.JOIN_LAN, reconnectPlan(metaOf(Role.JOIN, null, "talkrypt://x")))
        // A join with no saved invite cannot reconnect.
        assertEquals(ReconnectPlan.IMPOSSIBLE, reconnectPlan(metaOf(Role.JOIN, null, null)))
    }

    @Test fun any_always_on_predicate() {
        val s = Sessions()
        s.open(meta("a", 1), null)   // PERSISTENT_LOCAL
        assertEquals(false, anyAlwaysOn(s))
        val m = meta("b", 1).copy(persistence = Persistence.ALWAYS_ON)
        s.open(m, null)
        assertEquals(true, anyAlwaysOn(s))
    }
}
