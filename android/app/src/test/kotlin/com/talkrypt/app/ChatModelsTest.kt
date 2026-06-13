package com.talkrypt.app

import org.junit.Assert.assertEquals
import org.junit.Test

class ChatModelsTest {
    @Test fun meta_roundtrip() {
        val m = ChatMeta(
            id = "abc", title = "#general", role = Role.HOST, group = true,
            posture = "pq-pure", access = "open", inviteUri = "talkrypt://x",
            onion = null, persistence = Persistence.PERSISTENT_LOCAL,
            safety = "1A2B3C4D", createdAt = 100, lastActivityAt = 200,
        )
        assertEquals(m, ChatMeta.decode(m.encode()))
    }

    @Test fun meta_with_spaces_and_special_chars() {
        val m = ChatMeta(
            id = "id", title = "Team \\ ops \"room\"", role = Role.JOIN, group = false,
            posture = "hybrid", access = "contacts", inviteUri = null, onion = "abc.onion",
            persistence = Persistence.EPHEMERAL, safety = "ZZ", createdAt = 0, lastActivityAt = 0,
        )
        assertEquals(m, ChatMeta.decode(m.encode()))
    }

    @Test fun msg_roundtrip_with_separators_and_newlines() {
        val msg = ChatMsg(
            kind = MsgKind.MESSAGE, sender = "fp123", display = "alice",
            mine = false, text = "line1\nline2   end", marking = "SECRET", ts = 42,
        )
        assertEquals(msg, ChatMsg.decode(msg.encode()))
    }

    @Test fun history_roundtrip() {
        val a = ChatMsg(MsgKind.MESSAGE, "fp", "a", false, "hi", null, 1)
        val b = ChatMsg(MsgKind.SYSTEM, null, null, false, "joined", null, 2)
        val blob = ChatMsg.encodeList(listOf(a, b))
        assertEquals(listOf(a, b), ChatMsg.decodeList(blob))
    }

    @Test fun empty_history_roundtrip() {
        assertEquals(emptyList<ChatMsg>(), ChatMsg.decodeList(ChatMsg.encodeList(emptyList())))
    }
}
