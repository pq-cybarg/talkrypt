package com.talkrypt.app

/** Persistence tier for a chat. Phase 1 implements EPHEMERAL + PERSISTENT_LOCAL;
 *  ALWAYS_ON is wired in Phase 2 (foreground service). */
enum class Persistence { EPHEMERAL, PERSISTENT_LOCAL, ALWAYS_ON }

enum class Role { HOST, JOIN }

enum class MsgKind { MESSAGE, SYSTEM, ACTION }

// Field/record separators for the dependency-free codec (so models unit-test on
// the plain JVM with no JSON lib). Fields never contain a raw separator because
// esc() escapes them; that lets split() on the raw separator stay unambiguous.
private const val US = "" // unit (field) separator
private const val RS = "" // record (message) separator

private fun esc(s: String) = s
    .replace("\\", "\\\\").replace("\n", "\\n").replace(US, "\\u").replace(RS, "\\r")

private fun unesc(s: String): String {
    val out = StringBuilder(); var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '\\' && i + 1 < s.length) {
            when (s[i + 1]) {
                '\\' -> out.append('\\')
                'n' -> out.append('\n')
                'u' -> out.append('')
                'r' -> out.append('')
                else -> out.append(s[i + 1])
            }
            i += 2
        } else { out.append(c); i++ }
    }
    return out.toString()
}

/** The persisted record for one chat (no live state). */
data class ChatMeta(
    val id: String,
    val title: String,
    val role: Role,
    val group: Boolean,
    val posture: String,
    val access: String,
    val inviteUri: String?,
    val onion: String?,
    val persistence: Persistence,
    val safety: String,
    val createdAt: Long,
    val lastActivityAt: Long,
    /** Per-chat Tor state dir (stable across reconnects → same .onion); null if not Tor. */
    val torDir: String? = null,
    /** Hosted/joined over the Nym mixnet (multi-homed); drives the reconnect plan. */
    val mixnet: Boolean = false,
) {
    fun encode(): String = listOf(
        id, title, role.name, group.toString(), posture, access,
        inviteUri ?: "", onion ?: "", persistence.name, safety,
        createdAt.toString(), lastActivityAt.toString(), torDir ?: "", mixnet.toString(),
    ).joinToString(US) { esc(it) }

    companion object {
        fun decode(s: String): ChatMeta {
            val f = s.split(US).map { unesc(it) }
            return ChatMeta(
                id = f[0], title = f[1], role = Role.valueOf(f[2]), group = f[3].toBoolean(),
                posture = f[4], access = f[5], inviteUri = f[6].ifEmpty { null },
                onion = f[7].ifEmpty { null }, persistence = Persistence.valueOf(f[8]),
                safety = f[9], createdAt = f[10].toLong(), lastActivityAt = f[11].toLong(),
                torDir = f.getOrNull(12)?.ifEmpty { null },
                mixnet = f.getOrNull(13)?.toBoolean() ?: false,
            )
        }
    }
}

/** One message/line in a chat's history, attributed to its sender. */
data class ChatMsg(
    val kind: MsgKind,
    val sender: String?,
    val display: String?,
    val mine: Boolean,
    val text: String,
    val marking: String?,
    val ts: Long,
) {
    fun encode(): String = listOf(
        kind.name, sender ?: "", display ?: "", mine.toString(), text, marking ?: "", ts.toString(),
    ).joinToString(US) { esc(it) }

    companion object {
        fun decode(s: String): ChatMsg {
            val f = s.split(US).map { unesc(it) }
            return ChatMsg(
                kind = MsgKind.valueOf(f[0]), sender = f[1].ifEmpty { null },
                display = f[2].ifEmpty { null }, mine = f[3].toBoolean(), text = f[4],
                marking = f[5].ifEmpty { null }, ts = f[6].toLong(),
            )
        }
        fun encodeList(msgs: List<ChatMsg>): String = msgs.joinToString(RS) { it.encode() }
        fun decodeList(s: String): List<ChatMsg> =
            if (s.isEmpty()) emptyList() else s.split(RS).map { decode(it) }
    }
}

/** A roster member (live state only; not persisted directly). */
data class Member(
    val fp: String,
    var display: String? = null,
    var contact: Boolean = false,
    var friend: Boolean = false,
    var connected: Boolean = false,
)
