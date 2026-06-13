# Multi-session Chats — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Android client into a Telegram-style multi-chat client — many chats live at once, a chat list as home, Back returns to the list while chats keep running, and every kept chat's multi-party history is sealed at rest.

**Architecture:** Replace the single `MainActivity.client` with a `Sessions` manager holding many `LiveChat`s (client + history + roster + unread). One poll loop drains all live clients and routes events to the right room. New screens: `chatListScreen` (home), `newChatScreen` (host/join + persistence tier), `chatScreen(chatId)`. History sealed via the FFI seal API behind an Android-Keystore `HardwareKeyWrapper`. App-only change; the Rust core is unchanged.

**Tech Stack:** Kotlin (classic Android Views, no Compose), uniffi FFI (`talkrypt_ffi`), Android Keystore/StrongBox, Gradle. Dependency-free string encoding (no JSON lib) so models unit-test on the JVM.

**Spec:** `docs/superpowers/specs/2026-06-12-multisession-chats-design.md`

---

## File structure

| File | Responsibility |
| --- | --- |
| `crates/ffi/src/lib.rs` (modify: tests mod) | Rust test proving two `TalkryptClient`s run concurrently. |
| `android/app/build.gradle` (modify) | Add JUnit + a JVM unit-test source set. |
| `android/app/src/test/kotlin/com/talkrypt/app/ChatModelsTest.kt` (create) | JVM tests: model encode/decode round-trip. |
| `android/app/src/test/kotlin/com/talkrypt/app/SessionsTest.kt` (create) | JVM tests: recency ordering + unread accounting. |
| `android/app/src/main/kotlin/com/talkrypt/app/ChatModels.kt` (create) | `ChatMeta`, `ChatMsg`, `Member`, `Persistence`, `Role` + dependency-free codec. |
| `android/app/src/main/kotlin/com/talkrypt/app/Sessions.kt` (create) | `Sessions` manager + `LiveChat` (in-memory state, recency, unread). |
| `android/app/src/main/kotlin/com/talkrypt/app/ChatStore.kt` (create) | Seal/unseal per-chat blob + index over the FFI seal API + Keystore wrapper. |
| `android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt` (modify) | chat list / new chat / chat(id) screens, `pollAll()`, `nav()`/back, session wiring. |

Conventions to follow (already in `MainActivity.kt`): palette fields (`bg`,`panel`,`field`,`fg`,`muted`,`accent`), view helpers (`column`,`text`,`label`,`pillButton`,`inputField`,`darkSpinner`,`lp`,`dp`,`roundRect`,`circle`,`applyInsets`), `getSharedPreferences("talkrypt", MODE_PRIVATE)`, `account()`, `toast()`.

---

## Task 1: FFI concurrency test (two live clients)

**Files:**
- Modify: `crates/ffi/src/lib.rs` (the `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the test** — append inside `mod tests` (after the existing `ffi_host_join_send_receive`):

```rust
    /// Multi-session foundation: two independent chats run at once and don't
    /// cross-talk — the assumption the Android session manager relies on.
    #[test]
    fn two_concurrent_chats_are_independent() {
        let a = TalkryptClient::host("127.0.0.1:19931".into(), "#a".into(), "pq-pure".into()).expect("host a");
        let b = TalkryptClient::host("127.0.0.1:19932".into(), "#b".into(), "pq-pure".into()).expect("host b");
        let ja = TalkryptClient::join(a.invite_uri()).expect("join a");
        let jb = TalkryptClient::join(b.invite_uri()).expect("join b");
        ja.send("alpha".into()).expect("send a");
        jb.send("beta".into()).expect("send b");

        let collect = |c: &TalkryptClient| {
            let mut got = Vec::new();
            for _ in 0..50 {
                while let Some(ev) = c.poll_event() {
                    if let FfiEvent::Message { text, .. } = ev { got.push(text); }
                }
                if !got.is_empty() { break; }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            got
        };
        let on_a = collect(&a);
        let on_b = collect(&b);
        assert!(on_a.contains(&"alpha".to_string()), "chat A got: {on_a:?}");
        assert!(on_b.contains(&"beta".to_string()), "chat B got: {on_b:?}");
        // No cross-talk between the two rooms.
        assert!(!on_a.contains(&"beta".to_string()));
        assert!(!on_b.contains(&"alpha".to_string()));
    }
```

- [ ] **Step 2: Run it**

Run: `cargo test -p talkrypt-ffi two_concurrent_chats_are_independent -- --nocapture`
Expected: PASS (the core supports independent clients). If it fails, that is a real finding — stop and investigate before any Android work.

- [ ] **Step 3: Commit**

```bash
git add crates/ffi/src/lib.rs
git commit -m 'test(ffi): two concurrent TalkryptClients are independent (multi-session foundation)'
```

---

## Task 2: JVM unit-test source set

**Files:**
- Modify: `android/app/build.gradle`
- Create: `android/app/src/test/kotlin/com/talkrypt/app/SmokeTest.kt`

- [ ] **Step 1: Add JUnit + test source dir** — in `android/app/build.gradle`, add to the `android.sourceSets` block a `test` entry, and a `testImplementation` dep:

In `sourceSets { main { ... } }` add a sibling:
```gradle
        test { java.srcDirs += 'src/test/kotlin' }
```
In `dependencies { ... }` add:
```gradle
    testImplementation 'junit:junit:4.13.2'
```

- [ ] **Step 2: Write a smoke test** — `android/app/src/test/kotlin/com/talkrypt/app/SmokeTest.kt`:

```kotlin
package com.talkrypt.app

import org.junit.Assert.assertEquals
import org.junit.Test

class SmokeTest {
    @Test fun jvm_tests_run() = assertEquals(4, 2 + 2)
}
```

- [ ] **Step 3: Run it**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'com.talkrypt.app.SmokeTest'`
Expected: BUILD SUCCESSFUL, 1 test passed.

- [ ] **Step 4: Commit**

```bash
git add android/app/build.gradle android/app/src/test
git commit -m 'build(android): add JVM unit-test source set (JUnit)'
```

---

## Task 3: ChatModels (data + dependency-free codec)

**Files:**
- Create: `android/app/src/main/kotlin/com/talkrypt/app/ChatModels.kt`
- Test: `android/app/src/test/kotlin/com/talkrypt/app/ChatModelsTest.kt`

Encoding is line-oriented with unit/record separators (no JSON lib, so it runs on the plain JVM). `US` = `` (field sep), `RS` = `` (record sep). Text is escaped so separators/newlines survive.

- [ ] **Step 1: Write the failing test** — `ChatModelsTest.kt`:

```kotlin
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

    @Test fun msg_roundtrip_with_separators_and_newlines() {
        val msg = ChatMsg(
            kind = MsgKind.MESSAGE, sender = "fp123", display = "alice",
            mine = false, text = "line1\nline2   end", marking = "SECRET", ts = 42,
        )
        assertEquals(msg, ChatMsg.decode(msg.encode()))
    }

    @Test fun history_roundtrip() {
        val a = ChatMsg(MsgKind.MESSAGE, "fp", "a", false, "hi", null, 1)
        val b = ChatMsg(MsgKind.SYSTEM, null, null, false, "joined", null, 2)
        val blob = ChatMsg.encodeList(listOf(a, b))
        assertEquals(listOf(a, b), ChatMsg.decodeList(blob))
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'com.talkrypt.app.ChatModelsTest'`
Expected: FAIL to compile (`ChatMeta`/`ChatMsg` unresolved).

- [ ] **Step 3: Implement** — `ChatModels.kt`:

```kotlin
package com.talkrypt.app

/** Persistence tier for a chat (Phase 1 implements EPHEMERAL + PERSISTENT_LOCAL;
 *  ALWAYS_ON is wired in Phase 2's foreground service). */
enum class Persistence { EPHEMERAL, PERSISTENT_LOCAL, ALWAYS_ON }

enum class Role { HOST, JOIN }

enum class MsgKind { MESSAGE, SYSTEM, ACTION }

private const val US = ""   // field separator
private const val RS = ""   // record separator

private fun esc(s: String) = s
    .replace("\\", "\\\\").replace("\n", "\\n").replace(US, "\\u").replace(RS, "\\r")
private fun unesc(s: String): String {
    val out = StringBuilder(); var i = 0
    while (i < s.length) {
        val c = s[i]
        if (c == '\\' && i + 1 < s.length) {
            when (s[i + 1]) { '\\' -> out.append('\\'); 'n' -> out.append('\n'); 'u' -> out.append(''); 'r' -> out.append(''); else -> out.append(s[i + 1]) }
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
) {
    fun encode(): String = listOf(
        id, title, role.name, group.toString(), posture, access,
        inviteUri ?: "", onion ?: "", persistence.name, safety,
        createdAt.toString(), lastActivityAt.toString(),
    ).joinToString(US) { esc(it) }

    companion object {
        fun decode(s: String): ChatMeta {
            val f = s.split(US).map { unesc(it) }
            return ChatMeta(
                id = f[0], title = f[1], role = Role.valueOf(f[2]), group = f[3].toBoolean(),
                posture = f[4], access = f[5], inviteUri = f[6].ifEmpty { null },
                onion = f[7].ifEmpty { null }, persistence = Persistence.valueOf(f[8]),
                safety = f[9], createdAt = f[10].toLong(), lastActivityAt = f[11].toLong(),
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'com.talkrypt.app.ChatModelsTest'`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/ChatModels.kt android/app/src/test/kotlin/com/talkrypt/app/ChatModelsTest.kt
git commit -m 'feat(android): chat models + dependency-free codec (multi-party history)'
```

---

## Task 4: Sessions manager

**Files:**
- Create: `android/app/src/main/kotlin/com/talkrypt/app/Sessions.kt`
- Test: `android/app/src/test/kotlin/com/talkrypt/app/SessionsTest.kt`

`LiveChat` holds the `TalkryptClient?`; tests use `client = null` (pure-JVM, no native lib). The manager logic (recency ordering, unread, active tracking) is framework-free.

- [ ] **Step 1: Write the failing test** — `SessionsTest.kt`:

```kotlin
package com.talkrypt.app

import org.junit.Assert.*
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
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'com.talkrypt.app.SessionsTest'`
Expected: FAIL to compile (`Sessions` unresolved).

- [ ] **Step 3: Implement** — `Sessions.kt`:

```kotlin
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
 *  unit-tests on the JVM. UI observes via [ordered]/[get]/[active]. */
class Sessions {
    private val chats = LinkedHashMap<String, LiveChat>()
    var active: String? = null
        private set

    fun open(meta: ChatMeta, client: TalkryptClient?): LiveChat {
        val existing = chats[meta.id]
        if (existing != null) { existing.meta = meta; if (client != null) existing.client = client; return existing }
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

    /** Disconnect a chat but keep its record/history. */
    fun disconnect(id: String) { chats[id]?.let { it.client?.let { /* drop ref */ }; it.client = null } }

    /** Forget a chat entirely. */
    fun remove(id: String) { chats.remove(id) }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd android && ./gradlew :app:testDebugUnitTest --tests 'com.talkrypt.app.SessionsTest'`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/Sessions.kt android/app/src/test/kotlin/com/talkrypt/app/SessionsTest.kt
git commit -m 'feat(android): Sessions manager (multi-chat live state, recency, unread)'
```

---

## Task 5: ChatStore (sealed history at rest)

**Files:**
- Create: `android/app/src/main/kotlin/com/talkrypt/app/ChatStore.kt`

Seals each kept chat to `filesDir/chats/<id>.tkc` and maintains `filesDir/chats/index`. Uses the FFI `sealSecret`/`unsealSecret` with an Android-Keystore-backed `HardwareKeyWrapper` (StrongBox when present). No new unit test here (it needs the native lib + Keystore); covered by the on-device checklist in Task 11. The encode/decode it relies on is already JVM-tested (Task 3).

- [ ] **Step 1: Implement** — `ChatStore.kt`:

```kotlin
package com.talkrypt.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import uniffi.talkrypt_ffi.HardwareKeyWrapper
import uniffi.talkrypt_ffi.sealSecret
import uniffi.talkrypt_ffi.unsealSecret

/** Wraps the seal KEK with a non-exportable Android Keystore AES key (StrongBox
 *  when available), so chat history is hardware-gated at rest. Mirrors the
 *  HardwareKeyWrapper contract from docs/hardware-backed-sealing.md. */
class KeystoreWrapper(strongBox: Boolean) : HardwareKeyWrapper {
    private val alias = "talkrypt.history.kek"
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val wantStrongBox = strongBox
    private fun key(): SecretKey {
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .apply { if (wantStrongBox) setIsStrongBoxBacked(true) }
            .build()
        kg.init(spec); return kg.generateKey()
    }
    override fun wrap(kek: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return c.iv + c.doFinal(kek)
    }
    override fun unwrap(wrapped: ByteArray): ByteArray {
        val iv = wrapped.copyOfRange(0, 12); val ct = wrapped.copyOfRange(12, wrapped.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
        return c.doFinal(ct)
    }
}

/** Sealed at-rest store for chat metadata + history. */
class ChatStore(ctx: Context) {
    private val dir = File(ctx.filesDir, "chats").apply { mkdirs() }
    private val index = File(dir, "index")
    // Try StrongBox; if key-gen fails (no SE), fall back to TEE-backed.
    private val wrapper: HardwareKeyWrapper =
        runCatching { KeystoreWrapper(true).also { it.wrap(ByteArray(32)) } }.getOrNull()
            ?: KeystoreWrapper(false)

    private fun blobFile(id: String) = File(dir, "$id.tkc")

    /** Persist one kept chat (meta + history). Ephemeral chats must not call this. */
    fun save(meta: ChatMeta, history: List<ChatMsg>) {
        val plain = (meta.encode() + " " + ChatMsg.encodeList(history)).toByteArray(Charsets.UTF_8)
        val sealed = sealSecret(plain, null, wrapper)
        blobFile(meta.id).writeBytes(sealed)
        writeIndex((readIndex() + meta.id).distinct())
    }

    /** Load one chat's (meta, history), or null if missing/corrupt. */
    fun load(id: String): Pair<ChatMeta, List<ChatMsg>>? = runCatching {
        val plain = unsealSecret(blobFile(id).readBytes(), null, wrapper).toString(Charsets.UTF_8)
        val cut = plain.indexOf(' ')
        ChatMeta.decode(plain.substring(0, cut)) to ChatMsg.decodeList(plain.substring(cut + 1))
    }.getOrNull()

    /** All kept chat ids (skips entries that fail to load). */
    fun ids(): List<String> = readIndex().filter { blobFile(it).exists() }

    fun delete(id: String) {
        blobFile(id).delete()
        writeIndex(readIndex() - id)
    }

    private fun readIndex(): List<String> =
        if (index.exists()) index.readText().split("\n").filter { it.isNotBlank() } else emptyList()
    private fun writeIndex(ids: List<String>) = index.writeText(ids.joinToString("\n"))
}
```

- [ ] **Step 2: Compile-check** (no unit test; build the debug sources)

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL (resolves `sealSecret`/`unsealSecret`/`HardwareKeyWrapper` from the generated bindings — these exist after a normal `android/build-apk.sh` run that regenerates Kotlin bindings; if unresolved, run `bash android/build-apk.sh` once to refresh `app/src/main/kotlin/uniffi/`).

- [ ] **Step 3: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/ChatStore.kt
git commit -m 'feat(android): ChatStore — chat history sealed at rest via FFI seal + Keystore'
```

---

## Task 6: Wire the session manager + poll-all into MainActivity

**Files:**
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt`

Replace the single-client state with `Sessions` + `ChatStore`, and make polling drain every live chat.

- [ ] **Step 1: Replace the client field + add managers** — change the fields near line 53:

Replace:
```kotlin
    private var client: TalkryptClient? = null
    private var messages: LinearLayout? = null
    private var scroll: ScrollView? = null
```
with:
```kotlin
    private val sessions = Sessions()
    private val store by lazy { ChatStore(this) }
    private var messages: LinearLayout? = null
    private var scroll: ScrollView? = null
    /** Currently rendered chat id, or null on the list/other screens. */
    private val activeId: String? get() = sessions.active
    /** Convenience: the client of the on-screen chat (for send). */
    private val activeClient: TalkryptClient? get() = sessions.active?.let { sessions.get(it)?.client }
```

- [ ] **Step 2: Replace `poll()` with `pollAll()`** — replace the whole `poll()` function (lines ~1170–1213) with one loop over all live chats that routes events through `sessions` and renders only the active chat:

```kotlin
    /** One loop drains every connected chat; events route to their room. The
     *  active chat renders live, others accrue unread. Started once in onCreate. */
    private fun pollAll() {
        ui.postDelayed(object : Runnable {
            override fun run() {
                for (lc in sessions.live()) {
                    val c = lc.client ?: continue
                    val id = lc.meta.id
                    while (true) {
                        val e = runCatching { c.pollEvent() }.getOrNull() ?: break
                        handleEvent(id, lc, e)
                    }
                }
                ui.postDelayed(this, 250)
            }
        }, 250)
    }

    private fun handleEvent(id: String, lc: LiveChat, e: FfiEvent) {
        val now = System.currentTimeMillis()
        when (e) {
            is FfiEvent.Message -> {
                val m = ChatMsg(MsgKind.MESSAGE, e.from, e.from.take(8), false, e.text, e.marking.ifEmpty { null }, now)
                sessions.recordIncoming(id, m)
                if (activeId == id) addBubble(e.text, mine = false, sender = e.from.take(8), marking = e.marking.ifEmpty { null })
                else refreshListRowIfVisible()
                scheduleSave(id)
            }
            is FfiEvent.Connected -> { lc.roster.getOrPut(e.fingerprint) { Member(e.fingerprint) }.connected = true; sysLine(id, "● ${e.fingerprint.take(8)} connected") }
            is FfiEvent.Disconnected -> { lc.roster[e.fingerprint]?.connected = false; sysLine(id, "○ ${e.fingerprint.take(8)} left") }
            is FfiEvent.Identity -> {
                val mem = lc.roster.getOrPut(e.accountFingerprint) { Member(e.accountFingerprint) }
                mem.display = e.username.ifEmpty { e.accountFingerprint.take(8) }; mem.contact = e.contact; mem.friend = e.friend
                val who = mem.display!!
                sysLine(id, when { e.friend -> "✓ friend $who"; e.contact -> "• contact $who"; else -> "• account $who (not a contact)" })
                if (!e.contact && activeId == id) {
                    val fp = e.accountFingerprint; val name = e.username
                    addAction("Add “$who” as a contact") {
                        val cl = lc.client
                        if (cl != null && cl.addSeenContact(fp, name.ifEmpty { null }, false)) { saveContacts(cl); system("added contact $who") }
                        else toast("could not add (account not seen)")
                    }
                }
            }
            is FfiEvent.Error -> sysLine(id, "! ${e.message}")
        }
    }

    /** Append a system line to a chat; render if it's on screen. */
    private fun sysLine(id: String, s: String) {
        sessions.recordIncoming(id, ChatMsg(MsgKind.SYSTEM, null, null, false, s, null, System.currentTimeMillis()))
        if (activeId == id) system(s)
        scheduleSave(id)
    }

    /** Persist a kept chat shortly after activity (debounced); ephemeral chats skip disk. */
    private val pendingSaves = HashSet<String>()
    private fun scheduleSave(id: String) {
        val lc = sessions.get(id) ?: return
        if (lc.meta.persistence == Persistence.EPHEMERAL) return
        if (!pendingSaves.add(id)) return
        ui.postDelayed({
            pendingSaves.remove(id)
            sessions.get(id)?.let { runCatching { store.save(it.meta, it.history) } }
        }, 1500)
    }

    /** Refresh the visible chat-list rows (no-op if a chat is on screen). */
    private fun refreshListRowIfVisible() { if (activeId == null) ui.post { setContentView(chatListScreen()) } }
```

- [ ] **Step 3: Start polling once in `onCreate`** — after `setContentView(setupScreen())` becomes `setContentView(chatListScreen())` (Task 7), add `pollAll()`. (Done in Task 7's onCreate edit.)

- [ ] **Step 4: Compile-check**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: errors only about `chatListScreen`/`setupScreen` not yet renamed — resolved by Tasks 7–9. (If you implement Tasks 6–9 before compiling, compile once at the end of Task 9.)

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt
git commit -m 'feat(android): session-managed poll-all routing events to rooms'
```

---

## Task 7: Chat-list home + back navigation

**Files:**
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt`

- [ ] **Step 1: Load saved chats + start polling in `onCreate`** — replace `setContentView(setupScreen())` (line ~80) with:

```kotlin
        loadSavedChats()
        setContentView(chatListScreen())
        pollAll()
```

And add the loader (place near the other helpers):
```kotlin
    /** Hydrate the session list from sealed storage (history only; not connected). */
    private fun loadSavedChats() {
        for (id in store.ids()) {
            val (meta, hist) = store.load(id) ?: continue
            val lc = sessions.open(meta, null)
            lc.history.clear(); lc.history.addAll(hist)
        }
    }
```

- [ ] **Step 2: Add `chatListScreen()`** — new function:

```kotlin
    private fun chatListScreen(): View {
        sessions.setActive(null)
        backState = Back.HOME
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }

        val headRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        headRow.addView(text("talkrypt", 26f, fg, bold = true), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        headRow.addView(text("⋯", 24f, muted).apply { setPadding(dp(12), dp(4), dp(8), dp(4)); setOnClickListener { setContentView(utilitiesScreen()) } })
        col.addView(headRow, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))

        col.addView(pillButton("＋  New chat", accent, Color.WHITE) { setContentView(newChatScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(16), bottom = dp(8)))

        val chats = sessions.ordered()
        if (chats.isEmpty()) {
            col.addView(text("No chats yet — tap ＋ to host or join.", 14f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(40)))
        } else {
            for (lc in chats) col.addView(chatRow(lc), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
        }
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    /** One Telegram-style row: glyph · title · last-sender preview · time · unread/live. */
    private fun chatRow(lc: LiveChat): View {
        val m = lc.meta
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            background = roundRect(panel, 14); setPadding(dp(14), dp(12), dp(14), dp(12))
            setOnClickListener { openChat(m.id) }
            setOnLongClickListener { chatRowMenu(lc); true }
        }
        val glyph = text(if (m.group) "#" else "✺", 20f, Color.WHITE, center = true).apply {
            background = circle(if (m.group) accent else peerBubble); gravity = Gravity.CENTER
        }
        row.addView(glyph, LinearLayout.LayoutParams(dp(44), dp(44)).apply { rightMargin = dp(12) })

        val mid = column(Color.TRANSPARENT)
        mid.addView(text(m.title, 16f, fg, bold = true))
        val last = lc.history.lastOrNull { it.kind == MsgKind.MESSAGE }
        val preview = when {
            last != null && last.mine -> "you: ${last.text}"
            last != null -> "${last.display ?: last.sender?.take(8) ?: "?"}: ${last.text}"
            else -> if (m.role == Role.HOST) "hosting" else "joined"
        }
        val members = lc.roster.size
        val sub = if (m.group && members > 0) "$preview · $members members" else preview
        mid.addView(text(sub, 13f, muted).apply { maxLines = 1; ellipsize = android.text.TextUtils.TruncateAt.END })
        row.addView(mid, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))

        val right = column(Color.TRANSPARENT).apply { gravity = Gravity.END }
        right.addView(text(relTime(m.lastActivityAt), 11f, muted))
        if (lc.unread > 0) right.addView(text(lc.unread.toString(), 11f, Color.WHITE, center = true).apply { background = circle(accent); setPadding(dp(7), dp(2), dp(7), dp(2)) }.also { it.gravity = Gravity.CENTER }, lp(WRAP_CONTENT, WRAP_CONTENT, top = dp(4)))
        else if (lc.client != null) right.addView(text("●", 12f, accent), lp(WRAP_CONTENT, WRAP_CONTENT, top = dp(4)))
        row.addView(right, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        return row
    }

    private fun relTime(ts: Long): String {
        val d = System.currentTimeMillis() - ts
        return when {
            d < 60_000 -> "now"
            d < 3_600_000 -> "${d / 60_000}m"
            d < 86_400_000 -> "${d / 3_600_000}h"
            else -> "${d / 86_400_000}d"
        }
    }

    private fun chatRowMenu(lc: LiveChat) {
        val id = lc.meta.id
        android.app.AlertDialog.Builder(this)
            .setTitle(lc.meta.title)
            .setItems(arrayOf("Re-share invite", "Leave (disconnect, keep history)", "Delete (erase)")) { _, which ->
                when (which) {
                    0 -> lc.meta.inviteUri?.let { shareText(it) } ?: toast("no invite")
                    1 -> { sessions.disconnect(id); setContentView(chatListScreen()) }
                    2 -> { sessions.disconnect(id); sessions.remove(id); runCatching { store.delete(id) }; setContentView(chatListScreen()) }
                }
            }.show()
    }
```

- [ ] **Step 2b: Add back-state + `openChat` + utilities screen + `shareText`**:

```kotlin
    private enum class Back { HOME, LIST_CHILD }
    private var backState = Back.HOME

    private fun openChat(id: String) {
        sessions.setActive(id)
        setContentView(chatScreen(id))
    }

    private fun shareText(s: String) {
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, s) }, "Share invite"))
    }

    /** The old utility buttons, moved off the chat-first home. */
    private fun utilitiesScreen(): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("More", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })
        col.addView(pillButton("Find nearby host (BLE / Wi-Fi Direct)", panel, fg) { findNearby() }, lp(MATCH_PARENT, dp(50), top = dp(8)))
        col.addView(pillButton("Share app (P2P over Wi-Fi)", panel, fg) { shareApp() }, lp(MATCH_PARENT, dp(50), top = dp(10)))
        col.addView(pillButton("Anchors (username directory)", panel, fg) { setContentView(anchorsScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(10)))
        col.addView(pillButton("Contacts", panel, fg) { setContentView(contactsScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(10)))
        col.addView(pillButton("Linked devices", panel, fg) { setContentView(linkedDevicesScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(10)))
        col.addView(pillButton("Segments (contextual identities)", panel, fg) { setContentView(segmentsScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(10)))
        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv); return sv
    }
```

- [ ] **Step 3: Override `onBackPressed`** — add to the class:

```kotlin
    @Suppress("DEPRECATION", "MissingSuperCall")
    override fun onBackPressed() {
        when {
            activeId != null -> { setContentView(chatListScreen()) }   // chat → list (stays live)
            backState == Back.LIST_CHILD -> setContentView(chatListScreen())  // subscreen → list
            else -> super.onBackPressed()                              // list → exit
        }
    }
```

Ensure every non-list screen builder sets `backState = Back.LIST_CHILD` at its top (`contactsScreen`, `linkedDevicesScreen`, `segmentsScreen`, `anchorsScreen`, `findNearbyScreen`, `shareScreen`, `restrictedHostScreen`, `joinPreflightScreen`, `acceptLinkConfirmScreen`, `linkOfferRunningScreen`, `anchorRunningScreen`, `newChatScreen`). Add `backState = Back.LIST_CHILD` as their first statement.

- [ ] **Step 4: Add the missing imports** at the top of the file: `import android.content.Intent` (if absent) and `import android.app.AlertDialog` is referenced fully-qualified above (no import needed).

- [ ] **Step 5: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt
git commit -m 'feat(android): Telegram-style chat list home + back navigation + utilities overflow'
```

---

## Task 8: New-chat screen (rename setup + persistence tier) + session-creating host/join

**Files:**
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt`

- [ ] **Step 1: Rename `setupScreen()` → `newChatScreen()`** and add a persistence selector. Change the signature `private fun setupScreen(): View` to `private fun newChatScreen(): View`; set `backState = Back.LIST_CHILD` as the first line; remove the moved utility buttons (Anchors/Contacts/Linked/Segments/Find nearby/Share app — they now live in `utilitiesScreen()`), and add after the ACCESS spinner:

```kotlin
        col.addView(label("PERSISTENCE").also { it.setPadding(0, dp(20), 0, dp(8)) })
        val persistence = darkSpinner(listOf("Ephemeral (memory only)", "Persistent (saved, reconnectable)", "Always-on (Phase 2)"))
        col.addView(persistence, lp(MATCH_PARENT, WRAP_CONTENT))
```

Map the selection: index 0 → `Persistence.EPHEMERAL`, 1 → `PERSISTENT_LOCAL`, 2 → treat as `PERSISTENT_LOCAL` for now + `toast("Always-on lands in Phase 2; saved instead")`.

Pass the chosen tier into `startHost`/`startJoin`.

- [ ] **Step 2: Update the Host button handler** to pass tier:

```kotlin
        col.addView(pillButton("Host a chat", accent, Color.WHITE) {
            startHost(channel.text.toString().ifBlank { "#general" }, posture.selectedItem.toString(), access.selectedItem.toString(), tierOf(persistence))
        }, lp(MATCH_PARENT, dp(54), top = dp(32)))
```
and the Join button to remember the tier for the preflight:
```kotlin
        col.addView(pillButton("Join", panel, fg) {
            val uri = invite.text.toString().trim()
            if (uri.startsWith("talkrypt://")) { pendingTier = tierOf(persistence); startJoin(uri) } else toast("Paste a talkrypt:// invite")
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))
```

Add helpers:
```kotlin
    private var pendingTier = Persistence.PERSISTENT_LOCAL
    private fun tierOf(sp: Spinner): Persistence = when (sp.selectedItemPosition) {
        0 -> Persistence.EPHEMERAL
        else -> Persistence.PERSISTENT_LOCAL   // index 2 (Always-on) downgraded in Phase 1
    }
    private fun chatId(seed: String): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(seed.toByteArray()).joinToString("") { "%02x".format(it) }.take(24)
```

- [ ] **Step 3: Rewrite `startHost` to create a session** — replace its `ui.post { ... }` body so it builds a `ChatMeta`, opens a `LiveChat`, persists if kept, and opens the chat:

```kotlin
    private fun startHost(channel: String, posture: String, access: String = "open", tier: Persistence = Persistence.PERSISTENT_LOCAL) {
        toast("creating chat…")
        thread {
            try {
                val c = if (useTor) TalkryptClient.hostTor(channel, posture, torStateDir())
                        else TalkryptClient.host("${ApkShareServer.lanIp() ?: "127.0.0.1"}:9779", channel, posture)
                runCatching { c.presentAccount(account(), null) }
                runCatching { loadContacts(c) }
                runCatching { c.setAccessMode(access) }
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(invite), channel, Role.HOST, group = false, posture = posture,
                        access = access, inviteUri = invite, onion = if (useTor) invite else null,
                        persistence = tier, safety = sn.take(11), createdAt = now, lastActivityAt = now)
                    val lc = sessions.open(meta, c)
                    if (tier != Persistence.EPHEMERAL) runCatching { store.save(meta, lc.history) }
                    openChat(meta.id)
                    sysLine(meta.id, "hosting — share the invite to let a friend join")
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = "invite")
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) { ui.post { toast("host failed: ${e.message}") } }
        }
    }
```

- [ ] **Step 4: Rewrite `doJoin` to create a session**:

```kotlin
    private fun doJoin(uri: String, username: String?, presentAccount: Boolean) {
        toast(if (useTor) "joining over Tor…" else "joining…")
        thread {
            try {
                val c = if (useTor) TalkryptClient.joinTor(uri, torStateDir()) else TalkryptClient.join(uri)
                val sn = c.safetyNumber()
                if (presentAccount) runCatching { c.presentAccount(account(), username) }
                runCatching { loadContacts(c) }
                val title = runCatching { inviteChannel(uri) }.getOrDefault("chat")
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(uri), title, Role.JOIN, group = false, posture = "", access = "open",
                        inviteUri = uri, onion = if (uri.contains(".onion")) uri else null,
                        persistence = pendingTier, safety = sn.take(11), createdAt = now, lastActivityAt = now)
                    val lc = sessions.open(meta, c)
                    if (meta.persistence != Persistence.EPHEMERAL) runCatching { store.save(meta, lc.history) }
                    openChat(meta.id)
                    sysLine(meta.id, if (presentAccount) "joined" + (username?.let { " as $it" } ?: "") else "joined as pseudonym")
                }
            } catch (e: Exception) { ui.post { toast("join failed: ${e.message}") } }
        }
    }
```

- [ ] **Step 5: Update other `chatScreen(...)` call sites** (restricted host ~959, linked ~466, segments ~580) to create a session + `openChat` the same way (build a `ChatMeta`, `sessions.open`, `openChat(id)`), instead of calling `chatScreen(title, subtitle)` directly. Minimal: wrap each in a small local that mirrors `doJoin`'s `ui.post` block with the right title/role.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt
git commit -m 'feat(android): new-chat screen with persistence tier; host/join create sessions'
```

---

## Task 9: Chat screen by id (back button + per-room render + members)

**Files:**
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt`

- [ ] **Step 1: Replace `chatScreen(title, subtitle)` with `chatScreen(chatId)`**:

```kotlin
    private fun chatScreen(chatId: String): View {
        val lc = sessions.get(chatId) ?: return chatListScreen()
        sessions.setActive(chatId)
        val root = column(bg)

        // header: back · title/subtitle · overflow
        val header = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setBackgroundColor(panel); setPadding(dp(8), dp(10), dp(12), dp(10)) }
        header.addView(text("‹", 30f, fg).apply { setPadding(dp(10), 0, dp(10), 0); setOnClickListener { setContentView(chatListScreen()) } })
        val titles = column(Color.TRANSPARENT)
        titles.addView(text(lc.meta.title, 17f, fg, bold = true))
        val tier = when (lc.meta.persistence) { Persistence.EPHEMERAL -> "ephemeral"; Persistence.ALWAYS_ON -> "always-on"; else -> "persistent" }
        val members = if (lc.roster.isNotEmpty()) "${lc.roster.size} members · " else ""
        titles.addView(text("$members safety ${lc.meta.safety} · $tier", 12f, muted).also { it.setPadding(0, dp(2), 0, 0) })
        header.addView(titles, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        header.addView(text("⋯", 22f, muted).apply { setPadding(dp(10), dp(4), dp(8), dp(4)); setOnClickListener { chatRowMenu(lc) } })
        root.addView(header, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        // messages
        val list = column(bg).apply { setPadding(dp(12), dp(12), dp(12), dp(12)) }
        messages = list
        val sv = ScrollView(this).apply { isFillViewport = true; addView(list) }
        scroll = sv
        root.addView(sv, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        // replay this chat's history into the view
        for (m in lc.history) when (m.kind) {
            MsgKind.MESSAGE -> addBubble(m.text, m.mine, sender = if (m.mine) null else m.display, marking = m.marking)
            MsgKind.SYSTEM, MsgKind.ACTION -> system(m.text)
        }

        // input bar
        val bar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setBackgroundColor(panel); setPadding(dp(12), dp(10), dp(12), dp(10)) }
        val input = inputField("Message").apply { background = roundRect(field, 24) }
        bar.addView(input, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        val send = text("➤", 20f, Color.WHITE, center = true).apply { background = circle(accent); gravity = Gravity.CENTER }
        send.setOnClickListener { val t = input.text.toString(); if (t.isNotEmpty()) { input.setText(""); sendMessage(chatId, t) } }
        bar.addView(send, LinearLayout.LayoutParams(dp(48), dp(48)).apply { leftMargin = dp(10) })
        root.addView(bar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        applyInsets(root)
        return root
    }
```

- [ ] **Step 2: Make `sendMessage` chat-scoped**:

```kotlin
    private fun sendMessage(chatId: String, t: String) {
        val lc = sessions.get(chatId) ?: return
        val c = lc.client ?: run { toast("disconnected — reopen to reconnect"); return }
        val msg = ChatMsg(MsgKind.MESSAGE, null, null, mine = true, text = t, marking = null, ts = System.currentTimeMillis())
        lc.history.add(msg); sessions.touch(chatId, msg.ts)
        addBubble(t, mine = true)
        scheduleSave(chatId)
        thread { runCatching { c.send(t) }.onFailure { ui.post { toast("send failed") } } }
    }
```

- [ ] **Step 3: Remove the now-unused `bind()`** and any remaining `client`/`poll()` references (the linked/segment join paths now go through sessions). Search: `grep -n "bind(\|client\b\| poll()" MainActivity.kt` and reconcile.

- [ ] **Step 4: Save kept chats in `onPause`** — add:

```kotlin
    override fun onPause() {
        super.onPause()
        for (lc in sessions.all()) if (lc.meta.persistence != Persistence.EPHEMERAL) runCatching { store.save(lc.meta, lc.history) }
    }
```

- [ ] **Step 5: Full compile**

Run: `cd android && ./gradlew :app:compileDebugKotlin`
Expected: BUILD SUCCESSFUL.

- [ ] **Step 6: Commit**

```bash
git add android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt
git commit -m 'feat(android): chat screen by id — back button, per-room history, member count'
```

---

## Task 10: Build, install to the Seeker, and verify

**Files:** none (verification)

- [ ] **Step 1: Run all unit tests**

Run: `cargo test -p talkrypt-ffi two_concurrent_chats_are_independent` then `cd android && ./gradlew :app:testDebugUnitTest`
Expected: all PASS.

- [ ] **Step 2: Build the APK (Tor on, so persistent/onion paths exist)**

Run: `TALKRYPT_TOR=1 bash android/build-apk.sh`
Expected: `BUILD SUCCESSFUL`, APK at `android/app/build/outputs/apk/debug/app-debug.apk`.

- [ ] **Step 3: Install to the Seeker by serial**

Run: `adb -s SM02G4061972692 install -r android/app/build/outputs/apk/debug/app-debug.apk`
Expected: `Success`.

- [ ] **Step 4: On-device checklist** (drive manually / via a second emulator peer):
  - Launch → empty chat list with **＋ New chat**.
  - Host chat A (Persistent) → opens chat; Back → A shows in the list with a live ●.
  - ＋ → join/host chat B → both A and B in the list, both live.
  - While viewing B, send into A from a peer → A's row shows an **unread badge**; B unaffected.
  - Open A → unread clears, history intact, **‹ back** returns to the list (A still live).
  - Kill + relaunch → kept chats reappear **with history**; an Ephemeral chat is gone.
  - Long-press a row → Delete → it disappears and its sealed blob is removed.

- [ ] **Step 5: Commit any fixes found, then tag the phase done**

```bash
git add -A && git commit -m 'fix(android): Phase 1 multi-session on-device fixes'   # only if fixes were needed
```

---

## Self-review notes
- **Spec coverage:** session manager (T4,6), poll-all routing (T6), chat list + back (T7), new-chat + tier (T8), chat-by-id + members (T9), sealed history (T5,8,9), multi-party roster/attribution (T3,6,9), FFI concurrency (T1), tests (T1–4), on-device (T10). Phase-2/3 explicitly out of scope.
- **Reconnect of a saved-but-disconnected chat** (client==null) is *open the row → re-run host/join from `inviteUri`* — Phase 1 keeps it manual (full auto-reconnect is Phase 2). A disconnected chat renders history read-only; sending toasts "reopen to reconnect."
- **chatId stability:** host ids derive from the invite URI (stable within a session; a re-host mints a new invite → new id, acceptable in Phase 1 since hosts are typically ephemeral). Join ids derive from the invite URI (stable).
