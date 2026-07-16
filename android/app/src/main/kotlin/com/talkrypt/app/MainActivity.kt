package com.talkrypt.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.provider.Settings
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowInsets
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import com.talkrypt.custody.CustodyBridge
import kotlin.concurrent.thread
import uniffi.talkrypt_ffi.Account
import uniffi.talkrypt_ffi.AnchorNode
import uniffi.talkrypt_ffi.DeviceKey
import uniffi.talkrypt_ffi.FfiEvent
import uniffi.talkrypt_ffi.LinkOffer
import uniffi.talkrypt_ffi.SegmentKey
import uniffi.talkrypt_ffi.TalkryptClient
import uniffi.talkrypt_ffi.accountSegmentChain
import uniffi.talkrypt_ffi.anchorRegister
import uniffi.talkrypt_ffi.anchorResolve
import uniffi.talkrypt_ffi.inviteChannel
import uniffi.talkrypt_ffi.inviteIsOnion
import uniffi.talkrypt_ffi.inviteHasNym
import uniffi.talkrypt_ffi.nymImportTicketbook
import uniffi.talkrypt_ffi.torBootstrapPercent
import uniffi.talkrypt_ffi.linkAccept
import uniffi.talkrypt_ffi.linkedSegmentChain

/**
 * The talkrypt chat app — a post-quantum, end-to-end encrypted chat over the
 * shared `TalkryptClient` FFI, with a Signal-style bubble UI. The device's
 * key-custody tier (StrongBox on the Seeker) and ML-DSA-87 identity show in the
 * header. NOT certified / NOT audited — see the README.
 */
class MainActivity : Activity() {
    private val ui = Handler(Looper.getMainLooper())

    /** Shared with the always-on [ChatService] so both see one set of live chats. */
    private val sessions get() = SessionHub.sessions
    private val store by lazy { ChatStore(this) }
    private var messages: LinearLayout? = null   // message list of the on-screen chat (null on other screens)
    private var scroll: ScrollView? = null
    private var chatChip: TextView? = null       // header connection chip of the on-screen chat
    private var chatDetail: TextView? = null     // header members/safety/tier line
    private var renderedCount = 0                // history entries already rendered into [messages]
    private val drafts = HashMap<String, String>()  // per-chat unsent input; survives screen swaps
    private var shareServer: ApkShareServer? = null
    private var useTor = false // route the next host/join over Tor (.onion)
    private var useNym = false // also route over the Nym mixnet (multi-homed invite)
    private var pendingTier = Persistence.PERSISTENT_LOCAL  // tier chosen for the next join
    private val pendingSaves = HashSet<String>()
    private var polling = false   // guards a single foreground drain+render loop

    /** Currently rendered chat id, or null on the list/other screens. */
    private val activeId: String? get() = sessions.active

    private enum class Back { HOME, LIST_CHILD }
    private var backState = Back.HOME

    // Per-chat Arti state dirs live under filesDir/tor/<sub>. A chat stores its
    // <sub> in ChatMeta.torDir so reconnecting reuses the same onion identity.
    // Connection helpers live in ChatNet (shared with ChatService); these thin
    // delegates keep the Activity's existing call sites readable.
    private fun torDirPath(sub: String): String = ChatNet.torDirPath(this, sub)
    private fun freshTorSub(): String = ChatNet.freshTorSub()
    private fun isEmulator(): Boolean = ChatNet.isEmulator()

    // Nearby discovery (BLE + Wi-Fi Direct) state.
    private var nearby: List<NearbyDiscovery> = emptyList()
    private val foundInvites = LinkedHashMap<String, NearbyDiscovery.Peer>()
    private var nearbyList: LinearLayout? = null
    private var pendingNearby: (() -> Unit)? = null

    // palette — tokens live in [Tk]; local aliases keep call sites short
    private val bg = Tk.bg
    private val panel = Tk.panel
    private val field = Tk.field
    private val fg = Tk.fg
    private val muted = Tk.muted
    private val accent = Tk.accent
    private val peerBubble = Tk.peerBubble
    private val onAccent = Tk.onAccent

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tintSystemBars()
        SessionHub.hydrate(this)   // load saved chats (skips any already live)
        setContentView(chatListScreen())
        handleDeepLink(intent)
        // The drain+render poll loop starts in onResume (paired with the
        // foreground flag that hands draining to/from the always-on service).
    }

    override fun onResume() {
        super.onResume()
        SessionHub.foreground = true   // this Activity drains + renders events
        // Catch up with whatever the always-on service drained while we were
        // paused: append the missed history to the open chat (keeps the draft
        // and scroll), or refresh the list's previews/badges.
        val id = activeId
        if (id != null) sessions.get(id)?.let { renderNew(it); updateChatHeader(it) }
        else if (backState == Back.HOME) setContentView(chatListScreen())
        pollAll()
    }

    // We keep font-scale/density in configChanges (so a system font-size change
    // doesn't recreate the Activity and dump the user to the list), but the
    // already-built views hold old sp sizes. Rebuild the open chat so its header
    // and bubbles don't end up mixed old/new size. Other screens rebuild on nav.
    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        val id = activeId
        if (id != null) { renderedCount = 0; setContentView(chatScreen(id)) }
        else if (backState == Back.HOME) setContentView(chatListScreen())
    }

    @Suppress("DEPRECATION", "MissingSuperCall")
    override fun onBackPressed() {
        when {
            onConnecting -> { cancelJoin(); setContentView(chatListScreen()) } // abort the join
            activeId != null -> setContentView(chatListScreen())       // chat → list (stays live)
            backState == Back.LIST_CHILD -> setContentView(chatListScreen())  // subscreen → list
            else -> super.onBackPressed()                              // list → exit
        }
    }

    override fun onPause() {
        super.onPause()
        SessionHub.foreground = false   // hand event draining to the service (if running)
        for (lc in sessions.all()) if (lc.meta.persistence != Persistence.EPHEMERAL) {
            runCatching { store.save(lc.meta, lc.history) }
        }
        // Keep any always-on chats connected while we're backgrounded.
        ChatService.startIfNeeded(this)
    }

    // Match the system bars to the app background. The setters are deprecated on
    // API 35 (no-ops under edge-to-edge, which we already handle via insets) but
    // still tint the bars on older devices.
    @Suppress("DEPRECATION")
    private fun tintSystemBars() {
        window.statusBarColor = bg
        window.navigationBarColor = bg
    }

    // A talkrypt:// link was opened (scanned QR via the OS camera, or tapped).
    // Auto-join the chat it encodes. singleTask routes re-opens here.
    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDeepLink(intent)
    }

    private fun handleDeepLink(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "talkrypt") {
            val uri = data.toString()
            // A device-linking offer (channel "#link") routes to the linking
            // confirm screen — not the chat join flow.
            val isLink = runCatching { inviteChannel(uri) == "#link" }.getOrDefault(false)
            if (isLink) {
                setContentView(acceptLinkConfirmScreen(uri))
            } else {
                toast("opening invite…")
                // Explicit default — a deep-linked join must not silently inherit
                // whatever tier the last manual join happened to pick.
                pendingTier = Persistence.PERSISTENT_LOCAL
                startJoin(uri)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        shareServer?.stop()
        stopNearby()
    }

    companion object {
        private const val REQ_NEARBY = 0x4E42 // "NB"
        private const val REQ_SCAN = 0x5343
        private const val REQ_NOTIF = 0x4E54  // "NT" — POST_NOTIFICATIONS for the always-on service
        private const val REQ_TICKETBOOK = 0x544B // "TK" — pick a Nym ticketbook file to import
        private const val ANCHOR_SEP = "\u001F" // delimiter for stored (uri, username)
    }

    /** Open the in-app camera QR scanner; the result returns to [onActivityResult]. */
    private fun launchScanner() {
        startActivityForResult(Intent(this, QrScanActivity::class.java), REQ_SCAN)
    }

    /** Pick a Nym ticketbook file (minted by the user's own Nym tooling) to import
     *  as paid bandwidth — no wallet mnemonic ever enters talkrypt. */
    private fun launchTicketbookImport() {
        val pick = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(pick, REQ_TICKETBOOK)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK) return
        when (requestCode) {
            REQ_SCAN -> {
                // Route a scanned talkrypt:// invite like a deep link would.
                val uri = data?.getStringExtra(QrScanActivity.EXTRA_RESULT)?.trim().orEmpty()
                if (!uri.startsWith("talkrypt://")) { toast("Not a talkrypt QR"); return }
                val isLink = runCatching { inviteChannel(uri) == "#link" }.getOrDefault(false)
                if (isLink) setContentView(acceptLinkConfirmScreen(uri)) else { toast("opening invite…"); startJoin(uri) }
            }
            REQ_TICKETBOOK -> {
                val uri = data?.data ?: return
                // Read off the UI thread; import touches the local credential store.
                thread {
                    val res = runCatching {
                        val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                            ?: throw java.io.IOException("could not read file")
                        nymImportTicketbook(ChatNet.sharedTorDir(this), bytes)
                    }
                    ui.post {
                        res.fold(
                            { toast("Nym credential imported — paid mixnet ready (no mnemonic needed)") },
                            { toast("import failed: ${ChatNet.friendlyError(it.message)}") },
                        )
                    }
                }
            }
        }
    }

    // ---------- setup screen ----------
    private fun newChatScreen(): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }

        col.addView(text("New chat", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })

        val channel = inputField("#general")
        col.addView(label("CHANNEL", channel))
        col.addView(channel, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))

        val posture = darkSpinner(listOf("pq-pure", "hybrid", "pq-pure-compact"))
        col.addView(label("POSTURE", posture).also { it.setPadding(0, dp(20), 0, dp(8)) })
        col.addView(posture, lp(MATCH_PARENT, WRAP_CONTENT))

        val access = darkSpinner(listOf("open", "contacts", "friends"))
        col.addView(label("ACCESS", access).also { it.setPadding(0, dp(20), 0, dp(8)) })
        col.addView(access, lp(MATCH_PARENT, WRAP_CONTENT))

        val persistence = darkSpinner(listOf("Ephemeral (memory only)", "Persistent (saved, reconnectable)", "Always-on (Phase 2)"))
        col.addView(label("PERSISTENCE", persistence).also { it.setPadding(0, dp(20), 0, dp(8)) })
        // Default to Persistent (matches pendingTier's default): a real chat is
        // never silently ephemeral if a dropdown tap is missed, and Ephemeral
        // stays an explicit one-tap opt-in.
        persistence.setSelection(1)
        col.addView(persistence, lp(MATCH_PARENT, WRAP_CONTENT))

        // Route toggles start from the app-wide defaults (Settings); flipping
        // them here affects this chat setup only.
        useTor = prefsBool("default_tor", useTor)
        useNym = prefsBool("default_nym", useNym)
        val torBox = CheckBox(this).apply {
            text = "Route over Tor (.onion; slow to start)"
            setTextColor(muted)
            isChecked = useTor
            setOnCheckedChangeListener { _, checked -> useTor = checked }
        }
        col.addView(torBox, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16)))

        // Optional Nym mixnet leg: multi-homes the invite over Tor+Nym for
        // traffic-analysis resistance. Only functional if the .so was built with
        // --features nym (else host/join over Nym returns a clear error).
        val nymBox = CheckBox(this).apply {
            text = "Also route over Nym mixnet (opt-in; multi-homes the invite)"
            setTextColor(muted)
            isChecked = useNym
            setOnCheckedChangeListener { _, checked -> useNym = checked }
        }
        col.addView(nymBox, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
        col.addView(text("Paid Nym bandwidth (wallet mnemonic / credential) is set up in Settings.", 13f, muted)
            .also { it.setPadding(0, dp(4), 0, 0) })

        col.addView(pillButton("Host a chat", accent, onAccent) {
            startHost(
                channel.text.toString().ifBlank { "#general" },
                posture.selectedItem.toString(),
                access.selectedItem.toString(),
                tierOf(persistence),
            )
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(32)))
        col.addView(pillButton("Registry-restricted chat", panel, fg) {
            pendingTier = tierOf(persistence)
            setContentView(restrictedHostScreen(channel.text.toString().ifBlank { "#general" }, posture.selectedItem.toString()))
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(text("— or join —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(28), bottom = dp(12)))
        val invite = inputField("talkrypt://…")
        col.addView(invite, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Join", panel, fg) {
            val uri = invite.text.toString().trim()
            if (uri.startsWith("talkrypt://")) { pendingTier = tierOf(persistence); startJoin(uri) } else toast("Paste a talkrypt:// invite")
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(12)))
        col.addView(pillButton("Scan a QR code", accent, onAccent) {
            pendingTier = tierOf(persistence)
            launchScanner()
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        // In-person: find a nearby host, or send this very app P2P.
        col.addView(text("— in person —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(28), bottom = dp(12)))
        col.addView(pillButton("Find nearby host (BLE / Wi-Fi Direct)", accent, onAccent) {
            findNearby()
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Share app (P2P over Wi-Fi)", panel, fg) {
            shareApp()
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(12)))
        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))

        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    /** Map the persistence spinner to a tier (Always-on downgrades to persistent in Phase 1). */
    private fun tierOf(sp: Spinner): Persistence = when (sp.selectedItemPosition) {
        0 -> Persistence.EPHEMERAL
        2 -> Persistence.ALWAYS_ON        // Phase 2b: backed by the foreground ChatService
        else -> Persistence.PERSISTENT_LOCAL
    }

    private fun chatId(seed: String): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(seed.toByteArray())
            .joinToString("") { "%02x".format(it) }.take(24)

    // ---------- chat list (home) ----------
    private fun chatListScreen(): View {
        sessions.setActive(null)
        messages = null; scroll = null; chatChip = null; chatDetail = null
        backState = Back.HOME
        onConnecting = false
        setSecure(false)
        // Leaving a subscreen: stop what it started (BLE/Wi-Fi Direct scanning,
        // the APK share server) so system-back can't leak them.
        stopNearby()
        shareServer?.stop(); shareServer = null
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }

        val headRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
        val titleCol = column(Color.TRANSPARENT)
        titleCol.addView(text("talkrypt", 26f, fg, bold = true))
        // The custody probe can hit StrongBox (slow) — fill in off the main
        // thread; usually instant thanks to the TkApp prewarm cache.
        val tierLine = text("🔒 … · ML-DSA-87", 12f, accent)
        titleCol.addView(tierLine)
        thread {
            val t = runCatching { CustodyBridge.detectTier().name }.getOrDefault("UNKNOWN")
            ui.post { tierLine.text = "🔒 $t · ML-DSA-87" }
        }
        headRow.addView(titleCol, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        headRow.addView(text("⋯", 26f, muted).apply {
            contentDescription = "More"
            minimumWidth = dp(48); minimumHeight = dp(48); gravity = Gravity.CENTER
            setPadding(dp(12), dp(4), dp(8), dp(4)); setOnClickListener { setContentView(utilitiesScreen()) }
        })
        col.addView(headRow, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))

        col.addView(pillButton("＋  New chat", accent, onAccent) { setContentView(newChatScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(8)))

        val chats = sessions.ordered()
        if (chats.isEmpty()) {
            col.addView(text("No chats yet — tap ＋ to host or join.", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(40)))
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
        val glyph = text(if (m.group) "#" else "✺", 20f, if (m.group) onAccent else fg, center = true).apply {
            background = circle(if (m.group) accent else peerBubble); gravity = Gravity.CENTER
            importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO // decorative
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
        if (lc.unread > 0) {
            right.addView(text(lc.unread.toString(), 11f, onAccent, center = true).apply {
                background = circle(accent); setPadding(dp(7), dp(2), dp(7), dp(2)); gravity = Gravity.CENTER
            }, lp(WRAP_CONTENT, WRAP_CONTENT, top = dp(4)))
        }
        val (cs, cc) = connInfo(lc)
        right.addView(text("● $cs", 10f, cc), lp(WRAP_CONTENT, WRAP_CONTENT, top = dp(4)))
        row.addView(right, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        return row
    }

    /** Amber for "up but no peer yet" states (host published / dialing). */
    private val amber = Tk.amber

    /** Connection state for a chat: a short label + a color. Distinguishes
     *  offline (no session) from connected-with-peer from hosting/dialing-but-
     *  alone, so the dot isn't just "a session exists". */
    private fun connInfo(lc: LiveChat): Pair<String, Int> {
        val online = lc.roster.values.count { it.connected }
        return when {
            lc.client == null -> "offline" to muted
            online > 0 -> (if (online == 1) "online" else "$online online") to accent
            lc.meta.role == Role.HOST -> "hosting" to amber
            else -> "connecting" to amber
        }
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
        val connected = lc.client != null
        val items = buildList {
            add("Re-share invite")
            if (lc.meta.inviteUri != null) add("Show invite QR")
            add("Safety number (verify)")
            if (!connected) add("Reconnect")
            add("Leave (disconnect, keep history)")
            add("Delete (erase)")
        }
        android.app.AlertDialog.Builder(this)
            .setTitle(lc.meta.title)
            .setItems(items.toTypedArray()) { _, which ->
                when (items[which]) {
                    "Re-share invite" -> lc.meta.inviteUri?.let { shareText(it) } ?: toast("no invite")
                    "Show invite QR" -> lc.meta.inviteUri?.let { showInviteQr(it) }
                    "Safety number (verify)" -> {
                        android.app.AlertDialog.Builder(this)
                            .setTitle("Safety number")
                            .setMessage("${lc.meta.safety}\n\nCompare this with your peer out-of-band; a mismatch means the channel is not talking to who you think.")
                            .setPositiveButton("Copy") { _, _ ->
                                val cm = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText("talkrypt safety number", lc.meta.safety))
                                toast("copied")
                            }
                            .setNegativeButton("Close", null)
                            .show()
                    }
                    "Reconnect" -> reconnect(id)
                    "Leave (disconnect, keep history)" -> { sessions.disconnect(id); setContentView(chatListScreen()) }
                    "Delete (erase)" -> confirm("Delete “${lc.meta.title}”?", "Erases this chat and its history from this device. This cannot be undone.", "Delete") {
                        sessions.disconnect(id); sessions.remove(id); drafts.remove(id); runCatching { store.delete(id) }; setContentView(chatListScreen())
                    }
                }
            }.show()
    }

    private fun openChat(id: String) {
        sessions.setActive(id)
        onConnecting = false // entering a chat (incl. from a finished join)
        // Lazily reconnect a saved-but-disconnected persistent chat when opened.
        val lc = sessions.get(id)
        if (lc != null && lc.client == null && lc.meta.persistence != Persistence.EPHEMERAL &&
            reconnectPlan(lc.meta) != ReconnectPlan.IMPOSSIBLE) reconnect(id)
        ensureAlwaysOn()
        setContentView(chatScreen(id))
    }

    /** If any chat is on the always-on tier, ensure notifications are permitted
     *  (API 33+) and the foreground [ChatService] is running to keep it alive. */
    private fun ensureAlwaysOn() {
        if (!anyAlwaysOn(sessions)) return
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            runCatching { requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF) }
        }
        ChatService.startIfNeeded(this)
    }

    /** Register a freshly-connected client as a session, persist if kept, open it. */
    private fun enterSession(meta: ChatMeta, c: TalkryptClient, sysMsg: String) {
        val lc = sessions.open(meta, c)
        if (meta.persistence != Persistence.EPHEMERAL) runCatching { store.save(meta, lc.history) }
        openChat(meta.id)
        sysLine(meta.id, sysMsg)
    }

    private fun shareText(s: String) {
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, s) }, "Share invite"))
    }

    /** The old utility buttons, moved off the chat-first home (⋯ on the list). */
    private fun utilitiesScreen(): View {
        backState = Back.LIST_CHILD
        setSecure(false) // leaving Settings
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("More", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })
        col.addView(pillButton("Anchors (username directory)", panel, fg) { setContentView(anchorsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
        col.addView(pillButton("Contacts", panel, fg) { setContentView(contactsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton("Linked devices", panel, fg) { setContentView(linkedDevicesScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton("Segments (contextual identities)", panel, fg) { setContentView(segmentsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton("Settings", panel, fg) { setContentView(settingsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    // ---------- settings ----------
    private fun prefsBool(key: String, def: Boolean): Boolean =
        getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE).getBoolean(key, def)

    private fun putPrefsBool(key: String, v: Boolean) =
        getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE).edit().putBoolean(key, v).apply()

    /** A panel card with a heading and a muted detail line (settings rows). */
    private fun infoCard(title: String, detail: String, onClick: (() -> Unit)? = null, titleColor: Int = fg): View {
        val card = column(Color.TRANSPARENT).apply {
            background = roundRect(panel, 14); setPadding(dp(14), dp(12), dp(14), dp(12))
        }
        card.addView(text(title, 15f, titleColor, bold = true))
        card.addView(text(detail, 13f, muted).also { it.setPadding(0, dp(2), 0, 0) })
        if (onClick != null) { card.isClickable = true; card.setOnClickListener { onClick() } }
        return card
    }

    // Accessors for updating an [infoCard] in place after async work resolves
    // (child 0 is the title, child 1 the detail line — see infoCard).
    private fun cardTitle(card: View): TextView = (card as LinearLayout).getChildAt(0) as TextView
    private fun cardDetail(card: View): TextView = (card as LinearLayout).getChildAt(1) as TextView

    /** Block screenshots/recents previews while a screen shows secrets (the
     *  mnemonic in Settings). Scoped, not app-wide, so chat/QR screenshots and
     *  adb-driven UI checks still work. */
    private fun setSecure(on: Boolean) {
        if (on) window.addFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
        else window.clearFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE)
    }

    // Debounced, off-main-thread mnemonic sealing (a Keystore op per keystroke
    // caused input jank and sealed half-typed mnemonics).
    private var pendingMnemonic: String? = null
    private val sealMnemonic = Runnable {
        val v = pendingMnemonic ?: return@Runnable
        thread {
            runCatching { SecretStore.put(this, "nym_mnemonic", v) }
                .onFailure { ui.post { toast("couldn't seal mnemonic: ${it.message}") } }
        }
    }

    /** App-wide settings: identity, security, network defaults, notifications,
     *  about. Per-chat choices (posture, access, persistence, routing) stay in
     *  the new-chat screen; this holds everything that outlives a single chat. */
    private fun settingsScreen(): View {
        backState = Back.LIST_CHILD
        setSecure(true) // the mnemonic lives here; cleared on the exits below
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Settings", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })

        // -- identity --
        col.addView(label("IDENTITY"), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(6)))
        // Safety number derivation reconstructs the ML-DSA account — done off
        // the main thread (usually cached by the TkApp prewarm).
        var sn: String? = null
        val snCard = infoCard("Account safety number", "deriving…", onClick = {
            val v = sn
            if (v == null) { toast("still deriving…") } else {
                val cm = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("talkrypt safety number", v))
                toast("copied")
            }
        })
        col.addView(snCard, lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        storedLink()?.let { (_, username, accountSn) ->
            col.addView(infoCard("Linked as secondary device", "account ${accountSn.take(11)}" + if (username.isNotEmpty()) " · @$username" else ""),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        }

        // -- security --
        col.addView(label("SECURITY"), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        val custodyCard = infoCard("Key custody: …", "Where this device can keep keys (StrongBox > TEE > software). Reported to peers as your custody tier.")
        col.addView(custodyCard, lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        thread {
            val v = runCatching { account().safetyNumber() }.getOrDefault("unavailable")
            val t = runCatching { CustodyBridge.detectTier().name }.getOrDefault("UNKNOWN")
            ui.post {
                sn = v
                cardDetail(snCard).text = "$v — tap to copy. Compare out-of-band to verify you."
                cardTitle(custodyCard).text = "Key custody: $t"
            }
        }
        val sealErr = SecretStore.lastError
        if (sealErr == null) {
            col.addView(infoCard("Secrets sealed at rest", "Identity seeds and the Nym mnemonic are encrypted with a non-exportable Android Keystore key (StrongBox when available)."),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        } else {
            col.addView(infoCard("Sealing degraded", "The Keystore reported: $sealErr. Secrets that couldn't be sealed remain in app-private plaintext until it recovers.", titleColor = amber),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        }

        // Paid Nym bandwidth (optional): mnemonic (sealed at rest) or ticketbook.
        col.addView(label("NYM PAID BANDWIDTH (OPTIONAL)"), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        // Masked by default (it controls funds), autofill excluded, sealed on a
        // debounce off the main thread rather than per keystroke.
        val nymMnem = inputField("NYM wallet mnemonic — blank = free mixnet").apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            transformationMethod = android.text.method.PasswordTransformationMethod.getInstance()
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            setText(ChatNet.nymMnemonic(this@MainActivity))
            addTextChangedListener(object : android.text.TextWatcher {
                override fun afterTextChanged(s: android.text.Editable?) {
                    pendingMnemonic = s?.toString()?.trim()
                    ui.removeCallbacks(sealMnemonic)
                    ui.postDelayed(sealMnemonic, 700)
                }
                override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
                override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
            })
        }
        col.addView(nymMnem, lp(MATCH_PARENT, WRAP_CONTENT))
        val reveal = CheckBox(this).apply {
            text = "Show mnemonic"
            setTextColor(muted)
            setOnCheckedChangeListener { _, checked ->
                nymMnem.transformationMethod =
                    if (checked) null else android.text.method.PasswordTransformationMethod.getInstance()
                nymMnem.setSelection(nymMnem.text.length)
            }
        }
        col.addView(reveal, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(4)))
        col.addView(text("Or import a ticketbook credential minted with your own Nym tooling (the wallet seed never enters this app):", 13f, muted)
            .also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(pillButton("Import Nym credential", panel, fg) { launchTicketbookImport() },
            lp(MATCH_PARENT, dp(50), top = dp(4)))

        // -- network defaults --
        col.addView(label("NETWORK DEFAULTS FOR NEW CHATS"), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        val torDef = CheckBox(this).apply {
            text = "Route over Tor (.onion)"
            setTextColor(muted); isChecked = prefsBool("default_tor", false)
            setOnCheckedChangeListener { _, c -> putPrefsBool("default_tor", c) }
        }
        col.addView(torDef, lp(MATCH_PARENT, WRAP_CONTENT))
        val nymDef = CheckBox(this).apply {
            text = "Also route over Nym mixnet"
            setTextColor(muted); isChecked = prefsBool("default_nym", false)
            setOnCheckedChangeListener { _, c -> putPrefsBool("default_nym", c) }
        }
        col.addView(nymDef, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(4)))

        // -- notifications --
        col.addView(label("NOTIFICATIONS"), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        col.addView(infoCard("Always-on chats", "Kept connected by a foreground service with a persistent notification. Tap to adjust it in system settings.", onClick = {
            runCatching {
                startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }.onFailure { toast("couldn't open notification settings") }
        }), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))

        // -- about --
        col.addView(label("ABOUT"), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        val ver = runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull() ?: "?"
        col.addView(infoCard("talkrypt $ver", "Post-quantum E2E chat over Tor. NOT certified · NOT accredited · NOT audited — experimental software; classification markings are advisory labels only."),
            lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))

        col.addView(pillButton("Back", panel, fg) { setContentView(utilitiesScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    // ---------- contacts screen ----------
    private fun contactsScreen(): View {
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Contacts", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Accounts you recognize. Recognition only — being a contact (or friend) doesn't grant channel access; that's set per chat.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        val contacts = storedContacts()
        if (contacts.isEmpty()) {
            col.addView(
                text("No contacts yet. In a chat, when an account presents itself, tap “Add as a contact”.", 13f, muted),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(12)),
            )
        } else {
            for ((pk, name, friend) in contacts) {
                val label = (name.ifEmpty { pk.take(12) }) + (if (friend) "  [friend]" else "")
                col.addView(text(label, 15f, if (friend) accent else fg).apply {
                    background = roundRect(panel, 12); setPadding(dp(14), dp(12), dp(14), dp(12))
                }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
            }
        }
        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    // ---------- P2P app sharing ----------
    private fun shareApp() {
        toast("starting local share…")
        thread {
            val server = ApkShareServer(ApkShareServer.apkPath(this))
            val url = server.start()
            ui.post {
                if (url == null) {
                    server.stop()
                    toast("No Wi-Fi/LAN address — join a Wi-Fi network or hotspot first")
                    return@post
                }
                shareServer?.stop()
                shareServer = server
                setContentView(shareScreen(url))
            }
        }
    }

    private fun shareScreen(url: String): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Share talkrypt", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                "On the same Wi-Fi or hotspot, the other phone scans this code (or opens the URL), " +
                    "downloads the app, and installs it (allow “install unknown apps” once).",
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(20)),
        )
        addQrInto(col, url, 0.72f)
        col.addView(text(url, 13f, accent, center = true).also { it.setPadding(0, dp(18), 0, dp(8)) })
        // The transfer is plain HTTP on the local network — give the receiver a
        // fingerprint to compare so a hostile LAN can't swap the APK silently.
        val fpLine = text("APK SHA-256: computing…", 12f, muted, center = true)
        col.addView(fpLine, lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
        thread {
            val fp = runCatching {
                val md = java.security.MessageDigest.getInstance("SHA-256")
                java.io.File(ApkShareServer.apkPath(this)).inputStream().use { ins ->
                    val buf = ByteArray(65536)
                    while (true) { val n = ins.read(buf); if (n < 0) break; md.update(buf, 0, n) }
                }
                md.digest().joinToString("") { "%02x".format(it) }.take(16).chunked(4).joinToString(" ")
            }.getOrNull()
            ui.post {
                fpLine.text = if (fp != null) "APK SHA-256 (first 16): $fp — verify on the receiving phone" else "couldn't compute APK fingerprint"
            }
        }
        col.addView(pillButton("Done", panel, fg) {
            shareServer?.stop(); shareServer = null
            setContentView(chatListScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    /** Add a centered QR image of `data` (sized as a fraction of screen width). */
    private fun addQrInto(parent: LinearLayout, data: String, widthFraction: Float) {
        val bmp = Qr.bitmap(data) ?: run {
            parent.addView(text("(QR too large to render — use the text)", 12f, muted, center = true))
            return
        }
        val side = (resources.displayMetrics.widthPixels * widthFraction).toInt()
        val iv = ImageView(this).apply {
            setImageBitmap(bmp)
            setBackgroundColor(Color.WHITE)
            setPadding(dp(10), dp(10), dp(10), dp(10))
        }
        val wrap = LinearLayout(this).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(iv, LinearLayout.LayoutParams(side, side))
        }
        parent.addView(wrap, lp(MATCH_PARENT, WRAP_CONTENT))
    }

    // ---------- device linking (primary certifies a secondary device) ----------
    // Held while a link offer is running so its accept loop stays alive.
    private var linkOffer: LinkOffer? = null

    private var cachedDeviceKey: DeviceKey? = null

    /** This device's persistent linked-device key (generated + persisted once).
     *  Distinct from `account()`: a linked secondary device holds this key but
     *  NOT the account secret — it presents a certificate the primary issued.
     *  The seed is sealed at rest by [SecretStore]. Cached + synchronized so an
     *  unreadable seed doesn't yield a DIFFERENT ephemeral key on every call
     *  (which would break a link mid-flow). */
    @Synchronized
    private fun deviceKey(): DeviceKey {
        cachedDeviceKey?.let { return it }
        SecretStore.get(this, "device_seed")?.let { seed ->
            runCatching { DeviceKey.fromSeedHex(seed) }.getOrNull()?.let { cachedDeviceKey = it; return it }
        }
        val d = DeviceKey.generate()
        // Never clobber an existing-but-unreadable seed (see ChatNet.account).
        if (!SecretStore.has(this, "device_seed")) {
            runCatching { SecretStore.put(this, "device_seed", d.seedHex()) }
        }
        cachedDeviceKey = d
        return d
    }

    /** The account this device is linked to, if any: (chainHex, username, accountSafetyNumber). */
    private fun storedLink(): Triple<String, String, String>? {
        val p = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        val chain = p.getString("link_chain", null) ?: return null
        return Triple(chain, p.getString("link_username", "") ?: "", p.getString("link_account_sn", "") ?: "")
    }

    private fun saveLink(chainHex: String, username: String, accountSn: String) {
        getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE).edit()
            .putString("link_chain", chainHex)
            .putString("link_username", username)
            .putString("link_account_sn", accountSn)
            .apply()
    }

    private fun clearLink() {
        getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE).edit()
            .remove("link_chain").remove("link_username").remove("link_account_sn").apply()
    }

    private fun linkedDevicesScreen(): View {
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Linked devices", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                "Link this device to your account on another device, so contacts recognize all your devices as one account. The account key never leaves the device that holds it — only a signed certificate crosses the wire.",
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )

        val link = storedLink()
        if (link != null) {
            col.addView(text("THIS DEVICE IS LINKED", 12f, muted, bold = true))
            col.addView(text("account ${link.third.take(35)}…", 13f, accent))
            if (link.second.isNotEmpty()) col.addView(text("username ${link.second}", 13f, fg))
            col.addView(
                text("device ${deviceKey().fingerprintHex().take(24)}…", 12f, muted),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(14)),
            )
            col.addView(label("JOIN A CHAT AS THIS ACCOUNT (talkrypt:// invite)"))
            val joinUri = inputField("talkrypt://…")
            col.addView(joinUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
            col.addView(pillButton("Join as this account", accent, onAccent) {
                val u = joinUri.text.toString().trim()
                if (u.startsWith("talkrypt://")) joinAsLinked(u) else toast("paste a talkrypt:// invite")
            }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
            col.addView(pillButton("Unlink this device", panel, Tk.danger) {
                confirm("Unlink this device?", "Removes the link certificate — contacts will no longer recognize this device as part of the account until you link again.", "Unlink") {
                    clearLink(); toast("unlinked"); setContentView(linkedDevicesScreen())
                }
            }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
            col.addView(text("— or re-link —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(22), bottom = dp(6)))
        }

        // Primary role: certify ANOTHER device under this device's account.
        col.addView(text("LINK ANOTHER DEVICE TO MY ACCOUNT", 12f, muted, bold = true).also { it.setPadding(0, dp(4), 0, dp(4)) })
        col.addView(text("This device holds the account. Show a one-time QR the new device scans.", 12f, muted))
        col.addView(pillButton("Start a link offer", accent, onAccent) {
            startLinkOffer()
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        // Secondary role: link THIS device using an offer from the primary.
        col.addView(text("LINK THIS DEVICE TO AN ACCOUNT", 12f, muted, bold = true).also { it.setPadding(0, dp(22), 0, dp(4)) })
        col.addView(label("LINK OFFER (talkrypt:// from the primary)"))
        val offerUri = inputField("talkrypt://…")
        col.addView(offerUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        col.addView(pillButton("Accept link on this device", panel, fg) {
            val u = offerUri.text.toString().trim()
            if (u.startsWith("talkrypt://")) setContentView(acceptLinkConfirmScreen(u)) else toast("paste the link offer URI")
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun startLinkOffer() {
        toast("starting link offer…")
        thread {
            try {
                val lan = ApkShareServer.lanIp() ?: "127.0.0.1"
                val offer = LinkOffer.host(account(), "$lan:9110", null)
                ui.post {
                    linkOffer = offer // hold it alive (the accept loop runs while held)
                    setContentView(linkOfferRunningScreen(offer.uri(), offer.accountSafetyNumber()))
                }
            } catch (e: Exception) {
                ui.post { toast("link offer failed: ${e.message}") }
            }
        }
    }

    private fun linkOfferRunningScreen(uri: String, accountSn: String): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Link offer running", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("On the NEW device, scan this (or paste the URI into Linked devices → Accept link). The account key stays on this device.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        addQrInto(col, uri, 0.66f)
        col.addView(text(uri, 12f, accent, center = true).also { it.setPadding(0, dp(14), 0, dp(16)) })
        col.addView(text("VERIFY OUT OF BAND — account safety number:", 12f, muted, bold = true))
        col.addView(text(accountSn, 13f, fg), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))
        col.addView(pillButton("Done", panel, fg) {
            linkOffer = null; setContentView(linkedDevicesScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun acceptLinkConfirmScreen(uri: String): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Link this device?", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("This certifies THIS device under the account offering the link. Afterward, verify the account safety number shown matches the other device, out of band.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        col.addView(text(uri, 12f, muted), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))
        col.addView(pillButton("Accept link on this device", accent, onAccent) {
            acceptLink(uri)
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Cancel", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun acceptLink(uri: String) {
        toast("linking this device…")
        thread {
            try {
                val res = linkAccept(deviceKey(), uri, "android")
                saveLink(res.chainHex, res.username, res.accountSafetyNumber)
                ui.post {
                    setContentView(linkedDevicesScreen())
                    toast("linked to account ${res.accountSafetyNumber.take(11)}…")
                }
            } catch (e: Exception) {
                ui.post { toast("link failed: ${e.message}") }
            }
        }
    }

    private fun joinAsLinked(uri: String) {
        val link = storedLink() ?: run { toast("this device isn't linked"); return }
        toast("joining as linked account…")
        thread {
            try {
                val c = TalkryptClient.joinLinked(uri, deviceKey(), link.first, link.second.ifEmpty { null })
                val sn = c.safetyNumber()
                runCatching { loadContacts(c) } // recognize saved contacts
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(uri), runCatching { inviteChannel(uri) }.getOrDefault("chat"), Role.JOIN, false, "", "open", uri, if (runCatching { inviteIsOnion(uri) }.getOrDefault(false)) uri else null, pendingTier, sn, now, now)
                    enterSession(meta, c, "joined as linked account" + (link.second.takeIf { it.isNotEmpty() }?.let { " ($it)" } ?: ""))
                }
            } catch (e: Exception) {
                ui.post { toast("join failed: ${e.message}") }
            }
        }
    }

    // ---------- segment sub-identities (mutually-unlinkable contexts) ----------
    /** The raw "name<sep>seedhex" entries, sealed at rest by [SecretStore] as one
     *  newline-joined value. A legacy plaintext StringSet is migrated on first
     *  read (sealed, then removed) — these are identity seeds like the account's. */
    private fun segmentSet(): Set<String> {
        val p = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        p.getStringSet("segments", null)?.let { legacy ->
            runCatching {
                SecretStore.put(this, "segments", legacy.joinToString("\n"))
                p.edit().remove("segments").apply()
            }
            return legacy // served from the legacy copy this once; sealed next read
        }
        return SecretStore.get(this, "segments")?.split("\n")?.filterTo(HashSet()) { it.isNotEmpty() } ?: emptySet()
    }

    private fun saveSegmentSet(set: Set<String>) {
        runCatching { SecretStore.put(this, "segments", set.joinToString("\n")) }
            .onFailure { toast("couldn't seal segments: ${it.message}") }
    }

    /** Persisted segments: (name, seed-hex). Each is an unlinkable contextual
     *  identity under this device's account (account→device→segment). */
    private fun storedSegments(): List<Pair<String, String>> =
        segmentSet().mapNotNull {
            val s = it.split(contactSep)
            if (s.size == 2) s[0] to s[1] else null
        }.sortedBy { it.first }

    private fun addSegment(name: String): SegmentKey {
        val seg = SegmentKey.generate()
        val set = HashSet(segmentSet())
        set.removeAll { it.substringBefore(contactSep) == name } // replace same-name
        set.add(name + contactSep + seg.seedHex())
        saveSegmentSet(set)
        return seg
    }

    private fun removeSegment(name: String) {
        val set = HashSet(segmentSet())
        set.removeAll { it.substringBefore(contactSep) == name }
        saveSegmentSet(set)
    }

    private fun segmentsScreen(): View {
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Segments", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                "Contextual sub-identities under your account. Each segment authenticates with its own key, so different segments are unlinkable to each other — yet a contact who recognizes your account recognizes every segment. Use one per context (work, activism, …).",
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(12)),
        )

        val linked = storedLink()
        col.addView(
            text(
                if (linked != null) "rooted at your linked account ${linked.third.take(20)}…"
                else "rooted at this device's account",
                12f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(12)),
        )

        col.addView(label("JOIN A CHAT (talkrypt:// invite)"))
        val joinUri = inputField("talkrypt://…")
        col.addView(joinUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6), bottom = dp(8)))

        val segs = storedSegments()
        if (segs.isEmpty()) {
            col.addView(text("No segments yet — create one below.", 13f, muted), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        } else {
            segs.forEach { (name, seed) ->
                val seg = runCatching { SegmentKey.fromSeedHex(seed) }.getOrNull() ?: return@forEach
                col.addView(text("● $name", 15f, fg, bold = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
                col.addView(text("safety ${seg.safetyNumber().take(23)}…", 12f, muted))
                col.addView(pillButton("Join as “$name”", accent, onAccent) {
                    val u = joinUri.text.toString().trim()
                    if (u.startsWith("talkrypt://")) joinAsSegment(u, seg, name) else toast("paste a talkrypt:// invite above")
                }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
                col.addView(pillButton("Delete “$name”", panel, Tk.danger) {
                    confirm("Delete segment “$name”?", "Erases this segment's key — chats joined under it can't be rejoined as the same identity. This cannot be undone.", "Delete") {
                        removeSegment(name); setContentView(segmentsScreen())
                    }
                }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
            }
        }

        col.addView(text("— new segment —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20), bottom = dp(8)))
        col.addView(label("SEGMENT NAME (context label)"))
        val name = inputField("work")
        col.addView(name, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        col.addView(pillButton("Create segment", accent, onAccent) {
            val n = name.text.toString().trim()
            if (n.isEmpty()) { toast("name the segment"); return@pillButton }
            addSegment(n); toast("created segment “$n”"); setContentView(segmentsScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun joinAsSegment(uri: String, segment: SegmentKey, name: String) {
        toast("joining as “$name”…")
        thread {
            try {
                // Build account→device→segment: from the stored link chain if this
                // device is linked (no account key needed), else from the account
                // this device holds. deviceKey() is the intermediate device layer.
                val linked = storedLink()
                val chain = if (linked != null) {
                    linkedSegmentChain(deviceKey(), linked.first, segment, name)
                } else {
                    accountSegmentChain(account(), deviceKey(), segment, name)
                }
                val c = TalkryptClient.joinSegment(uri, segment, chain, name)
                val sn = c.safetyNumber()
                runCatching { loadContacts(c) } // recognize saved contacts
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(uri), runCatching { inviteChannel(uri) }.getOrDefault("chat"), Role.JOIN, false, "", "open", uri, if (runCatching { inviteIsOnion(uri) }.getOrDefault(false)) uri else null, pendingTier, sn, now, now)
                    enterSession(meta, c, "joined as segment “$name”")
                }
            } catch (e: Exception) {
                ui.post { toast("join failed: ${e.message}") }
            }
        }
    }

    // ---------- nearby discovery (BLE + Wi-Fi Direct) ----------
    private fun findNearby() {
        withNearbyPermissions {
            foundInvites.clear()
            setContentView(findNearbyScreen())
            stopNearby()
            nearby = listOf(NearbyDiscovery.ble(this), NearbyDiscovery.wifiDirect(this))
            nearby.forEach { d ->
                d.startScanning(
                    onFound = { peer -> addNearbyPeer(peer) },
                    onError = { msg -> toast(msg) },
                )
            }
            promptWifiIfOff()
        }
    }

    /** Wi-Fi Direct needs the Wi-Fi radio on. If it's off, offer a one-tap enable
     *  via the system Wi-Fi panel (Bluetooth discovery still works regardless). */
    private fun promptWifiIfOff() {
        val wifi = getSystemService(WifiManager::class.java)
        if (wifi?.isWifiEnabled == false) {
            toast("Wi-Fi is off — turn it on for Wi-Fi Direct (Bluetooth still works)")
            // API 29+ slide-up Wi-Fi panel; apps can't toggle Wi-Fi directly.
            runCatching { startActivity(Intent(Settings.Panel.ACTION_WIFI)) }
        }
    }

    private fun findNearbyScreen(): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Nearby hosts", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Scanning over Bluetooth LE and Wi-Fi Direct. Tap a host to join.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        nearbyList = list
        col.addView(list, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(text("…", 13f, muted, center = true).also { it.setPadding(0, dp(16), 0, dp(16)) })
        col.addView(pillButton("Back", panel, fg) {
            stopNearby(); setContentView(chatListScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(12)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun addNearbyPeer(peer: NearbyDiscovery.Peer) {
        if (foundInvites.put(peer.inviteUri, peer) != null) return // de-dupe
        val list = nearbyList ?: return
        list.addView(pillButton("Join ${peer.name}", accent, onAccent) {
            stopNearby(); startJoin(peer.inviteUri)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
    }

    private fun startNearbyAdvertising(invite: String) {
        withNearbyPermissions {
            stopNearby()
            nearby = listOf(NearbyDiscovery.ble(this), NearbyDiscovery.wifiDirect(this))
            nearby.forEach { it.startAdvertising(invite) }
            system("broadcasting nearby (BLE + Wi-Fi Direct)")
        }
    }

    private fun stopNearby() {
        nearby.forEach { runCatching { it.stop() } }
        nearby = emptyList()
        nearbyList = null
    }

    // ---------- runtime permissions for nearby ----------
    private fun nearbyPermissions(): Array<String> {
        val p = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= 31) {
            p += Manifest.permission.BLUETOOTH_ADVERTISE
            p += Manifest.permission.BLUETOOTH_SCAN
            p += Manifest.permission.BLUETOOTH_CONNECT
        }
        if (Build.VERSION.SDK_INT >= 33) {
            p += Manifest.permission.NEARBY_WIFI_DEVICES
        }
        // Pre-31 BLE scan and pre-33 Wi-Fi Direct need fine location.
        if (Build.VERSION.SDK_INT < 33) {
            p += Manifest.permission.ACCESS_FINE_LOCATION
        }
        return p.distinct().toTypedArray()
    }

    private fun withNearbyPermissions(action: () -> Unit) {
        val needed = nearbyPermissions().filter {
            checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
        }
        if (needed.isEmpty()) {
            action()
        } else {
            pendingNearby = action
            requestPermissions(needed.toTypedArray(), REQ_NEARBY)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF) {
            val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
            if (!granted) toast("notifications blocked — always-on chats still run, but without a status notification")
        }
        if (requestCode == REQ_NEARBY) {
            val granted = grantResults.isNotEmpty() &&
                grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            val act = pendingNearby
            pendingNearby = null
            if (granted) {
                act?.invoke()
            } else {
                toast("nearby discovery needs Bluetooth / nearby-Wi-Fi permission")
            }
        }
    }

    // ---------- anchors (username registry directory) ----------
    private var anchorNode: AnchorNode? = null

    /** Load this device's account, generating + persisting one on first use.
     *  Delegates to [ChatNet] so the service builds the same account. */
    private fun account(): Account = ChatNet.account(this)

    // ----- contacts (recognized accounts), persisted across sessions -----
    private val contactSep = "\u001F"

    /** Persisted contacts: (account pubkey hex, name, friend). */
    private fun storedContacts(): List<Triple<String, String, Boolean>> {
        val prefs = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        return prefs.getStringSet("contacts", emptySet()).orEmpty().mapNotNull {
            val p = it.split(contactSep)
            if (p.size == 3) Triple(p[0], p[1], p[2] == "1") else null
        }
    }

    /** Save the client's current contacts to SharedPreferences. */
    private fun saveContacts(client: TalkryptClient) {
        val set = client.exportContacts()
            .map { "${it.accountPubkeyHex}$contactSep${it.name}$contactSep${if (it.friend) "1" else "0"}" }
            .toSet()
        getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
            .edit().putStringSet("contacts", set).apply()
    }

    /** Re-add persisted contacts into a fresh client (call after creating it). */
    private fun loadContacts(client: TalkryptClient) = ChatNet.loadContacts(this, client)

    // Anchors you are bound at (where you registered a username) — the only
    // registries it makes sense to gate a chat by, since you're a member.
    private fun boundAnchors(): List<Pair<String, String>> {
        val prefs = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        return prefs.getStringSet("bound_anchors", emptySet()).orEmpty().mapNotNull {
            val p = it.split(ANCHOR_SEP)
            if (p.size == 2) p[0] to p[1] else null
        }
    }

    private fun addBoundAnchor(uri: String, username: String) {
        val prefs = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        val set = HashSet(prefs.getStringSet("bound_anchors", emptySet()).orEmpty())
        // Replace any prior entry for this anchor (latest username wins).
        set.removeAll { it.substringBefore(ANCHOR_SEP) == uri }
        set.add(uri + ANCHOR_SEP + username)
        prefs.edit().putStringSet("bound_anchors", set).apply()
    }

    private fun anchorsScreen(): View {
        val acct = account()
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Anchors", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("A username directory you spawn or point at by location. Names map to account keys; verify safety numbers out of band.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(12)),
        )
        col.addView(text("YOUR ACCOUNT", 12f, muted, bold = true))
        col.addView(text(acct.safetyNumber().take(35) + "…", 13f, accent), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))

        // Spawn your own anchor.
        col.addView(pillButton("Spawn my own anchor", accent, onAccent) {
            spawnAnchor()
        }, lp(MATCH_PARENT, WRAP_CONTENT))

        // Use a known anchor by entering its location.
        col.addView(text("— or use a known anchor —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24), bottom = dp(10)))
        col.addView(label("ANCHOR LOCATION (talkrypt:// URI)"))
        val anchorUri = inputField("talkrypt://…")
        col.addView(anchorUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))

        col.addView(label("USERNAME").also { it.setPadding(0, dp(16), 0, dp(6)) })
        val uname = inputField("alice")
        col.addView(uname, lp(MATCH_PARENT, WRAP_CONTENT))

        val result = text("", 13f, fg).also { it.setPadding(0, dp(14), 0, 0) }

        col.addView(pillButton("Register my username here", panel, fg) {
            val uri = anchorUri.text.toString().trim()
            val name = uname.text.toString().trim()
            if (!uri.startsWith("talkrypt://") || name.isEmpty()) { toast("enter an anchor URI + username"); return@pillButton }
            registerAtAnchor(uri, acct, name, result)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16)))

        col.addView(pillButton("Resolve this username", panel, fg) {
            val uri = anchorUri.text.toString().trim()
            val name = uname.text.toString().trim()
            if (!uri.startsWith("talkrypt://") || name.isEmpty()) { toast("enter an anchor URI + username"); return@pillButton }
            resolveAtAnchor(uri, name, result)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(result, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Back", panel, fg) {
            setContentView(chatListScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))

        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun spawnAnchor() {
        toast("spawning anchor…")
        thread {
            try {
                val lan = ApkShareServer.lanIp() ?: "127.0.0.1"
                val node = AnchorNode.host("$lan:9100", "#anchor")
                ui.post {
                    anchorNode = node // keep it alive (the registry runs while held)
                    setContentView(anchorRunningScreen(node.uri()))
                }
            } catch (e: Exception) {
                ui.post { toast("anchor failed: ${e.message}") }
            }
        }
    }

    private fun anchorRunningScreen(uri: String): View {
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Anchor running", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Others register/resolve usernames here. Share this location (scan or copy). It runs while the app is open.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        addQrInto(col, uri, 0.66f)
        col.addView(text(uri, 13f, accent, center = true).also { it.setPadding(0, dp(16), 0, dp(20)) })
        col.addView(pillButton("Back", panel, fg) { setContentView(anchorsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun registerAtAnchor(uri: String, acct: Account, name: String, result: TextView) {
        result.text = "registering…"
        thread {
            val msg = try {
                anchorRegister(uri, acct, name)
                // Remember we're bound here so registry-restricted chats can
                // offer it — the only registries it makes sense to gate by.
                addBoundAnchor(uri, name)
                "✓ registered “$name” → your account at this anchor"
            } catch (e: Exception) {
                "! register failed: ${e.message}"
            }
            ui.post { result.text = msg }
        }
    }

    private fun resolveAtAnchor(uri: String, name: String, result: TextView) {
        result.text = "resolving…"
        thread {
            val msg = try {
                val sn = anchorResolve(uri, name)
                if (sn != null) "“$name” → account safety number:\n$sn\n(verify out of band before trusting)"
                else "“$name” is not registered here (or registries disagreed)"
            } catch (e: Exception) {
                "! resolve failed: ${e.message}"
            }
            ui.post { result.text = msg }
        }
    }

    // ---------- registry-restricted chat spawning ----------
    // You can only gate a chat by a registry you're a member of (else you'd lock
    // yourself out), so we offer ONLY anchors you're bound at, and grey out any
    // that fail a live ping (unreachable, or your record isn't there).
    private fun restrictedHostScreen(channel: String, posture: String): View {
        val acct = account()
        val anchors = boundAnchors()
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Registry-restricted chat", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Only members of the chosen registry can join $channel. You can pick only registries you're bound at; unreachable ones (or ones missing your record) are greyed out.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(18)),
        )
        if (anchors.isEmpty()) {
            col.addView(text("You aren't registered at any anchor yet. Open Anchors and register a username first.", 13f, amber), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
        } else {
            for ((uri, username) in anchors) {
                // One disabled row per bound anchor; a background ping enables it.
                val row = pillButton("checking ${shortUri(uri)} …", panel, muted) { /* set on success */ }
                row.isEnabled = false
                row.alpha = 0.5f
                row.isClickable = false
                col.addView(row, lp(MATCH_PARENT, dp(52), top = dp(8)))
                pingAnchor(uri, username, acct, row, "Host gated by “$username@${shortUri(uri)}”") {
                    startRestrictedHost(channel, posture, uri, username)
                }
            }
        }
        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun shortUri(uri: String): String {
        val body = uri.removePrefix("talkrypt://")
        return "…" + body.takeLast(10)
    }

    /**
     * Ping an anchor in the background: a membership is "live" iff the anchor is
     * reachable AND holds our account record (resolve(username) == our account).
     * Enables `row` with `liveLabel` + `onLive` on success; greys it out on
     * failure. Shared by the restricted-host picker and the join preflight.
     */
    private fun pingAnchor(
        uri: String,
        username: String,
        acct: Account,
        row: TextView,
        liveLabel: String,
        onLive: () -> Unit,
    ) {
        thread {
            val ok = try {
                anchorResolve(uri, username) == acct.safetyNumber()
            } catch (e: Exception) {
                false
            }
            ui.post {
                if (ok) {
                    row.text = liveLabel
                    row.setTextColor(onAccent)
                    row.background = roundRect(accent, 14)
                    row.alpha = 1f
                    row.isEnabled = true
                    row.isClickable = true
                    row.setOnClickListener { onLive() }
                } else {
                    row.text = "✗ ${shortUri(uri)} — unreachable or no record"
                    row.alpha = 0.5f
                }
            }
        }
    }

    private fun startRestrictedHost(channel: String, posture: String, anchorUri: String, username: String) {
        toast("creating restricted chat…")
        thread {
            try {
                val port = ChatNet.allocLanPort()
                val c = TalkryptClient.host(ChatNet.lanBind(port), channel, posture, ChatNet.lanAdvertise(port))
                runCatching { c.presentAccount(account(), username) }
                runCatching { loadContacts(c) } // recognize saved contacts
                val members = c.restrictToAnchor(anchorUri)
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(invite), channel, Role.HOST, false, posture, "restricted", invite, if (useTor) invite else null, pendingTier, sn, now, now)
                    enterSession(meta, c, "registry-restricted — only the $members anchor member(s) can join")
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = "invite")
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) {
                ui.post { toast("restricted host failed: ${e.message}") }
            }
        }
    }

    // ---------- chat screen ----------
    private fun tierLabel(p: Persistence) =
        when (p) { Persistence.EPHEMERAL -> "ephemeral"; Persistence.ALWAYS_ON -> "always-on"; else -> "persistent" }

    /** Refresh the on-screen chat header (connection chip + details) in place —
     *  connection events must NOT rebuild the screen, that wipes the draft. */
    private fun updateChatHeader(lc: LiveChat) {
        val (cs, cc) = connInfo(lc)
        chatChip?.apply { text = "● $cs"; setTextColor(cc) }
        val memberStr = if (lc.roster.isNotEmpty()) "${lc.roster.size} members · " else ""
        chatDetail?.text = "  ·  ${memberStr}safety ${lc.meta.safety.take(11)} · ${tierLabel(lc.meta.persistence)}"
    }

    /** Render history entries not yet on screen (the initial replay, live events,
     *  and anything the service drained while the Activity was paused). All
     *  history-backed rendering funnels through here so [renderedCount] stays
     *  true; render-only extras (invite QR, action rows) don't count. */
    private fun renderNew(lc: LiveChat) {
        if (messages == null) return
        while (renderedCount < lc.history.size) {
            val m = lc.history[renderedCount++]
            when (m.kind) {
                MsgKind.MESSAGE -> addBubble(m.text, m.mine, sender = if (m.mine) null else m.display, marking = m.marking)
                MsgKind.SYSTEM, MsgKind.ACTION -> system(m.text)
            }
        }
    }

    private fun chatScreen(chatId: String): View {
        val lc = sessions.get(chatId) ?: return chatListScreen()
        sessions.setActive(chatId)
        // panel behind the system-bar insets so the header/input bar meet the
        // screen edges without a bg-colored seam; the message area paints bg.
        val root = column(panel)

        // header: back · title/subtitle · overflow. Heights pinned WRAP_CONTENT so
        // only the messages ScrollView (weight 1) takes the remaining space.
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(panel); setPadding(dp(8), dp(10), dp(12), dp(10))
        }
        header.addView(text("‹", 30f, fg).apply {
            contentDescription = "Back"
            minimumWidth = dp(48); minimumHeight = dp(48); gravity = Gravity.CENTER
            setPadding(dp(10), 0, dp(10), 0); setOnClickListener { setContentView(chatListScreen()) }
        })
        val titles = column(Color.TRANSPARENT)
        titles.addView(text(lc.meta.title, 17f, fg, bold = true))
        // Header subtitle: a colored connection-state chip + muted chat details.
        // Kept as fields so connection events can update them without a rebuild.
        val subRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; setPadding(0, dp(2), 0, 0) }
        chatChip = text("", 12f, muted, bold = true).also { subRow.addView(it) }
        chatDetail = text("", 12f, muted).also { subRow.addView(it) }
        titles.addView(subRow)
        updateChatHeader(lc)
        header.addView(titles, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        header.addView(text("⋯", 22f, muted).apply {
            contentDescription = "Chat menu"
            minimumWidth = dp(48); minimumHeight = dp(48); gravity = Gravity.CENTER
            setPadding(dp(10), dp(4), dp(8), dp(4)); setOnClickListener { chatRowMenu(lc) }
        })
        root.addView(header, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        // messages — the only weighted child. Polite live region so TalkBack
        // announces appended bubbles/system lines without stealing focus.
        val list = column(bg).apply {
            setPadding(dp(12), dp(12), dp(12), dp(12))
            accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        }
        messages = list
        val sv = ScrollView(this).apply { isFillViewport = true; setBackgroundColor(bg); addView(list) }
        scroll = sv
        root.addView(sv, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        // replay this chat's stored history into the view
        renderedCount = 0
        renderNew(lc)

        // input bar — pinned to the bottom
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(panel); setPadding(dp(12), dp(10), dp(12), dp(10))
        }
        // Restore any unsent draft; mirror edits into [drafts] so the text
        // survives screen swaps (connection events, back, process pauses).
        val input = inputField("Message").apply {
            background = roundRect(field, 24)
            setText(drafts[chatId] ?: "")
            addTextChangedListener(object : android.text.TextWatcher {
                override fun afterTextChanged(s: android.text.Editable?) { drafts[chatId] = s?.toString() ?: "" }
                override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
                override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
            })
        }
        bar.addView(input, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        val send = text("➤", 20f, onAccent, center = true).apply {
            contentDescription = "Send"
            background = circle(accent)
            gravity = Gravity.CENTER
        }
        send.setOnClickListener {
            val t = input.text.toString()
            // Only clear once the message is accepted — a failed/deferred send
            // must never eat the composed text.
            if (t.isNotEmpty() && sendMessage(chatId, t)) input.setText("")
        }
        bar.addView(send, LinearLayout.LayoutParams(dp(48), dp(48)).apply { leftMargin = dp(10) })
        root.addView(bar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        applyInsets(root)
        return root
    }

    // ---------- bubbles ----------
    private fun addBubble(body: String, mine: Boolean, sender: String? = null, marking: String? = null) {
        val list = messages ?: return
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = if (mine) Gravity.END else Gravity.START
        }
        val bubble = column(Color.TRANSPARENT).apply {
            background = bubbleBg(mine)
            setPadding(dp(14), dp(10), dp(14), dp(10))
        }
        if (!marking.isNullOrEmpty()) {
            bubble.addView(text(marking, 10f, amber, bold = true))
        }
        if (sender != null) bubble.addView(text(sender, 11f, accent, bold = true))
        bubble.addView(text(body, 15f, if (mine) onAccent else fg).apply {
            // cap long messages at ~76% of screen width so bubbles don't span edge-to-edge
            maxWidth = (resources.displayMetrics.widthPixels * 0.76f).toInt()
        })
        wrap.addView(bubble, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        list.addView(wrap, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        autoscroll()
    }

    private fun system(s: String) {
        val list = messages ?: return
        list.addView(text(s, 12f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10), bottom = dp(2)))
        autoscroll()
    }

    /** A tappable action row inside the message list (e.g. "Add as contact"). */
    private fun addAction(label: String, onClick: () -> Unit) {
        val list = messages ?: return
        val btn = pillButton(label, panel, accent, onClick).apply { minimumHeight = dp(44) }
        list.addView(btn, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6), bottom = dp(2)))
        autoscroll()
    }

    /** Scroll to the newest entry only if the view is already at (near) the
     *  bottom — never yank the screen away from someone reading history. */
    private fun autoscroll() {
        val sv = scroll ?: return
        val list = messages ?: return
        if (sv.scrollY + sv.height >= list.height - dp(80)) {
            sv.post { sv.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private fun bubbleBg(mine: Boolean) = GradientDrawable().apply {
        setColor(if (mine) accent else peerBubble)
        cornerRadius = dp(18).toFloat()
    }

    // ---------- engine actions (off the UI thread; the facade blocks) ----------
    private fun startHost(channel: String, posture: String, access: String = "open", tier: Persistence = Persistence.PERSISTENT_LOCAL) {
        toast("creating chat…")
        thread {
            try {
                // Bind to the LAN/hotspot address (not loopback) so the invite is
                // dialable from another device — required for QR/nearby joining.
                // Over Tor, all chats share one Arti client + state dir (see
                // ChatNet.sharedTorDir); the onion service is per-chat within it.
                // Nym multi-homes over Tor too, so it also uses the shared Tor dir.
                val torSub = if (useTor || useNym) "shared" else null
                val c = if (useNym) {
                    TalkryptClient.hostNym(channel, posture, ChatNet.sharedTorDir(this), ChatNet.nymMnemonic(this))
                } else if (useTor) {
                    TalkryptClient.hostTor(channel, posture, ChatNet.sharedTorDir(this))
                } else {
                    // Bind a free port (so multiple chats can host at once); advertise
                    // the address peers dial.
                    val port = ChatNet.allocLanPort()
                    TalkryptClient.host(ChatNet.lanBind(port), channel, posture, ChatNet.lanAdvertise(port))
                }
                runCatching { c.presentAccount(account(), null) }
                runCatching { loadContacts(c) } // recognize saved contacts
                runCatching { c.setAccessMode(access) }
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(
                        id = chatId(invite), title = channel, role = Role.HOST, group = false,
                        posture = posture, access = access, inviteUri = invite,
                        onion = if (useTor || useNym) invite else null, persistence = tier,
                        safety = sn, createdAt = now, lastActivityAt = now, torDir = torSub,
                        mixnet = useNym,
                    )
                    val lc = sessions.open(meta, c)
                    if (tier != Persistence.EPHEMERAL) runCatching { store.save(meta, lc.history) }
                    openChat(meta.id)
                    sysLine(meta.id, "hosting — share the invite to let a friend join:")
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = "invite")
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) { ui.post { toast("host failed: ${e.message}") } }
        }
    }

    // Entry from the Join button / deep link / nearby: surface the preflight so
    // the joiner picks which (live) membership to present before connecting.
    private fun startJoin(uri: String) {
        setContentView(joinPreflightScreen(uri))
    }

    /**
     * Join preflight: the same bound-anchor grey-out guard as restricted hosting,
     * but for the *joiner*. If a chat is registry-restricted you're admitted only
     * if your account is a member, so present a membership that's actually live.
     * A pseudonym fallback is always offered (won't pass a restricted gate).
     */
    private fun joinPreflightScreen(uri: String): View {
        backState = Back.LIST_CHILD
        val acct = account()
        val anchors = boundAnchors()
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text("Join chat", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("If this chat is registry-restricted, you're admitted only as a member. Present a live membership, or join as a pseudonym (open chats only).", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(18)),
        )
        if (anchors.isEmpty()) {
            col.addView(text("You have no registry memberships yet — register at an anchor to join restricted chats.", 13f, amber), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
        } else {
            col.addView(text("PRESENT A MEMBERSHIP", 12f, muted, bold = true))
            for ((anchorUri, username) in anchors) {
                val row = pillButton("checking ${shortUri(anchorUri)} …", panel, muted) { }
                row.isEnabled = false; row.alpha = 0.5f; row.isClickable = false
                col.addView(row, lp(MATCH_PARENT, dp(52), top = dp(8)))
                pingAnchor(anchorUri, username, acct, row, "Join as “$username@${shortUri(anchorUri)}”") {
                    doJoin(uri, username, presentAccount = true)
                }
            }
        }
        col.addView(text("— or —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20), bottom = dp(10)))
        col.addView(pillButton("Join with my account (no username)", panel, fg) {
            doJoin(uri, null, presentAccount = true)
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Join as pseudonym (unlinkable)", panel, fg) {
            doJoin(uri, null, presentAccount = false)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton("Back", panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun doJoin(uri: String, username: String?, presentAccount: Boolean) {
        // Route over Tor if the invite is an onion (decoded from the descriptor —
        // the `.onion` is inside the base32, not the URI text), OR the user asked.
        // Otherwise a pasted onion invite would be plain-TCP dialed and fail.
        val isOnion = runCatching { inviteIsOnion(uri) }.getOrDefault(false)
        // A nym-bearing invite is dialed through the mixnet (auto, like onion→Tor),
        // and the user can also opt in explicitly. joinNym picks the best endpoint
        // by preference and falls back to the onion if present.
        val isNymInvite = runCatching { inviteHasNym(uri) }.getOrDefault(false)
        val nym = useNym || isNymInvite
        val tor = useTor || isOnion
        val title = runCatching { inviteChannel(uri) }.getOrDefault("chat")
        val tier = pendingTier
        val torSub = if (tor || nym) "shared" else null
        // Show a connecting screen with live progress instead of a silent toast —
        // the first Tor/mixnet connect is slow and was previously opaque.
        setContentView(connectingScreen(title, tor || nym))
        startConnectingPoll(tor || nym)
        val gen = ++joinGen
        thread {
            try {
                val c = if (nym) TalkryptClient.joinNym(uri, ChatNet.sharedTorDir(this), ChatNet.nymMnemonic(this))
                        else if (tor) TalkryptClient.joinTor(uri, ChatNet.sharedTorDir(this))
                        else TalkryptClient.join(uri)
                val sn = c.safetyNumber()
                if (presentAccount) runCatching { c.presentAccount(account(), username) }
                runCatching { loadContacts(c) } // recognize saved contacts
                ui.post {
                    if (gen != joinGen) return@post // cancelled — drop the client quietly
                    connecting = false
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(
                        id = chatId(uri), title = title, role = Role.JOIN, group = false,
                        posture = "", access = "open", inviteUri = uri,
                        onion = if (isOnion || nym) uri else null, persistence = tier,
                        safety = sn, createdAt = now, lastActivityAt = now, torDir = torSub,
                        mixnet = nym,
                    )
                    val lc = sessions.open(meta, c)
                    if (tier != Persistence.EPHEMERAL) runCatching { store.save(meta, lc.history) }
                    openChat(meta.id)
                    sysLine(meta.id, if (presentAccount) "joined" + (username?.let { " as $it" } ?: "") else "joined as pseudonym")
                }
            } catch (e: Exception) {
                ui.post {
                    if (gen != joinGen) return@post // cancelled — nothing to report
                    connecting = false
                    connectingLabel?.apply { text = "failed: ${ChatNet.friendlyError(e.message)}"; setTextColor(Tk.danger) }
                    toast("join failed")
                }
            }
        }
    }

    private var connecting = false
    private var onConnecting = false // the connecting screen is on top
    // Bumped whenever a join starts or is cancelled; a finishing join thread
    // whose generation is stale must NOT hijack whatever screen the user is on.
    private var joinGen = 0

    /** Invalidate the in-flight join so its thread's ui.post is dropped and the
     *  bootstrap poll stops. Shared by the Cancel button and system-back. */
    private fun cancelJoin() { connecting = false; onConnecting = false; joinGen++ }
    private var connectingLabel: TextView? = null

    /** A connecting screen with a live status line (Tor bootstrap % → handshake). */
    private fun connectingScreen(title: String, tor: Boolean): View {
        backState = Back.LIST_CHILD
        onConnecting = true
        val col = column(bg).apply { setPadding(dp(24), dp(64), dp(24), dp(24)) }
        col.addView(text("Connecting", 26f, fg, bold = true, center = true))
        col.addView(text(title, 16f, muted, center = true).also { it.setPadding(0, dp(8), 0, dp(28)) })
        val lbl = text(if (tor) "Bootstrapping Tor…" else "Connecting…", 16f, accent, center = true)
        connectingLabel = lbl
        col.addView(lbl)
        if (tor) col.addView(
            text("First Tor connect is slow; later ones are instant.", 12f, muted, center = true)
                .also { it.setPadding(0, dp(16), 0, 0) },
        )
        col.addView(pillButton("Cancel", panel, fg) {
            cancelJoin(); setContentView(chatListScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(36)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    /** Poll the shared Tor client's bootstrap percent and update the label until
     *  the connect finishes (the join thread clears `connecting`). */
    private fun startConnectingPoll(tor: Boolean) {
        if (!tor) return
        connecting = true
        ui.postDelayed(object : Runnable {
            override fun run() {
                if (!connecting) return
                val pct = runCatching { torBootstrapPercent().toInt() }.getOrDefault(0)
                connectingLabel?.text =
                    if (pct < 100) "Bootstrapping Tor… $pct%" else "Building circuit + handshaking…"
                ui.postDelayed(this, 300)
            }
        }, 300)
    }

    /** Re-establish a saved chat's connection (Phase 2a). Reuses its onion dir so
     *  a Tor host comes back on the SAME .onion. No-op if already connected. */
    private fun reconnect(id: String) {
        val lc = sessions.get(id) ?: return
        if (lc.client != null) return
        val m = lc.meta
        val plan = reconnectPlan(m)
        if (plan == ReconnectPlan.IMPOSSIBLE) { toast("can't reconnect — no saved invite"); return }
        val net = when (plan) {
            ReconnectPlan.HOST_NYM, ReconnectPlan.JOIN_NYM -> "Nym"
            ReconnectPlan.HOST_TOR, ReconnectPlan.JOIN_TOR -> "Tor"
            else -> "LAN"
        }
        sysLine(id, "reconnecting over $net…"); toast("reconnecting over $net…")
        thread {
            try {
                // Shared with ChatService — one place builds a client from a meta.
                val c = ChatNet.connect(this, m)
                val freshInvite = if (m.role == Role.HOST) runCatching { c.inviteUri() }.getOrNull() else null
                ui.post {
                    lc.client = c
                    // A re-hosted LAN chat gets a fresh invite; keep the same chatId.
                    if (freshInvite != null) lc.meta = lc.meta.copy(inviteUri = freshInvite)
                    sysLine(id, "reconnected over $net")
                    when {
                        activeId == id -> setContentView(chatScreen(id))
                        activeId == null && backState == Back.HOME -> setContentView(chatListScreen())
                        else -> {} // user is on some other screen — don't yank it away
                    }
                }
            } catch (e: Exception) { ui.post { sysLine(id, "reconnect failed ($net): ${ChatNet.friendlyError(e.message)}"); toast("reconnect failed") } }
        }
    }

    /** Try to send; returns whether the message was accepted. When it isn't
     *  (no client yet), the caller keeps the composed text in the input. */
    private fun sendMessage(chatId: String, t: String): Boolean {
        val lc = sessions.get(chatId) ?: return false
        val c = lc.client ?: run { reconnect(chatId); toast("reconnecting — your text is kept, try again in a moment"); return false }
        val msg = ChatMsg(MsgKind.MESSAGE, null, null, mine = true, text = t, marking = null, ts = System.currentTimeMillis())
        lc.history.add(msg); sessions.touch(chatId, msg.ts)
        if (activeId == chatId) renderNew(lc)
        scheduleSave(chatId)
        thread { runCatching { c.send(t) }.onFailure { ui.post { toast("send failed") } } }
        return true
    }

    /** One loop drains every connected chat; events route to their room. The
     *  active chat renders live, others accrue an unread badge. Started in onCreate. */
    /** Foreground drain+render loop. Gated on [SessionHub.foreground] so it stops
     *  when the Activity pauses (the service drains in the background) and a
     *  single loop runs at a time. */
    private fun pollAll() {
        if (polling) return
        polling = true
        ui.postDelayed(object : Runnable {
            override fun run() {
                if (!SessionHub.foreground) { polling = false; return }
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

    /** Record the event into the shared model ([applyEvent]) then render it if
     *  its chat is on screen. The recording is shared with the headless service;
     *  only the rendering is Activity-specific. */
    private fun handleEvent(id: String, lc: LiveChat, e: FfiEvent) {
        val msg = applyEvent(sessions, id, lc, e)
        if (activeId == id) {
            renderNew(lc)
            // Connection changes refresh the header chip in place — a rebuild
            // here used to wipe the user's half-typed draft on every peer flap.
            if (e is FfiEvent.Connected || e is FfiEvent.Disconnected) updateChatHeader(lc)
            if (e is FfiEvent.Identity && !e.contact) {
                val who = lc.roster[e.accountFingerprint]?.display ?: e.accountFingerprint.take(8)
                val fp = e.accountFingerprint; val name = e.username
                addAction("Add “$who” as a contact") {
                    val cl = lc.client
                    if (cl != null && cl.addSeenContact(fp, name.ifEmpty { null }, false)) { saveContacts(cl); system("added contact $who") }
                    else toast("could not add (account not seen)")
                }
            }
        } else refreshListRowIfVisible()
        scheduleSave(id)
    }

    /** Append a system line to a chat; render if it's the on-screen chat. */
    private fun sysLine(id: String, s: String) {
        sessions.recordIncoming(id, ChatMsg(MsgKind.SYSTEM, null, null, false, s, null, System.currentTimeMillis()))
        if (activeId == id) sessions.get(id)?.let { renderNew(it) }
        scheduleSave(id)
    }

    /** Persist a kept chat shortly after activity (debounced); ephemeral chats skip disk. */
    private fun scheduleSave(id: String) {
        val lc = sessions.get(id) ?: return
        if (lc.meta.persistence == Persistence.EPHEMERAL) return
        if (!pendingSaves.add(id)) return
        ui.postDelayed({
            pendingSaves.remove(id)
            sessions.get(id)?.let { runCatching { store.save(it.meta, it.history) } }
        }, 1500)
    }

    /** Redraw the chat list if it's the visible screen (to refresh unread/preview).
     *  Guarded so it never replaces a subscreen the user is on, and debounced so
     *  an event burst rebuilds once, not once per event. */
    private var listRefreshQueued = false
    private fun refreshListRowIfVisible() {
        if (activeId != null || backState != Back.HOME) return
        if (listRefreshQueued) return
        listRefreshQueued = true
        ui.postDelayed({
            listRefreshQueued = false
            if (activeId == null && backState == Back.HOME) setContentView(chatListScreen())
        }, 300)
    }

    // ---------- view helpers ----------
    // The pre-30 inset getters are deprecated; suppressed at function level so
    // the annotation isn't on a block-level expression (which parses ambiguously).
    @Suppress("DEPRECATION")
    private fun applyInsets(v: View) {
        v.setOnApplyWindowInsetsListener { view, insets ->
            val top: Int
            val bottom: Int
            if (Build.VERSION.SDK_INT >= 30) {
                val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                top = b.top; bottom = b.bottom
            } else {
                top = insets.systemWindowInsetTop
                bottom = insets.systemWindowInsetBottom
            }
            view.setPadding(view.paddingLeft, top, view.paddingRight, bottom)
            insets
        }
        v.requestApplyInsets()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun roundRect(color: Int, radius: Int) = GradientDrawable().apply {
        setColor(color); cornerRadius = dp(radius).toFloat()
    }

    /** A dark-themed dropdown: light text on a dark field + dark popup. The stock
     *  `ArrayAdapter` colors items with the default theme's (dark) text, which is
     *  unreadable on talkrypt's dark background — so set the text color explicitly
     *  for both the collapsed selection and the dropdown rows. */
    private fun darkSpinner(items: List<String>): Spinner {
        val sp = Spinner(this)
        sp.background = roundRect(field, 14)
        sp.setPopupBackgroundDrawable(roundRect(panel, 12))
        val adapter = object : ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, items) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View =
                (super.getView(position, convertView, parent) as TextView).apply {
                    setTextColor(fg)
                    // Match the input fields' padding so the collapsed selection
                    // isn't cramped against the rounded field edges.
                    setPadding(dp(16), dp(14), dp(16), dp(14))
                }

            override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View =
                (super.getDropDownView(position, convertView, parent) as TextView).apply {
                    setTextColor(fg)
                    // transparent rows — the popup itself is the panel roundRect,
                    // so opaque row backgrounds would square off its corners
                    setBackgroundColor(Color.TRANSPARENT)
                    setPadding(dp(16), dp(14), dp(16), dp(14))
                }
        }
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        sp.adapter = adapter
        return sp
    }

    private fun circle(color: Int) = GradientDrawable().apply {
        shape = GradientDrawable.OVAL; setColor(color)
    }

    private fun column(color: Int) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        if (color != Color.TRANSPARENT) setBackgroundColor(color)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
    }

    private fun lp(w: Int, h: Int, top: Int = 0, bottom: Int = 0) =
        LinearLayout.LayoutParams(w, h).apply { topMargin = top; bottomMargin = bottom }

    private fun text(s: String, size: Float, color: Int, bold: Boolean = false, center: Boolean = false) =
        TextView(this).apply {
            text = s; textSize = size; setTextColor(color)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            if (center) gravity = Gravity.CENTER_HORIZONTAL
        }

    /** Section/field label. Pass the field as [target] so screen readers link
     *  the visible label to it (labelFor needs the target to carry an id). */
    private fun label(s: String, target: View? = null) = text(s, 12f, muted, bold = true).apply {
        if (target != null) {
            if (target.id == View.NO_ID) target.id = View.generateViewId()
            labelFor = target.id
        }
    }

    private fun inputField(hint: String) = EditText(this).apply {
        this.hint = hint; setTextColor(fg); setHintTextColor(Tk.hint)
        background = roundRect(field, 14); setPadding(dp(16), dp(14), dp(16), dp(14)); textSize = 15f
    }

    private fun pillButton(label: String, bgColor: Int, textColor: Int, onClick: () -> Unit) =
        text(label, 16f, textColor, bold = true, center = true).apply {
            gravity = Gravity.CENTER
            background = roundRect(bgColor, 14)
            isClickable = true
            // Rows are WRAP_CONTENT + this minimum, so labels that wrap at large
            // font scale grow the pill instead of clipping (48dp a11y floor).
            minimumHeight = dp(50)
            setPadding(dp(16), dp(12), dp(16), dp(12))
            setOnClickListener { onClick() }
        }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()

    /** Show an invite as a scannable QR in a dialog. A dialog (not injected
     *  bubbles) survives the chat-screen rebuilds a reconnect triggers. */
    private fun showInviteQr(invite: String) {
        val bmp = Qr.bitmap(invite)
        val box = column(Color.TRANSPARENT).apply { setPadding(dp(20), dp(20), dp(20), dp(8)); gravity = Gravity.CENTER_HORIZONTAL }
        if (bmp != null) {
            val side = (resources.displayMetrics.widthPixels * 0.6f).toInt()
            box.addView(ImageView(this).apply { setImageBitmap(bmp); setBackgroundColor(Color.WHITE); setPadding(dp(10), dp(10), dp(10), dp(10)) },
                LinearLayout.LayoutParams(side, side))
        }
        box.addView(text(invite, 12f, muted, center = true).also { it.setPadding(0, dp(14), 0, 0) })
        android.app.AlertDialog.Builder(this)
            .setTitle("Invite QR")
            .setView(box)
            .setPositiveButton("Share") { _, _ -> shareText(invite) }
            .setNegativeButton("Close", null)
            .show()
    }

    /** Confirmation gate for irreversible actions (delete/unlink). */
    private fun confirm(title: String, detail: String, verb: String, action: () -> Unit) {
        android.app.AlertDialog.Builder(this)
            .setTitle(title).setMessage(detail)
            .setPositiveButton(verb) { _, _ -> action() }
            .setNegativeButton("Cancel", null)
            .show()
            .apply { getButton(android.app.AlertDialog.BUTTON_POSITIVE)?.setTextColor(Tk.danger) }
    }
}
