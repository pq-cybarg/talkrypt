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
import uniffi.talkrypt_ffi.AdvertisePolicy
import uniffi.talkrypt_ffi.AnchorNode
import uniffi.talkrypt_ffi.FfiBeacon
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
    // SUB-SPEC A / #68: the active beacon (radio backend + FFI handle), if running.
    private var beaconBackend: RadioBeacon? = null
    private var beacon: FfiBeacon? = null
    // Mesh messaging over a LoRa BLE node (Meshtastic/Meshcore backend + FFI handle + scan), if running.
    private var meshBackend: MeshRadioBackend? = null
    private var meshNode: uniffi.talkrypt_ffi.FfiMeshNode? = null
    private var meshScan: android.bluetooth.le.ScanCallback? = null

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
    private var pendingBle: (() -> Unit)? = null
    /// Guard against double-submit of a host/join action: a second tap while the
    /// first is still bootstrapping would spin up a duplicate session/listener.
    private var inFlight = false

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
                toast(Loc.s(R.string.m1_opening_invite))
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
        private const val REQ_BLE = 0x424C // "BL" — BLE advertise/scan/connect for the beacon
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
                if (!uri.startsWith("talkrypt://")) { toast(Loc.s(R.string.m1_not_a_talkrypt_qr)); return }
                val isLink = runCatching { inviteChannel(uri) == "#link" }.getOrDefault(false)
                if (isLink) setContentView(acceptLinkConfirmScreen(uri)) else { toast(Loc.s(R.string.m1_opening_invite)); startJoin(uri) }
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
                            { toast(Loc.s(R.string.m1_nym_credential_imported)) },
                            { toast(Loc.s(R.string.m1_import_failed, ChatNet.friendlyError(it.message))) },
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

        col.addView(text(Loc.s(R.string.m1_new_chat), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })

        val channel = inputField("#general")
        col.addView(label(Loc.s(R.string.m1_channel), channel))
        col.addView(channel, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))

        val posture = darkSpinner(listOf("pq-pure", "hybrid", "pq-pure-compact"))
        col.addView(label(Loc.s(R.string.m1_posture), posture).also { it.setPadding(0, dp(20), 0, dp(8)) })
        col.addView(posture, lp(MATCH_PARENT, WRAP_CONTENT))

        val access = darkSpinner(listOf("open", "contacts", "friends"))
        col.addView(label(Loc.s(R.string.m1_access), access).also { it.setPadding(0, dp(20), 0, dp(8)) })
        col.addView(access, lp(MATCH_PARENT, WRAP_CONTENT))

        // SUB-SPEC A §5: the chat's baseline for how look-alike (homoglyph) names
        // are shown — travels in the invite so joiners inherit it (any viewer may
        // tighten it locally later, never loosen). Uses the a11y 2-arg label form.
        val namePolicy = darkSpinner(listOf(Loc.s(R.string.m1_name_display_signal_style), Loc.s(R.string.m1_name_display_warn), Loc.s(R.string.m1_name_display_suppress)))
        col.addView(label(Loc.s(R.string.m1_name_display), namePolicy).also { it.setPadding(0, dp(20), 0, dp(8)) })
        col.addView(namePolicy, lp(MATCH_PARENT, WRAP_CONTENT))

        val persistence = darkSpinner(listOf(Loc.s(R.string.m1_persistence_ephemeral), Loc.s(R.string.m1_persistence_persistent), Loc.s(R.string.m1_persistence_always_on)))
        col.addView(label(Loc.s(R.string.m1_persistence), persistence).also { it.setPadding(0, dp(20), 0, dp(8)) })
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
            text = Loc.s(R.string.m1_route_over_tor)
            setTextColor(muted)
            isChecked = useTor
            setOnCheckedChangeListener { _, checked -> useTor = checked }
        }
        col.addView(torBox, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16)))

        // Optional Nym mixnet leg: multi-homes the invite over Tor+Nym for
        // traffic-analysis resistance. Only functional if the .so was built with
        // --features nym (else host/join over Nym returns a clear error).
        val nymBox = CheckBox(this).apply {
            text = Loc.s(R.string.m1_route_over_nym)
            setTextColor(muted)
            isChecked = useNym
            setOnCheckedChangeListener { _, checked -> useNym = checked }
        }
        col.addView(nymBox, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
        col.addView(text(Loc.s(R.string.m1_paid_nym_bandwidth), 13f, muted)
            .also { it.setPadding(0, dp(4), 0, 0) })

        col.addView(pillButton(Loc.s(R.string.m1_host_a_chat), accent, onAccent) {
            startHost(
                channel.text.toString().ifBlank { "#general" },
                posture.selectedItem.toString(),
                access.selectedItem.toString(),
                tierOf(persistence),
                when (namePolicy.selectedItemPosition) { 1 -> "warn"; 2 -> "suppress"; else -> "" },
            )
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(32)))
        col.addView(pillButton(Loc.s(R.string.m1_registry_restricted_chat), panel, fg) {
            pendingTier = tierOf(persistence)
            setContentView(restrictedHostScreen(channel.text.toString().ifBlank { "#general" }, posture.selectedItem.toString()))
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(text(Loc.s(R.string.m1_or_join), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(28), bottom = dp(12)))
        val invite = inputField(Loc.s(R.string.m1_join_invite_hint))
        col.addView(invite, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton(Loc.s(R.string.m1_join), panel, fg) {
            val uri = invite.text.toString().trim()
            if (uri.startsWith("talkrypt://")) { pendingTier = tierOf(persistence); startJoin(uri) } else toast(Loc.s(R.string.m1_paste_invite))
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(12)))
        col.addView(pillButton(Loc.s(R.string.m1_scan_qr), accent, onAccent) {
            pendingTier = tierOf(persistence)
            launchScanner()
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        // In-person: find a nearby host, or send this very app P2P.
        col.addView(text(Loc.s(R.string.m1_in_person), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(28), bottom = dp(12)))
        col.addView(pillButton(Loc.s(R.string.m1_find_nearby_host), accent, onAccent) {
            findNearby()
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton(Loc.s(R.string.m1_share_app), panel, fg) {
            shareApp()
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(12)))
        col.addView(pillButton(Loc.s(R.string.m1_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))

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
        val tierLine = text(Loc.s(R.string.m1_tier_line_placeholder), 12f, accent)
        titleCol.addView(tierLine)
        thread {
            val t = runCatching { CustodyBridge.detectTier().name }.getOrDefault("UNKNOWN")
            ui.post { tierLine.text = Loc.s(R.string.m1_tier_line, t) }
        }
        headRow.addView(titleCol, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        headRow.addView(text("⋯", 26f, muted).apply {
            contentDescription = Loc.s(R.string.m1_more)
            minimumWidth = dp(48); minimumHeight = dp(48); gravity = Gravity.CENTER
            setPaddingRelative(dp(12), dp(4), dp(8), dp(4)); setOnClickListener { setContentView(utilitiesScreen()) }
        })
        col.addView(headRow, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))

        col.addView(pillButton(Loc.s(R.string.m1_new_chat_button), accent, onAccent) { setContentView(newChatScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(8)))

        val chats = sessions.ordered()
        if (chats.isEmpty()) {
            col.addView(text(Loc.s(R.string.m1_no_chats_yet), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(40)))
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
        row.addView(glyph, LinearLayout.LayoutParams(dp(44), dp(44)).apply { marginEnd = dp(12) })

        val mid = column(Color.TRANSPARENT)
        mid.addView(text(m.title, 16f, fg, bold = true))
        val last = lc.history.lastOrNull { it.kind == MsgKind.MESSAGE }
        val preview = when {
            last != null && last.mine -> Loc.s(R.string.m1_preview_you, last.text)
            last != null -> Loc.s(R.string.m1_preview_sender, last.display ?: last.sender?.take(8) ?: "?", last.text)
            else -> if (m.role == Role.HOST) Loc.s(R.string.m1_hosting) else Loc.s(R.string.m1_joined)
        }
        val members = lc.roster.size
        val sub = if (m.group && members > 0) Loc.s(R.string.m1_preview_members, preview, members) else preview
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
        right.addView(text(Loc.s(R.string.m1_conn_dot, cs), 10f, cc), lp(WRAP_CONTENT, WRAP_CONTENT, top = dp(4)))
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
            lc.client == null -> Loc.s(R.string.m1_offline) to muted
            online > 0 -> (if (online == 1) Loc.s(R.string.m1_online) else Loc.s(R.string.m1_online_count, online)) to accent
            lc.meta.role == Role.HOST -> Loc.s(R.string.m1_hosting) to amber
            else -> Loc.s(R.string.m1_connecting) to amber
        }
    }

    private fun relTime(ts: Long): String {
        val d = System.currentTimeMillis() - ts
        return when {
            d < 60_000 -> Loc.s(R.string.m1_time_now)
            d < 3_600_000 -> Loc.s(R.string.m1_time_minutes, d / 60_000)
            d < 86_400_000 -> Loc.s(R.string.m1_time_hours, d / 3_600_000)
            else -> Loc.s(R.string.m1_time_days, d / 86_400_000)
        }
    }

    private fun chatRowMenu(lc: LiveChat) {
        val id = lc.meta.id
        val connected = lc.client != null
        val beaconOn = beacon != null
        val meshOn = meshBackend != null
        val items = buildList {
            add("Manage callsigns")
            add(if (beaconOn) "Stop nearby beacon" else "Beacon nearby (BLE + Wi-Fi)")
            if (beaconOn) add("Beacon self-test (spoof)")
            if (meshOn) {
                add("Stop mesh (LoRa)")
            } else {
                add("Mesh over LoRa (Meshtastic BLE)")
                add("Mesh over LoRa (Meshcore BLE)")
            }
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
                    "Manage callsigns" -> setContentView(nameBookScreen(id))
                    "Beacon nearby (BLE + Wi-Fi)" -> startBeacon(id)
                    "Stop nearby beacon" -> stopBeacon(id)
                    "Beacon self-test (spoof)" -> beaconSpoofSelfTest(id)
                    "Mesh over LoRa (Meshtastic BLE)" -> startMesh(id, MeshKind.MESHTASTIC)
                    "Mesh over LoRa (Meshcore BLE)" -> startMesh(id, MeshKind.MESHCORE)
                    "Stop mesh (LoRa)" -> stopMesh(id)
                    "Re-share invite" -> lc.meta.inviteUri?.let { shareText(it) } ?: toast(Loc.s(R.string.m1_no_invite))
                    "Show invite QR" -> lc.meta.inviteUri?.let { showInviteQr(it) }
                    "Safety number (verify)" -> {
                        android.app.AlertDialog.Builder(this)
                            .setTitle(Loc.s(R.string.m1_safety_number_title))
                            .setMessage(Loc.s(R.string.m1_safety_number_body, lc.meta.safety))
                            .setPositiveButton(Loc.s(R.string.m1_copy)) { _, _ ->
                                val cm = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                                cm.setPrimaryClip(android.content.ClipData.newPlainText("talkrypt safety number", lc.meta.safety))
                                toast(Loc.s(R.string.m1_copied))
                            }
                            .setNegativeButton(Loc.s(R.string.m1_close), null)
                            .show()
                    }
                    "Reconnect" -> reconnect(id)
                    "Leave (disconnect, keep history)" -> { sessions.disconnect(id); setContentView(chatListScreen()) }
                    "Delete (erase)" -> confirm(Loc.s(R.string.m2_delete_chat_title, lc.meta.title), Loc.s(R.string.m2_delete_chat_body), Loc.s(R.string.m2_delete)) {
                        sessions.disconnect(id); sessions.remove(id); drafts.remove(id); runCatching { store.delete(id) }; setContentView(chatListScreen())
                    }
                }
            }.show()
    }

    /** SUB-SPEC A / #68: start the pre-session CQ beacon over BLE. Core seals THIS
     *  chat's beacon under the chat root and hands the opaque blob to the BLE backend
     *  ([BleBeaconBackend.advertise]); the scan side reads nearby beacons and feeds
     *  them back via `deliverBeacon`, so an invite-holder resolves them into a
     *  `BeaconSeen` event. One active beacon at a time (matches the single-active-chat
     *  UI); requires the BLE permissions the app already requests for nearby discovery. */
    private fun startBeacon(id: String) {
        val c = sessions.get(id)?.client ?: run { toast(Loc.s(R.string.m2_connect_first)); return }
        stopBeacon(id) // replace any prior beacon
        // Only advertise/scan once BLE permission is actually granted (deferred if
        // the user is prompted) — otherwise the first tap would silently no-op.
        ensureBlePermissions {
            // Both radios at once (Rust MultiBeacon's Kotlin peer): BLE short-range +
            // Wi-Fi/NSD for larger payloads/range. Each is best-effort; a dead radio is fine.
            val backend = MultiLocalBeacon(listOf(BleBeaconBackend(this), WifiBeaconBackend(this)))
            val fb = c.startLocalPresence(backend, AdvertisePolicy.FULL)
            // Push each scanned opaque blob into core; a match for our invite -> BeaconSeen.
            backend.startScanning({ blob, src -> runCatching { fb.deliverBeacon(blob, src) } },
                { msg -> ui.post { sysLine(id, Loc.s(R.string.m2_beacon_msg, msg)) } })
            beaconBackend = backend
            beacon = fb
            sysLine(id, Loc.s(R.string.m2_beaconing_nearby))
        }
    }

    private fun stopBeacon(id: String) {
        beacon?.let { runCatching { it.close() } }   // stops core's advertise/scan task
        beaconBackend?.let { runCatching { it.stop() } }
        if (beacon != null) sysLine(id, Loc.s(R.string.m2_nearby_beacon_stopped))
        beacon = null
        beaconBackend = null
    }

    /** Which LoRa mesh firmware the node runs — selects the BLE service to scan for
     *  and the backend to build. */
    private enum class MeshKind(
        val label: String,
        val service: java.util.UUID,
        val make: (android.content.Context, android.bluetooth.BluetoothDevice) -> MeshRadioBackend,
    ) {
        MESHTASTIC("Meshtastic", MeshtasticBleBackend.SERVICE, ::MeshtasticBleBackend),
        MESHCORE("Meshcore", MeshcoreBleBackend.SERVICE, ::MeshcoreBleBackend),
    }

    /** Carry this chat's messages over a LoRa node reached by BLE (#68 mesh messaging).
     *  Scans for a node advertising the chosen firmware's GATT service, links it via the
     *  matching [MeshRadioBackend], and calls `startMeshMessaging` so outbound group frames
     *  also ride LoRa and inbound ones are fed back through `deliverPacket`. Establish the
     *  chat over the primary transport first; the mesh is an additional broadcast path.
     *  On-device only (the emulator has no real BLE). */
    @android.annotation.SuppressLint("MissingPermission")
    private fun startMesh(id: String, kind: MeshKind) {
        val c = sessions.get(id)?.client ?: run { toast(Loc.s(R.string.m2_connect_first)); return }
        stopMesh(id)
        // Scan only after BLE permission is granted (deferred if prompted), so the
        // first mesh tap can't silently fail.
        ensureBlePermissions {
        val mgr = getSystemService(android.bluetooth.BluetoothManager::class.java)
        val scanner = mgr?.adapter?.bluetoothLeScanner ?: run { toast(Loc.s(R.string.m2_no_ble_scanner)); return@ensureBlePermissions }
        val filter = android.bluetooth.le.ScanFilter.Builder()
            .setServiceUuid(android.os.ParcelUuid(kind.service)).build()
        val settings = android.bluetooth.le.ScanSettings.Builder()
            .setScanMode(android.bluetooth.le.ScanSettings.SCAN_MODE_LOW_LATENCY).build()
        val cb = object : android.bluetooth.le.ScanCallback() {
            override fun onScanResult(type: Int, result: android.bluetooth.le.ScanResult?) {
                val dev = result?.device ?: return
                runCatching { scanner.stopScan(this) }
                meshScan = null
                val backend = kind.make(this@MainActivity, dev)
                val fmn = c.startMeshMessaging(backend, 0.toUByte()) // mesh channel 0
                backend.startReceiving { ch, p, from -> runCatching { fmn.deliverPacket(ch, p, from) } }
                meshBackend = backend
                meshNode = fmn
                ui.post { sysLine(id, Loc.s(R.string.m2_mesh_linked, kind.label)) }
            }
            override fun onScanFailed(errorCode: Int) {
                ui.post { sysLine(id, Loc.s(R.string.m2_mesh_scan_failed, errorCode)) }
            }
        }
        meshScan = cb
        try {
            scanner.startScan(listOf(filter), settings, cb)
            sysLine(id, Loc.s(R.string.m2_mesh_looking, kind.label))
        } catch (e: SecurityException) {
            toast(Loc.s(R.string.m2_ble_scan_denied))
        }
        } // ensureBlePermissions
    }

    private fun stopMesh(id: String) {
        meshScan?.let { cb ->
            runCatching {
                getSystemService(android.bluetooth.BluetoothManager::class.java)
                    ?.adapter?.bluetoothLeScanner?.stopScan(cb)
            }
        }
        meshNode?.let { runCatching { it.close() } } // stops core's mesh advertise/scan task
        meshBackend?.let { runCatching { it.stop() } }
        if (meshBackend != null) sysLine(id, Loc.s(R.string.m2_mesh_stopped))
        meshScan = null
        meshNode = null
        meshBackend = null
    }

    /** Emulator/QEMU spoof self-test (no real radio): feed the exact opaque blob core
     *  asked the backend to advertise straight back through `deliverBeacon`, exercising
     *  the full core round-trip (seal -> advertise -> open -> `Event::BeaconSeen`). On
     *  real hardware the BLE scan path delivers this over the air instead. */
    private fun beaconSpoofSelfTest(id: String) {
        val fb = beacon ?: run { toast(Loc.s(R.string.m2_start_beacon_first)); return }
        val blob = beaconBackend?.lastAdvertised()
            ?: run { toast(Loc.s(R.string.m2_no_blob_yet)); return }
        runCatching { fb.deliverBeacon(blob, "spoof-self") }
        sysLine(id, Loc.s(R.string.m2_beacon_selftest))
    }

    /** Request the BLE runtime permissions (API 31+) the beacon/nearby features need. */
    /** Ensure BLE advertise/scan/connect permissions, THEN run `onGranted`. If a
     *  grant is needed we stash the action and resume it from
     *  `onRequestPermissionsResult` (REQ_BLE) — previously the caller raced the
     *  dialog and the first beacon/mesh tap silently failed (there was no handler
     *  for the grant at all). On <31 the runtime perms don't exist, so run now. */
    private fun ensureBlePermissions(onGranted: () -> Unit) {
        if (Build.VERSION.SDK_INT < 31) {
            onGranted()
            return
        }
        val perms = arrayOf(
            android.Manifest.permission.BLUETOOTH_ADVERTISE,
            android.Manifest.permission.BLUETOOTH_SCAN,
            android.Manifest.permission.BLUETOOTH_CONNECT,
        ).filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (perms.isEmpty()) {
            onGranted()
        } else {
            pendingBle = onGranted
            runCatching { requestPermissions(perms.toTypedArray(), REQ_BLE) }
        }
    }

    /** SUB-SPEC A: manage your self-declared callsigns for this chat — a name book
     *  (add / switch / remove), the CQ cadence toggles (periodic + on-message name-id),
     *  a viewer name-trust control, and a roster view surfacing each peer's tier badge
     *  and always-available safety number. Reached from the chat overflow menu. */
    private fun nameBookScreen(chatId: String): View {
        val lc = sessions.get(chatId) ?: return chatListScreen()
        val c = lc.client
        val col = column(bg).apply { setPadding(dp(20), dp(20), dp(20), dp(20)) }
        col.addView(text(Loc.s(R.string.m2_callsigns), 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(4)) })
        col.addView(text(Loc.s(R.string.m2_callsigns_desc), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(12)))

        if (c == null) {
            col.addView(text(Loc.s(R.string.m2_connect_to_manage_names), 14f, muted), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
            col.addView(pillButton(Loc.s(R.string.m2_back), panel, fg) { setContentView(chatScreen(chatId)) }, lp(MATCH_PARENT, dp(50), top = dp(20)))
            return ScrollView(this).apply { setBackgroundColor(bg); addView(col); applyInsets(this) }
        }

        // ----- your saved names -----
        col.addView(label(Loc.s(R.string.m2_your_names)).also { it.setPadding(0, dp(12), 0, dp(8)) })
        val names = runCatching { c.listNames() }.getOrDefault(emptyList())
        val active = runCatching { c.leadingNameId() }.getOrDefault("")
        if (names.isEmpty()) {
            col.addView(text(Loc.s(R.string.m2_none_yet_add), 13f, muted), lp(MATCH_PARENT, WRAP_CONTENT))
        }
        for (n in names) {
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL }
            val badge = if (n.linked) "🔗 " else ""
            val star = if (n.id == active) "★ " else ""
            row.addView(text("$star$badge${n.label}", 16f, if (n.id == active) accent else fg), LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
            if (n.id != active) row.addView(pillButton(Loc.s(R.string.m2_use), accent, Color.WHITE) {
                thread { val ok = runCatching { c.useName(n.id) }.getOrDefault(false)
                    ui.post { toast(if (ok) Loc.s(R.string.m2_calling_as, n.label) else Loc.s(R.string.m2_failed)); setContentView(nameBookScreen(chatId)) } }
            }.apply { setPadding(dp(16), dp(8), dp(16), dp(8)) }, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply { marginEnd = dp(8) })
            row.addView(pillButton("✕", panel, muted) {
                c.removeName(n.id); toast(Loc.s(R.string.m2_removed)); setContentView(nameBookScreen(chatId))
            }.apply { setPadding(dp(14), dp(8), dp(14), dp(8)) }, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
            col.addView(row, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
        }

        // ----- add a name -----
        val add = inputField(Loc.s(R.string.m2_new_callsign))
        col.addView(add, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(14)))
        col.addView(pillButton(Loc.s(R.string.m2_save_to_name_book), panel, fg) {
            val v = add.text.toString().trim()
            if (v.isNotEmpty()) { c.addBareName(v, v); add.setText(""); setContentView(nameBookScreen(chatId)) }
        }, lp(MATCH_PARENT, dp(48), top = dp(8)))
        col.addView(pillButton(Loc.s(R.string.m2_set_announce_now), accent, Color.WHITE) {
            val v = add.text.toString().trim()
            if (v.isNotEmpty()) { c.setLeadingName(v); thread { runCatching { c.announcePresence() } }
                add.setText(""); toast(Loc.s(R.string.m2_calling_as, v)); setContentView(nameBookScreen(chatId)) }
        }, lp(MATCH_PARENT, dp(48), top = dp(8)))
        col.addView(pillButton(Loc.s(R.string.m2_set_verified), panel, fg) {
            val v = add.text.toString().trim()
            if (v.isNotEmpty()) {
                // Our account certifies this device → peers resolve it at the Linked
                // tier (insider-unforgeable), unlike a bare callsign.
                c.setLinkedLeadingName(account(), v); thread { runCatching { c.announcePresence() } }
                add.setText(""); toast(Loc.s(R.string.m2_verified_name, v)); setContentView(nameBookScreen(chatId))
            }
        }, lp(MATCH_PARENT, dp(48), top = dp(8)))
        col.addView(text(Loc.s(R.string.m2_verified_desc), 12f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))

        // ----- CQ cadence -----
        col.addView(label(Loc.s(R.string.m2_cq_beacon)).also { it.setPadding(0, dp(24), 0, dp(8)) })
        val periodicOn = runCatching { c.presenceCadenceSecs() }.getOrDefault(0uL) > 0uL
        val onMsg = runCatching { c.presenceCadenceOnMessageId() }.getOrDefault(false)
        col.addView(pillButton(if (periodicOn) Loc.s(R.string.m2_periodic_on) else Loc.s(R.string.m2_periodic_off), if (periodicOn) accent else panel, if (periodicOn) Color.WHITE else fg) {
            c.setPresenceCadence(if (periodicOn) 0uL else 300uL, onMsg); setContentView(nameBookScreen(chatId))
        }, lp(MATCH_PARENT, dp(48), top = dp(8)))
        col.addView(pillButton(if (onMsg) Loc.s(R.string.m2_onmsg_on) else Loc.s(R.string.m2_onmsg_off), if (onMsg) accent else panel, if (onMsg) Color.WHITE else fg) {
            c.setPresenceCadence(if (periodicOn) 300uL else 0uL, !onMsg); setContentView(nameBookScreen(chatId))
        }, lp(MATCH_PARENT, dp(48), top = dp(8)))
        col.addView(text(Loc.s(R.string.m2_onmsg_desc), 12f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))

        // ----- viewer name-trust policy (how strictly to show OTHERS' names) -----
        col.addView(label(Loc.s(R.string.m2_show_others)).also { it.setPadding(0, dp(24), 0, dp(8)) })
        val policy = darkSpinner(listOf(Loc.s(R.string.m2_nametrust_signal), Loc.s(R.string.m2_nametrust_warn), Loc.s(R.string.m2_nametrust_suppress)))
        col.addView(policy, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton(Loc.s(R.string.m2_apply_nametrust), panel, fg) {
            val v = when (policy.selectedItemPosition) { 1 -> "warn"; 2 -> "suppress"; else -> "signal" }
            c.setNameTrustPolicy(v); toast(Loc.s(R.string.m2_nametrust_set, v))
        }, lp(MATCH_PARENT, dp(48), top = dp(8)))
        col.addView(text(Loc.s(R.string.m2_tighten_only), 12f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))

        // ----- who's here (resolved names + safety numbers) -----
        if (lc.roster.isNotEmpty()) {
            col.addView(label(Loc.s(R.string.m2_whos_here)).also { it.setPadding(0, dp(24), 0, dp(8)) })
            for (m in lc.roster.values) {
                val badge = when (m.nameTier) { "Linked" -> "🔗 "; "RegistryConfirmed" -> "✓ "; else -> "" }
                val shown = m.display ?: m.fp.take(8)
                val sn = if (m.safetyNumber.isNotEmpty()) Loc.s(R.string.m2_safety_suffix, m.safetyNumber) else ""
                col.addView(text("$badge$shown$sn", 14f, fg).apply {
                    setOnClickListener { toast(Loc.s(R.string.m2_safety_number, m.safetyNumber.ifEmpty { m.fp.take(16) })) }
                }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
            }
        }

        col.addView(pillButton(Loc.s(R.string.m2_back), panel, fg) { setContentView(chatScreen(chatId)) }, lp(MATCH_PARENT, dp(50), top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
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
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, s) }, Loc.s(R.string.m2_share_invite)))
    }

    /** The old utility buttons, moved off the chat-first home (⋯ on the list). */
    private fun utilitiesScreen(): View {
        backState = Back.LIST_CHILD
        setSecure(false) // leaving Settings
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m2_more), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })
        col.addView(pillButton(Loc.s(R.string.m2_anchors), panel, fg) { setContentView(anchorsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
        col.addView(pillButton(Loc.s(R.string.m2_contacts), panel, fg) { setContentView(contactsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton(Loc.s(R.string.m2_linked_devices), panel, fg) { setContentView(linkedDevicesScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton(Loc.s(R.string.m2_segments), panel, fg) { setContentView(segmentsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton(Loc.s(R.string.m2_settings), panel, fg) { setContentView(settingsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton(Loc.s(R.string.m2_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
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
                .onFailure { ui.post { toast(Loc.s(R.string.m2_seal_mnemonic_err, it.message)) } }
        }
    }

    /** App-wide settings: identity, security, network defaults, notifications,
     *  about. Per-chat choices (posture, access, persistence, routing) stay in
     *  the new-chat screen; this holds everything that outlives a single chat. */
    private fun settingsScreen(): View {
        backState = Back.LIST_CHILD
        setSecure(true) // the mnemonic lives here; cleared on the exits below
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m2_settings), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, dp(16)) })

        // -- identity --
        col.addView(label(Loc.s(R.string.m2_identity)), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(6)))
        // Safety number derivation reconstructs the ML-DSA account — done off
        // the main thread (usually cached by the TkApp prewarm).
        var sn: String? = null
        val snCard = infoCard(Loc.s(R.string.m2_account_safety_number), Loc.s(R.string.m2_deriving), onClick = {
            val v = sn
            if (v == null) { toast(Loc.s(R.string.m2_still_deriving)) } else {
                val cm = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("talkrypt safety number", v))
                toast(Loc.s(R.string.m2_copied))
            }
        })
        col.addView(snCard, lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        storedLink()?.let { (_, username, accountSn) ->
            col.addView(infoCard(Loc.s(R.string.m2_linked_secondary), Loc.s(R.string.m2_account_short, accountSn.take(11)) + if (username.isNotEmpty()) Loc.s(R.string.m2_username_handle, username) else ""),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        }

        // -- security --
        col.addView(label(Loc.s(R.string.m2_security)), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        val custodyCard = infoCard(Loc.s(R.string.m2_key_custody_loading), Loc.s(R.string.m2_key_custody_desc))
        col.addView(custodyCard, lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        thread {
            val v = runCatching { account().safetyNumber() }.getOrDefault("unavailable")
            val t = runCatching { CustodyBridge.detectTier().name }.getOrDefault("UNKNOWN")
            ui.post {
                sn = v
                cardDetail(snCard).text = Loc.s(R.string.m2_safety_tap_copy, v)
                cardTitle(custodyCard).text = Loc.s(R.string.m2_key_custody, t)
            }
        }
        val sealErr = SecretStore.lastError
        if (sealErr == null) {
            col.addView(infoCard(Loc.s(R.string.m2_secrets_sealed), Loc.s(R.string.m2_secrets_sealed_desc)),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        } else {
            col.addView(infoCard(Loc.s(R.string.m2_sealing_degraded), Loc.s(R.string.m2_sealing_degraded_desc, sealErr), titleColor = amber),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        }

        // Paid Nym bandwidth (optional): mnemonic (sealed at rest) or ticketbook.
        col.addView(label(Loc.s(R.string.m2_nym_paid_bw)), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        // Masked by default (it controls funds), autofill excluded, sealed on a
        // debounce off the main thread rather than per keystroke.
        val nymMnem = inputField(Loc.s(R.string.m2_nym_mnemonic_hint)).apply {
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
            text = Loc.s(R.string.m2_show_mnemonic)
            setTextColor(muted)
            setOnCheckedChangeListener { _, checked ->
                nymMnem.transformationMethod =
                    if (checked) null else android.text.method.PasswordTransformationMethod.getInstance()
                nymMnem.setSelection(nymMnem.text.length)
            }
        }
        col.addView(reveal, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(4)))
        col.addView(text(Loc.s(R.string.m2_ticketbook_desc), 13f, muted)
            .also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(pillButton(Loc.s(R.string.m2_import_nym_cred), panel, fg) { launchTicketbookImport() },
            lp(MATCH_PARENT, dp(50), top = dp(4)))

        // -- network defaults --
        col.addView(label(Loc.s(R.string.m2_network_defaults)), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        val torDef = CheckBox(this).apply {
            text = Loc.s(R.string.m2_route_tor)
            setTextColor(muted); isChecked = prefsBool("default_tor", false)
            setOnCheckedChangeListener { _, c -> putPrefsBool("default_tor", c) }
        }
        col.addView(torDef, lp(MATCH_PARENT, WRAP_CONTENT))
        val nymDef = CheckBox(this).apply {
            text = Loc.s(R.string.m2_route_nym)
            setTextColor(muted); isChecked = prefsBool("default_nym", false)
            setOnCheckedChangeListener { _, c -> putPrefsBool("default_nym", c) }
        }
        col.addView(nymDef, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(4)))

        // -- notifications --
        col.addView(label(Loc.s(R.string.m2_notifications)), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        col.addView(infoCard(Loc.s(R.string.m2_always_on_chats), Loc.s(R.string.m2_always_on_desc), onClick = {
            runCatching {
                startActivity(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                    .putExtra(Settings.EXTRA_APP_PACKAGE, packageName))
            }.onFailure { toast(Loc.s(R.string.m2_open_notif_err)) }
        }), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))

        // -- about --
        col.addView(label(Loc.s(R.string.m2_about)), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16), bottom = dp(6)))
        val ver = runCatching { packageManager.getPackageInfo(packageName, 0).versionName }.getOrNull() ?: "?"
        col.addView(infoCard(Loc.s(R.string.m2_about_version, ver), Loc.s(R.string.m2_about_desc)),
            lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))

        col.addView(pillButton(Loc.s(R.string.m2_back), panel, fg) { setContentView(utilitiesScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    // ---------- contacts screen ----------
    private fun contactsScreen(): View {
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m2_contacts), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m2_contacts_desc), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        val contacts = storedContacts()
        if (contacts.isEmpty()) {
            col.addView(
                text(Loc.s(R.string.m2_no_contacts), 13f, muted),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(12)),
            )
        } else {
            for ((pk, name, friend) in contacts) {
                val label = (name.ifEmpty { pk.take(12) }) + (if (friend) Loc.s(R.string.m2_friend_suffix) else "")
                col.addView(text(label, 15f, if (friend) accent else fg).apply {
                    background = roundRect(panel, 12); setPadding(dp(14), dp(12), dp(14), dp(12))
                }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
            }
        }
        col.addView(pillButton(Loc.s(R.string.m2_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    // ---------- P2P app sharing ----------
    private fun shareApp() {
        toast(Loc.s(R.string.m2_starting_share))
        thread {
            val server = ApkShareServer(ApkShareServer.apkPath(this))
            val url = server.start()
            ui.post {
                if (url == null) {
                    server.stop()
                    toast(Loc.s(R.string.m2_no_wifi))
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
        col.addView(text(Loc.s(R.string.m2_share_talkrypt), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                Loc.s(R.string.m2_share_instructions),
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(20)),
        )
        addQrInto(col, url, 0.72f)
        col.addView(text(url, 13f, accent, center = true).also { it.setPadding(0, dp(18), 0, dp(8)) })
        // The transfer is plain HTTP on the local network — give the receiver a
        // fingerprint to compare so a hostile LAN can't swap the APK silently.
        val fpLine = text(Loc.s(R.string.m2_apk_computing), 12f, muted, center = true)
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
                fpLine.text = if (fp != null) Loc.s(R.string.m3_apk_sha256_verify, fp) else Loc.s(R.string.m3_apk_fingerprint_failed)
            }
        }
        col.addView(pillButton(Loc.s(R.string.m3_done), panel, fg) {
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
            parent.addView(text(Loc.s(R.string.m3_qr_too_large), 12f, muted, center = true))
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
        col.addView(text(Loc.s(R.string.m3_linked_devices), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                Loc.s(R.string.m3_linked_devices_desc),
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )

        val link = storedLink()
        if (link != null) {
            col.addView(text(Loc.s(R.string.m3_this_device_is_linked), 12f, muted, bold = true))
            col.addView(text(Loc.s(R.string.m3_account_prefix, link.third.take(35)), 13f, accent))
            if (link.second.isNotEmpty()) col.addView(text(Loc.s(R.string.m3_username_prefix, link.second), 13f, fg))
            col.addView(
                text(Loc.s(R.string.m3_device_prefix, deviceKey().fingerprintHex().take(24)), 12f, muted),
                lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(14)),
            )
            col.addView(label(Loc.s(R.string.m3_join_chat_as_account)))
            val joinUri = inputField("talkrypt://…")
            col.addView(joinUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
            col.addView(pillButton(Loc.s(R.string.m3_join_as_this_account), accent, onAccent) {
                val u = joinUri.text.toString().trim()
                if (u.startsWith("talkrypt://")) joinAsLinked(u) else toast(Loc.s(R.string.m3_paste_talkrypt_invite))
            }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
            col.addView(pillButton(Loc.s(R.string.m3_unlink_this_device), panel, Tk.danger) {
                confirm(Loc.s(R.string.m3_unlink_this_device_q), Loc.s(R.string.m3_unlink_body), Loc.s(R.string.m3_unlink)) {
                    clearLink(); toast(Loc.s(R.string.m3_unlinked)); setContentView(linkedDevicesScreen())
                }
            }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
            col.addView(text(Loc.s(R.string.m3_or_relink), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(22), bottom = dp(6)))
        }

        // Primary role: certify ANOTHER device under this device's account.
        col.addView(text(Loc.s(R.string.m3_link_another_device), 12f, muted, bold = true).also { it.setPadding(0, dp(4), 0, dp(4)) })
        col.addView(text(Loc.s(R.string.m3_link_another_device_desc), 12f, muted))
        col.addView(pillButton(Loc.s(R.string.m3_start_link_offer), accent, onAccent) {
            startLinkOffer()
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        // Secondary role: link THIS device using an offer from the primary.
        col.addView(text(Loc.s(R.string.m3_link_this_device_to_account), 12f, muted, bold = true).also { it.setPadding(0, dp(22), 0, dp(4)) })
        col.addView(label(Loc.s(R.string.m3_link_offer_label)))
        val offerUri = inputField("talkrypt://…")
        col.addView(offerUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        col.addView(pillButton(Loc.s(R.string.m3_accept_link_on_this_device), panel, fg) {
            val u = offerUri.text.toString().trim()
            if (u.startsWith("talkrypt://")) setContentView(acceptLinkConfirmScreen(u)) else toast(Loc.s(R.string.m3_paste_link_offer_uri))
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(pillButton(Loc.s(R.string.m3_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun startLinkOffer() {
        if (inFlight) { toast(Loc.s(R.string.m3_already_starting)); return }
        inFlight = true
        toast(Loc.s(R.string.m3_starting_link_offer))
        thread {
            try {
                val lan = ApkShareServer.lanIp() ?: "127.0.0.1"
                val offer = LinkOffer.host(account(), "$lan:9110", null)
                ui.post {
                    linkOffer = offer // hold it alive (the accept loop runs while held)
                    setContentView(linkOfferRunningScreen(offer.uri(), offer.accountSafetyNumber()))
                }
            } catch (e: Exception) {
                ui.post { toast(Loc.s(R.string.m3_link_offer_failed, e.message)) }
            } finally {
                ui.post { inFlight = false }
            }
        }
    }

    private fun linkOfferRunningScreen(uri: String, accountSn: String): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m3_link_offer_running), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m3_link_offer_running_desc), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        addQrInto(col, uri, 0.66f)
        col.addView(text(uri, 12f, accent, center = true).also { it.setPadding(0, dp(14), 0, dp(16)) })
        col.addView(text(Loc.s(R.string.m3_verify_oob_account_sn), 12f, muted, bold = true))
        col.addView(text(accountSn, 13f, fg), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))
        col.addView(pillButton(Loc.s(R.string.m3_done), panel, fg) {
            linkOffer = null; setContentView(linkedDevicesScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun acceptLinkConfirmScreen(uri: String): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m3_link_this_device_q), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m3_link_this_device_desc), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        col.addView(text(uri, 12f, muted), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))
        col.addView(pillButton(Loc.s(R.string.m3_accept_link_on_this_device), accent, onAccent) {
            acceptLink(uri)
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton(Loc.s(R.string.m3_cancel), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun acceptLink(uri: String) {
        if (inFlight) { toast(Loc.s(R.string.m3_already_linking)); return }
        inFlight = true
        toast(Loc.s(R.string.m3_linking_this_device))
        thread {
            try {
                val res = linkAccept(deviceKey(), uri, "android")
                saveLink(res.chainHex, res.username, res.accountSafetyNumber)
                ui.post {
                    setContentView(linkedDevicesScreen())
                    toast(Loc.s(R.string.m3_linked_to_account, res.accountSafetyNumber.take(11)))
                }
            } catch (e: Exception) {
                ui.post { toast(Loc.s(R.string.m3_link_failed, e.message)) }
            } finally {
                ui.post { inFlight = false }
            }
        }
    }

    private fun joinAsLinked(uri: String) {
        val link = storedLink() ?: run { toast(Loc.s(R.string.m3_device_not_linked)); return }
        toast(Loc.s(R.string.m3_joining_as_linked))
        thread {
            try {
                val c = TalkryptClient.joinLinked(uri, deviceKey(), link.first, link.second.ifEmpty { null })
                val sn = c.safetyNumber()
                runCatching { loadContacts(c) } // recognize saved contacts
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(uri), runCatching { inviteChannel(uri) }.getOrDefault("chat"), Role.JOIN, false, "", "open", uri, if (runCatching { inviteIsOnion(uri) }.getOrDefault(false)) uri else null, pendingTier, sn, now, now)
                    enterSession(meta, c, Loc.s(R.string.m3_joined_as_linked_account) + (link.second.takeIf { it.isNotEmpty() }?.let { Loc.s(R.string.m3_name_paren_suffix, it) } ?: ""))
                }
            } catch (e: Exception) {
                ui.post { toast(Loc.s(R.string.m3_join_failed, e.message)) }
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
            .onFailure { toast(Loc.s(R.string.m3_seal_segments_failed, it.message)) }
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
        col.addView(text(Loc.s(R.string.m3_segments), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                Loc.s(R.string.m3_segments_desc),
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(12)),
        )

        val linked = storedLink()
        col.addView(
            text(
                if (linked != null) Loc.s(R.string.m3_rooted_at_linked_account, linked.third.take(20))
                else Loc.s(R.string.m3_rooted_at_device_account),
                12f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(12)),
        )

        col.addView(label(Loc.s(R.string.m3_join_a_chat)))
        val joinUri = inputField("talkrypt://…")
        col.addView(joinUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6), bottom = dp(8)))

        val segs = storedSegments()
        if (segs.isEmpty()) {
            col.addView(text(Loc.s(R.string.m3_no_segments_yet), 13f, muted), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(8)))
        } else {
            // Reconstruct each segment's ML-DSA key + safety number OFF the main
            // thread (one keygen per segment is too much to do during layout —
            // ANR/jank with several segments), then post the rows into this box so
            // the screen renders immediately and fills in.
            val segsBox = column(bg)
            col.addView(segsBox, lp(MATCH_PARENT, WRAP_CONTENT))
            val loading = text(Loc.s(R.string.m3_loading_segments), 13f, muted)
            segsBox.addView(loading, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
            thread {
                val built = segs.mapNotNull { (name, seed) ->
                    val seg = runCatching { SegmentKey.fromSeedHex(seed) }.getOrNull() ?: return@mapNotNull null
                    Triple(name, seg, runCatching { seg.safetyNumber() }.getOrDefault(""))
                }
                ui.post {
                    segsBox.removeView(loading)
                    built.forEach { (name, seg, sn) ->
                        segsBox.addView(text("● $name", 15f, fg, bold = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
                        segsBox.addView(text(Loc.s(R.string.m3_safety_prefix, sn.take(23)), 12f, muted))
                        segsBox.addView(pillButton(Loc.s(R.string.m3_join_as_name, name), accent, onAccent) {
                            val u = joinUri.text.toString().trim()
                            if (u.startsWith("talkrypt://")) joinAsSegment(u, seg, name) else toast(Loc.s(R.string.m3_paste_talkrypt_invite_above))
                        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
                        segsBox.addView(pillButton(Loc.s(R.string.m3_delete_name, name), panel, Tk.danger) {
                            confirm(Loc.s(R.string.m3_delete_segment_q, name), Loc.s(R.string.m3_delete_segment_body), Loc.s(R.string.m3_delete)) {
                                removeSegment(name); setContentView(segmentsScreen())
                            }
                        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
                    }
                }
            }
        }

        col.addView(text(Loc.s(R.string.m3_new_segment), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20), bottom = dp(8)))
        col.addView(label(Loc.s(R.string.m3_segment_name_label)))
        val name = inputField(Loc.s(R.string.m3_hint_work))
        col.addView(name, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        col.addView(pillButton(Loc.s(R.string.m3_create_segment), accent, onAccent) {
            val n = name.text.toString().trim()
            if (n.isEmpty()) { toast(Loc.s(R.string.m3_name_the_segment)); return@pillButton }
            addSegment(n); toast(Loc.s(R.string.m3_created_segment, n)); setContentView(segmentsScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(pillButton(Loc.s(R.string.m3_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun joinAsSegment(uri: String, segment: SegmentKey, name: String) {
        toast(Loc.s(R.string.m3_joining_as_name, name))
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
                    enterSession(meta, c, Loc.s(R.string.m3_joined_as_segment, name))
                }
            } catch (e: Exception) {
                ui.post { toast(Loc.s(R.string.m3_join_failed, e.message)) }
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
            toast(Loc.s(R.string.m3_wifi_off))
            // API 29+ slide-up Wi-Fi panel; apps can't toggle Wi-Fi directly.
            runCatching { startActivity(Intent(Settings.Panel.ACTION_WIFI)) }
        }
    }

    private fun findNearbyScreen(): View {
        backState = Back.LIST_CHILD
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m3_nearby_hosts), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m3_nearby_scanning), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        nearbyList = list
        col.addView(list, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(text("…", 13f, muted, center = true).also { it.setPadding(0, dp(16), 0, dp(16)) })
        col.addView(pillButton(Loc.s(R.string.m3_back), panel, fg) {
            stopNearby(); setContentView(chatListScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(12)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun addNearbyPeer(peer: NearbyDiscovery.Peer) {
        if (foundInvites.put(peer.inviteUri, peer) != null) return // de-dupe
        val list = nearbyList ?: return
        list.addView(pillButton(Loc.s(R.string.m3_join_peer, peer.name), accent, onAccent) {
            stopNearby(); startJoin(peer.inviteUri)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))
    }

    private fun startNearbyAdvertising(invite: String) {
        withNearbyPermissions {
            stopNearby()
            nearby = listOf(NearbyDiscovery.ble(this), NearbyDiscovery.wifiDirect(this))
            nearby.forEach { it.startAdvertising(invite) }
            system(Loc.s(R.string.m3_broadcasting_nearby))
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
            if (!granted) toast(Loc.s(R.string.m3_notifications_blocked))
        }
        if (requestCode == REQ_NEARBY) {
            val granted = grantResults.isNotEmpty() &&
                grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            val act = pendingNearby
            pendingNearby = null
            if (granted) {
                act?.invoke()
            } else {
                toast(Loc.s(R.string.m3_nearby_perm_needed))
            }
        }
        if (requestCode == REQ_BLE) {
            // Resume the deferred beacon/mesh start now that BLE perms resolved.
            val act = pendingBle
            pendingBle = null
            val granted = grantResults.isNotEmpty() &&
                grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            if (granted) {
                act?.invoke()
            } else {
                toast(Loc.s(R.string.m3_beacon_perm_needed))
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
        col.addView(text(Loc.s(R.string.m4_anchors_title), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m4_anchors_desc), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(12)),
        )
        col.addView(text(Loc.s(R.string.m4_your_account), 12f, muted, bold = true))
        // Safety-number derivation hashes the ML-DSA account key — off the main
        // thread so this screen lays out instantly and fills the number in.
        val snView = text(Loc.s(R.string.m4_deriving), 13f, accent)
        col.addView(snView, lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))
        thread {
            val sn = runCatching { acct.safetyNumber().take(35) + "…" }.getOrDefault(Loc.s(R.string.m4_unavailable))
            ui.post { snView.text = sn }
        }

        // Spawn your own anchor.
        col.addView(pillButton(Loc.s(R.string.m4_spawn_my_anchor), accent, onAccent) {
            spawnAnchor()
        }, lp(MATCH_PARENT, WRAP_CONTENT))

        // Use a known anchor by entering its location.
        col.addView(text(Loc.s(R.string.m4_or_use_known_anchor), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24), bottom = dp(10)))
        col.addView(label(Loc.s(R.string.m4_anchor_location_label)))
        val anchorUri = inputField("talkrypt://…")
        col.addView(anchorUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))

        col.addView(label(Loc.s(R.string.m4_username_label)).also { it.setPadding(0, dp(16), 0, dp(6)) })
        val uname = inputField(Loc.s(R.string.m4_username_hint))
        col.addView(uname, lp(MATCH_PARENT, WRAP_CONTENT))

        val result = text("", 13f, fg).also { it.setPadding(0, dp(14), 0, 0) }

        col.addView(pillButton(Loc.s(R.string.m4_register_username_here), panel, fg) {
            val uri = anchorUri.text.toString().trim()
            val name = uname.text.toString().trim()
            if (!uri.startsWith("talkrypt://") || name.isEmpty()) { toast(Loc.s(R.string.m4_enter_anchor_uri_username)); return@pillButton }
            registerAtAnchor(uri, acct, name, result)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16)))

        col.addView(pillButton(Loc.s(R.string.m4_resolve_this_username), panel, fg) {
            val uri = anchorUri.text.toString().trim()
            val name = uname.text.toString().trim()
            if (!uri.startsWith("talkrypt://") || name.isEmpty()) { toast(Loc.s(R.string.m4_enter_anchor_uri_username)); return@pillButton }
            resolveAtAnchor(uri, name, result)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))

        col.addView(result, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton(Loc.s(R.string.m4_back), panel, fg) {
            setContentView(chatListScreen())
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))

        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun spawnAnchor() {
        if (inFlight) { toast(Loc.s(R.string.m4_already_spawning)); return }
        inFlight = true
        toast(Loc.s(R.string.m4_spawning_anchor))
        thread {
            try {
                val lan = ApkShareServer.lanIp() ?: "127.0.0.1"
                val node = AnchorNode.host("$lan:9100", "#anchor")
                ui.post {
                    anchorNode = node // keep it alive (the registry runs while held)
                    setContentView(anchorRunningScreen(node.uri()))
                }
            } catch (e: Exception) {
                ui.post { toast(Loc.s(R.string.m4_anchor_failed, e.message)) }
            } finally {
                ui.post { inFlight = false }
            }
        }
    }

    private fun anchorRunningScreen(uri: String): View {
        val col = column(bg).apply { setPadding(dp(16), dp(8), dp(16), dp(24)) }
        col.addView(text(Loc.s(R.string.m4_anchor_running_title), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m4_anchor_running_desc), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        addQrInto(col, uri, 0.66f)
        col.addView(text(uri, 13f, accent, center = true).also { it.setPadding(0, dp(16), 0, dp(20)) })
        col.addView(pillButton(Loc.s(R.string.m4_back), panel, fg) { setContentView(anchorsScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun registerAtAnchor(uri: String, acct: Account, name: String, result: TextView) {
        result.text = Loc.s(R.string.m4_registering)
        thread {
            val msg = try {
                anchorRegister(uri, acct, name)
                // Remember we're bound here so registry-restricted chats can
                // offer it — the only registries it makes sense to gate by.
                addBoundAnchor(uri, name)
                Loc.s(R.string.m4_register_success, name)
            } catch (e: Exception) {
                Loc.s(R.string.m4_register_failed, e.message)
            }
            ui.post { result.text = msg }
        }
    }

    private fun resolveAtAnchor(uri: String, name: String, result: TextView) {
        result.text = Loc.s(R.string.m4_resolving)
        thread {
            val msg = try {
                val sn = anchorResolve(uri, name)
                if (sn != null) Loc.s(R.string.m4_resolve_safety_number, name, sn)
                else Loc.s(R.string.m4_resolve_not_registered, name)
            } catch (e: Exception) {
                Loc.s(R.string.m4_resolve_failed, e.message)
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
        col.addView(text(Loc.s(R.string.m4_registry_restricted_title), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m4_registry_restricted_desc, channel), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(18)),
        )
        if (anchors.isEmpty()) {
            col.addView(text(Loc.s(R.string.m4_not_registered_any_anchor), 13f, amber), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
        } else {
            for ((uri, username) in anchors) {
                // One disabled row per bound anchor; a background ping enables it.
                val row = pillButton(Loc.s(R.string.m4_checking_anchor, shortUri(uri)), panel, muted) { /* set on success */ }
                row.isEnabled = false
                row.alpha = 0.5f
                row.isClickable = false
                col.addView(row, lp(MATCH_PARENT, dp(52), top = dp(8)))
                pingAnchor(uri, username, acct, row, Loc.s(R.string.m4_host_gated_by, username, shortUri(uri))) {
                    startRestrictedHost(channel, posture, uri, username)
                }
            }
        }
        col.addView(pillButton(Loc.s(R.string.m4_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(24)))
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
                    row.text = Loc.s(R.string.m4_anchor_unreachable, shortUri(uri))
                    row.alpha = 0.5f
                }
            }
        }
    }

    private fun startRestrictedHost(channel: String, posture: String, anchorUri: String, username: String) {
        toast(Loc.s(R.string.m4_creating_restricted_chat))
        thread {
            try {
                val port = ChatNet.allocLanPort()
                val c = TalkryptClient.host(ChatNet.lanBind(port), channel, posture, ChatNet.lanAdvertise(port), null)
                runCatching { c.presentAccount(account(), username) }
                runCatching { loadContacts(c) } // recognize saved contacts
                val members = c.restrictToAnchor(anchorUri)
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    val now = System.currentTimeMillis()
                    val meta = ChatMeta(chatId(invite), channel, Role.HOST, false, posture, "restricted", invite, if (useTor) invite else null, pendingTier, sn, now, now)
                    enterSession(meta, c, Loc.s(R.string.m4_registry_restricted_members, members))
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = Loc.s(R.string.m4_sender_invite))
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) {
                ui.post { toast(Loc.s(R.string.m4_restricted_host_failed, e.message)) }
            }
        }
    }

    // ---------- chat screen ----------
    private fun tierLabel(p: Persistence) =
        when (p) { Persistence.EPHEMERAL -> Loc.s(R.string.m4_tier_ephemeral); Persistence.ALWAYS_ON -> Loc.s(R.string.m4_tier_always_on); else -> Loc.s(R.string.m4_tier_persistent) }

    /** Refresh the on-screen chat header (connection chip + details) in place —
     *  connection events must NOT rebuild the screen, that wipes the draft. */
    private fun updateChatHeader(lc: LiveChat) {
        val (cs, cc) = connInfo(lc)
        chatChip?.apply { text = "● $cs"; setTextColor(cc) }
        val memberStr = if (lc.roster.isNotEmpty()) Loc.s(R.string.m4_members_prefix, lc.roster.size) else ""
        chatDetail?.text = Loc.s(R.string.m4_chat_detail, memberStr, lc.meta.safety.take(11), tierLabel(lc.meta.persistence))
    }

    /** Render history entries not yet on screen (the initial replay, live events,
     *  and anything the service drained while the Activity was paused). All
     *  history-backed rendering funnels through here so [renderedCount] stays
     *  true; render-only extras (invite QR, action rows) don't count. SUB-SPEC A:
     *  each bubble's trust-tier badge is read from the CURRENT roster at render
     *  time, so a re-render (see [rerenderTranscript]) reflects tier changes. */
    private fun renderNew(lc: LiveChat) {
        if (messages == null) return
        while (renderedCount < lc.history.size) {
            val m = lc.history[renderedCount++]
            when (m.kind) {
                MsgKind.MESSAGE -> addBubble(m.text, m.mine, sender = if (m.mine) null else m.display, marking = m.marking,
                    tier = if (m.mine) "" else (m.sender?.let { lc.roster[it]?.nameTier } ?: ""),
                    delivery = if (m.mine) m.delivery else Delivery.NONE)
                MsgKind.SYSTEM, MsgKind.ACTION -> system(m.text)
            }
        }
    }

    /** Re-render the whole transcript in place — clears the message list and replays
     *  history so a trust/tier change (Event::Name) reflects on EARLIER bubbles.
     *  Rebuilds only the message list (not the screen), so the input draft is kept. */
    private fun rerenderTranscript(lc: LiveChat) {
        messages?.removeAllViews()
        renderedCount = 0
        renderNew(lc)
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
            setBackgroundColor(panel); setPaddingRelative(dp(8), dp(10), dp(12), dp(10))
        }
        header.addView(text(if (isRtl) "›" else "‹", 30f, fg).apply {
            contentDescription = Loc.s(R.string.m4_back)
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
            contentDescription = Loc.s(R.string.m4_chat_menu)
            minimumWidth = dp(48); minimumHeight = dp(48); gravity = Gravity.CENTER
            setPaddingRelative(dp(10), dp(4), dp(8), dp(4)); setOnClickListener { chatRowMenu(lc) }
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

        // replay this chat's stored history into the view (tier-aware; see renderNew)
        renderedCount = 0
        renderNew(lc)

        // input bar — pinned to the bottom
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(panel); setPadding(dp(12), dp(10), dp(12), dp(10))
        }
        // Restore any unsent draft; mirror edits into [drafts] so the text
        // survives screen swaps (connection events, back, process pauses).
        val input = inputField(Loc.s(R.string.m4_message_hint)).apply {
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
            contentDescription = Loc.s(R.string.m4_send)
            background = circle(accent)
            gravity = Gravity.CENTER
            // The send arrow points in the writing direction: ➤ (LTR) / ◀ flipped
            // for RTL so it reads "forward" toward the message column.
            scaleX = if (isRtl) -1f else 1f
        }
        send.setOnClickListener {
            val t = input.text.toString()
            // Only clear once the message is accepted — a failed/deferred send
            // must never eat the composed text.
            if (t.isNotEmpty() && sendMessage(chatId, t)) input.setText("")
        }
        bar.addView(send, LinearLayout.LayoutParams(dp(48), dp(48)).apply { marginStart = dp(10) })
        root.addView(bar, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        applyInsets(root)
        return root
    }

    // ---------- bubbles ----------
    private fun addBubble(body: String, mine: Boolean, sender: String? = null, marking: String? = null, tier: String = "", delivery: Delivery = Delivery.NONE) {
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
        if (sender != null) {
            // SUB-SPEC A: tint the sender label by trust tier — a verified (account-
            // linked / registry-confirmed) callsign gets a badge + verified-green,
            // a bare/unverified one stays the neutral accent so it can't pass for
            // verified at a glance.
            val (badge, color) = when (tier) {
                "Linked" -> "🔗 " to Color.parseColor("#7FD1A6")
                "RegistryConfirmed" -> "✓ " to Color.parseColor("#7FD1A6")
                else -> "" to accent
            }
            bubble.addView(text("$badge$sender", 11f, color, bold = true))
        }
        bubble.addView(text(body, 15f, if (mine) onAccent else fg).apply {
            // cap long messages at ~76% of screen width so bubbles don't span edge-to-edge
            maxWidth = (resources.displayMetrics.widthPixels * 0.76f).toInt()
        })
        // Per-bubble delivery glyph on OUR messages: · sent → ✓✓ delivered → ✗ failed.
        // (Honest: ✓✓ appears only on a real ack — group/persistent path; pairwise
        // 1:1 stays at · because there's no ack to upgrade it.)
        if (mine && delivery != Delivery.NONE) {
            val (glyph, color) = when (delivery) {
                Delivery.DELIVERED -> "✓✓" to onAccent
                Delivery.FAILED -> "✗" to Color.parseColor("#E57373")
                else -> "·" to onAccent
            }
            val glyphView = text(glyph, 10f, color).apply {
                contentDescription = when (delivery) {
                    Delivery.DELIVERED -> Loc.s(R.string.m4_delivery_delivered); Delivery.FAILED -> Loc.s(R.string.m4_delivery_not_delivered); else -> Loc.s(R.string.m4_delivery_sent)
                }
            }
            bubble.addView(glyphView, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT).apply {
                gravity = Gravity.END; topMargin = dp(2)
            })
        }
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
    private fun startHost(channel: String, posture: String, access: String = "open", tier: Persistence = Persistence.PERSISTENT_LOCAL, namePolicy: String = "") {
        if (inFlight) { toast(Loc.s(R.string.m4_already_creating_chat)); return }
        inFlight = true
        // Over Tor/Nym the bootstrap takes tens of seconds; show a connecting
        // screen (not just a toast on the unchanged form) so the host isn't left
        // staring at a form that looks like nothing happened.
        if (useTor || useNym) setContentView(connectingScreen(Loc.s(R.string.m4_starting_chat_over, if (useNym) "Nym + Tor" else "Tor"), true))
        else toast(Loc.s(R.string.m4_creating_chat))
        thread {
            try {
                // Bind to the LAN/hotspot address (not loopback) so the invite is
                // dialable from another device — required for QR/nearby joining.
                // Over Tor, all chats share one Arti client + state dir (see
                // ChatNet.sharedTorDir); the onion service is per-chat within it.
                // Nym multi-homes over Tor too, so it also uses the shared Tor dir.
                val torSub = if (useTor || useNym) "shared" else null
                // SUB-SPEC A §5: the chosen name-trust baseline (empty = default) is
                // set at creation so it travels in the invite and joiners inherit it.
                val pol = namePolicy.ifEmpty { null }
                val c = if (useNym) {
                    TalkryptClient.hostNym(channel, posture, ChatNet.sharedTorDir(this), ChatNet.nymMnemonic(this), pol)
                } else if (useTor) {
                    TalkryptClient.hostTor(channel, posture, ChatNet.sharedTorDir(this), pol)
                } else {
                    // Bind a free port (so multiple chats can host at once); advertise
                    // the address peers dial.
                    val port = ChatNet.allocLanPort()
                    TalkryptClient.host(ChatNet.lanBind(port), channel, posture, ChatNet.lanAdvertise(port), pol)
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
                    sysLine(meta.id, Loc.s(R.string.m4_hosting_share_invite))
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = Loc.s(R.string.m4_sender_invite))
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) {
                // Return to home so the user isn't stranded on the connecting screen.
                ui.post { toast(Loc.s(R.string.m5_host_failed, e.message)); if (useTor || useNym) setContentView(chatListScreen()) }
            } finally {
                inFlight = false
            }
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
        col.addView(text(Loc.s(R.string.m5_join_chat), 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(Loc.s(R.string.m5_join_restricted_explainer), 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(18)),
        )
        if (anchors.isEmpty()) {
            col.addView(text(Loc.s(R.string.m5_no_memberships), 13f, amber), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
        } else {
            col.addView(text(Loc.s(R.string.m5_present_a_membership), 12f, muted, bold = true))
            for ((anchorUri, username) in anchors) {
                val row = pillButton(Loc.s(R.string.m5_checking_anchor, shortUri(anchorUri)), panel, muted) { }
                row.isEnabled = false; row.alpha = 0.5f; row.isClickable = false
                col.addView(row, lp(MATCH_PARENT, dp(52), top = dp(8)))
                pingAnchor(anchorUri, username, acct, row, Loc.s(R.string.m5_join_as_member, username, shortUri(anchorUri))) {
                    doJoin(uri, username, presentAccount = true)
                }
            }
        }
        col.addView(text(Loc.s(R.string.m5_or_separator), 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20), bottom = dp(10)))
        col.addView(pillButton(Loc.s(R.string.m5_join_with_account), panel, fg) {
            doJoin(uri, null, presentAccount = true)
        }, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton(Loc.s(R.string.m5_join_as_pseudonym), panel, fg) {
            doJoin(uri, null, presentAccount = false)
        }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10)))
        col.addView(pillButton(Loc.s(R.string.m5_back), panel, fg) { setContentView(chatListScreen()) }, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun doJoin(uri: String, username: String?, presentAccount: Boolean) {
        if (inFlight) { toast(Loc.s(R.string.m5_already_joining)); return }
        inFlight = true
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
                    sysLine(meta.id, if (presentAccount) Loc.s(R.string.m5_joined) + (username?.let { Loc.s(R.string.m5_as_suffix, it) } ?: "") else Loc.s(R.string.m5_joined_as_pseudonym))
                }
            } catch (e: Exception) {
                ui.post {
                    if (gen != joinGen) return@post // cancelled — nothing to report
                    connecting = false
                    connectingLabel?.apply { text = Loc.s(R.string.m5_failed, ChatNet.friendlyError(e.message)); setTextColor(Tk.danger) }
                    toast(Loc.s(R.string.m5_join_failed))
                }
            } finally {
                inFlight = false
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
        col.addView(text(Loc.s(R.string.m5_connecting_title), 26f, fg, bold = true, center = true))
        col.addView(text(title, 16f, muted, center = true).also { it.setPadding(0, dp(8), 0, dp(28)) })
        val lbl = text(if (tor) Loc.s(R.string.m5_bootstrapping_tor) else Loc.s(R.string.m5_connecting), 16f, accent, center = true)
        connectingLabel = lbl
        col.addView(lbl)
        if (tor) col.addView(
            text(Loc.s(R.string.m5_first_tor_slow), 12f, muted, center = true)
                .also { it.setPadding(0, dp(16), 0, 0) },
        )
        col.addView(pillButton(Loc.s(R.string.m5_cancel), panel, fg) {
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
                    if (pct < 100) Loc.s(R.string.m5_bootstrapping_tor_pct, pct) else Loc.s(R.string.m5_building_circuit)
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
        if (plan == ReconnectPlan.IMPOSSIBLE) { toast(Loc.s(R.string.m5_cant_reconnect)); return }
        val net = when (plan) {
            ReconnectPlan.HOST_NYM, ReconnectPlan.JOIN_NYM -> "Nym"
            ReconnectPlan.HOST_TOR, ReconnectPlan.JOIN_TOR -> "Tor"
            else -> "LAN"
        }
        sysLine(id, Loc.s(R.string.m5_reconnecting_over, net)); toast(Loc.s(R.string.m5_reconnecting_over, net))
        thread {
            try {
                // Shared with ChatService — one place builds a client from a meta.
                val c = ChatNet.connect(this, m)
                val freshInvite = if (m.role == Role.HOST) runCatching { c.inviteUri() }.getOrNull() else null
                ui.post {
                    lc.client = c
                    // A re-hosted LAN chat gets a fresh invite; keep the same chatId.
                    if (freshInvite != null) lc.meta = lc.meta.copy(inviteUri = freshInvite)
                    sysLine(id, Loc.s(R.string.m5_reconnected_over, net))
                    when {
                        activeId == id -> setContentView(chatScreen(id))
                        activeId == null && backState == Back.HOME -> setContentView(chatListScreen())
                        else -> {} // user is on some other screen — don't yank it away
                    }
                }
            } catch (e: Exception) { ui.post { sysLine(id, Loc.s(R.string.m5_reconnect_failed_detail, net, ChatNet.friendlyError(e.message))); toast(Loc.s(R.string.m5_reconnect_failed)) } }
        }
    }

    /** Try to send; returns whether the message was accepted. When it isn't
     *  (no client yet), the caller keeps the composed text in the input. */
    private fun sendMessage(chatId: String, t: String): Boolean {
        val lc = sessions.get(chatId) ?: return false
        val c = lc.client ?: run { reconnect(chatId); toast(Loc.s(R.string.m5_reconnecting_text_kept)); return false }
        // SUB-SPEC A: /name and /cq are handled locally (self-declared name + CQ beacon),
        // mirroring the CLI, rather than sent as chat text. Handled = accepted (true).
        if (t.startsWith("/name") || t.startsWith("/cq")) { handleNameCommand(chatId, c, t.trim()); return true }
        val msg = ChatMsg(MsgKind.MESSAGE, null, null, mine = true, text = t, marking = null,
            ts = System.currentTimeMillis(), delivery = Delivery.SENT)
        lc.history.add(msg); sessions.touch(chatId, msg.ts)
        if (activeId == chatId) renderNew(lc)
        scheduleSave(chatId)
        // send() returns this message's hex gossip_id; stash it on the bubble so a
        // later Delivered event flips its glyph · → ✓✓. On failure, mark it ✗.
        thread {
            runCatching { c.send(t) }
                .onSuccess { gid -> ui.post { msg.gossipId = gid } }
                .onFailure { ui.post { msg.delivery = Delivery.FAILED; if (activeId == chatId) rerenderTranscript(lc); toast(Loc.s(R.string.m5_send_failed)) } }
        }
        return true
    }

    /** SUB-SPEC A slash commands (self-declared name + CQ beacon), mirroring the CLI:
     *  `/name <callsign>` | `/name off` | `/name new <cs>` | `/name list` |
     *  `/name use <id>` | `/cq` | `/cq periodic <mins>|off` | `/cq onmsg on|off`.
     *  The name book is also editable in the "Manage callsigns" screen. */
    private fun handleNameCommand(chatId: String, c: TalkryptClient, t: String) {
        when {
            t == "/name list" -> {
                val names = runCatching { c.listNames() }.getOrDefault(emptyList())
                if (names.isEmpty()) sysLine(chatId, Loc.s(R.string.m5_name_book_empty))
                else {
                    val active = runCatching { c.leadingNameId() }.getOrDefault("")
                    names.forEach {
                        val mark = if (it.id == active) "* " else "  "
                        val tier = if (it.linked) Loc.s(R.string.m5_tier_account_linked) else Loc.s(R.string.m5_tier_bare)
                        sysLine(chatId, Loc.s(R.string.m5_name_list_entry, mark, it.id, it.label, tier))
                    }
                }
            }
            t.startsWith("/name new ") -> {
                val label = t.removePrefix("/name new ").trim()
                if (label.isNotEmpty()) { c.addBareName(label, label); sysLine(chatId, Loc.s(R.string.m5_saved_to_name_book, label)) }
            }
            t.startsWith("/name use ") -> {
                val id = t.removePrefix("/name use ").trim()
                thread {
                    val ok = runCatching { c.useName(id) }.getOrDefault(false)
                    ui.post { sysLine(chatId, if (ok) Loc.s(R.string.m5_switched_to, id) else Loc.s(R.string.m5_no_saved_name, id)) }
                }
            }
            t.startsWith("/name link ") -> {
                // Account-LINKED (verified) name: our account certifies this device key,
                // so peers resolve it at the insider-unforgeable Linked tier.
                val label = t.removePrefix("/name link ").trim()
                if (label.isNotEmpty()) {
                    c.setLinkedLeadingName(account(), label)
                    thread { runCatching { c.announcePresence() } }
                    sysLine(chatId, Loc.s(R.string.m5_calling_verified, label))
                }
            }
            t.startsWith("/name ") -> {
                val label = t.removePrefix("/name ").trim()
                if (label == "off") { c.setLeadingName(""); sysLine(chatId, Loc.s(R.string.m5_name_cleared)) }
                else {
                    c.setLeadingName(label)
                    thread { runCatching { c.announcePresence() } }
                    sysLine(chatId, Loc.s(R.string.m5_calling_as, label))
                }
            }
            t == "/cq" -> { thread { runCatching { c.announcePresence() } }; sysLine(chatId, Loc.s(R.string.m5_cq_announced)) }
            t.startsWith("/cq periodic") -> {
                val rest = t.removePrefix("/cq periodic").trim()
                val secs = if (rest == "off" || rest.isEmpty()) 0L else (rest.toLongOrNull()?.times(60) ?: 0L)
                // Preserve the on-message-id flag when changing the periodic interval.
                val onMsg = runCatching { c.presenceCadenceOnMessageId() }.getOrDefault(false)
                c.setPresenceCadence(secs.toULong(), onMsg)
                sysLine(chatId, if (secs == 0L) Loc.s(R.string.m5_cq_cadence_off) else Loc.s(R.string.m5_cq_cadence_every, secs / 60))
            }
            t.startsWith("/cq onmsg") -> {
                val on = t.removePrefix("/cq onmsg").trim().let { it == "on" || it.isEmpty() }
                val secs = runCatching { c.presenceCadenceSecs() }.getOrDefault(0uL)
                c.setPresenceCadence(secs, on)
                sysLine(chatId, Loc.s(R.string.m5_cq_onmsg, if (on) Loc.s(R.string.m5_state_on) else Loc.s(R.string.m5_state_off)))
            }
            else -> sysLine(chatId, Loc.s(R.string.m5_name_usage))
        }
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
        applyEvent(sessions, id, lc, e)
        if (activeId == id) {
            // A trust/name change (Event::Name — e.g. a mode-3 stale-name drop or a
            // tier upgrade) can retroactively change how EARLIER messages should be
            // badged, so re-render the transcript in place. This is deterministic —
            // unlike main, which only refreshed tiers incidentally on a connection
            // flap (full setContentView). We rebuild only the message list, never the
            // whole screen, so the user's half-typed input draft is preserved.
            // Delivered/OutboxDropped mutate an EARLIER bubble's glyph in place
            // (applyEvent returned null), so they rebuild the transcript too.
            if (e is FfiEvent.Name || e is FfiEvent.Delivered || e is FfiEvent.OutboxDropped) rerenderTranscript(lc) else renderNew(lc)
            // Connection changes refresh the header chip in place — a rebuild here
            // used to wipe the draft on every peer flap.
            if (e is FfiEvent.Connected || e is FfiEvent.Disconnected) updateChatHeader(lc)
            if (e is FfiEvent.Identity && !e.contact) {
                val who = lc.roster[e.accountFingerprint]?.display ?: e.accountFingerprint.take(8)
                val fp = e.accountFingerprint; val name = e.username
                addAction(Loc.s(R.string.m5_add_as_contact, who)) {
                    val cl = lc.client
                    if (cl != null && cl.addSeenContact(fp, name.ifEmpty { null }, false)) { saveContacts(cl); system(Loc.s(R.string.m5_added_contact, who)) }
                    else toast(Loc.s(R.string.m5_could_not_add))
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

    /** True when the resolved layout direction is right-to-left (Arabic, Hebrew,
     *  Persian, Urdu). Used to flip directional glyphs (back chevron, send arrow)
     *  that the framework can't auto-mirror because they're text, not drawables.
     *  Horizontal LinearLayouts + relative padding/margins already mirror under
     *  supportsRtl, so only these glyphs need an explicit flip. */
    private val isRtl: Boolean
        get() = resources.configuration.layoutDirection == View.LAYOUT_DIRECTION_RTL

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
            .setTitle(Loc.s(R.string.m5_invite_qr))
            .setView(box)
            .setPositiveButton(Loc.s(R.string.m5_share)) { _, _ -> shareText(invite) }
            .setNegativeButton(Loc.s(R.string.m5_close), null)
            .show()
    }

    /** Confirmation gate for irreversible actions (delete/unlink). */
    private fun confirm(title: String, detail: String, verb: String, action: () -> Unit) {
        android.app.AlertDialog.Builder(this)
            .setTitle(title).setMessage(detail)
            .setPositiveButton(verb) { _, _ -> action() }
            .setNegativeButton(Loc.s(R.string.m5_cancel), null)
            .show()
            .apply { getButton(android.app.AlertDialog.BUTTON_POSITIVE)?.setTextColor(Tk.danger) }
    }
}
