package com.talkrypt.app

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowInsets
import android.widget.ArrayAdapter
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
import uniffi.talkrypt_ffi.FfiEvent
import uniffi.talkrypt_ffi.TalkryptClient
import uniffi.talkrypt_ffi.anchorRegister
import uniffi.talkrypt_ffi.anchorResolve

/**
 * The talkrypt chat app — a post-quantum, end-to-end encrypted chat over the
 * shared `TalkryptClient` FFI, with a Signal-style bubble UI. The device's
 * key-custody tier (StrongBox on the Seeker) and ML-DSA-87 identity show in the
 * header. NOT certified / NOT audited — see the README.
 */
class MainActivity : Activity() {
    private val ui = Handler(Looper.getMainLooper())
    private var client: TalkryptClient? = null
    private var messages: LinearLayout? = null
    private var scroll: ScrollView? = null
    private var shareServer: ApkShareServer? = null

    // Nearby discovery (BLE + Wi-Fi Direct) state.
    private var nearby: List<NearbyDiscovery> = emptyList()
    private val foundInvites = LinkedHashMap<String, NearbyDiscovery.Peer>()
    private var nearbyList: LinearLayout? = null
    private var pendingNearby: (() -> Unit)? = null

    // palette
    private val bg = Color.parseColor("#0B0E13")
    private val panel = Color.parseColor("#161B22")
    private val field = Color.parseColor("#1C2230")
    private val fg = Color.parseColor("#E6EDF3")
    private val muted = Color.parseColor("#8B949E")
    private val accent = Color.parseColor("#2EA043")
    private val peerBubble = Color.parseColor("#222B36")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        tintSystemBars()
        setContentView(setupScreen())
        handleDeepLink(intent)
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
            toast("opening invite…")
            startJoin(data.toString())
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        shareServer?.stop()
        stopNearby()
    }

    companion object {
        private const val REQ_NEARBY = 0x4E42 // "NB"
    }

    // ---------- setup screen ----------
    private fun setupScreen(): View {
        val tier = runCatching { CustodyBridge.detectTier().name }.getOrDefault("UNKNOWN")
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }

        col.addView(text("talkrypt", 32f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(text("post-quantum · end-to-end encrypted", 14f, muted))

        // custody/probe status pill
        val pill = text("🔒  $tier  ·  ML-DSA-87", 13f, accent).apply {
            background = roundRect(panel, 18); setPadding(dp(16), dp(10), dp(16), dp(10))
        }
        col.addView(pill, lp(WRAP_CONTENT, WRAP_CONTENT, top = dp(20), bottom = dp(28)))

        col.addView(label("CHANNEL"))
        val channel = inputField("#general")
        col.addView(channel, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8)))

        col.addView(label("POSTURE").also { it.setPadding(0, dp(20), 0, dp(8)) })
        val posture = Spinner(this).also {
            it.background = roundRect(field, 14)
            it.adapter = ArrayAdapter(
                this, android.R.layout.simple_spinner_dropdown_item,
                listOf("pq-pure", "hybrid", "pq-pure-compact"),
            )
        }
        col.addView(posture, lp(MATCH_PARENT, WRAP_CONTENT))

        col.addView(pillButton("Host a chat", accent, Color.WHITE) {
            startHost(channel.text.toString().ifBlank { "#general" }, posture.selectedItem.toString())
        }, lp(MATCH_PARENT, dp(54), top = dp(32)))

        col.addView(text("— or join —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(28), bottom = dp(12)))
        val invite = inputField("talkrypt://…")
        col.addView(invite, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Join", panel, fg) {
            val uri = invite.text.toString().trim()
            if (uri.startsWith("talkrypt://")) startJoin(uri) else toast("Paste a talkrypt:// invite")
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))

        // In-person: find a nearby host, or send this very app P2P.
        col.addView(text("— in person —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(28), bottom = dp(12)))
        col.addView(pillButton("Find nearby host (BLE / Wi-Fi Direct)", accent, Color.WHITE) {
            findNearby()
        }, lp(MATCH_PARENT, dp(50)))
        col.addView(pillButton("Share app (P2P over Wi-Fi)", panel, fg) {
            shareApp()
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))
        col.addView(pillButton("Anchors (username directory)", panel, fg) {
            setContentView(anchorsScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))

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
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Share talkrypt", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text(
                "On the same Wi-Fi or hotspot, the other phone scans this code (or opens the URL), " +
                    "downloads the app, and installs it (allow “install unknown apps” once).",
                13f, muted,
            ),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(20)),
        )
        addQrInto(col, url, 0.72f)
        col.addView(text(url, 14f, accent, center = true).also { it.setPadding(0, dp(18), 0, dp(24)) })
        col.addView(pillButton("Done", panel, fg) {
            shareServer?.stop(); shareServer = null
            setContentView(setupScreen())
        }, lp(MATCH_PARENT, dp(50)))
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
        }
    }

    private fun findNearbyScreen(): View {
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Nearby hosts", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Scanning over Bluetooth LE and Wi-Fi Direct. Tap a host to join.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        val list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        nearbyList = list
        col.addView(list, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(text("…", 13f, muted, center = true).also { it.setPadding(0, dp(16), 0, dp(16)) })
        col.addView(pillButton("Back", panel, fg) {
            stopNearby(); setContentView(setupScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun addNearbyPeer(peer: NearbyDiscovery.Peer) {
        if (foundInvites.put(peer.inviteUri, peer) != null) return // de-dupe
        val list = nearbyList ?: return
        list.addView(pillButton("Join ${peer.name}", accent, Color.WHITE) {
            stopNearby(); startJoin(peer.inviteUri)
        }, lp(MATCH_PARENT, dp(52), top = dp(8)))
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

    /** Load this device's account, generating + persisting one on first use. */
    private fun account(): Account {
        val prefs = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        val seed = prefs.getString("account_seed", null)
        if (seed != null) {
            runCatching { return Account.fromSeedHex(seed) }
        }
        val a = Account.generate()
        prefs.edit().putString("account_seed", a.seedHex()).apply()
        return a
    }

    private fun anchorsScreen(): View {
        val acct = account()
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Anchors", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("A username directory you spawn or point at by location. Names map to account keys; verify safety numbers out of band.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(12)),
        )
        col.addView(text("YOUR ACCOUNT", 12f, muted, bold = true))
        col.addView(text(acct.safetyNumber().take(35) + "…", 13f, accent), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))

        // Spawn your own anchor.
        col.addView(pillButton("Spawn my own anchor", accent, Color.WHITE) {
            spawnAnchor()
        }, lp(MATCH_PARENT, dp(50)))

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
        }, lp(MATCH_PARENT, dp(50), top = dp(16)))

        col.addView(pillButton("Resolve this username", panel, fg) {
            val uri = anchorUri.text.toString().trim()
            val name = uname.text.toString().trim()
            if (!uri.startsWith("talkrypt://") || name.isEmpty()) { toast("enter an anchor URI + username"); return@pillButton }
            resolveAtAnchor(uri, name, result)
        }, lp(MATCH_PARENT, dp(50), top = dp(10)))

        col.addView(result, lp(MATCH_PARENT, WRAP_CONTENT))
        col.addView(pillButton("Back", panel, fg) {
            setContentView(setupScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(20)))

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
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Anchor running", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Others register/resolve usernames here. Share this location (scan or copy). It runs while the app is open.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        addQrInto(col, uri, 0.66f)
        col.addView(text(uri, 13f, accent, center = true).also { it.setPadding(0, dp(16), 0, dp(20)) })
        col.addView(pillButton("Back", panel, fg) { setContentView(anchorsScreen()) }, lp(MATCH_PARENT, dp(50)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun registerAtAnchor(uri: String, acct: Account, name: String, result: TextView) {
        result.text = "registering…"
        thread {
            val msg = try {
                anchorRegister(uri, acct, name)
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

    // ---------- chat screen ----------
    private fun chatScreen(title: String, subtitle: String): View {
        val root = column(bg)

        // header bar — MUST be WRAP_CONTENT height. `column()` defaults children
        // to MATCH_PARENT height, which (with no weight) would expand to fill the
        // whole screen and push the messages list + input bar off the bottom —
        // that was the "no text-entry field" bug. Pin explicit heights so only
        // the messages ScrollView (weight 1) takes the remaining space.
        val header = column(panel).apply { setPadding(dp(20), dp(14), dp(20), dp(14)) }
        header.addView(text(title, 17f, fg, bold = true))
        header.addView(text(subtitle, 12f, muted).also { it.setPadding(0, dp(2), 0, 0) })
        root.addView(header, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))

        // messages — the only weighted child; takes all space between header/bar
        val list = column(bg).apply { setPadding(dp(12), dp(12), dp(12), dp(12)) }
        messages = list
        val sv = ScrollView(this).apply { isFillViewport = true; addView(list) }
        scroll = sv
        root.addView(sv, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        // input bar — pinned to the bottom, WRAP_CONTENT height
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(panel); setPadding(dp(12), dp(10), dp(12), dp(10))
        }
        val input = inputField("Message").apply { background = roundRect(field, 24) }
        bar.addView(input, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        val send = text("➤", 20f, Color.WHITE, center = true).apply {
            background = circle(accent)
            gravity = Gravity.CENTER
        }
        send.setOnClickListener {
            val t = input.text.toString()
            if (t.isNotEmpty()) { input.setText(""); sendMessage(t) }
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
            bubble.addView(text(marking, 10f, Color.parseColor("#FFD166"), bold = true))
        }
        if (sender != null) bubble.addView(text(sender, 11f, accent, bold = true))
        bubble.addView(text(body, 15f, if (mine) Color.WHITE else fg).apply {
            // cap long messages at ~76% of screen width so bubbles don't span edge-to-edge
            maxWidth = (resources.displayMetrics.widthPixels * 0.76f).toInt()
        })
        wrap.addView(bubble, LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT))
        list.addView(wrap, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        scroll?.post { scroll?.fullScroll(View.FOCUS_DOWN) }
    }

    private fun system(s: String) {
        val list = messages ?: return
        list.addView(text(s, 12f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(10), bottom = dp(2)))
        scroll?.post { scroll?.fullScroll(View.FOCUS_DOWN) }
    }

    private fun bubbleBg(mine: Boolean) = GradientDrawable().apply {
        setColor(if (mine) accent else peerBubble)
        cornerRadius = dp(18).toFloat()
    }

    // ---------- engine actions (off the UI thread; the facade blocks) ----------
    private fun startHost(channel: String, posture: String) {
        toast("creating chat…")
        thread {
            try {
                // Bind to the LAN/hotspot address (not loopback) so the invite is
                // dialable from another device — required for QR/nearby joining.
                val listen = "${ApkShareServer.lanIp() ?: "127.0.0.1"}:9779"
                val c = TalkryptClient.host(listen, channel, posture)
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    setContentView(chatScreen(channel, "$posture · safety ${sn.take(11)}"))
                    system("hosting — let a friend scan this to join:")
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = "invite")
                    bind(c); poll()
                    // Also broadcast the invite over BLE + Wi-Fi Direct so a
                    // nearby phone can find it with no QR (best-effort; opt-in
                    // via the granted radios).
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) { ui.post { toast("host failed: ${e.message}") } }
        }
    }

    private fun startJoin(uri: String) {
        toast("joining…")
        thread {
            try {
                val c = TalkryptClient.join(uri); val sn = c.safetyNumber()
                ui.post {
                    setContentView(chatScreen("chat", "safety ${sn.take(11)} · peers ${c.peerCount()}"))
                    system("joined — say hello")
                    bind(c); poll()
                }
            } catch (e: Exception) { ui.post { toast("join failed: ${e.message}") } }
        }
    }

    private fun sendMessage(t: String) {
        val c = client ?: return
        addBubble(t, mine = true)
        thread { runCatching { c.send(t) }.onFailure { ui.post { toast("send failed") } } }
    }

    private fun bind(c: TalkryptClient) { client = c }

    private fun poll() {
        ui.postDelayed(object : Runnable {
            override fun run() {
                val c = client ?: return
                while (true) {
                    val e = runCatching { c.pollEvent() }.getOrNull() ?: break
                    when (e) {
                        is FfiEvent.Message ->
                            addBubble(e.text, mine = false, sender = e.from.take(8),
                                marking = e.marking.ifEmpty { null })
                        is FfiEvent.Connected -> system("● ${e.fingerprint.take(8)} connected")
                        is FfiEvent.Identity -> {
                            val who = e.username.ifEmpty { e.accountFingerprint.take(8) }
                            system(if (e.friend) "✓ friend $who" else "• account $who (not a friend)")
                        }
                        is FfiEvent.Disconnected -> system("○ ${e.fingerprint.take(8)} left")
                        is FfiEvent.Error -> system("! ${e.message}")
                    }
                }
                ui.postDelayed(this, 250)
            }
        }, 250)
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

    private fun label(s: String) = text(s, 12f, muted, bold = true)

    private fun inputField(hint: String) = EditText(this).apply {
        this.hint = hint; setTextColor(fg); setHintTextColor(muted)
        background = roundRect(field, 14); setPadding(dp(16), dp(14), dp(16), dp(14)); textSize = 15f
    }

    private fun pillButton(label: String, bgColor: Int, textColor: Int, onClick: () -> Unit) =
        text(label, 16f, textColor, bold = true, center = true).apply {
            gravity = Gravity.CENTER
            background = roundRect(bgColor, 14)
            isClickable = true
            setOnClickListener { onClick() }
        }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
