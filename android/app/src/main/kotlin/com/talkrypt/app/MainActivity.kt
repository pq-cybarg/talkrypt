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
    private var client: TalkryptClient? = null
    private var messages: LinearLayout? = null
    private var scroll: ScrollView? = null
    private var shareServer: ApkShareServer? = null
    private var useTor = false // route the next host/join over Tor (.onion)

    /** Writable state dir for Arti (onion keys + dir cache) under app storage. */
    private fun torStateDir(): String = java.io.File(filesDir, "tor").absolutePath

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
            val uri = data.toString()
            // A device-linking offer (channel "#link") routes to the linking
            // confirm screen — not the chat join flow.
            val isLink = runCatching { inviteChannel(uri) == "#link" }.getOrDefault(false)
            if (isLink) {
                setContentView(acceptLinkConfirmScreen(uri))
            } else {
                toast("opening invite…")
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
        private const val ANCHOR_SEP = "\u001F" // delimiter for stored (uri, username)
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
        val posture = darkSpinner(listOf("pq-pure", "hybrid", "pq-pure-compact"))
        col.addView(posture, lp(MATCH_PARENT, WRAP_CONTENT))

        col.addView(label("ACCESS").also { it.setPadding(0, dp(20), 0, dp(8)) })
        val access = darkSpinner(listOf("open", "contacts", "friends"))
        col.addView(access, lp(MATCH_PARENT, WRAP_CONTENT))

        val torBox = CheckBox(this).apply {
            text = "Route over Tor (.onion; slow to start)"
            setTextColor(muted)
            isChecked = useTor
            setOnCheckedChangeListener { _, checked -> useTor = checked }
        }
        col.addView(torBox, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(16)))

        col.addView(pillButton("Host a chat", accent, Color.WHITE) {
            startHost(
                channel.text.toString().ifBlank { "#general" },
                posture.selectedItem.toString(),
                access.selectedItem.toString(),
            )
        }, lp(MATCH_PARENT, dp(54), top = dp(32)))
        col.addView(pillButton("Registry-restricted chat", panel, fg) {
            setContentView(restrictedHostScreen(channel.text.toString().ifBlank { "#general" }, posture.selectedItem.toString()))
        }, lp(MATCH_PARENT, dp(50), top = dp(10)))

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
        col.addView(pillButton("Contacts", panel, fg) {
            setContentView(contactsScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))
        col.addView(pillButton("Linked devices", panel, fg) {
            setContentView(linkedDevicesScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))
        col.addView(pillButton("Segments (contextual identities)", panel, fg) {
            setContentView(segmentsScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(12)))

        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    // ---------- contacts screen ----------
    private fun contactsScreen(): View {
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Contacts", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Accounts you recognize. Recognition only — being a contact (or friend) doesn't grant channel access; that's set per chat.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        val contacts = storedContacts()
        if (contacts.isEmpty()) {
            col.addView(
                text("No contacts yet. In a chat, when an account presents itself, tap “Add as a contact”.", 14f, muted),
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
        col.addView(pillButton("Back", panel, fg) { setContentView(setupScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(20)))
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

    // ---------- device linking (primary certifies a secondary device) ----------
    // Held while a link offer is running so its accept loop stays alive.
    private var linkOffer: LinkOffer? = null

    /** This device's persistent linked-device key (generated + persisted once).
     *  Distinct from `account()`: a linked secondary device holds this key but
     *  NOT the account secret — it presents a certificate the primary issued. */
    private fun deviceKey(): DeviceKey {
        val prefs = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        val seed = prefs.getString("device_seed", null)
        if (seed != null) {
            runCatching { return DeviceKey.fromSeedHex(seed) }
        }
        val d = DeviceKey.generate()
        prefs.edit().putString("device_seed", d.seedHex()).apply()
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
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Linked devices", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
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
            col.addView(pillButton("Join as this account", accent, Color.WHITE) {
                val u = joinUri.text.toString().trim()
                if (u.startsWith("talkrypt://")) joinAsLinked(u) else toast("paste a talkrypt:// invite")
            }, lp(MATCH_PARENT, dp(50), top = dp(10)))
            col.addView(pillButton("Unlink this device", panel, fg) {
                clearLink(); toast("unlinked"); setContentView(linkedDevicesScreen())
            }, lp(MATCH_PARENT, dp(50), top = dp(10)))
            col.addView(text("— or re-link —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(22), bottom = dp(6)))
        }

        // Primary role: certify ANOTHER device under this device's account.
        col.addView(text("LINK ANOTHER DEVICE TO MY ACCOUNT", 12f, muted, bold = true).also { it.setPadding(0, dp(4), 0, dp(4)) })
        col.addView(text("This device holds the account. Show a one-time QR the new device scans.", 12f, muted))
        col.addView(pillButton("Start a link offer", accent, Color.WHITE) {
            startLinkOffer()
        }, lp(MATCH_PARENT, dp(50), top = dp(10)))

        // Secondary role: link THIS device using an offer from the primary.
        col.addView(text("LINK THIS DEVICE TO AN ACCOUNT", 12f, muted, bold = true).also { it.setPadding(0, dp(22), 0, dp(4)) })
        col.addView(label("LINK OFFER (talkrypt:// from the primary)"))
        val offerUri = inputField("talkrypt://…")
        col.addView(offerUri, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        col.addView(pillButton("Accept link on this device", panel, fg) {
            val u = offerUri.text.toString().trim()
            if (u.startsWith("talkrypt://")) setContentView(acceptLinkConfirmScreen(u)) else toast("paste the link offer URI")
        }, lp(MATCH_PARENT, dp(50), top = dp(10)))

        col.addView(pillButton("Back", panel, fg) { setContentView(setupScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(24)))
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
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
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
        }, lp(MATCH_PARENT, dp(50)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun acceptLinkConfirmScreen(uri: String): View {
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Link this device?", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("This certifies THIS device under the account offering the link. Afterward, verify the account safety number shown matches the other device, out of band.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(16)),
        )
        col.addView(text(uri, 12f, muted), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(20)))
        col.addView(pillButton("Accept link on this device", accent, Color.WHITE) {
            acceptLink(uri)
        }, lp(MATCH_PARENT, dp(54)))
        col.addView(pillButton("Cancel", panel, fg) { setContentView(setupScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(10)))
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
                    setContentView(chatScreen("chat", "linked · safety ${sn.take(11)} · peers ${c.peerCount()}"))
                    system("joined as linked account" + (link.second.takeIf { it.isNotEmpty() }?.let { " ($it)" } ?: ""))
                    bind(c); poll()
                }
            } catch (e: Exception) {
                ui.post { toast("join failed: ${e.message}") }
            }
        }
    }

    // ---------- segment sub-identities (mutually-unlinkable contexts) ----------
    /** Persisted segments: (name, seed-hex). Each is an unlinkable contextual
     *  identity under this device's account (account→device→segment). */
    private fun storedSegments(): List<Pair<String, String>> {
        val p = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        return p.getStringSet("segments", emptySet()).orEmpty().mapNotNull {
            val s = it.split(contactSep)
            if (s.size == 2) s[0] to s[1] else null
        }.sortedBy { it.first }
    }

    private fun addSegment(name: String): SegmentKey {
        val seg = SegmentKey.generate()
        val p = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        val set = HashSet(p.getStringSet("segments", emptySet()).orEmpty())
        set.removeAll { it.substringBefore(contactSep) == name } // replace same-name
        set.add(name + contactSep + seg.seedHex())
        p.edit().putStringSet("segments", set).apply()
        return seg
    }

    private fun removeSegment(name: String) {
        val p = getSharedPreferences("talkrypt", android.content.Context.MODE_PRIVATE)
        val set = HashSet(p.getStringSet("segments", emptySet()).orEmpty())
        set.removeAll { it.substringBefore(contactSep) == name }
        p.edit().putStringSet("segments", set).apply()
    }

    private fun segmentsScreen(): View {
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Segments", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
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
                col.addView(pillButton("Join as “$name”", accent, Color.WHITE) {
                    val u = joinUri.text.toString().trim()
                    if (u.startsWith("talkrypt://")) joinAsSegment(u, seg, name) else toast("paste a talkrypt:// invite above")
                }, lp(MATCH_PARENT, dp(46), top = dp(6)))
                col.addView(pillButton("Delete “$name”", panel, fg) {
                    removeSegment(name); setContentView(segmentsScreen())
                }, lp(MATCH_PARENT, dp(42), top = dp(6)))
            }
        }

        col.addView(text("— new segment —", 13f, muted, center = true), lp(MATCH_PARENT, WRAP_CONTENT, top = dp(20), bottom = dp(8)))
        col.addView(label("SEGMENT NAME (context label)"))
        val name = inputField("work")
        col.addView(name, lp(MATCH_PARENT, WRAP_CONTENT, top = dp(6)))
        col.addView(pillButton("Create segment", accent, Color.WHITE) {
            val n = name.text.toString().trim()
            if (n.isEmpty()) { toast("name the segment"); return@pillButton }
            addSegment(n); toast("created segment “$n”"); setContentView(segmentsScreen())
        }, lp(MATCH_PARENT, dp(50), top = dp(10)))

        col.addView(pillButton("Back", panel, fg) { setContentView(setupScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(24)))
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
                    setContentView(chatScreen("chat", "segment “$name” · safety ${sn.take(11)} · peers ${c.peerCount()}"))
                    system("joined as segment “$name”")
                    bind(c); poll()
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
    private fun loadContacts(client: TalkryptClient) {
        storedContacts().forEach { (pk, name, friend) ->
            client.addContactHex(pk, name.ifEmpty { null }, friend)
        }
    }

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
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Registry-restricted chat", 26f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("Only members of the chosen registry can join $channel. You can pick only registries you're bound at; unreachable ones (or ones missing your record) are greyed out.", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(18)),
        )
        if (anchors.isEmpty()) {
            col.addView(text("You aren't registered at any anchor yet. Open Anchors and register a username first.", 14f, Color.parseColor("#FFD166")), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
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
        col.addView(pillButton("Back", panel, fg) { setContentView(setupScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(24)))
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
                    row.setTextColor(Color.WHITE)
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
                val listen = "${ApkShareServer.lanIp() ?: "127.0.0.1"}:9779"
                val c = TalkryptClient.host(listen, channel, posture)
                runCatching { c.presentAccount(account(), username) }
                runCatching { loadContacts(c) } // recognize saved contacts
                val members = c.restrictToAnchor(anchorUri)
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    setContentView(chatScreen(channel, "restricted · $members member(s) · safety ${sn.take(11)}"))
                    system("registry-restricted — only the $members anchor member(s) can join")
                    messages?.let { addQrInto(it, invite, 0.62f) }
                    addBubble(invite, mine = false, sender = "invite")
                    bind(c); poll()
                    startNearbyAdvertising(invite)
                }
            } catch (e: Exception) {
                ui.post { toast("restricted host failed: ${e.message}") }
            }
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

    /** A tappable action row inside the message list (e.g. "Add as contact"). */
    private fun addAction(label: String, onClick: () -> Unit) {
        val list = messages ?: return
        val btn = pillButton(label, panel, accent, onClick)
        list.addView(btn, lp(MATCH_PARENT, dp(44), top = dp(6), bottom = dp(2)))
        scroll?.post { scroll?.fullScroll(View.FOCUS_DOWN) }
    }

    private fun bubbleBg(mine: Boolean) = GradientDrawable().apply {
        setColor(if (mine) accent else peerBubble)
        cornerRadius = dp(18).toFloat()
    }

    // ---------- engine actions (off the UI thread; the facade blocks) ----------
    private fun startHost(channel: String, posture: String, access: String = "open") {
        toast("creating chat…")
        thread {
            try {
                // Bind to the LAN/hotspot address (not loopback) so the invite is
                // dialable from another device — required for QR/nearby joining.
                // Over Tor, host an onion service instead (the .onion goes in the invite).
                val c = if (useTor) {
                    TalkryptClient.hostTor(channel, posture, torStateDir())
                } else {
                    val listen = "${ApkShareServer.lanIp() ?: "127.0.0.1"}:9779"
                    TalkryptClient.host(listen, channel, posture)
                }
                // Present our account so peers (and registry-restricted hosts)
                // can resolve us as that account.
                runCatching { c.presentAccount(account(), null) }
                runCatching { loadContacts(c) } // recognize saved contacts
                // Apply the chosen access mode (open / contacts / friends).
                runCatching { c.setAccessMode(access) }
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    val tag = if (access == "open") posture else "$posture · $access only"
                    setContentView(chatScreen(channel, "$tag · safety ${sn.take(11)}"))
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
        val acct = account()
        val anchors = boundAnchors()
        val col = column(bg).apply { setPadding(dp(24), dp(8), dp(24), dp(24)) }
        col.addView(text("Join chat", 28f, fg, bold = true).also { it.setPadding(0, dp(8), 0, 0) })
        col.addView(
            text("If this chat is registry-restricted, you're admitted only as a member. Present a live membership, or join as a pseudonym (open chats only).", 13f, muted),
            lp(MATCH_PARENT, WRAP_CONTENT, top = dp(8), bottom = dp(18)),
        )
        if (anchors.isEmpty()) {
            col.addView(text("You have no registry memberships yet — register at an anchor to join restricted chats.", 14f, Color.parseColor("#FFD166")), lp(MATCH_PARENT, WRAP_CONTENT, bottom = dp(16)))
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
        }, lp(MATCH_PARENT, dp(50)))
        col.addView(pillButton("Join as pseudonym (unlinkable)", panel, fg) {
            doJoin(uri, null, presentAccount = false)
        }, lp(MATCH_PARENT, dp(50), top = dp(10)))
        col.addView(pillButton("Back", panel, fg) { setContentView(setupScreen()) }, lp(MATCH_PARENT, dp(50), top = dp(20)))
        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
    }

    private fun doJoin(uri: String, username: String?, presentAccount: Boolean) {
        toast(if (useTor) "joining over Tor…" else "joining…")
        thread {
            try {
                val c = if (useTor) TalkryptClient.joinTor(uri, torStateDir()) else TalkryptClient.join(uri)
                val sn = c.safetyNumber()
                // Present our account (optionally as a username) so a registry-
                // restricted host can admit us and the peer can friend us. A
                // pseudonym presents nothing and won't pass a restricted gate.
                if (presentAccount) runCatching { c.presentAccount(account(), username) }
                runCatching { loadContacts(c) } // recognize saved contacts
                ui.post {
                    setContentView(chatScreen("chat", "safety ${sn.take(11)} · peers ${c.peerCount()}"))
                    system(if (presentAccount) "joined" + (username?.let { " as $it" } ?: "") else "joined as pseudonym")
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
                            system(
                                when {
                                    e.friend -> "✓ friend $who"
                                    e.contact -> "• contact $who"
                                    else -> "• account $who (not a contact)"
                                },
                            )
                            // Offer to recognize an unknown account (verify the
                            // safety number out of band first).
                            if (!e.contact) {
                                val fp = e.accountFingerprint
                                val name = e.username
                                addAction("Add “$who” as a contact") {
                                    val cl = client
                                    if (cl != null && cl.addSeenContact(fp, name.ifEmpty { null }, false)) {
                                        saveContacts(cl)
                                        system("added contact $who")
                                    } else {
                                        toast("could not add (account not seen)")
                                    }
                                }
                            }
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
                    setPadding(dp(12), paddingTop, dp(12), paddingBottom)
                }

            override fun getDropDownView(position: Int, convertView: View?, parent: ViewGroup): View =
                (super.getDropDownView(position, convertView, parent) as TextView).apply {
                    setTextColor(fg)
                    setBackgroundColor(panel)
                    setPadding(dp(16), dp(12), dp(16), dp(12))
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
