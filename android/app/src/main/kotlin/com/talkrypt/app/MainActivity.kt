package com.talkrypt.app

import android.app.Activity
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
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import com.talkrypt.custody.CustodyBridge
import kotlin.concurrent.thread
import uniffi.talkrypt_ffi.FfiEvent
import uniffi.talkrypt_ffi.TalkryptClient

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

    // palette
    private val bg = Color.parseColor("#0B0E13")
    private val panel = Color.parseColor("#161B22")
    private val field = Color.parseColor("#1C2230")
    private val fg = Color.parseColor("#E6EDF3")
    private val muted = Color.parseColor("#8B949E")
    private val accent = Color.parseColor("#2EA043")
    private val peerBubble = Color.parseColor("#222B36")
    private val hostPort = "127.0.0.1:9779"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = bg
        window.navigationBarColor = bg
        setContentView(setupScreen())
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

        val sv = ScrollView(this).apply { setBackgroundColor(bg); addView(col) }
        applyInsets(sv)
        return sv
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
                val c = TalkryptClient.host(hostPort, channel, posture)
                val invite = c.inviteUri(); val sn = c.safetyNumber()
                ui.post {
                    setContentView(chatScreen(channel, "$posture · safety ${sn.take(11)}"))
                    system("hosting on $hostPort — share the invite:")
                    addBubble(invite, mine = false, sender = "invite")
                    bind(c); poll()
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
                        is FfiEvent.Disconnected -> system("○ ${e.fingerprint.take(8)} left")
                        is FfiEvent.Error -> system("! ${e.message}")
                    }
                }
                ui.postDelayed(this, 250)
            }
        }, 250)
    }

    // ---------- view helpers ----------
    private fun applyInsets(v: View) {
        v.setOnApplyWindowInsetsListener { view, insets ->
            val top: Int; val bottom: Int
            if (Build.VERSION.SDK_INT >= 30) {
                val b = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                top = b.top; bottom = b.bottom
            } else {
                @Suppress("DEPRECATION") top = insets.systemWindowInsetTop
                @Suppress("DEPRECATION") bottom = insets.systemWindowInsetBottom
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
