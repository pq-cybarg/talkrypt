package com.talkrypt.app

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.method.ScrollingMovementMethod
import android.view.Gravity
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import com.talkrypt.custody.CustodyBridge
import kotlin.concurrent.thread
import uniffi.talkrypt_ffi.FfiEvent
import uniffi.talkrypt_ffi.TalkryptClient

/**
 * The talkrypt chat app: host or join a post-quantum E2E chat over the shared
 * `TalkryptClient` FFI, with a message log + input. The custody tier this device
 * achieves (StrongBox on the Seeker) is shown in the header. NOT certified /
 * NOT audited — see the README.
 */
class MainActivity : Activity() {
    private val ui = Handler(Looper.getMainLooper())
    private var client: TalkryptClient? = null
    private var log: TextView? = null

    // palette
    private val bg = Color.parseColor("#0E1116")
    private val panel = Color.parseColor("#161B22")
    private val fg = Color.parseColor("#E6EDF3")
    private val muted = Color.parseColor("#8B949E")
    private val accent = Color.parseColor("#3FB950")
    private val hostPort = "127.0.0.1:9779"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(setupScreen())
    }

    // ---- setup screen: host or join ----
    private fun setupScreen(): LinearLayout {
        val tier = runCatching { CustodyBridge.detectTier().name }.getOrDefault("UNKNOWN")
        val root = column(bg).apply { setPadding(48, 96, 48, 48) }

        root.addView(text("talkrypt", 30f, fg, bold = true))
        root.addView(text("post-quantum · end-to-end encrypted", 14f, muted))
        root.addView(text("key custody: $tier   ·   identity: ML-DSA-87", 12f, accent).also { it.setPadding(0, 8, 0, 32) })

        root.addView(text("CHANNEL", 12f, muted))
        val channel = field("#general")
        root.addView(channel)

        root.addView(text("POSTURE", 12f, muted).also { it.setPadding(0, 24, 0, 8) })
        val posture = Spinner(this).also {
            it.adapter = android.widget.ArrayAdapter(
                this, android.R.layout.simple_spinner_dropdown_item,
                listOf("pq-pure", "hybrid", "pq-pure-compact"),
            )
        }
        root.addView(posture)

        val hostBtn = button("Host a chat", accent) {
            startHost(channel.text.toString().ifBlank { "#general" }, posture.selectedItem.toString())
        }
        root.addView(hostBtn, LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = 40 })

        root.addView(text("— or join —", 13f, muted, center = true).also { it.setPadding(0, 28, 0, 8) })
        val invite = field("talkrypt://…")
        root.addView(invite)
        root.addView(button("Join", panel) {
            val uri = invite.text.toString().trim()
            if (uri.startsWith("talkrypt://")) startJoin(uri)
            else toast("Paste a talkrypt:// invite")
        })
        return root
    }

    // ---- chat screen ----
    private fun chatScreen(header: String): LinearLayout {
        val root = column(bg)
        root.addView(text(header, 13f, muted).also {
            it.setBackgroundColor(panel); it.setPadding(32, 48, 32, 24)
        })
        val l = TextView(this).apply {
            setTextColor(fg); textSize = 13f
            typeface = Typeface.MONOSPACE
            setPadding(32, 24, 32, 24)
            movementMethod = ScrollingMovementMethod()
        }
        log = l
        val scroll = ScrollView(this).apply { addView(l) }
        root.addView(scroll, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setBackgroundColor(panel); setPadding(20, 16, 20, 32)
        }
        val input = field("message").apply {
            layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f)
        }
        row.addView(input)
        row.addView(button("Send", accent) {
            val t = input.text.toString()
            if (t.isNotEmpty()) { input.setText(""); sendMessage(t) }
        })
        root.addView(row)
        return root
    }

    // ---- engine actions (off the UI thread; the facade is blocking) ----
    private fun startHost(channel: String, posture: String) {
        toast("creating chat…")
        thread {
            try {
                val c = TalkryptClient.host(hostPort, channel, posture)
                val invite = c.inviteUri()
                val sn = c.safetyNumber()
                ui.post {
                    setContentView(chatScreen("hosting $channel · $posture · $hostPort"))
                    append("safety number: $sn", muted)
                    append("share this invite:", muted)
                    append(invite, accent)
                    append("", fg)
                    bind(c); poll()
                }
            } catch (e: Exception) {
                ui.post { toast("host failed: ${e.message}") }
            }
        }
    }

    private fun startJoin(uri: String) {
        toast("joining…")
        thread {
            try {
                val c = TalkryptClient.join(uri)
                val sn = c.safetyNumber()
                ui.post {
                    setContentView(chatScreen("joined · peers ${c.peerCount()}"))
                    append("safety number: $sn", muted)
                    append("", fg)
                    bind(c); poll()
                }
            } catch (e: Exception) {
                ui.post { toast("join failed: ${e.message}") }
            }
        }
    }

    private fun sendMessage(t: String) {
        val c = client ?: return
        append("me: $t", accent)
        thread { runCatching { c.send(t) }.onFailure { ui.post { toast("send failed") } } }
    }

    private fun bind(c: TalkryptClient) { client = c }

    private fun poll() {
        ui.postDelayed(object : Runnable {
            override fun run() {
                val c = client ?: return
                var e = runCatching { c.pollEvent() }.getOrNull()
                while (e != null) {
                    when (e) {
                        is FfiEvent.Message -> {
                            val tag = if (e.marking.isNotEmpty()) "[${e.marking}] " else ""
                            append("$tag${e.from.take(8)}: ${e.text}", fg)
                        }
                        is FfiEvent.Connected -> append("* peer connected: ${e.fingerprint.take(8)}", muted)
                        is FfiEvent.Disconnected -> append("* peer left: ${e.fingerprint.take(8)}", muted)
                        is FfiEvent.Error -> append("! ${e.message}", Color.parseColor("#F85149"))
                    }
                    e = runCatching { c.pollEvent() }.getOrNull()
                }
                ui.postDelayed(this, 250)
            }
        }, 250)
    }

    // ---- view helpers ----
    private fun append(s: String, color: Int) {
        val l = log ?: return
        val start = l.text.length
        l.append(s + "\n")
        val sp = android.text.SpannableString(l.text)
        sp.setSpan(android.text.style.ForegroundColorSpan(color), start, (start + s.length).coerceAtMost(sp.length), 0)
        l.text = sp
        (l.parent as? ScrollView)?.post { (l.parent as ScrollView).fullScroll(ScrollView.FOCUS_DOWN) }
    }

    private fun column(color: Int) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; setBackgroundColor(color)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
    }

    private fun text(s: String, size: Float, color: Int, bold: Boolean = false, center: Boolean = false) =
        TextView(this).apply {
            text = s; textSize = size; setTextColor(color)
            if (bold) setTypeface(typeface, Typeface.BOLD)
            if (center) gravity = Gravity.CENTER_HORIZONTAL
        }

    private fun field(hint: String) = EditText(this).apply {
        this.hint = hint; setTextColor(fg); setHintTextColor(muted)
        setBackgroundColor(panel); setPadding(28, 24, 28, 24); textSize = 15f
    }

    private fun button(label: String, color: Int, onClick: () -> Unit) = Button(this).apply {
        text = label; setTextColor(Color.WHITE); setBackgroundColor(color)
        setOnClickListener { onClick() }
    }

    private fun toast(s: String) =
        android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_SHORT).show()
}
